/*
 * BPFHV paravirtual network device
 *   Device emulation main functionalities
 *
 * Copyright (c) 2018 Vincenzo Maffione <v.maffione@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "hw/hw.h"
#include "hw/pci/pci.h"
#include "hw/pci/msi.h"
#include "hw/pci/msix.h"
#include "net/net.h"
#include "sysemu/sysemu.h"
#include "sysemu/kvm.h"
#include "qemu/error-report.h"
#include "qemu/iov.h"
#include "qemu/range.h"
#include "qapi/error.h"
#include "linux/virtio_net.h"

#include <libelf.h>
#include <gelf.h>

#include "bpfhv.h"
#include "bpfhv_sring_hv.h"

/*
 * Compile-time tunables.
 */

/* Consume the memory listener interface to get updates about
 * guest memory map. The updates are used to build a translation
 * table to speed up the translation of descriptor addresses
 * (GPA --> HVA). */
#define BPFHV_MEMLI

/* Let KVM handle the TX kicks in kernelspace, rather than
 * have KVM return to QEMU and QEMU handling the TX kicks. */
#define BPFHV_TX_IOEVENTFD

/* Debug timer to show ring statistics. */
#undef  BPFHV_DEBUG_TIMER

/* Verbose debug information. */
#undef  BPFHV_DEBUG

/*
 * End of tunables.
 */

#ifdef BPFHV_DEBUG
#define DBG(fmt, ...) do { \
        fprintf(stderr, "bpfhv-if: " fmt "\n", ## __VA_ARGS__); \
    } while (0)
#else
#define DBG(fmt, ...) do {} while (0)
#endif

static const char *regnames[] = {
    "STATUS",
    "CTRL",
    "MAC_LO",
    "MAC_HI",
    "NUM_RX_QUEUES",
    "NUM_TX_QUEUES",
    "NUM_RX_BUFS",
    "NUM_TX_BUFS",
    "RX_CTX_SIZE",
    "TX_CTX_SIZE",
    "DOORBELL_SIZE",
    "QUEUE_SELECT",
    "CTX_PADDR_LO",
    "CTX_PADDR_HI",
    "PROG_SELECT",
    "PROG_SIZE",
    "DOORBELL_GVA_LO",
    "DOORBELL_GVA_HI",
    "VERSION",
    "FEATURES",
};

#define BPFHV_CSUM_FEATURES (BPFHV_F_TX_CSUM | BPFHV_F_RX_CSUM)

#define BPFHV_GSO_FEATURES (BPFHV_F_TSOv4   | BPFHV_F_TCPv4_LRO \
                           |  BPFHV_F_TSOv6 | BPFHV_F_TCPv6_LRO \
                           |  BPFHV_F_UFO   | BPFHV_F_UDP_LRO)

typedef struct BpfHvProg_st {
    unsigned int num_insns;
    uint64_t *insns;
} BpfHvProg;

/* Each eBPF instruction is 8 bytes wide. */
#define BPF_INSN_SIZE   8

struct BpfHvState_st;

typedef struct BpfHvTxQueue_st {
    struct bpfhv_tx_context *ctx;
    QEMUBH *bh;
    NetClientState *nc;
    struct BpfHvState_st *parent;
    unsigned int vector;
#ifdef BPFHV_TX_IOEVENTFD
    EventNotifier ioeventfd;
#endif /* BPFHV_TX_IOEVENTFD */
} BpfHvTxQueue;

typedef struct BpfHvRxQueue_st {
    struct bpfhv_rx_context *ctx;
} BpfHvRxQueue;

typedef struct BpfHvTranslateEntry_st {
    uint64_t gpa_start;
    uint64_t gpa_end;
    uint64_t size;
    void *hva_start;
    MemoryRegion *mr;
} BpfHvTranslateEntry;

typedef struct BpfHvState_st {
    /* Parent class. This is a private field, and it cannot be used. */
    PCIDevice pci_device;

    NICState *nic;
    NICConf conf;
    MemoryRegion regs;
    MemoryRegion dbmmio;
    MemoryRegion progmmio;

    /* Storage for the I/O registers. */
    uint32_t ioregs[BPFHV_REG_END >> 2];

    /* Total number of queues, including both receive and transmit
     * ones. */
    unsigned int num_queues;

    /* eBPF programs associated to this device. */
    BpfHvProg progs[BPFHV_PROG_MAX];

    /* True if the guest provided all the receive (or ransmit) contexts. */
    bool rx_contexts_ready;
    bool tx_contexts_ready;

    /* True if the guest changed doorbell GVA, and therefore we may need
     * to relocate the eBPF programs before the guest reads them. */
    bool doorbell_gva_changed;

    BpfHvRxQueue *rxq;
    BpfHvTxQueue *txq;

    /* Length of the virtio net header that we are using to implement
     * the offloads supported by the backend. */
    int vnet_hdr_len;

    /* The features that we expose to the guest. */
    uint32_t hv_features;

    /* Name of the set of eBPF programs currently in use. */
    const char *progsname;

#ifdef BPFHV_DEBUG_TIMER
    QEMUTimer  *debug_timer;
#define BPFHV_DEBUG_TIMER_MS	2000
#endif /* BPFHV_DEBUG_TIMER */

#ifdef BPFHV_MEMLI
    MemoryListener memory_listener;
    BpfHvTranslateEntry *trans_entries;
    unsigned int num_trans_entries;
    BpfHvTranslateEntry *trans_entries_tmp;
    unsigned int num_trans_entries_tmp;
#endif /* BPFHV_MEMLI */

    QemuThread proc_th;
} BpfHvState;

/* Macro to generate I/O register indices. */
#define BPFHV_REG(x) ((BPFHV_REG_ ## x) >> 2)

#define TYPE_BPFHV_PCI  "bpfhv-pci"

#define BPFHV(obj) \
            OBJECT_CHECK(BpfHvState, (obj), TYPE_BPFHV_PCI)

#ifdef BPFHV_DEBUG_TIMER
static void
bpfhv_debug_timer(void *opaque)
{
    BpfHvState *s = opaque;
    int i;

    if (s->rx_contexts_ready) {
        for (i = 0; i < s->ioregs[BPFHV_REG(NUM_RX_QUEUES)]; i++) {
            sring_rxq_dump(s->rxq[i].ctx);
        }
    }

    if (s->tx_contexts_ready) {
        for (i = 0; i < s->ioregs[BPFHV_REG(NUM_TX_QUEUES)]; i++) {
            sring_txq_dump(s->txq[i].ctx);
        }
    }

    timer_mod(s->debug_timer, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) +
              BPFHV_DEBUG_TIMER_MS);
}
#endif /* BPFHV_DEBUG_TIMER */

static int
bpfhv_can_receive(NetClientState *nc)
{
    BpfHvState *s = qemu_get_nic_opaque(nc);
    unsigned int i;

    if (unlikely(!(s->ioregs[BPFHV_REG(STATUS)] & BPFHV_STATUS_RX_ENABLED))) {
        return false;
    }

    for (i = 0; i < s->ioregs[BPFHV_REG(NUM_RX_QUEUES)]; i++) {
        if (sring_can_receive(s->rxq[i].ctx)) {
            return true;
        }
        /* We don't have enough RX descriptors, and thus we need to enable
         * RX kicks on this queue. */
        sring_rxq_notification(s->rxq[i].ctx, /*enable=*/true);
        break; /* We only support a single receive queue for now. */
    }

    return false;
}

static ssize_t
bpfhv_receive_iov(NetClientState *nc, const struct iovec *iov, int iovcnt)
{
    BpfHvState *s = qemu_get_nic_opaque(nc);
    bool notify;
    ssize_t ret;

    if (!(s->ioregs[BPFHV_REG(STATUS)] & BPFHV_STATUS_RX_ENABLED)) {
        /* This should never happen, because we exported the can_receive
         * method. */
        return 0;
    }

    /* We only support a single receive queue for now. */
    ret = sring_receive_iov(s, s->rxq[0].ctx, iov, iovcnt, s->vnet_hdr_len,
                            &notify);
    if (ret > 0 && notify) {
        msix_notify(PCI_DEVICE(s), 0);
    }

    return ret;
}

/* Device link status is up iff all the receive contexts are valid and
 * the network backend link status is up. */
static void
bpfhv_link_status_update(BpfHvState *s)
{
    bool status = !!(s->ioregs[BPFHV_REG(STATUS)] & BPFHV_STATUS_LINK);
    NetClientState *nc = qemu_get_queue(s->nic);
    bool new_status;

    new_status = !(nc->link_down) && s->rx_contexts_ready;
    if (new_status == status) {
        return;
    }

    DBG("Link status goes %s", new_status ? "up" : "down");
    s->ioregs[BPFHV_REG(STATUS)] ^= BPFHV_STATUS_LINK;
    if (new_status) {
        /* Link status goes up, which means that bpfhv_can_receive()
         * may return true, hence we need to wake up the backend. */
        qemu_flush_queued_packets(nc);
#ifdef BPFHV_DEBUG_TIMER
        timer_mod(s->debug_timer, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) +
                BPFHV_DEBUG_TIMER_MS);
    } else {
        timer_del(s->debug_timer);
#endif /* BPFHV_DEBUG_TIMER */
    }
}

static void
bpfhv_backend_link_status_changed(NetClientState *nc)
{
    BpfHvState *s = qemu_get_nic_opaque(nc);

    bpfhv_link_status_update(s);
}

static NetClientInfo net_bpfhv_info = {
    .type = NET_CLIENT_DRIVER_NIC,
    .size = sizeof(NICState),
    .can_receive = bpfhv_can_receive,
    .receive_iov = bpfhv_receive_iov,
    .link_status_changed = bpfhv_backend_link_status_changed,
};

static int bpfhv_progs_load(BpfHvState *s, const char *progsname, Error **errp);

static void
bpfhv_ctrl_update(BpfHvState *s, uint32_t newval)
{
    uint32_t changed = s->ioregs[BPFHV_REG(CTRL)] ^ newval;
    int i;

    if (changed & BPFHV_CTRL_RX_ENABLE) {
        if (newval & BPFHV_CTRL_RX_ENABLE) {
            /* Guest asked to enable receive operation. We can accept
             * that only if all the receive contexts are present. */
            if (!s->rx_contexts_ready) {
                newval &= ~BPFHV_CTRL_RX_ENABLE;
            } else {
                /* Set the status bit before flushing queued packets,
                 * otherwise can_receive will return false. */
                s->ioregs[BPFHV_REG(STATUS)] |= BPFHV_STATUS_RX_ENABLED;
                for (i = 0; i < s->ioregs[BPFHV_REG(NUM_RX_QUEUES)]; i++) {
                    sring_rxq_notification(s->rxq[i].ctx, /*enable=*/true);
                }
                /* Guest enabled receive operation, which means that
                 * bpfhv_can_receive() may return true, hence we need to wake
                 * up the backend. */
                qemu_flush_queued_packets(qemu_get_queue(s->nic));
                DBG("Receive enabled");
            }
        } else {
            /* Guest asked to disable receive operation. */
            s->ioregs[BPFHV_REG(STATUS)] &= ~BPFHV_STATUS_RX_ENABLED;
            DBG("Receive disabled");
        }
    }

    if (changed & BPFHV_CTRL_TX_ENABLE) {
        if (newval & BPFHV_CTRL_TX_ENABLE) {
            /* Guest asked to enable transmit operation. We can accept
             * that only if all the transmit contexts are present. */
            if (!s->tx_contexts_ready) {
                newval &= ~BPFHV_CTRL_TX_ENABLE;
            } else {
                s->ioregs[BPFHV_REG(STATUS)] |= BPFHV_STATUS_TX_ENABLED;
                for (i = 0; i < s->ioregs[BPFHV_REG(NUM_TX_QUEUES)]; i++) {
                    qemu_bh_schedule(s->txq[i].bh);
                }
                DBG("Transmit enabled");
            }
        } else {
            /* Guest asked to disable transmit operation. */
            s->ioregs[BPFHV_REG(STATUS)] &= ~BPFHV_STATUS_TX_ENABLED;
            for (i = 0; i < s->ioregs[BPFHV_REG(NUM_TX_QUEUES)]; i++) {
                qemu_bh_cancel(s->txq[i].bh);
            }
            DBG("Transmit disabled");
        }
    }

    if (changed & BPFHV_CTRL_UPGRADE_READY) {
        /* Guest says it is ready to upgrade. First, reset the
         * bit as we don't store it. */
        newval &= ~BPFHV_CTRL_UPGRADE_READY;
        if (!(s->ioregs[BPFHV_REG(STATUS)] & BPFHV_STATUS_UPGRADE)) {
            /* No upgrade is pending, hence we ignore this request. */
        } else {
            Error *local_err = NULL;

            /* Perform the upgrade and clear the status bit. We currently
             * do not recover from upgrade failure. */
            if (bpfhv_progs_load(s, s->progsname, &local_err)) {
                error_propagate(&error_fatal, local_err);
                return;
            }
            s->ioregs[BPFHV_REG(STATUS)] &= ~BPFHV_STATUS_UPGRADE;
        }
    }

    /* Temporary hack to play with program upgrade. We trigger
     * and upgrade interrupt if the guest writes to bit 31 of
     * the control register. */
    if (changed & (1 << 31)) {
        s->ioregs[BPFHV_REG(STATUS)] |= BPFHV_STATUS_UPGRADE;
        newval &= ~(1 << 31);
        msix_notify(PCI_DEVICE(s), s->num_queues);
    }

    s->ioregs[BPFHV_REG(CTRL)] = newval;
}

static void
bpfhv_ctx_remap(BpfHvState *s)
{
    unsigned int qsel = s->ioregs[BPFHV_REG(QUEUE_SELECT)];
    bool rx = false;
    hwaddr base, len;
    void **pvaddr;

    base = (((uint64_t)s->ioregs[BPFHV_REG(CTX_PADDR_HI)]) << 32ULL) |
                    (uint64_t)s->ioregs[BPFHV_REG(CTX_PADDR_LO)];

    if (qsel < s->ioregs[BPFHV_REG(NUM_RX_QUEUES)]) {
        pvaddr = (void **)&s->rxq[qsel].ctx;
        len = s->ioregs[BPFHV_REG(RX_CTX_SIZE)];
        rx = true;
    } else {
        qsel -= s->ioregs[BPFHV_REG(NUM_RX_QUEUES)];
        pvaddr = (void **) &s->txq[qsel].ctx;
        len = s->ioregs[BPFHV_REG(TX_CTX_SIZE)];
        rx = false;
    }

    /* Unmap the previous context, if any. */
    if (*pvaddr) {
        cpu_physical_memory_unmap(*pvaddr, len, /*is_write=*/1, len);
        *pvaddr = NULL;
    }

    /* Map the new context if it is provided. */
    if (base != 0) {
        *pvaddr = cpu_physical_memory_map(base, &len, /*is_write=*/1);
        DBG("Queue %sX#%u GPA %llx (%llu) mapped at HVA %p", rx ? "R" : "T",
            qsel, (unsigned long long)base, (unsigned long long)len, *pvaddr);

        /* Also initialize the hypervisor-side of the context. */
        if (rx) {
            sring_rx_ctx_init(s->rxq[qsel].ctx,
                              s->ioregs[BPFHV_REG(NUM_RX_BUFS)]);
        } else {
            sring_tx_ctx_init(s->txq[qsel].ctx,
                              s->ioregs[BPFHV_REG(NUM_TX_BUFS)]);
        }
    }

    /* Update rx_contexts_ready and tx_contexts_ready. */
    if (rx) {
        int i;

        s->rx_contexts_ready = true;
        for (i = 0; i < s->ioregs[BPFHV_REG(NUM_RX_QUEUES)]; i++) {
            if (s->rxq[i].ctx == NULL) {
                s->rx_contexts_ready = false;
                break;
            }
        }

        /* Possibly update link status, which depends on
         * rx_contexs_ready. */
        bpfhv_link_status_update(s);
    } else {
        int i;

        s->tx_contexts_ready = true;
        for (i = 0; i < s->ioregs[BPFHV_REG(NUM_TX_QUEUES)]; i++) {
            if (s->txq[i].ctx == NULL) {
                s->tx_contexts_ready = false;
                break;
            }
        }
    }
}

static void
bpfhv_io_write(void *opaque, hwaddr addr, uint64_t val, unsigned size)
{
    BpfHvState *s = opaque;
    unsigned int index;

    addr = addr & BPFHV_REG_MASK;
    index = addr >> 2;

    if (addr >= BPFHV_REG_END) {
        DBG("Unknown I/O write, addr=0x%08"PRIx64", val=0x%08"PRIx64,
            addr, val);
        return;
    }

    assert(index < ARRAY_SIZE(regnames));

    DBG("I/O write to %s, val=0x%08" PRIx64, regnames[index], val);

    switch (addr) {
    case BPFHV_REG_CTRL:
        bpfhv_ctrl_update(s, (uint32_t)val);
        break;

    case BPFHV_REG_QUEUE_SELECT:
        if (val >= s->num_queues) {
            DBG("Guest tried to select invalid queue #%"PRIx64"", val);
            break;
        }
        s->ioregs[index] = val;
        break;

    case BPFHV_REG_DOORBELL_GVA_LO:
    case BPFHV_REG_DOORBELL_GVA_HI:
        s->doorbell_gva_changed |= (s->ioregs[index] != (uint32_t)val);
        /* fallback */
    case BPFHV_REG_CTX_PADDR_LO:
        s->ioregs[index] = val;
        break;

    case BPFHV_REG_CTX_PADDR_HI:
        s->ioregs[index] = val;
        /* A write to the most significant 32-bit word also triggers context
         * mapping (or unmapping). */
        bpfhv_ctx_remap(s);
        break;

    case BPFHV_REG_PROG_SELECT:
        if (val >= BPFHV_PROG_MAX) {
            DBG("Guest tried to select invalid program #%"PRIx64"", val);
            break;
        }
        s->ioregs[index] = val;
        s->ioregs[BPFHV_REG(PROG_SIZE)] = s->progs[val].num_insns;
        break;

    case BPFHV_REG_FEATURES: {
        NetClientState *peer = qemu_get_queue(s->nic)->peer;
        Error *local_err = NULL;
        const char *progsname;
        int prev_hdr_len;
        bool csum, gso;

        /* Check that 'val' is a subset of s->hv_features. */
        if ((s->hv_features | val) != s->hv_features) {
            DBG("Driver tried to select features unknown to the hv");
            break;
        }

        /* Configure virtio-net header and offloads in the backend, depending
         * on the features activated by the guest. */
        csum = val & BPFHV_CSUM_FEATURES;
        gso = val & BPFHV_GSO_FEATURES;
        prev_hdr_len = s->vnet_hdr_len;
        s->vnet_hdr_len = (csum || gso) ? sizeof(struct virtio_net_hdr_v1) : 0;
        if ((s->vnet_hdr_len == 0 &&
            peer->info->type == NET_CLIENT_DRIVER_TAP)) {
            /* The tap backend does not support removing the virtio-net
             * header once it has been set. However, we can unnegotiate
             * the header --> qemu_using_vnet_hdr(peer, false). */
        } else {
            qemu_set_vnet_hdr_len(peer, s->vnet_hdr_len);
        }
        qemu_using_vnet_hdr(peer, s->vnet_hdr_len != 0);
        qemu_set_offload(peer, /*csum=*/csum, /*tso4=*/gso,
                         /*tso6=*/gso, /*ecn=*/false, /*ufo=*/gso);

        /* Load the corresponding eBPF programs. */
        progsname = gso ? "sringgso" : (csum ? "sringcsum" : "sring");
        if (bpfhv_progs_load(s, progsname, &local_err)) {
            error_propagate(&error_fatal, local_err);
            return;
        }

        /* Update the features register. */
        s->ioregs[index] = val;
        break;
    }

    default:
        DBG("I/O write to %s ignored, val=0x%08" PRIx64,
            regnames[index], val);
        return;
        break;
    }
}

static uint64_t
bpfhv_io_read(void *opaque, hwaddr addr, unsigned size)
{
    BpfHvState *s = opaque;
    unsigned int index;

    addr = addr & BPFHV_REG_MASK;
    index = addr >> 2;

    if (addr >= BPFHV_REG_END) {
        DBG("Unknown I/O read, addr=0x%08"PRIx64, addr);
        return 0;
    }

    assert(index < ARRAY_SIZE(regnames));

    DBG("I/O read from %s, val=0x%08x", regnames[index], s->ioregs[index]);

    return s->ioregs[index];
}

static void
bpfhv_tx_complete(NetClientState *nc, ssize_t len)
{
    BpfHvState *s = qemu_get_nic_opaque(nc);
    int i;

    if (!(s->ioregs[BPFHV_REG(STATUS)] & BPFHV_STATUS_TX_ENABLED)) {
        return;
    }

    for (i = 0; i < s->ioregs[BPFHV_REG(NUM_TX_QUEUES)]; i++) {
        bool notify;

        sring_txq_notification(s->txq[i].ctx, /*enable=*/true);

        sring_txq_drain(s, nc, s->txq[i].ctx, bpfhv_tx_complete,
                        s->vnet_hdr_len, &notify);
        if (notify) {
	    msix_notify(PCI_DEVICE(s), s->txq[i].vector);
        }
    }
}

static void
bpfhv_tx_bh(void *opaque)
{
    BpfHvTxQueue *txq = opaque;
    BpfHvState *s = txq->parent;
    bool notify;
    ssize_t ret;

    if (!(s->ioregs[BPFHV_REG(STATUS)] & BPFHV_STATUS_TX_ENABLED)) {
        return;
    }

    ret = sring_txq_drain(s, txq->nc, txq->ctx, bpfhv_tx_complete,
                          s->vnet_hdr_len, &notify);
    if (notify) {
	    msix_notify(PCI_DEVICE(s), txq->vector);
    }
    if (ret == -EBUSY || ret == -EINVAL) {
        return;
    }

    if (ret >= BPFHV_HV_TX_BUDGET) {
        /* We processed a full budget of packets, thus it is likely that more
         * are pending (or will come in short). */
        qemu_bh_schedule(txq->bh);
        return;
    }

    /* If less than a full budget, re-enable notification and flush
     * anything that may have come in while we weren't looking.
     * If we find something, assume the guest is still active and
     * reschedule. */
    sring_txq_notification(txq->ctx, /*enable=*/true);
    ret = sring_txq_drain(s, txq->nc, txq->ctx, bpfhv_tx_complete,
                          s->vnet_hdr_len, &notify);
    if (notify) {
	    msix_notify(PCI_DEVICE(s), txq->vector);
    }
    if (ret == -EINVAL) {
        return;
    } else if (ret > 0) {
        sring_txq_notification(txq->ctx, /*enable=*/false);
        qemu_bh_schedule(txq->bh);
    }
}

#ifdef BPFHV_TX_IOEVENTFD
static void
bpfhv_tx_evnotify(EventNotifier *ioeventfd)
{
    BpfHvTxQueue *txq = container_of(ioeventfd, BpfHvTxQueue, ioeventfd);

    if (unlikely(!event_notifier_test_and_clear(ioeventfd))) {
        return;
    }
    bpfhv_tx_bh(txq);
}
#endif /* BPFHV_TX_IOEVENTFD */

static void
bpfhv_dbmmio_write(void *opaque, hwaddr addr, uint64_t val, unsigned size)
{
    BpfHvState *s = opaque;
    unsigned int doorbell;

    doorbell = addr / s->ioregs[BPFHV_REG(DOORBELL_SIZE)];
    if (doorbell >= s->num_queues) {
        DBG("Invalid doorbell write, addr=0x%08"PRIx64, addr);
        return;
    }
    if (doorbell < s->ioregs[BPFHV_REG(NUM_RX_QUEUES)]) {
        DBG("Doorbell RX#%u rung", doorbell);
        /* Immediately disable RX kicks on this queue. */
        sring_rxq_notification(s->rxq[doorbell].ctx, /*enable=*/false);
        /* Guest provided more RX descriptors, which means that
         * bpfhv_can_receive() may return true, hence we need to wake
         * up the backend. */
        qemu_flush_queued_packets(qemu_get_queue(s->nic));
    } else {
        /* We never enter here if BPFHV_TX_IOEVENTFD is defined. */
        doorbell -= s->ioregs[BPFHV_REG(NUM_RX_QUEUES)];
        sring_txq_notification(s->txq[doorbell].ctx, /*enable=*/false);
        DBG("Doorbell TX#%u rung", doorbell);
        qemu_bh_schedule(s->txq[doorbell].bh);
    }
}

static const MemoryRegionOps bpfhv_io_ops = {
    .read = bpfhv_io_read,
    .write = bpfhv_io_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
};

static const MemoryRegionOps bpfhv_dbmmio_ops = {
    .read = NULL, /* this is a write-only region */
    .write = bpfhv_dbmmio_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl = {
	/* These are only limitations of the emulation code, and they are not
	 * visible to the guest, which can still perform larger or shorter
	 * writes. See description of 'impl' and 'valid' fields. */
        .min_access_size = 4,
        .max_access_size = 4,
    },
};

static uint64_t
bpfhv_progmmio_read(void *opaque, hwaddr addr, unsigned size)
{
    BpfHvState *s = opaque;
    unsigned int progsel;
    BpfHvProg *prog;
    uint32_t *readp;

    progsel = s->ioregs[BPFHV_REG(PROG_SELECT)];
    if (progsel <= BPFHV_PROG_NONE || progsel >= BPFHV_PROG_MAX) {
        DBG("Prog I/O read from unselected program, addr=0x%08"PRIx64, addr);
        return 0;
    }

    if (s->doorbell_gva_changed) {
       /* We may need to relocate the programs here. Not needed for now. */
       s->doorbell_gva_changed = false;
    }

    prog = &s->progs[progsel];

    if (addr + size > prog->num_insns * BPF_INSN_SIZE) {
        DBG("Out of bounds prog I/O read, addr=0x%08"PRIx64, addr);
        return 0;
    }

    readp = (uint32_t *)(((uint8_t *)prog->insns) + addr);

    return *readp;
}

static const MemoryRegionOps bpfhv_progmmio_ops = {
    .read = bpfhv_progmmio_read,
    .write = NULL, /* this is a read-only region */
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl = {
	/* These are only limitations of the emulation code, and they are not
	 * visible to the guest, which can still perform larger or shorter
	 * writes. See description of 'impl' and 'valid' fields. */
        .min_access_size = 4,
        .max_access_size = 4,
    },
};

#ifdef BPFHV_MEMLI
static void
bpfhv_memli_begin(MemoryListener *listener)
{
    BpfHvState *s = container_of(listener, BpfHvState, memory_listener);

    s->num_trans_entries_tmp = 0;
    s->trans_entries_tmp = NULL;
}

static void
bpfhv_memli_region_add(MemoryListener *listener,
                       MemoryRegionSection *section)
{
    BpfHvState *s = container_of(listener, BpfHvState, memory_listener);
    uint64_t size = int128_get64(section->size);
    uint64_t gpa_start = section->offset_within_address_space;
    uint64_t gpa_end = range_get_last(gpa_start, size) + 1;
    void *hva_start;
    BpfHvTranslateEntry *last = NULL;
    bool add_entry = true;

    if (!memory_region_is_ram(section->mr)) {
        return;
    }

    hva_start = memory_region_get_ram_ptr(section->mr) +
                      section->offset_within_region;
    if (s->num_trans_entries_tmp > 0) {
        /* Check if we can coalasce the last MemoryRegionSection to
         * the current one. */
        last = s->trans_entries_tmp + s->num_trans_entries_tmp - 1;
        if (gpa_start == last->gpa_end &&
            hva_start == last->hva_start + last->size) {
            add_entry = false;
            last->gpa_end = gpa_end;
            last->size += size;
        }
    }

    if (add_entry) {
        s->num_trans_entries_tmp++;
        s->trans_entries_tmp = g_renew(BpfHvTranslateEntry,
            s->trans_entries_tmp, s->num_trans_entries_tmp);
        last = s->trans_entries_tmp + s->num_trans_entries_tmp - 1;
        last->gpa_start = gpa_start;
        last->gpa_end = gpa_end;
        last->size = size;
        last->hva_start = hva_start;
        last->mr = section->mr;
        memory_region_ref(last->mr);
    }
    DBG("append memory section %lx-%lx sz %lx %p", gpa_start, gpa_end,
        size, hva_start);
}

static void
bpfhv_memli_commit(MemoryListener *listener)
{
    BpfHvState *s = container_of(listener, BpfHvState, memory_listener);
    BpfHvTranslateEntry *old_trans_entries;
    int num_old_trans_entries;
    int i;

    old_trans_entries = s->trans_entries;
    num_old_trans_entries = s->num_trans_entries;
    s->trans_entries = s->trans_entries_tmp;
    s->num_trans_entries = s->num_trans_entries_tmp;

    if (s->trans_entries && old_trans_entries &&
        s->num_trans_entries == num_old_trans_entries &&
        !memcmp(s->trans_entries, old_trans_entries,
                sizeof(s->trans_entries[0]) * s->num_trans_entries)) {
        /* Nothing changed. */
        goto out;
    }

#ifdef BPFHV_DEBUG
    for (i = 0; i < s->num_trans_entries; i++) {
        BpfHvTranslateEntry *te = s->trans_entries + i;
        DBG("entry: gpa %lx-%lx size %lx hva_start %p\n",
            te->gpa_start, te->gpa_end, te->size, te->hva_start);
    }
#endif
out:
    s->trans_entries_tmp = NULL;
    s->num_trans_entries_tmp = 0;
    for (i = 0; i < num_old_trans_entries; i++) {
        BpfHvTranslateEntry *te = old_trans_entries + i;
        memory_region_unref(te->mr);
    }
    g_free(old_trans_entries);
}

static inline void *
bpfhv_translate_addr(BpfHvState *s, uint64_t gpa, uint64_t len)
{
    BpfHvTranslateEntry *te = s->trans_entries + 0;

    if (unlikely(!(te->gpa_start <= gpa && gpa + len <= te->gpa_end))) {
        int i;

        for (i = 1; i < s->num_trans_entries; i++) {
            te = s->trans_entries + i;
            if (te->gpa_start <= gpa && gpa + len <= te->gpa_end) {
                /* Match. Move this entry to the first position. */
                BpfHvTranslateEntry tmp = *te;
                *te = s->trans_entries[0];
                s->trans_entries[0] = tmp;
                te = s->trans_entries + 0;
                break;
            }
        }
        assert(i < s->num_trans_entries);
    }

    return te->hva_start + (gpa - te->gpa_start);

}
#endif /* BPFHV_MEMLI */

void *
bpfhv_mem_map(BpfHvState *s, hwaddr paddr, hwaddr *plen, int is_write)
{
#ifdef BPFHV_MEMLI
    return bpfhv_translate_addr(s, paddr, *plen);
#else  /* !BPFHV_MEMLI */
    return cpu_physical_memory_map(paddr, plen, is_write);
#endif /* !BPFHV_MEMLI */
}

void
bpfhv_mem_unmap(BpfHvState *s, void *buffer, hwaddr len, int is_write)
{
#ifndef BPFHV_MEMLI
    cpu_physical_memory_unmap(buffer, /*len=*/len, is_write,
                              /*access_len=*/len);
#endif /* !BPFHV_MEMLI */
}
static void *
bpfhv_proc_thread(void *opaque)
{
    return NULL;
}

static int
bpfhv_progs_load(BpfHvState *s, const char *progsname, Error **errp)
{
    const char *prog_names[BPFHV_PROG_MAX] = {"none",
                                              "rxp", "rxc", "rxi", "rxr",
                                              "txp", "txc", "txi", "txr"};
    char filename[64];
    GElf_Ehdr ehdr;
    int ret = -1;
    char *path;
    Elf *elf;
    int fd;
    int i;

    for (i = 0; i < BPFHV_PROG_MAX; i++) {
        if (s->progs[i].insns != NULL) {
            g_free(s->progs[i].insns);
            s->progs[i].insns = NULL;
        }
        s->progs[i].num_insns = 0;
    }

    snprintf(filename, sizeof(filename), "bpfhv_%s_progs.o", progsname);
    path = qemu_find_file(QEMU_FILE_TYPE_EBPF, filename);
    if (!path) {
        error_setg(errp, "Could not locate %s", filename);
        return -1;
    }

    fd = open(path, O_RDONLY, 0);
    g_free(path);
    path = NULL;
    if (fd < 0) {
        error_setg_errno(errp, errno, "Failed to open %s", filename);
        return -1;
    }
    if (elf_version(EV_CURRENT) == EV_NONE) {
        error_setg(errp, "ELF version mismatch");
        goto err;
    }
    elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf) {
        error_setg(errp, "Failed to initialize ELF library for %s", filename);
        goto err;
    }

    if (gelf_getehdr(elf, &ehdr) != &ehdr) {
        error_setg(errp, "Failed to get ELF header for %s", filename);
        goto err;
    }

    for (i = 1; i < ehdr.e_shnum; i++) {
        Elf_Data *sdata;
        GElf_Shdr shdr;
        Elf_Scn *scn;
        char *shname;

        scn = elf_getscn(elf, i);
        if (!scn) {
            continue;
        }

        if (gelf_getshdr(scn, &shdr) != &shdr) {
            continue;
        }

        if (shdr.sh_type != SHT_PROGBITS) {
            continue;
        }

        shname = elf_strptr(elf, ehdr.e_shstrndx, shdr.sh_name);
        if (!shname || shdr.sh_size == 0) {
            continue;
        }

        sdata = elf_getdata(scn, NULL);
        if (!sdata || elf_getdata(scn, sdata) != NULL) {
            continue;
        }

        {
            int j;

            for (j = 0; j < ARRAY_SIZE(prog_names); j++) {
                if (!strcmp(shname, prog_names[j])) {
                    break;
                }
            }

            if (j >= ARRAY_SIZE(prog_names)) {
                continue;
            }

            if (s->progs[j].insns != NULL) {
                DBG("warning: %s contains more sections with name %s",
                    filename, prog_names[j]);
                continue;
            }

            s->progs[j].insns = g_malloc(sdata->d_size);
            memcpy(s->progs[j].insns, sdata->d_buf, sdata->d_size);
            s->progs[j].num_insns = sdata->d_size / BPF_INSN_SIZE;
        }
    }

    for (i = BPFHV_PROG_NONE + 1; i < BPFHV_PROG_MAX; i++) {
        if (s->progs[i].insns == NULL || s->progs[i].num_insns == 0) {
            error_setg(errp, "Program %s missing in ELF '%s'",
                       prog_names[i], filename);
            goto err;
        }
    }

    ret = 0;
    elf_end(elf);
    s->progsname = progsname;
err:
    close(fd);

    return ret;
}

static void
pci_bpfhv_realize(PCIDevice *pci_dev, Error **errp)
{
    DeviceState *dev = DEVICE(pci_dev);
    BpfHvState *s = BPFHV(pci_dev);
    unsigned int num_tx_queues;
    unsigned int num_rx_queues;
    NetClientState *nc;
    uint8_t *pci_conf;
    int i;

    pci_conf = pci_dev->config;
    pci_conf[PCI_CACHE_LINE_SIZE] = 0x10;
    pci_conf[PCI_INTERRUPT_PIN] = 1; /* interrupt pin A */

    /* Initializations related to QEMU networking. */
    qemu_macaddr_default_if_unset(&s->conf.macaddr);
    s->nic = qemu_new_nic(&net_bpfhv_info, &s->conf,
                          object_get_typename(OBJECT(s)), dev->id, s);
    nc = qemu_get_queue(s->nic);
    qemu_format_nic_info_str(nc, s->conf.macaddr.a);

    s->vnet_hdr_len = 0;
    s->hv_features = BPFHV_F_SG;
    /* Check if backend supports virtio-net offloadings. */
    if (qemu_has_vnet_hdr(nc->peer) &&
        qemu_has_vnet_hdr_len(nc->peer, sizeof(struct virtio_net_hdr_v1))) {
        bool csum = true;
        bool gso = true;

        if (csum) {
            s->hv_features |= BPFHV_CSUM_FEATURES;
        }
        if (gso) {
            s->hv_features |= BPFHV_GSO_FEATURES;
        }
    }

    /* Initialize device registers. */
    memset(s->ioregs, 0, sizeof(s->ioregs));
    s->ioregs[BPFHV_REG(VERSION)] = BPFHV_VERSION;
    s->ioregs[BPFHV_REG(NUM_RX_QUEUES)] = num_rx_queues = 1;
    s->ioregs[BPFHV_REG(NUM_TX_QUEUES)] = num_tx_queues = 1;
    s->ioregs[BPFHV_REG(NUM_RX_BUFS)] = 256;
    s->ioregs[BPFHV_REG(NUM_TX_BUFS)] = 256;
    s->ioregs[BPFHV_REG(RX_CTX_SIZE)] = sizeof(struct bpfhv_rx_context)
        + sring_rx_ctx_size(s->ioregs[BPFHV_REG(NUM_RX_BUFS)]);
    s->ioregs[BPFHV_REG(TX_CTX_SIZE)] = sizeof(struct bpfhv_tx_context)
        + sring_tx_ctx_size(s->ioregs[BPFHV_REG(NUM_TX_BUFS)]);
    s->ioregs[BPFHV_REG(DOORBELL_SIZE)] = 8; /* could be 4096 */
    s->ioregs[BPFHV_REG(FEATURES)] = s->hv_features;
    s->num_queues = num_rx_queues + num_tx_queues;
    s->doorbell_gva_changed = false;
    s->rx_contexts_ready = s->tx_contexts_ready = false;

    /* Initialize eBPF programs (default implementation). */
    if (bpfhv_progs_load(s, "sring", errp)) {
        return;
    }

    /* Initialize device queues. */
    s->rxq = g_malloc0(num_rx_queues * sizeof(s->rxq[0]));
    s->txq = g_malloc0(num_tx_queues * sizeof(s->txq[0]));
    for (i = 0; i < num_tx_queues; i++) {
#ifdef BPFHV_TX_IOEVENTFD
        int ret;

        /* Init a notifier that runs the TX bottom half code
         * (bpfhv_tx_bh) every time it is triggered. */
        ret = event_notifier_init(&s->txq[i].ioeventfd, 0);
        if (ret) {
            error_setg_errno(errp, errno, "Failed to initialize "
                             "ioeventfd for TX#%d", i);
            return;
        }
        event_notifier_set_handler(&s->txq[i].ioeventfd,
                                   bpfhv_tx_evnotify);
#endif /* BPFHV_TX_IOEVENTFD */

        s->txq[i].bh = qemu_bh_new(bpfhv_tx_bh, s->txq + i);
        s->txq[i].nc = nc;
        s->txq[i].parent = s;
        s->txq[i].vector = s->ioregs[BPFHV_REG(NUM_RX_QUEUES)] + i;
    }

    /* Init I/O mapped memory region, exposing bpfhv registers. */
    memory_region_init_io(&s->regs, OBJECT(s), &bpfhv_io_ops, s,
                          "bpfhv-regs", BPFHV_REG_MASK + 1);
    pci_register_bar(pci_dev, BPFHV_REG_PCI_BAR,
                     PCI_BASE_ADDRESS_SPACE_MEMORY, &s->regs);

    /* Init memory mapped memory region, to expose doorbells. */
    memory_region_init_io(&s->dbmmio, OBJECT(s), &bpfhv_dbmmio_ops, s,
                          "bpfhv-doorbell",
                          s->ioregs[BPFHV_REG(DOORBELL_SIZE)] * s->num_queues);
    pci_register_bar(pci_dev, BPFHV_DOORBELL_PCI_BAR,
                     PCI_BASE_ADDRESS_SPACE_MEMORY, &s->dbmmio);

    /* Init memory mapped memory region, to expose eBPF programs. */
    memory_region_init_io(&s->progmmio, OBJECT(s), &bpfhv_progmmio_ops, s,
                          "bpfhv-prog", BPFHV_PROG_SIZE_MAX * BPF_INSN_SIZE);
    pci_register_bar(pci_dev, BPFHV_PROG_PCI_BAR,
                     PCI_BASE_ADDRESS_SPACE_MEMORY, &s->progmmio);

    /* Allocate a PCI bar to manage MSI-X information for this device. */
    if (msix_init_exclusive_bar(pci_dev, s->num_queues + 1,
                                BPFHV_MSIX_PCI_BAR, NULL)) {
        error_setg(errp, "Failed to initialize MSI-X BAR");
        return;
    }

#ifdef BPFHV_TX_IOEVENTFD
    for (i = 0; i < num_tx_queues; i++) {
        /* Let KVM write into the event notifier, so that when
         * QEMU wakes up it can directly run the TX bottom
         * half, rather then going through, bpfhv_dbmmio_write(). */
        hwaddr dbofs = (num_rx_queues + i)
                     * s->ioregs[BPFHV_REG(DOORBELL_SIZE)];

        memory_region_add_eventfd(&s->dbmmio, dbofs, 4, false, 0,
                                  &s->txq[i].ioeventfd);
    }
#endif /* BPFHV_TX_IOEVENTFD */

    /* Initialize MSI-X interrupts, one per queue. */
    for (i = 0; i < s->num_queues + 1; i++) {
        int ret = msix_vector_use(pci_dev, i);

        if (ret) {
            int j;

            for (j = 0; j < i; j++) {
                msix_vector_unuse(pci_dev, j);
            }
            msix_uninit_exclusive_bar(PCI_DEVICE(s));
            error_setg(errp, "Failed to setup MSIX vector #%d (error=%d)",
                             i, ret);
            return;
        }
    }

#ifdef BPFHV_DEBUG_TIMER
    s->debug_timer = timer_new_ms(QEMU_CLOCK_VIRTUAL, bpfhv_debug_timer, s);
#endif /* BPFHV_DEBUG_TIMER */

#ifdef BPFHV_MEMLI
    /* Support for memory listener. */
    s->memory_listener.priority = 10,
    s->memory_listener.begin = bpfhv_memli_begin,
    s->memory_listener.commit = bpfhv_memli_commit,
    s->memory_listener.region_add = bpfhv_memli_region_add,
    s->memory_listener.region_nop = bpfhv_memli_region_add,
    memory_listener_register(&s->memory_listener, &address_space_memory);
#endif /* BPFHV_MEMLI */

    qemu_thread_create(&s->proc_th, "bpfhv", bpfhv_proc_thread,
                       s, QEMU_THREAD_JOINABLE);
}

static void
pci_bpfhv_uninit(PCIDevice *dev)
{
    BpfHvState *s = BPFHV(dev);
    int i;

    qemu_thread_join(&s->proc_th);

#ifdef BPFHV_MEMLI
    memory_listener_unregister(&s->memory_listener);
#endif /* BPFHV_MEMLI */

#ifdef BPFHV_DEBUG_TIMER
    timer_del(s->debug_timer);
    timer_free(s->debug_timer);
#endif /* BPFHV_DEBUG_TIMER */

    for (i = 0; i < BPFHV_PROG_MAX; i++) {
        if (s->progs[i].insns != NULL) {
            g_free(s->progs[i].insns);
            s->progs[i].insns = NULL;
        }
    }

    for (i = 0; i < s->ioregs[BPFHV_REG(NUM_TX_QUEUES)]; i++) {
#ifdef BPFHV_TX_IOEVENTFD
        hwaddr dbofs = (s->ioregs[BPFHV_REG(NUM_RX_QUEUES)] + i)
                     * s->ioregs[BPFHV_REG(DOORBELL_SIZE)];

        memory_region_del_eventfd(&s->dbmmio, dbofs, 4, false, 0,
                                  &s->txq[i].ioeventfd);
        event_notifier_set_handler(&s->txq[i].ioeventfd, NULL);
        event_notifier_cleanup(&s->txq[i].ioeventfd);
#endif /* BPFHV_TX_IOEVENTFD */
        qemu_bh_delete(s->txq[i].bh);
        s->txq[i].bh = NULL;
    }

    g_free(s->rxq);
    g_free(s->txq);
    for (i = 0; i < s->num_queues + 1; i++) {
        msix_vector_unuse(PCI_DEVICE(s), i);
    }
    msix_uninit_exclusive_bar(PCI_DEVICE(s));
    qemu_del_nic(s->nic);
}

static void qdev_bpfhv_reset(DeviceState *dev)
{
    BpfHvState *s = BPFHV(dev);
    uint8_t *macaddr;

    /* Init MAC address registers. */
    macaddr = s->conf.macaddr.a;
    s->ioregs[BPFHV_REG(MAC_HI)] = (macaddr[0] << 8) | macaddr[1];
    s->ioregs[BPFHV_REG(MAC_LO)] = (macaddr[2] << 24) | (macaddr[3] << 16)
                                 | (macaddr[4] << 8) | macaddr[5];

    DBG("%s(%p)", __func__, s);
}

static const VMStateDescription vmstate_bpfhv = {
    .name = "bpfhv",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (VMStateField[]) {
        VMSTATE_PCI_DEVICE(pci_device, BpfHvState),
        VMSTATE_UINT32(ioregs[0], BpfHvState),
        VMSTATE_END_OF_LIST()
    }
};

static Property bpfhv_properties[] = {
    DEFINE_NIC_PROPERTIES(BpfHvState, conf),
    DEFINE_PROP_END_OF_LIST(),
};

static void bpfhv_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);

    k->realize = pci_bpfhv_realize;
    k->exit = pci_bpfhv_uninit;
    k->vendor_id = BPFHV_PCI_VENDOR_ID;
    k->device_id = BPFHV_PCI_DEVICE_ID;
    k->class_id = PCI_CLASS_NETWORK_ETHERNET;
    set_bit(DEVICE_CATEGORY_NETWORK, dc->categories);
    dc->desc = "BPF network device";
    dc->reset = qdev_bpfhv_reset;
    dc->vmsd = &vmstate_bpfhv;
    dc->props = bpfhv_properties;
}

static void bpfhv_instance_init(Object *obj)
{
    BpfHvState *s = BPFHV(obj);
    device_add_bootindex_property(obj, &s->conf.bootindex,
                                  "bootindex", "/ethernet-phy@0",
                                  DEVICE(s), NULL);
}

static const TypeInfo bpfhv_info = {
    .name          = TYPE_BPFHV_PCI,
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(BpfHvState),
    .instance_init = bpfhv_instance_init,
    .class_init    = bpfhv_class_init,
    .interfaces = (InterfaceInfo[]) {
        { INTERFACE_PCIE_DEVICE },
        { INTERFACE_CONVENTIONAL_PCI_DEVICE },
        { }
    },
};

static void bpfhv_register_types(void)
{
    type_register_static(&bpfhv_info);
}

type_init(bpfhv_register_types)
