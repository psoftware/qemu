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
#include "qemu/cutils.h"
#include "qemu/error-report.h"
#include "qemu/iov.h"
#include "qemu/range.h"
#include "qapi/error.h"
#include "linux/virtio_net.h"

#include <libelf.h>
#include <gelf.h>

#include "bpfhv/bpfhv.h"
#include "bpfhv/sring_hv.h"
#include "bpfhv/netproxy.h"

/*
 * Compile-time tunables.
 */

/* Consume the memory listener interface to get updates about
 * guest memory map. The updates are used to build a translation
 * table to speed up the translation of descriptor addresses
 * (GPA --> HVA). */
#define BPFHV_MEMLI

/* Debug information. Define it as 1 get for basic debugging,
 * and as 2 to get additional (verbose) memory listener logs. */
#define BPFHV_DEBUG 0

/* Periodically issue upgrade interrupts (for debugging). */
#undef  BPFHV_UPGRADE_TIMER
#define BPFHV_UPGRADE_TIMER_MS	10000

/* Debug timer to show ring statistics. */
#undef  BPFHV_DEBUG_TIMER
#define BPFHV_DEBUG_TIMER_MS	2000

/*
 * End of tunables.
 */

#if BPFHV_DEBUG > 0
#define DBG(fmt, ...) do { \
        fprintf(stderr, "bpfhv-pci: " fmt "\n", ## __VA_ARGS__); \
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
    "DUMP_LEN",
    "DUMP_INPUT",
    "DUMP_OFS",
};

#define BPFHV_CSUM_FEATURES (BPFHV_F_TX_CSUM | BPFHV_F_RX_CSUM)

#define BPFHV_GSO_FEATURES (BPFHV_F_TSOv4   | BPFHV_F_TCPv4_LRO \
                           |  BPFHV_F_TSOv6 | BPFHV_F_TCPv6_LRO \
                           |  BPFHV_F_UFO   | BPFHV_F_UDP_LRO)

typedef struct BpfhvProg {
    unsigned int num_insns;
    uint64_t *insns;
} BpfhvProg;

/* Each eBPF instruction is 8 bytes wide. */
#define BPF_INSN_SIZE   8

struct BpfhvState;

typedef struct BpfhvQueue {
    struct BpfhvState *parent;

    union {
        struct bpfhv_tx_context *tx;
        struct bpfhv_rx_context *rx;
    } ctx;

    /* Net client associated to this queue. */
    NetClientState *nc;

    /* Bottom half for I/O thread processing. Only used
     * for TX queues. */
    QEMUBH *bh;

    /* MSI-X vector associated to this queue. */
    unsigned int vector;

    /* For TX queues we let KVM handle the TX kicks in kernelspace,
     * rather than have KVM return to QEMU and QEMU handling the TX
     * kicks. For RX queues this field is only used in case of proxy. */
    EventNotifier ioeventfd;

    /* Information used only in case of proxy. */
    hwaddr ctx_gpa;
    EventNotifier irqfd;
    int virq;

    /* Name of this queue (for debug). */
    char name[8];
} BpfhvQueue;

typedef struct BpfhvTranslateEntry {
    uint64_t gpa_start;
    uint64_t gpa_end;
    uint64_t size;
    void *hva_start;
    MemoryRegion *mr;
} BpfhvTranslateEntry;

typedef struct BpfhvState {
    /* Parent class. This is a private field, and it cannot be used. */
    PCIDevice pci_device;

    NICState *nic;
    NICConf nic_conf;
    MemoryRegion regs;
    MemoryRegion dbmmio;
    MemoryRegion progmmio;

    /* Storage for the I/O registers. */
    uint32_t ioregs[BPFHV_REG_END >> 2];

    /* Total number of queue pairs. For the moment being we assume that
     * we have an equal number of transmit and receive queues. */
    uint32_t num_queue_pairs;

    /* Total number of queues, including both receive and transmit
     * ones (this is twice as num_queue_pairs). */
    uint32_t num_queues;

    /* eBPF programs associated to this device. */
    BpfhvProg progs[BPFHV_PROG_MAX];

    /* True if the guest provided all the receive (or ransmit) contexts. */
    bool rx_contexts_ready;
    bool tx_contexts_ready;

    /* True if the guest changed doorbell GVA, and therefore we may need
     * to relocate the eBPF programs before the guest reads them. */
    bool doorbell_gva_changed;

    BpfhvQueue *q;

    /* Length of the virtio net header that we are using to implement
     * the offloads supported by the backend. */
    int32_t vnet_hdr_len;

    /* The features that we expose to the guest. */
    uint32_t hv_features;

    /* Name of the set of eBPF programs currently in use. */
    char progsname[32];

    /* Name of the set of eBPF programs to load next. */
    char progsname_next[32];

    /* Current dump of queues status to be exposed to the guest. */
    char *curdump;

    /* Tunables exposed to the user. */
    struct {
        uint16_t num_rx_bufs;
        uint16_t num_tx_bufs;
        bool csum;
        bool gso;
    } net_conf;
    uint32_t doorbell_size;

    /* An opaque pointer to the proxy net backend, if present. */
    struct BpfhvProxyState *proxy;

#ifdef BPFHV_MEMLI
    MemoryListener memory_listener;
    BpfhvTranslateEntry *trans_entries;
    unsigned int num_trans_entries;
    BpfhvTranslateEntry *trans_entries_tmp;
    unsigned int num_trans_entries_tmp;
#endif /* BPFHV_MEMLI */

#ifdef BPFHV_DEBUG_TIMER
    QEMUTimer *debug_timer;
#endif /* BPFHV_DEBUG_TIMER */

#ifdef BPFHV_UPGRADE_TIMER
    QEMUTimer *upgrade_timer;
#endif /* BPFHV_UPGRADE_TIMER */

} BpfhvState;

/* Macros to iterate over RX or TX queues. */
#define RXI_BEGIN(_s)   0
#define RXI_END(_s)     (_s)->num_queue_pairs
#define TXI_BEGIN(_s)   (_s)->num_queue_pairs
#define TXI_END(_s)     (_s)->num_queues
#define BRXQ(_s, _idx)  (&(_s)->q[_idx])
#define BTXQ(_s, _idx)  (&(_s)->q[TXI_BEGIN(_s) + (_idx)])

/* Macro to generate I/O register indices. */
#define BPFHV_REG(x) ((BPFHV_REG_ ## x) >> 2)

#define TYPE_BPFHV_PCI  "bpfhv-pci"

#define BPFHV(obj) \
            OBJECT_CHECK(BpfhvState, (obj), TYPE_BPFHV_PCI)

static char *
bpfhv_dump_realloc(char *tot, size_t *totlen, const char *append)
{
    if (strlen(tot) + strlen(append) >= *totlen) {
        *totlen += strlen(append) * 2;
        tot = g_realloc(tot, *totlen);
    }

    return tot;
}

static char *
bpfhv_dump_string(BpfhvState *s)
{
    char *result = NULL;
    size_t totlen = 64;
    int i;

    assert(s->proxy == NULL);

    result = g_realloc(result, totlen);
    result[0] = '\0';

    if (s->rx_contexts_ready) {
        for (i = RXI_BEGIN(s); i < RXI_END(s); i++) {
            char *dump = sring_rxq_dump(s->q[i].ctx.rx);
            result = bpfhv_dump_realloc(result, &totlen, dump);
            pstrcat(result, totlen, dump);
            g_free(dump);
        }
    }

    if (s->tx_contexts_ready) {
        for (i = TXI_BEGIN(s); i < TXI_END(s); i++) {
            char *dump = sring_txq_dump(s->q[i].ctx.tx);
            result = bpfhv_dump_realloc(result, &totlen, dump);
            pstrcat(result, totlen, dump);
            g_free(dump);
        }
    }

    memset(result + strlen(result), 0, totlen - strlen(result));

    return result;
}

static char *
bpfhv_progpath(const char *progsname)
{
    char filename[64];

    snprintf(filename, sizeof(filename), "bpfhv_%s_progs.o", progsname);

    return qemu_find_file(QEMU_FILE_TYPE_EBPF, filename);
}

#ifdef BPFHV_DEBUG_TIMER
static void
bpfhv_debug_timer(void *opaque)
{
    BpfhvState *s = opaque;
    char *dump;

    assert(s->proxy == NULL);

    dump = bpfhv_dump_string(s);
    printf("%s", dump);
    g_free(dump);

    timer_mod(s->debug_timer, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) +
              BPFHV_DEBUG_TIMER_MS);
}
#endif /* BPFHV_DEBUG_TIMER */

#ifdef BPFHV_UPGRADE_TIMER
static void
bpfhv_upgrade_timer(void *opaque)
{
    BpfhvState *s = opaque;

    assert(s->proxy == NULL);

    /* Trigger program change (oscillating between no offloads,
     * CSUM offloads and CSUM+GSO offloads). */
    if (!strcmp(s->progsname, "sring") &&
        (s->hv_features & BPFHV_CSUM_FEATURES) == BPFHV_CSUM_FEATURES) {
        pstrcpy(s->progsname_next, sizeof(s->progsname_next), "sringcsum");
        s->ioregs[BPFHV_REG(FEATURES)] = BPFHV_F_SG | BPFHV_CSUM_FEATURES;
    } else if (!strcmp(s->progsname, "sringcsum") &&
               (s->hv_features & BPFHV_GSO_FEATURES) == BPFHV_GSO_FEATURES &&
               (s->hv_features & BPFHV_CSUM_FEATURES) == BPFHV_CSUM_FEATURES) {
        pstrcpy(s->progsname_next, sizeof(s->progsname_next), "sringgso");
        s->ioregs[BPFHV_REG(FEATURES)] = s->hv_features;
    } else if (!strcmp(s->progsname, "sringgso")) {
        pstrcpy(s->progsname_next, sizeof(s->progsname_next), "sring");
        s->ioregs[BPFHV_REG(FEATURES)] = BPFHV_F_SG;
    }

    /* Pretend an upgrade happened and inform the guest about that. */
    s->ioregs[BPFHV_REG(STATUS)] |= BPFHV_STATUS_UPGRADE;
    msix_notify(PCI_DEVICE(s), s->num_queues);

    timer_mod(s->upgrade_timer, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) +
              BPFHV_UPGRADE_TIMER_MS);
}
#endif /* BPFHV_UPGRADE_TIMER */

static int
bpfhv_progs_load_fd(BpfhvState *s, int fd, const char *progsname,
                    const char *path, Error **errp)
{
    const char *prog_names[BPFHV_PROG_MAX] = {"none",
                                              "rxp", "rxc", "rxi", "rxr",
                                              "txp", "txc", "txi", "txr"};
    GElf_Ehdr ehdr;
    int ret = -1;
    Elf *elf;
    int i;

    for (i = 0; i < BPFHV_PROG_MAX; i++) {
        if (s->progs[i].insns != NULL) {
            g_free(s->progs[i].insns);
            s->progs[i].insns = NULL;
        }
        s->progs[i].num_insns = 0;
    }

    if (elf_version(EV_CURRENT) == EV_NONE) {
        error_setg(errp, "ELF version mismatch");
        return -1;
    }
    elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf) {
        error_setg(errp, "Failed to initialize ELF library for %s", path);
        return -1;
    }

    if (gelf_getehdr(elf, &ehdr) != &ehdr) {
        error_setg(errp, "Failed to get ELF header for %s", path);
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
                    path, prog_names[j]);
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
                       prog_names[i], path);
            goto err;
        }
    }

    ret = 0;
    pstrcpy(s->progsname, sizeof(s->progsname), progsname);
    DBG("Loaded program: %s", s->progsname);
err:
    elf_end(elf);

    return ret;
}

static int
bpfhv_progs_load(BpfhvState *s, const char *progsname, Error **errp)
{
    int ret = -1;
    char *path;
    int fd;

    if (!strncmp(progsname, s->progsname, sizeof(s->progsname))) {
        return 0;
    }

    path = bpfhv_progpath(progsname);
    if (!path) {
        error_setg(errp, "Could not locate bpfhv_%s_progs.o", progsname);
        return -1;
    }

    fd = open(path, O_RDONLY, 0);
    if (fd < 0) {
        error_setg_errno(errp, errno, "Failed to open %s", path);
        goto err;
    }

    ret = bpfhv_progs_load_fd(s, fd, progsname, path, errp);
    close(fd);
err:
    g_free(path);

    return ret;
}

/* Do most of the setup with the backend process. Only skip setting
 * the queue context, because that causes the backend process to
 * reinitialize the private context, and we want to do that only when
 * the guest is not using it. */
static int
bpfhv_proxy_reinit(BpfhvState *s, Error **errp)
{
    const char *progpath = "bpfhv_proxy_progs.o";
    size_t rx_ctx_size, tx_ctx_size;
    uint64_t be_features;
    int progfd;
    uint32_t i;
    int ret;

    if (bpfhv_proxy_get_features(s->proxy, &be_features)) {
        error_setg(errp, "Failed to get proxy features");
        return -1;
    }
    s->hv_features = be_features & 0xffffffff;

    /* We set the features in case they did not change so the
     * guest won't write to the features register. */
    if (bpfhv_proxy_set_features(s->proxy,
            s->hv_features & s->ioregs[BPFHV_REG(FEATURES)])) {
        error_setg(errp, "Failed to set proxy features");
        return -1;
    }

    if (bpfhv_proxy_set_parameters(s->proxy, s->net_conf.num_rx_bufs,
                                   s->net_conf.num_tx_bufs, &rx_ctx_size,
                                   &tx_ctx_size)) {
        error_setg(errp, "Failed to set proxy parameters");
        return -1;
    }

    s->ioregs[BPFHV_REG(RX_CTX_SIZE)] = rx_ctx_size;
    s->ioregs[BPFHV_REG(TX_CTX_SIZE)] = tx_ctx_size;

    progfd = bpfhv_proxy_get_programs(s->proxy);
    if (progfd < 0) {
        error_setg(errp, "Failed to get proxy programs");
        return -1;
    }

    ret = bpfhv_progs_load_fd(s, progfd, "proxy", progpath, errp);
    close(progfd);
    if (ret) {
        return ret;
    }

    for (i = 0; i < s->num_queues; i++) {
        int kickfd = event_notifier_get_fd(&s->q[i].ioeventfd);
        int irqfd = event_notifier_get_fd(&s->q[i].irqfd);

        if (bpfhv_proxy_set_queue_kickfd(s->proxy, i, kickfd)) {
            error_setg(errp, "Failed to set queue %s kickfd to "
                       "%d", s->q[i].name, kickfd);
            return -1;
        }

        if (s->q[i].virq < 0) {
            /* Irqfd not ready. */
            irqfd = -1;
        }

        ret = bpfhv_proxy_set_queue_irqfd(s->proxy, /*queue_idx=*/i,
                                          irqfd);
        if (ret) {
            error_report("Failed to set queue %s irqfd to %d",
                         s->q[i].name, irqfd);
        }
    }

    return 0;
}

static int
bpfhv_can_receive(NetClientState *nc)
{
    BpfhvState *s = qemu_get_nic_opaque(nc);
    BpfhvQueue *rxq;

    if (unlikely(s->proxy != NULL)) {
        /* For some reason this is called even if the proxy peer never
         * sends anything. */
        return false;
    }

    if (unlikely(!(s->ioregs[BPFHV_REG(STATUS)] & BPFHV_STATUS_RX_ENABLED))) {
        return false;
    }

    rxq = BRXQ(s, nc->queue_index);

    if (sring_can_receive(rxq->ctx.rx)) {
        return true;
    }

    /* We don't have enough RX descriptors, and thus we need to enable
     * RX kicks on this queue. */
    sring_rxq_notification(rxq->ctx.rx, /*enable=*/true);

    return false;
}

static ssize_t
bpfhv_receive_iov(NetClientState *nc, const struct iovec *iov, int iovcnt)
{
    BpfhvState *s = qemu_get_nic_opaque(nc);
    BpfhvQueue *rxq;
    bool notify;
    ssize_t ret;

    assert(s->proxy == NULL);

    if (unlikely(!(s->ioregs[BPFHV_REG(STATUS)] & BPFHV_STATUS_RX_ENABLED))) {
        /* This should never happen, because we exported the can_receive
         * method. */
        return 0;
    }

    rxq = BRXQ(s, nc->queue_index);

    ret = sring_receive_iov(s, rxq->ctx.rx, iov, iovcnt, s->vnet_hdr_len,
                            &notify);
    if (ret > 0 && notify) {
        msix_notify(PCI_DEVICE(s), nc->queue_index);
    }

    return ret;
}

/* Device link status is up iff all the receive contexts are valid and
 * the network backend link status is up. */
static void
bpfhv_link_status_update(BpfhvState *s)
{
    bool status = !!(s->ioregs[BPFHV_REG(STATUS)] & BPFHV_STATUS_LINK);
    NetClientState *nc = qemu_get_queue(s->nic);
    bool new_status;
    unsigned int i;

    new_status = !(nc->link_down) && s->rx_contexts_ready;
    if (new_status == status) {
        return;
    }

    DBG("Link status goes %s", new_status ? "up" : "down");
    s->ioregs[BPFHV_REG(STATUS)] ^= BPFHV_STATUS_LINK;
    if (new_status) {
        if (!s->proxy) {
            /* Link status goes up, which means that bpfhv_can_receive()
             * may return true, hence we need to wake up the backend. */
            for (i = RXI_BEGIN(s); i < RXI_END(s); i++) {
                qemu_flush_queued_packets(s->q[i].nc);
            }
        }
#ifdef BPFHV_DEBUG_TIMER
        if (s->debug_timer) {
            timer_mod(s->debug_timer, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) +
                                      BPFHV_DEBUG_TIMER_MS);
        }
#endif /* BPFHV_DEBUG_TIMER */
#ifdef BPFHV_UPGRADE_TIMER
        if (s->upgrade_timer) {
            timer_mod(s->upgrade_timer, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) +
                                        BPFHV_UPGRADE_TIMER_MS);
        }
#endif /* BPFHV_UPGRADE_TIMER */
    } else {
        if (!s->proxy) {
            /* Link status goes down, so we stop the transmit bottom halves
             * and purge any packets queued for receive. */
            for (i = TXI_BEGIN(s); i < TXI_END(s); i++) {
                qemu_bh_cancel(s->q[i].bh);
                qemu_purge_queued_packets(s->q[i].nc);
            }
        }
#ifdef BPFHV_DEBUG_TIMER
        if (s->debug_timer) {
            timer_del(s->debug_timer);
        }
#endif /* BPFHV_DEBUG_TIMER */
#ifdef BPFHV_UPGRADE_TIMER
        if (s->upgrade_timer) {
            timer_del(s->upgrade_timer);
        }
#endif /* BPFHV_UPGRADE_TIMER */
    }
}

static void
bpfhv_backend_link_status_changed(NetClientState *nc)
{
    BpfhvState *s = qemu_get_nic_opaque(nc);

    /* In case of proxy, link going up means that the backend
     * process just reconnected (or signalled that an upgrade
     * is necessary). */
    if (s->proxy && !nc->link_down) {
        Error *local_err = NULL;

        if (bpfhv_proxy_reinit(s, &local_err)) {
            error_propagate(&error_fatal, local_err);
            return;
        }
        s->ioregs[BPFHV_REG(STATUS)] |= BPFHV_STATUS_UPGRADE;
        msix_notify(PCI_DEVICE(s), s->num_queues);
    }

    bpfhv_link_status_update(s);
}

static NetClientInfo net_bpfhv_info = {
    .type = NET_CLIENT_DRIVER_NIC,
    .size = sizeof(NICState),
    .can_receive = bpfhv_can_receive,
    .receive_iov = bpfhv_receive_iov,
    .link_status_changed = bpfhv_backend_link_status_changed,
};

static int
bpfhv_guest_notifiers_init(BpfhvState *s)
{
    uint32_t i;

    assert(s->proxy != NULL);

    for (i = 0; i < s->num_queues; i++) {
        /* Setup KVM irqfd, using an MSI-X entry and the eventfd
         * associated to this queue. */
        unsigned int vector = s->q[i].vector;
        int fd = event_notifier_get_fd(&s->q[i].irqfd);
        int virq = -1;
        int ret;

        msix_vector_use(PCI_DEVICE(s), vector);

        virq = kvm_irqchip_add_msi_route(kvm_state, vector, PCI_DEVICE(s));
        if (virq < 0) {
            error_report("kvm_irqchip_add_msi_route() failed: %s",
                         strerror(-virq));
            return -1;
        }

        ret = kvm_irqchip_add_irqfd_notifier_gsi(kvm_state, &s->q[i].irqfd,
                                                 NULL, virq);
        if (ret) {
            kvm_irqchip_release_virq(kvm_state, virq);
            error_report("kvm_irqchip_add_irqfd_notifier_gsi() "
                         "failed: %s", strerror(-ret));
            return -1;
        }

        s->q[i].virq = virq;

        ret = bpfhv_proxy_set_queue_irqfd(s->proxy, /*queue_idx=*/i, fd);
        if (ret) {
            error_report("Failed to set queue %s irqfd to %d",
                         s->q[i].name, fd);
        }
    }

    return 0;
}

static int
bpfhv_guest_notifiers_fini(BpfhvState *s)
{
    uint32_t i;

    assert(s->proxy != NULL);

    for (i = 0; i < s->num_queues; i++) {
        unsigned int vector = s->q[i].vector;
        int fd = -1;
        int ret;

        if (s->q[i].virq == -1) {
            continue;  /* Not initialized, nothing to do. */
        }

        ret = bpfhv_proxy_set_queue_irqfd(s->proxy, /*queue_idx=*/i, fd);
        if (ret) {
            error_report("Failed to set queue %s irqfd to %d",
                         s->q[i].name, fd);
        }

        ret = kvm_irqchip_remove_irqfd_notifier_gsi(kvm_state, &s->q[i].irqfd,
                                                    s->q[i].virq);
        if (ret) {
            error_report("kvm_irqchip_remove_irqfd_notifier_gsi() failed: %s",
                         strerror(-ret));
        }

        kvm_irqchip_release_virq(kvm_state, s->q[i].virq);
        s->q[i].virq = -1;
        msix_vector_unuse(PCI_DEVICE(s), vector);
    }

    return 0;
}

static void
bpfhv_ctrl_update(BpfhvState *s, uint32_t cmd)
{
    /* Was RX/TX enabled before this operation ? */
    bool rx_enabled = (s->ioregs[BPFHV_REG(STATUS)] & BPFHV_STATUS_RX_ENABLED);
    bool tx_enabled = (s->ioregs[BPFHV_REG(STATUS)] & BPFHV_STATUS_TX_ENABLED);
    /* Is this command asking to enable RX/TX ? */
    bool rx_enable = (cmd & BPFHV_CTRL_RX_ENABLE);
    bool rx_disable = (cmd & BPFHV_CTRL_RX_DISABLE);
    /* Is this command asking to disable RX/TX ? */
    bool tx_enable = (cmd & BPFHV_CTRL_TX_ENABLE);
    bool tx_disable = (cmd & BPFHV_CTRL_TX_DISABLE);
    int i;

    if (s->proxy && !(rx_enabled && tx_enabled) &&
        (rx_enabled || rx_enable) && (tx_enabled || tx_enable)) {
        /* With this operation, both TX and RX will become enabled.
         * We assume that the guest completed its MSI-X setup
         * at this point (or in the other call site below).
         * TODO We should intercept modifications to the MSI-X
         * table, e.g., like ivshmem_write_config(), calling
         * msix_set_vector_notifiers().*/
        bpfhv_guest_notifiers_init(s);
    }

    if (!rx_enabled && rx_enable) {
        /* Guest asked to enable receive operation. We can accept
         * that only if all the receive contexts are present. */
        if (s->rx_contexts_ready) {
            /* Set the status bit before flushing queued packets,
             * otherwise can_receive will return false. */
            s->ioregs[BPFHV_REG(STATUS)] |= BPFHV_STATUS_RX_ENABLED;
            if (s->proxy) {
                bpfhv_proxy_enable(s->proxy, /*is_rx=*/true, /*enable=*/true);
            } else {
                for (i = RXI_BEGIN(s); i < RXI_END(s); i++) {
                    sring_rxq_notification(s->q[i].ctx.rx, /*enable=*/true);
                    /* Guest enabled receive operation, which means that
                     * bpfhv_can_receive() may return true, hence we need
                     * to wake up the backend. */
                    qemu_flush_queued_packets(s->q[i].nc);
                }
            }
            DBG("Receive enabled");
        }
    }

    if (rx_enabled && rx_disable) {
        /* Guest asked to disable receive operation. */
        s->ioregs[BPFHV_REG(STATUS)] &= ~BPFHV_STATUS_RX_ENABLED;
        if (s->proxy) {
            bpfhv_proxy_enable(s->proxy, /*is_rx=*/true, /*enable=*/false);
        }
        DBG("Receive disabled");
    }

    if (!tx_enabled && tx_enable) {
        /* Guest asked to enable transmit operation. We can accept
         * that only if all the transmit contexts are present. */
        if (s->tx_contexts_ready) {
            s->ioregs[BPFHV_REG(STATUS)] |= BPFHV_STATUS_TX_ENABLED;
            if (s->proxy) {
                bpfhv_proxy_enable(s->proxy, /*is_rx=*/false, /*enable=*/true);
            } else {
                for (i = TXI_BEGIN(s); i < TXI_END(s); i++) {
                    qemu_bh_schedule(s->q[i].bh);
                }
            }
            DBG("Transmit enabled");
        }
    }

    if (tx_enabled && tx_disable) {
        if (s->proxy) {
            bpfhv_proxy_enable(s->proxy, /*is_rx=*/false, /*enable=*/false);
        } else {
            /* Guest asked to disable transmit operation, so we need to stop the
             * bottom halves and clear the TX_ENABLED status bit.
             * Before doing that, we drain the transmit queues to avoid dropping
             * guest packets. */
            for (i = TXI_BEGIN(s); i < TXI_END(s); i++) {
                bool notify;

                sring_txq_drain(s, s->q[i].nc, s->q[i].ctx.tx, /*callback=*/NULL,
                                s->vnet_hdr_len, &notify);
                qemu_bh_cancel(s->q[i].bh);
            }
        }
        s->ioregs[BPFHV_REG(STATUS)] &= ~BPFHV_STATUS_TX_ENABLED;
        DBG("Transmit disabled");
    }

    if (s->proxy && (rx_enabled || tx_enabled) &&
            (!rx_enabled || rx_disable) && (!tx_enabled || tx_disable)) {
        /* With this operation, both TX and RX will become disabled. */
        bpfhv_guest_notifiers_fini(s);
    }

    if (cmd & BPFHV_CTRL_UPGRADE_READY) {
        /* Guest says it is ready to upgrade. */
        if (!(s->ioregs[BPFHV_REG(STATUS)] & BPFHV_STATUS_UPGRADE)) {
            /* No upgrade is pending, hence we ignore this request. */
        } else {
            Error *local_err = NULL;

            /* Perform the upgrade and clear the status bit. We currently
             * do not recover from upgrade failure. */
            if (!s->proxy) {
                if (bpfhv_progs_load(s, s->progsname_next, &local_err)) {
                    error_propagate(&error_fatal, local_err);
                    return;
                }
            }
            s->ioregs[BPFHV_REG(STATUS)] &= ~BPFHV_STATUS_UPGRADE;
        }
    }

    if ((cmd & BPFHV_CTRL_QUEUES_DUMP) && !s->proxy) {
        if (s->curdump != NULL) {
            g_free(s->curdump);
        }
        s->curdump = bpfhv_dump_string(s);
        s->ioregs[BPFHV_REG(DUMP_LEN)] = strlen(s->curdump) + 1;
    }
}

static void
bpfhv_ctx_remap(BpfhvState *s)
{
    unsigned int qsel = s->ioregs[BPFHV_REG(QUEUE_SELECT)];
    bool rx = false;
    hwaddr base, len;
    void **pvaddr;

    base = (((uint64_t)s->ioregs[BPFHV_REG(CTX_PADDR_HI)]) << 32ULL) |
                    (uint64_t)s->ioregs[BPFHV_REG(CTX_PADDR_LO)];

    if (s->proxy) {
        if (bpfhv_proxy_set_queue_ctx(s->proxy, qsel, base)) {
            error_report("Failed to set queue %s context gpa to %"PRIx64"",
                         s->q[qsel].name, base);
        }
    }

    s->q[qsel].ctx_gpa = base;
    pvaddr = (void **)&s->q[qsel].ctx;

    if (qsel < s->num_queue_pairs) {
        len = s->ioregs[BPFHV_REG(RX_CTX_SIZE)];
        rx = true;
    } else {
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
        DBG("Queue %s GPA %llx (%llu) mapped at HVA %p", s->q[qsel].name,
            (unsigned long long)base, (unsigned long long)len, *pvaddr);

        if (!s->proxy) {
            /* In case of no proxy also initialize the hypervisor-specific
             * part of the context. */
            if (rx) {
                sring_rx_ctx_init(s->q[qsel].ctx.rx,
                        s->ioregs[BPFHV_REG(NUM_RX_BUFS)]);
            } else {
                sring_tx_ctx_init(s->q[qsel].ctx.tx,
                        s->ioregs[BPFHV_REG(NUM_TX_BUFS)]);
            }
        }
    }

    /* Update rx_contexts_ready and tx_contexts_ready. */
    if (rx) {
        int i;

        s->rx_contexts_ready = true;
        for (i = RXI_BEGIN(s); i < RXI_END(s); i++) {
            if (s->q[i].ctx.rx == NULL) {
                s->rx_contexts_ready = false;
                break;
            }
        }

        /* Possibly update link status, which depends on
         * rx_contexts_ready. */
        bpfhv_link_status_update(s);
    } else {
        int i;

        s->tx_contexts_ready = true;
        for (i = TXI_BEGIN(s); i < TXI_END(s); i++) {
            if (s->q[i].ctx.tx == NULL) {
                s->tx_contexts_ready = false;
                break;
            }
        }
    }
}

static void
bpfhv_io_write(void *opaque, hwaddr addr, uint64_t val, unsigned size)
{
    BpfhvState *s = opaque;
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
        NetClientState *peer0 = qemu_get_queue(s->nic)->peer;
        Error *local_err = NULL;
        const char *progsname;

        /* Check that 'val' is a subset of s->hv_features. */
        if ((s->hv_features | val) != s->hv_features) {
            DBG("Driver tried to select features unknown to the hv");
            break;
        }

        if (s->proxy) {
            if (bpfhv_proxy_set_features(s->proxy, val)) {
                error_setg(&local_err, "Failed to set proxy features");
                error_propagate(&error_fatal, local_err);
                return;
            }
        } else {
            /* Configure virtio-net header and offloads in the backend,
             * depending on the features activated by the guest. */
            unsigned int i;
            bool csum, gso;

            csum = val & BPFHV_CSUM_FEATURES;
            gso = val & BPFHV_GSO_FEATURES;
            s->vnet_hdr_len = (csum || gso) ? sizeof(struct virtio_net_hdr_v1) : 0;
            if ((s->vnet_hdr_len == 0 &&
                peer0->info->type == NET_CLIENT_DRIVER_TAP)) {
                /* The tap backend does not support removing the virtio-net
                 * header once it has been set. However, we can unnegotiate
                 * the header --> qemu_using_vnet_hdr(peer, false). */
            } else {
                for (i = 0; i < s->num_queue_pairs; i++) {
                    qemu_set_vnet_hdr_len(qemu_get_subqueue(s->nic, i)->peer,
                                          s->vnet_hdr_len);
                }
            }
            for (i = 0; i < s->num_queue_pairs; i++) {
                qemu_using_vnet_hdr(qemu_get_subqueue(s->nic, i)->peer,
                                    s->vnet_hdr_len != 0);
            }
            qemu_set_offload(peer0, /*csum=*/csum, /*tso4=*/gso,
                             /*tso6=*/gso, /*ecn=*/false, /*ufo=*/gso);

            /* Load the corresponding eBPF programs. */
            progsname = gso ? "sringgso" : (csum ? "sringcsum" : "sring");
            if (bpfhv_progs_load(s, progsname, &local_err)) {
                error_propagate(&error_fatal, local_err);
                return;
            }
        }

        /* Update the features register. */
        s->ioregs[index] = val;
        break;
    }

    case BPFHV_REG_DUMP_OFS:
        if (val >= s->ioregs[BPFHV_REG(DUMP_LEN)]) {
            DBG("Driver tried to set out of bounds dump offset %lu", val);
            break;
        }
        val &= ~((hwaddr)3);
        s->ioregs[index] = val;
        assert(s->curdump != NULL);
        s->ioregs[BPFHV_REG(DUMP_INPUT)] = *((uint32_t *)(s->curdump + val));
        break;

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
    BpfhvState *s = opaque;
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
    BpfhvState *s = qemu_get_nic_opaque(nc);
    int i;

    if (!(s->ioregs[BPFHV_REG(STATUS)] & BPFHV_STATUS_TX_ENABLED)) {
        return;
    }

    for (i = TXI_BEGIN(s); i < TXI_END(s); i++) {
        bool notify;

        sring_txq_notification(s->q[i].ctx.tx, /*enable=*/true);

        sring_txq_drain(s, nc, s->q[i].ctx.tx, bpfhv_tx_complete,
                        s->vnet_hdr_len, &notify);
        if (notify) {
	    msix_notify(PCI_DEVICE(s), s->q[i].vector);
        }
    }
}

static void
bpfhv_tx_bh(void *opaque)
{
    BpfhvQueue *txq = opaque;
    BpfhvState *s = txq->parent;
    bool notify;
    ssize_t ret;

    if (!(s->ioregs[BPFHV_REG(STATUS)] & BPFHV_STATUS_TX_ENABLED)) {
        return;
    }

    ret = sring_txq_drain(s, txq->nc, txq->ctx.tx, bpfhv_tx_complete,
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
    sring_txq_notification(txq->ctx.tx, /*enable=*/true);
    ret = sring_txq_drain(s, txq->nc, txq->ctx.tx, bpfhv_tx_complete,
                          s->vnet_hdr_len, &notify);
    if (notify) {
	    msix_notify(PCI_DEVICE(s), txq->vector);
    }
    if (ret == -EINVAL) {
        return;
    } else if (ret > 0) {
        sring_txq_notification(txq->ctx.tx, /*enable=*/false);
        qemu_bh_schedule(txq->bh);
    }
}

static void
bpfhv_tx_evnotify(EventNotifier *ioeventfd)
{
    BpfhvQueue *txq = container_of(ioeventfd, BpfhvQueue, ioeventfd);

    if (unlikely(!event_notifier_test_and_clear(ioeventfd))) {
        return;
    }
    bpfhv_tx_bh(txq);
}

static void
bpfhv_dbmmio_write(void *opaque, hwaddr addr, uint64_t val, unsigned size)
{
    BpfhvState *s = opaque;
    unsigned int doorbell;

    doorbell = addr / s->doorbell_size;
    if (doorbell >= s->num_queues) {
        DBG("Invalid doorbell write, addr=0x%08"PRIx64, addr);
        return;
    }

    /* In case of proxy all the kicks must be diverted to a separate
     * process, thus we cannot get here. */
    assert(s->proxy == NULL);

    if (doorbell < s->num_queue_pairs) {
        DBG("Doorbell RX#%u rung", doorbell);
        /* Immediately disable RX kicks on this queue. */
        sring_rxq_notification(s->q[doorbell].ctx.rx, /*enable=*/false);
        /* Guest provided more RX descriptors, which means that
         * bpfhv_can_receive() may return true, hence we need to wake
         * up the backend. */
        qemu_flush_queued_packets(s->q[doorbell].nc);
    } else {
        /* We never enter here if because we use the ioeventfd approach
         * (bpfhv_tx_evnotify). */
        assert(false);
        sring_txq_notification(s->q[doorbell].ctx.tx, /*enable=*/false);
        DBG("Doorbell TX#%u rung", doorbell);
        qemu_bh_schedule(s->q[doorbell].bh);
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
    BpfhvState *s = opaque;
    unsigned int progsel;
    BpfhvProg *prog;
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
    BpfhvState *s = container_of(listener, BpfhvState, memory_listener);

    s->num_trans_entries_tmp = 0;
    s->trans_entries_tmp = NULL;
}

static void
bpfhv_memli_region_add(MemoryListener *listener,
                       MemoryRegionSection *section)
{
    BpfhvState *s = container_of(listener, BpfhvState, memory_listener);
    uint64_t size = int128_get64(section->size);
    uint64_t gpa_start = section->offset_within_address_space;
    uint64_t gpa_end = range_get_last(gpa_start, size) + 1;
    void *hva_start;
    BpfhvTranslateEntry *last = NULL;
    bool add_entry = true;

    if (!memory_region_is_ram(section->mr)) {
        return;
    }

    hva_start = memory_region_get_ram_ptr(section->mr) +
                      section->offset_within_region;
#if BPFHV_DEBUG > 1
    DBG("new memory section %lx-%lx sz %lx %p", gpa_start, gpa_end,
        size, hva_start);
#endif
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
        s->trans_entries_tmp = g_renew(BpfhvTranslateEntry,
            s->trans_entries_tmp, s->num_trans_entries_tmp);
        last = s->trans_entries_tmp + s->num_trans_entries_tmp - 1;
        last->gpa_start = gpa_start;
        last->gpa_end = gpa_end;
        last->size = size;
        last->hva_start = hva_start;
        last->mr = section->mr;
        memory_region_ref(last->mr);
    }
}

static void
bpfhv_memli_commit(MemoryListener *listener)
{
    BpfhvState *s = container_of(listener, BpfhvState, memory_listener);
    BpfhvTranslateEntry *old_trans_entries;
    int num_old_trans_entries;
    int i;

    old_trans_entries = s->trans_entries;
    num_old_trans_entries = s->num_trans_entries;
    s->trans_entries = s->trans_entries_tmp;
    s->num_trans_entries = s->num_trans_entries_tmp;

#if BPFHV_DEBUG > 1
    for (i = 0; i < s->num_trans_entries; i++) {
        BpfhvTranslateEntry *te = s->trans_entries + i;
        DBG("    entry %d: gpa %lx-%lx size %lx hva_start %p", i,
            te->gpa_start, te->gpa_end, te->size, te->hva_start);
    }
#endif

    s->trans_entries_tmp = NULL;
    s->num_trans_entries_tmp = 0;
    for (i = 0; i < num_old_trans_entries; i++) {
        BpfhvTranslateEntry *te = old_trans_entries + i;
        memory_region_unref(te->mr);
    }
    g_free(old_trans_entries);
}

static inline void *
bpfhv_translate_addr(BpfhvState *s, uint64_t gpa, uint64_t len)
{
    BpfhvTranslateEntry *te = s->trans_entries + 0;

    if (unlikely(!(te->gpa_start <= gpa && gpa + len <= te->gpa_end))) {
        int i;

        for (i = 1; i < s->num_trans_entries; i++) {
            te = s->trans_entries + i;
            if (te->gpa_start <= gpa && gpa + len <= te->gpa_end) {
                /* Match. Move this entry to the first position. */
                BpfhvTranslateEntry tmp = *te;
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
bpfhv_mem_map(BpfhvState *s, hwaddr paddr, hwaddr *plen, int is_write)
{
#ifdef BPFHV_MEMLI
    return bpfhv_translate_addr(s, paddr, *plen);
#else  /* !BPFHV_MEMLI */
    return cpu_physical_memory_map(paddr, plen, is_write);
#endif /* !BPFHV_MEMLI */
}

void
bpfhv_mem_unmap(BpfhvState *s, void *buffer, hwaddr len, int is_write)
{
#ifndef BPFHV_MEMLI
    cpu_physical_memory_unmap(buffer, /*len=*/len, is_write,
                              /*access_len=*/len);
#endif /* !BPFHV_MEMLI */
}

static bool
bpfhv_num_bufs_validate(unsigned int num_bufs)
{
    if (num_bufs < 16 || num_bufs > 8192 ||
            (num_bufs & (num_bufs - 1)) != 0) {
        return false;
    }
    return true;
}

static bool
bpfhv_doorbell_size_validate(unsigned int db_size)
{
    if (db_size < 8 || db_size > (1 << 21) ||
            (db_size & (db_size - 1)) != 0) {
        return false;
    }
    return true;
}

static void
pci_bpfhv_realize(PCIDevice *pci_dev, Error **errp)
{
    DeviceState *dev = DEVICE(pci_dev);
    BpfhvState *s = BPFHV(pci_dev);
    NetClientState *nc;
    uint8_t *pci_conf;
    int i;

    pci_conf = pci_dev->config;
    pci_conf[PCI_CACHE_LINE_SIZE] = 0x10;
    pci_conf[PCI_INTERRUPT_PIN] = 1; /* interrupt pin A */

    /* Initializations related to QEMU networking. */
    qemu_macaddr_default_if_unset(&s->nic_conf.macaddr);
    s->nic = qemu_new_nic(&net_bpfhv_info, &s->nic_conf,
                          object_get_typename(OBJECT(s)), dev->id, s);
    nc = qemu_get_queue(s->nic);
    qemu_format_nic_info_str(nc, s->nic_conf.macaddr.a);

    /* Check if the net backend is a proxy to a separate process. */
    s->proxy = bpfhv_proxy_get(nc->peer);
    if (s->proxy != NULL) {
        DBG("Found proxy net backend");
    }

    s->vnet_hdr_len = 0;
    s->hv_features = 0;
    if (!s->proxy) {
        /* Check if backend supports virtio-net offloadings. */
        s->hv_features = BPFHV_F_SG;
        if (qemu_has_vnet_hdr(nc->peer) &&
            qemu_has_vnet_hdr_len(nc->peer, sizeof(struct virtio_net_hdr_v1))) {
            if (s->net_conf.csum) {
                s->hv_features |= BPFHV_CSUM_FEATURES;
            }
            if (s->net_conf.gso) {
                s->hv_features |= BPFHV_GSO_FEATURES;
            }
        }
    }

    /* Validate the tunable parameters. */
    s->num_queue_pairs = MAX(s->nic_conf.peers.queues, 1);
    if (s->num_queue_pairs > 32) {
        error_setg(errp, "Too many queue pairs %u", s->num_queue_pairs);
        return;
    }
    s->num_queues = s->num_queue_pairs * 2;

    if (!bpfhv_num_bufs_validate(s->net_conf.num_rx_bufs)) {
        error_setg(errp, "Invalid number of rx bufs: %u",
                   s->net_conf.num_rx_bufs);
        return;
    }

    if (!bpfhv_num_bufs_validate(s->net_conf.num_tx_bufs)) {
        error_setg(errp, "Invalid number of tx bufs: %u",
                   s->net_conf.num_tx_bufs);
        return;
    }

    if (!bpfhv_doorbell_size_validate(s->doorbell_size)) {
        error_setg(errp, "Invalid doorbell size: %u", s->doorbell_size);
        return;
    }

    /* Init I/O mapped memory region, exposing bpfhv registers. */
    memory_region_init_io(&s->regs, OBJECT(s), &bpfhv_io_ops, s,
                          "bpfhv-regs", BPFHV_REG_MASK + 1);
    pci_register_bar(pci_dev, BPFHV_REG_PCI_BAR,
                     PCI_BASE_ADDRESS_SPACE_MEMORY, &s->regs);

    /* Init memory mapped memory region, to expose doorbells. */
    memory_region_init_io(&s->dbmmio, OBJECT(s), &bpfhv_dbmmio_ops, s,
                          "bpfhv-doorbell",
                          s->doorbell_size * s->num_queues);
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

    /* Initialize device queues. */
    s->q = g_malloc0(s->num_queues * sizeof(s->q[0]));

    for (i = 0; i < s->num_queues; i++) {
        bool is_rx = i < s->num_queue_pairs;
        hwaddr dbofs = i * s->doorbell_size;
        int k = i;
        int ret;

        if (!is_rx) {
            k -= s->num_queue_pairs;
        }

        snprintf(s->q[i].name, sizeof(s->q[i].name), "%s%u",
                 is_rx ? "RX" : "TX", k);

        s->q[i].nc = qemu_get_subqueue(s->nic, k);
        s->q[i].parent = s;
        s->q[i].vector = i;
        s->q[i].virq = -1;
        s->q[i].ctx_gpa = 0;
        s->q[i].bh = NULL;

        /* Let KVM write into an event notifier, so that with no proxy
         * QEMU can wake up and directly run the TX bottom half, rather
         * than going through bpfhv_dbmmio_write(). With the proxy, do
         * the ioeventfd setup for both TX and RX queues. */
        if (s->proxy || i >= s->num_queue_pairs) {
            ret = event_notifier_init(&s->q[i].ioeventfd, 0);
            if (ret) {
                error_setg_errno(errp, errno, "Failed to initialize "
                                 "ioeventfd for %s", s->q[i].name);
                return;
            }
            event_notifier_set_handler(&s->q[i].ioeventfd, NULL);

            memory_region_add_eventfd(&s->dbmmio, dbofs, 4, false, 0,
                                      &s->q[i].ioeventfd);
        }

        /* In case of proxy we also initialize notifiers for for TX and RX
         * interrupts, to be used by the proxy backend. */
        if (s->proxy) {
            ret = event_notifier_init(&s->q[i].irqfd, 0);
            if (ret) {
                error_setg_errno(errp, errno, "Failed to initialize "
                                 "ioeventfd for %s", s->q[i].name);
                return;
            }
            event_notifier_set_handler(&s->q[i].irqfd, NULL);
        }
    }

    for (i = TXI_BEGIN(s); i < TXI_END(s); i++) {
        /* Init a notifier to be triggered by guest TX kicks. If there is
         * no proxy, the TX bottom half code (bpfhv_tx_bh) is executed
         * in response to a kick. Otherwise the kick is handled by the
         * proxy backend. */

        if (!s->proxy) {
            event_notifier_set_handler(&s->q[i].ioeventfd,
                                       bpfhv_tx_evnotify);
            s->q[i].bh = qemu_bh_new(bpfhv_tx_bh, s->q + i);
        }
    }

    /* Initialize MSI-X interrupts, one per queue, plus one for the
     * upgrade notification. */
    for (i = 0; i < s->num_queues + 1; i++) {
        int ret = msix_vector_use(pci_dev, i);

        if (ret) {
            error_setg(errp, "Failed to setup MSIX vector #%d (error=%d)",
                             i, ret);
            return;
        }
    }

#ifdef BPFHV_DEBUG_TIMER
    if (!s->proxy) {
        s->debug_timer = timer_new_ms(QEMU_CLOCK_VIRTUAL,
                                      bpfhv_debug_timer, s);
    }
#endif /* BPFHV_DEBUG_TIMER */

#ifdef BPFHV_UPGRADE_TIMER
    if (!s->proxy) {
        s->upgrade_timer = timer_new_ms(QEMU_CLOCK_VIRTUAL,
                                        bpfhv_upgrade_timer, s);
    }
#endif /* BPFHV_UPGRADE_TIMER */

#ifdef BPFHV_MEMLI
    /* Support for memory listener. Only used in case of no proxy. */
    if (!s->proxy) {
        s->memory_listener.priority = 10,
        s->memory_listener.begin = bpfhv_memli_begin,
        s->memory_listener.commit = bpfhv_memli_commit,
        s->memory_listener.region_add = bpfhv_memli_region_add,
        s->memory_listener.region_nop = bpfhv_memli_region_add,
        memory_listener_register(&s->memory_listener, &address_space_memory);
    }
#endif /* BPFHV_MEMLI */

    if (s->proxy) {
        /* Run reconnection protocol with the backend. */
        if (bpfhv_proxy_reinit(s, errp)) {
            return;
        }
    }

    DBG("**** device realized ****");
}

static void
pci_bpfhv_uninit(PCIDevice *dev)
{
    BpfhvState *s = BPFHV(dev);
    int i;

#ifdef BPFHV_MEMLI
    if (!s->proxy) {
        memory_listener_unregister(&s->memory_listener);
    }
#endif /* BPFHV_MEMLI */

#ifdef BPFHV_DEBUG_TIMER
    if (s->debug_timer) {
        timer_del(s->debug_timer);
        timer_free(s->debug_timer);
    }
#endif /* BPFHV_DEBUG_TIMER */

#ifdef BPFHV_UPGRADE_TIMER
    if (s->upgrade_timer) {
        timer_del(s->upgrade_timer);
        timer_free(s->upgrade_timer);
    }
#endif /* BPFHV_UPGRADE_TIMER */

    for (i = 0; i < BPFHV_PROG_MAX; i++) {
        if (s->progs[i].insns != NULL) {
            g_free(s->progs[i].insns);
            s->progs[i].insns = NULL;
        }
    }

    for (i = 0; i < s->num_queues; i++) {
        hwaddr dbofs = i * s->doorbell_size;

        /* Clean up ioeventfd (if it was initialized). */
        if (s->proxy || i >= s->num_queue_pairs) {
            memory_region_del_eventfd(&s->dbmmio, dbofs, 4, false, 0,
                                      &s->q[i].ioeventfd);
            event_notifier_set_handler(&s->q[i].ioeventfd, NULL);
            event_notifier_cleanup(&s->q[i].ioeventfd);
        }

        /* Clean up irqfd (if it was initialized). */
        if (s->proxy) {
            event_notifier_set_handler(&s->q[i].irqfd, NULL);
            event_notifier_cleanup(&s->q[i].irqfd);
        }
    }

    for (i = TXI_BEGIN(s); i < TXI_END(s); i++) {
        if (s->q[i].bh) {
            qemu_bh_delete(s->q[i].bh);
            s->q[i].bh = NULL;
        }
    }

    g_free(s->q);
    for (i = 0; i < s->num_queues + 1; i++) {
        msix_vector_unuse(PCI_DEVICE(s), i);
    }
    msix_uninit_exclusive_bar(PCI_DEVICE(s));
    if (s->curdump) {
        g_free(s->curdump);
    }
    qemu_del_nic(s->nic);
    DBG("**** device unrealized ****");
}

static void qdev_bpfhv_reset(DeviceState *dev)
{
    BpfhvState *s = BPFHV(dev);
    Error *local_err = NULL;
    uint8_t *macaddr;

    /* Initialize device registers. */
    memset(s->ioregs, 0, sizeof(s->ioregs));
    s->ioregs[BPFHV_REG(VERSION)] = BPFHV_VERSION;
    s->ioregs[BPFHV_REG(NUM_RX_QUEUES)] = s->num_queue_pairs;
    s->ioregs[BPFHV_REG(NUM_TX_QUEUES)] = s->num_queue_pairs;
    s->ioregs[BPFHV_REG(NUM_RX_BUFS)] = s->net_conf.num_rx_bufs;
    s->ioregs[BPFHV_REG(NUM_TX_BUFS)] = s->net_conf.num_tx_bufs;
    s->ioregs[BPFHV_REG(RX_CTX_SIZE)] = sizeof(struct bpfhv_rx_context)
        + sring_rx_ctx_size(s->ioregs[BPFHV_REG(NUM_RX_BUFS)]);
    s->ioregs[BPFHV_REG(TX_CTX_SIZE)] = sizeof(struct bpfhv_tx_context)
        + sring_tx_ctx_size(s->ioregs[BPFHV_REG(NUM_TX_BUFS)]);
    s->ioregs[BPFHV_REG(DOORBELL_SIZE)] = s->doorbell_size;
    s->ioregs[BPFHV_REG(FEATURES)] = s->hv_features;
    macaddr = s->nic_conf.macaddr.a;
    s->ioregs[BPFHV_REG(MAC_HI)] = (macaddr[0] << 8) | macaddr[1];
    s->ioregs[BPFHV_REG(MAC_LO)] = (macaddr[2] << 24) | (macaddr[3] << 16)
                                 | (macaddr[4] << 8) | macaddr[5];

    s->doorbell_gva_changed = false;
    s->rx_contexts_ready = s->tx_contexts_ready = false;
    if (s->curdump) {
        g_free(s->curdump);
    }
    s->curdump = NULL;

    if (!s->proxy) {
        /* In case of no proxy, initialize eBPF programs (default
         * implementation). In case of proxy, the eBPF coded is
         * loaded by bpfhv_proxy_reinit(). */
        pstrcpy(s->progsname_next, sizeof(s->progsname_next), "sring");
        if (bpfhv_progs_load(s, s->progsname_next, &local_err)) {
            error_propagate(&error_fatal, local_err);
            return;
        }
    }

    DBG("**** device reset ****");
}

static const VMStateDescription vmstate_bpfhv = {
    .name = "bpfhv",
    .version_id = 1,
    .minimum_version_id = 1,
//  .pre_save = bpfhv_pre_save,
//  .post_load = bpfhv_post_load,
    .fields = (VMStateField[]) {
        VMSTATE_PCI_DEVICE(pci_device, BpfhvState),
        VMSTATE_UINT32_ARRAY(ioregs, BpfhvState, BPFHV_REG_END >> 2),
        VMSTATE_UINT32(num_queue_pairs, BpfhvState),
        VMSTATE_UINT32(num_queues, BpfhvState),
        VMSTATE_BOOL(rx_contexts_ready, BpfhvState),
        VMSTATE_BOOL(tx_contexts_ready, BpfhvState),
        VMSTATE_BOOL(doorbell_gva_changed, BpfhvState),
//      VMSTATE_STRUCT_POINTER(q, BpfhvState, ...),
        VMSTATE_INT32(vnet_hdr_len, BpfhvState),
        VMSTATE_UINT32(hv_features, BpfhvState),
        VMSTATE_END_OF_LIST()
    }
};

static Property bpfhv_properties[] = {
    DEFINE_NIC_PROPERTIES(BpfhvState, nic_conf),
    DEFINE_PROP_UINT32("doorbell_size", BpfhvState, doorbell_size, 8),
    DEFINE_PROP_UINT16("num_rx_bufs", BpfhvState, net_conf.num_rx_bufs, 256),
    DEFINE_PROP_UINT16("num_tx_bufs", BpfhvState, net_conf.num_tx_bufs, 256),
    DEFINE_PROP_BOOL("csum", BpfhvState, net_conf.csum, true),
    DEFINE_PROP_BOOL("gso", BpfhvState, net_conf.gso, true),
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
    dc->desc = "BPF paravirtual network device";
    dc->reset = qdev_bpfhv_reset;
    dc->vmsd = &vmstate_bpfhv;
    dc->props = bpfhv_properties;
}

static void bpfhv_instance_init(Object *obj)
{
    BpfhvState *s = BPFHV(obj);
    device_add_bootindex_property(obj, &s->nic_conf.bootindex,
                                  "bootindex", "/ethernet-phy@0",
                                  DEVICE(s), NULL);
}

static const TypeInfo bpfhv_info = {
    .name          = TYPE_BPFHV_PCI,
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(BpfhvState),
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
