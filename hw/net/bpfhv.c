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

#include <libelf.h>
#include <gelf.h>

#include "bpfhv.h"
#include "bpfhv_sring.h"
#include "bpfhv_sring_hv.h"

#define BPFHV_DEBUG
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
};

typedef struct BpfHvProg_st {
    unsigned int num_insns;
    uint64_t *insns;
} BpfHvProg;

/* Each eBPF instruction is 8 bytes wide. */
#define BPF_INSN_SIZE   8

typedef struct BpfHvTxQueue_st {
    struct bpfhv_tx_context *ctx;
} BpfHvTxQueue;

typedef struct BpfHvRxQueue_st {
    struct bpfhv_rx_context *ctx;
} BpfHvRxQueue;

typedef struct BpfHvState_st {
    /* Parent class. This is a private field, and it cannot be used. */
    PCIDevice pci_device;

    NICState *nic;
    NICConf conf;
    MemoryRegion io;
    MemoryRegion dbmmio;
    MemoryRegion progmmio;

    /* Storage for the I/O registers. */
    uint32_t ioregs[BPFHV_IO_END >> 2];

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
} BpfHvState;

/* Macro to generate I/O register indices. */
#define BPFHV_REG(x) ((BPFHV_IO_ ## x) >> 2)

#define TYPE_BPFHV_PCI  "bpfhv-pci"

#define BPFHV(obj) \
            OBJECT_CHECK(BpfHvState, (obj), TYPE_BPFHV_PCI)

static int
bpfhv_can_receive(NetClientState *nc)
{
    BpfHvState *s = qemu_get_nic_opaque(nc);
    unsigned int i;

    if (!s->rx_contexts_ready) {
        return false;
    }

    for (i = 0; i < s->ioregs[BPFHV_REG(NUM_RX_QUEUES)]; i++) {
        if (sring_can_receive(s->rxq[i].ctx)) {
            return true;
        }
        break; /* We only support a single receive queue for now. */
    }

    return false;
}

static ssize_t
bpfhv_receive_iov(NetClientState *nc, const struct iovec *iov, int iovcnt)
{
    BpfHvState *s = qemu_get_nic_opaque(nc);

    if (!s->rx_contexts_ready) {
        /* This should never happen, because we exported the can_receive method. */
        return 0;
    }

    /* We only support a single receive queue for now. */
    return sring_receive_iov(s->rxq[0].ctx, iov, iovcnt);
}

/* Device link status is up iff all the contexts are valid and
 * the network backend link status is up. */
static void
bpfhv_link_status_update(BpfHvState *s)
{
    bool status = !!(s->ioregs[BPFHV_REG(STATUS)] & BPFHV_STATUS_LINK);
    NetClientState *nc = qemu_get_queue(s->nic);
    bool new_status;
    unsigned int i;

    s->rx_contexts_ready = true;
    for (i = 0; i < s->ioregs[BPFHV_REG(NUM_RX_QUEUES)]; i++) {
        if (s->rxq[i].ctx == NULL) {
            s->rx_contexts_ready = false;
            break;
        }
    }

    s->tx_contexts_ready = true;
    for (i = 0; i < s->ioregs[BPFHV_REG(NUM_TX_QUEUES)]; i++) {
        if (s->txq[i].ctx == NULL) {
            s->tx_contexts_ready = false;
            break;
        }
    }

    new_status = !(nc->link_down) && s->rx_contexts_ready
                    && s->tx_contexts_ready;
    if (new_status == status) {
        return;
    }

    DBG("Link status goes %s", new_status ? "up" : "down");
    s->ioregs[BPFHV_REG(STATUS)] ^= BPFHV_STATUS_LINK;
    if (new_status) {
        qemu_flush_queued_packets(nc);
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

static void
bpfhv_ctrl_update(BpfHvState *s, uint32_t newval)
{
    uint32_t changed = s->ioregs[BPFHV_REG(CTRL)] ^ newval;

    if (changed & BPFHV_CTRL_RX_ENABLE) {
        if (newval & BPFHV_CTRL_RX_ENABLE) {
            /* Guest asked to enable receive operation. We can do that
             * only if all the receive contexts are present. */
            if (s->rx_contexts_ready) {
            } else {
                newval &= ~BPFHV_CTRL_RX_ENABLE;
            }
        }
    }

    if (changed & BPFHV_CTRL_TX_ENABLE) {
        if (newval & BPFHV_CTRL_TX_ENABLE) {
            if (s->tx_contexts_ready) {
            } else {
                newval &= ~BPFHV_CTRL_TX_ENABLE;
            }
        }
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
        if (rx) {
            sring_rx_ctx_init(s->rxq[qsel].ctx,
                              s->ioregs[BPFHV_REG(NUM_RX_BUFS)]);
        } else {
            sring_tx_ctx_init(s->txq[qsel].ctx,
                              s->ioregs[BPFHV_REG(NUM_TX_BUFS)]);
        }
    }

    /* Possibly update link status. */
    bpfhv_link_status_update(s);
}

static void
bpfhv_io_write(void *opaque, hwaddr addr, uint64_t val, unsigned size)
{
    BpfHvState *s = opaque;
    unsigned int index;

    addr = addr & BPFHV_IO_MASK;
    index = addr >> 2;

    if (addr >= BPFHV_IO_END) {
        DBG("Unknown I/O write, addr=0x%08"PRIx64", val=0x%08"PRIx64,
            addr, val);
        return;
    }

    assert(index < ARRAY_SIZE(regnames));

    DBG("I/O write to %s, val=0x%08" PRIx64, regnames[index], val);

    switch (addr) {
    case BPFHV_IO_CTRL:
        bpfhv_ctrl_update(s, (uint32_t)val);
        break;

    case BPFHV_IO_QUEUE_SELECT:
        if (val >= s->num_queues) {
            DBG("Guest tried to select invalid queue #%"PRIx64"", val);
            break;
        }
        s->ioregs[index] = val;
        break;

    case BPFHV_IO_DOORBELL_GVA_LO:
    case BPFHV_IO_DOORBELL_GVA_HI:
        s->doorbell_gva_changed |= (s->ioregs[index] != (uint32_t)val);
        /* fallback */
    case BPFHV_IO_CTX_PADDR_LO:
        s->ioregs[index] = val;
        break;

    case BPFHV_IO_CTX_PADDR_HI:
        s->ioregs[index] = val;
        /* A write to the most significant 32-bit word also triggers context
         * mapping (or unmapping). */
        bpfhv_ctx_remap(s);
        break;

    case BPFHV_IO_PROG_SELECT:
        if (val >= BPFHV_PROG_MAX) {
            DBG("Guest tried to select invalid program #%"PRIx64"", val);
            break;
        }
        s->ioregs[index] = val;
        s->ioregs[BPFHV_REG(PROG_SIZE)] = s->progs[val].num_insns;
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
    BpfHvState *s = opaque;
    unsigned int index;

    addr = addr & BPFHV_IO_MASK;
    index = addr >> 2;

    if (addr >= BPFHV_IO_END) {
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

    for (i = 0; i < s->ioregs[BPFHV_REG(NUM_TX_QUEUES)]; i++) {
        sring_txq_drain(nc, s->txq[i].ctx, bpfhv_tx_complete);
    }
}

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
        qemu_flush_queued_packets(qemu_get_queue(s->nic));
    } else {
        doorbell -= s->ioregs[BPFHV_REG(NUM_RX_QUEUES)];
        DBG("Doorbell TX#%u rung", doorbell);
        sring_txq_drain(qemu_get_queue(s->nic), s->txq[doorbell].ctx,
                        bpfhv_tx_complete);
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

static int
bpfhv_progs_load(BpfHvState *s, const char *implname, Error **errp)
{
    const char *prog_names[BPFHV_PROG_MAX] = {"none", "txp", "txc", "rxp", "rxc"};
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

    snprintf(filename, sizeof(filename), "bpfhv_%s_progs.o", implname);
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
            error_setg(errp, "Program %s missing in ELF '%s'", prog_names[i], filename);
            goto err;
        }
    }

    ret = 0;
err:
    close(fd);

    return ret;
}

static void
pci_bpfhv_realize(PCIDevice *pci_dev, Error **errp)
{
    const char *implname = "sring";
    DeviceState *dev = DEVICE(pci_dev);
    BpfHvState *s = BPFHV(pci_dev);
    NetClientState *nc;
    uint8_t *pci_conf;

    pci_conf = pci_dev->config;
    pci_conf[PCI_CACHE_LINE_SIZE] = 0x10;
    pci_conf[PCI_INTERRUPT_PIN] = 1; /* interrupt pin A */

    /* Initializations related to QEMU networking. */
    qemu_macaddr_default_if_unset(&s->conf.macaddr);
    s->nic = qemu_new_nic(&net_bpfhv_info, &s->conf,
                          object_get_typename(OBJECT(s)), dev->id, s);
    nc = qemu_get_queue(s->nic);
    qemu_format_nic_info_str(nc, s->conf.macaddr.a);

    /* Initialize device registers. */
    memset(s->ioregs, 0, sizeof(s->ioregs));
    s->ioregs[BPFHV_REG(NUM_RX_QUEUES)] = 1;
    s->ioregs[BPFHV_REG(NUM_TX_QUEUES)] = 1;
    s->ioregs[BPFHV_REG(NUM_RX_BUFS)] = 256;
    s->ioregs[BPFHV_REG(NUM_TX_BUFS)] = 256;
    s->ioregs[BPFHV_REG(RX_CTX_SIZE)] = sizeof(struct bpfhv_rx_context)
        + sring_rx_ctx_size(s->ioregs[BPFHV_REG(NUM_RX_BUFS)]);
    s->ioregs[BPFHV_REG(TX_CTX_SIZE)] = sizeof(struct bpfhv_tx_context)
        + sring_tx_ctx_size(s->ioregs[BPFHV_REG(NUM_TX_BUFS)]);
    s->ioregs[BPFHV_REG(DOORBELL_SIZE)] = 8; /* could be 4096 */
    s->num_queues = s->ioregs[BPFHV_REG(NUM_RX_QUEUES)] +
                    s->ioregs[BPFHV_REG(NUM_TX_QUEUES)];
    s->doorbell_gva_changed = false;
    s->rx_contexts_ready = s->tx_contexts_ready = false;

    /* Initialize eBPF programs. */
    if (bpfhv_progs_load(s, implname, errp)) {
        error_setg(errp, "Failed to load eBPF programs for '%s'", implname);
        return;
    }

    /* Initialize device queues. */
    s->rxq = g_malloc0(s->ioregs[BPFHV_REG(NUM_RX_QUEUES)]
			* sizeof(s->rxq[0]));
    s->txq = g_malloc0(s->ioregs[BPFHV_REG(NUM_TX_QUEUES)]
			* sizeof(s->txq[0]));

    /* Init I/O mapped memory region, exposing bpfhv registers. */
    memory_region_init_io(&s->io, OBJECT(s), &bpfhv_io_ops, s,
                          "bpfhv-io", BPFHV_IO_MASK + 1);
    pci_register_bar(pci_dev, BPFHV_IO_PCI_BAR,
                     PCI_BASE_ADDRESS_SPACE_IO, &s->io);

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
    if (msix_init_exclusive_bar(pci_dev, s->num_queues,
                                BPFHV_MSIX_PCI_BAR, NULL)) {
        error_setg(errp, "Failed to initialize MSI-X BAR");
        return;
    }

    DBG("%s(%p)", __func__, s);
}

static void
pci_bpfhv_uninit(PCIDevice *dev)
{
    BpfHvState *s = BPFHV(dev);
    int i;

    for (i = 0; i < BPFHV_PROG_MAX; i++) {
        if (s->progs[i].insns != NULL) {
            g_free(s->progs[i].insns);
            s->progs[i].insns = NULL;
        }
    }

    g_free(s->rxq);
    g_free(s->txq);
    msix_uninit_exclusive_bar(PCI_DEVICE(s));
    qemu_del_nic(s->nic);

    DBG("%s: %p", __func__, s);
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
