/*
 * QEMU netmap passthrough device
 *
 * Copyright (c) 2015 Vincenzo Maffione <v.maffione@gmail.com>
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

#include <net/if.h>
#include "net/netmap.h"
#include "net/netmap_virt.h"
#include "include/hw/net/ptnetmap.h"

#ifdef PTNET_DEBUG
#define DBG(fmt, ...) do { \
        fprintf(stderr, "ptnet-if: " fmt "\n", ## __VA_ARGS__); \
    } while (0)
#else
#define DBG(fmt, ...) do {} while (0)
#endif

static const char *regnames[] = {
    "PTFEAT",
    "PTCTL",
    "MAC_LO",
    "MAC_HI",
    "CSBBAH",
    "CSBBAL",
    "NIFP_OFS",
    "NUM_TX_RINGS",
    "NUM_RX_RINGS",
    "NUM_TX_SLOTS",
    "NUM_RX_SLOTS",
    "VNET_HDR_LEN",
    "HOSTMEMID",
    "CSB_GH_BAH",
    "CSB_GH_BAL",
    "CSB_HG_BAH",
    "CSB_HG_BAL",
};

#define REGNAMES_LEN  (sizeof(regnames) / (sizeof(regnames[0])))

typedef struct PtNetState_st {
    PCIDevice pci_device; /* Private field. */

    NICState *nic;
    NICConf conf;
    MemoryRegion io;

    PTNetmapState *ptbe;

    unsigned int num_rings;

    /* Guest --> Host notification support. */
    EventNotifier *host_notifiers;

    /* Host --> Guest notification support. */
    EventNotifier *guest_notifiers;
    int *virqs;

    uint32_t ioregs[PTNET_IO_END >> 2];
    char *csb_gh;
    char *csb_hg;
} PtNetState;

#define TYPE_PTNET_PCI  "ptnet-pci"

#define PTNET(obj) \
            OBJECT_CHECK(PtNetState, (obj), TYPE_PTNET_PCI)

static ssize_t
ptnet_receive(NetClientState *nc, const uint8_t *buf, size_t size)
{
    return size;
}

/* Initialize an eventfd and tell the VMM to write() into the eventfd
 * each time the guest acesses the I/O register specified by 'ofs'.
 * We don't need an handler, since the eventfd will be drained
 * in kernelspace. */
static int
ptnet_host_notifier_init(PtNetState *s, EventNotifier *e, hwaddr ofs,
                         Error **errp)
{
    int ret = event_notifier_init(e, 0);

    if (ret) {
        error_setg(errp, "Host notifier initialization failed");
        return ret;
    }
    event_notifier_set_handler(e, NULL);
    memory_region_add_eventfd(&s->io, ofs, 4, false, 0, e);

    return 0;
}

static void
ptnet_host_notifier_fini(PtNetState *s, EventNotifier *e, hwaddr ofs)
{
    memory_region_del_eventfd(&s->io, ofs, 4, false, 0, e);
    event_notifier_cleanup(e);
}

static int
ptnet_guest_notifier_init(PtNetState *s, EventNotifier *e, unsigned int vector)
{
    /* Initialize an eventfd. */
    int ret = event_notifier_init(e, 0);

    if (ret) {
        error_report("Guest notifier initialization failed");
        return ret;
    }

    event_notifier_set_handler(e, NULL);

    msix_vector_use(PCI_DEVICE(s), vector);

    /* Setup KVM irqfd, using an MSI-X entry and the eventfd initialize
     * above. */
    ret = s->virqs[vector] = kvm_irqchip_add_msi_route(kvm_state, vector,
                                                       PCI_DEVICE(s));
    if (ret < 0) {
        error_report("kvm_irqchip_add_msi_route() failed: %s", strerror(-ret));
        goto err_msi_route;
    }

    ret = kvm_irqchip_add_irqfd_notifier_gsi(kvm_state, e, NULL,
                                             s->virqs[vector]);
    if (ret) {
        error_report("kvm_irqchip_add_irqfd_notifier_gsi() failed: %s",
                     strerror(-ret));
        goto err_add_irqfd;
    }

    return 0;

err_add_irqfd:
    kvm_irqchip_release_virq(kvm_state, s->virqs[vector]);
err_msi_route:
    event_notifier_cleanup(e);

    return ret;
}

static void
ptnet_guest_notifier_fini(PtNetState *s, EventNotifier *e, unsigned int vector)
{
    int ret;

    if (s->virqs[vector] == -1) {
        /* Not initialized, nothing to do. */
        return;
    }

    ret = kvm_irqchip_remove_irqfd_notifier_gsi(kvm_state, e,
                                                s->virqs[vector]);
    if (ret) {
        error_report("kvm_irqchip_remove_irqfd_notifier_gsi() failed: %s",
                     strerror(-ret));
    }
    kvm_irqchip_release_virq(kvm_state, s->virqs[vector]);
    s->virqs[vector] = -1;
    event_notifier_cleanup(e);
}

static int
ptnet_guest_notifiers_init(PtNetState *s)
{
    unsigned int vec = 0;
    int i;

    msix_unuse_all_vectors(PCI_DEVICE(s));

    for (i = 0; i < s->num_rings; i++, vec++) {
        int ret = ptnet_guest_notifier_init(s, s->guest_notifiers + i, vec);

        if (ret) {
            return ret;
        }
    }

    return 0;
}

static int
ptnet_guest_notifiers_fini(PtNetState *s)
{
    unsigned int vec = 0;
    int i;

    for (i = 0; i < s->num_rings; i++, vec++) {
        ptnet_guest_notifier_fini(s, s->guest_notifiers + i, vec);
    }

    msix_unuse_all_vectors(PCI_DEVICE(s));

    return 0;
}

static int
ptnet_get_netmap_if(PtNetState *s)
{
    unsigned int num_rings;
    struct nmreq_port_info_get nif;
    int ret;

    ret = ptnetmap_get_netmap_if(s->ptbe, &nif);
    if (ret) {
        return ret;
    }

    s->ioregs[PTNET_IO_NIFP_OFS >> 2] = nif.nr_offset;
    s->ioregs[PTNET_IO_NUM_TX_RINGS >> 2] = nif.nr_tx_rings;
    s->ioregs[PTNET_IO_NUM_RX_RINGS >> 2] = nif.nr_rx_rings;
    s->ioregs[PTNET_IO_NUM_TX_SLOTS >> 2] = nif.nr_tx_slots;
    s->ioregs[PTNET_IO_NUM_RX_SLOTS >> 2] = nif.nr_rx_slots;

    num_rings = s->ioregs[PTNET_IO_NUM_TX_RINGS >> 2] +
                s->ioregs[PTNET_IO_NUM_RX_RINGS >> 2];
    if (s->num_rings && num_rings && s->num_rings != num_rings) {
        error_report("Number of rings don't match (%" PRIu32 " != %" PRIu32 ")",
                     s->num_rings, num_rings);
        return -1;
    }
    s->num_rings = num_rings;

    return 0;
}

static int
ptnet_ptctl_create(PtNetState *s)
{
    int *ioeventfds, *irqfds;
    int ret, i;

    if (s->csb_gh == NULL || s->csb_hg == NULL) {
        error_report("CSB not set, can't create ptnetmap worker");
        return -ENXIO;
    }

    /* Guest must have allocated MSI-X at this point, so that we can setup
     * the irqfd notification mechanism. */
    ret = ptnet_guest_notifiers_init(s);
    if (ret) {
        return ret;
    }

    ioeventfds = g_malloc(sizeof(*ioeventfds) * s->num_rings);
    irqfds = g_malloc(sizeof(*irqfds) * s->num_rings);

    for (i = 0; i < s->num_rings; i++) {
        ioeventfds[i] = event_notifier_get_fd(s->host_notifiers + i);
        irqfds[i] = event_notifier_get_fd(s->guest_notifiers + i);
    }

    /* The ownership of the ioeventfds and irqfds arrays is passed
     * to the callee. */
    ret = ptnetmap_kloop_start(s->ptbe, s->csb_gh, s->csb_hg,
                               s->num_rings, ioeventfds, irqfds);

    return ret;
}

static int
ptnet_ptctl_delete(PtNetState *s)
{
    /* Guest is not going to use MSI-X until next regif, we
     * can tear down the irqfd notification mechanism. */
    ptnet_guest_notifiers_fini(s);

    return ptnetmap_kloop_stop(s->ptbe);
}

static int
ptnet_ptctl(PtNetState *s, uint64_t cmd)
{
    int ret = -EINVAL;

    switch (cmd) {
    case PTNETMAP_PTCTL_CREATE:
        /* React to guest REGIF operation. */
        ret = ptnet_ptctl_create(s);
        break;

    case PTNETMAP_PTCTL_DELETE:
        /* React to guest UNREGIF operation. */
        ret = ptnet_ptctl_delete(s);
        break;
    default:
        break;
    }

    s->ioregs[PTNET_IO_PTCTL >> 2] = -ret;

    return ret;
}

static void
ptnet_csb_map_one(PtNetState *s, char **csbp, unsigned int bah,
                  unsigned int bal, size_t entry_size, int is_write)
{
    hwaddr base = ((uint64_t)s->ioregs[bah >> 2] << 32) |
                    s->ioregs[bal >> 2];
    hwaddr len = entry_size * (s->ioregs[PTNET_IO_NUM_TX_RINGS >> 2]
                               + s->ioregs[PTNET_IO_NUM_RX_RINGS >> 2]);

    if (*csbp) {
        cpu_physical_memory_unmap(*csbp, len, is_write, len);
        *csbp = NULL;
    }
    if (base) {
        *csbp = cpu_physical_memory_map(base, &len, is_write);
    }
}

static void
ptnet_io_write(void *opaque, hwaddr addr, uint64_t val, unsigned size)
{
    PtNetState *s = opaque;
    unsigned int index;

    if (!s->ptbe) {
        DBG("Invalid I/O write, backend does not support passthrough");
        return;
    }

    addr = addr & PTNET_IO_MASK;
    index = addr >> 2;

    (void)s;

    if (addr >= PTNET_IO_END) {
        DBG("Unknown I/O write addr=0x%08"PRIx64", val=0x%08"PRIx64,
            addr, val);
        return;
    }

    assert(index < REGNAMES_LEN);

    switch (addr) {
    case PTNET_IO_PTFEAT:
        val = ptnetmap_ack_features(s->ptbe, val);
        s->ioregs[index] = val;
        break;

    case PTNET_IO_PTCTL:
        ptnet_ptctl(s, val);
        break;

    case PTNET_IO_CSB_GH_BAH:
    case PTNET_IO_CSB_HG_BAH:
        s->ioregs[index] = val;
        break;

    case PTNET_IO_CSB_GH_BAL:
        /* Write to BAL triggers CSB mapping. */
        s->ioregs[index] = val;
        ptnet_csb_map_one(s, &s->csb_gh, PTNET_IO_CSB_GH_BAH,
                          PTNET_IO_CSB_GH_BAL, sizeof(struct nm_csb_atok),
                          /*is_write=*/0);
        /* Stop the sync-kloop in case it is still running. */
        ptnet_ptctl(s, PTNETMAP_PTCTL_DELETE);
        break;

    case PTNET_IO_CSB_HG_BAL:
        /* Write to BAL triggers CSB mapping. */
        s->ioregs[index] = val;
        ptnet_csb_map_one(s, &s->csb_hg, PTNET_IO_CSB_HG_BAH,
                          PTNET_IO_CSB_HG_BAL, sizeof(struct nm_csb_ktoa),
                          /*is_write=*/1);
        /* Stop the sync-kloop in case it is still running. */
        ptnet_ptctl(s, PTNETMAP_PTCTL_DELETE);
        break;

    case PTNET_IO_VNET_HDR_LEN:
        if (qemu_has_vnet_hdr_len(qemu_get_queue(s->nic)->peer, val)) {
	    qemu_set_vnet_hdr_len(qemu_get_queue(s->nic)->peer, val);
            s->ioregs[index] = val;
        }
        break;
    }

    DBG("I/O write to %s, val=0x%08" PRIx64, regnames[index], val);
}

static uint64_t
ptnet_io_read(void *opaque, hwaddr addr, unsigned size)
{
    PtNetState *s = opaque;
    unsigned int index;

    addr = addr & PTNET_IO_MASK;
    index = addr >> 2;

    (void)s;

    if (addr >= PTNET_IO_END) {
        DBG("Unknown I/O read addr=0x%08"PRIx64, addr);
        return 0;
    }

    assert(index < REGNAMES_LEN);

    switch (addr) {
    case PTNET_IO_NIFP_OFS:
    case PTNET_IO_NUM_TX_RINGS:
    case PTNET_IO_NUM_RX_RINGS:
    case PTNET_IO_NUM_TX_SLOTS:
    case PTNET_IO_NUM_RX_SLOTS:
        /* Fill in device registers with information about nifp_offset,
         * num_*x_rings, and num_*x_slots. */
        ptnet_get_netmap_if(s);
        break;

    case PTNET_IO_HOSTMEMID:
        s->ioregs[index] = ptnetmap_get_hostmemid(s->ptbe);
    }

    DBG("I/O read from %s, val=0x%08x", regnames[index], s->ioregs[index]);

    return s->ioregs[index];
}

static const MemoryRegionOps ptnet_io_ops = {
    .read = ptnet_io_read,
    .write = ptnet_io_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
};

static const VMStateDescription vmstate_ptnet = {
    .name = "ptnet",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (VMStateField[]) {
        VMSTATE_PCI_DEVICE(pci_device, PtNetState),
        VMSTATE_UINT32(ioregs[PTNET_IO_PTFEAT >> 2], PtNetState),
        VMSTATE_UINT32(ioregs[PTNET_IO_PTCTL >> 2], PtNetState),
        VMSTATE_UINT32(ioregs[PTNET_IO_MAC_LO >> 2], PtNetState),
        VMSTATE_UINT32(ioregs[PTNET_IO_MAC_HI >> 2], PtNetState),
        VMSTATE_UINT32(ioregs[PTNET_IO_NIFP_OFS >> 2], PtNetState),
        VMSTATE_UINT32(ioregs[PTNET_IO_NUM_TX_RINGS >> 2], PtNetState),
        VMSTATE_UINT32(ioregs[PTNET_IO_NUM_RX_RINGS >> 2], PtNetState),
        VMSTATE_UINT32(ioregs[PTNET_IO_NUM_TX_SLOTS >> 2], PtNetState),
        VMSTATE_UINT32(ioregs[PTNET_IO_NUM_RX_SLOTS >> 2], PtNetState),
        VMSTATE_UINT32(ioregs[PTNET_IO_VNET_HDR_LEN >> 2], PtNetState),
        VMSTATE_UINT32(ioregs[PTNET_IO_HOSTMEMID >> 2], PtNetState),
        VMSTATE_UINT32(ioregs[PTNET_IO_CSB_GH_BAH >> 2], PtNetState),
        VMSTATE_UINT32(ioregs[PTNET_IO_CSB_GH_BAL >> 2], PtNetState),
        VMSTATE_UINT32(ioregs[PTNET_IO_CSB_HG_BAH >> 2], PtNetState),
        VMSTATE_UINT32(ioregs[PTNET_IO_CSB_HG_BAL >> 2], PtNetState),
        VMSTATE_END_OF_LIST()
    }
};

/* PCI interface */

static NetClientInfo net_ptnet_info = {
    .type = NET_CLIENT_DRIVER_NIC,
    .size = sizeof(NICState),
    .receive = ptnet_receive,
};

static void
pci_ptnet_realize(PCIDevice *pci_dev, Error **errp)
{
    unsigned int kick_reg = PTNET_IO_KICK_BASE;
    DeviceState *dev = DEVICE(pci_dev);
    PtNetState *s = PTNET(pci_dev);
    NetClientState *nc;
    uint8_t *pci_conf;
    int i;

    pci_conf = pci_dev->config;
    pci_conf[PCI_CACHE_LINE_SIZE] = 0x10;
    pci_conf[PCI_INTERRUPT_PIN] = 1; /* interrupt pin A */

    /* Init I/O mapped memory region, exposing ptnetmap registers. */
    memory_region_init_io(&s->io, OBJECT(s), &ptnet_io_ops, s,
                          "ptnet-io", PTNET_IO_MASK + 1);
    pci_register_bar(pci_dev, PTNETMAP_IO_PCI_BAR,
                     PCI_BASE_ADDRESS_SPACE_IO, &s->io);

    qemu_macaddr_default_if_unset(&s->conf.macaddr);

    s->nic = qemu_new_nic(&net_ptnet_info, &s->conf,
                          object_get_typename(OBJECT(s)), dev->id, s);
    nc = qemu_get_queue(s->nic);
    qemu_format_nic_info_str(nc, s->conf.macaddr.a);

    s->ptbe = nc->peer ? get_ptnetmap(nc->peer) : NULL;

    s->num_rings = 0;
    if (ptnet_get_netmap_if(s)) {
        error_setg(errp, "Failed to get netmap backend to pass-through");
        return;
    }

    /* Allocate a PCI bar to manage MSI-X information for this device. */
    if (msix_init_exclusive_bar(pci_dev, s->num_rings,
                                PTNETMAP_MSIX_PCI_BAR, NULL)) {
        error_setg(errp, "Failed to initialize MSI-X BAR");
        return;
    }

    /* We can setup host --> guest notifications immediately, since
     * we already have the information we need: the address of
     * TXKICK/RXKICK registers. */
    s->host_notifiers = g_malloc(2 * s->num_rings * sizeof(EventNotifier));
    s->guest_notifiers = s->host_notifiers + s->num_rings;
    s->virqs = g_malloc(s->num_rings * sizeof(*s->virqs));

    for (i = 0; i < s->num_rings; i++, kick_reg += 4) {
        s->virqs[i] = -1; /* start from a known value */
        if (ptnet_host_notifier_init(s, s->host_notifiers + i,
                                     kick_reg, errp)) {
            return;
        }
    }

    DBG("%s(%p)", __func__, s);
}

static void
pci_ptnet_uninit(PCIDevice *dev)
{
    unsigned int kick_reg = PTNET_IO_KICK_BASE;
    PtNetState *s = PTNET(dev);
    int i;

    for (i = 0; i < s->num_rings; i++, kick_reg += 4) {
        ptnet_host_notifier_fini(s, s->host_notifiers + i, kick_reg);
    }
    g_free(s->host_notifiers);
    g_free(s->virqs);

    msix_uninit_exclusive_bar(PCI_DEVICE(s));
    qemu_del_nic(s->nic);

    DBG("%s: %p", __func__, s);
}

static void qdev_ptnet_reset(DeviceState *dev)
{
    PtNetState *s = PTNET(dev);
    uint8_t *macaddr;

    /* Init MAC address registers. */
    macaddr = s->conf.macaddr.a;
    s->ioregs[PTNET_IO_MAC_HI >> 2] = (macaddr[0] << 8) | macaddr[1];
    s->ioregs[PTNET_IO_MAC_LO >> 2] = (macaddr[2] << 24) | (macaddr[3] << 16)
                                 | (macaddr[4] << 8) | macaddr[5];
    s->csb_gh = s->csb_hg = NULL;
    DBG("%s(%p)", __func__, s);
}

static Property ptnet_properties[] = {
    DEFINE_NIC_PROPERTIES(PtNetState, conf),
    DEFINE_PROP_END_OF_LIST(),
};

static void ptnet_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);

    k->realize = pci_ptnet_realize;
    k->exit = pci_ptnet_uninit;
    k->vendor_id = PTNETMAP_PCI_VENDOR_ID;
    k->device_id = PTNETMAP_PCI_NETIF_ID;
    k->class_id = PCI_CLASS_NETWORK_ETHERNET;
    set_bit(DEVICE_CATEGORY_NETWORK, dc->categories);
    dc->desc = "Netmap passthrough network device";
    dc->reset = qdev_ptnet_reset;
    dc->vmsd = &vmstate_ptnet;
    dc->props = ptnet_properties;
}

static void ptnet_instance_init(Object *obj)
{
    PtNetState *s = PTNET(obj);
    device_add_bootindex_property(obj, &s->conf.bootindex,
                                  "bootindex", "/ethernet-phy@0",
                                  DEVICE(s), NULL);
}

static const TypeInfo ptnet_info = {
    .name          = TYPE_PTNET_PCI,
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(PtNetState),
    .instance_init = ptnet_instance_init,
    .class_init    = ptnet_class_init,
    .interfaces = (InterfaceInfo[]) {
        { INTERFACE_PCIE_DEVICE },
        { INTERFACE_CONVENTIONAL_PCI_DEVICE },
        { }
    },
};

static void ptnet_register_types(void)
{
    type_register_static(&ptnet_info);
}

type_init(ptnet_register_types)
