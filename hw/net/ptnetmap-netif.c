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
#include "qemu/iov.h"
#include "qemu/range.h"

#include <net/if.h>
#include "net/netmap.h"
#include "net/netmap_virt.h"
#include "include/hw/net/ptnetmap.h"

#undef PTNET_DEBUG
#ifdef PTNET_DEBUG
#define DBG(fmt, ...) do { \
        fprintf(stderr, "ptnet-if: " fmt "\n", ## __VA_ARGS__); \
    } while (0)
#else
#define DBG(what, fmt, ...) do {} while (0)
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
};

#define REGNAMES_LEN  (sizeof(regnames)/(sizeof(regnames[0])))

typedef struct PtNetState_st {
    PCIDevice pci_device; /* Private field. */

    NICState *nic;
    NICConf conf;
    MemoryRegion io;
#ifndef PTNET_CSB_ALLOC
    MemoryRegion mem;
    MemoryRegion csb_ram;
#endif  /* !PTNET_CSB_ALLOC */

    PTNetmapState *ptbe;

    unsigned int num_rings;

    /* Guest --> Host notification support. */
    EventNotifier *host_notifiers;

    /* Host --> Guest notification support. */
    EventNotifier *guest_notifiers;
    int *virqs;

    uint32_t ioregs[PTNET_IO_END >> 2];
#ifndef PTNET_CSB_ALLOC
    char csb[NETMAP_VIRT_CSB_SIZE];
#else /* PTNET_CSB_ALLOC */
    char *csb;
#endif
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
static void
ptnet_host_notifier_init(PtNetState *s, EventNotifier *e, hwaddr ofs)
{
    int ret = event_notifier_init(e, 0);

    if (ret) {
        printf("%s: host notifier initialization failed\n", __func__);
        return;
    }
    event_notifier_set_handler(e, true, NULL);
    memory_region_add_eventfd(&s->io, ofs, 4, false, 0, e);

}

static void
ptnet_host_notifier_fini(PtNetState *s, EventNotifier *e, hwaddr ofs)
{
    memory_region_del_eventfd(&s->io, ofs, 4, false, 0, e);
    event_notifier_cleanup(e);
}

static void
ptnet_guest_notifier_init(PtNetState *s, EventNotifier *e, unsigned int vector)
{
    /* Initialize an eventfd. */
    int ret = event_notifier_init(e, 0);

    if (ret) {
        printf("%s: guest notifier initialization failed\n", __func__);
        return;
    }

    event_notifier_set_handler(e, false, NULL);

    msix_vector_use(PCI_DEVICE(s), vector);

    /* Setup KVM irqfd, using an MSI-X entry and the eventfd initialize
     * above. */
    s->virqs[vector] = kvm_irqchip_add_msi_route(kvm_state, vector,
                                                 PCI_DEVICE(s));
    if (s->virqs[vector] < 0) {
        printf("%s: kvm_irqchip_add_msi_route() failed: %d\n", __func__,
               -s->virqs[vector]);
        goto err_msi_route;
    }

    ret = kvm_irqchip_add_irqfd_notifier_gsi(kvm_state, e, NULL,
                                             s->virqs[vector]);
    if (ret) {
        printf("%s: kvm_irqchip_add_irqfd_notifier_gsi() failed: %d\n",
               __func__, ret);
        goto err_add_irqfd;
    }

    return;

err_add_irqfd:
    kvm_irqchip_release_virq(kvm_state, s->virqs[vector]);
err_msi_route:
    event_notifier_cleanup(e);
}

static void
ptnet_guest_notifier_fini(PtNetState *s, EventNotifier *e, unsigned int vector)
{
    int ret;

    if (s->virqs[vector] == -1) {
        printf("%s: guest notifier #%u not initialized, nothing to do\n",
               __func__, vector);
        return;
    }

    ret = kvm_irqchip_remove_irqfd_notifier_gsi(kvm_state, e,
                                                s->virqs[vector]);
    if (ret) {
        printf("%s: kvm_irqchip_remove_irqfd_notifier_gsi() failed: %d\n",
               __func__, ret);
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

    for (i = 0; i < s->num_rings; i++, vec ++) {
        ptnet_guest_notifier_init(s, s->guest_notifiers + i, vec);
    }

    return 0;
}

static int
ptnet_guest_notifiers_fini(PtNetState *s)
{
    unsigned int vec = 0;
    int i;

    for (i = 0; i < s->num_rings; i++, vec ++) {
        ptnet_guest_notifier_fini(s, s->guest_notifiers + i, vec);
    }

    msix_unuse_all_vectors(PCI_DEVICE(s));

    return 0;
}

static int
ptnet_get_netmap_if(PtNetState *s)
{
    unsigned int num_rings;
    NetmapIf nif;
    int ret;

    ret = ptnetmap_get_netmap_if(s->ptbe, &nif);
    if (ret) {
        return ret;
    }

    s->ioregs[PTNET_IO_NIFP_OFS >> 2] = nif.nifp_offset;
    s->ioregs[PTNET_IO_NUM_TX_RINGS >> 2] = nif.num_tx_rings;
    s->ioregs[PTNET_IO_NUM_RX_RINGS >> 2] = nif.num_rx_rings;
    s->ioregs[PTNET_IO_NUM_TX_SLOTS >> 2] = nif.num_tx_slots;
    s->ioregs[PTNET_IO_NUM_RX_SLOTS >> 2] = nif.num_rx_slots;

    num_rings = s->ioregs[PTNET_IO_NUM_TX_RINGS >> 2] +
                s->ioregs[PTNET_IO_NUM_RX_RINGS >> 2];
    if (s->num_rings && num_rings && s->num_rings != num_rings) {
        printf("Number of rings change is not supported");
        return -1;
    }
    s->num_rings = num_rings;

    return 0;
}

static int
ptnet_ptctl_create(PtNetState *s)
{
    struct ptnetmap_cfgentry_qemu *cfgentry;
    struct ptnetmap_cfg *cfg;
    int ret;
    int i;

    if (s->csb == NULL) {
        printf("%s: Unexpected NULL CSB", __func__);
        return -1;
    }

    /* Guest must haave allocated MSI-X now, we can setup
     * the irqfd notification mechanism. */
    ret = ptnet_guest_notifiers_init(s);
    if (ret) {
        return ret;
    }

    cfg = g_malloc(sizeof(*cfg) + s->num_rings * sizeof(*cfgentry));
    cfg->cfgtype = PTNETMAP_CFGTYPE_QEMU;
    cfg->entry_size = sizeof(*cfgentry);
    cfg->num_rings = s->num_rings;
    cfg->ptrings = s->csb;
    cfgentry = (struct ptnetmap_cfgentry_qemu *)(cfg + 1);

    for (i = 0; i < s->num_rings; i++, cfgentry ++) {
        cfgentry->ioeventfd = event_notifier_get_fd(s->host_notifiers + i);
        cfgentry->irqfd = event_notifier_get_fd(s->guest_notifiers + i);
    }

    ret = ptnetmap_create(s->ptbe, cfg);
    g_free(cfg);

    return ret;
}

static int
ptnet_ptctl_delete(PtNetState *s)
{
    /* Guest is not going to use MSI-X until next regif, we
     * can tear donw the irqfd notification mechanism. */
    ptnet_guest_notifiers_fini(s);

    return ptnetmap_delete(s->ptbe);
}

static void
ptnet_ptctl(PtNetState *s, uint64_t cmd)
{
    int ret = EINVAL;

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

    s->ioregs[PTNET_IO_PTCTL >> 2] = ret;
}

#ifdef PTNET_CSB_ALLOC
static void
ptnet_csb_mapping(PtNetState *s)
{
    hwaddr base = ((uint64_t)s->ioregs[PTNET_IO_CSBBAH >> 2] << 32) |
                    s->ioregs[PTNET_IO_CSBBAL >> 2];
    hwaddr len = 4096;

    if (s->csb) {
        cpu_physical_memory_unmap(s->csb, len, 1, len);
        s->csb = NULL;
    }
    if (base) {
        s->csb = cpu_physical_memory_map(base, &len, 1 /* is_write */);
    }
}
#endif  /* PTNET_CSB_ALLOC */

static void
ptnet_io_write(void *opaque, hwaddr addr, uint64_t val, unsigned size)
{
    PtNetState *s = opaque;
    unsigned int index;

    if (!s->ptbe) {
        printf("Invalid I/O write, backend does not support passthrough\n");
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

        case PTNET_IO_CSBBAH:
            s->ioregs[index] = val;
            break;

        case PTNET_IO_CSBBAL:
            s->ioregs[index] = val;
#ifdef PTNET_CSB_ALLOC
            ptnet_csb_mapping(s);
#endif  /* PTNET_CSB_ALLOC */
            break;

	case PTNET_IO_VNET_HDR_LEN:
            qemu_set_vnet_hdr_len(qemu_get_queue(s->nic)->peer, val);
            if (qemu_has_vnet_hdr_len(qemu_get_queue(s->nic)->peer, val)) {
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
        VMSTATE_UINT32(ioregs[PTNET_IO_CSBBAH >> 2], PtNetState),
        VMSTATE_UINT32(ioregs[PTNET_IO_CSBBAL >> 2], PtNetState),
        VMSTATE_UINT32(ioregs[PTNET_IO_NIFP_OFS >> 2], PtNetState),
        VMSTATE_UINT32(ioregs[PTNET_IO_NUM_TX_RINGS >> 2], PtNetState),
        VMSTATE_UINT32(ioregs[PTNET_IO_NUM_RX_RINGS >> 2], PtNetState),
        VMSTATE_UINT32(ioregs[PTNET_IO_NUM_TX_SLOTS >> 2], PtNetState),
        VMSTATE_UINT32(ioregs[PTNET_IO_NUM_RX_SLOTS >> 2], PtNetState),
        VMSTATE_UINT32(ioregs[PTNET_IO_VNET_HDR_LEN >> 2], PtNetState),
        VMSTATE_UINT32(ioregs[PTNET_IO_HOSTMEMID >> 2], PtNetState),
        VMSTATE_END_OF_LIST()
    }
};

/* PCI interface */

static NetClientInfo net_ptnet_info = {
    .type = NET_CLIENT_DRIVER_NIC,
    .size = sizeof(NICState),
    .receive = ptnet_receive,
};

static void ptnet_write_config(PCIDevice *pci_dev, uint32_t address,
                                uint32_t val, int len)
{
    pci_default_write_config(pci_dev, address, val, len);

    if (range_covers_byte(address, len, PCI_COMMAND) &&
        (pci_dev->config[PCI_COMMAND] & PCI_COMMAND_MASTER)) {
        DBG("%s(%p)", __func__, PTNET(pci_dev));
    }
}

static void
pci_ptnet_realize(PCIDevice *pci_dev, Error **errp)
{
    unsigned int kick_reg = PTNET_IO_KICK_BASE;
    DeviceState *dev = DEVICE(pci_dev);
    PtNetState *s = PTNET(pci_dev);
    NetClientState *nc;
    uint8_t *pci_conf;
    int i;

    pci_dev->config_write = ptnet_write_config;
    pci_conf = pci_dev->config;
    pci_conf[PCI_CACHE_LINE_SIZE] = 0x10;
    pci_conf[PCI_INTERRUPT_PIN] = 1; /* interrupt pin A */

    /* Init I/O mapped memory region, exposing ptnetmap registers. */
    memory_region_init_io(&s->io, OBJECT(s), &ptnet_io_ops, s,
                          "ptnet-io", PTNET_IO_MASK + 1);
    pci_register_bar(pci_dev, PTNETMAP_IO_PCI_BAR,
                     PCI_BASE_ADDRESS_SPACE_IO, &s->io);

#ifndef PTNET_CSB_ALLOC
    /* Init memory mapped memory region, exposing CSB.
     * It is important that size(s->csb_ram) < size(s->mem),
     * otherwise KVM memory setup routines fail. */
    memory_region_init(&s->mem, OBJECT(s), "ptnet-mem", NETMAP_VIRT_CSB_SIZE);
    memory_region_init_ram_ptr(&s->csb_ram, OBJECT(s), "ptnet-csb-ram",
                               sizeof(struct ptnet_csb), s->csb);
    memory_region_add_subregion(&s->mem, 0, &s->csb_ram);
    vmstate_register_ram(&s->csb_ram, DEVICE(s));
    pci_register_bar(pci_dev, PTNETMAP_MEM_PCI_BAR,
                     PCI_BASE_ADDRESS_SPACE_MEMORY |
		     PCI_BASE_ADDRESS_MEM_PREFETCH, &s->mem);
#endif /* !PTNET_CSB_ALLOC */

    qemu_macaddr_default_if_unset(&s->conf.macaddr);

    s->nic = qemu_new_nic(&net_ptnet_info, &s->conf,
                          object_get_typename(OBJECT(s)), dev->id, s);
    nc = qemu_get_queue(s->nic);
    qemu_format_nic_info_str(nc, s->conf.macaddr.a);

    s->ptbe = nc->peer ? get_ptnetmap(nc->peer) : NULL;

    s->num_rings = 0;
    ptnet_get_netmap_if(s);

    /* Allocate a PCI bar to manage MSI-X information for this device. */
    if (msix_init_exclusive_bar(pci_dev, s->num_rings, PTNETMAP_MSIX_PCI_BAR)) {
        printf("[ERR] Failed to intialize MSI-X BAR\n");
    }

    /* We can setup host --> guest notifications immediately, since
     * we already have the information we need: the address of
     * TXKICK/RXKICK registers. */
    s->host_notifiers = g_malloc(2 * s->num_rings * sizeof(EventNotifier));
    s->guest_notifiers = s->host_notifiers + s->num_rings;
    s->virqs = g_malloc(s->num_rings * sizeof(*s->virqs));

    for (i = 0; i < s->num_rings; i++, kick_reg += 4) {
        s->virqs[i] = -1; /* start from a known value */
        ptnet_host_notifier_init(s, s->host_notifiers + i, kick_reg);
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
#ifdef PTNET_CSB_ALLOC
    s->csb = NULL;
#endif  /* PTNET_CSB_ALLOC */
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
};

static void ptnet_register_types(void)
{
    type_register_static(&ptnet_info);
}

type_init(ptnet_register_types)
