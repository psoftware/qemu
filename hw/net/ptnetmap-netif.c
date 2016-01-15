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


#include "hw/hw.h"
#include "hw/pci/pci.h"
#include "hw/pci/msi.h"
#include "hw/pci/msix.h"
#include "net/net.h"
#include "sysemu/sysemu.h"
#include "qemu/iov.h"
#include "qemu/range.h"

#include <net/if.h>
#include "net/netmap.h"
#include "dev/netmap/netmap_virt.h"
#include "include/hw/net/ptnetmap.h"

#define PTNET_DEBUG

#ifdef PTNET_DEBUG
#define DBG(fmt, ...) do { \
        fprintf(stderr, "ptnet: " fmt "\n", ## __VA_ARGS__); \
    } while (0)
#else
#define DBG(what, fmt, ...) do {} while (0)
#endif

#define CSB_SIZE      4096

typedef struct PtNetState_st {
    PCIDevice pci_device; /* Private field. */

    NICState *nic;
    NICConf conf;
    MemoryRegion io;
    MemoryRegion mem;
    MemoryRegion csb_ram;

    PTNetmapState *ptbe;

    /* Guest --> Host notification support. */
    EventNotifier host_tx_notifier;
    EventNotifier host_rx_notifier;

    /* Host --> Guest notification support. */
    EventNotifier guest_tx_notifier;
    EventNotifier guest_rx_notifier;
    int virqs[2];

    struct ptnetmap_cfg host_cfg;

    uint32_t ioregs[PTNET_IO_END];
    char csb[CSB_SIZE];
} PtNetState;

#define TYPE_PTNET_PCI  "ptnet-pci"

#define PTNET(obj) \
            OBJECT_CHECK(PtNetState, (obj), TYPE_PTNET_PCI)

static void
ptnet_set_link_status(NetClientState *nc)
{
    PtNetState *s = qemu_get_nic_opaque(nc);

    DBG("%s(%p)", __func__, s);
}

static int
ptnet_can_receive(NetClientState *nc)
{
    return false;
}

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
    event_notifier_set_handler(e, NULL);
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
    MSIMessage msg;

    if (ret) {
        printf("%s: guest notifier initialization failed\n", __func__);
        return;
    }

    event_notifier_set_handler(e, NULL);

    msix_vector_use(PCI_DEVICE(s), vector);

    /* Read the MSI-X message prepared by the guest and use it
     * to setup KVM irqfd, using the eventfd initialized
     * above. */
    msg = msix_get_message(PCI_DEVICE(s), vector);
    s->virqs[vector] = kvm_irqchip_add_msi_route(kvm_state, msg,
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

    ret = kvm_irqchip_remove_irqfd_notifier_gsi(kvm_state, e,
                                                s->virqs[vector]);
    if (ret) {
        printf("%s: kvm_irqchip_add_irqfd_notifier_gsi() failed: %d\n",
               __func__, ret);
    }
    kvm_irqchip_release_virq(kvm_state, s->virqs[vector]);
    event_notifier_cleanup(e);
}

static int
ptnet_guest_notifiers_init(PtNetState *s)
{
    msix_unuse_all_vectors(PCI_DEVICE(s));

    ptnet_guest_notifier_init(s, &s->guest_tx_notifier, PTNETMAP_MSIX_VEC_TX);
    ptnet_guest_notifier_init(s, &s->guest_rx_notifier, PTNETMAP_MSIX_VEC_RX);

    return 0;
}

static int
ptnet_guest_notifiers_fini(PtNetState *s)
{
    ptnet_guest_notifier_fini(s, &s->guest_tx_notifier, PTNETMAP_MSIX_VEC_TX);
    ptnet_guest_notifier_fini(s, &s->guest_rx_notifier, PTNETMAP_MSIX_VEC_RX);

    msix_unuse_all_vectors(PCI_DEVICE(s));

    return 0;
}

static int
ptnet_get_netmap_if(PtNetState *s)
{
    struct paravirt_csb *csb = (struct paravirt_csb *)s->csb;
    NetmapIf nif;
    int ret;

    ret = ptnetmap_get_netmap_if(s->ptbe, &nif);
    if (ret) {
        return ret;
    }

    csb->nifp_offset = nif.nifp_offset;
    csb->num_tx_rings = nif.num_tx_rings;
    csb->num_rx_rings = nif.num_rx_rings;
    csb->num_tx_slots = nif.num_tx_slots;
    csb->num_rx_slots = nif.num_rx_slots;
    printf("txr %u rxr %u txd %u rxd %u nifp_offset %u\n",
            csb->num_tx_rings,
            csb->num_rx_rings,
            csb->num_tx_slots,
            csb->num_rx_slots,
            csb->nifp_offset);

    return 0;
}

static int
ptnet_regif(PtNetState *s)
{
    struct paravirt_csb *csb = (struct paravirt_csb *)s->csb;

    s->host_cfg.features = PTNETMAP_CFG_FEAT_CSB | PTNETMAP_CFG_FEAT_EVENTFD;

    s->host_cfg.tx_ring.ioeventfd = event_notifier_get_fd(&s->host_tx_notifier);
    s->host_cfg.tx_ring.irqfd = event_notifier_get_fd(&s->guest_tx_notifier);
    s->host_cfg.rx_ring.ioeventfd = event_notifier_get_fd(&s->host_rx_notifier);
    s->host_cfg.rx_ring.irqfd = event_notifier_get_fd(&s->guest_rx_notifier);

    s->host_cfg.csb = csb;
    csb->host_need_txkick = 1;
    csb->guest_need_txkick = 0;
    csb->guest_need_rxkick = 1;
    csb->host_need_rxkick = 1;

    return ptnetmap_create(s->ptbe, &s->host_cfg);
}

static int
ptnet_unregif(PtNetState *s)
{
    return ptnetmap_delete(s->ptbe);
}

static void
ptnet_ptctl(PtNetState *s, uint64_t cmd)
{
    int ret = EINVAL;

    switch (cmd) {
        case NET_PARAVIRT_PTCTL_CONFIG:
            /* Fill CSB fields: nifp_offset, num_*x_rings,
             * and num_*x_slots. */
            ret = ptnet_get_netmap_if(s);
            break;

        case NET_PARAVIRT_PTCTL_REGIF:
            /* Emulate a REGIF for the guest. */
            ret = ptnet_regif(s);
            break;

        case NET_PARAVIRT_PTCTL_UNREGIF:
            /* Emulate an UNREGIF for the guest. */
            ret = ptnet_unregif(s);
            break;

        case NET_PARAVIRT_PTCTL_HOSTMEMID:
            ret = ptnetmap_get_hostmemid(s->ptbe);
            break;

        default:
            break;
    }

    s->ioregs[PTNET_IO_PTSTS >> 2] = ret;
}

static void
ptnet_ctrl(PtNetState *s, uint64_t cmd)
{
    int ret = EINVAL;

    switch (cmd) {
        case PTNET_CTRL_IRQINIT:
            /* Guest has allocated MSI-X, we can setup
             * the irqfd notification mechanism. */
            ret = ptnet_guest_notifiers_init(s);
            break;

        case PTNET_CTRL_IRQFINI:
            /* Guest is going to deallocate MSI-X, we
             * can tear donw the irqfd notification
             * mechanism. */
            ret = ptnet_guest_notifiers_fini(s);
            break;

        default:
            break;
    }

    s->ioregs[PTNET_IO_PTSTS >> 2] = ret;
}

static void
ptnet_io_write(void *opaque, hwaddr addr, uint64_t val, unsigned size)
{
    PtNetState *s = opaque;
    unsigned int index;
    const char *regname = "";

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

    switch (addr) {
        case PTNET_IO_PTFEAT:
            val = ptnetmap_ack_features(s->ptbe, val);
            regname = "PTNET_IO_PTFEAT";
            break;

        case PTNET_IO_PTCTL:
            ptnet_ptctl(s, val);
            regname = "PTNET_IO_PTCTL";
            break;

        case PTNET_IO_PTSTS:
            regname = "PTNET_IO_PTSTS";
            break;

        case PTNET_IO_CTRL:
            ptnet_ctrl(s, val);
            regname = "PTNET_IO_CTRL";
            break;

        case PTNET_IO_TXKICK:
            regname = "PTNET_IO_TXKICK";
            break;

        case PTNET_IO_RXKICK:
            regname = "PTNET_IO_RXKICK";
            break;
    }

    DBG("I/O write to %s, val=0x%08" PRIx64, regname, val);

    s->ioregs[index] = val;
}

static uint64_t
ptnet_io_read(void *opaque, hwaddr addr, unsigned size)
{
    PtNetState *s = opaque;
    unsigned int index;
    const char *regname = "";

    addr = addr & PTNET_IO_MASK;
    index = addr >> 2;

    (void)s;

    if (addr >= PTNET_IO_END) {
        DBG("Unknown I/O read addr=0x%08"PRIx64, addr);
        return 0;
    }

    switch (addr) {
        case PTNET_IO_PTFEAT:
            regname = "PTNET_IO_PTFEAT";
            break;

        case PTNET_IO_PTCTL:
            regname = "PTNET_IO_PTCTL";
            break;

        case PTNET_IO_PTSTS:
            regname = "PTNET_IO_PTSTS";
            break;

        case PTNET_IO_CTRL:
            regname = "PTNET_IO_CTRL";
            break;

        case PTNET_IO_TXKICK:
            regname = "PTNET_IO_TXKICK";
            break;

        case PTNET_IO_RXKICK:
            regname = "PTNET_IO_RXKICK";
            break;
    }

    DBG("I/O read from %s, val=0x%04x", regname, s->ioregs[index]);

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

static void ptnet_pre_save(void *opaque)
{
    PtNetState *s = opaque;
    DBG("%s(%p)", __func__, s);
}

static int ptnet_post_load(void *opaque, int version_id)
{
    PtNetState *s = opaque;
    DBG("%s(%p)", __func__, s);
    return 0;
}

static const VMStateDescription vmstate_ptnet = {
    .name = "ptnet",
    .version_id = 1,
    .minimum_version_id = 1,
    .pre_save = ptnet_pre_save,
    .post_load = ptnet_post_load,
    .fields = (VMStateField[]) {
        VMSTATE_PCI_DEVICE(pci_device, PtNetState),
        VMSTATE_UINT32(ioregs[PTNET_IO_PTFEAT], PtNetState),
        VMSTATE_UINT32(ioregs[PTNET_IO_PTCTL], PtNetState),
        VMSTATE_UINT32(ioregs[PTNET_IO_PTSTS], PtNetState),
        VMSTATE_END_OF_LIST()
    }
};

/* PCI interface */

static NetClientInfo net_ptnet_info = {
    .type = NET_CLIENT_OPTIONS_KIND_NIC,
    .size = sizeof(NICState),
    .can_receive = ptnet_can_receive,
    .receive = ptnet_receive,
    .link_status_changed = ptnet_set_link_status,
};

static void ptnet_write_config(PCIDevice *pci_dev, uint32_t address,
                                uint32_t val, int len)
{
    PtNetState *s = PTNET(pci_dev);

    pci_default_write_config(pci_dev, address, val, len);

    if (range_covers_byte(address, len, PCI_COMMAND) &&
        (pci_dev->config[PCI_COMMAND] & PCI_COMMAND_MASTER)) {
        DBG("%s(%p)", __func__, s);
    }
}

static void
pci_ptnet_realize(PCIDevice *pci_dev, Error **errp)
{
    DeviceState *dev = DEVICE(pci_dev);
    PtNetState *s = PTNET(pci_dev);
    NetClientState *nc;
    uint8_t *pci_conf;
    uint8_t *macaddr;

    pci_dev->config_write = ptnet_write_config;
    pci_conf = pci_dev->config;
    pci_conf[PCI_CACHE_LINE_SIZE] = 0x10;
    pci_conf[PCI_INTERRUPT_PIN] = 1; /* interrupt pin A */

    /* Init I/O mapped memory region, exposing ptnetmap registers. */
    memory_region_init_io(&s->io, OBJECT(s), &ptnet_io_ops, s,
                          "ptnet-io", PTNET_IO_MASK + 1);
    pci_register_bar(pci_dev, PTNETMAP_IO_PCI_BAR,
                     PCI_BASE_ADDRESS_SPACE_IO, &s->io);

    /* Init memory mapped memory region, exposing CSB.
     * It is important that size(s->csb_ram) < size(s->mem),
     * otherwise KVM memory setup routines fail. */
    memory_region_init(&s->mem, OBJECT(s), "ptnet-mem", CSB_SIZE);
    memory_region_init_ram_ptr(&s->csb_ram, OBJECT(s), "ptnet-csb-ram",
                               sizeof(struct paravirt_csb), s->csb);
    memory_region_add_subregion(&s->mem, 0, &s->csb_ram);
    vmstate_register_ram(&s->csb_ram, DEVICE(s));
    pci_register_bar(pci_dev, PTNETMAP_MEM_PCI_BAR,
                     PCI_BASE_ADDRESS_SPACE_MEMORY |
		     PCI_BASE_ADDRESS_MEM_PREFETCH, &s->mem);

    /* Allocate a PCI bar to manage MSI-X information for this device. */
    if (msix_init_exclusive_bar(pci_dev, 2, PTNETMAP_MSIX_PCI_BAR)) {
        printf("[ERR] Failed to intialize MSI-X BAR\n");
    }

    qemu_macaddr_default_if_unset(&s->conf.macaddr);
    macaddr = s->conf.macaddr.a;

    s->nic = qemu_new_nic(&net_ptnet_info, &s->conf,
                          object_get_typename(OBJECT(s)), dev->id, s);
    nc = qemu_get_queue(s->nic);
    qemu_format_nic_info_str(nc, macaddr);

    s->ptbe = nc->peer ? get_ptnetmap(nc->peer) : NULL;

    /* We can setup host --> guest notifications immediately, since
     * we already have the information we need: the address of
     * TXKICK/RXKICK registers. */
    ptnet_host_notifier_init(s, &s->host_tx_notifier, PTNET_IO_TXKICK);
    ptnet_host_notifier_init(s, &s->host_rx_notifier, PTNET_IO_RXKICK);

    DBG("%s(%p)", __func__, s);
}

static void
pci_ptnet_uninit(PCIDevice *dev)
{
    PtNetState *s = PTNET(dev);

    ptnet_host_notifier_fini(s, &s->host_tx_notifier, PTNET_IO_TXKICK);
    ptnet_host_notifier_fini(s, &s->host_rx_notifier, PTNET_IO_RXKICK);

    msix_uninit_exclusive_bar(PCI_DEVICE(s));

    qemu_del_nic(s->nic);

    DBG("%s: %p", __func__, s);
}

static void qdev_ptnet_reset(DeviceState *dev)
{
    PtNetState *s = PTNET(dev);

    /* Init registers */

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
