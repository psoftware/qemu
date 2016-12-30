/*
 * ptnetmap-memdev PCI device
 *
 * Copyright (c) 2015 Stefano Garzarella
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "qemu/osdep.h"
#include "hw/hw.h"
#include "hw/pci/pci.h"
#include "qemu/event_notifier.h"
#include "qemu/osdep.h"
#include "hw/net/ptnetmap.h"

#ifdef PTNET_DEBUG
#define DBG(fmt, ...) do { \
        fprintf(stderr, "ptnet-mdev: " fmt "\n", ## __VA_ARGS__); \
    } while (0)
#else
#define DBG(fmt, ...) do {} while (0)
#endif

static uint64_t
upper_pow2(uint32_t v) {
    /* from bit-twiddling hacks */
    v--;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    v++;
    return v;
}

typedef struct PTNetmapMemDevState {
    /*< private >*/
    PCIDevice parent_obj;

    /*< public >*/
    MemoryRegion io_bar;        /* ptnetmap register BAR */
    MemoryRegion mem_bar;       /* ptnetmap shared memory BAR */
    MemoryRegion mem_ram;       /* ptnetmap shared memory subregion */
    void *mem_ptr;              /* host virtual pointer to netmap memory */
    struct netmap_pools_info pi;

    QTAILQ_ENTRY(PTNetmapMemDevState) next;
} PTNetmapMemDevState;

static QTAILQ_HEAD(, PTNetmapMemDevState) ptn_memdevs = QTAILQ_HEAD_INITIALIZER(ptn_memdevs);

#define TYPE_PTNETMAP_MEMDEV	PTNETMAP_MEMDEV_NAME

#define PTNETMAP_MEMDEV(obj) \
    OBJECT_CHECK(PTNetmapMemDevState, (obj), TYPE_PTNETMAP_MEMDEV)

static void
ptnetmap_memdev_io_write(void *opaque, hwaddr addr, uint64_t val,
                         unsigned size)
{
    DBG("invalid I/O write [addr 0x%lx]", addr);
}

static uint64_t
ptnetmap_memdev_io_read(void *opaque, hwaddr addr, unsigned size)
{
    PTNetmapMemDevState *memd = opaque;
    uint64_t ret = 0;

    switch (addr) {
        case PTNET_MDEV_IO_MEMSIZE_LO:
            ret = memd->pi.memsize & 0xffffffff;
            break;
        case PTNET_MDEV_IO_MEMSIZE_HI:
            ret = memd->pi.memsize >> 32;
            break;
        case PTNET_MDEV_IO_MEMID:
            ret = memd->pi.memid;
            break;
        case PTNET_MDEV_IO_IF_POOL_OFS:
            ret = memd->pi.if_pool_offset;
            break;
        case PTNET_MDEV_IO_IF_POOL_OBJNUM:
            ret = memd->pi.if_pool_objtotal;
            break;
        case PTNET_MDEV_IO_IF_POOL_OBJSZ:
            ret = memd->pi.if_pool_objsize;
            break;
        case PTNET_MDEV_IO_RING_POOL_OFS:
            ret = memd->pi.ring_pool_offset;
            break;
        case PTNET_MDEV_IO_RING_POOL_OBJNUM:
            ret = memd->pi.ring_pool_objtotal;
            break;
        case PTNET_MDEV_IO_RING_POOL_OBJSZ:
            ret = memd->pi.ring_pool_objsize;
            break;
        case PTNET_MDEV_IO_BUF_POOL_OFS:
            ret = memd->pi.buf_pool_offset;
            break;
        case PTNET_MDEV_IO_BUF_POOL_OBJNUM:
            ret = memd->pi.buf_pool_objtotal;
            break;
        case PTNET_MDEV_IO_BUF_POOL_OBJSZ:
            ret = memd->pi.buf_pool_objsize;
            break;
        default:
            DBG("invalid I/O read [addr 0x%lx]", addr);
            return 0;
    }

    DBG("I/O read: addr 0x%lx, val 0x%lx", addr, ret);

    return ret;
}

static const MemoryRegionOps ptnetmap_memdev_io_ops = {
    .read = ptnetmap_memdev_io_read,
    .write = ptnetmap_memdev_io_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
};

static int
ptnetmap_memdev_init(PCIDevice *dev)
{
    PTNetmapMemDevState *memd = PTNETMAP_MEMDEV(dev);
    uint8_t *pci_conf;
    uint64_t size;

    pci_conf = dev->config;
    pci_conf[PCI_INTERRUPT_PIN] = 0; /* no interrupt pin */

    /* init register PCI_BAR */
    size = upper_pow2(PTNET_MDEV_IO_END);
    memory_region_init_io(&memd->io_bar, OBJECT(memd),
            &ptnetmap_memdev_io_ops, memd, "ptnetmap-io-bar", size);
    pci_register_bar(dev, PTNETMAP_IO_PCI_BAR, PCI_BASE_ADDRESS_SPACE_IO,
            &memd->io_bar);

    /* init PCI_BAR to map netmap memory into the guest */
    if (memd->mem_ptr) {
        size = upper_pow2(memd->pi.memsize);
        DBG("map BAR size %lx (%lu MiB)", size, size >> 20);

        memory_region_init(&memd->mem_bar, OBJECT(memd),
                           "ptnetmap-mem-bar", size);
        memory_region_init_ram_ptr(&memd->mem_ram, OBJECT(memd),
                                   "ptnetmap-mem-ram", memd->pi.memsize,
				   memd->mem_ptr);
        memory_region_add_subregion(&memd->mem_bar, 0, &memd->mem_ram);
        vmstate_register_ram(&memd->mem_ram, DEVICE(memd));
        pci_register_bar(dev, PTNETMAP_MEM_PCI_BAR,
                PCI_BASE_ADDRESS_SPACE_MEMORY  |
                PCI_BASE_ADDRESS_MEM_PREFETCH /*  |
                PCI_BASE_ADDRESS_MEM_TYPE_64 */, &memd->mem_bar);
    }

    QTAILQ_INSERT_TAIL(&ptn_memdevs, memd, next);
    DBG("new instance initialized");

    return 0;
}

static void
ptnetmap_memdev_uninit(PCIDevice *dev)
{
    PTNetmapMemDevState *memd = PTNETMAP_MEMDEV(dev);

    QTAILQ_REMOVE(&ptn_memdevs, memd, next);
    DBG("new instance uninitialized");
}

 /*
  * find memd through memid
  */
static struct PTNetmapMemDevState *
ptnetmap_memdev_find(uint16_t memid)
{
    PTNetmapMemDevState *memd;

    QTAILQ_FOREACH(memd, &ptn_memdevs, next) {
        if (memid == memd->pi.memid) {
            return memd;
        }
    }

    return NULL;
}

/* Function exported to be used by the netmap backend. */
int
ptnetmap_memdev_create(void *mem_ptr, struct netmap_pools_info *pi)
{
    PTNetmapMemDevState *memd;
    PCIDevice *dev;
    PCIBus *bus;

    DBG("creating new instance");

    if (ptnetmap_memdev_find(pi->memid)) {
        DBG("memdev instance for mem-id %d already exists", pi->memid);
        return 0;
    }

    bus = pci_find_primary_bus();

    if (bus == NULL) {
        DBG("unable to find PCI BUS");
        return -1;
    }

    /* Create a new PCI device belonging to the ptnetmap class. */
    dev = pci_create(bus, -1, TYPE_PTNETMAP_MEMDEV);

    /* Set shared memory parameters for the new ptnetmap memdev instance. */
    memd = PTNETMAP_MEMDEV(dev);
    memd->mem_ptr = mem_ptr;
    memd->pi = *pi;

    /* Initialize the new device. */
    qdev_init_nofail(&dev->qdev);

    DBG("created new instance");

    return 0;
}

static void
qdev_ptnetmap_memdev_reset(DeviceState *dev)
{
}

static void
ptnetmap_memdev_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);

    k->init = ptnetmap_memdev_init;
    k->exit = ptnetmap_memdev_uninit;
    k->vendor_id = PTNETMAP_PCI_VENDOR_ID;
    k->device_id = PTNETMAP_PCI_DEVICE_ID;
    k->revision = 0x00;
    k->class_id = PCI_CLASS_OTHERS;
    dc->desc = "ptnetmap memory device";
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
    dc->reset = qdev_ptnetmap_memdev_reset;
}

static const TypeInfo ptnetmap_memdev_info = {
    .name          = TYPE_PTNETMAP_MEMDEV,
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(PTNetmapMemDevState),
    .class_init    = ptnetmap_memdev_class_init,
};

static void ptnetmap_memdev_register_types(void)
{
    type_register_static(&ptnetmap_memdev_info);
}

type_init(ptnetmap_memdev_register_types)
