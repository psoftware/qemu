/*
 * bpfhv-proxy.c
 *
 * Copyright (c) 2019 Vincenzo Maffione <v.maffione@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include "qemu/osdep.h"
#include "clients.h"
#include "chardev/char-fe.h"
#include "qapi/error.h"
#include "qapi/qapi-commands-net.h"
#include "qemu/config-file.h"
#include "qemu/error-report.h"
#include "qemu/option.h"
#include "qemu/range.h"
#include "exec/memory.h"
#include "exec/address-spaces.h"
#include "trace.h"

#include "bpfhv/bpfhv-proxy.h"
#include "bpfhv/bpfhv.h"

/* Verbose debug information. */
#define BPFHV_DEBUG

#ifdef BPFHV_DEBUG
#define DBG(fmt, ...) do { \
        fprintf(stderr, "bpfhv-proxy: " fmt "\n", ## __VA_ARGS__); \
    } while (0)
#else
#define DBG(fmt, ...) do {} while (0)
#endif

typedef struct BpfhvProxyMemliRegion {
    uint64_t gpa_start;
    uint64_t gpa_end;
    uint64_t size;
    void *hva_start;
    MemoryRegion *mr;
} BpfhvProxyMemliRegion;

typedef struct BpfhvProxyState {
    NetClientState nc;
    CharBackend chr; /* only queue index 0 */
    guint watch;

    /* True if we have an active backend. */
    bool active;

    /* Data structures needed to receive updates on the
     * guest memory map. */
    MemoryListener memory_listener;
    BpfhvProxyMemliRegion mem_regs_arr[2][BPFHV_PROXY_MAX_REGIONS];
    BpfhvProxyMemliRegion *mem_regs_next;
    BpfhvProxyMemliRegion *mem_regs;
    size_t num_mem_regs;
    size_t num_mem_regs_next;

    /* Number of queue pairs. */
    unsigned int num_queues;

    /* File descriptor of an open file from which the eBPF programs
     * can be read. */
    int progfd;

    /* Size of the RX and TX contexts (including the initial part
     * visible to the guest. */
    size_t rx_ctx_size;
    size_t tx_ctx_size;
} BpfhvProxyState;

static int
bpfhv_proxy_sendmsg(BpfhvProxyState *s, BpfhvProxyMessage *msg,
                    int *fds, size_t num_fds)
{
    size_t size = sizeof(msg->hdr) + msg->hdr.size;
    int ret;

    msg->hdr.flags |= BPFHV_PROXY_VERSION;

    if (fds != NULL && num_fds > 0) {
        if (qemu_chr_fe_set_msgfds(&s->chr, fds, num_fds) < 0) {
            error_report("Failed to set msg fds.");
            return -1;
        }
    }

    ret = qemu_chr_fe_write_all(&s->chr, (const uint8_t *)msg, size);
    if (ret != size) {
        error_report("Failed to write msg."
                     " Wrote %d instead of %zu.", ret, size);
        return -1;
    }

    return 0;
}

static int
bpfhv_proxy_recvmsg(BpfhvProxyState *s, BpfhvProxyMessage *msg,
                    int *fds, size_t num_fds)
{
    BpfhvProxyReqType reqtype_sent = msg->hdr.reqtype;
    int size = sizeof(msg->hdr), ret;

    /* Read message header. */
    ret = qemu_chr_fe_read_all(&s->chr, (uint8_t *)&msg->hdr, size);
    if (ret != size) {
        error_report("Failed to read msg header. Read %d instead of %d.",
                     ret, size);
        return -1;
    }

    if (fds != NULL && num_fds > 0) {
        if (qemu_chr_fe_get_msgfds(&s->chr, fds, num_fds) < 0) {
            error_report("Failed to get msg fds.");
            return -1;
        }
    }

    /* Validate version. */
    if ((msg->hdr.flags & BPFHV_PROXY_F_VERSION_MASK) != BPFHV_PROXY_VERSION) {
        error_report("Request version mismatch. Expected %u, got %u.",
                     BPFHV_PROXY_VERSION,
                     msg->hdr.flags & BPFHV_PROXY_F_VERSION_MASK);
        return -1;
    }

    /* Validate request type. */
    if (msg->hdr.reqtype != reqtype_sent) {
        error_report("Request type mismatch. Expected %u, got %u.",
                reqtype_sent, msg->hdr.reqtype);
        return -1;
    }

    /* Validate payload size. */
    if (msg->hdr.size > sizeof(msg->payload)) {
        error_report("Failed to read msg header. "
                "Size %u exceeds the maximum %zu.", msg->hdr.size,
                sizeof(msg->payload));
        return -1;
    }

    /* Check for errors */
    if (msg->hdr.flags & BPFHV_PROXY_F_ERROR) {
        error_report("Backend reported an error.");
        return -1;
    }

    if (msg->hdr.size > 0) {
        memset(&msg->payload, 0, sizeof(msg->payload));
        size = msg->hdr.size;
        ret = qemu_chr_fe_read_all(&s->chr, (uint8_t *)&msg->payload, size);
        if (ret != size) {
            error_report("Failed to read msg payload."
                         " Read %u instead of %u.", ret, msg->hdr.size);
            return -1;
        }
    }

    return 0;
}

static int
bpfhv_proxy_sendrecv(BpfhvProxyState *s, BpfhvProxyMessage *msg,
                     int *fds, size_t num_fds)
{
    int ret = bpfhv_proxy_sendmsg(s, msg, fds, num_fds);

    if (ret) {
        return ret;
    }

    return bpfhv_proxy_recvmsg(s, msg, NULL, 0);
}

static int
bpfhv_proxy_get_features(BpfhvProxyState *s, uint64_t *features)
{
    BpfhvProxyMessage msg;
    int ret;

    memset(&msg, 0, sizeof(msg));
    msg.hdr.reqtype = BPFHV_PROXY_REQ_GET_FEATURES;

    ret = bpfhv_proxy_sendrecv(s, &msg, NULL, 0);
    if (ret) {
        return ret;
    }

    *features = msg.payload.u64;

    DBG("Got features %llx", (long long unsigned)*features);

    return 0;
}

static int
bpfhv_proxy_set_features(BpfhvProxyState *s, uint64_t features)
{
    BpfhvProxyMessage msg;
    int ret;

    memset(&msg, 0, sizeof(msg));
    msg.hdr.reqtype = BPFHV_PROXY_REQ_SET_FEATURES;
    msg.hdr.size = sizeof(msg.payload.u64);
    msg.payload.u64 = features;

    ret = bpfhv_proxy_sendrecv(s, &msg, NULL, 0);
    if (ret) {
        return ret;
    }

    DBG("Set features %llx", (long long unsigned)features);

    return 0;
}

static int
bpfhv_proxy_set_parameters(BpfhvProxyState *s, unsigned int num_queues,
                           unsigned int num_rx_bufs, unsigned int num_tx_bufs)
{
    BpfhvProxyMessage msg;
    int ret;

    memset(&msg, 0, sizeof(msg));
    msg.hdr.reqtype = BPFHV_PROXY_REQ_SET_PARAMETERS;
    msg.hdr.size = sizeof(msg.payload.params);
    msg.payload.params.num_rx_queues =
        msg.payload.params.num_tx_queues = num_queues;
    msg.payload.params.num_rx_bufs = num_rx_bufs;
    msg.payload.params.num_tx_bufs = num_tx_bufs;

    ret = bpfhv_proxy_sendrecv(s, &msg, NULL, 0);
    if (ret) {
        return ret;
    }

    if (msg.payload.ctx_sizes.rx_ctx_size < sizeof(struct bpfhv_rx_context) ||
            msg.payload.ctx_sizes.rx_ctx_size > (1 << 24)) {
        error_report("Invalid RX ctx size %u",
                     msg.payload.ctx_sizes.rx_ctx_size);
        return -1;
    }

    if (msg.payload.ctx_sizes.tx_ctx_size < sizeof(struct bpfhv_tx_context) ||
            msg.payload.ctx_sizes.tx_ctx_size > (1 << 24)) {
        error_report("Invalid TX ctx size %u",
                     msg.payload.ctx_sizes.tx_ctx_size);
        return -1;
    }

    s->rx_ctx_size = (size_t)msg.payload.ctx_sizes.rx_ctx_size;
    s->tx_ctx_size = (size_t)msg.payload.ctx_sizes.tx_ctx_size;

    DBG("Set queue parameters: %u queue pairs, %u rx bufs, %u tx bufs",
        num_queues, num_rx_bufs, num_tx_bufs);
    DBG("Got context sizes: RX %zu, TX %zu", s->rx_ctx_size, s->tx_ctx_size);

    return 0;
}

static int
bpfhv_proxy_get_programs(BpfhvProxyState *s)
{
    BpfhvProxyMessage msg;
    int progfd = -1;
    int ret;

    memset(&msg, 0, sizeof(msg));
    msg.hdr.reqtype = BPFHV_PROXY_REQ_GET_PROGRAMS;
    msg.hdr.size = 0;

    ret = bpfhv_proxy_sendmsg(s, &msg, NULL, 0);
    if (ret) {
        return ret;
    }

    ret = bpfhv_proxy_recvmsg(s, &msg, &progfd, 1);
    if (ret) {
        return ret;
    }

    if (s->progfd >= 0) {
        close(s->progfd);
    }
    s->progfd = progfd;

    DBG("Got program fd (%d)", s->progfd);

    return 0;

}

static int
bpfhv_proxy_set_mem_table(BpfhvProxyState *s)
{
    int fds[BPFHV_PROXY_MAX_REGIONS];
    BpfhvProxyMessage msg;
    size_t num_fds = 0;
    int ret;
    int i;

    if (s->num_mem_regs == 0) {
        return 0;  /* Nothing to do. */
    }

    memset(&msg, 0, sizeof(msg));
    msg.hdr.reqtype = BPFHV_PROXY_REQ_SET_MEM_TABLE;
    msg.hdr.size = sizeof(msg.payload.memory_map);

    msg.payload.memory_map.num_regions = s->num_mem_regs;
    for (i = 0; i < s->num_mem_regs; i++) {
        ram_addr_t offset;
        MemoryRegion *mr;
        int fd;

        mr = memory_region_from_host(s->mem_regs[i].hva_start,
                                     &offset);
        assert(mr != NULL);
        fd = memory_region_get_fd(mr);
        assert(fd >= 0);

        assert(i < BPFHV_PROXY_MAX_REGIONS);
        msg.payload.memory_map.regions[i].guest_physical_addr =
            s->mem_regs[i].gpa_start;
        msg.payload.memory_map.regions[i].size = s->mem_regs[i].size;
        msg.payload.memory_map.regions[i].hypervisor_virtual_addr =
            (uintptr_t)s->mem_regs[i].hva_start;
        msg.payload.memory_map.regions[i].mmap_offset = offset;
        fds[num_fds++] = fd;
    }

    ret = bpfhv_proxy_sendrecv(s, &msg, fds, num_fds);
    if (ret) {
        return ret;
    }

    return 0;
}

static int
bpfhv_proxy_set_queue_ctx(BpfhvProxyState *s, unsigned int queue_idx,
                          hwaddr gpa)
{
    bool is_rx = queue_idx < s->num_queues;
    BpfhvProxyMessage msg;
    int ret;

    memset(&msg, 0, sizeof(msg));
    msg.hdr.reqtype = BPFHV_PROXY_REQ_SET_QUEUE_CTX;
    msg.hdr.size = sizeof(msg.payload.queue_ctx);

    msg.payload.queue_ctx.queue_idx = queue_idx;
    msg.payload.queue_ctx.guest_physical_addr = gpa;

    ret = bpfhv_proxy_sendrecv(s, &msg, NULL, 0);
    if (ret) {
        return ret;
    }

    if (!is_rx) {
        queue_idx -= s->num_queues;
    }
    DBG("Set queue ctx %s%u %"PRIx64"", is_rx ? "RX" : "TX",
            queue_idx, gpa);

    return 0;
}

static void
bpfhv_proxy_stop(BpfhvProxyState *s)
{
    /* TODO stop */
}

static int
bpfhv_proxy_start(BpfhvProxyState *s)
{
    uint64_t guest_features = BPFHV_F_SG;
    uint64_t be_features = 0;
    unsigned int num_bufs = 256;
    int ret;

    /* Negotiate features. */
    ret = bpfhv_proxy_get_features(s, &be_features);
    if (ret) {
        return ret;
    }
    ret = bpfhv_proxy_set_features(s, be_features & guest_features);
    if (ret) {
        return ret;
    }

    /* Set number of queues. and get size of RX and TX contexts. */
    ret = bpfhv_proxy_set_parameters(s, s->num_queues, /*rx=*/num_bufs,
                                     /*tx=*/num_bufs);
    if (ret) {
        return ret;
    }

    /* Get the eBPF programs to be injected to the guest. */
    ret = bpfhv_proxy_get_programs(s);
    if (ret) {
        return ret;
    }

    /* Set the guest memory map. */
    ret = bpfhv_proxy_set_mem_table(s);
    if (ret) {
        return ret;
    }

    /* Set the physical address of RX and TX queues. */
    ret = bpfhv_proxy_set_queue_ctx(s, /*queue_idx=*/0, /*gpa=*/0);
    if (ret) {
        return ret;
    }
    ret = bpfhv_proxy_set_queue_ctx(s, /*queue_idx=*/1, /*gpa=*/0);
    if (ret) {
        return ret;
    }

    return 0;
}

static void
bpfhv_proxy_cleanup(NetClientState *nc)
{
    BpfhvProxyState *s = DO_UPCAST(BpfhvProxyState, nc, nc);

    if (nc->queue_index == 0) {
        if (s->watch) {
            g_source_remove(s->watch);
            s->watch = 0;
        }
        qemu_chr_fe_deinit(&s->chr, true);
    }

    qemu_purge_queued_packets(nc);
}

static bool
bpfhv_proxy_has_vnet_hdr(NetClientState *nc)
{
    assert(nc->info->type == NET_CLIENT_DRIVER_BPFHV_PROXY);

    return true;
}

static bool
bpfhv_proxy_has_ufo(NetClientState *nc)
{
    assert(nc->info->type == NET_CLIENT_DRIVER_BPFHV_PROXY);

    return true;
}

static ssize_t
bpfhv_proxy_receive(NetClientState *nc, const uint8_t *buf, size_t size)
{
    /* Silently drop packets. */
    printf("dropping packet (len=%zu)\n", size);

    return size;
}
static NetClientInfo net_bpfhv_proxy_info = {
    .type = NET_CLIENT_DRIVER_BPFHV_PROXY,
    .size = sizeof(BpfhvProxyState),
    .cleanup = bpfhv_proxy_cleanup,
    .has_vnet_hdr = bpfhv_proxy_has_vnet_hdr,
    .has_ufo = bpfhv_proxy_has_ufo,
    .receive = bpfhv_proxy_receive,
};

static void
bpfhv_proxy_memli_begin(MemoryListener *listener)
{
    BpfhvProxyState *s = container_of(listener, BpfhvProxyState, memory_listener);

    s->num_mem_regs_next = 0;
}

static void
bpfhv_proxy_memli_region_add(MemoryListener *listener,
                       MemoryRegionSection *section)
{
    BpfhvProxyState *s = container_of(listener, BpfhvProxyState, memory_listener);
    uint64_t size = int128_get64(section->size);
    uint64_t gpa_start = section->offset_within_address_space;
    uint64_t gpa_end = range_get_last(gpa_start, size) + 1;
    void *hva_start;
    BpfhvProxyMemliRegion *last = NULL;
    bool add_entry = true;

    if (!memory_region_is_ram(section->mr) ||
            memory_region_get_fd(section->mr) < 0) {
        return;
    }

    hva_start = memory_region_get_ram_ptr(section->mr) +
                      section->offset_within_region;
    DBG("new memory section %lx-%lx sz %lx %p",
        gpa_start, gpa_end, size, hva_start);
    if (s->num_mem_regs_next > 0) {
        /* Check if we can coalasce the last MemoryRegionSection to
         * the current one. */
        last = s->mem_regs_next + s->num_mem_regs_next - 1;
        if (gpa_start == last->gpa_end &&
            hva_start == last->hva_start + last->size) {
            add_entry = false;
            last->gpa_end = gpa_end;
            last->size += size;
        }
    }

    if (add_entry) {
        if (s->num_mem_regs_next >= BPFHV_PROXY_MAX_REGIONS) {
            error_report("Error: Guest memory map has more than "
                         "%zu memory regions.", s->num_mem_regs_next);
            return;
        }
        s->num_mem_regs_next++;
        last = s->mem_regs_next + s->num_mem_regs_next - 1;
        last->gpa_start = gpa_start;
        last->gpa_end = gpa_end;
        last->size = size;
        last->hva_start = hva_start;
        last->mr = section->mr;
        memory_region_ref(last->mr);
    }
}

static void
bpfhv_proxy_memli_commit(MemoryListener *listener)
{
    BpfhvProxyState *s = container_of(listener, BpfhvProxyState, memory_listener);
    bool changed;
    int i;

    /* Swap current map with the next map. */
    {
        BpfhvProxyMemliRegion *mem_regs_tmp;
        int num_mem_regs_tmp;

        mem_regs_tmp = s->mem_regs;
        s->mem_regs = s->mem_regs_next;
        s->mem_regs_next = mem_regs_tmp;
        num_mem_regs_tmp = s->num_mem_regs;
        s->num_mem_regs = s->num_mem_regs_next;
        s->num_mem_regs_next = num_mem_regs_tmp;
    }

#ifdef BPFHV_DEBUG
    DBG("Memtable:");
    for (i = 0; i < s->num_mem_regs; i++) {
        BpfhvProxyMemliRegion *me = s->mem_regs + i;
        DBG("    entry #%d: gpa %lx-%lx size %lx hva_start %p", i,
            me->gpa_start, me->gpa_end, me->size, me->hva_start);
    }
#endif
    changed = s->num_mem_regs != s->num_mem_regs_next ||
              memcmp(s->mem_regs, s->mem_regs_next,
                sizeof(s->mem_regs[0]) * s->num_mem_regs);

    if (s->active && changed) {
        bpfhv_proxy_set_mem_table(s);
    }

    /* Free the (previously) current map. */
    for (i = 0; i < s->num_mem_regs_next; i++) {
        BpfhvProxyMemliRegion *me = s->mem_regs_next + i;
        memory_region_unref(me->mr);
    }
}

static gboolean
bpfhv_proxy_watch(GIOChannel *chan, GIOCondition cond, void *opaque)
{
    BpfhvProxyState *s = opaque;

    qemu_chr_fe_disconnect(&s->chr);

    return TRUE;
}

static void
bpfhv_proxy_event(void *opaque, int event)
{
    const char *name = opaque;
    NetClientState *nc;
    BpfhvProxyState *s;
    Error *err = NULL;

    nc = qemu_find_netdev(name);
    assert(nc != NULL);

    s = DO_UPCAST(BpfhvProxyState, nc, nc);
//  Chardev *chr = qemu_chr_fe_get_driver(&s->chr);
    switch (event) {
    case CHR_EVENT_OPENED:
        DBG("Backend connected (label=%s)", s->chr.chr->label);
        if (bpfhv_proxy_start(s) < 0) {
            qemu_chr_fe_disconnect(&s->chr);
            return;
        }
        s->watch = qemu_chr_fe_add_watch(&s->chr, G_IO_HUP,
                                         bpfhv_proxy_watch, s);
        s->active = true;
        /* Notify the front-end about the link status going up. */
        qmp_set_link(name, true, &err);
        break;

    case CHR_EVENT_CLOSED:
        /* Notify the front-end about the link status going down. */
        qmp_set_link(name, false, &err);
        if (s->watch) {
            g_source_remove(s->watch);
            s->watch = 0;
        }
        s->active = false;
        bpfhv_proxy_stop(s);
        DBG("Backend disconnected (label=%s)", s->chr.chr->label);
        break;
    }

    if (err) {
        error_report_err(err);
    }
}

static int
bpfhv_proxy_check_net_frontend(void *opaque, QemuOpts *opts, Error **errp)
{
    const char *name = opaque;
    const char *driver, *netdev;

    driver = qemu_opt_get(opts, "driver");
    netdev = qemu_opt_get(opts, "netdev");

    if (!driver || !netdev) {
        return 0;
    }

    if (strcmp(netdev, name) == 0 &&
        strcmp(driver, "bpfhv-pci")) {
        error_setg(errp, "bpfhv-proxy requires frontend driver bpfhv-pci");
        return -1;
    }

    return 0;
}

int
net_init_bpfhv_proxy(const Netdev *netdev, const char *name,
                        NetClientState *peer, Error **errp)
{
    const NetdevBpfhvProxyOptions *opts;
    NetClientState *nc = NULL;
    Error *err = NULL;
    BpfhvProxyState *s;
    Chardev *chr;
    int idx = 0;

    assert(netdev->type == NET_CLIENT_DRIVER_BPFHV_PROXY);
    opts = &netdev->u.bpfhv_proxy;

    chr = qemu_chr_find(opts->chardev);
    if (chr == NULL) {
        error_setg(errp, "chardev \"%s\" not found", opts->chardev);
        return -1;
    }

    if (!qemu_chr_has_feature(chr, QEMU_CHAR_FEATURE_RECONNECTABLE)) {
        error_setg(errp, "chardev \"%s\" is not reconnectable",
                   opts->chardev);
        return -1;
    }

    if (!qemu_chr_has_feature(chr, QEMU_CHAR_FEATURE_FD_PASS)) {
        error_setg(errp, "chardev \"%s\" does not support FD passing",
                   opts->chardev);
        return -1;
    }

    /* Check that network fronted is what we expect. */
    if (qemu_opts_foreach(qemu_find_opts("device"),
                          bpfhv_proxy_check_net_frontend,
                          (char *)name, errp)) {
        return -1;
    }

    nc = qemu_new_net_client(&net_bpfhv_proxy_info, peer, "bpfhv_proxy", name);
    snprintf(nc->info_str, sizeof(nc->info_str), "bpfhv-proxy%d to %s",
             idx, chr->label);
    nc->queue_index = idx;
    s = DO_UPCAST(BpfhvProxyState, nc, nc);
    if (!qemu_chr_fe_init(&s->chr, chr, &err)) {
        error_report_err(err);
        goto err;
    }

    s->progfd = -1;
    s->num_queues = 1;

    /* Initialize memory listener. */
    s->mem_regs_next = s->mem_regs_arr[0];
    s->mem_regs = s->mem_regs_arr[1];
    s->memory_listener.priority = 10,
    s->memory_listener.begin = bpfhv_proxy_memli_begin,
    s->memory_listener.commit = bpfhv_proxy_memli_commit,
    s->memory_listener.region_add = bpfhv_proxy_memli_region_add,
    s->memory_listener.region_nop = bpfhv_proxy_memli_region_add,
    memory_listener_register(&s->memory_listener, &address_space_memory);

    do {
        if (qemu_chr_fe_wait_connected(&s->chr, &err) < 0) {
            error_report_err(err);
            memory_listener_unregister(&s->memory_listener);
            goto err;
        }
        qemu_chr_fe_set_handlers(&s->chr, NULL, NULL, bpfhv_proxy_event,
                                 NULL, nc->name, NULL, true);
    } while (!s->active);

    return 0;

err:
    if (nc) {
        qemu_del_net_client(nc);
    }

    return -1;
}
