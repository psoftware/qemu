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
#include "trace.h"

#include "bpfhv-proxy.h"
#include "../hw/net/bpfhv.h"

/* Verbose debug information. */
#define BPFHV_DEBUG

#ifdef BPFHV_DEBUG
#define DBG(fmt, ...) do { \
        fprintf(stderr, "bpfhv-if: " fmt "\n", ## __VA_ARGS__); \
    } while (0)
#else
#define DBG(fmt, ...) do {} while (0)
#endif

typedef struct BpfhvProxyState {
    NetClientState nc;
    CharBackend chr; /* only queue index 0 */
    guint watch;
    bool active;
} BpfhvProxyState;

static int
bpfhv_proxy_sendmsg(BpfhvProxyState *s, const BpfhvProxyMessage *msg)
{
    size_t size = sizeof(msg->hdr) + msg->hdr.size;
    int ret;

#if 0
    if (qemu_chr_fe_set_msgfds(chr, fds, fd_num) < 0) {
        error_report("Failed to set msg fds.");
        return -1;
    }
#endif

    ret = qemu_chr_fe_write_all(&s->chr, (const uint8_t *)msg, size);
    if (ret != size) {
        error_report("Failed to write msg."
                     " Wrote %d instead of %zu.", ret, size);
        return -1;
    }

    return 0;
}

static int
bpfhv_proxy_recvmsg(BpfhvProxyState *s, BpfhvProxyMessage *msg)
{
    int size = sizeof(msg->hdr), ret;

    /* Read message header. */
    ret = qemu_chr_fe_read_all(&s->chr, (uint8_t *)&msg->hdr, size);
    if (ret != size) {
        error_report("Failed to read msg header. Read %d instead of %d.",
                     ret, size);
        return -1;
    }

    /* Validate payload size. */
    if (msg->hdr.size > sizeof(msg->payload)) {
        error_report("Failed to read msg header. "
                "Size %u exceeds the maximum %zu.", msg->hdr.size,
                sizeof(msg->payload));
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
bpfhv_proxy_get_features(BpfhvProxyState *s, uint64_t *features)
{
    BpfhvProxyMessage msg;
    int ret;

    memset(&msg, 0, sizeof(msg));
    msg.hdr.reqtype = BPFHV_PROXY_REQ_GET_FEATURES;

    ret = bpfhv_proxy_sendmsg(s, &msg);
    if (ret) {
        return ret;
    }

    ret = bpfhv_proxy_recvmsg(s, &msg);
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

    ret = bpfhv_proxy_sendmsg(s, &msg);

    if (ret == 0) {
        DBG("Set features %llx", (long long unsigned)features);
    }

    return ret;
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
    int ret;

    ret = bpfhv_proxy_get_features(s, &be_features);
    if (ret) {
        return ret;
    }

    return bpfhv_proxy_set_features(s, be_features & guest_features);
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

static gboolean
bpfhv_proxy_watch(GIOChannel *chan, GIOCondition cond,
                                           void *opaque)
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
        qmp_set_link(name, true, &err);
        s->active = true;
        break;

    case CHR_EVENT_CLOSED:
        if (s->watch) {
            g_source_remove(s->watch);
            s->watch = 0;
        }
        qmp_set_link(name, false, &err);
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

    do {
        if (qemu_chr_fe_wait_connected(&s->chr, &err) < 0) {
            error_report_err(err);
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
