/*
 * netmap access for qemu
 *
 * Copyright (c) 2012-2013 Luigi Rizzo
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
#include <sys/ioctl.h>
#include <net/if.h>
#define NETMAP_WITH_LIBS
#include <net/netmap.h>
#include <net/netmap_user.h>

#include "net/net.h"
#include "net/tap.h"
#include "clients.h"
#include "sysemu/sysemu.h"
#include "qemu/error-report.h"
#include "qapi/error.h"
#include "qemu/iov.h"
#include "qemu/cutils.h"
#include "hw/net/ptnetmap.h"

typedef struct NetmapState {
    NetClientState      nc;
    int                 fd;
    uint16_t            mem_id;
    void                *mem;
    char                ifname[IFNAMSIZ];
    struct netmap_ring  *tx;
    struct netmap_ring  *rx;
    bool                read_poll;
    bool                write_poll;
    struct iovec        iov[IOV_MAX];
    int                 vnet_hdr_len;  /* Current virtio-net header length. */
    QTAILQ_ENTRY(NetmapState) next;
    PTNetmapState       ptnetmap;
} NetmapState;

static QTAILQ_HEAD(, NetmapState) netmap_clients =
                   QTAILQ_HEAD_INITIALIZER(netmap_clients);

#ifndef __FreeBSD__
#define pkt_copy bcopy
#else
/* A fast copy routine only for multiples of 64 bytes, non overlapped. */
static inline void pkt_copy(const void *_src, void *_dst, int l)
{
    const uint64_t *src = _src;
    uint64_t *dst = _dst;
    if (unlikely(l >= 1024)) {
        bcopy(src, dst, l);
        return;
    }
    for (; l > 0; l -= 64) {
        *dst++ = *src++;
        *dst++ = *src++;
        *dst++ = *src++;
        *dst++ = *src++;
        *dst++ = *src++;
        *dst++ = *src++;
        *dst++ = *src++;
        *dst++ = *src++;
    }
}
#endif /* __FreeBSD__ */

/*
 * find nm_desc parent with same allocator
 */
static NetmapState *netmap_find_memory(uint16_t mem_id, NetmapState *exclude)
{
    NetmapState *s;

    QTAILQ_FOREACH(s, &netmap_clients, next) {
        if (s != exclude && mem_id == s->mem_id) {
            printf("Found netmap parent: ifname: %s mem_id: %d\n",
                    s->ifname, s->mem_id);
            return s;
        }
    }

    return NULL;
}

/*
 * Open a netmap device. We only use the first TX ring and the first
 * RX ring, even if there are more.
 */
static int netmap_open(NetmapState *s, Error **errp)
{
    struct nmreq_register req;
    struct nmreq_header hdr;
    struct netmap_if *nifp;
    NetmapState *other;
    int ret;

    s->fd = open("/dev/netmap", O_RDWR);
    if (s->fd < 0) {
        error_setg_errno(errp, errno, "Failed to open(/dev/netmap)");
        return -1;
    }

    memset(&hdr, 0, sizeof(hdr));
    memset(&req, 0, sizeof(req));

    hdr.nr_version = NETMAP_API;
    strncpy(hdr.nr_name, s->ifname, sizeof(hdr.nr_name) - 1);
    hdr.nr_reqtype = NETMAP_REQ_REGISTER;
    hdr.nr_body    = (uintptr_t)&req;
    hdr.nr_options = (uintptr_t)NULL;
    req.nr_mode    = NR_REG_ALL_NIC;
    req.nr_flags   = NR_EXCLUSIVE | NR_NO_TX_POLL;
    ret            = ioctl(s->fd, NIOCCTRL, &hdr);
    if (ret) {
        error_setg_errno(errp, errno, "Failed to register %s", s->ifname);
        return ret;
    }
    s->mem_id = req.nr_mem_id;

    /* Check if we already have a netmap port that uses the same memory as the
     * one just opened, so that nm_mmap() can skip mmap() and inherit from
     * parent. */
    other = netmap_find_memory(req.nr_mem_id, s);
    if (!other) {
        s->mem = mmap(0, req.nr_memsize, PROT_WRITE | PROT_READ,
                        MAP_SHARED, s->fd, 0);
        if (s->mem == MAP_FAILED) {
            error_setg_errno(errp, errno, "Failed to mmap %s",
                    s->ifname);
            return -1;
        }
    } else {
        s->mem = other->mem;
    }
    nifp = NETMAP_IF(s->mem, req.nr_offset);
    s->tx = NETMAP_TXRING(nifp, 0);
    s->rx = NETMAP_RXRING(nifp, 0);

    return 0;
}

static void netmap_send(void *opaque);
static void netmap_writable(void *opaque);

/* Set the event-loop handlers for the netmap backend. */
static void netmap_update_fd_handler(NetmapState *s)
{
    qemu_set_fd_handler(s->fd,
                        s->read_poll ? netmap_send : NULL,
                        s->write_poll ? netmap_writable : NULL,
                        s);
}

/* Update the read handler. */
static void netmap_read_poll(NetmapState *s, bool enable)
{
    if (s->read_poll != enable) { /* Do nothing if not changed. */
        s->read_poll = enable;
        netmap_update_fd_handler(s);
    }
}

/* Update the write handler. */
static void netmap_write_poll(NetmapState *s, bool enable)
{
    if (s->write_poll != enable) {
        s->write_poll = enable;
        netmap_update_fd_handler(s);
    }
}

static void netmap_poll(NetClientState *nc, bool enable)
{
    NetmapState *s = DO_UPCAST(NetmapState, nc, nc);

    if (s->read_poll != enable || s->write_poll != enable) {
        s->write_poll = enable;
        s->read_poll  = enable;
        netmap_update_fd_handler(s);
    }
}

/*
 * The fd_write() callback, invoked if the fd is marked as
 * writable after a poll. Unregister the handler and flush any
 * buffered packets.
 */
static void netmap_writable(void *opaque)
{
    NetmapState *s = opaque;

    netmap_write_poll(s, false);
    qemu_flush_queued_packets(&s->nc);
}

static ssize_t netmap_receive(NetClientState *nc,
      const uint8_t *buf, size_t size)
{
    NetmapState *s = DO_UPCAST(NetmapState, nc, nc);
    struct netmap_ring *ring = s->tx;
    uint32_t i;
    uint32_t idx;
    uint8_t *dst;

    if (unlikely(!ring)) {
        /* Drop. */
        return size;
    }

    if (unlikely(size > ring->nr_buf_size)) {
        RD(5, "[netmap_receive] drop packet of size %d > %d\n",
                                    (int)size, ring->nr_buf_size);
        return size;
    }

    if (nm_ring_empty(ring)) {
        /* No available slots in the netmap TX ring. */
        netmap_write_poll(s, true);
        return 0;
    }

    i = ring->cur;
    idx = ring->slot[i].buf_idx;
    dst = (uint8_t *)NETMAP_BUF(ring, idx);

    ring->slot[i].len = size;
    ring->slot[i].flags = 0;
    pkt_copy(buf, dst, size);
    ring->cur = ring->head = nm_ring_next(ring, i);
    ioctl(s->fd, NIOCTXSYNC, NULL);

    return size;
}

static ssize_t netmap_receive_iov(NetClientState *nc,
                    const struct iovec *iov, int iovcnt)
{
    NetmapState *s = DO_UPCAST(NetmapState, nc, nc);
    struct netmap_ring *ring = s->tx;
    uint32_t last;
    uint32_t idx;
    uint8_t *dst;
    int j;
    uint32_t i;

    if (unlikely(!ring)) {
        /* Drop the packet. */
        return iov_size(iov, iovcnt);
    }

    last = i = ring->cur;

    if (nm_ring_space(ring) < iovcnt) {
        /* Not enough netmap slots. */
        netmap_write_poll(s, true);
        return 0;
    }

    for (j = 0; j < iovcnt; j++) {
        int iov_frag_size = iov[j].iov_len;
        int offset = 0;
        int nm_frag_size;

        /* Split each iovec fragment over more netmap slots, if
           necessary. */
        while (iov_frag_size) {
            nm_frag_size = MIN(iov_frag_size, ring->nr_buf_size);

            if (unlikely(nm_ring_empty(ring))) {
                /* We run out of netmap slots while splitting the
                   iovec fragments. */
                netmap_write_poll(s, true);
                return 0;
            }

            idx = ring->slot[i].buf_idx;
            dst = (uint8_t *)NETMAP_BUF(ring, idx);

            ring->slot[i].len = nm_frag_size;
            ring->slot[i].flags = NS_MOREFRAG;
            pkt_copy(iov[j].iov_base + offset, dst, nm_frag_size);

            last = i;
            i = nm_ring_next(ring, i);

            offset += nm_frag_size;
            iov_frag_size -= nm_frag_size;
        }
    }
    /* The last slot must not have NS_MOREFRAG set. */
    ring->slot[last].flags &= ~NS_MOREFRAG;

    /* Now update ring->cur and ring->head. */
    ring->cur = ring->head = i;

    ioctl(s->fd, NIOCTXSYNC, NULL);

    return iov_size(iov, iovcnt);
}

/* Complete a previous send (backend --> guest) and enable the
   fd_read callback. */
static void netmap_send_completed(NetClientState *nc, ssize_t len)
{
    NetmapState *s = DO_UPCAST(NetmapState, nc, nc);

    netmap_read_poll(s, true);
}

static void netmap_send(void *opaque)
{
    NetmapState *s = opaque;
    struct netmap_ring *ring = s->rx;

    /* Keep sending while there are available packets into the netmap
       RX ring and the forwarding path towards the peer is open. */
    while (!nm_ring_empty(ring)) {
        uint32_t i;
        uint32_t idx;
        bool morefrag;
        int iovcnt = 0;
        int iovsize;

        do {
            i = ring->cur;
            idx = ring->slot[i].buf_idx;
            morefrag = (ring->slot[i].flags & NS_MOREFRAG);
            s->iov[iovcnt].iov_base = (u_char *)NETMAP_BUF(ring, idx);
            s->iov[iovcnt].iov_len = ring->slot[i].len;
            iovcnt++;

            ring->cur = ring->head = nm_ring_next(ring, i);
        } while (!nm_ring_empty(ring) && morefrag);

        if (unlikely(nm_ring_empty(ring) && morefrag)) {
            RD(5, "[netmap_send] ran out of slots, with a pending"
                   "incomplete packet\n");
        }

        iovsize = qemu_sendv_packet_async(&s->nc, s->iov, iovcnt,
                                            netmap_send_completed);

        if (iovsize == 0) {
            /* The peer does not receive anymore. Packet is queued, stop
             * reading from the backend until netmap_send_completed()
             */
            netmap_read_poll(s, false);
            break;
        }
    }
}

/* Flush and close. */
static void netmap_cleanup(NetClientState *nc)
{
    NetmapState *s = DO_UPCAST(NetmapState, nc, nc);

    qemu_purge_queued_packets(nc);
    ptnetmap_kloop_stop(&s->ptnetmap);

    if (s->fd >= 0) {
        netmap_poll(nc, false);
        close(s->fd);
        s->fd = -1;
    }

    QTAILQ_REMOVE(&netmap_clients, s, next);
}

static void nmreq_hdr_init(struct nmreq_header *hdr, const char *ifname)
{
    memset(hdr, 0, sizeof(*hdr));
    hdr->nr_version = NETMAP_API;
    strncpy(hdr->nr_name, ifname, sizeof(hdr->nr_name) - 1);
}

/* Offloading manipulation support callbacks. */
static int netmap_fd_set_vnet_hdr_len(NetmapState *s, int len)
{
    /* Issue a NETMAP_REQ_PORT_HDR_SET command to change the virtio-net header
     * length for the netmap adapter associated to 's->ifname'. We reuse
     * 's->fd' for convenience, although we could use a different (unbound)
     * netmap control device.
     */
    struct nmreq_port_hdr req;
    struct nmreq_header hdr;

    nmreq_hdr_init(&hdr, s->ifname);
    hdr.nr_reqtype = NETMAP_REQ_PORT_HDR_SET;
    hdr.nr_body    = (uintptr_t)&req;
    memset(&req, 0, sizeof(req));
    req.nr_hdr_len = len;

    return ioctl(s->fd, NIOCCTRL, &hdr);
}

static bool netmap_has_vnet_hdr_len(NetClientState *nc, int len)
{
    NetmapState *s = DO_UPCAST(NetmapState, nc, nc);
    int prev_len = s->vnet_hdr_len;

    /* Check that we can set the new length. */
    if (netmap_fd_set_vnet_hdr_len(s, len)) {
        return false;
    }

    /* Restore the previous length. */
    if (netmap_fd_set_vnet_hdr_len(s, prev_len)) {
        error_report("Failed to restore vnet-hdr length %d on %s: %s",
                     prev_len, s->ifname, strerror(errno));
    }

    return true;
}

/* A netmap interface that supports virtio-net headers always
 * supports UFO, so we use this callback also for the has_ufo hook. */
static bool netmap_has_vnet_hdr(NetClientState *nc)
{
    return netmap_has_vnet_hdr_len(nc, sizeof(struct virtio_net_hdr));
}

static void netmap_using_vnet_hdr(NetClientState *nc, bool enable)
{
}

static void netmap_set_vnet_hdr_len(NetClientState *nc, int len)
{
    NetmapState *s = DO_UPCAST(NetmapState, nc, nc);
    int err;

    err = netmap_fd_set_vnet_hdr_len(s, len);
    if (err) {
        error_report("Unable to set vnet-hdr length %d on %s: %s",
                     len, s->ifname, strerror(errno));
    } else {
        /* Keep track of the current length. */
        s->vnet_hdr_len = len;
    }
}

static void netmap_set_offload(NetClientState *nc, int csum, int tso4, int tso6,
                               int ecn, int ufo)
{
    NetmapState *s = DO_UPCAST(NetmapState, nc, nc);

    /* Setting a virtio-net header length greater than zero automatically
     * enables the offloadings. */
    if (!s->vnet_hdr_len) {
        netmap_set_vnet_hdr_len(nc, sizeof(struct virtio_net_hdr));
    }
}

/* NetClientInfo methods */
static NetClientInfo net_netmap_info = {
    .type = NET_CLIENT_DRIVER_NETMAP,
    .size = sizeof(NetmapState),
    .receive = netmap_receive,
    .receive_iov = netmap_receive_iov,
    .poll = netmap_poll,
    .cleanup = netmap_cleanup,
    .has_ufo = netmap_has_vnet_hdr,
    .has_vnet_hdr = netmap_has_vnet_hdr,
    .has_vnet_hdr_len = netmap_has_vnet_hdr_len,
    .using_vnet_hdr = netmap_using_vnet_hdr,
    .set_offload = netmap_set_offload,
    .set_vnet_hdr_len = netmap_set_vnet_hdr_len,
};

/*
 * Support for netmap passthrough.
 */

PTNetmapState *get_ptnetmap(NetClientState *nc)
{
    NetmapState *s = DO_UPCAST(NetmapState, nc, nc);
    struct nmreq_pools_info pi;
    struct nmreq_header hdr;
    int err;

    if (nc->info->type != NET_CLIENT_DRIVER_NETMAP
                              || s->ptnetmap.netmap != s) {
        return NULL;
    }

    /* Use NETMAP_REQ_POOLS_INFO_GET to get information about the memory
     * allocator for 's->ifname'. We reuse 's->fd' for convenience, although
     * we could use a different (unbound) netmap control device.*/
    nmreq_hdr_init(&hdr, s->ifname);
    hdr.nr_reqtype = NETMAP_REQ_POOLS_INFO_GET;
    hdr.nr_body    = (uintptr_t)&pi;
    memset(&pi, 0, sizeof(pi));
    err = ioctl(s->fd, NIOCCTRL, &hdr);
    if (err) {
        error_report("Unable to execute POOLS_INFO_GET on %s: %s",
                     s->ifname, strerror(errno));
        return NULL;
    }

    /* Create a new ptnetmap memdev that exposes the memory allocator,
     * if it does not exist yet. */
    ptnetmap_memdev_create(s->mem, &pi);

    return &s->ptnetmap;
}

/* Store and return the features we agree upon. */
uint32_t ptnetmap_ack_features(PTNetmapState *ptn, uint32_t wanted_features)
{
    ptn->acked_features = ptn->features & wanted_features;

    return ptn->acked_features;
}

/* Get info on 's->ifname'. We reuse 's->fd' for convenience, although we
 * could use a different (unbound) netmap control device. */
static int netmap_port_info_get(NetmapState *s, struct nmreq_port_info_get *nif)
{
    struct nmreq_header hdr;
    int ret;

    nmreq_hdr_init(&hdr, s->ifname);
    hdr.nr_reqtype = NETMAP_REQ_PORT_INFO_GET;
    hdr.nr_body    = (uintptr_t)nif;
    memset(nif, 0, sizeof(*nif));
    ret = ioctl(s->fd, NIOCCTRL, &hdr);
    if (ret) {
        error_report("NETMAP_REQ_PORT_INFO_GET failed on %s", s->ifname);
    }

    return ret;
}

int ptnetmap_get_netmap_if(PTNetmapState *ptn, struct nmreq_port_info_get *nif)
{
    if (!ptn) {
        error_report("Cannot get netmap info on a backend that "
                     "is not netmap");
        return -1;
    }

    return netmap_port_info_get(ptn->netmap, nif);
}

int ptnetmap_get_hostmemid(PTNetmapState *ptn)
{
    NetmapState *s = ptn->netmap;

    return s->mem_id;
}

struct SyncKloopThreadCtx {
    NetmapState *s;
    int num_entries;
    int *ioeventfds;
    int *irqfds;
    void *csb_gh;
    void *csb_hg;
};

/* Start a kernel sync loop for the netmap rings bound to 's->fd'. */
static void *ptnetmap_sync_kloop_worker(void *opaque)
{
    struct nmreq_opt_sync_kloop_eventfds *evopt;
    struct SyncKloopThreadCtx *ctx = opaque;
    struct nmreq_sync_kloop_start req;
    struct nmreq_opt_csb csbopt;
    NetmapState *s = ctx->s;
    struct nmreq_header hdr;
    size_t opt_size;
    int err, i;

    /* Prepare the CSB option. */
    memset(&csbopt, 0, sizeof(csbopt));
    csbopt.nro_opt.nro_reqtype = NETMAP_REQ_OPT_CSB;
    csbopt.csb_atok = (uintptr_t)ctx->csb_gh;
    csbopt.csb_ktoa = (uintptr_t)ctx->csb_hg;

    /* Prepare the eventfds option. */
    opt_size = sizeof(*evopt) + ctx->num_entries * sizeof(evopt->eventfds[0]);
    evopt = g_malloc(opt_size);
    memset(evopt, 0, opt_size);
    evopt->nro_opt.nro_next    = 0;
    evopt->nro_opt.nro_reqtype = NETMAP_REQ_OPT_SYNC_KLOOP_EVENTFDS;
    evopt->nro_opt.nro_status  = 0;
    evopt->nro_opt.nro_size    = opt_size;
    for (i = 0; i < ctx->num_entries; i++) {
        evopt->eventfds[i].ioeventfd = ctx->ioeventfds[i];
        evopt->eventfds[i].irqfd     = ctx->irqfds[i];
    }

    /* Link the two options together. */
    csbopt.nro_opt.nro_next = (uintptr_t)evopt;

    /* Prepare the request and link the options. */
    nmreq_hdr_init(&hdr, s->ifname);
    hdr.nr_reqtype = NETMAP_REQ_SYNC_KLOOP_START;
    hdr.nr_body    = (uintptr_t)&req;
    hdr.nr_options = (uintptr_t)&csbopt;
    memset(&req, 0, sizeof(req));
    req.sleep_us = 100;  /* ignored by the kernel */
    err          = ioctl(s->fd, NIOCCTRL, &hdr);
    if (err) {
        error_report("Unable to execute SYNC_KLOOP_START on %s: %s",
                     s->ifname, strerror(errno));
    }

    g_free(evopt);
    g_free(ctx->ioeventfds);
    g_free(ctx->irqfds);
    g_free(ctx);

    return NULL;
}

int ptnetmap_kloop_start(PTNetmapState *ptn, void *csb_gh, void *csb_hg,
                unsigned int num_entries, int *ioeventfds, int *irqfds)
{
    struct SyncKloopThreadCtx *ctx;
    NetmapState *s = ptn->netmap;

    if (ptn->worker_started) {
        g_free(ioeventfds);
        g_free(irqfds);
        return 0;
    }

    /* Ask netmap to start sync-kloop. */
    ctx = g_malloc(sizeof(*ctx));
    ctx->s = s;
    ctx->csb_gh = csb_gh;
    ctx->csb_hg = csb_hg;
    ctx->num_entries = num_entries;
    ctx->ioeventfds = ioeventfds;
    ctx->irqfds = irqfds;
    qemu_thread_create(&ptn->th, "ptnetmap-sync-kloop",
                       ptnetmap_sync_kloop_worker, ctx, QEMU_THREAD_JOINABLE);

    ptn->worker_started = true;

    return 0;
}

int ptnetmap_kloop_stop(PTNetmapState *ptn)
{
    NetmapState *s = ptn->netmap;
    struct nmreq_header hdr;
    int err = 0;

    if (!ptn->worker_started) {
        return 0;
    }

    /* Ask netmap to stop sync-kloop for the rings bound to 's->fd'. */
    nmreq_hdr_init(&hdr, s->ifname);
    hdr.nr_reqtype = NETMAP_REQ_SYNC_KLOOP_STOP;
    err            = ioctl(s->fd, NIOCCTRL, &hdr);
    if (err) {
        error_report("Unable to execute SYNC_KLOOP_STOP on %s: %s",
                     s->ifname, strerror(errno));
        err = -errno;
    }
    qemu_thread_join(&ptn->th);
    ptn->worker_started = false;

    return err;
}

/* The exported init function
 *
 * ... -net netmap,ifname="..."
 */
int net_init_netmap(const Netdev *netdev,
                    const char *name, NetClientState *peer, Error **errp)
{
    const NetdevNetmapOptions *netmap_opts = &netdev->u.netmap;
    const char *ifname = netmap_opts->ifname;
    const char *nmpref = "netmap:";
    NetClientState *nc;
    Error *err = NULL;
    NetmapState *s;

    /* Create a new net client object. */
    nc = qemu_new_net_client(&net_netmap_info, peer, "netmap", name);
    s = DO_UPCAST(NetmapState, nc, nc);
    QTAILQ_INSERT_TAIL(&netmap_clients, s, next);
    s->vnet_hdr_len = 0;

    /* Strip the netmap prefix, if present. */
    if (!strncmp(ifname, nmpref, strlen(nmpref))) {
        ifname += strlen(nmpref);
    }
    pstrcpy(s->ifname, sizeof(s->ifname), ifname);

    /* Open a netmap control device and bind it to 's->ifname'. This must
     * be done before all the subsequent ioctl() operations. */
    netmap_open(s, &err);
    if (err) {
        error_propagate(errp, err);
        return -1;
    }

    if (!netmap_opts->passthrough) {
        /* Initially only poll for reads. We poll on write only when
         * the TX rings become full. */
        netmap_read_poll(s, true);
    } else {
        /* Enable get_ptnetmap() by initializing s->ptnetmap.netmap. Also
         * check if 's->ifname' supports virtio-net headers. */
        s->ptnetmap.netmap = s;
        s->ptnetmap.features = 0;
        s->ptnetmap.acked_features = 0;
        s->ptnetmap.worker_started = false;

        if (netmap_has_vnet_hdr_len(nc, sizeof(struct virtio_net_hdr_v1))) {
            s->ptnetmap.features |= PTNETMAP_F_VNET_HDR;
        }
    }

    return 0;
}

