/*
 * vhost-mpi support
 *
 * Copyright Nextworks 2014
 *
 * Authors:
 *  Vincenzo Maffione <v.maffione@nextworks.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Contributions after 2012-01-13 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#include "hw/virtio/virtio-mpi.h"
#include "net/vhost_mpi.h"
#include "qemu/error-report.h"

#include "config.h"

// TODO #ifdef CONFIG_VHOST_MPI
#include <linux/vhost.h>
#include <sys/socket.h>
#include <linux/kvm.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/virtio_ring.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>

#include <stdio.h>

#include "hw/virtio/vhost.h"
#include "hw/virtio/virtio-bus.h"


#define CONFIG_VHOST_MPI_TEST
#ifdef CONFIG_VHOST_MPI_TEST
#include <pthread.h>
#include <sys/poll.h>
#include <time.h>


#define BAN "vhost_mpi_test: "
static const char *text = "Ciao dall'host!";

struct vhost_mpi_tester_data {
    int vhostfd;
    int stop;
#define MODE_WRITE  0
#define MODE_READ   1
    int mode;
    struct timespec period_ts;
};

static __inline struct timespec
timespec_add(struct timespec a, struct timespec b)
{
	struct timespec ret = { a.tv_sec + b.tv_sec, a.tv_nsec + b.tv_nsec };
	if (ret.tv_nsec >= 1000000000) {
		ret.tv_sec++;
		ret.tv_nsec -= 1000000000;
	}
	return ret;
}

static __inline struct timespec
timespec_sub(struct timespec a, struct timespec b)
{
	struct timespec ret = { a.tv_sec - b.tv_sec, a.tv_nsec - b.tv_nsec };
	if (ret.tv_nsec < 0) {
		ret.tv_sec--;
		ret.tv_nsec += 1000000000;
	}
	return ret;
}

/*
 * wait until ts, either busy or sleeping if more than 1ms.
 * Return wakeup time.
 */
static struct timespec
wait_time(struct timespec ts)
{
	for (;;) {
		struct timespec w, cur;
		clock_gettime(CLOCK_MONOTONIC, &cur);
		w = timespec_sub(ts, cur);
		if (w.tv_sec < 0)
			return cur;
		else if (w.tv_sec > 0 || w.tv_nsec > 1000000)
			poll(NULL, 0, 1);
	}
}

static void *vhost_mpi_tester_work(void *arg)
{
    struct vhost_mpi_tester_data *data = arg;
    char *buffer;
    size_t buffer_size = 2048;
    int n;
    int len;
    struct timespec next_ts;

    buffer = malloc(buffer_size);
    if (!buffer) {
        printf(BAN "buffer allocation failed\n");
        return NULL;
    }

    printf(BAN "Worker thread started [mode = %d] ...\n", data->mode);

    /* Fill the buffer for writes. */
    strcpy(buffer, text);
    len = strlen(buffer) + 1;

    clock_gettime(CLOCK_MONOTONIC, &next_ts);

    while (!data->stop) {
        if (data->mode == MODE_READ) {
            n = read(data->vhostfd, buffer, buffer_size);
            if (n < 0) {
                perror(BAN "read failed %d\n");
                exit(EXIT_FAILURE);
            }
#ifdef VERBOSE
            printf("read %d bytes: '", n);
            {
                int j;

                for (j = 0; j < n; j++) {
                    printf("%c", buffer[j]);
                }
                printf("'\n");
            }
#endif
        } else {
            n = write(data->vhostfd, buffer, len);
            if (n < 0) {
                perror(BAN "write failed %d\n");
                exit(EXIT_FAILURE);
            }
            wait_time(next_ts);
            next_ts = timespec_add(next_ts, data->period_ts);
#ifdef VERBOSE
            printf("written %d bytes\n", n);
#endif
        }
    }

    free(buffer);

    printf(BAN "... worker thread stopped\n");

    return NULL;
}

static void *vhost_mpi_tester_ctrl(void *arg)
{
    struct vhost_mpi_tester_data *data = arg;
    char inbuf[10];
    pthread_t wth;
    int r;
    int running = 0;
    unsigned long int nsecs;

    for (;;) {
        printf(BAN "    command [w|r|s] >>\n");
        r = read(0, inbuf, sizeof(inbuf));
        if (r <= 0) {
            if (r < 0) {
                perror("ctrlread\n");
            }
            continue;
        }

        switch (inbuf[0]) {
            case 'w':
            case 'r':
                if (running) {
                    printf(BAN "Worker thread already running\n");
                    break;
                }
                data->stop = 0;
                data->period_ts.tv_sec = 0;
                data->period_ts.tv_nsec = 1 * 1000 * 1000;
                if (inbuf[0] == 'r') {
                    data->mode = MODE_READ;
                } else {
                    data->mode = MODE_WRITE;
                }
                r = pthread_create(&wth, NULL, vhost_mpi_tester_work, (void *)data);
                if (r < 0) {
                    perror(BAN "Cannot start the thread\n");
                }
                running = 1;
                break;

            case 's':
                if (!running) {
                    printf(BAN "No worker thread is running\n");
                    break;
                }
                data->stop = 1;
                pthread_join(wth, NULL);
                running = 0;
                break;

            case '+':
                if (!running) {
                    printf(BAN "No worker thread is running\n");
                    break;
                }
                nsecs = data->period_ts.tv_nsec;
                nsecs += nsecs/25;
                if (nsecs >= 1000 * 1000 * 1000) {
                    nsecs = 1000 * 1000 * 1000 - 1;
                }
                data->period_ts.tv_nsec = nsecs;
                printf(BAN "new period: %lu ns\n", data->period_ts.tv_nsec);
                break;

            case '-':
                if (!running) {
                    printf(BAN "No worker thread is running\n");
                    break;
                }
                nsecs = data->period_ts.tv_nsec;
                nsecs -= nsecs/25;
                if (nsecs <= 0) {
                    nsecs = 1;
                }
                data->period_ts.tv_nsec = nsecs;
                printf(BAN "new period: %lu ns\n", data->period_ts.tv_nsec);
                break;
    
            default:
                printf(BAN "ctrl: unknown command\n");
                break;
        }

    }

    return NULL;
}

static int vhost_mpi_test_started = 0;

static void vhost_mpi_test(int vhostfd)
{
    pthread_t cth;
    int r;
    struct vhost_mpi_tester_data *data;

    if (vhost_mpi_test_started) {
        return;
    }
    vhost_mpi_test_started = 1;

    data = malloc(sizeof(*data));
    if (data == NULL) {
        printf(BAN "cannot allocate tester data\n");
        return;
    }
    data->vhostfd = vhostfd;

    /* Create the control thread. */
    r = pthread_create(&cth, NULL, vhost_mpi_tester_ctrl, (void *)data);
    if (r < 0) {
        printf(BAN "Cannot start the thread\n");
    }
}
#endif

struct vhost_mpi {
    struct vhost_dev dev;
    struct vhost_virtqueue vqs[2];
};

unsigned vhost_mpi_get_features(struct vhost_mpi *net, unsigned features)
{
    /* Clear features not supported by host kernel. */
    if (!(net->dev.features & (1 << VIRTIO_F_NOTIFY_ON_EMPTY))) {
        features &= ~(1 << VIRTIO_F_NOTIFY_ON_EMPTY);
    }
    if (!(net->dev.features & (1 << VIRTIO_RING_F_INDIRECT_DESC))) {
        features &= ~(1 << VIRTIO_RING_F_INDIRECT_DESC);
    }
    if (!(net->dev.features & (1 << VIRTIO_RING_F_EVENT_IDX))) {
        features &= ~(1 << VIRTIO_RING_F_EVENT_IDX);
    }
    return features;
}

void vhost_mpi_ack_features(struct vhost_mpi *net, unsigned features)
{
    net->dev.acked_features = net->dev.backend_features;
    if (features & (1 << VIRTIO_F_NOTIFY_ON_EMPTY)) {
        net->dev.acked_features |= (1 << VIRTIO_F_NOTIFY_ON_EMPTY);
    }
    if (features & (1 << VIRTIO_RING_F_INDIRECT_DESC)) {
        net->dev.acked_features |= (1 << VIRTIO_RING_F_INDIRECT_DESC);
    }
    if (features & (1 << VIRTIO_RING_F_EVENT_IDX)) {
        net->dev.acked_features |= (1 << VIRTIO_RING_F_EVENT_IDX);
    }
}

struct vhost_mpi *vhost_mpi_init(int devfd, bool force)
{
    int r;
    struct vhost_mpi *net = g_malloc(sizeof *net);
    net->dev.backend_features = 0;

    /* XXX probably VirtIODevice could be VirtIOMpi, and the
        caller needs to link the VirtIOMpi instance to the vhost_mpi instance
        allocated here.  */

    net->dev.nvqs = 2;
    net->dev.vqs = net->vqs;

    r = vhost_dev_init(&net->dev, devfd, "/dev/vhost-mpi", force);
    if (r < 0) {
        goto fail;
    }
    if (~net->dev.features & net->dev.backend_features) {
        fprintf(stderr, "vhost lacks feature mask %" PRIu64 " for backend\n",
                (uint64_t)(~net->dev.features & net->dev.backend_features));
        vhost_dev_cleanup(&net->dev);
        goto fail;
    }

    /* Set sane init value. Override when guest acks. */
    vhost_mpi_ack_features(net, 0);
    return net;
fail:
    g_free(net);
    return NULL;
}

bool vhost_mpi_query(VHostMpiState *net, VirtIODevice *dev)
{
    return vhost_dev_query(&net->dev, dev);
}

struct vhost_mpi_command {
    unsigned int index;
    unsigned int enable;
};

/* Name overloading. Should be a temporary solution. */
#define VHOST_MPI_STARTSTOP     VHOST_NET_SET_BACKEND

static int vhost_mpi_start_one(struct vhost_mpi *net,
                               VirtIODevice *dev,
                               int vq_index)
{
    int r;
    struct vhost_mpi_command cmd = {
            .enable = 1,
        };

    if (net->dev.started) {
        return 0;
    }

    net->dev.nvqs = 2;
    net->dev.vqs = net->vqs;
    net->dev.vq_index = vq_index;

    r = vhost_dev_enable_notifiers(&net->dev, dev);
    if (r < 0) {
        goto fail_notifiers;
    }

    r = vhost_dev_start(&net->dev, dev);
    if (r < 0) {
        goto fail_start;
    }

    /* VHOST_NET_SET_BACKEND used to implement "VHOST_MPI_START" */
    for (cmd.index = 0; cmd.index < net->dev.nvqs; cmd.index++) {
        r = ioctl(net->dev.control, VHOST_MPI_STARTSTOP, &cmd);
        if (r < 0) {
            r = -errno;
            goto fail;
        }
    }

#ifdef CONFIG_VHOST_MPI_TEST
    vhost_mpi_test(net->dev.control);
#endif

    return 0;
fail:
    cmd.enable = 0;
    while (cmd.index-- > 0) {
        int r = ioctl(net->dev.control, VHOST_NET_SET_BACKEND, &cmd);
        assert(r >= 0);
    }
    vhost_dev_stop(&net->dev, dev);
fail_start:
    vhost_dev_disable_notifiers(&net->dev, dev);
fail_notifiers:
    return r;
}

static void vhost_mpi_stop_one(struct vhost_mpi *net,
                               VirtIODevice *dev)
{
    struct vhost_mpi_command cmd = {
            .enable = 0,
        };

    if (!net->dev.started) {
        return;
    }

    /* VHOST_NET_SET_BACKEND used to implement "VHOST_MPI_STOP" */
    for (cmd.index = 0; cmd.index < net->dev.nvqs; cmd.index++) {
        int r = ioctl(net->dev.control, VHOST_MPI_STARTSTOP, &cmd);
        assert(r >= 0);
    }

    vhost_dev_stop(&net->dev, dev);
    vhost_dev_disable_notifiers(&net->dev, dev);
}

int vhost_mpi_start(VirtIODevice *dev, int total_queues)
{
    BusState *qbus = BUS(qdev_get_parent_bus(DEVICE(dev)));
    VirtioBusState *vbus = VIRTIO_BUS(qbus);
    VirtioBusClass *k = VIRTIO_BUS_GET_CLASS(vbus);
    VHostMpiState *net = VIRTIO_MPI(dev)->vhost_mpi;
    int r, i = 0;

    printf("vhost_mpi_start\n");

    if (!k->set_guest_notifiers) {
        error_report("binding does not support guest notifiers");
        r = -ENOSYS;
        goto err;
    }

    for (i = 0; i < total_queues; i++) {
        r = vhost_mpi_start_one(net, dev, i * 2);

        if (r < 0) {
            goto err;
        }
    }

    r = k->set_guest_notifiers(qbus->parent, total_queues * 2, true);
    if (r < 0) {
        error_report("Error binding guest notifier: %d", -r);
        goto err;
    }

    return 0;

err:
    while (--i >= 0) {
        vhost_mpi_stop_one(NULL, dev);
    }
    return r;
}

void vhost_mpi_stop(VirtIODevice *dev, int total_queues)
{
    BusState *qbus = BUS(qdev_get_parent_bus(DEVICE(dev)));
    VirtioBusState *vbus = VIRTIO_BUS(qbus);
    VirtioBusClass *k = VIRTIO_BUS_GET_CLASS(vbus);
    VHostMpiState *net = VIRTIO_MPI(dev)->vhost_mpi;
    int i, r;

    printf("vhost_mpi_stop\n");

    r = k->set_guest_notifiers(qbus->parent, total_queues * 2, false);
    if (r < 0) {
        fprintf(stderr, "vhost guest notifier cleanup failed: %d\n", r);
        fflush(stderr);
    }
    assert(r >= 0);

    for (i = 0; i < total_queues; i++) {
        vhost_mpi_stop_one(net, dev);
    }
}

void vhost_mpi_cleanup(struct vhost_mpi *net)
{
    vhost_dev_cleanup(&net->dev);
    g_free(net);
}

bool vhost_mpi_virtqueue_pending(VHostMpiState *net, int idx)
{
    return vhost_virtqueue_pending(&net->dev, idx);
}

void vhost_mpi_virtqueue_mask(VHostMpiState *net, VirtIODevice *dev,
                              int idx, bool mask)
{
    vhost_virtqueue_mask(&net->dev, dev, idx, mask);
}
// TODO #endif  /* CONFIG_VHOST_MPI */
