#ifndef __VIRTIO_PRODCONS_H__
#define __VIRTIO_PRODCONS_H__

struct virtpc_ioctl_data {
    unsigned int devid;
    unsigned int wp;       /* producer work in ns */
    unsigned int wc;       /* consumer work in ns */
    unsigned int yp;       /* prodcuer sleep in ns */
    unsigned int yc;       /* consumer sleep in ns */
    unsigned int duration; /* in seconds */
    unsigned int sleeping; /* 0 --> producer uses notifications
                            * 1 --> producer uses sleeping */
};

#endif  /* __VIRTIO_PRODCONS_H__ */
