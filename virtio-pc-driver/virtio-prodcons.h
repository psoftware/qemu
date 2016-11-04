#ifndef __VIRTIO_PRODCONS_H__
#define __VIRTIO_PRODCONS_H__

struct virtpc_ioctl_data {
    unsigned int devid;
    unsigned int wp;
    unsigned int wc;
    unsigned int duration;
};

#endif  /* __VIRTIO_PRODCONS_H__ */
