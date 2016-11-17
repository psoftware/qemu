#ifndef __VIRTIO_PRODCONS_H__
#define __VIRTIO_PRODCONS_H__

enum {
    VPC_WP = 1,
    VPC_WC,
    VPC_YP,
    VPC_YC,
    VPC_PSLEEP,
    VPC_CSLEEP,
    VPC_INCSP,
    VPC_INCSC,
    VPC_LAST
};

/* Layout of the virtio-prodcons config space */
struct virtio_pc_config {
    uint32_t    wp;
    uint32_t    wc;
    uint32_t    yp;
    uint32_t    yc;
    uint32_t    psleep;
    uint32_t    csleep;
    uint32_t    incsp;
    uint32_t    incsc;
};

struct virtpc_ioctl_data {
    unsigned int devid;
    unsigned int wp;       /* producer work in nanoseconds */
    unsigned int wc;       /* consumer work in nanoseconds */
    unsigned int yp;       /* producer sleep in nanoseconds */
    unsigned int yc;       /* consumer sleep in nanoseconds */
    unsigned int duration; /* in seconds */
    unsigned int psleep; /* 0 --> producer uses notifications
                          * 1 --> producer uses sleeping */
    unsigned int csleep; /* 0 --> consumer uses notifications
                          * 1 --> consumer uses sleeping */
    unsigned int incsp; /* artificially increase sp, in nanoseconds */
    unsigned int incsc; /* artificially increase sc, in nanoseconds */
};

#endif  /* __VIRTIO_PRODCONS_H__ */