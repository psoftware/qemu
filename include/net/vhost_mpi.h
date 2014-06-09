#ifndef VHOST_MPI_H
#define VHOST_MPI_H

//#define VERBOSE
#ifdef VERBOSE
#define IFV(x) x
#else
#define IFV(x) do {} while (0)
#endif

struct vhost_mpi;
typedef struct vhost_mpi VHostMpiState;

VHostMpiState *vhost_mpi_init(int devfd, bool force);

bool vhost_mpi_query(VHostMpiState *mpi, VirtIODevice *dev);
int vhost_mpi_start(VirtIODevice *dev, int total_queues);
void vhost_mpi_stop(VirtIODevice *dev, int total_queues);

void vhost_mpi_cleanup(VHostMpiState *mpi);

unsigned vhost_mpi_get_features(VHostMpiState *mpi, unsigned features);
void vhost_mpi_ack_features(VHostMpiState *mpi, unsigned features);

bool vhost_mpi_virtqueue_pending(VHostMpiState *mpi, int n);
void vhost_mpi_virtqueue_mask(VHostMpiState *mpi, VirtIODevice *dev,
                              int idx, bool mask);
#endif
