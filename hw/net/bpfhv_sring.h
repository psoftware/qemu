#ifndef __BPFHV_SRING_H__
#define __BPFHV_SRING_H__

#include <stdint.h>

struct sring_tx_context {
    uint32_t tail;
    uint32_t head;
};

#endif  /* __BPFHV_SRING_H__ */
