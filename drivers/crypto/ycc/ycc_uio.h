// SPDX-License-Identifier: GPL-2.0
#ifndef __YCC_UIO_H
#define __YCC_UIO_H

#ifndef CONFIG_UIO
static inline int ycc_uio_register(struct ycc_ring *ring) { return 0; };
static inline void ycc_uio_unregister(struct ycc_ring *ring) { };
#else
int ycc_uio_register(struct ycc_ring *ring);
void ycc_uio_unregister(struct ycc_ring *ring);
#endif

#endif
