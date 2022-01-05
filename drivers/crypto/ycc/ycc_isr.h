/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __YCC_ISR_H

#include "ycc_dev.h"

int ycc_enable_msix(struct ycc_dev *ydev);
void ycc_disable_msix(struct ycc_dev *ydev);
int ycc_alloc_irqs(struct ycc_dev *ydev);
void ycc_free_irqs(struct ycc_dev *ydev);
int ycc_init_global_err(struct ycc_dev *ydev);
void ycc_deinit_global_err(struct ycc_dev *ydev);
#endif
