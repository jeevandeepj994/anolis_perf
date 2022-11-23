/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ALICC_ISR_H

#include "alicc_dev.h"

int alicc_enable_msix(struct alicc_dev *ydev);
void alicc_disable_msix(struct alicc_dev *ydev);
int alicc_alloc_irqs(struct alicc_dev *ydev);
void alicc_free_irqs(struct alicc_dev *ydev);
int alicc_init_global_err(struct alicc_dev *ydev);
void alicc_deinit_global_err(struct alicc_dev *ydev);
#endif
