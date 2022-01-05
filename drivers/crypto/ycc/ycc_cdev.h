// SPDX-License-Identifier: GPL-2.0
#ifndef __YCC_CDEV_H
#define __YCC_CDEV_H

#include <linux/cdev.h>
#include "ycc_dev.h"

#define YCC_CDEV_NAME		"ycc_dev_ctrl"

struct ycc_cdev {
	dev_t devno;
	struct class *class;
	struct cdev cdev;
};

int ycc_cdev_register(void);
void ycc_cdev_unregister(void);
#endif
