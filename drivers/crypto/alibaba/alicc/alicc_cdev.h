// SPDX-License-Identifier: GPL-2.0
#ifndef __ALICC_CDEV_H
#define __ALICC_CDEV_H

#include <linux/cdev.h>
#include "alicc_dev.h"

#define ALICC_CDEV_NAME		"alicc_dev_ctrl"

struct alicc_cdev {
	dev_t devno;
	struct class *class;
	struct cdev cdev;
};

int alicc_cdev_register(void);
void alicc_cdev_unregister(void);
#endif
