// SPDX-License-Identifier: GPL-2.0
#include <linux/cdev.h>
#include <linux/sched.h>
#include <linux/kobject.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include "ycc_cdev.h"

static struct ycc_cdev ycdev;

static int ycc_cdev_open(struct inode *inode, struct file *filp)
{
	return 0;
}

static int ycc_cdev_release(struct inode *inode, struct file *filp)
{
	return 0;
}

static long ycc_cdev_ioctl(struct file *filp, unsigned int cmd,
			  unsigned long arg)
{
	return 0;
}

static const struct file_operations ycc_fops = {
	.open = ycc_cdev_open,
	.release = ycc_cdev_release,
	.unlocked_ioctl = ycc_cdev_ioctl,
};

int ycc_cdev_register(void)
{
	struct device *device;
	int ret;

	ret = alloc_chrdev_region(&ycdev.devno, 0, 1, YCC_CDEV_NAME);
	if (ret) {
		pr_err("Failed to alloc ycc cdev region\n");
		return ret;
	}

	ycdev.class = class_create(THIS_MODULE, YCC_CDEV_NAME);
	if (IS_ERR(ycdev.class)) {
		pr_err("Failed to create ycc cdev class\n");
		ret = PTR_ERR(ycdev.class);
		goto unregister_region;
	}

	cdev_init(&ycdev.cdev, &ycc_fops);
	ret = cdev_add(&ycdev.cdev, ycdev.devno, 1);
	if (ret) {
		pr_err("Failed to add ycc cdev\n");
		goto destroy_class;
	}

	device = device_create(ycdev.class, NULL, ycdev.devno,
			       NULL, YCC_CDEV_NAME);
	if (IS_ERR(device)) {
		pr_err("Failed to create ycc cdev device\n");
		ret = PTR_ERR(device);
		goto del_cdev;
	}

	return 0;
del_cdev:
	cdev_del(&ycdev.cdev);
destroy_class:
	class_destroy(ycdev.class);
unregister_region:
	unregister_chrdev_region(ycdev.devno, 1);
	return ret;
}

void ycc_cdev_unregister(void)
{
	device_destroy(ycdev.class, ycdev.devno);
	cdev_del(&ycdev.cdev);
	class_destroy(ycdev.class);
	unregister_chrdev_region(ycdev.devno, 1);
}
