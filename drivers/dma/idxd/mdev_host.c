// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) Intel Corporation. All rights rsvd. */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/iommu.h>
#include <linux/mdev.h>
#include <uapi/linux/idxd.h>
#include "idxd.h"

int idxd_mdev_host_init(struct idxd_device *idxd, const struct mdev_parent_ops *ops)
{
	struct device *dev = &idxd->pdev->dev;
	int rc;

	if (!test_bit(IDXD_FLAG_IMS_SUPPORTED, &idxd->flags))
		return -EOPNOTSUPP;

	rc = iommu_dev_enable_feature(dev, IOMMU_DEV_FEAT_AUX);
	if (rc < 0) {
		dev_warn(dev, "Failed to enable aux-domain: %d\n", rc);
		return rc;
	}

	rc = mdev_register_device(dev, ops);
	if (rc < 0) {
		iommu_dev_disable_feature(dev, IOMMU_DEV_FEAT_AUX);
		return rc;
	}

	idxd->mdev_host_init = true;
	return 0;
}
EXPORT_SYMBOL_GPL(idxd_mdev_host_init);

void idxd_mdev_host_release(struct kref *kref)
{
	struct idxd_device *idxd = container_of(kref, struct idxd_device, mdev_kref);
	struct device *dev = &idxd->pdev->dev;

	mdev_unregister_device(dev);
	iommu_dev_disable_feature(dev, IOMMU_DEV_FEAT_AUX);
}
EXPORT_SYMBOL_GPL(idxd_mdev_host_release);
