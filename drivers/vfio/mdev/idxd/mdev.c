// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2019,2020 Intel Corporation. All rights rsvd. */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/device.h>
#include <linux/sched/task.h>
#include <linux/io-64-nonatomic-lo-hi.h>
#include <linux/mm.h>
#include <linux/mmu_context.h>
#include <linux/vfio.h>
#include <linux/mdev.h>
#include <linux/msi.h>
#include <linux/intel-iommu.h>
#include <linux/intel-svm.h>
#include <linux/kvm_host.h>
#include <linux/eventfd.h>
#include <linux/circ_buf.h>
#include <linux/irqchip/irq-ims-msi.h>
#include <uapi/linux/idxd.h>
#include "registers.h"
#include "idxd.h"
#include "../../vfio/pci/vfio_pci_private.h"
#include "mdev.h"

int idxd_mdev_get_pasid(struct mdev_device *mdev, u32 *pasid)
{
	struct vfio_group *vfio_group;
	struct iommu_domain *iommu_domain;
	struct device *dev = mdev_dev(mdev);
	struct device *iommu_device = mdev_get_iommu_device(mdev);
	struct vdcm_idxd *vidxd = mdev_get_drvdata(mdev);
	int mdev_pasid;

	if (!vidxd->ivdev.vfio_group) {
		dev_warn(dev, "Missing vfio_group.\n");
		return -EINVAL;
	}

	vfio_group = vidxd->ivdev.vfio_group;

	iommu_domain = vfio_group_iommu_domain(vfio_group);
	if (IS_ERR_OR_NULL(iommu_domain))
		goto err;

	mdev_pasid = iommu_aux_get_pasid(iommu_domain, iommu_device);
	if (mdev_pasid < 0)
		goto err;

	*pasid = (u32)mdev_pasid;
	return 0;

 err:
	vfio_group_put_external_user(vfio_group);
	vidxd->ivdev.vfio_group = NULL;
	return -EFAULT;
}

MODULE_IMPORT_NS(IDXD);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Intel Corporation");
