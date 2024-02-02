// SPDX-License-Identifier: GPL-2.0-only
/*
 *
 * Userspace interface for CSV guest driver
 *
 * Copyright (C) Hygon Info Technologies Ltd.
 */
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>
#include <linux/cc_platform.h>

#include <asm/cacheflush.h>

#include <uapi/linux/kvm_para.h>

#include "csv-guest.h"

static long csv_get_report(void __user *argp)
{
	u8	*csv_report;
	long	ret;
	struct	csv_report_req req;

	if (copy_from_user(&req, argp, sizeof(struct csv_report_req)))
		return -EFAULT;

	if (req.len < CSV_REPORT_INPUT_DATA_LEN)
		return -EINVAL;

	csv_report = kzalloc(req.len, GFP_KERNEL);
	if (!csv_report) {
		ret = -ENOMEM;
		goto out;
	}

	/* Save user input data */
	if (copy_from_user(csv_report, req.report_data, CSV_REPORT_INPUT_DATA_LEN)) {
		ret = -EFAULT;
		goto out;
	}

	/* Generate CSV_REPORT using "KVM_HC_VM_ATTESTATION" VMMCALL */
	ret = kvm_hypercall2(KVM_HC_VM_ATTESTATION, __pa(csv_report), req.len);
	if (ret)
		goto out;

	if (copy_to_user(req.report_data, csv_report, req.len))
		ret = -EFAULT;

out:
	kfree(csv_report);
	return ret;
}

static long csv_guest_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case CSV_CMD_GET_REPORT:
		return csv_get_report((void __user *)arg);
	default:
		return -ENOTTY;
	}
}

static void mem_test_init(void)
{
	char head_str[] = "test mem encrypt";
	u64 *va_addr = __va(0x0);

	if (va_addr) {
		memset(va_addr, 0x66, PAGE_SIZE);
		memcpy(va_addr, head_str, sizeof(head_str));
		clflush_cache_range(va_addr, PAGE_SIZE);
	} else
		pr_err("Initialize 1 page for csv memory test failed!\n");
}

static const struct file_operations csv_guest_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = csv_guest_ioctl,
	.compat_ioctl = csv_guest_ioctl,
};

static struct miscdevice csv_guest_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "csv-guest",
	.fops = &csv_guest_fops,
	.mode = 0777,
};

static int __init csv_guest_init(void)
{
	// This module only working on CSV guest vm.
	if (!cc_platform_has(CC_ATTR_GUEST_MEM_ENCRYPT))
		return -ENODEV;

	// Initialize 1 page for csv memory test
	mem_test_init();

	return misc_register(&csv_guest_dev);
}

static void __exit csv_guest_exit(void)
{
	misc_deregister(&csv_guest_dev);
}

MODULE_LICENSE("GPL");
MODULE_VERSION("1.0.0");
MODULE_DESCRIPTION("HYGON CSV Guest Driver");
module_init(csv_guest_init);
module_exit(csv_guest_exit);
