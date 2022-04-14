// SPDX-License-Identifier: GPL-2.0-only
/*
 * CSV driver for KVM
 *
 * HYGON CSV support
 *
 * Copyright (C) Hygon Info Technologies Ltd.
 */

#include <linux/kvm_host.h>
#include <linux/psp-sev.h>
#include <linux/psp-csv.h>
#include <linux/kvm_types.h>
#include <linux/vmalloc.h>
#include <asm/cacheflush.h>
#include <asm/e820/api.h>
#include "kvm_cache_regs.h"
#include "svm.h"
#include "csv.h"
#include "x86.h"

#undef  pr_fmt
#define pr_fmt(fmt) "CSV: " fmt

struct encrypt_data_block {
	struct {
		u64 npages:	12;
		u64 pfn:	52;
	} entry[512];
};

struct kvm_csv_info {
	struct kvm_sev_info *sev;

	bool csv_active;	/* CSV enabled guest */
};

struct kvm_svm_csv {
	struct kvm_svm kvm_svm;
	struct kvm_csv_info csv_info;
};

static struct kvm_x86_ops svm_x86_ops;

static inline struct kvm_svm_csv *to_kvm_svm_csv(struct kvm *kvm)
{
	return (struct kvm_svm_csv *)container_of(kvm, struct kvm_svm, kvm);
}

static bool csv_guest(struct kvm *kvm)
{
	struct kvm_csv_info *csv = &to_kvm_svm_csv(kvm)->csv_info;

	return sev_es_guest(kvm) && csv->csv_active;
}

static int __csv_issue_cmd(int fd, int id, void *data, int *error)
{
	struct fd f;
	int ret;

	f = fdget(fd);
	if (!f.file)
		return -EBADF;

	ret = sev_issue_cmd_external_user(f.file, id, data, error);

	fdput(f);
	return ret;
}

static int csv_issue_cmd(struct kvm *kvm, int id, void *data, int *error)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;

	return __csv_issue_cmd(sev->fd, id, data, error);
}

static int csv_guest_init(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct kvm_csv_info *csv = &to_kvm_svm_csv(kvm)->csv_info;

	if (unlikely(csv->csv_active))
		return -EINVAL;

	if (unlikely(!sev->es_active))
		return -EINVAL;

	csv->csv_active = true;
	csv->sev = sev;

	return 0;
}

static int csv_launch_encrypt_data(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_csv_info *csv = &to_kvm_svm_csv(kvm)->csv_info;
	struct kvm_csv_launch_encrypt_data params;
	struct csv_data_launch_encrypt_data *encrypt_data = NULL;
	struct encrypt_data_block *blocks = NULL;
	u8 *data = NULL;
	u32 offset;
	u32 num_entries, num_entries_in_block;
	u32 num_blocks, num_blocks_max;
	u32 i, n;
	unsigned long pfn;
	int ret = 0;
	int error = 0;

	if (!csv_guest(kvm))
		return -ENOTTY;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data,
			   sizeof(params))) {
		ret = -EFAULT;
		goto exit;
	}

	if ((params.len & ~PAGE_MASK) || !params.len || !params.uaddr) {
		ret = -EINVAL;
		goto exit;
	}

	num_entries = params.len / PAGE_SIZE;
	num_entries_in_block = ARRAY_SIZE(blocks->entry);
	num_blocks = (num_entries + num_entries_in_block - 1) / num_entries_in_block;
	num_blocks_max = ARRAY_SIZE(encrypt_data->data_blocks);

	if (num_blocks >= num_blocks_max) {
		ret = -EINVAL;
		goto exit;
	}

	data = vzalloc(params.len);
	if (!data) {
		ret = -ENOMEM;
		goto exit;
	}
	if (copy_from_user(data, (void __user *)params.uaddr, params.len)) {
		ret = -EFAULT;
		goto data_free;
	}

	blocks = vzalloc(num_blocks * sizeof(*blocks));
	if (!blocks) {
		ret = -ENOMEM;
		goto data_free;
	}

	for (offset = 0, i = 0, n = 0; offset < params.len; offset += PAGE_SIZE) {
		pfn = vmalloc_to_pfn(offset + data);
		if (offset && ((blocks[n].entry[i].pfn + 1) == pfn))
			blocks[n].entry[i].npages += 1;
		else {
			if (offset) {
				i = (i + 1) % num_entries_in_block;
				n = (i == 0) ? (n + 1) : n;
			}
			blocks[n].entry[i].pfn = pfn;
			blocks[n].entry[i].npages = 1;
		}
	}

	encrypt_data = kzalloc(sizeof(*encrypt_data), GFP_KERNEL);
	if (!encrypt_data) {
		ret = -ENOMEM;
		goto block_free;
	}

	encrypt_data->handle = csv->sev->handle;
	encrypt_data->length = params.len;
	encrypt_data->gpa = params.gpa;
	for (i = 0; i <= n; i++) {
		encrypt_data->data_blocks[i] =
			vmalloc_to_pfn((void *)blocks + i * sizeof(*blocks)) << PAGE_SHIFT;
	}

	clflush_cache_range(data, params.len);
	ret = csv_issue_cmd(kvm, CSV_CMD_LAUNCH_ENCRYPT_DATA,
			    encrypt_data, &error);

	kfree(encrypt_data);
block_free:
	vfree(blocks);
data_free:
	vfree(data);
exit:
	return ret;
}

static int csv_mem_enc_op(struct kvm *kvm, void __user *argp)
{
	struct kvm_sev_cmd sev_cmd;
	int r = -EINVAL;

	if (!argp)
		return 0;

	if (copy_from_user(&sev_cmd, argp, sizeof(struct kvm_sev_cmd)))
		return -EFAULT;

	mutex_lock(&kvm->lock);

	switch (sev_cmd.id) {
	case KVM_CSV_INIT:
		r = csv_guest_init(kvm, &sev_cmd);
		break;
	case KVM_CSV_LAUNCH_ENCRYPT_DATA:
		r = csv_launch_encrypt_data(kvm, &sev_cmd);
		break;
	default:
		mutex_unlock(&kvm->lock);
		if (likely(svm_x86_ops.mem_enc_op))
			r = svm_x86_ops.mem_enc_op(kvm, argp);
		goto out;
	}

	mutex_unlock(&kvm->lock);

	if (copy_to_user(argp, &sev_cmd, sizeof(struct kvm_sev_cmd)))
		r = -EFAULT;

out:
	return r;
}

#define CSV_BIT		30

void __init csv_init(struct kvm_x86_ops *ops)
{
	unsigned int eax, ebx, ecx, edx;

	if (boot_cpu_data.x86_vendor != X86_VENDOR_HYGON)
		return;

	/* Retrieve CSV CPUID information */
	cpuid(0x8000001f, &eax, &ebx, &ecx, &edx);
	if (eax & CSV_BIT) {
		memcpy(&svm_x86_ops, ops, sizeof(struct kvm_x86_ops));

		ops->mem_enc_op = csv_mem_enc_op;
		ops->vm_size = sizeof(struct kvm_svm_csv);
	}
}
