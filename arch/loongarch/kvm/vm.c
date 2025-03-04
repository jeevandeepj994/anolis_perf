// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020-2023 Loongson Technology Corporation Limited
 */

#include <linux/kvm_host.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_extioi.h>
#include <asm/kvm_pch_pic.h>

const struct _kvm_stats_desc kvm_vm_stats_desc[] = {
	KVM_GENERIC_VM_STATS(),
	STATS_DESC_ICOUNTER(VM, pages),
	STATS_DESC_ICOUNTER(VM, hugepages),
};

const struct kvm_stats_header kvm_vm_stats_header = {
	.name_size = KVM_STATS_NAME_SIZE,
	.num_desc = ARRAY_SIZE(kvm_vm_stats_desc),
	.id_offset =  sizeof(struct kvm_stats_header),
	.desc_offset = sizeof(struct kvm_stats_header) + KVM_STATS_NAME_SIZE,
	.data_offset = sizeof(struct kvm_stats_header) + KVM_STATS_NAME_SIZE +
					sizeof(kvm_vm_stats_desc),
};

int kvm_arch_init_vm(struct kvm *kvm, unsigned long type)
{
	int i;

	/* Allocate page table to map GPA -> RPA */
	kvm->arch.pgd = kvm_pgd_alloc();
	if (!kvm->arch.pgd)
		return -ENOMEM;

	kvm->arch.phyid_map = kvzalloc(sizeof(struct kvm_phyid_map),
				GFP_KERNEL_ACCOUNT);
	if (!kvm->arch.phyid_map) {
		free_page((unsigned long)kvm->arch.pgd);
		kvm->arch.pgd = NULL;
		return -ENOMEM;
	}

	kvm_init_vmcs(kvm);
	kvm->arch.gpa_size = BIT(cpu_vabits - 1);
	kvm->arch.root_level = CONFIG_PGTABLE_LEVELS - 1;
	kvm->arch.invalid_ptes[0] = 0;
	kvm->arch.invalid_ptes[1] = (unsigned long)invalid_pte_table;
#if CONFIG_PGTABLE_LEVELS > 2
	kvm->arch.invalid_ptes[2] = (unsigned long)invalid_pmd_table;
#endif
#if CONFIG_PGTABLE_LEVELS > 3
	kvm->arch.invalid_ptes[3] = (unsigned long)invalid_pud_table;
#endif
	for (i = 0; i <= kvm->arch.root_level; i++)
		kvm->arch.pte_shifts[i] = PAGE_SHIFT + i * (PAGE_SHIFT - 3);

	spin_lock_init(&kvm->arch.phyid_map_lock);
	return 0;
}

void kvm_arch_destroy_vm(struct kvm *kvm)
{
	kvm_destroy_vcpus(kvm);
	free_page((unsigned long)kvm->arch.pgd);
	kvfree(kvm->arch.phyid_map);
	kvm->arch.pgd = NULL;
	kvm->arch.phyid_map = NULL;
}

int kvm_vm_ioctl_check_extension(struct kvm *kvm, long ext)
{
	int r;

	switch (ext) {
	case KVM_CAP_IRQCHIP:
	case KVM_CAP_ONE_REG:
	case KVM_CAP_ENABLE_CAP:
	case KVM_CAP_READONLY_MEM:
	case KVM_CAP_SYNC_MMU:
	case KVM_CAP_IMMEDIATE_EXIT:
	case KVM_CAP_IOEVENTFD:
	case KVM_CAP_MP_STATE:
	case KVM_CAP_SET_GUEST_DEBUG:
	case KVM_CAP_VM_ATTRIBUTES:
		r = 1;
		break;
	case KVM_CAP_NR_VCPUS:
		r = num_online_cpus();
		break;
	case KVM_CAP_MAX_VCPUS:
		r = KVM_MAX_VCPUS;
		break;
	case KVM_CAP_MAX_VCPU_ID:
		r = KVM_MAX_VCPU_IDS;
		break;
	case KVM_CAP_NR_MEMSLOTS:
		r = KVM_USER_MEM_SLOTS;
		break;
	default:
		r = 0;
		break;
	}

	return r;
}

static int kvm_vm_feature_has_attr(struct kvm *kvm, struct kvm_device_attr *attr)
{
	switch (attr->attr) {
	case KVM_LOONGARCH_VM_FEAT_PMU:
		if (cpu_has_pmp)
			return 0;
		return -ENXIO;

	default:
		return -ENXIO;
	}
}

static int kvm_vm_has_attr(struct kvm *kvm, struct kvm_device_attr *attr)
{
	switch (attr->group) {
	case KVM_LOONGARCH_VM_FEAT_CTRL:
		return kvm_vm_feature_has_attr(kvm, attr);
	case KVM_LOONGARCH_VM_HAVE_IRQCHIP:
		return 0;
	default:
		return -ENXIO;
	}
}

int kvm_arch_vm_ioctl(struct file *filp, unsigned int ioctl, unsigned long arg)
{
	int r;
	struct kvm *kvm = filp->private_data;
	void __user *argp = (void __user *)arg;
	struct kvm_device_attr attr;

	switch (ioctl) {
	case KVM_CREATE_IRQCHIP: {
		r = 1;
		break;
	}
	case KVM_HAS_DEVICE_ATTR: {
		if (copy_from_user(&attr, argp, sizeof(attr)))
			return -EFAULT;

		return kvm_vm_has_attr(kvm, &attr);
	}
	default:
		return -EINVAL;
	}

	return r;
}

int kvm_vm_ioctl_irq_line(struct kvm *kvm, struct kvm_irq_level *data,
			  bool line_status)
{
	bool level;
	struct loongarch_pch_pic *s;
	int type, vcpu, irq, vcpus, val, ret = 0;

	level = data->level;
	val = data->irq;
	s = kvm->arch.pch_pic;
	vcpus = atomic_read(&kvm->online_vcpus);

	type = (val >> KVM_LOONGARCH_IRQ_TYPE_SHIFT) & KVM_LOONGARCH_IRQ_TYPE_MASK;
	vcpu = (val >> KVM_LOONGARCH_IRQ_VCPU_SHIFT) & KVM_LOONGARCH_IRQ_VCPU_MASK;
	irq = (val >> KVM_LOONGARCH_IRQ_NUM_SHIFT) & KVM_LOONGARCH_IRQ_NUM_MASK;

	switch (type) {
	case KVM_LOONGARCH_IRQ_TYPE_IOAPIC:
		if (irq < KVM_IRQCHIP_NUM_PINS)
			pch_pic_set_irq(s, irq, level);
		else if (irq < 256)
			pch_msi_set_irq(kvm, irq, level);
		else
			ret = -EINVAL;
		break;
	default:
		ret = -EINVAL;
	}

	return ret;
}

bool kvm_arch_irqchip_in_kernel(struct kvm *kvm)
{
	return (bool)((!!kvm->arch.extioi) && (!!kvm->arch.pch_pic));
}
