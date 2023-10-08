// SPDX-License-Identifier: GPL-2.0-only
/*
 *  ARM Neoverse N2 core cpuectlr support
 */

#include <asm/cpu.h>
#include <asm/sysreg.h>
#include <asm/cputype.h>
#include <asm/virt.h>
#include <linux/cpu.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/percpu.h>
#include <linux/smp.h>
#include <linux/dmi.h>
#include <linux/arm-smccc.h>

#define SYS_IMP_CPUECTLR_EL1		sys_reg(3, 0, 15, 1, 4)
#define SYS_ACTLR_EL2			sys_reg(3, 4, 1, 0, 1)

#define NEOVERSE_N2_ACTLR_EL2_ECTLREN_MASK	BIT(1)
#define MIDR_EL1_NEOVERSE_N2_MASK	(GENMASK(31, 24) | GENMASK(19, 16) | \
						GENMASK(15, 4))
#define MIDR_EL1_NEOVERSE_N2_ID		0x410FD490

#define ID_AA64MMFR1_VHE_MASK		GENMASK_ULL(11, 8)
#define ID_AA64MMFR1_VHE_VALID		0x1

#define CPUECTLR_WRITE_FAULT		GENMASK_ULL(63, 0)

#define ARM_OEM_SMC_FN			0xC300FFEC
#define ACTLR_EL3_CTRL_QUERY		0x51
#define ACTLR_EL3_CTRL_QUERY_ENABLE	1
#define ACTLR_EL3_CTRL_QUERY_DISABLE	0
#define ACTLR_EL3_CTRL_DISABLE		0x52
#define ACTLR_EL3_CTRL_ENABLE		0x53
#define ACTLR_EL3_CTRL_ENABLE_OK	0

#define CPUECTLR_SAFE_NONE		0
#define CPUECTLR_SAFE_RO		1
#define CPUECTLR_SAFE_RW		2

#define BIOS_VENDOR_FILTER		"Alibaba"
#define BIOS_VERSION_MATCH		"1.2.M1.AL."

struct cpuectlr_info {
	int	cpu_id;
	struct	kobject kobj;
	u64	reg_cpuectlr_el1;
	const struct attribute_group *cpuectlr_attr_group_ptr;
};

DEFINE_PER_CPU(struct cpuectlr_info, cpuectlr_data);

static struct kobj_type cpuectlr_kobj_type = {
	.sysfs_ops = &kobj_sysfs_ops,
};

static void read_cpuectlr(void *dummy)
{
	int cpu = smp_processor_id();
	struct cpuectlr_info *info = &per_cpu(cpuectlr_data, cpu);

	info->reg_cpuectlr_el1 = read_sysreg_s(SYS_IMP_CPUECTLR_EL1);
}

static void write_cpuectlr(void *dummy)
{
	int cpu = smp_processor_id();
	u64 *orig_cpuectlr = (u64 *)dummy;
	u64 new_cpuectlr;
	struct cpuectlr_info *info = &per_cpu(cpuectlr_data, cpu);

	write_sysreg_s(info->reg_cpuectlr_el1, SYS_IMP_CPUECTLR_EL1);

	/* read again to verify writing is valid */
	new_cpuectlr = read_sysreg_s(SYS_IMP_CPUECTLR_EL1);

	if (new_cpuectlr != info->reg_cpuectlr_el1) {
		pr_err("CPU #%d write cpuectlr failed: expect %llx, but %llx\n",
			cpu, info->reg_cpuectlr_el1, new_cpuectlr);

		/* recall cpuectlr */
		if (new_cpuectlr != *orig_cpuectlr)
			write_sysreg_s(*orig_cpuectlr, SYS_IMP_CPUECTLR_EL1);

		info->reg_cpuectlr_el1 = *orig_cpuectlr;

		/* use CPUECTLR_WRITE_FAULT as err code to return */
		*orig_cpuectlr = CPUECTLR_WRITE_FAULT;
		return;
	}

	pr_debug("CPU #%d origin cpuectlr: %llx, update to %llx\n", cpu,
		*orig_cpuectlr, new_cpuectlr);
}

#define kobj_to_cpuectlr_info(kobj)	\
	container_of(kobj, struct cpuectlr_info, kobj)

#define CPUECTLR_ATTR(_name, H, L)					\
	static ssize_t _name##_show(struct kobject *kobj,		\
		struct kobj_attribute *attr, char *buf)			\
	{								\
		struct cpuectlr_info *info = kobj_to_cpuectlr_info(kobj);\
		u64 cpuectlr_mask_##_name = GENMASK_ULL((H), (L));	\
		int cpuectlr_shift_##_name = L;				\
									\
		smp_call_function_single(info->cpu_id,			\
			read_cpuectlr, NULL, 1);			\
									\
		return sprintf(buf, "%lld\n",				\
			(info->reg_cpuectlr_el1 & cpuectlr_mask_##_name)\
				>> cpuectlr_shift_##_name);		\
	}								\
									\
	static ssize_t _name##_store(struct kobject *kobj,		\
		struct kobj_attribute *attr, const char *buf, size_t len)\
	{								\
		struct cpuectlr_info *info = kobj_to_cpuectlr_info(kobj);\
		u64 cpuectlr_mask_##_name = GENMASK_ULL((H), (L));	\
		int cpuectlr_shift_##_name = L;				\
		u64 cpuectlr_max_##_name = GENMASK((H) - (L), 0);	\
									\
		u64 val;						\
		u64 orig_cpuectlr;					\
		int ret;						\
		ret = kstrtou64(buf, 10, &val);				\
		if (ret)						\
			return -EINVAL;					\
									\
		if (val > cpuectlr_max_##_name)				\
			return -EINVAL;					\
									\
		smp_call_function_single(info->cpu_id,			\
			read_cpuectlr, NULL, 1);			\
		orig_cpuectlr = info->reg_cpuectlr_el1;			\
		info->reg_cpuectlr_el1 &= ~cpuectlr_mask_##_name;	\
		info->reg_cpuectlr_el1 |= (val << cpuectlr_shift_##_name);\
		smp_call_function_single(info->cpu_id,			\
			write_cpuectlr, &orig_cpuectlr, 1);		\
									\
		if (orig_cpuectlr == CPUECTLR_WRITE_FAULT)		\
			return -EACCES;					\
									\
		return len;						\
	}								\
	static struct kobj_attribute					\
		cpuectlr_attr_rw_##_name = __ATTR_RW(_name);		\
	static struct kobj_attribute					\
		cpuectlr_attr_ro_##_name = __ATTR_RO(_name)

CPUECTLR_ATTR(cmc_min_ways, 63, 61);
CPUECTLR_ATTR(prefetch_sts_disable, 9, 9);
CPUECTLR_ATTR(prefetch_sti_disable, 8, 8);

static struct attribute *cpuectlr_rw_attrs[] = {
	&cpuectlr_attr_rw_cmc_min_ways.attr,
	&cpuectlr_attr_rw_prefetch_sts_disable.attr,
	&cpuectlr_attr_rw_prefetch_sti_disable.attr,
	NULL
};

static struct attribute *cpuectlr_ro_attrs[] = {
	&cpuectlr_attr_ro_cmc_min_ways.attr,
	&cpuectlr_attr_ro_prefetch_sts_disable.attr,
	&cpuectlr_attr_ro_prefetch_sti_disable.attr,
	NULL
};

static const struct attribute_group cpuectlr_rw_attr_group = {
	.attrs = cpuectlr_rw_attrs,
};

static const struct attribute_group cpuectlr_ro_attr_group = {
	.attrs = cpuectlr_ro_attrs,
};

static int cpuectlr_rw_safe_check(void)
{
	bool is_guest;
	u64 actlr_el2;
	const char *bios_vendor;
	const char *bios_version;
	struct arm_smccc_res res;

	is_guest = !is_hyp_mode_available();

	if (is_guest) {
		/* check privilege by hvc */
		arm_smccc_1_1_hvc(ARM_SMCCC_CPUECTLR_PRIVILEGE, &res);

		if (res.a0 != SMCCC_RET_SUCCESS)
			return CPUECTLR_SAFE_NONE;

		return CPUECTLR_SAFE_RW;
	}

	/* Now, we check if host os rw cpuectlr safely, currentEL is EL2 */

	/* check and enable neoverse n2 ACTLR_EL2.ECTLREN */
	actlr_el2 = read_sysreg_s(SYS_ACTLR_EL2);
	if (!(actlr_el2 & NEOVERSE_N2_ACTLR_EL2_ECTLREN_MASK))
		write_sysreg_s((actlr_el2 | NEOVERSE_N2_ACTLR_EL2_ECTLREN_MASK),
			SYS_ACTLR_EL2);

	/* check actlr_el3_ectlren by smc.
	 * This capability requires the BIOS vendor to be Alibaba
	 * and the version is 1.2.M1.AL.*.*.*
	 */
	bios_vendor = dmi_get_system_info(DMI_BIOS_VENDOR);
	bios_version = dmi_get_system_info(DMI_BIOS_VERSION);

	if (strcmp(bios_vendor, BIOS_VENDOR_FILTER))
		return CPUECTLR_SAFE_RO;

	/* check bios version prefix */
	if (strncmp(bios_version, BIOS_VERSION_MATCH,
			strlen(BIOS_VERSION_MATCH)))
		return CPUECTLR_SAFE_RO;

	arm_smccc_smc(ARM_OEM_SMC_FN, ACTLR_EL3_CTRL_QUERY,
		0, 0, 0, 0, 0, 0, &res);
	if (res.a0 == ACTLR_EL3_CTRL_QUERY_ENABLE)
		return CPUECTLR_SAFE_RW;

	arm_smccc_smc(ARM_OEM_SMC_FN, ACTLR_EL3_CTRL_ENABLE,
		0, 0, 0, 0, 0, 0, &res);
	if (res.a0 == ACTLR_EL3_CTRL_ENABLE_OK)
		return CPUECTLR_SAFE_RW;

	return CPUECTLR_SAFE_RO;
}

static int cpuectlr_online(unsigned int cpu)
{
	int rc;
	struct device *dev;
	struct cpuectlr_info *info = &per_cpu(cpuectlr_data, cpu);
	int safe_check;

	info->cpu_id = cpu;

	safe_check = cpuectlr_rw_safe_check();

	dev = get_cpu_device(cpu);
	if (!dev)
		return -ENODEV;

	rc = kobject_add(&info->kobj, &dev->kobj, "cpu_extended_ctrl");
	if (rc)
		return rc;

	if (safe_check == CPUECTLR_SAFE_RW)
		info->cpuectlr_attr_group_ptr = &cpuectlr_rw_attr_group;
	else if (safe_check == CPUECTLR_SAFE_RO)
		info->cpuectlr_attr_group_ptr = &cpuectlr_ro_attr_group;
	else
		info->cpuectlr_attr_group_ptr = NULL;

	if (info->cpuectlr_attr_group_ptr) {
		rc = sysfs_create_group(&info->kobj,
			info->cpuectlr_attr_group_ptr);
		if (rc) {
			kobject_del(&info->kobj);
			info->cpuectlr_attr_group_ptr = NULL;
		}
	}

	return rc;
}

static int cpuectlr_offline(unsigned int cpu)
{
	struct device *dev;
	struct cpuectlr_info *info = &per_cpu(cpuectlr_data, cpu);

	dev = get_cpu_device(cpu);
	if (!dev)
		return -ENODEV;

	if (!info->kobj.parent)
		return 0;

	if (info->cpuectlr_attr_group_ptr) {
		sysfs_remove_group(&info->kobj, info->cpuectlr_attr_group_ptr);
		info->cpuectlr_attr_group_ptr = NULL;
	}

	kobject_del(&info->kobj);

	return 0;
}

static bool cpuectlr_can_export(void)
{
	u32 midr_el1 = read_cpuid_id();

	/* We need to open CONFIG_ARM64_VHE and support cpu VHE features to
	 * know the kernel is currently in guest or host, otherwise these
	 * interfaces will not be exposed
	 */
#ifdef CONFIG_ARM64_VHE
	u64 id_aa64mmfr1 = read_sysreg_s(SYS_ID_AA64MMFR1_EL1);
	bool support_vhe = ((id_aa64mmfr1 & ID_AA64MMFR1_VHE_MASK) >>
		ID_AA64MMFR1_VHE_SHIFT) == ID_AA64MMFR1_VHE_VALID;
	if (!support_vhe)
		return false;
#else
	return false;
#endif

	/* only support for arm64 neoverse n2 */
	return ((midr_el1 & MIDR_EL1_NEOVERSE_N2_MASK)
			== MIDR_EL1_NEOVERSE_N2_ID);
}

static int __init cpuectlr_init(void)
{
	int cpu, ret;
	struct cpuectlr_info *info;

	if (!cpuectlr_can_export())
		return -EACCES;

	for_each_possible_cpu(cpu) {
		info = &per_cpu(cpuectlr_data, cpu);
		kobject_init(&info->kobj, &cpuectlr_kobj_type);
	}

	ret = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN,
			"arm64/cpu_extended_ctrl:online",
			cpuectlr_online, cpuectlr_offline);

	if (ret < 0) {
		pr_err("cpu_extended_ctrl:failed to register hotplug callbacks.\n");
		return ret;
	}
	return 0;
}
device_initcall(cpuectlr_init);
