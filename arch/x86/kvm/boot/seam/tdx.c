// SPDX-License-Identifier: GPL-2.0
#include <linux/earlycpio.h>
#include <linux/fs.h>
#include <linux/initrd.h>
#include <linux/percpu.h>
#include <linux/memblock.h>
#include <linux/idr.h>
#include <linux/sort.h>

#include <asm/cpu.h>
#include <asm/cmdline.h>
#include <asm/tdx.h>
#include <asm/virtext.h>
#include <asm/tlbflush.h>
#include <asm/e820/api.h>

#include "seamloader.h"

#undef pr_fmt
#define pr_fmt(fmt) "tdx: " fmt

/* Instruct tdx_ops.h to do boot-time friendly SEAMCALL exception handling. */
#define INTEL_TDX_BOOT_TIME_SEAMCALL 1

#include "vmx/tdx_arch.h"
#include "vmx/tdx_ops.h"
#include "vmx/tdx_errno.h"

#include "vmx/vmcs.h"

enum TDX_HOST_OPTION {
	TDX_HOST_OFF,
	TDX_HOST_ON,
};

static struct seamldr_info p_seamldr_info;

static enum TDX_HOST_OPTION tdx_host __initdata;

static char tdx_npseamldr_name[128] = "intel-seam/np-seamldr.acm";

/*
 * TDX module status during initialization
 */
enum tdx_module_status_t {
	/* P-SEAMDLR status is unknown */
	TDX_SEAMLDR_UNKNOWN,
	/* P-SEAMDLR is loaded */
	TDX_SEAMLDR_READY,
	/* TDX module is loaded, but not initialized */
	TDX_MODULE_LOADED,
	/* TDX module is fully initialized */
	TDX_MODULE_INITIALIZED,
	/* TDX module is shutdown due to error during initialization */
	TDX_MODULE_SHUTDOWN,
};

enum tdx_module_status_t tdx_module_status;
EXPORT_SYMBOL_GPL(tdx_module_status);

static int __init setup_tdx_npseamldr(char *str)
{
	strscpy(tdx_npseamldr_name, str, sizeof(tdx_npseamldr_name));
	return 0;
}
early_param("tdx_npseamldr", setup_tdx_npseamldr);

static int __init tdx_host_param(char *str)
{
	if (str && !strcmp(str, "on"))
		tdx_host = TDX_HOST_ON;

	return 0;
}
early_param("tdx_host", tdx_host_param);

/*
 * cpu_vmxon() - Enable VMX on the current CPU
 *
 * Set CR4.VMXE and enable VMX
 */
static inline int cpu_vmxon(u64 vmxon_pointer)
{
	u64 msr;

	cr4_set_bits(X86_CR4_VMXE);

	asm_volatile_goto("1: vmxon %[vmxon_pointer]\n\t"
			_ASM_EXTABLE(1b, %l[fault])
			: : [vmxon_pointer] "m"(vmxon_pointer)
			: : fault);
	return 0;

fault:
	WARN_ONCE(1, "VMXON faulted, MSR_IA32_FEAT_CTL (0x3a) = 0x%llx\n",
			rdmsrl_safe(MSR_IA32_FEAT_CTL, &msr) ? 0xdeadbeef : msr);
	cr4_clear_bits(X86_CR4_VMXE);

	return -EFAULT;
}

static inline int tdx_init_vmxon_vmcs(struct vmcs *vmcs)
{
	u64 msr;

	/*
	 * Can't enable TDX if VMX is unsupported or disabled by BIOS.
	 * cpu_has(X86_FEATURE_VMX) can't be relied on as the BSP calls this
	 * before the kernel has configured feat_ctl().
	 */
	if (!cpu_has_vmx())
		return -EOPNOTSUPP;

	if (rdmsrl_safe(MSR_IA32_FEAT_CTL, &msr) ||
	    !(msr & FEAT_CTL_LOCKED) ||
	    !(msr & FEAT_CTL_VMX_ENABLED_OUTSIDE_SMX))
		return -EOPNOTSUPP;

	if (rdmsrl_safe(MSR_IA32_VMX_BASIC, &msr))
		return -EOPNOTSUPP;

	memset(vmcs, 0, PAGE_SIZE);
	vmcs->hdr.revision_id = (u32)msr;

	return 0;
}

static inline int tdx_get_keyids(u32 *keyids_start, u32 *nr_keyids)
{
	u64 msr;

	if (rdmsrl_safe(MSR_IA32_MKTME_KEYID_PART, &msr))
		return -EOPNOTSUPP;

	/* KeyID 0 is reserved, i.e. KeyIDs are 1-based. */
	*keyids_start = (msr & 0xffffffff) + 1;
	*nr_keyids  = (msr >> 32) & 0xffffffff;

	return 0;
}

static bool __init tdx_all_cpus_available(void)
{
	/*
	 * CPUs detected in ACPI can be marked as disabled due to:
	 *   1) disabled in ACPI MADT table
	 *   2) disabled by 'disable_cpu_apicid' kernel parameter, which
	 *     disables CPU with particular APIC id.
	 *   3) limited by 'nr_cpus' kernel parameter.
	 */
	if (disabled_cpus) {
		pr_info("Disabled CPUs detected\n");
		goto err;
	}

	if (num_possible_cpus() < num_processors) {
		pr_info("Number of CPUs limited by 'possible_cpus' kernel param\n");
		goto err;
	}

#ifdef CONFIG_SMP
	if (setup_max_cpus < num_processors) {
		pr_info("Boot-time CPUs limited by 'maxcpus' kernel param\n");
		goto err;
	}
#endif

	return true;

err:
	pr_info("Skipping TDX-SEAM load/config.\n");
	return false;
}

static bool __init tdx_get_firmware(struct cpio_data *blob, const char *name)
{
	char path[64];
	long offset;
	void *data;
	size_t size;
	static const char * const search_path[] = {
		"lib/firmware/%s",
		"usr/lib/firmware/%s",
		"opt/intel/%s"
	};
	int i;

	if (get_builtin_firmware(blob, name))
		return true;

	if (!IS_ENABLED(CONFIG_BLK_DEV_INITRD) || !initrd_start)
		return false;

	for (i = 0; i < ARRAY_SIZE(search_path); i++) {
		offset = 0;
		data = (void *)initrd_start;
		size = initrd_end - initrd_start;
		snprintf(path, sizeof(path), search_path[i], name);
		while (size > 0) {
			*blob = find_cpio_data(path, data, size, &offset);

			/* find the filename, the returned blob name is empty */
			if (blob->data && blob->name[0] == '\0')
				return true;

			if (!blob->data)
				break;

			/* match the item with the same path prefix, skip it*/
			data += offset;
			size -= offset;
		}
	}

	return false;
}

int __init p_seamldr_get_info(void)
{
	int ret = 0;
	struct vmcs *vmcs = NULL;
	int vmxoff_err = 0;

	vmcs = (struct vmcs *)get_zeroed_page(GFP_KERNEL);
	if (!vmcs) {
		pr_err("Failed to alloc vmcs\n");
		return -ENOMEM;
	}

	ret = tdx_init_vmxon_vmcs(vmcs);
	if (ret) {
		pr_err("Failed to init vmcs\n");
		goto out;
	}

	WARN_ON(__read_cr4() & X86_CR4_VMXE);
	ret = cpu_vmxon(__pa(vmcs));
	if (ret)
		goto out;

	ret = seamldr_info(__pa(&p_seamldr_info));

	vmxoff_err = cpu_vmxoff();
	if (!ret && vmxoff_err)
		ret = vmxoff_err;
	if (ret)
		goto out;

	if (!p_seamldr_info.p_seamldr_ready) {
		pr_err("p_seamldr_ready is not set, it seems buggy P-SEAMLDR\n");
		ret = -EINVAL;
		goto out;
	}

	pr_info("TDX P-SEAMLDR: "
			"attributes 0x%0x vendor_id 0x%x "
			"build_date %d build_num 0x%x "
			"minor_version 0x%x major_version 0x%x.\n",
			p_seamldr_info.attributes,
			p_seamldr_info.vendor_id,
			p_seamldr_info.build_date,
			p_seamldr_info.build_num,
			p_seamldr_info.minor_version,
			p_seamldr_info.major_version);
out:
	free_page((unsigned long)vmcs);
	return ret;
}

int __init tdh_seam_init(void)
{
	struct cpio_data seamldr;
	int ret;

	/* Avoid TDX overhead when opt-in is not present. */
	if (tdx_host != TDX_HOST_ON)
		return 0;

	if (!platform_has_tdx())
		return 0;

	tdx_module_status = TDX_SEAMLDR_UNKNOWN;
	ret = p_seamldr_get_info();
	if (ret == -EIO) {
		pr_err("No P-SEAMLDR loaded by BIOS.\n");

		if (!tdx_get_firmware(&seamldr, tdx_npseamldr_name)) {
			pr_err("Cannot found np-seamldr:%s\n", tdx_npseamldr_name);
			goto error;
		}

		ret = seam_load_module(&seamldr);
		if (ret) {
			pr_err("Failed to launch seamldr %d\n", ret);
			goto error;
		}
		ret = p_seamldr_get_info();
		if (ret) {
			pr_err("Get P-SEAMLDR failed with %d\n", ret);
			goto error;
		}
	} else if (ret) {
		pr_err("Get P-SEAMLDR failed with %d\n", ret);
		goto error;
	}
	tdx_module_status = TDX_SEAMLDR_READY;
	setup_force_cpu_cap(X86_FEATURE_TDX);
	return 0;

error:
	pr_err("can't load/init TDX-SEAM.\n");
	setup_clear_cpu_cap(X86_FEATURE_TDX);
	return ret;
}
early_initcall(tdh_seam_init);

static bool tdx_keyid_sufficient(void)
{
	u32 _keyids_start, nr_keyids;

	/*
	 * Don't load/configure SEAM if not all CPUs can be brought up during
	 * smp_init(), TDX must execute TDH_SYS_LP_INIT on all logical processors.
	 */
	if (WARN_ON_ONCE(!tdx_all_cpus_available()))
		return false;

	if (tdx_get_keyids(&_keyids_start, &nr_keyids))
		return false;

	/*
	 * TDX requires at least two KeyIDs: one global KeyID to
	 * protect the metadata of the TDX module and one or more
	 * KeyIDs to run TD guests.
	 */
	return nr_keyids >= 2;
}

bool platform_has_tdx(void)
{
	return is_seamrr_enabled() && tdx_keyid_sufficient();
}
