// SPDX-License-Identifier: GPL-2.0-only
/*
 * HYGON CSV support
 *
 * Copyright (C) Hygon Info Technologies Ltd.
 */

#include <linux/preempt.h>
#include <linux/smp.h>
#include <linux/memblock.h>
#include <asm/mem_encrypt.h>
#include <asm/csv_command.h>
#include "../mm/mm_internal.h"

#include "csv_command_common.c"

u32 vendor_ebx __section(".data") = 0;
u32 vendor_ecx __section(".data") = 0;
u32 vendor_edx __section(".data") = 0;

struct secure_call_pages {
	struct csv_secure_call_cmd page_a;
	struct csv_secure_call_cmd page_b;
};

static u32 csv_percpu_secure_call_init __initdata;
static u32 early_secure_call_page_idx __initdata;

static DEFINE_PER_CPU(struct secure_call_pages*, secure_call_data);
static DEFINE_PER_CPU(int, secure_call_page_idx);

typedef void (*csv_secure_call_func)(u64 base_address, u64 num_pages,
				     enum csv_secure_command_type cmd_type);

/*
 * Check whether host supports CSV in hygon platform.
 * Called in the guest, it always returns false.
 */
bool csv_enable(void)
{
	unsigned int eax, ebx, ecx, edx;
	unsigned long me_mask;
	u64 msr;
	bool csv_enabled;

	if (boot_cpu_data.x86_vendor != X86_VENDOR_HYGON)
		return false;

	if (sev_status)
		return false;

	/* Check for the SME/CSV support leaf */
	eax = 0x80000000;
	ecx = 0;
	native_cpuid(&eax, &ebx, &ecx, &edx);
	if (eax < 0x8000001f)
		return false;

#define SME_BIT		BIT(0)
	/*
	 * Check for the CSV feature:
	 * CPUID Fn8000_001F[EAX]
	 * - Bit 30 - CSV support
	 */
	eax = 0x8000001f;
	ecx = 0;
	native_cpuid(&eax, &ebx, &ecx, &edx);
	if (!(eax & SME_BIT))
		return false;

	csv_enabled = (eax & CPUID_CSV_ENABLED) ? true : false;
	me_mask = 1UL << (ebx & 0x3f);

	/* No SME if Hypervisor bit is set */
	eax = 1;
	ecx = 0;
	native_cpuid(&eax, &ebx, &ecx, &edx);
	if (ecx & BIT(31))
		return false;

	/* For SME, check the SYSCFG MSR */
	msr = __rdmsr(MSR_K8_SYSCFG);
	if (!(msr & MSR_K8_SYSCFG_MEM_ENCRYPT))
		return false;

	return !!me_mask && csv_enabled;
}

bool noinstr csv_active(void)
{
	if (vendor_ebx == 0 || vendor_ecx == 0 || vendor_edx == 0) {
		u32 eax = 0;

		native_cpuid(&eax, &vendor_ebx, &vendor_ecx, &vendor_edx);
	}

	/* HygonGenuine */
	if (vendor_ebx == CPUID_VENDOR_HygonGenuine_ebx &&
	    vendor_ecx == CPUID_VENDOR_HygonGenuine_ecx &&
	    vendor_edx == CPUID_VENDOR_HygonGenuine_edx)
		return !!(sev_status & MSR_CSV_ENABLED);
	else
		return false;
}

void __init csv_early_reset_memory(struct boot_params *bp)
{
	if (!csv_active())
		return;

	csv_scan_secure_call_pages(bp);
	csv_early_secure_call(0, 0, CSV_SECURE_CMD_RESET);
}

void __init csv_early_update_memory_dec(u64 vaddr, u64 pages)
{
	if (!csv_active())
		return;

	if (pages)
		csv_early_secure_call(__pa(vaddr), pages, CSV_SECURE_CMD_DEC);
}

void __init csv_early_update_memory_enc(u64 vaddr, u64 pages)
{
	if (!csv_active())
		return;

	if (pages)
		csv_early_secure_call(__pa(vaddr), pages, CSV_SECURE_CMD_ENC);
}

static void __init csv_alloc_secure_call_data(int cpu)
{
	struct secure_call_pages *data;

	data = memblock_alloc(sizeof(*data), PAGE_SIZE);
	if (!data)
		panic("Can't allocate CSV secure all data");

	per_cpu(secure_call_data, cpu) = data;
}

static void __init csv_secure_call_update_table(void)
{
	int cpu;
	struct secure_call_pages *data;
	struct csv_secure_call_cmd *page_rd;
	struct csv_secure_call_cmd *page_wr;
	u32 cmd_ack;

	if (!csv_active())
		return;

	page_rd = (void *)early_memremap_encrypted(csv_boot_sc_page_a, PAGE_SIZE);
	page_wr = (void *)early_memremap_encrypted(csv_boot_sc_page_b, PAGE_SIZE);

	while (1) {
		page_wr->cmd_type = CSV_SECURE_CMD_UPDATE_SECURE_CALL_TABLE;
		page_wr->nums = 0;

		/* initialize per-cpu secure call pages */
		for_each_possible_cpu(cpu) {
			if (cpu >= SECURE_CALL_ENTRY_MAX)
				panic("csv does not support cpus > %d\n",
				      SECURE_CALL_ENTRY_MAX);
			csv_alloc_secure_call_data(cpu);
			data = per_cpu(secure_call_data, cpu);
			per_cpu(secure_call_page_idx, cpu) = 0;
			page_wr->entry[cpu].base_address = __pa(data);
			page_wr->entry[cpu].size = PAGE_SIZE * 2;
			page_wr->nums++;
		}

		/*
		 * Write command in page_wr must be done before retrieve cmd
		 * ack from page_rd, and it is ensured by the mb below.
		 */
		mb();

		cmd_ack = page_rd->cmd_type;
		if (cmd_ack != CSV_SECURE_CMD_UPDATE_SECURE_CALL_TABLE)
			break;
	}

	early_memunmap(page_rd, PAGE_SIZE);
	early_memunmap(page_wr, PAGE_SIZE);
}

/**
 * __csv_early_secure_call - issue secure call command at the stage where new
 *			kernel page table is created and early identity page
 *			table is deprecated .
 * @base_address:	Start address of the specified memory range.
 * @num_pages:		number of the specific pages.
 * @cmd_type:		Secure call cmd type.
 */
static void __init __csv_early_secure_call(u64 base_address, u64 num_pages,
					   enum csv_secure_command_type cmd_type)
{
	struct csv_secure_call_cmd *page_rd;
	struct csv_secure_call_cmd *page_wr;
	u32 cmd_ack;

	if (csv_boot_sc_page_a == -1ul || csv_boot_sc_page_b == -1ul)
		return;

	if (!csv_percpu_secure_call_init) {
		csv_secure_call_update_table();
		csv_percpu_secure_call_init = 1;
	}

	if (early_secure_call_page_idx == 0) {
		page_rd = (void *)early_memremap_encrypted(csv_boot_sc_page_a,
							   PAGE_SIZE);
		page_wr = (void *)early_memremap_encrypted(csv_boot_sc_page_b,
							   PAGE_SIZE);
	} else {
		page_wr = (void *)early_memremap_encrypted(csv_boot_sc_page_a,
							   PAGE_SIZE);
		page_rd = (void *)early_memremap_encrypted(csv_boot_sc_page_b,
							   PAGE_SIZE);
	}

	while (1) {
		page_wr->cmd_type = (u32)cmd_type;
		page_wr->nums = 1;
		page_wr->entry[0].base_address = base_address;
		page_wr->entry[0].size = num_pages << PAGE_SHIFT;

		/*
		 * Write command in page_wr must be done before retrieve cmd
		 * ack from page_rd, and it is ensured by the mb below.
		 */
		mb();

		cmd_ack = page_rd->cmd_type;
		if (cmd_ack != cmd_type)
			break;
	}

	early_memunmap(page_rd, PAGE_SIZE);
	early_memunmap(page_wr, PAGE_SIZE);

	early_secure_call_page_idx ^= 1;
}


static void __csv_memory_enc_dec(csv_secure_call_func secure_call, u64 vaddr,
				 u64 pages, bool enc)
{
	u64 vaddr_end, vaddr_next;
	u64 psize, pmask;
	u64 last_paddr, paddr;
	u64 last_psize = 0;
	pte_t *kpte;
	int level;
	enum csv_secure_command_type cmd_type;

	if (!csv_active())
		return;

	cmd_type = enc ? CSV_SECURE_CMD_ENC : CSV_SECURE_CMD_DEC;
	vaddr_next = vaddr;
	vaddr_end = vaddr + (pages << PAGE_SHIFT);
	for (; vaddr < vaddr_end; vaddr = vaddr_next) {
		kpte = lookup_address(vaddr, &level);
		if (!kpte || pte_none(*kpte)) {
			panic("invalid pte, vaddr 0x%llx\n", vaddr);
			goto out;
		}

		psize = page_level_size(level);
		pmask = page_level_mask(level);

		vaddr_next = (vaddr & pmask) + psize;
		paddr = ((pte_pfn(*kpte) << PAGE_SHIFT) & pmask) +
			(vaddr & ~pmask);
		psize -= (vaddr & ~pmask);

		if (vaddr_end - vaddr < psize)
			psize = vaddr_end - vaddr;
		if (last_psize == 0 || (last_paddr + last_psize) == paddr) {
			last_paddr = (last_psize == 0 ? paddr : last_paddr);
			last_psize += psize;
		} else {
			secure_call(last_paddr, last_psize >> PAGE_SHIFT,
				    cmd_type);
			last_paddr = paddr;
			last_psize = psize;
		}
	}

	if (last_psize)
		secure_call(last_paddr, last_psize >> PAGE_SHIFT, cmd_type);

out:
	return;
}

void __init csv_early_memory_enc_dec(u64 vaddr, u64 size, bool enc)
{
	u64 npages;

	npages = (size + (vaddr & ~PAGE_MASK) + PAGE_SIZE - 1) >> PAGE_SHIFT;
	__csv_memory_enc_dec(__csv_early_secure_call, vaddr & PAGE_MASK,
			     npages, enc);
}
