// SPDX-License-Identifier: GPL-2.0-only
/*
 * Kernel-based Virtual Machine driver for Linux
 *
 * AMD SVM-SEV support
 *
 * Copyright 2010 Red Hat, Inc. and/or its affiliates.
 */

#include <linux/kvm_types.h>
#include <linux/kvm_host.h>
#include <linux/kernel.h>
#include <linux/highmem.h>
#include <linux/psp-sev.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/processor.h>
#include <linux/trace_events.h>
#include <asm/fpu/internal.h>

#include <asm/trapnr.h>

#include <asm/pkru.h>
#include <asm/fpu/xcr.h>

#include "x86.h"
#include "svm.h"
#include "cpuid.h"
#include "trace.h"

#define __ex(x) __kvm_handle_fault_on_reboot(x)

static u8 sev_enc_bit;
static DECLARE_RWSEM(sev_deactivate_lock);
static DEFINE_MUTEX(sev_bitmap_lock);
unsigned int max_sev_asid;
static unsigned int min_sev_asid;
static unsigned long sev_me_mask;
static unsigned long *sev_asid_bitmap;
static unsigned long *sev_reclaim_asid_bitmap;

static DEFINE_MUTEX(csv_cmd_batch_mutex);

static const char sev_vm_mnonce[] = "VM_ATTESTATION";

struct enc_region {
	struct list_head list;
	unsigned long npages;
	struct page **pages;
	unsigned long uaddr;
	unsigned long size;
};

/* Called with the sev_bitmap_lock held, or on shutdown  */
static int sev_flush_asids(int min_asid, int max_asid)
{
	int ret, pos, error = 0;

	/* Check if there are any ASIDs to reclaim before performing a flush */
	pos = find_next_bit(sev_reclaim_asid_bitmap, max_asid, min_asid);
	if (pos >= max_asid)
		return -EBUSY;

	/*
	 * DEACTIVATE will clear the WBINVD indicator causing DF_FLUSH to fail,
	 * so it must be guarded.
	 */
	down_write(&sev_deactivate_lock);

	wbinvd_on_all_cpus();
	ret = sev_guest_df_flush(&error);

	up_write(&sev_deactivate_lock);

	if (ret)
		pr_err("SEV: DF_FLUSH failed, ret=%d, error=%#x\n", ret, error);

	return ret;
}

/* Must be called with the sev_bitmap_lock held */
static bool __sev_recycle_asids(int min_asid, int max_asid)
{
	if (sev_flush_asids(min_asid, max_asid))
		return false;

	/* The flush process will flush all reclaimable SEV and SEV-ES ASIDs */
	bitmap_xor(sev_asid_bitmap, sev_asid_bitmap, sev_reclaim_asid_bitmap,
		   max_sev_asid);
	bitmap_zero(sev_reclaim_asid_bitmap, max_sev_asid);

	return true;
}

static int sev_asid_new(bool es_active)
{
	int pos, min_asid, max_asid;
	bool retry = true;

	mutex_lock(&sev_bitmap_lock);

	/*
	 * SEV-enabled guests must use asid from min_sev_asid to max_sev_asid.
	 * SEV-ES-enabled guest can use from 1 to min_sev_asid - 1.
	 */
	min_asid = es_active ? 0 : min_sev_asid - 1;
	max_asid = es_active ? min_sev_asid - 1 : max_sev_asid;

	/*
	 * No matter what the min_sev_asid is, all asids in range
	 * [1, max_sev_asid] can be used for CSV2 guest on Hygon CPUs.
	 */
	if (boot_cpu_data.x86_vendor == X86_VENDOR_HYGON)
		max_asid = max_sev_asid;
again:
	pos = find_next_zero_bit(sev_asid_bitmap, max_sev_asid, min_asid);
	if (pos >= max_asid) {
		if (retry && __sev_recycle_asids(min_asid, max_asid)) {
			retry = false;
			goto again;
		}
		mutex_unlock(&sev_bitmap_lock);
		return -EBUSY;
	}

	__set_bit(pos, sev_asid_bitmap);

	mutex_unlock(&sev_bitmap_lock);

	return pos + 1;
}

static int sev_get_asid(struct kvm *kvm)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;

	return sev->asid;
}

static void sev_asid_free(int asid)
{
	struct svm_cpu_data *sd;
	int cpu, pos;

	mutex_lock(&sev_bitmap_lock);

	pos = asid - 1;
	__set_bit(pos, sev_reclaim_asid_bitmap);

	for_each_possible_cpu(cpu) {
		sd = per_cpu(svm_data, cpu);
		sd->sev_vmcbs[asid] = NULL;
	}

	mutex_unlock(&sev_bitmap_lock);
}

static void sev_decommission(unsigned int handle)
{
	struct sev_data_decommission *decommission;

	if (!handle)
		return;

	decommission = kzalloc(sizeof(*decommission), GFP_KERNEL);
	if (!decommission)
		return;

	decommission->handle = handle;
	sev_guest_decommission(decommission, NULL);

	kfree(decommission);
}

static void sev_unbind_asid(struct kvm *kvm, unsigned int handle)
{
	struct sev_data_deactivate *data;

	if (!handle)
		return;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return;

	/* deactivate handle */
	data->handle = handle;

	/* Guard DEACTIVATE against WBINVD/DF_FLUSH used in ASID recycling */
	down_read(&sev_deactivate_lock);
	sev_guest_deactivate(data, NULL);
	up_read(&sev_deactivate_lock);

	kfree(data);

	sev_decommission(handle);
}

static int sev_guest_init(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	bool es_active = argp->id == KVM_SEV_ES_INIT;
	int asid, ret;

	if (kvm->created_vcpus)
		return -EINVAL;

	ret = -EBUSY;
	if (unlikely(sev->active))
		return ret;

	asid = sev_asid_new(es_active);
	if (asid < 0)
		return ret;

	ret = sev_platform_init(&argp->error);
	if (ret)
		goto e_free;

	sev->active = true;
	sev->es_active = es_active;
	sev->asid = asid;
	INIT_LIST_HEAD(&sev->regions_list);

	return 0;

e_free:
	sev_asid_free(asid);
	return ret;
}

static int sev_bind_asid(struct kvm *kvm, unsigned int handle, int *error)
{
	struct sev_data_activate *data;
	int asid = sev_get_asid(kvm);
	int ret;

	data = kzalloc(sizeof(*data), GFP_KERNEL_ACCOUNT);
	if (!data)
		return -ENOMEM;

	/* activate ASID on the given handle */
	data->handle = handle;
	data->asid   = asid;
	ret = sev_guest_activate(data, error);
	kfree(data);

	return ret;
}

static int __sev_issue_cmd(int fd, int id, void *data, int *error)
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

static int sev_issue_cmd(struct kvm *kvm, int id, void *data, int *error)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;

	return __sev_issue_cmd(sev->fd, id, data, error);
}

static int __csv_issue_ringbuf_cmds(int fd, int *psp_ret)
{
	struct fd f;
	int ret;

	f = fdget(fd);
	if (!f.file)
		return -EBADF;

	ret = csv_issue_ringbuf_cmds_external_user(f.file, psp_ret);

	fdput(f);
	return ret;
}

static int csv_issue_ringbuf_cmds(struct kvm *kvm, int *psp_ret)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;

	return __csv_issue_ringbuf_cmds(sev->fd, psp_ret);
}

static int sev_launch_start(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_launch_start *start;
	struct kvm_sev_launch_start params;
	void *dh_blob, *session_blob;
	int *error = &argp->error;
	int ret;

	if (!sev_guest(kvm))
		return -ENOTTY;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data, sizeof(params)))
		return -EFAULT;

	start = kzalloc(sizeof(*start), GFP_KERNEL_ACCOUNT);
	if (!start)
		return -ENOMEM;

	dh_blob = NULL;
	if (params.dh_uaddr) {
		dh_blob = psp_copy_user_blob(params.dh_uaddr, params.dh_len);
		if (IS_ERR(dh_blob)) {
			ret = PTR_ERR(dh_blob);
			goto e_free;
		}

		start->dh_cert_address = __sme_set(__pa(dh_blob));
		start->dh_cert_len = params.dh_len;
	}

	session_blob = NULL;
	if (params.session_uaddr) {
		session_blob = psp_copy_user_blob(params.session_uaddr, params.session_len);
		if (IS_ERR(session_blob)) {
			ret = PTR_ERR(session_blob);
			goto e_free_dh;
		}

		start->session_address = __sme_set(__pa(session_blob));
		start->session_len = params.session_len;
	}

	start->handle = params.handle;
	start->policy = params.policy;

	/* create memory encryption context */
	ret = __sev_issue_cmd(argp->sev_fd, SEV_CMD_LAUNCH_START, start, error);
	if (ret)
		goto e_free_session;

	/* Bind ASID to this guest */
	ret = sev_bind_asid(kvm, start->handle, error);
	if (ret) {
		sev_decommission(start->handle);
		goto e_free_session;
	}

	/* return handle to userspace */
	params.handle = start->handle;
	if (copy_to_user((void __user *)(uintptr_t)argp->data, &params, sizeof(params))) {
		sev_unbind_asid(kvm, start->handle);
		ret = -EFAULT;
		goto e_free_session;
	}

	sev->handle = start->handle;
	sev->fd = argp->sev_fd;

e_free_session:
	kfree(session_blob);
e_free_dh:
	kfree(dh_blob);
e_free:
	kfree(start);
	return ret;
}

static struct page **sev_pin_memory(struct kvm *kvm, unsigned long uaddr,
				    unsigned long ulen, unsigned long *n,
				    int write)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	unsigned long npages, size;
	int npinned;
	unsigned long locked, lock_limit;
	struct page **pages;
	unsigned long first, last;
	unsigned int flags = 0;
	int ret;

	lockdep_assert_held(&kvm->lock);

	if (ulen == 0 || uaddr + ulen < uaddr)
		return ERR_PTR(-EINVAL);

	/* Calculate number of pages. */
	first = (uaddr & PAGE_MASK) >> PAGE_SHIFT;
	last = ((uaddr + ulen - 1) & PAGE_MASK) >> PAGE_SHIFT;
	npages = (last - first + 1);

	locked = sev->pages_locked + npages;
	lock_limit = rlimit(RLIMIT_MEMLOCK) >> PAGE_SHIFT;
	if (locked > lock_limit && !capable(CAP_IPC_LOCK)) {
		pr_err("SEV: %lu locked pages exceed the lock limit of %lu.\n", locked, lock_limit);
		return ERR_PTR(-ENOMEM);
	}

	if (WARN_ON_ONCE(npages > INT_MAX))
		return ERR_PTR(-EINVAL);

	/* Avoid using vmalloc for smaller buffers. */
	size = npages * sizeof(struct page *);
	if (size > PAGE_SIZE)
		pages = __vmalloc(size, GFP_KERNEL_ACCOUNT | __GFP_ZERO);
	else
		pages = kmalloc(size, GFP_KERNEL_ACCOUNT);

	if (!pages)
		return ERR_PTR(-ENOMEM);

	flags = write ? FOLL_WRITE : 0;

	/* Pin the user virtual address. */
	npinned = pin_user_pages_fast(uaddr, npages, flags | FOLL_LONGTERM, pages);
	if (npinned != npages) {
		pr_err("SEV: Failure locking %lu pages.\n", npages);
		ret = -ENOMEM;
		goto err;
	}

	*n = npages;
	sev->pages_locked = locked;

	return pages;

err:
	if (npinned > 0)
		unpin_user_pages(pages, npinned);

	kvfree(pages);
	return ERR_PTR(ret);
}

static void sev_unpin_memory(struct kvm *kvm, struct page **pages,
			     unsigned long npages)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;

	unpin_user_pages(pages, npages);
	kvfree(pages);
	sev->pages_locked -= npages;
}

static void sev_clflush_pages(struct page *pages[], unsigned long npages)
{
	uint8_t *page_virtual;
	unsigned long i;

	if (this_cpu_has(X86_FEATURE_SME_COHERENT) || npages == 0 ||
	    pages == NULL)
		return;

	for (i = 0; i < npages; i++) {
		page_virtual = kmap_atomic(pages[i]);
		clflush_cache_range(page_virtual, PAGE_SIZE);
		kunmap_atomic(page_virtual);
		cond_resched();
	}
}

static unsigned long get_num_contig_pages(unsigned long idx,
				struct page **inpages, unsigned long npages)
{
	unsigned long paddr, next_paddr;
	unsigned long i = idx + 1, pages = 1;

	/* find the number of contiguous pages starting from idx */
	paddr = __sme_page_pa(inpages[idx]);
	while (i < npages) {
		next_paddr = __sme_page_pa(inpages[i++]);
		if ((paddr + PAGE_SIZE) == next_paddr) {
			pages++;
			paddr = next_paddr;
			continue;
		}
		break;
	}

	return pages;
}

static int sev_launch_update_data(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	unsigned long vaddr, vaddr_end, next_vaddr, npages, pages, size, i;
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct kvm_sev_launch_update_data params;
	struct sev_data_launch_update_data *data;
	struct page **inpages;
	int ret;

	if (!sev_guest(kvm))
		return -ENOTTY;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data, sizeof(params)))
		return -EFAULT;

	data = kzalloc(sizeof(*data), GFP_KERNEL_ACCOUNT);
	if (!data)
		return -ENOMEM;

	vaddr = params.uaddr;
	size = params.len;
	vaddr_end = vaddr + size;

	/* Lock the user memory. */
	inpages = sev_pin_memory(kvm, vaddr, size, &npages, 1);
	if (IS_ERR(inpages)) {
		ret = PTR_ERR(inpages);
		goto e_free;
	}

	/*
	 * Flush (on non-coherent CPUs) before LAUNCH_UPDATE encrypts pages in
	 * place; the cache may contain the data that was written unencrypted.
	 */
	sev_clflush_pages(inpages, npages);

	for (i = 0; vaddr < vaddr_end; vaddr = next_vaddr, i += pages) {
		int offset, len;

		/*
		 * If the user buffer is not page-aligned, calculate the offset
		 * within the page.
		 */
		offset = vaddr & (PAGE_SIZE - 1);

		/* Calculate the number of pages that can be encrypted in one go. */
		pages = get_num_contig_pages(i, inpages, npages);

		len = min_t(size_t, ((pages * PAGE_SIZE) - offset), size);

		data->handle = sev->handle;
		data->len = len;
		data->address = __sme_page_pa(inpages[i]) + offset;
		ret = sev_issue_cmd(kvm, SEV_CMD_LAUNCH_UPDATE_DATA, data, &argp->error);
		if (ret)
			goto e_unpin;

		size -= len;
		next_vaddr = vaddr + len;
	}

e_unpin:
	/* content of memory is updated, mark pages dirty */
	for (i = 0; i < npages; i++) {
		set_page_dirty_lock(inpages[i]);
		mark_page_accessed(inpages[i]);
	}
	/* unlock the user pages */
	sev_unpin_memory(kvm, inpages, npages);
e_free:
	kfree(data);
	return ret;
}

static int sev_es_sync_vmsa(struct vcpu_svm *svm)
{
	struct vmcb_save_area *save = &svm->vmcb->save;

	/* Check some debug related fields before encrypting the VMSA */
	if (svm->vcpu.guest_debug || (save->dr7 & ~DR7_FIXED_1))
		return -EINVAL;

	/* Sync registgers */
	save->rax = svm->vcpu.arch.regs[VCPU_REGS_RAX];
	save->rbx = svm->vcpu.arch.regs[VCPU_REGS_RBX];
	save->rcx = svm->vcpu.arch.regs[VCPU_REGS_RCX];
	save->rdx = svm->vcpu.arch.regs[VCPU_REGS_RDX];
	save->rsp = svm->vcpu.arch.regs[VCPU_REGS_RSP];
	save->rbp = svm->vcpu.arch.regs[VCPU_REGS_RBP];
	save->rsi = svm->vcpu.arch.regs[VCPU_REGS_RSI];
	save->rdi = svm->vcpu.arch.regs[VCPU_REGS_RDI];
#ifdef CONFIG_X86_64
	save->r8  = svm->vcpu.arch.regs[VCPU_REGS_R8];
	save->r9  = svm->vcpu.arch.regs[VCPU_REGS_R9];
	save->r10 = svm->vcpu.arch.regs[VCPU_REGS_R10];
	save->r11 = svm->vcpu.arch.regs[VCPU_REGS_R11];
	save->r12 = svm->vcpu.arch.regs[VCPU_REGS_R12];
	save->r13 = svm->vcpu.arch.regs[VCPU_REGS_R13];
	save->r14 = svm->vcpu.arch.regs[VCPU_REGS_R14];
	save->r15 = svm->vcpu.arch.regs[VCPU_REGS_R15];
#endif
	save->rip = svm->vcpu.arch.regs[VCPU_REGS_RIP];

	/* Sync some non-GPR registers before encrypting */
	save->xcr0 = svm->vcpu.arch.xcr0;
	save->pkru = svm->vcpu.arch.pkru;
	save->xss  = svm->vcpu.arch.ia32_xss;

	/*
	 * SEV-ES will use a VMSA that is pointed to by the VMCB, not
	 * the traditional VMSA that is part of the VMCB. Copy the
	 * traditional VMSA as it has been built so far (in prep
	 * for LAUNCH_UPDATE_VMSA) to be the initial SEV-ES state.
	 */
	memcpy(svm->vmsa, save, sizeof(*save));

	return 0;
}

static int __sev_launch_update_vmsa(struct kvm *kvm, struct kvm_vcpu *vcpu,
				    int *error)
{
	struct sev_data_launch_update_vmsa *vmsa;
	struct vcpu_svm *svm = to_svm(vcpu);
	int ret;

	vmsa = kzalloc(sizeof(*vmsa), GFP_KERNEL);
	if (!vmsa)
		return -ENOMEM;

	/* Perform some pre-encryption checks against the VMSA */
	ret = sev_es_sync_vmsa(svm);
	if (ret)
		goto e_free;

	/*
	 * The LAUNCH_UPDATE_VMSA command will perform in-place encryption of
	 * the VMSA memory content (i.e it will write the same memory region
	 * with the guest's key), so invalidate it first.
	 */
	clflush_cache_range(svm->vmsa, PAGE_SIZE);

	vmsa->handle = to_kvm_svm(kvm)->sev_info.handle;
	vmsa->address = __sme_pa(svm->vmsa);
	vmsa->len = PAGE_SIZE;
	ret = sev_issue_cmd(kvm, SEV_CMD_LAUNCH_UPDATE_VMSA, vmsa, error);

	if (ret)
		goto e_free;

	vcpu->arch.guest_state_protected = true;

	/*
	 * Backup encrypted vmsa to support rebooting CSV2 guest. The
	 * clflush_cache_range() is necessary to invalidate prefetched
	 * memory area pointed by svm->vmsa so that we can read fresh
	 * memory updated by PSP.
	 */
	if (boot_cpu_data.x86_vendor == X86_VENDOR_HYGON) {
		clflush_cache_range(svm->vmsa, PAGE_SIZE);
		memcpy(svm->reset_vmsa, svm->vmsa, PAGE_SIZE);
	}

e_free:
	kfree(vmsa);
	return ret;
}

static int sev_launch_update_vmsa(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_vcpu *vcpu;
	int i, ret;

	if (!sev_es_guest(kvm))
		return -ENOTTY;

	kvm_for_each_vcpu(i, vcpu, kvm) {
		ret = mutex_lock_killable(&vcpu->mutex);
		if (ret)
			return ret;

		ret = __sev_launch_update_vmsa(kvm, vcpu, &argp->error);

		mutex_unlock(&vcpu->mutex);
		if (ret)
			return ret;
	}

	return 0;
}

static int sev_launch_measure(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	void __user *measure = (void __user *)(uintptr_t)argp->data;
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_launch_measure *data;
	struct kvm_sev_launch_measure params;
	void __user *p = NULL;
	void *blob = NULL;
	int ret;

	if (!sev_guest(kvm))
		return -ENOTTY;

	if (copy_from_user(&params, measure, sizeof(params)))
		return -EFAULT;

	data = kzalloc(sizeof(*data), GFP_KERNEL_ACCOUNT);
	if (!data)
		return -ENOMEM;

	/* User wants to query the blob length */
	if (!params.len)
		goto cmd;

	p = (void __user *)(uintptr_t)params.uaddr;
	if (p) {
		if (params.len > SEV_FW_BLOB_MAX_SIZE) {
			ret = -EINVAL;
			goto e_free;
		}

		ret = -ENOMEM;
		blob = kzalloc(params.len, GFP_KERNEL_ACCOUNT);
		if (!blob)
			goto e_free;

		data->address = __psp_pa(blob);
		data->len = params.len;
	}

cmd:
	data->handle = sev->handle;
	ret = sev_issue_cmd(kvm, SEV_CMD_LAUNCH_MEASURE, data, &argp->error);

	/*
	 * If we query the session length, FW responded with expected data.
	 */
	if (!params.len)
		goto done;

	if (ret)
		goto e_free_blob;

	if (blob) {
		if (copy_to_user(p, blob, params.len))
			ret = -EFAULT;
	}

done:
	params.len = data->len;
	if (copy_to_user(measure, &params, sizeof(params)))
		ret = -EFAULT;
e_free_blob:
	kfree(blob);
e_free:
	kfree(data);
	return ret;
}

static int sev_launch_finish(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_launch_finish *data;
	int ret;

	if (!sev_guest(kvm))
		return -ENOTTY;

	data = kzalloc(sizeof(*data), GFP_KERNEL_ACCOUNT);
	if (!data)
		return -ENOMEM;

	data->handle = sev->handle;
	ret = sev_issue_cmd(kvm, SEV_CMD_LAUNCH_FINISH, data, &argp->error);

	kfree(data);
	return ret;
}

static int sev_guest_status(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct kvm_sev_guest_status params;
	struct sev_data_guest_status *data;
	int ret;

	if (!sev_guest(kvm))
		return -ENOTTY;

	data = kzalloc(sizeof(*data), GFP_KERNEL_ACCOUNT);
	if (!data)
		return -ENOMEM;

	data->handle = sev->handle;
	ret = sev_issue_cmd(kvm, SEV_CMD_GUEST_STATUS, data, &argp->error);
	if (ret)
		goto e_free;

	params.policy = data->policy;
	params.state = data->state;
	params.handle = data->handle;

	if (copy_to_user((void __user *)(uintptr_t)argp->data, &params, sizeof(params)))
		ret = -EFAULT;
e_free:
	kfree(data);
	return ret;
}

static int __sev_issue_dbg_cmd(struct kvm *kvm, unsigned long src,
			       unsigned long dst, int size,
			       int *error, bool enc)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_dbg *data;
	int ret;

	data = kzalloc(sizeof(*data), GFP_KERNEL_ACCOUNT);
	if (!data)
		return -ENOMEM;

	data->handle = sev->handle;
	data->dst_addr = dst;
	data->src_addr = src;
	data->len = size;

	ret = sev_issue_cmd(kvm,
			    enc ? SEV_CMD_DBG_ENCRYPT : SEV_CMD_DBG_DECRYPT,
			    data, error);
	kfree(data);
	return ret;
}

static int __sev_dbg_decrypt(struct kvm *kvm, unsigned long src_paddr,
			     unsigned long dst_paddr, int sz, int *err)
{
	int offset;

	/*
	 * Its safe to read more than we are asked, caller should ensure that
	 * destination has enough space.
	 */
	offset = src_paddr & 15;
	src_paddr = round_down(src_paddr, 16);
	sz = round_up(sz + offset, 16);

	return __sev_issue_dbg_cmd(kvm, src_paddr, dst_paddr, sz, err, false);
}

static int __sev_dbg_decrypt_user(struct kvm *kvm, unsigned long paddr,
				  unsigned long __user dst_uaddr,
				  unsigned long dst_paddr,
				  int size, int *err)
{
	struct page *tpage = NULL;
	int ret, offset;

	/* if inputs are not 16-byte then use intermediate buffer */
	if (!IS_ALIGNED(dst_paddr, 16) ||
	    !IS_ALIGNED(paddr,     16) ||
	    !IS_ALIGNED(size,      16)) {
		tpage = (void *)alloc_page(GFP_KERNEL | __GFP_ZERO);
		if (!tpage)
			return -ENOMEM;

		dst_paddr = __sme_page_pa(tpage);
	}

	ret = __sev_dbg_decrypt(kvm, paddr, dst_paddr, size, err);
	if (ret)
		goto e_free;

	if (tpage) {
		offset = paddr & 15;
		if (copy_to_user((void __user *)(uintptr_t)dst_uaddr,
				 page_address(tpage) + offset, size))
			ret = -EFAULT;
	}

e_free:
	if (tpage)
		__free_page(tpage);

	return ret;
}

static int __sev_dbg_encrypt_user(struct kvm *kvm, unsigned long paddr,
				  unsigned long __user vaddr,
				  unsigned long dst_paddr,
				  unsigned long __user dst_vaddr,
				  int size, int *error)
{
	struct page *src_tpage = NULL;
	struct page *dst_tpage = NULL;
	int ret, len = size;

	/* If source buffer is not aligned then use an intermediate buffer */
	if (!IS_ALIGNED(vaddr, 16)) {
		src_tpage = alloc_page(GFP_KERNEL);
		if (!src_tpage)
			return -ENOMEM;

		if (copy_from_user(page_address(src_tpage),
				(void __user *)(uintptr_t)vaddr, size)) {
			__free_page(src_tpage);
			return -EFAULT;
		}

		paddr = __sme_page_pa(src_tpage);
	}

	/*
	 *  If destination buffer or length is not aligned then do read-modify-write:
	 *   - decrypt destination in an intermediate buffer
	 *   - copy the source buffer in an intermediate buffer
	 *   - use the intermediate buffer as source buffer
	 */
	if (!IS_ALIGNED(dst_vaddr, 16) || !IS_ALIGNED(size, 16)) {
		int dst_offset;

		dst_tpage = alloc_page(GFP_KERNEL);
		if (!dst_tpage) {
			ret = -ENOMEM;
			goto e_free;
		}

		ret = __sev_dbg_decrypt(kvm, dst_paddr,
					__sme_page_pa(dst_tpage), size, error);
		if (ret)
			goto e_free;

		/*
		 *  If source is kernel buffer then use memcpy() otherwise
		 *  copy_from_user().
		 */
		dst_offset = dst_paddr & 15;

		if (src_tpage)
			memcpy(page_address(dst_tpage) + dst_offset,
			       page_address(src_tpage), size);
		else {
			if (copy_from_user(page_address(dst_tpage) + dst_offset,
					   (void __user *)(uintptr_t)vaddr, size)) {
				ret = -EFAULT;
				goto e_free;
			}
		}

		paddr = __sme_page_pa(dst_tpage);
		dst_paddr = round_down(dst_paddr, 16);
		len = round_up(size, 16);
	}

	ret = __sev_issue_dbg_cmd(kvm, paddr, dst_paddr, len, error, true);

e_free:
	if (src_tpage)
		__free_page(src_tpage);
	if (dst_tpage)
		__free_page(dst_tpage);
	return ret;
}

static int sev_dbg_crypt(struct kvm *kvm, struct kvm_sev_cmd *argp, bool dec)
{
	unsigned long vaddr, vaddr_end, next_vaddr;
	unsigned long dst_vaddr;
	struct page **src_p, **dst_p;
	struct kvm_sev_dbg debug;
	unsigned long n;
	unsigned int size;
	int ret;

	if (!sev_guest(kvm))
		return -ENOTTY;

	if (copy_from_user(&debug, (void __user *)(uintptr_t)argp->data, sizeof(debug)))
		return -EFAULT;

	if (!debug.len || debug.src_uaddr + debug.len < debug.src_uaddr)
		return -EINVAL;
	if (!debug.dst_uaddr)
		return -EINVAL;

	vaddr = debug.src_uaddr;
	size = debug.len;
	vaddr_end = vaddr + size;
	dst_vaddr = debug.dst_uaddr;

	for (; vaddr < vaddr_end; vaddr = next_vaddr) {
		int len, s_off, d_off;

		/* lock userspace source and destination page */
		src_p = sev_pin_memory(kvm, vaddr & PAGE_MASK, PAGE_SIZE, &n, 0);
		if (IS_ERR(src_p))
			return PTR_ERR(src_p);

		dst_p = sev_pin_memory(kvm, dst_vaddr & PAGE_MASK, PAGE_SIZE, &n, 1);
		if (IS_ERR(dst_p)) {
			sev_unpin_memory(kvm, src_p, n);
			return PTR_ERR(dst_p);
		}

		/*
		 * Flush (on non-coherent CPUs) before DBG_{DE,EN}CRYPT read or modify
		 * the pages; flush the destination too so that future accesses do not
		 * see stale data.
		 */
		sev_clflush_pages(src_p, 1);
		sev_clflush_pages(dst_p, 1);

		/*
		 * Since user buffer may not be page aligned, calculate the
		 * offset within the page.
		 */
		s_off = vaddr & ~PAGE_MASK;
		d_off = dst_vaddr & ~PAGE_MASK;
		len = min_t(size_t, (PAGE_SIZE - s_off), size);

		if (dec)
			ret = __sev_dbg_decrypt_user(kvm,
						     __sme_page_pa(src_p[0]) + s_off,
						     dst_vaddr,
						     __sme_page_pa(dst_p[0]) + d_off,
						     len, &argp->error);
		else
			ret = __sev_dbg_encrypt_user(kvm,
						     __sme_page_pa(src_p[0]) + s_off,
						     vaddr,
						     __sme_page_pa(dst_p[0]) + d_off,
						     dst_vaddr,
						     len, &argp->error);

		sev_unpin_memory(kvm, src_p, n);
		sev_unpin_memory(kvm, dst_p, n);

		if (ret)
			goto err;

		next_vaddr = vaddr + len;
		dst_vaddr = dst_vaddr + len;
		size -= len;
	}
err:
	return ret;
}

static int sev_launch_secret(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_launch_secret *data;
	struct kvm_sev_launch_secret params;
	struct page **pages;
	void *blob, *hdr;
	unsigned long n, i;
	int ret, offset;

	if (!sev_guest(kvm))
		return -ENOTTY;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data, sizeof(params)))
		return -EFAULT;

	pages = sev_pin_memory(kvm, params.guest_uaddr, params.guest_len, &n, 1);
	if (IS_ERR(pages))
		return PTR_ERR(pages);

	/*
	 * Flush (on non-coherent CPUs) before LAUNCH_SECRET encrypts pages in
	 * place; the cache may contain the data that was written unencrypted.
	 */
	sev_clflush_pages(pages, n);

	/*
	 * The secret must be copied into contiguous memory region, lets verify
	 * that userspace memory pages are contiguous before we issue command.
	 */
	if (get_num_contig_pages(0, pages, n) != n) {
		ret = -EINVAL;
		goto e_unpin_memory;
	}

	ret = -ENOMEM;
	data = kzalloc(sizeof(*data), GFP_KERNEL_ACCOUNT);
	if (!data)
		goto e_unpin_memory;

	offset = params.guest_uaddr & (PAGE_SIZE - 1);
	data->guest_address = __sme_page_pa(pages[0]) + offset;
	data->guest_len = params.guest_len;

	blob = psp_copy_user_blob(params.trans_uaddr, params.trans_len);
	if (IS_ERR(blob)) {
		ret = PTR_ERR(blob);
		goto e_free;
	}

	data->trans_address = __psp_pa(blob);
	data->trans_len = params.trans_len;

	hdr = psp_copy_user_blob(params.hdr_uaddr, params.hdr_len);
	if (IS_ERR(hdr)) {
		ret = PTR_ERR(hdr);
		goto e_free_blob;
	}
	data->hdr_address = __psp_pa(hdr);
	data->hdr_len = params.hdr_len;

	data->handle = sev->handle;
	ret = sev_issue_cmd(kvm, SEV_CMD_LAUNCH_UPDATE_SECRET, data, &argp->error);

	kfree(hdr);

e_free_blob:
	kfree(blob);
e_free:
	kfree(data);
e_unpin_memory:
	/* content of memory is updated, mark pages dirty */
	for (i = 0; i < n; i++) {
		set_page_dirty_lock(pages[i]);
		mark_page_accessed(pages[i]);
	}
	sev_unpin_memory(kvm, pages, n);
	return ret;
}

static int sev_get_attestation_report(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	void __user *report = (void __user *)(uintptr_t)argp->data;
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_attestation_report *data;
	struct kvm_sev_attestation_report params;
	void __user *p;
	void *blob = NULL;
	int ret;

	if (!sev_guest(kvm))
		return -ENOTTY;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data, sizeof(params)))
		return -EFAULT;

	data = kzalloc(sizeof(*data), GFP_KERNEL_ACCOUNT);
	if (!data)
		return -ENOMEM;

	/* User wants to query the blob length */
	if (!params.len)
		goto cmd;

	p = (void __user *)(uintptr_t)params.uaddr;
	if (p) {
		if (params.len > SEV_FW_BLOB_MAX_SIZE) {
			ret = -EINVAL;
			goto e_free;
		}

		ret = -ENOMEM;
		blob = kmalloc(params.len, GFP_KERNEL);
		if (!blob)
			goto e_free;

		data->address = __psp_pa(blob);
		data->len = params.len;
		memcpy(data->mnonce, params.mnonce, sizeof(params.mnonce));
	}
cmd:
	data->handle = sev->handle;
	ret = sev_issue_cmd(kvm, SEV_CMD_ATTESTATION_REPORT, data, &argp->error);
	/*
	 * If we query the session length, FW responded with expected data.
	 */
	if (!params.len)
		goto done;

	if (ret)
		goto e_free_blob;

	if (blob) {
		if (copy_to_user(p, blob, params.len))
			ret = -EFAULT;
	}

done:
	params.len = data->len;
	if (copy_to_user(report, &params, sizeof(params)))
		ret = -EFAULT;
e_free_blob:
	kfree(blob);
e_free:
	kfree(data);
	return ret;
}

/* Userspace wants to query session length. */
static int
__sev_send_start_query_session_length(struct kvm *kvm, struct kvm_sev_cmd *argp,
				      struct kvm_sev_send_start *params)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_send_start *data;
	int ret;

	data = kzalloc(sizeof(*data), GFP_KERNEL_ACCOUNT);
	if (data == NULL)
		return -ENOMEM;

	data->handle = sev->handle;
	ret = sev_issue_cmd(kvm, SEV_CMD_SEND_START, data, &argp->error);

	params->session_len = data->session_len;
	if (copy_to_user((void __user *)(uintptr_t)argp->data, params,
				sizeof(struct kvm_sev_send_start)))
		ret = -EFAULT;

	kfree(data);
	return ret;
}

static int sev_send_start(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_send_start *data;
	struct kvm_sev_send_start params;
	void *amd_certs, *session_data;
	void *pdh_cert, *plat_certs;
	int ret;

	if (!sev_guest(kvm))
		return -ENOTTY;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data,
				sizeof(struct kvm_sev_send_start)))
		return -EFAULT;

	/* if session_len is zero, userspace wants to query the session length */
	if (!params.session_len)
		return __sev_send_start_query_session_length(kvm, argp,
				&params);

	/* some sanity checks */
	if (!params.pdh_cert_uaddr || !params.pdh_cert_len ||
	    !params.session_uaddr || params.session_len > SEV_FW_BLOB_MAX_SIZE)
		return -EINVAL;

	/* allocate the memory to hold the session data blob */
	session_data = kmalloc(params.session_len, GFP_KERNEL_ACCOUNT);
	if (!session_data)
		return -ENOMEM;

	/* copy the certificate blobs from userspace */
	pdh_cert = psp_copy_user_blob(params.pdh_cert_uaddr,
				params.pdh_cert_len);
	if (IS_ERR(pdh_cert)) {
		ret = PTR_ERR(pdh_cert);
		goto e_free_session;
	}

	plat_certs = psp_copy_user_blob(params.plat_certs_uaddr,
				params.plat_certs_len);
	if (IS_ERR(plat_certs)) {
		ret = PTR_ERR(plat_certs);
		goto e_free_pdh;
	}

	amd_certs = psp_copy_user_blob(params.amd_certs_uaddr,
				params.amd_certs_len);
	if (IS_ERR(amd_certs)) {
		ret = PTR_ERR(amd_certs);
		goto e_free_plat_cert;
	}

	data = kzalloc(sizeof(*data), GFP_KERNEL_ACCOUNT);
	if (data == NULL) {
		ret = -ENOMEM;
		goto e_free_amd_cert;
	}

	/* populate the FW SEND_START field with system physical address */
	data->pdh_cert_address = __psp_pa(pdh_cert);
	data->pdh_cert_len = params.pdh_cert_len;
	data->plat_certs_address = __psp_pa(plat_certs);
	data->plat_certs_len = params.plat_certs_len;
	data->amd_certs_address = __psp_pa(amd_certs);
	data->amd_certs_len = params.amd_certs_len;
	data->session_address = __psp_pa(session_data);
	data->session_len = params.session_len;
	data->handle = sev->handle;

	ret = sev_issue_cmd(kvm, SEV_CMD_SEND_START, data, &argp->error);

	if (!ret && copy_to_user((void __user *)(uintptr_t)params.session_uaddr,
			session_data, params.session_len)) {
		ret = -EFAULT;
		goto e_free;
	}

	params.policy = data->policy;
	params.session_len = data->session_len;
	if (copy_to_user((void __user *)(uintptr_t)argp->data, &params,
				sizeof(struct kvm_sev_send_start)))
		ret = -EFAULT;

e_free:
	kfree(data);
e_free_amd_cert:
	kfree(amd_certs);
e_free_plat_cert:
	kfree(plat_certs);
e_free_pdh:
	kfree(pdh_cert);
e_free_session:
	kfree(session_data);
	return ret;
}

/* Userspace wants to query either header or trans length. */
static int
__sev_send_update_data_query_lengths(struct kvm *kvm, struct kvm_sev_cmd *argp,
				     struct kvm_sev_send_update_data *params)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_send_update_data *data;
	int ret;

	data = kzalloc(sizeof(*data), GFP_KERNEL_ACCOUNT);
	if (!data)
		return -ENOMEM;

	data->handle = sev->handle;
	ret = sev_issue_cmd(kvm, SEV_CMD_SEND_UPDATE_DATA, data, &argp->error);

	params->hdr_len = data->hdr_len;
	params->trans_len = data->trans_len;

	if (copy_to_user((void __user *)(uintptr_t)argp->data, params,
			 sizeof(struct kvm_sev_send_update_data)))
		ret = -EFAULT;

	kfree(data);
	return ret;
}

static int sev_send_update_data(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_send_update_data *data;
	struct kvm_sev_send_update_data params;
	void *hdr, *trans_data;
	struct page **guest_page;
	unsigned long n;
	int ret, offset;

	if (!sev_guest(kvm))
		return -ENOTTY;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data,
			sizeof(struct kvm_sev_send_update_data)))
		return -EFAULT;

	/* userspace wants to query either header or trans length */
	if (!params.trans_len || !params.hdr_len)
		return __sev_send_update_data_query_lengths(kvm, argp, &params);

	if (!params.trans_uaddr || !params.guest_uaddr ||
	    !params.guest_len || !params.hdr_uaddr)
		return -EINVAL;

	/* Check if we are crossing the page boundary */
	offset = params.guest_uaddr & (PAGE_SIZE - 1);
	if (params.guest_len > PAGE_SIZE || (params.guest_len + offset) > PAGE_SIZE)
		return -EINVAL;

	/* Pin guest memory */
	guest_page = sev_pin_memory(kvm, params.guest_uaddr & PAGE_MASK,
				    PAGE_SIZE, &n, 0);
	if (IS_ERR(guest_page))
		return PTR_ERR(guest_page);

	/* allocate memory for header and transport buffer */
	ret = -ENOMEM;
	hdr = kmalloc(params.hdr_len, GFP_KERNEL_ACCOUNT);
	if (!hdr)
		goto e_unpin;

	trans_data = kmalloc(params.trans_len, GFP_KERNEL_ACCOUNT);
	if (!trans_data)
		goto e_free_hdr;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		goto e_free_trans_data;

	data->hdr_address = __psp_pa(hdr);
	data->hdr_len = params.hdr_len;
	data->trans_address = __psp_pa(trans_data);
	data->trans_len = params.trans_len;

	/* The SEND_UPDATE_DATA command requires C-bit to be always set. */
	data->guest_address = (page_to_pfn(guest_page[0]) << PAGE_SHIFT) +
				offset;
	data->guest_address |= sev_me_mask;
	data->guest_len = params.guest_len;
	data->handle = sev->handle;

	ret = sev_issue_cmd(kvm, SEV_CMD_SEND_UPDATE_DATA, data, &argp->error);

	if (ret)
		goto e_free;

	/* copy transport buffer to user space */
	if (copy_to_user((void __user *)(uintptr_t)params.trans_uaddr,
			 trans_data, params.trans_len)) {
		ret = -EFAULT;
		goto e_free;
	}

	/* Copy packet header to userspace. */
	if (copy_to_user((void __user *)(uintptr_t)params.hdr_uaddr, hdr,
			 params.hdr_len))
		ret = -EFAULT;

e_free:
	kfree(data);
e_free_trans_data:
	kfree(trans_data);
e_free_hdr:
	kfree(hdr);
e_unpin:
	sev_unpin_memory(kvm, guest_page, n);

	return ret;
}

/* Userspace wants to query either header or trans length. */
static int
__sev_send_update_vmsa_query_lengths(struct kvm *kvm, struct kvm_sev_cmd *argp,
				     struct kvm_sev_send_update_vmsa *params)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_send_update_vmsa *vmsa;
	int ret;

	vmsa = kzalloc(sizeof(*vmsa), GFP_KERNEL_ACCOUNT);
	if (!vmsa)
		return -ENOMEM;

	vmsa->handle = sev->handle;
	ret = sev_issue_cmd(kvm, SEV_CMD_SEND_UPDATE_VMSA, vmsa, &argp->error);

	params->hdr_len = vmsa->hdr_len;
	params->trans_len = vmsa->trans_len;

	if (copy_to_user((void __user *)argp->data, params,
			 sizeof(struct kvm_sev_send_update_vmsa)))
		ret = -EFAULT;

	kfree(vmsa);
	return ret;
}

static int sev_send_update_vmsa(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_send_update_vmsa *vmsa;
	struct kvm_sev_send_update_vmsa params;
	struct kvm_vcpu *vcpu;
	void *hdr, *trans_data;
	int ret;

	if (!sev_es_guest(kvm))
		return -ENOTTY;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data,
			   sizeof(struct kvm_sev_send_update_vmsa)))
		return -EFAULT;

	/* userspace wants to query either header or trans length */
	if (!params.trans_len || !params.hdr_len)
		return __sev_send_update_vmsa_query_lengths(kvm, argp, &params);

	if (!params.trans_uaddr || !params.hdr_uaddr)
		return -EINVAL;

	/* Get the target vcpu */
	vcpu = kvm_get_vcpu_by_id(kvm, params.vcpu_id);
	if (!vcpu) {
		pr_err("%s: invalid vcpu\n", __func__);
		return -EINVAL;
	}

	pr_debug("%s: vcpu (%d)\n", __func__, vcpu->vcpu_id);

	/* allocate memory for header and transport buffer */
	ret = -ENOMEM;
	hdr = kzalloc(params.hdr_len, GFP_KERNEL_ACCOUNT);
	if (!hdr)
		return ret;

	trans_data = kzalloc(params.trans_len, GFP_KERNEL_ACCOUNT);
	if (!trans_data)
		goto e_free_hdr;

	vmsa = kzalloc(sizeof(*vmsa), GFP_KERNEL);
	if (!vmsa)
		goto e_free_trans_data;

	vmsa->hdr_address = __psp_pa(hdr);
	vmsa->hdr_len = params.hdr_len;
	vmsa->trans_address = __psp_pa(trans_data);
	vmsa->trans_len = params.trans_len;

	/* The SEND_UPDATE_VMSA command requires C-bit to be always set. */
	vmsa->guest_address = __pa(to_svm(vcpu)->vmsa) | sev_me_mask;
	vmsa->guest_len = PAGE_SIZE;
	vmsa->handle = sev->handle;

	ret = sev_issue_cmd(kvm, SEV_CMD_SEND_UPDATE_VMSA, vmsa, &argp->error);

	if (ret)
		goto e_free;

	/* copy transport buffer to user space */
	if (copy_to_user((void __user *)(uintptr_t)params.trans_uaddr,
			 trans_data, params.trans_len)) {
		ret = -EFAULT;
		goto e_free;
	}

	/* Copy packet header to userspace. */
	ret = copy_to_user((void __user *)(uintptr_t)params.hdr_uaddr, hdr,
			   params.hdr_len);

e_free:
	kfree(vmsa);
e_free_trans_data:
	kfree(trans_data);
e_free_hdr:
	kfree(hdr);

	return ret;
}

static int sev_send_finish(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_send_finish *data;
	int ret;

	if (!sev_guest(kvm))
		return -ENOTTY;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	data->handle = sev->handle;
	ret = sev_issue_cmd(kvm, SEV_CMD_SEND_FINISH, data, &argp->error);

	kfree(data);
	return ret;
}

static int sev_send_cancel(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_send_cancel *data;
	int ret;

	if (!sev_guest(kvm))
		return -ENOTTY;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	data->handle = sev->handle;
	ret = sev_issue_cmd(kvm, SEV_CMD_SEND_CANCEL, data, &argp->error);

	kfree(data);
	return ret;
}

static int sev_receive_start(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_receive_start *start;
	struct kvm_sev_receive_start params;
	int *error = &argp->error;
	void *session_data;
	void *pdh_data;
	int ret;

	if (!sev_guest(kvm))
		return -ENOTTY;

	/* Get parameter from the userspace */
	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data,
			sizeof(struct kvm_sev_receive_start)))
		return -EFAULT;

	/* some sanity checks */
	if (!params.pdh_uaddr || !params.pdh_len ||
	    !params.session_uaddr || !params.session_len)
		return -EINVAL;

	pdh_data = psp_copy_user_blob(params.pdh_uaddr, params.pdh_len);
	if (IS_ERR(pdh_data))
		return PTR_ERR(pdh_data);

	session_data = psp_copy_user_blob(params.session_uaddr,
			params.session_len);
	if (IS_ERR(session_data)) {
		ret = PTR_ERR(session_data);
		goto e_free_pdh;
	}

	ret = -ENOMEM;
	start = kzalloc(sizeof(*start), GFP_KERNEL);
	if (!start)
		goto e_free_session;

	start->handle = params.handle;
	start->policy = params.policy;
	start->pdh_cert_address = __psp_pa(pdh_data);
	start->pdh_cert_len = params.pdh_len;
	start->session_address = __psp_pa(session_data);
	start->session_len = params.session_len;

	/* create memory encryption context */
	ret = __sev_issue_cmd(argp->sev_fd, SEV_CMD_RECEIVE_START, start,
				error);
	if (ret)
		goto e_free;

	/* Bind ASID to this guest */
	ret = sev_bind_asid(kvm, start->handle, error);
	if (ret) {
		sev_decommission(start->handle);
		goto e_free;
	}

	params.handle = start->handle;
	if (copy_to_user((void __user *)(uintptr_t)argp->data,
			 &params, sizeof(struct kvm_sev_receive_start))) {
		ret = -EFAULT;
		sev_unbind_asid(kvm, start->handle);
		goto e_free;
	}

	sev->handle = start->handle;
	sev->fd = argp->sev_fd;

e_free:
	kfree(start);
e_free_session:
	kfree(session_data);
e_free_pdh:
	kfree(pdh_data);

	return ret;
}

static int sev_receive_update_data(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct kvm_sev_receive_update_data params;
	struct sev_data_receive_update_data *data;
	void *hdr = NULL, *trans = NULL;
	struct page **guest_page;
	unsigned long n;
	int ret, offset;

	if (!sev_guest(kvm))
		return -EINVAL;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data,
			sizeof(struct kvm_sev_receive_update_data)))
		return -EFAULT;

	if (!params.hdr_uaddr || !params.hdr_len ||
	    !params.guest_uaddr || !params.guest_len ||
	    !params.trans_uaddr || !params.trans_len)
		return -EINVAL;

	/* Check if we are crossing the page boundary */
	offset = params.guest_uaddr & (PAGE_SIZE - 1);
	if (params.guest_len > PAGE_SIZE || (params.guest_len + offset) > PAGE_SIZE)
		return -EINVAL;

	hdr = psp_copy_user_blob(params.hdr_uaddr, params.hdr_len);
	if (IS_ERR(hdr))
		return PTR_ERR(hdr);

	trans = psp_copy_user_blob(params.trans_uaddr, params.trans_len);
	if (IS_ERR(trans)) {
		ret = PTR_ERR(trans);
		goto e_free_hdr;
	}

	ret = -ENOMEM;
	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		goto e_free_trans;

	data->hdr_address = __psp_pa(hdr);
	data->hdr_len = params.hdr_len;
	data->trans_address = __psp_pa(trans);
	data->trans_len = params.trans_len;

	/* Pin guest memory */
	guest_page = sev_pin_memory(kvm, params.guest_uaddr & PAGE_MASK,
				    PAGE_SIZE, &n, 1);
	if (IS_ERR(guest_page)) {
		ret = PTR_ERR(guest_page);
		goto e_free;
	}

	/*
	 * Flush (on non-coherent CPUs) before RECEIVE_UPDATE_DATA, the PSP
	 * encrypts the written data with the guest's key, and the cache may
	 * contain dirty, unencrypted data.
	 */
	sev_clflush_pages(guest_page, n);

	/* The RECEIVE_UPDATE_DATA command requires C-bit to be always set. */
	data->guest_address = (page_to_pfn(guest_page[0]) << PAGE_SHIFT) +
				offset;
	data->guest_address |= sev_me_mask;
	data->guest_len = params.guest_len;
	data->handle = sev->handle;

	ret = sev_issue_cmd(kvm, SEV_CMD_RECEIVE_UPDATE_DATA, data,
				&argp->error);

	sev_unpin_memory(kvm, guest_page, n);

e_free:
	kfree(data);
e_free_trans:
	kfree(trans);
e_free_hdr:
	kfree(hdr);

	return ret;
}

static int sev_receive_update_vmsa(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct kvm_sev_receive_update_vmsa params;
	struct sev_data_receive_update_vmsa *vmsa;
	struct kvm_vcpu *vcpu;
	void *hdr = NULL, *trans = NULL;
	int ret;

	if (!sev_es_guest(kvm))
		return -ENOTTY;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data,
			   sizeof(struct kvm_sev_receive_update_vmsa)))
		return -EFAULT;

	if (!params.hdr_uaddr || !params.hdr_len ||
	    !params.trans_uaddr || !params.trans_len)
		return -EINVAL;

	/* Get the target vcpu */
	vcpu = kvm_get_vcpu_by_id(kvm, params.vcpu_id);
	if (!vcpu) {
		pr_err("%s: invalid vcpu\n", __func__);
		return -EINVAL;
	}

	pr_debug("%s: vcpu (%d)\n", __func__, vcpu->vcpu_id);

	hdr = psp_copy_user_blob(params.hdr_uaddr, params.hdr_len);
	if (IS_ERR(hdr))
		return PTR_ERR(hdr);

	trans = psp_copy_user_blob(params.trans_uaddr, params.trans_len);
	if (IS_ERR(trans)) {
		ret = PTR_ERR(trans);
		goto e_free_hdr;
	}

	ret = -ENOMEM;
	vmsa = kzalloc(sizeof(*vmsa), GFP_KERNEL);
	if (!vmsa)
		goto e_free_trans;

	vmsa->hdr_address = __psp_pa(hdr);
	vmsa->hdr_len = params.hdr_len;
	vmsa->trans_address = __psp_pa(trans);
	vmsa->trans_len = params.trans_len;

	/*
	 * Flush before RECEIVE_UPDATE_VMSA, the PSP encrypts the
	 * written VMSA memory content with the guest's key), and
	 * the cache may contain dirty, unencrypted data.
	 */
	clflush_cache_range(to_svm(vcpu)->vmsa, PAGE_SIZE);

	/* The RECEIVE_UPDATE_VMSA command requires C-bit to be always set. */
	vmsa->guest_address = __pa(to_svm(vcpu)->vmsa) | sev_me_mask;
	vmsa->guest_len = PAGE_SIZE;
	vmsa->handle = sev->handle;

	ret = sev_issue_cmd(kvm, SEV_CMD_RECEIVE_UPDATE_VMSA, vmsa, &argp->error);

	if (!ret)
		vcpu->arch.guest_state_protected = true;

	kfree(vmsa);
e_free_trans:
	kfree(trans);
e_free_hdr:
	kfree(hdr);

	return ret;
}

static int sev_receive_finish(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_receive_finish *data;
	int ret;

	if (!sev_guest(kvm))
		return -ENOTTY;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	data->handle = sev->handle;
	ret = sev_issue_cmd(kvm, SEV_CMD_RECEIVE_FINISH, data, &argp->error);

	kfree(data);
	return ret;
}

/*--1024--1023--1024--1023--*/
#define TRANS_MEMPOOL_1ST_BLOCK_OFFSET		0
#define TRANS_MEMPOOL_2ND_BLOCK_OFFSET		(1024 << PAGE_SHIFT)
#define TRANS_MEMPOOL_3RD_BLOCK_OFFSET		(2047 << PAGE_SHIFT)
#define TRANS_MEMPOOL_4TH_BLOCK_OFFSET		(3071 << PAGE_SHIFT)
#define TRANS_MEMPOOL_BLOCKS_MAX_OFFSET		(4094 << PAGE_SHIFT)
#define TRANS_MEMPOOL_BLOCK_NUM			4
#define TRANS_MEMPOOL_BLOCK_SIZE		(1024 * PAGE_SIZE)

static size_t g_mempool_offset;
void *g_trans_mempool[TRANS_MEMPOOL_BLOCK_NUM] = { 0, };

static void reset_mempool_offset(void)
{
	g_mempool_offset = 0;
}

static int alloc_trans_mempool(void)
{
	int i;

	for (i = 0; i < TRANS_MEMPOOL_BLOCK_NUM; i++) {
		WARN_ONCE(g_trans_mempool[i],
			  "CSV: g_trans_mempool[%d] was tainted\n", i);

		g_trans_mempool[i] = kzalloc(TRANS_MEMPOOL_BLOCK_SIZE, GFP_KERNEL);
		if (!g_trans_mempool[i])
			goto free_trans_mempool;
	}

	g_mempool_offset = 0;
	return 0;

free_trans_mempool:
	for (i = 0; i < TRANS_MEMPOOL_BLOCK_NUM; i++) {
		kfree(g_trans_mempool[i]);
		g_trans_mempool[i] = NULL;
	}

	return -ENOMEM;
}

static void free_trans_mempool(void)
{
	int i;

	for (i = 0; i < TRANS_MEMPOOL_BLOCK_NUM; i++) {
		kfree(g_trans_mempool[i]);
		g_trans_mempool[i] = NULL;
	}

	g_mempool_offset = 0;
}

static void __maybe_unused *get_trans_data_from_mempool(size_t size)
{
	void *trans = NULL;
	char *trans_data = NULL;
	int i;
	size_t offset;

	if (g_mempool_offset < TRANS_MEMPOOL_2ND_BLOCK_OFFSET) {
		i = 0;
		offset = g_mempool_offset - TRANS_MEMPOOL_1ST_BLOCK_OFFSET;
	} else if (g_mempool_offset < TRANS_MEMPOOL_3RD_BLOCK_OFFSET) {
		i = 1;
		offset = g_mempool_offset - TRANS_MEMPOOL_2ND_BLOCK_OFFSET;
	} else if (g_mempool_offset < TRANS_MEMPOOL_4TH_BLOCK_OFFSET) {
		i = 2;
		offset = g_mempool_offset - TRANS_MEMPOOL_3RD_BLOCK_OFFSET;
	} else if (g_mempool_offset < TRANS_MEMPOOL_BLOCKS_MAX_OFFSET) {
		i = 3;
		offset = g_mempool_offset - TRANS_MEMPOOL_4TH_BLOCK_OFFSET;
	} else {
		pr_err("CSV: mempool is full (offset: %lu)\n", g_mempool_offset);
		return NULL;
	}

	trans_data = (char *)g_trans_mempool[i];
	trans = &trans_data[offset];
	g_mempool_offset += size;

	return trans;
}

static int csv_ringbuf_infos_free(struct kvm *kvm,
				  struct csv_ringbuf_infos *ringbuf_infos)
{
	int i;

	for (i = 0; i < ringbuf_infos->num; i++) {
		struct csv_ringbuf_info_item *item = ringbuf_infos->item[i];

		if (item) {
			if (item->data_vaddr)
				kfree((void *)item->data_vaddr);

			if (item->hdr_vaddr)
				kfree((void *)item->hdr_vaddr);

			if (item->pages)
				sev_unpin_memory(kvm, item->pages, item->n);

			kfree(item);

			ringbuf_infos->item[i] = NULL;
		}
	}

	return 0;
}

static int
sev_send_update_data_to_ringbuf(struct kvm *kvm,
				int prio,
				uintptr_t data_ptr,
				struct csv_ringbuf_infos *ringbuf_infos)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_send_update_data *data;
	struct kvm_sev_send_update_data params;
	struct csv_ringbuf_info_item *item;
	void *hdr, *trans_data;
	struct page **guest_page;
	unsigned long n;
	int ret, offset;

	if (!sev_guest(kvm))
		return -ENOTTY;

	if (copy_from_user(&params, (void __user *)data_ptr,
			sizeof(struct kvm_sev_send_update_data)))
		return -EFAULT;

	/*
	 * userspace shouldn't query either header or trans length in ringbuf
	 * mode.
	 */
	if (!params.trans_len || !params.hdr_len)
		return -EINVAL;

	if (!params.trans_uaddr || !params.guest_uaddr ||
	    !params.guest_len || !params.hdr_uaddr)
		return -EINVAL;

	/* Check if we are crossing the page boundary */
	offset = params.guest_uaddr & (PAGE_SIZE - 1);
	if (params.guest_len > PAGE_SIZE || (params.guest_len + offset) > PAGE_SIZE)
		return -EINVAL;

	/* Pin guest memory */
	guest_page = sev_pin_memory(kvm, params.guest_uaddr & PAGE_MASK,
				    PAGE_SIZE, &n, 0);
	if (IS_ERR(guest_page))
		return PTR_ERR(guest_page);

	/* Allocate memory for header and transport buffer */
	ret = -ENOMEM;
	hdr = kmalloc(params.hdr_len, GFP_KERNEL);
	if (!hdr)
		goto e_unpin;

	trans_data = get_trans_data_from_mempool(params.trans_len);
	if (!trans_data)
		goto e_free_hdr;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		goto e_free_hdr;

	data->hdr_address = __psp_pa(hdr);
	data->hdr_len = params.hdr_len;
	data->trans_address = __psp_pa(trans_data);
	data->trans_len = params.trans_len;

	/* The SEND_UPDATE_DATA command requires C-bit to be always set. */
	data->guest_address = (page_to_pfn(guest_page[0]) << PAGE_SHIFT) +
				offset;
	data->guest_address |= sev_me_mask;
	data->guest_len = params.guest_len;
	data->handle = sev->handle;

	ret = csv_fill_cmd_queue(prio, SEV_CMD_SEND_UPDATE_DATA, data, 0);
	if (ret)
		goto e_free;

	/*
	 * Create item to save page info and pointer, which will be freed
	 * in function csv_command_batch because it will be used after PSP
	 * return for copy_to_user.
	 */
	item = kzalloc(sizeof(*item), GFP_KERNEL);
	if (!item) {
		ret = -ENOMEM;
		goto e_free;
	}

	item->pages = guest_page;
	item->n = n;
	item->hdr_vaddr = (uintptr_t)hdr;
	item->trans_vaddr = (uintptr_t)trans_data;
	item->data_vaddr = (uintptr_t)data;
	item->hdr_uaddr = params.hdr_uaddr;
	item->trans_uaddr = params.trans_uaddr;
	item->hdr_len = params.hdr_len;
	item->trans_len = params.trans_len;

	ringbuf_infos->item[ringbuf_infos->num] = item;
	ringbuf_infos->num++;

	/* copy to ring buffer success, data freed after commands completed */
	goto finish;

e_free:
	kfree(data);
e_free_hdr:
	kfree(hdr);
e_unpin:
	sev_unpin_memory(kvm, guest_page, n);

finish:
	return ret;
}

static int
sev_send_update_data_copy_to_user(struct kvm *kvm,
				  struct csv_ringbuf_infos *ringbuf_infos)
{
	int i, ret = 0;

	for (i = 0; i < ringbuf_infos->num; i++) {
		struct csv_ringbuf_info_item *item = ringbuf_infos->item[i];

		/* copy transport buffer to user space */
		if (copy_to_user((void __user *)item->trans_uaddr,
				 (void *)item->trans_vaddr, item->trans_len)) {
			ret = -EFAULT;
			break;
		}

		/* Copy packet header to userspace. */
		if (copy_to_user((void __user *)item->hdr_uaddr,
				 (void *)item->hdr_vaddr, item->hdr_len)) {
			ret = -EFAULT;
			break;
		}
	}

	return ret;
}

static int
sev_receive_update_data_to_ringbuf(struct kvm *kvm,
				   int prio,
				   uintptr_t data_ptr,
				   struct csv_ringbuf_infos *ringbuf_infos)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct kvm_sev_receive_update_data params;
	struct sev_data_receive_update_data *data;
	struct csv_ringbuf_info_item *item;
	void *hdr = NULL, *trans = NULL;
	struct page **guest_page;
	unsigned long n;
	int ret, offset;

	if (!sev_guest(kvm))
		return -EINVAL;

	if (copy_from_user(&params, (void __user *)data_ptr,
			sizeof(struct kvm_sev_receive_update_data)))
		return -EFAULT;

	if (!params.hdr_uaddr || !params.hdr_len ||
	    !params.guest_uaddr || !params.guest_len ||
	    !params.trans_uaddr || !params.trans_len)
		return -EINVAL;

	/* Check if we are crossing the page boundary */
	offset = params.guest_uaddr & (PAGE_SIZE - 1);
	if (params.guest_len > PAGE_SIZE || (params.guest_len + offset) > PAGE_SIZE)
		return -EINVAL;

	hdr = psp_copy_user_blob(params.hdr_uaddr, params.hdr_len);
	if (IS_ERR(hdr))
		return PTR_ERR(hdr);

	ret = -ENOMEM;
	trans = get_trans_data_from_mempool(params.trans_len);
	if (!trans)
		goto e_free_hdr;

	if (copy_from_user(trans, (void __user *)params.trans_uaddr,
			params.trans_len)) {
		ret = -EFAULT;
		goto e_free_hdr;
	}

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		goto e_free_hdr;

	data->hdr_address = __psp_pa(hdr);
	data->hdr_len = params.hdr_len;
	data->trans_address = __psp_pa(trans);
	data->trans_len = params.trans_len;

	/* Pin guest memory */
	guest_page = sev_pin_memory(kvm, params.guest_uaddr & PAGE_MASK,
				    PAGE_SIZE, &n, 1);
	if (IS_ERR(guest_page)) {
		ret = PTR_ERR(guest_page);
		goto e_free;
	}

	/*
	 * Flush (on non-coherent CPUs) before RECEIVE_UPDATE_DATA, the PSP
	 * encrypts the written data with the guest's key, and the cache may
	 * contain dirty, unencrypted data.
	 */
	sev_clflush_pages(guest_page, n);

	/* The RECEIVE_UPDATE_DATA command requires C-bit to be always set. */
	data->guest_address = (page_to_pfn(guest_page[0]) << PAGE_SHIFT) +
				offset;
	data->guest_address |= sev_me_mask;
	data->guest_len = params.guest_len;
	data->handle = sev->handle;

	ret = csv_fill_cmd_queue(prio, SEV_CMD_RECEIVE_UPDATE_DATA, data, 0);

	if (ret)
		goto e_unpin;

	/*
	 * Create item to save page info and pointer, whitch will be freed
	 * in function csv_command_batch because it will be used after PSP
	 * return for copy_to_user.
	 */
	item = kzalloc(sizeof(*item), GFP_KERNEL);
	if (!item) {
		ret = -ENOMEM;
		goto e_unpin;
	}

	item->pages = guest_page;
	item->n = n;
	item->hdr_vaddr = (uintptr_t)hdr;
	item->trans_vaddr = (uintptr_t)trans;
	item->data_vaddr = (uintptr_t)data;

	ringbuf_infos->item[ringbuf_infos->num] = item;
	ringbuf_infos->num++;

	/* copy to ring buffer success, data freed after commands completed */
	goto finish;

e_unpin:
	sev_unpin_memory(kvm, guest_page, n);
e_free:
	kfree(data);
e_free_hdr:
	kfree(hdr);

finish:
	return ret;
}

typedef int (*csv_ringbuf_input_fn)(struct kvm *kvm, int prio,
				    uintptr_t data_ptr,
				    struct csv_ringbuf_infos *ringbuf_infos);
typedef int (*csv_ringbuf_output_fn)(struct kvm *kvm,
				     struct csv_ringbuf_infos *ringbuf_infos);

static int get_cmd_helpers(__u32 cmd,
			   csv_ringbuf_input_fn *to_ringbuf_fn,
			   csv_ringbuf_output_fn *to_user_fn)
{
	int ret = 0;

	/* copy commands to ring buffer*/
	switch (cmd) {
	case KVM_SEV_SEND_UPDATE_DATA:
		*to_ringbuf_fn = sev_send_update_data_to_ringbuf;
		*to_user_fn = sev_send_update_data_copy_to_user;
		break;
	case KVM_SEV_RECEIVE_UPDATE_DATA:
		*to_ringbuf_fn = sev_receive_update_data_to_ringbuf;
		*to_user_fn = NULL;
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

static int csv_command_batch(struct kvm *kvm, struct kvm_sev_cmd *argp)
{
	int ret;
	struct kvm_csv_command_batch params;
	uintptr_t node_addr;
	struct csv_ringbuf_infos *ringbuf_infos;
	csv_ringbuf_input_fn csv_cmd_to_ringbuf_fn = NULL;
	csv_ringbuf_output_fn csv_copy_to_user_fn = NULL;
	int prio = CSV_COMMAND_PRIORITY_HIGH;

	if (!sev_guest(kvm))
		return -ENOTTY;

	if (copy_from_user(&params, (void __user *)(uintptr_t)argp->data,
			sizeof(struct kvm_csv_command_batch)))
		return -EFAULT;

	/* return directly if node list is NULL */
	if (!params.csv_batch_list_uaddr)
		return 0;

	/* ring buffer init */
	if (csv_ring_buffer_queue_init())
		return -EINVAL;

	if (get_cmd_helpers(params.command_id,
			    &csv_cmd_to_ringbuf_fn, &csv_copy_to_user_fn)) {
		ret = -EINVAL;
		goto err_free_ring_buffer;
	}

	ringbuf_infos = kzalloc(sizeof(*ringbuf_infos), GFP_KERNEL);
	if (!ringbuf_infos) {
		ret = -ENOMEM;
		goto err_free_ring_buffer;
	}

	node_addr = (uintptr_t)params.csv_batch_list_uaddr;
	while (node_addr) {
		struct kvm_csv_batch_list_node node;

		if (copy_from_user(&node, (void __user *)node_addr,
				sizeof(struct kvm_csv_batch_list_node))) {
			ret = -EFAULT;
			goto err_free_ring_buffer_infos_items;
		}

		if (ringbuf_infos->num > SVM_RING_BUFFER_MAX) {
			pr_err("%s: ring num is too large:%d, cmd:0x%x\n",
				__func__, ringbuf_infos->num, params.command_id);

			ret = -EINVAL;
			goto err_free_ring_buffer_infos_items;
		}

		if (csv_cmd_to_ringbuf_fn(kvm, prio,
					  (uintptr_t)node.cmd_data_addr,
					  ringbuf_infos)) {
			ret = -EFAULT;
			goto err_free_ring_buffer_infos_items;
		}

		/* 1st half set to HIGH queue, 2nd half set to LOW queue */
		if (ringbuf_infos->num == SVM_RING_BUFFER_MAX / 2)
			prio = CSV_COMMAND_PRIORITY_LOW;

		node_addr = node.next_cmd_addr;
	}

	/* ring buffer process */
	ret = csv_issue_ringbuf_cmds(kvm, &argp->error);
	if (ret)
		goto err_free_ring_buffer_infos_items;

	ret = csv_check_stat_queue_status(&argp->error);
	if (ret)
		goto err_free_ring_buffer_infos_items;

	if (csv_copy_to_user_fn && csv_copy_to_user_fn(kvm, ringbuf_infos)) {
		ret = -EFAULT;
		goto err_free_ring_buffer_infos_items;
	}

err_free_ring_buffer_infos_items:
	csv_ringbuf_infos_free(kvm, ringbuf_infos);
	kfree(ringbuf_infos);
	reset_mempool_offset();

err_free_ring_buffer:
	csv_ring_buffer_queue_free();

	return ret;
}

int svm_mem_enc_op(struct kvm *kvm, void __user *argp)
{
	struct kvm_sev_cmd sev_cmd;
	int r;

	if (!svm_sev_enabled() || !sev)
		return -ENOTTY;

	if (!argp)
		return 0;

	if (copy_from_user(&sev_cmd, argp, sizeof(struct kvm_sev_cmd)))
		return -EFAULT;

	mutex_lock(&kvm->lock);

	switch (sev_cmd.id) {
	case KVM_SEV_ES_INIT:
		if (!sev_es) {
			r = -ENOTTY;
			goto out;
		}
		fallthrough;
	case KVM_SEV_INIT:
		r = sev_guest_init(kvm, &sev_cmd);
		break;
	case KVM_SEV_LAUNCH_START:
		r = sev_launch_start(kvm, &sev_cmd);
		break;
	case KVM_SEV_LAUNCH_UPDATE_DATA:
		r = sev_launch_update_data(kvm, &sev_cmd);
		break;
	case KVM_SEV_LAUNCH_UPDATE_VMSA:
		r = sev_launch_update_vmsa(kvm, &sev_cmd);
		break;
	case KVM_SEV_LAUNCH_MEASURE:
		r = sev_launch_measure(kvm, &sev_cmd);
		break;
	case KVM_SEV_LAUNCH_FINISH:
		r = sev_launch_finish(kvm, &sev_cmd);
		break;
	case KVM_SEV_GUEST_STATUS:
		r = sev_guest_status(kvm, &sev_cmd);
		break;
	case KVM_SEV_DBG_DECRYPT:
		r = sev_dbg_crypt(kvm, &sev_cmd, true);
		break;
	case KVM_SEV_DBG_ENCRYPT:
		r = sev_dbg_crypt(kvm, &sev_cmd, false);
		break;
	case KVM_SEV_LAUNCH_SECRET:
		r = sev_launch_secret(kvm, &sev_cmd);
		break;
	case KVM_SEV_GET_ATTESTATION_REPORT:
		r = sev_get_attestation_report(kvm, &sev_cmd);
		break;
	case KVM_SEV_SEND_START:
		r = sev_send_start(kvm, &sev_cmd);
		break;
	case KVM_SEV_SEND_UPDATE_DATA:
		r = sev_send_update_data(kvm, &sev_cmd);
		break;
	case KVM_SEV_SEND_UPDATE_VMSA:
		if (boot_cpu_data.x86_vendor == X86_VENDOR_HYGON)
			r = sev_send_update_vmsa(kvm, &sev_cmd);
		else
			r = -EINVAL;
		break;
	case KVM_SEV_SEND_FINISH:
		r = sev_send_finish(kvm, &sev_cmd);
		break;
	case KVM_SEV_SEND_CANCEL:
		r = sev_send_cancel(kvm, &sev_cmd);
		break;
	case KVM_SEV_RECEIVE_START:
		r = sev_receive_start(kvm, &sev_cmd);
		break;
	case KVM_SEV_RECEIVE_UPDATE_DATA:
		r = sev_receive_update_data(kvm, &sev_cmd);
		break;
	case KVM_SEV_RECEIVE_UPDATE_VMSA:
		if (boot_cpu_data.x86_vendor == X86_VENDOR_HYGON)
			r = sev_receive_update_vmsa(kvm, &sev_cmd);
		else
			r = -EINVAL;
		break;
	case KVM_SEV_RECEIVE_FINISH:
		r = sev_receive_finish(kvm, &sev_cmd);
		break;
	case KVM_CSV_COMMAND_BATCH:
		if (boot_cpu_data.x86_vendor == X86_VENDOR_HYGON) {
			mutex_lock(&csv_cmd_batch_mutex);
			r = csv_command_batch(kvm, &sev_cmd);
			mutex_unlock(&csv_cmd_batch_mutex);
			break;
		}
		fallthrough;
	default:
		r = -EINVAL;
		goto out;
	}

	if (copy_to_user(argp, &sev_cmd, sizeof(struct kvm_sev_cmd)))
		r = -EFAULT;

out:
	mutex_unlock(&kvm->lock);
	return r;
}

int sev_vm_attestation(struct kvm *kvm, unsigned long gpa, unsigned long len)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct sev_data_attestation_report *data = NULL;
	struct page **pages;
	unsigned long guest_uaddr, n;
	int ret = 0, offset, error;

	if (!sev_guest(kvm) || (boot_cpu_data.x86_vendor != X86_VENDOR_HYGON))
		return -ENOTTY;

	/*
	 * The physical address of guest must valid and page aligned, and
	 * the length of guest memory region must be page size aligned.
	 */
	if (!gpa || (gpa & ~PAGE_MASK) || (len & ~PAGE_MASK)) {
		pr_err("invalid guest address or length\n");
		return -EFAULT;
	}

	guest_uaddr = gfn_to_hva(kvm, gpa_to_gfn(gpa));
	pages = sev_pin_memory(kvm, guest_uaddr, len, &n, 1);
	if (IS_ERR(pages))
		return PTR_ERR(pages);

	/*
	 * The attestation report must be copied into contiguous memory region,
	 * lets verify that userspace memory pages are contiguous before we
	 * issue commmand.
	 */
	if (get_num_contig_pages(0, pages, n) != n) {
		ret = -EINVAL;
		goto e_unpin_memory;
	}

	ret = -ENOMEM;
	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		goto e_unpin_memory;

	/* sev_vm_mnonce indicates attestation request from guest */
	if (sizeof(sev_vm_mnonce) >= sizeof(data->mnonce)) {
		ret = -EINVAL;
		goto e_free;
	}

	memcpy(data->mnonce, sev_vm_mnonce, sizeof(sev_vm_mnonce));

	offset = guest_uaddr & (PAGE_SIZE - 1);
	data->address = __sme_page_pa(pages[0]) + offset;
	data->len = len;

	data->handle = sev->handle;
	ret = sev_issue_cmd(kvm, SEV_CMD_ATTESTATION_REPORT, data, &error);

	if (ret)
		pr_err("vm attestation ret %#x, error %#x\n", ret, error);

e_free:
	kfree(data);
e_unpin_memory:
	sev_unpin_memory(kvm, pages, n);
	return ret;
}

int svm_register_enc_region(struct kvm *kvm,
			    struct kvm_enc_region *range)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct enc_region *region;
	int ret = 0;

	if (!sev_guest(kvm))
		return -ENOTTY;

	if (range->addr > ULONG_MAX || range->size > ULONG_MAX)
		return -EINVAL;

	region = kzalloc(sizeof(*region), GFP_KERNEL_ACCOUNT);
	if (!region)
		return -ENOMEM;

	mutex_lock(&kvm->lock);
	region->pages = sev_pin_memory(kvm, range->addr, range->size, &region->npages, 1);
	if (IS_ERR(region->pages)) {
		ret = PTR_ERR(region->pages);
		mutex_unlock(&kvm->lock);
		goto e_free;
	}

	region->uaddr = range->addr;
	region->size = range->size;

	list_add_tail(&region->list, &sev->regions_list);
	mutex_unlock(&kvm->lock);

	/*
	 * The guest may change the memory encryption attribute from C=0 -> C=1
	 * or vice versa for this memory range. Lets make sure caches are
	 * flushed to ensure that guest data gets written into memory with
	 * correct C-bit.
	 */
	sev_clflush_pages(region->pages, region->npages);

	return ret;

e_free:
	kfree(region);
	return ret;
}

static struct enc_region *
find_enc_region(struct kvm *kvm, struct kvm_enc_region *range)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct list_head *head = &sev->regions_list;
	struct enc_region *i;

	list_for_each_entry(i, head, list) {
		if (i->uaddr == range->addr &&
		    i->size == range->size)
			return i;
	}

	return NULL;
}

static void __unregister_enc_region_locked(struct kvm *kvm,
					   struct enc_region *region)
{
	sev_unpin_memory(kvm, region->pages, region->npages);
	list_del(&region->list);
	kfree(region);
}

int svm_unregister_enc_region(struct kvm *kvm,
			      struct kvm_enc_region *range)
{
	struct enc_region *region;
	int ret;

	mutex_lock(&kvm->lock);

	if (!sev_guest(kvm)) {
		ret = -ENOTTY;
		goto failed;
	}

	region = find_enc_region(kvm, range);
	if (!region) {
		ret = -EINVAL;
		goto failed;
	}

	/*
	 * Ensure that all guest tagged cache entries are flushed before
	 * releasing the pages back to the system for use. CLFLUSH will
	 * not do this, so issue a WBINVD.
	 */
	wbinvd_on_all_cpus();

	__unregister_enc_region_locked(kvm, region);

	mutex_unlock(&kvm->lock);
	return 0;

failed:
	mutex_unlock(&kvm->lock);
	return ret;
}

void sev_vm_destroy(struct kvm *kvm)
{
	struct kvm_sev_info *sev = &to_kvm_svm(kvm)->sev_info;
	struct list_head *head = &sev->regions_list;
	struct list_head *pos, *q;

	if (!sev_guest(kvm))
		return;

	mutex_lock(&kvm->lock);

	/*
	 * Ensure that all guest tagged cache entries are flushed before
	 * releasing the pages back to the system for use. CLFLUSH will
	 * not do this, so issue a WBINVD.
	 */
	wbinvd_on_all_cpus();

	/*
	 * if userspace was terminated before unregistering the memory regions
	 * then lets unpin all the registered memory.
	 */
	if (!list_empty(head)) {
		list_for_each_safe(pos, q, head) {
			__unregister_enc_region_locked(kvm,
				list_entry(pos, struct enc_region, list));
			cond_resched();
		}
	}

	mutex_unlock(&kvm->lock);

	sev_unbind_asid(kvm, sev->handle);
	sev_asid_free(sev->asid);
}

void __init sev_set_cpu_caps(void)
{
	if (!sev)
		kvm_cpu_cap_clear(X86_FEATURE_SEV);
	if (!sev_es)
		kvm_cpu_cap_clear(X86_FEATURE_SEV_ES);
}

void __init sev_hardware_setup(void)
{
	unsigned int eax, ebx, ecx, edx;
	bool sev_es_supported = false;
	bool sev_supported = false;

	/*
	 * SEV must obviously be supported in hardware.  Sanity check that the
	 * CPU supports decode assists, which is mandatory for SEV guests to
	 * support instruction emulation.
	 */
	if (!boot_cpu_has(X86_FEATURE_SEV) ||
	    WARN_ON_ONCE(!boot_cpu_has(X86_FEATURE_DECODEASSISTS)))
		goto out;

	/* Retrieve SEV CPUID information */
	cpuid(0x8000001f, &eax, &ebx, &ecx, &edx);

	/* Set encryption bit location for SEV-ES guests */
	sev_enc_bit = ebx & 0x3f;

	/* Maximum number of encrypted guests supported simultaneously */
	max_sev_asid = ecx;

	if (!svm_sev_enabled())
		goto out;

	/* Minimum ASID value that should be used for SEV guest */
	min_sev_asid = edx;
	sev_me_mask = 1UL << (ebx & 0x3f);

	/* Initialize SEV ASID bitmaps */
	sev_asid_bitmap = bitmap_zalloc(max_sev_asid, GFP_KERNEL);
	if (!sev_asid_bitmap)
		goto out;

	sev_reclaim_asid_bitmap = bitmap_zalloc(max_sev_asid, GFP_KERNEL);
	if (!sev_reclaim_asid_bitmap) {
		bitmap_free(sev_asid_bitmap);
		sev_asid_bitmap = NULL;
		goto out;
	}

	if (boot_cpu_data.x86_vendor == X86_VENDOR_HYGON) {
		if (alloc_trans_mempool()) {
			bitmap_free(sev_asid_bitmap);
			sev_asid_bitmap = NULL;
			bitmap_free(sev_reclaim_asid_bitmap);
			sev_reclaim_asid_bitmap = NULL;
			goto out;
		}
		pr_info("CSV supported: %u ASIDs\n",
			max_sev_asid - min_sev_asid + 1);
	} else {
		pr_info("SEV supported: %u ASIDs\n",
			max_sev_asid - min_sev_asid + 1);
	}
	sev_supported = true;

	/* SEV-ES support requested? */
	if (!sev_es)
		goto out;

	/* Does the CPU support SEV-ES? */
	if (!boot_cpu_has(X86_FEATURE_SEV_ES))
		goto out;

	/*
	 * The ASIDs from 1 to max_sev_asid are available for hygon CSV2
	 * guest.
	 */
	if (boot_cpu_data.x86_vendor == X86_VENDOR_HYGON) {
		pr_info("CSV2 supported: %u ASIDs\n", max_sev_asid);
		sev_es_supported = true;
		goto out;
	}

	/* Has the system been allocated ASIDs for SEV-ES? */
	if (min_sev_asid == 1)
		goto out;

	pr_info("SEV-ES supported: %u ASIDs\n", min_sev_asid - 1);
	sev_es_supported = true;

out:
	sev = sev_supported;
	sev_es = sev_es_supported;
}

void sev_hardware_teardown(void)
{
	if (!svm_sev_enabled())
		return;

	/* No need to take sev_bitmap_lock, all VMs have been destroyed. */
	sev_flush_asids(0, max_sev_asid);

	if (boot_cpu_data.x86_vendor == X86_VENDOR_HYGON)
		free_trans_mempool();

	bitmap_free(sev_asid_bitmap);
	bitmap_free(sev_reclaim_asid_bitmap);
}

void sev_guest_memory_reclaimed(struct kvm *kvm)
{
	if (!sev_guest(kvm))
		return;

	wbinvd_on_all_cpus();
}

/*
 * Pages used by hardware to hold guest encrypted state must be flushed before
 * returning them to the system.
 */
static void sev_flush_encrypted_page(struct kvm_vcpu *vcpu, void *va)
{
	int asid = to_kvm_svm(vcpu->kvm)->sev_info.asid;

	/*
	 * Note!  The address must be a kernel address, as regular page walk
	 * checks are performed by VM_PAGE_FLUSH, i.e. operating on a user
	 * address is non-deterministic and unsafe.  This function deliberately
	 * takes a pointer to deter passing in a user address.
	 */
	unsigned long addr = (unsigned long)va;

	/*
	 * If CPU enforced cache coherency for encrypted mappings of the
	 * same physical page is supported, use CLFLUSHOPT instead. NOTE: cache
	 * flush is still needed in order to work properly with DMA devices.
	 */
	if (boot_cpu_has(X86_FEATURE_SME_COHERENT)) {
		clflush_cache_range(va, PAGE_SIZE);
		return;
	}

	/*
	 * VM Page Flush takes a host virtual address and a guest ASID.  Fall
	 * back to WBINVD if this faults so as not to make any problems worse
	 * by leaving stale encrypted data in the cache.
	 */
	if (WARN_ON_ONCE(wrmsrl_safe(MSR_AMD64_VM_PAGE_FLUSH, addr | asid)))
		goto do_wbinvd;

	return;

do_wbinvd:
	wbinvd_on_all_cpus();
}

void sev_free_vcpu(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm;

	if (!sev_es_guest(vcpu->kvm))
		return;

	svm = to_svm(vcpu);

	if (vcpu->arch.guest_state_protected)
		sev_flush_encrypted_page(vcpu, svm->vmsa);

	__free_page(virt_to_page(svm->vmsa));

	if (svm->ghcb_sa_free)
		kvfree(svm->ghcb_sa);

	__free_page(virt_to_page(svm->reset_vmsa));
}

static void dump_ghcb(struct vcpu_svm *svm)
{
	struct ghcb *ghcb = svm->ghcb;
	unsigned int nbits;

	/* Re-use the dump_invalid_vmcb module parameter */
	if (!dump_invalid_vmcb) {
		pr_warn_ratelimited("set kvm_amd.dump_invalid_vmcb=1 to dump internal KVM state.\n");
		return;
	}

	nbits = sizeof(ghcb->save.valid_bitmap) * 8;

	pr_err("GHCB (GPA=%016llx):\n", svm->vmcb->control.ghcb_gpa);
	pr_err("%-20s%016llx is_valid: %u\n", "sw_exit_code",
	       ghcb->save.sw_exit_code, ghcb_sw_exit_code_is_valid(ghcb));
	pr_err("%-20s%016llx is_valid: %u\n", "sw_exit_info_1",
	       ghcb->save.sw_exit_info_1, ghcb_sw_exit_info_1_is_valid(ghcb));
	pr_err("%-20s%016llx is_valid: %u\n", "sw_exit_info_2",
	       ghcb->save.sw_exit_info_2, ghcb_sw_exit_info_2_is_valid(ghcb));
	pr_err("%-20s%016llx is_valid: %u\n", "sw_scratch",
	       ghcb->save.sw_scratch, ghcb_sw_scratch_is_valid(ghcb));
	pr_err("%-20s%*pb\n", "valid_bitmap", nbits, ghcb->save.valid_bitmap);
}

static void sev_es_sync_to_ghcb(struct vcpu_svm *svm)
{
	struct kvm_vcpu *vcpu = &svm->vcpu;
	struct ghcb *ghcb = svm->ghcb;

	/*
	 * The GHCB protocol so far allows for the following data
	 * to be returned:
	 *   GPRs RAX, RBX, RCX, RDX
	 *
	 * Copy their values, even if they may not have been written during the
	 * VM-Exit.  It's the guest's responsibility to not consume random data.
	 */
	ghcb_set_rax(ghcb, vcpu->arch.regs[VCPU_REGS_RAX]);
	ghcb_set_rbx(ghcb, vcpu->arch.regs[VCPU_REGS_RBX]);
	ghcb_set_rcx(ghcb, vcpu->arch.regs[VCPU_REGS_RCX]);
	ghcb_set_rdx(ghcb, vcpu->arch.regs[VCPU_REGS_RDX]);
}

static void sev_es_sync_from_ghcb(struct vcpu_svm *svm)
{
	struct vmcb_control_area *control = &svm->vmcb->control;
	struct kvm_vcpu *vcpu = &svm->vcpu;
	struct ghcb *ghcb = svm->ghcb;
	u64 exit_code;

	/*
	 * The GHCB protocol so far allows for the following data
	 * to be supplied:
	 *   GPRs RAX, RBX, RCX, RDX
	 *   XCR0
	 *   CPL
	 *
	 * VMMCALL allows the guest to provide extra registers. KVM also
	 * expects RSI for hypercalls, so include that, too.
	 *
	 * Copy their values to the appropriate location if supplied.
	 */
	memset(vcpu->arch.regs, 0, sizeof(vcpu->arch.regs));

	BUILD_BUG_ON(sizeof(svm->valid_bitmap) != sizeof(ghcb->save.valid_bitmap));
	memcpy(&svm->valid_bitmap, &ghcb->save.valid_bitmap, sizeof(ghcb->save.valid_bitmap));

	vcpu->arch.regs[VCPU_REGS_RAX] = kvm_ghcb_get_rax_if_valid(svm, ghcb);
	vcpu->arch.regs[VCPU_REGS_RBX] = kvm_ghcb_get_rbx_if_valid(svm, ghcb);
	vcpu->arch.regs[VCPU_REGS_RCX] = kvm_ghcb_get_rcx_if_valid(svm, ghcb);
	vcpu->arch.regs[VCPU_REGS_RDX] = kvm_ghcb_get_rdx_if_valid(svm, ghcb);
	vcpu->arch.regs[VCPU_REGS_RSI] = kvm_ghcb_get_rsi_if_valid(svm, ghcb);

	svm->vmcb->save.cpl = kvm_ghcb_get_cpl_if_valid(svm, ghcb);

	if (kvm_ghcb_xcr0_is_valid(svm)) {
		vcpu->arch.xcr0 = ghcb_get_xcr0(ghcb);
		kvm_update_cpuid_runtime(vcpu);
	}

	/* Copy the GHCB exit information into the VMCB fields */
	exit_code = ghcb_get_sw_exit_code(ghcb);
	control->exit_code = lower_32_bits(exit_code);
	control->exit_code_hi = upper_32_bits(exit_code);
	control->exit_info_1 = ghcb_get_sw_exit_info_1(ghcb);
	control->exit_info_2 = ghcb_get_sw_exit_info_2(ghcb);
	svm->sw_scratch = kvm_ghcb_get_sw_scratch_if_valid(svm, ghcb);

	/* Clear the valid entries fields */
	memset(ghcb->save.valid_bitmap, 0, sizeof(ghcb->save.valid_bitmap));
}

static u64 kvm_ghcb_get_sw_exit_code(struct vmcb_control_area *control)
{
	return (((u64)control->exit_code_hi) << 32) | control->exit_code;
}

static int sev_es_validate_vmgexit(struct vcpu_svm *svm)
{
	struct vmcb_control_area *control = &svm->vmcb->control;
	struct kvm_vcpu *vcpu = &svm->vcpu;
	u64 exit_code;
	u64 reason;

	/*
	 * Retrieve the exit code now even though it may not be marked valid
	 * as it could help with debugging.
	 */
	exit_code = kvm_ghcb_get_sw_exit_code(control);

	/* Only GHCB Usage code 0 is supported */
	if (svm->ghcb->ghcb_usage) {
		reason = GHCB_ERR_INVALID_USAGE;
		goto vmgexit_err;
	}

	reason = GHCB_ERR_MISSING_INPUT;

	if (!kvm_ghcb_sw_exit_code_is_valid(svm) ||
	    !kvm_ghcb_sw_exit_info_1_is_valid(svm) ||
	    !kvm_ghcb_sw_exit_info_2_is_valid(svm))
		goto vmgexit_err;

	switch (exit_code) {
	case SVM_EXIT_READ_DR7:
		break;
	case SVM_EXIT_WRITE_DR7:
		if (!kvm_ghcb_rax_is_valid(svm))
			goto vmgexit_err;
		break;
	case SVM_EXIT_RDTSC:
		break;
	case SVM_EXIT_RDPMC:
		if (!kvm_ghcb_rcx_is_valid(svm))
			goto vmgexit_err;
		break;
	case SVM_EXIT_CPUID:
		if (!kvm_ghcb_rax_is_valid(svm) ||
		    !kvm_ghcb_rcx_is_valid(svm))
			goto vmgexit_err;
		if (vcpu->arch.regs[VCPU_REGS_RAX] == 0xd)
			if (!kvm_ghcb_xcr0_is_valid(svm))
				goto vmgexit_err;
		break;
	case SVM_EXIT_INVD:
		break;
	case SVM_EXIT_IOIO:
		if (control->exit_info_1 & SVM_IOIO_STR_MASK) {
			if (!kvm_ghcb_sw_scratch_is_valid(svm))
				goto vmgexit_err;
		} else {
			if (!(control->exit_info_1 & SVM_IOIO_TYPE_MASK))
				if (!kvm_ghcb_rax_is_valid(svm))
					goto vmgexit_err;
		}
		break;
	case SVM_EXIT_MSR:
		if (!kvm_ghcb_rcx_is_valid(svm))
			goto vmgexit_err;
		if (control->exit_info_1) {
			if (!kvm_ghcb_rax_is_valid(svm) ||
			    !kvm_ghcb_rdx_is_valid(svm))
				goto vmgexit_err;
		}
		break;
	case SVM_EXIT_VMMCALL:
		if (!kvm_ghcb_rax_is_valid(svm) ||
		    !kvm_ghcb_cpl_is_valid(svm))
			goto vmgexit_err;
		break;
	case SVM_EXIT_RDTSCP:
		break;
	case SVM_EXIT_WBINVD:
		break;
	case SVM_EXIT_MONITOR:
		if (!kvm_ghcb_rax_is_valid(svm) ||
		    !kvm_ghcb_rcx_is_valid(svm) ||
		    !kvm_ghcb_rdx_is_valid(svm))
			goto vmgexit_err;
		break;
	case SVM_EXIT_MWAIT:
		if (!kvm_ghcb_rax_is_valid(svm) ||
		    !kvm_ghcb_rcx_is_valid(svm))
			goto vmgexit_err;
		break;
	case SVM_VMGEXIT_MMIO_READ:
	case SVM_VMGEXIT_MMIO_WRITE:
		if (!kvm_ghcb_sw_scratch_is_valid(svm))
			goto vmgexit_err;
		break;
	case SVM_VMGEXIT_NMI_COMPLETE:
	case SVM_VMGEXIT_AP_HLT_LOOP:
	case SVM_VMGEXIT_AP_JUMP_TABLE:
	case SVM_VMGEXIT_UNSUPPORTED_EVENT:
		break;
	default:
		reason = GHCB_ERR_INVALID_EVENT;
		goto vmgexit_err;
	}

	return 0;

vmgexit_err:
	if (reason == GHCB_ERR_INVALID_USAGE) {
		vcpu_unimpl(vcpu, "vmgexit: ghcb usage %#x is not valid\n",
			    svm->ghcb->ghcb_usage);
	} else if (reason == GHCB_ERR_INVALID_EVENT) {
		vcpu_unimpl(vcpu, "vmgexit: exit code %#llx is not valid\n",
			    exit_code);
	} else {
		vcpu_unimpl(vcpu, "vmgexit: exit code %#llx input is not valid\n",
			    exit_code);
		dump_ghcb(svm);
	}

	ghcb_set_sw_exit_info_1(svm->ghcb, 2);
	ghcb_set_sw_exit_info_2(svm->ghcb, reason);

	/* Resume the guest to "return" the error code. */
	return 1;
}

void sev_es_unmap_ghcb(struct vcpu_svm *svm)
{
	if (!svm->ghcb)
		return;

	if (svm->ghcb_sa_free) {
		/*
		 * The scratch area lives outside the GHCB, so there is a
		 * buffer that, depending on the operation performed, may
		 * need to be synced, then freed.
		 */
		if (svm->ghcb_sa_sync) {
			kvm_write_guest(svm->vcpu.kvm,
					svm->sw_scratch,
					svm->ghcb_sa, svm->ghcb_sa_len);
			svm->ghcb_sa_sync = false;
		}

		kvfree(svm->ghcb_sa);
		svm->ghcb_sa = NULL;
		svm->ghcb_sa_free = false;
	}

	trace_kvm_vmgexit_exit(svm->vcpu.vcpu_id, svm->ghcb);

	sev_es_sync_to_ghcb(svm);

	kvm_vcpu_unmap(&svm->vcpu, &svm->ghcb_map, true);
	svm->ghcb = NULL;
}

void pre_sev_run(struct vcpu_svm *svm, int cpu)
{
	struct svm_cpu_data *sd = per_cpu(svm_data, cpu);
	int asid = sev_get_asid(svm->vcpu.kvm);

	/* Assign the asid allocated with this SEV guest */
	svm->vmcb->control.asid = asid;

	/*
	 * Flush guest TLB:
	 *
	 * 1) when different VMCB for the same ASID is to be run on the same host CPU.
	 * 2) or this VMCB was executed on different host CPU in previous VMRUNs.
	 */
	if (sd->sev_vmcbs[asid] == svm->vmcb &&
	    svm->vcpu.arch.last_vmentry_cpu == cpu)
		return;

	sd->sev_vmcbs[asid] = svm->vmcb;
	svm->vmcb->control.tlb_ctl = TLB_CONTROL_FLUSH_ASID;
	vmcb_mark_dirty(svm->vmcb, VMCB_ASID);
}

#define GHCB_SCRATCH_AREA_LIMIT		(16ULL * PAGE_SIZE)
static int setup_vmgexit_scratch(struct vcpu_svm *svm, bool sync, u64 len)
{
	struct vmcb_control_area *control = &svm->vmcb->control;
	u64 ghcb_scratch_beg, ghcb_scratch_end;
	u64 scratch_gpa_beg, scratch_gpa_end;
	void *scratch_va;

	scratch_gpa_beg = svm->sw_scratch;
	if (!scratch_gpa_beg) {
		pr_err("vmgexit: scratch gpa not provided\n");
		goto e_scratch;
	}

	scratch_gpa_end = scratch_gpa_beg + len;
	if (scratch_gpa_end < scratch_gpa_beg) {
		pr_err("vmgexit: scratch length (%#llx) not valid for scratch address (%#llx)\n",
		       len, scratch_gpa_beg);
		goto e_scratch;
	}

	if ((scratch_gpa_beg & PAGE_MASK) == control->ghcb_gpa) {
		/* Scratch area begins within GHCB */
		ghcb_scratch_beg = control->ghcb_gpa +
				   offsetof(struct ghcb, shared_buffer);
		ghcb_scratch_end = control->ghcb_gpa +
				   offsetof(struct ghcb, reserved_1);

		/*
		 * If the scratch area begins within the GHCB, it must be
		 * completely contained in the GHCB shared buffer area.
		 */
		if (scratch_gpa_beg < ghcb_scratch_beg ||
		    scratch_gpa_end > ghcb_scratch_end) {
			pr_err("vmgexit: scratch area is outside of GHCB shared buffer area (%#llx - %#llx)\n",
			       scratch_gpa_beg, scratch_gpa_end);
			goto e_scratch;
		}

		scratch_va = (void *)svm->ghcb;
		scratch_va += (scratch_gpa_beg - control->ghcb_gpa);
	} else {
		/*
		 * The guest memory must be read into a kernel buffer, so
		 * limit the size
		 */
		if (len > GHCB_SCRATCH_AREA_LIMIT) {
			pr_err("vmgexit: scratch area exceeds KVM limits (%#llx requested, %#llx limit)\n",
			       len, GHCB_SCRATCH_AREA_LIMIT);
			goto e_scratch;
		}
		scratch_va = kvzalloc(len, GFP_KERNEL);
		if (!scratch_va)
			return -ENOMEM;

		if (kvm_read_guest(svm->vcpu.kvm, scratch_gpa_beg, scratch_va, len)) {
			/* Unable to copy scratch area from guest */
			pr_err("vmgexit: kvm_read_guest for scratch area failed\n");

			kvfree(scratch_va);
			return -EFAULT;
		}

		/*
		 * The scratch area is outside the GHCB. The operation will
		 * dictate whether the buffer needs to be synced before running
		 * the vCPU next time (i.e. a read was requested so the data
		 * must be written back to the guest memory).
		 */
		svm->ghcb_sa_sync = sync;
		svm->ghcb_sa_free = true;
	}

	svm->ghcb_sa = scratch_va;
	svm->ghcb_sa_len = len;

	return 0;

e_scratch:
	ghcb_set_sw_exit_info_1(svm->ghcb, 2);
	ghcb_set_sw_exit_info_2(svm->ghcb, GHCB_ERR_INVALID_SCRATCH_AREA);

	return 1;
}

static void set_ghcb_msr_bits(struct vcpu_svm *svm, u64 value, u64 mask,
			      unsigned int pos)
{
	svm->vmcb->control.ghcb_gpa &= ~(mask << pos);
	svm->vmcb->control.ghcb_gpa |= (value & mask) << pos;
}

static u64 get_ghcb_msr_bits(struct vcpu_svm *svm, u64 mask, unsigned int pos)
{
	return (svm->vmcb->control.ghcb_gpa >> pos) & mask;
}

static void set_ghcb_msr(struct vcpu_svm *svm, u64 value)
{
	svm->vmcb->control.ghcb_gpa = value;
}

static int sev_handle_vmgexit_msr_protocol(struct vcpu_svm *svm)
{
	struct vmcb_control_area *control = &svm->vmcb->control;
	struct kvm_vcpu *vcpu = &svm->vcpu;
	u64 ghcb_info;
	int ret = 1;

	ghcb_info = control->ghcb_gpa & GHCB_MSR_INFO_MASK;

	trace_kvm_vmgexit_msr_protocol_enter(svm->vcpu.vcpu_id,
					     control->ghcb_gpa);

	switch (ghcb_info) {
	case GHCB_MSR_SEV_INFO_REQ:
		set_ghcb_msr(svm, GHCB_MSR_SEV_INFO(GHCB_VERSION_MAX,
						    GHCB_VERSION_MIN,
						    sev_enc_bit));
		break;
	case GHCB_MSR_CPUID_REQ: {
		u64 cpuid_fn, cpuid_reg, cpuid_value;

		cpuid_fn = get_ghcb_msr_bits(svm,
					     GHCB_MSR_CPUID_FUNC_MASK,
					     GHCB_MSR_CPUID_FUNC_POS);

		/* Initialize the registers needed by the CPUID intercept */
		vcpu->arch.regs[VCPU_REGS_RAX] = cpuid_fn;
		vcpu->arch.regs[VCPU_REGS_RCX] = 0;

		ret = svm_invoke_exit_handler(svm, SVM_EXIT_CPUID);
		if (!ret) {
			/* Error, keep GHCB MSR value as-is */
			break;
		}

		cpuid_reg = get_ghcb_msr_bits(svm,
					      GHCB_MSR_CPUID_REG_MASK,
					      GHCB_MSR_CPUID_REG_POS);
		if (cpuid_reg == 0)
			cpuid_value = vcpu->arch.regs[VCPU_REGS_RAX];
		else if (cpuid_reg == 1)
			cpuid_value = vcpu->arch.regs[VCPU_REGS_RBX];
		else if (cpuid_reg == 2)
			cpuid_value = vcpu->arch.regs[VCPU_REGS_RCX];
		else
			cpuid_value = vcpu->arch.regs[VCPU_REGS_RDX];

		set_ghcb_msr_bits(svm, cpuid_value,
				  GHCB_MSR_CPUID_VALUE_MASK,
				  GHCB_MSR_CPUID_VALUE_POS);

		set_ghcb_msr_bits(svm, GHCB_MSR_CPUID_RESP,
				  GHCB_MSR_INFO_MASK,
				  GHCB_MSR_INFO_POS);
		break;
	}
	case GHCB_MSR_TERM_REQ: {
		u64 reason_set, reason_code;

		reason_set = get_ghcb_msr_bits(svm,
					       GHCB_MSR_TERM_REASON_SET_MASK,
					       GHCB_MSR_TERM_REASON_SET_POS);
		reason_code = get_ghcb_msr_bits(svm,
						GHCB_MSR_TERM_REASON_MASK,
						GHCB_MSR_TERM_REASON_POS);
		pr_info("SEV-ES guest requested termination: %#llx:%#llx\n",
			reason_set, reason_code);

		vcpu->run->exit_reason = KVM_EXIT_SYSTEM_EVENT;
		vcpu->run->system_event.type = KVM_SYSTEM_EVENT_SEV_TERM |
					       KVM_SYSTEM_EVENT_NDATA_VALID;
		vcpu->run->system_event.ndata = 1;
		vcpu->run->system_event.data[1] = control->ghcb_gpa;

		return 0;
	}
	default:
		/* Error, keep GHCB MSR value as-is */
		break;
	}

	trace_kvm_vmgexit_msr_protocol_exit(svm->vcpu.vcpu_id,
					    control->ghcb_gpa, ret);

	return ret;
}

int sev_handle_vmgexit(struct vcpu_svm *svm)
{
	struct vmcb_control_area *control = &svm->vmcb->control;
	u64 ghcb_gpa, exit_code;
	int ret;

	/* Validate the GHCB */
	ghcb_gpa = control->ghcb_gpa;
	if (ghcb_gpa & GHCB_MSR_INFO_MASK)
		return sev_handle_vmgexit_msr_protocol(svm);

	if (!ghcb_gpa) {
		vcpu_unimpl(&svm->vcpu, "vmgexit: GHCB gpa is not set\n");

		/* Without a GHCB, just return right back to the guest */
		return 1;
	}

	if (kvm_vcpu_map(&svm->vcpu, ghcb_gpa >> PAGE_SHIFT, &svm->ghcb_map)) {
		/* Unable to map GHCB from guest */
		vcpu_unimpl(&svm->vcpu, "vmgexit: error mapping GHCB [%#llx] from guest\n",
			    ghcb_gpa);

		/* Without a GHCB, just return right back to the guest */
		return 1;
	}

	svm->ghcb = svm->ghcb_map.hva;

	trace_kvm_vmgexit_enter(svm->vcpu.vcpu_id, svm->ghcb);

	sev_es_sync_from_ghcb(svm);
	ret = sev_es_validate_vmgexit(svm);
	if (ret)
		return ret;

	ghcb_set_sw_exit_info_1(svm->ghcb, 0);
	ghcb_set_sw_exit_info_2(svm->ghcb, 0);

	exit_code = kvm_ghcb_get_sw_exit_code(control);
	switch (exit_code) {
	case SVM_VMGEXIT_MMIO_READ:
		ret = setup_vmgexit_scratch(svm, true, control->exit_info_2);
		if (ret)
			break;

		ret = kvm_sev_es_mmio_read(&svm->vcpu,
					   control->exit_info_1,
					   control->exit_info_2,
					   svm->ghcb_sa);
		break;
	case SVM_VMGEXIT_MMIO_WRITE:
		ret = setup_vmgexit_scratch(svm, false, control->exit_info_2);
		if (ret)
			break;

		ret = kvm_sev_es_mmio_write(&svm->vcpu,
					    control->exit_info_1,
					    control->exit_info_2,
					    svm->ghcb_sa);
		break;
	case SVM_VMGEXIT_NMI_COMPLETE:
		ret = svm_invoke_exit_handler(svm, SVM_EXIT_IRET);
		break;
	case SVM_VMGEXIT_AP_HLT_LOOP:
		ret = kvm_emulate_ap_reset_hold(&svm->vcpu);
		break;
	case SVM_VMGEXIT_AP_JUMP_TABLE: {
		struct kvm_sev_info *sev = &to_kvm_svm(svm->vcpu.kvm)->sev_info;

		switch (control->exit_info_1) {
		case 0:
			/* Set AP jump table address */
			sev->ap_jump_table = control->exit_info_2;
			break;
		case 1:
			/* Get AP jump table address */
			ghcb_set_sw_exit_info_2(svm->ghcb, sev->ap_jump_table);
			break;
		default:
			pr_err("svm: vmgexit: unsupported AP jump table request - exit_info_1=%#llx\n",
			       control->exit_info_1);
			ghcb_set_sw_exit_info_1(svm->ghcb, 2);
			ghcb_set_sw_exit_info_2(svm->ghcb, GHCB_ERR_INVALID_INPUT);
		}

		ret = 1;
		break;
	}
	case SVM_VMGEXIT_UNSUPPORTED_EVENT:
		vcpu_unimpl(&svm->vcpu,
			    "vmgexit: unsupported event - exit_info_1=%#llx, exit_info_2=%#llx\n",
			    control->exit_info_1, control->exit_info_2);
		ret = -EINVAL;
		break;
	default:
		ret = svm_invoke_exit_handler(svm, exit_code);
	}

	return ret;
}

int sev_es_string_io(struct vcpu_svm *svm, int size, unsigned int port, int in)
{
	int count;
	int bytes;
	int r;

	if (svm->vmcb->control.exit_info_2 > INT_MAX)
		return -EINVAL;

	count = svm->vmcb->control.exit_info_2;
	if (unlikely(check_mul_overflow(count, size, &bytes)))
		return -EINVAL;

	r = setup_vmgexit_scratch(svm, in, bytes);
	if (r)
		return r;

	return kvm_sev_es_string_io(&svm->vcpu, size, port, svm->ghcb_sa, count, in);
}

void sev_es_init_vmcb(struct vcpu_svm *svm)
{
	struct kvm_vcpu *vcpu = &svm->vcpu;

	svm->vmcb->control.nested_ctl |= SVM_NESTED_CTL_SEV_ES_ENABLE;
	svm->vmcb->control.virt_ext |= LBR_CTL_ENABLE_MASK;

	/*
	 * An SEV-ES guest requires a VMSA area that is a separate from the
	 * VMCB page. Do not include the encryption mask on the VMSA physical
	 * address since hardware will access it using the guest key.
	 */
	svm->vmcb->control.vmsa_pa = __pa(svm->vmsa);

	/* Can't intercept CR register access, HV can't modify CR registers */
	svm_clr_intercept(svm, INTERCEPT_CR0_READ);
	svm_clr_intercept(svm, INTERCEPT_CR4_READ);
	svm_clr_intercept(svm, INTERCEPT_CR8_READ);
	svm_clr_intercept(svm, INTERCEPT_CR0_WRITE);
	svm_clr_intercept(svm, INTERCEPT_CR4_WRITE);
	svm_clr_intercept(svm, INTERCEPT_CR8_WRITE);

	svm_clr_intercept(svm, INTERCEPT_SELECTIVE_CR0);

	/* Track EFER/CR register changes */
	svm_set_intercept(svm, TRAP_EFER_WRITE);
	svm_set_intercept(svm, TRAP_CR0_WRITE);
	svm_set_intercept(svm, TRAP_CR4_WRITE);
	svm_set_intercept(svm, TRAP_CR8_WRITE);

	/* No support for enable_vmware_backdoor */
	clr_exception_intercept(svm, GP_VECTOR);

	/* Can't intercept XSETBV, HV can't modify XCR0 directly */
	svm_clr_intercept(svm, INTERCEPT_XSETBV);

	/* Clear intercepts on selected MSRs */
	set_msr_interception(vcpu, svm->msrpm, MSR_EFER, 1, 1);
	set_msr_interception(vcpu, svm->msrpm, MSR_IA32_CR_PAT, 1, 1);
	set_msr_interception(vcpu, svm->msrpm, MSR_IA32_LASTBRANCHFROMIP, 1, 1);
	set_msr_interception(vcpu, svm->msrpm, MSR_IA32_LASTBRANCHTOIP, 1, 1);
	set_msr_interception(vcpu, svm->msrpm, MSR_IA32_LASTINTFROMIP, 1, 1);
	set_msr_interception(vcpu, svm->msrpm, MSR_IA32_LASTINTTOIP, 1, 1);
}

void sev_es_create_vcpu(struct vcpu_svm *svm)
{
	/*
	 * Set the GHCB MSR value as per the GHCB specification when creating
	 * a vCPU for an SEV-ES guest.
	 */
	set_ghcb_msr(svm, GHCB_MSR_SEV_INFO(GHCB_VERSION_MAX,
					    GHCB_VERSION_MIN,
					    sev_enc_bit));
}

void sev_es_vcpu_load(struct vcpu_svm *svm, int cpu)
{
	struct svm_cpu_data *sd = per_cpu(svm_data, cpu);
	struct vmcb_save_area *hostsa;
	unsigned int i;

	/*
	 * As an SEV-ES guest, hardware will restore the host state on VMEXIT,
	 * of which one step is to perform a VMLOAD. Since hardware does not
	 * perform a VMSAVE on VMRUN, the host savearea must be updated.
	 */
	asm volatile(__ex("vmsave") : : "a" (__sme_page_pa(sd->save_area)) : "memory");

	/*
	 * Certain MSRs are restored on VMEXIT, only save ones that aren't
	 * restored.
	 */
	for (i = 0; i < NR_HOST_SAVE_USER_MSRS; i++) {
		if (host_save_user_msrs[i].sev_es_restored)
			continue;

		rdmsrl(host_save_user_msrs[i].index, svm->host_user_msrs[i]);
	}

	/* XCR0 is restored on VMEXIT, save the current host value */
	hostsa = (struct vmcb_save_area *)(page_address(sd->save_area) + 0x400);
	hostsa->xcr0 = xgetbv(XCR_XFEATURE_ENABLED_MASK);

	/* PKRU is restored on VMEXIT, save the curent host value */
	hostsa->pkru = read_pkru();

	/* MSR_IA32_XSS is restored on VMEXIT, save the currnet host value */
	hostsa->xss = host_xss;
}

void sev_es_vcpu_put(struct vcpu_svm *svm)
{
	unsigned int i;

	/*
	 * Certain MSRs are restored on VMEXIT and were saved with vmsave in
	 * sev_es_vcpu_load() above. Only restore ones that weren't.
	 */
	for (i = 0; i < NR_HOST_SAVE_USER_MSRS; i++) {
		if (host_save_user_msrs[i].sev_es_restored)
			continue;

		wrmsrl(host_save_user_msrs[i].index, svm->host_user_msrs[i]);
	}
}

void sev_vcpu_deliver_sipi_vector(struct kvm_vcpu *vcpu, u8 vector)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	/* First SIPI: Use the values as initially set by the VMM */
	if (!svm->received_first_sipi) {
		svm->received_first_sipi = true;
		return;
	}

	/*
	 * Subsequent SIPI: Return from an AP Reset Hold VMGEXIT, where
	 * the guest will set the CS and RIP. Set SW_EXIT_INFO_2 to a
	 * non-zero value.
	 */
	if (!svm->ghcb)
		return;

	ghcb_set_sw_exit_info_2(svm->ghcb, 1);
}

int sev_es_ghcb_map(struct vcpu_svm *svm, u64 ghcb_gpa)
{
	if (kvm_vcpu_map(&svm->vcpu, ghcb_gpa >> PAGE_SHIFT, &svm->ghcb_map)) {
		/* Unable to map GHCB from guest */
		vcpu_unimpl(&svm->vcpu, "Missing GHCB [%#llx] from guest\n",
			    ghcb_gpa);

		svm->receiver_ghcb_map_fail = true;
		return -EINVAL;
	}

	svm->ghcb = svm->ghcb_map.hva;
	svm->receiver_ghcb_map_fail = false;

	pr_info("Mapping GHCB [%#llx] from guest at recipient\n", ghcb_gpa);

	return 0;
}

int csv_control_pre_system_reset(struct kvm *kvm)
{
	struct kvm_vcpu *vcpu;
	int i, ret;

	if (!sev_es_guest(kvm))
		return 0;

	kvm_for_each_vcpu(i, vcpu, kvm) {
		ret = mutex_lock_killable(&vcpu->mutex);
		if (ret)
			return ret;

		vcpu->arch.guest_state_protected = false;

		mutex_unlock(&vcpu->mutex);
	}

	return 0;
}

int csv_control_post_system_reset(struct kvm *kvm)
{
	struct kvm_vcpu *vcpu;
	int i, ret;

	/* Flush both host and guest caches before next boot flow */
	wbinvd_on_all_cpus();

	if (!sev_es_guest(kvm))
		return 0;

	kvm_for_each_vcpu(i, vcpu, kvm) {
		struct vcpu_svm *svm = to_svm(vcpu);

		ret = mutex_lock_killable(&vcpu->mutex);
		if (ret)
			return ret;

		memcpy(svm->vmsa, svm->reset_vmsa, PAGE_SIZE);

		/* Flush encrypted vmsa to memory */
		clflush_cache_range(svm->vmsa, PAGE_SIZE);

		svm->vcpu.arch.guest_state_protected = true;
		svm->received_first_sipi = false;

		mutex_unlock(&vcpu->mutex);
	}

	return 0;
}
