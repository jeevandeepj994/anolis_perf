/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __X86_SEAMLOADER_H
#define __X86_SEAMLOADER_H

#ifdef CONFIG_KVM_INTEL_TDX

#define SEAMLDR_MAX_NR_MODULE_PAGES    496

struct seamldr_params {
	u32 version;
	u32 scenario;
	u64 sigstruct_pa;
	u8 reserved[104];
	u64 module_pages;
	u64 module_pa_list[SEAMLDR_MAX_NR_MODULE_PAGES];
} __packed __aligned(PAGE_SIZE);

struct tee_tcb_svn {
	u16 seam;
	u8 reserved[14];
} __packed;

struct __tee_tcb_info {
	u64 valid;
	struct tee_tcb_svn tee_tcb_svn;
	u64 mrseam[6];		/* SHA-384 */
	u64 mrsignerseam[6];	/* SHA-384 */
	u64 attributes;
} __packed;

struct tee_tcb_info {
	struct __tee_tcb_info info;
	u8 reserved[111];
} __packed;

#define P_SEAMLDR_INFO_ALIGNMENT	256
struct seamldr_info {
	u32 version;
	u32 attributes;
	u32 vendor_id;
	u32 build_date;
	u16 build_num;
	u16 minor_version;
	u16 major_version;
	u8 reserved0[2];
	u32 acm_x2apicid;
	u8 reserved1[4];
	struct __tee_tcb_info seaminfo;
	u8 seam_ready;
	u8 seam_debug;
	u8 p_seamldr_ready;
	u8 reserved2[88];
} __packed __aligned(P_SEAMLDR_INFO_ALIGNMENT);

int __init __no_sanitize_address seam_load_module(struct cpio_data *cpio_np_seamldr);
bool is_seamrr_enabled(void);
#endif

#endif /* __X86_SEAMLOADER_H */
