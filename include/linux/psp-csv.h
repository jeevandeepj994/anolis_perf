/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Hygon Secure Virtualization feature CSV driver interface
 *
 * Copyright (C) Hygon Info Technologies Ltd.
 */

#ifndef __PSP_CSV_H__
#define __PSP_CSV_H__

#include <linux/types.h>

/**
 * Guest/platform management commands
 */
enum csv3_cmd {
	/* Guest launch commands */
	CSV_CMD_SET_GUEST_PRIVATE_MEMORY	= 0x200,
	CSV_CMD_LAUNCH_ENCRYPT_DATA		= 0x201,
	CSV_CMD_LAUNCH_ENCRYPT_VMCB		= 0x202,
	/* Guest NPT(Nested Page Table) management commands */
	CSV_CMD_UPDATE_NPT			= 0x203,

	/* Guest migration commands */
	CSV_CMD_SEND_ENCRYPT_DATA		= 0x210,
	CSV_CMD_SEND_ENCRYPT_CONTEXT		= 0x211,
	CSV_CMD_RECEIVE_ENCRYPT_DATA		= 0x212,
	CSV_CMD_RECEIVE_ENCRYPT_CONTEXT		= 0x213,

	/* Guest debug commands */
	CSV_CMD_DBG_READ_VMSA			= 0x220,
	CSV_CMD_DBG_READ_MEM			= 0x221,

	/* Platform secure memory management commands */
	CSV_CMD_SET_SMR				= 0x230,
	CSV_CMD_SET_SMCR			= 0x231,

	CSV3_CMD_MAX,
};

/**
 * struct csv_data_launch_encrypt_data - CSV_CMD_LAUNCH_ENCRYPT_DATA command
 *
 * @handle: handle of the VM to update
 * @gpa: guest address where data is copied
 * @length: len of memory to be encrypted
 * @data_blocks: memory regions to hold data page address
 */
struct csv_data_launch_encrypt_data {
	u32 handle;			/* In */
	u32 reserved;			/* In */
	u64 gpa;			/* In */
	u32 length;			/* In */
	u32 reserved1;			/* In */
	u64 data_blocks[8];		/* In */
} __packed;

/**
 * struct csv_data_launch_encrypt_vmcb - CSV_CMD_LAUNCH_ENCRYPT_VMCB command
 *
 * @handle: handle of the VM
 * @vcpu_id: id of vcpu per vmsa/vmcb
 * @vmsa_addr: memory address of initial vmsa data
 * @vmsa_len: len of initial vmsa data
 * @shadow_vmcb_addr: memory address of shadow vmcb data
 * @shadow_vmcb_len: len of shadow vmcb data
 * @secure_vmcb_addr: memory address of secure vmcb data
 * @secure_vmcb_len: len of secure vmcb data
 */
struct csv_data_launch_encrypt_vmcb {
	u32 handle;			/* In */
	u32 reserved;			/* In */
	u32 vcpu_id;			/* In */
	u32 reserved1;			/* In */
	u64 vmsa_addr;			/* In */
	u32 vmsa_len;			/* In */
	u32 reserved2;			/* In */
	u64 shadow_vmcb_addr;		/* In */
	u32 shadow_vmcb_len;		/* In */
	u32 reserved3;			/* In */
	u64 secure_vmcb_addr;		/* Out */
	u32 secure_vmcb_len;		/* Out */
} __packed;

/**
 * struct csv_data_update_npt - CSV_CMD_UPDATE_NPT command
 *
 * @handle: handle assigned to the VM
 * @error_code: nested page fault error code
 * @gpa: guest page address where npf happens
 * @spa: physical address which maps to gpa in host page table
 * @level: page level which can be mapped in nested page table
 * @page_attr: page attribute for gpa
 * @page_attr_mask: which page attribute bit should be set
 * @npages: number of pages from gpa is handled.
 */
struct csv_data_update_npt {
	u32 handle;			/* In */
	u32 reserved;			/* In */
	u32 error_code;			/* In */
	u32 reserved1;			/* In */
	u64 gpa;			/* In */
	u64 spa;			/* In */
	u64 level;			/* In */
	u64 page_attr;			/* In */
	u64 page_attr_mask;		/* In */
	u32 npages;			/* In/Out */
} __packed;

/**
 * struct csv_data_mem_region - define a memory region
 *
 * @base_address: base address of a memory region
 * @size: size of memory region
 */
struct csv_data_memory_region {
	u64 base_address;		/* In */
	u64 size;			/* In */
} __packed;

/**
 * struct csv_data_set_guest_private_memory - CSV_CMD_SET_GUEST_PRIVATE_MEMORY
 * command parameters
 *
 * @handle: handle assigned to the VM
 * @nregions: number of memory regions
 * @regions_paddr: address of memory containing multiple memory regions
 */
struct csv_data_set_guest_private_memory {
	u32 handle;			/* In */
	u32 nregions;			/* In */
	u64 regions_paddr;		/* In */
} __packed;

/**
 * struct csv_data_set_smr - CSV_CMD_SET_SMR command parameters
 *
 * @smr_entry_size: size of SMR entry
 * @nregions: number of memory regions
 * @regions_paddr: address of memory containing multiple memory regions
 */
struct csv_data_set_smr {
	u32 smr_entry_size;		/* In */
	u32 nregions;			/* In */
	u64 regions_paddr;		/* In */
} __packed;

/**
 * struct csv_data_set_smcr - CSV_CMD_SET_SMCR command parameters
 *
 * @base_address: start address of SMCR memory
 * @size: size of SMCR memory
 */
struct csv_data_set_smcr {
	u64 base_address;		/* In */
	u64 size;			/* In */
} __packed;

/**
 * struct csv_data_dbg_read_vmsa - CSV_CMD_DBG_READ_VMSA command parameters
 *
 * @handle: handle assigned to the VM
 * @spa: system physical address of memory to get vmsa of the specific vcpu
 * @size: size of the host memory
 * @vcpu_id: the specific vcpu
 */
struct csv_data_dbg_read_vmsa {
	u32 handle;			/* In */
	u32 reserved;			/* In */
	u64 spa;			/* In */
	u32 size;			/* In */
	u32 vcpu_id;			/* In */
} __packed;

/**
 * struct csv_data_dbg_read_mem - CSV_CMD_DBG_READ_MEM command parameters
 *
 * @handle: handle assigned to the VM
 * @gpa: guest physical address of the memory to access
 * @spa: system physical address of memory to get data from gpa
 * @size: size of guest memory to access
 */
struct csv_data_dbg_read_mem {
	u32 handle;			/* In */
	u32 reserved;			/* In */
	u64 gpa;			/* In */
	u64 spa;			/* In */
	u32 size;			/* In */
} __packed;

#endif
