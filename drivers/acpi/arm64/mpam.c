// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2022 Arm Ltd.

/* Parse the MPAM ACPI table feeding the discovered nodes into the driver */

#define pr_fmt(fmt) "ACPI MPAM: " fmt

#include <linux/acpi.h>
#include <linux/arm_mpam.h>
#include <linux/cpu.h>
#include <linux/cpumask.h>
#include <linux/platform_device.h>

#include <acpi/processor.h>

#include <asm/mpam.h>

/* Flags for acpi_table_mpam_msc.*_interrupt_flags */
#define ACPI_MPAM_MSC_IRQ_MODE_EDGE                    1
#define ACPI_MPAM_MSC_IRQ_TYPE_MASK                    (3<<1)
#define ACPI_MPAM_MSC_IRQ_TYPE_WIRED                   0
#define ACPI_MPAM_MSC_IRQ_AFFINITY_PROCESSOR_CONTAINER (1<<3)
#define ACPI_MPAM_MSC_IRQ_AFFINITY_VALID               (1<<4)

int ddrc_freq;

/* Use OEM info in MPAM ACPI table to distinguish different machine types */
struct acpi_mpam_machine_oem_info {
	enum mpam_machine_type type;
	char signature[ACPI_NAMESEG_SIZE + 1];
	u8 revision;
	char oem_id[ACPI_OEM_ID_SIZE + 1];
	char oem_table_id[ACPI_OEM_TABLE_ID_SIZE + 1];
	u32 oem_revision;
};

static struct acpi_mpam_machine_oem_info acpi_mpam_machines[MPAM_NUM_MACHINE_TYPES] = {
	[MPAM_YITIAN710] = {
		.signature = "YMPM",
		.revision = 0,
		.oem_id = "PTG   ",
		.oem_table_id = "PTG01   ",
		.oem_revision = 0,
	},
};

static bool frob_irq(struct platform_device *pdev, int intid, u32 flags,
		     int *irq, u32 processor_container_uid)
{
	int sense;

	if (!intid)
		return false;

	/* 0 in this field indicates a wired interrupt */
	if (flags & ACPI_MPAM_MSC_IRQ_TYPE_MASK)
		return false;

	if (flags & ACPI_MPAM_MSC_IRQ_MODE_EDGE)
		sense = ACPI_EDGE_SENSITIVE;
	else
		sense = ACPI_LEVEL_SENSITIVE;

	/*
	 * If the GSI is in the GIC's PPI range, try and create a partitioned
	 * percpu interrupt.
	 */
	if (16 <= intid && intid < 32 && processor_container_uid != ~0) {
		pr_err_once("Partitioned interrupts not supported\n");
		return false;
	} else {
		*irq = acpi_register_gsi(&pdev->dev, intid, sense,
					 ACPI_ACTIVE_HIGH);
	}
	if (*irq <= 0) {
		pr_err_once("Failed to register interrupt 0x%x with ACPI\n",
			    intid);
		return false;
	}

	return true;
}

static void acpi_mpam_parse_irqs(struct platform_device *pdev,
				 struct acpi_mpam_msc_node *tbl_msc,
				 struct resource *res, int *res_idx)
{
	u32 flags, aff = ~0;
	int irq;

	flags = tbl_msc->overflow_interrupt_flags;
	if (flags & ACPI_MPAM_MSC_IRQ_AFFINITY_VALID &&
	    flags & ACPI_MPAM_MSC_IRQ_AFFINITY_PROCESSOR_CONTAINER)
		aff = tbl_msc->overflow_interrupt_affinity;
	if (frob_irq(pdev, tbl_msc->overflow_interrupt, flags, &irq, aff)) {
		res[*res_idx].start = irq;
		res[*res_idx].end = irq;
		res[*res_idx].flags = IORESOURCE_IRQ;
		res[*res_idx].name = "overflow";

		(*res_idx)++;
	}

	flags = tbl_msc->error_interrupt_flags;
	if (flags & ACPI_MPAM_MSC_IRQ_AFFINITY_VALID &&
	    flags & ACPI_MPAM_MSC_IRQ_AFFINITY_PROCESSOR_CONTAINER)
		aff = tbl_msc->error_interrupt_affinity;
	else
		aff = ~0;
	if (frob_irq(pdev, tbl_msc->error_interrupt, flags, &irq, aff)) {
		res[*res_idx].start = irq;
		res[*res_idx].end = irq;
		res[*res_idx].flags = IORESOURCE_IRQ;
		res[*res_idx].name = "error";

		(*res_idx)++;
	}
}

static int acpi_mpam_parse_resource(struct mpam_msc *msc,
				    struct acpi_mpam_resource_node *res)
{
	u32 cache_id;
	int level;

	switch (res->locator_type) {
	case ACPI_MPAM_LOCATION_TYPE_PROCESSOR_CACHE:
		cache_id = res->locator.cache_locator.cache_reference;
		if (mpam_current_machine == MPAM_YITIAN710) {
			/*
			 * YITIAN710's BIOS doesn't support find level from
			 * cache id. Since it only supports L3 cache, use a
			 * fixed value, 3.
			 */
			level = 3;
		} else {
			level = find_acpi_cache_level_from_id(cache_id);
			if (level < 0) {
				pr_err_once("Bad level for cache with id %u\n", cache_id);
				return level;
			}
		}
		return mpam_ris_create(msc, res->ris_index, MPAM_CLASS_CACHE,
				       level, cache_id);
	case ACPI_MPAM_LOCATION_TYPE_MEMORY:
		if (mpam_current_machine == MPAM_YITIAN710)
			ddrc_freq = res->locator.memory_locator.reserved;
		return mpam_ris_create(msc, res->ris_index, MPAM_CLASS_MEMORY,
				       255, res->locator.memory_locator.proximity_domain);
	default:
		/* These get discovered later and treated as unknown */
		return 0;
	}
}

int acpi_mpam_parse_resources(struct mpam_msc *msc,
			      struct acpi_mpam_msc_node *tbl_msc)
{
	int i, err;
	struct acpi_mpam_resource_node *resources;

	resources = (struct acpi_mpam_resource_node *)(tbl_msc + 1);
	for (i = 0; i < tbl_msc->num_resouce_nodes; i++) {
		err = acpi_mpam_parse_resource(msc, &resources[i]);
		if (err)
			return err;
	}

	return 0;
}

static bool __init parse_msc_pm_link(struct acpi_mpam_msc_node *tbl_msc,
				     struct platform_device *pdev,
				     u32 *acpi_id)
{
	bool acpi_id_valid = false;
	struct acpi_device *buddy;
	char hid[16], uid[16];
	int err;

	memset(&hid, 0, sizeof(hid));
	memcpy(hid, &tbl_msc->hardware_id_linked_device,
	       sizeof(tbl_msc->hardware_id_linked_device));

	if (!strcmp(hid, ACPI_PROCESSOR_CONTAINER_HID)) {
		*acpi_id = tbl_msc->instance_id_linked_device;
		acpi_id_valid = true;
	}

	err = snprintf(uid, sizeof(uid), "%u",
		       tbl_msc->instance_id_linked_device);
	if (err < 0 || err >= sizeof(uid))
		return acpi_id_valid;

	buddy = acpi_dev_get_first_match_dev(hid, uid, -1);
	if (buddy) {
		device_link_add(&pdev->dev, &buddy->dev, DL_FLAG_STATELESS);
	}

	return acpi_id_valid;
}

static int decode_interface_type(struct acpi_mpam_msc_node *tbl_msc,
				 enum mpam_msc_iface *iface)
{
	switch (tbl_msc->interface_type){
	case 0:
		*iface = MPAM_IFACE_MMIO;
		return 0;
	case 1:
		*iface = MPAM_IFACE_PCC;
		return 0;
	default:
		return -EINVAL;
	}
}

static int __init _parse_table(struct acpi_table_header *table)
{
	char *table_end, *table_offset = (char *)(table + 1);
	struct property_entry props[4]; /* needs a sentinel */
	struct acpi_mpam_msc_node *tbl_msc;
	int next_res, next_prop, err = 0;
	struct acpi_device *companion;
	struct platform_device *pdev;
	enum mpam_msc_iface iface;
	struct resource res[3];
	char uid[16];
	u32 acpi_id;
	int msc_num = 0;

	table_end = (char *)table + table->length;

	while (table_offset < table_end) {
		tbl_msc = (struct acpi_mpam_msc_node *)table_offset;
		table_offset += tbl_msc->length;

		/*
		 * If any of the reserved fields are set, make no attempt to
		 * parse the msc structure. This will prevent the driver from
		 * probing all the MSC, meaning it can't discover the system
		 * wide supported partid and pmg ranges. This avoids whatever
		 * this MSC is truncating the partids and creating a screaming
		 * error interrupt.
		 */
		if (tbl_msc->reserved || tbl_msc->reserved1 || tbl_msc->reserved2)
			continue;

		if (decode_interface_type(tbl_msc, &iface))
			continue;

		next_res = 0;
		next_prop = 0;
		memset(res, 0, sizeof(res));
		memset(props, 0, sizeof(props));

		/*
		 * Use an extra msc_num instead of msc->identifier, since MSC
		 * nodes with different types in MPAM ACPI table may have the
		 * same id value.
		 */
		pdev = platform_device_alloc("mpam_msc", msc_num++);
		if (IS_ERR(pdev)) {
			err = PTR_ERR(pdev);
			break;
		}

		if (tbl_msc->length < sizeof(*tbl_msc)) {
			err = -EINVAL;
			break;
		}

		/* Some power management is described in the namespace: */
		err = snprintf(uid, sizeof(uid), "%u", tbl_msc->identifier);
		if (err > 0 && err < sizeof(uid)) {
			companion = acpi_dev_get_first_match_dev("ARMHAA5C", uid, -1);
			if (companion)
				ACPI_COMPANION_SET(&pdev->dev, companion);
		}

		if (iface == MPAM_IFACE_MMIO) {
			res[next_res].name = "MPAM:MSC";
			res[next_res].start = tbl_msc->base_address;
			res[next_res].end = tbl_msc->base_address + tbl_msc->mmio_size - 1;
			res[next_res].flags = IORESOURCE_MEM;
			next_res++;
		} else if (iface == MPAM_IFACE_PCC) {
			props[next_prop++] = PROPERTY_ENTRY_U32("pcc-channel",
								tbl_msc->base_address);
			next_prop++;
		}

		acpi_mpam_parse_irqs(pdev, tbl_msc, res, &next_res);
		err = platform_device_add_resources(pdev, res, next_res);
		if (err)
			break;

		props[next_prop++] = PROPERTY_ENTRY_U32("arm,not-ready-us",
							tbl_msc->max_nrdy_usec);

		/*
		 * The MSC's CPU affinity is described via its linked power
		 * management device, but only if it points at a Processor or
		 * Processor Container.
		 */
		if (parse_msc_pm_link(tbl_msc, pdev, &acpi_id)) {
			props[next_prop++] = PROPERTY_ENTRY_U32("cpu_affinity",
								acpi_id);
		}

		err = device_create_managed_software_node(&pdev->dev, props,
							  NULL);
		if (err)
			break;

		/* Come back later if you want the RIS too */
		err = platform_device_add_data(pdev, tbl_msc, tbl_msc->length);
		if (err)
			break;

		platform_device_add(pdev);
	}

	if (err)
		platform_device_put(pdev);

	return err;
}

static struct acpi_table_header *get_table(void)
{
	struct acpi_table_header *table;
	enum mpam_machine_type mtype;
	acpi_status status;

	if (acpi_disabled || !mpam_cpus_have_feature())
		return NULL;

	mtype = acpi_mpam_get_machine_type();

	if (mtype != MPAM_DEFAULT_MACHINE)
		status = acpi_get_table(acpi_mpam_machines[mtype].signature, 0, &table);
	else
		status = acpi_get_table(ACPI_SIG_MPAM, 0, &table);
	if (ACPI_FAILURE(status))
		return NULL;

	if (mtype == MPAM_DEFAULT_MACHINE && table->revision != 1)
		return NULL;

	/*
	 * Kunpeng's MPAM ACPI adopts an older version of MPAM ACPI, so
	 * this MPAM ACPI driver is not suitable for Kunpeng platform.
	 * Skip it.
	 */
	if (!strncmp(table->oem_id, "HISI", 4)) {
		acpi_put_table(table);
		return NULL;
	}

	return table;
}



static int __init acpi_mpam_parse(void)
{
	struct acpi_table_header *mpam;
	int err;

	mpam = get_table();
	if (!mpam)
		return 0;

	err = _parse_table(mpam);
	acpi_put_table(mpam);

	return err;
}

static int _count_msc(struct acpi_table_header *table)
{
	char *table_end, *table_offset = (char *)(table + 1);
	struct acpi_mpam_msc_node *tbl_msc;
	int ret = 0;

	tbl_msc = (struct acpi_mpam_msc_node *)table_offset;
	table_end = (char *)table + table->length;

	while (table_offset < table_end) {
		if (tbl_msc->length < sizeof(*tbl_msc))
			return -EINVAL;

		ret++;

		table_offset += tbl_msc->length;
		tbl_msc = (struct acpi_mpam_msc_node *)table_offset;
	}

	return ret;
}


int acpi_mpam_count_msc(void)
{
	struct acpi_table_header *mpam;
	int ret;

	mpam = get_table();
	if (!mpam)
		return 0;

	ret = _count_msc(mpam);
	acpi_put_table(mpam);

	return ret;
}

enum mpam_machine_type acpi_mpam_get_machine_type(void)
{
	struct acpi_table_header *table;
	enum mpam_machine_type ret;
	acpi_status status;
	int i;

	ret = MPAM_DEFAULT_MACHINE;

	for (i = MPAM_DEFAULT_MACHINE + 1; i < MPAM_NUM_MACHINE_TYPES; i++) {
		status = acpi_get_table(acpi_mpam_machines[i].signature, 0, &table);
		if (ACPI_FAILURE(status))
			continue;

		if (!memcmp(acpi_mpam_machines[i].oem_id, table->oem_id, ACPI_OEM_ID_SIZE) &&
		    !memcmp(acpi_mpam_machines[i].oem_table_id, table->oem_table_id,
		    ACPI_OEM_TABLE_ID_SIZE) &&
		    acpi_mpam_machines[i].oem_revision == table->oem_revision) {
			ret = i;
		}

		acpi_put_table(table);
	}

	return ret;
}

/*
 * Call after ACPI devices have been created, which happens behind acpi_scan_init()
 * called from subsys_initcall(). PCC requires the mailbox driver, which is
 * initialised from postcore_initcall().
 */
subsys_initcall_sync(acpi_mpam_parse);
