// SPDX-License-Identifier: GPL-2.0
#include <linux/pci.h>
#include <linux/pci-acpi.h>
#include <linux/pci-ecam.h>

#include <asm/pci.h>
#include <asm/sw64_init.h>

void set_devint_wken(int node)
{
	unsigned long val;

	/* enable INTD wakeup */
	val = 0x80;
	sw64_io_write(node, DEVINT_WKEN, val);
	sw64_io_write(node, DEVINTWK_INTEN, val);
}

#ifdef CONFIG_UNCORE_JUNZHANG
void set_adr_int(int node)
{
	sw64_io_write(node, ADR_INT_CONFIG, (0x0 << 16 | 0x3f));
	sw64_io_write(node, ADR_CTL, 0xc);
}
#endif

void set_pcieport_service_irq(int node, int index)
{
	if (IS_ENABLED(CONFIG_PCIE_PME))
		write_piu_ior0(node, index, PMEINTCONFIG, PME_ENABLE_INTD_CORE0);

	if (IS_ENABLED(CONFIG_PCIEAER))
		write_piu_ior0(node, index, AERERRINTCONFIG, AER_ENABLE_INTD_CORE0);
}

int chip_pcie_configure(struct pci_controller *hose)
{
	struct pci_dev *dev;
	struct pci_bus *bus, *top;
	struct list_head *next;
	unsigned int max_read_size, smallest_max_payload;
	int max_payloadsize;
	unsigned long rc_index, node;
	unsigned long piuconfig0, value;
	unsigned int pcie_caps_offset;
	unsigned int rc_conf_value;
	u16 devctl, new_values;
	bool rc_ari_disabled = false, found = false;
	unsigned char bus_max_num;

	node = hose->node;
	rc_index = hose->index;
	smallest_max_payload = read_rc_conf(node, rc_index, RC_EXP_DEVCAP);
	smallest_max_payload &= PCI_EXP_DEVCAP_PAYLOAD;
	bus_max_num = hose->busn_space->start;

	top = hose->bus;
	bus = top;
	next = top->devices.next;

	for (;;) {
		if (next == &bus->devices) {
			/* end of this bus, go up or finish */
			if (bus == top)
				break;

			next = bus->self->bus_list.next;
			bus = bus->self->bus;
			continue;
		}
		dev = list_entry(next, struct pci_dev, bus_list);
		if (dev->subordinate) {
			/* this is a pci-pci bridge, do its devices next */
			next = dev->subordinate->devices.next;
			bus = dev->subordinate;
		} else
			next = dev->bus_list.next;

		if (!found) {
			if (pci_is_root_bus(dev->bus)) {
				if (list_empty(&dev->subordinate->devices))
					rc_ari_disabled = true;
			} else {
				if (!pci_ari_enabled(dev->bus)) {
					rc_ari_disabled = true;
					found = true;
				}
			}
		}

		if (bus->busn_res.end > bus_max_num)
			bus_max_num = bus->busn_res.end;

		/* Query device PCIe capability register  */
		pcie_caps_offset = dev->pcie_cap;
		if (pcie_caps_offset == 0)
			continue;
		max_payloadsize = dev->pcie_mpss;
		if (max_payloadsize < smallest_max_payload)
			smallest_max_payload = max_payloadsize;
	}

	if (rc_ari_disabled) {
		rc_conf_value = read_rc_conf(node, rc_index, RC_EXP_DEVCTL2);
		rc_conf_value &= ~PCI_EXP_DEVCTL2_ARI;
		write_rc_conf(node, rc_index, RC_EXP_DEVCTL2, rc_conf_value);
	} else {
		rc_conf_value = read_rc_conf(node, rc_index, RC_EXP_DEVCTL2);
		rc_conf_value |= PCI_EXP_DEVCTL2_ARI;
		write_rc_conf(node, rc_index, RC_EXP_DEVCTL2, rc_conf_value);
	}

	rc_conf_value = read_rc_conf(node, rc_index, RC_EXP_DEVCAP);
	rc_conf_value &= PCI_EXP_DEVCAP_PAYLOAD;
	max_payloadsize = rc_conf_value;
	if (max_payloadsize < smallest_max_payload)
		smallest_max_payload = max_payloadsize;

	max_read_size = 0x2;   /* Limit to 512B */
	value = read_rc_conf(node, rc_index, RC_EXP_DEVCTL);
	value &= ~(PCI_EXP_DEVCTL_PAYLOAD | PCI_EXP_DEVCTL_READRQ);
	value |= (max_read_size << 12) | (smallest_max_payload << 5);
	write_rc_conf(node, rc_index, RC_EXP_DEVCTL, value);
	new_values = (max_read_size << 12) | (smallest_max_payload << 5);

	piuconfig0 = read_piu_ior0(node, rc_index, PIUCONFIG0);
	piuconfig0 &= ~(0x7fUL << 9);
	if (smallest_max_payload == 0x2) {
		piuconfig0 |= (0x20UL << 9);
		write_piu_ior0(node, rc_index, PIUCONFIG0, piuconfig0);
	} else {
		piuconfig0 |= (0x40UL << 9);
		write_piu_ior0(node, rc_index, PIUCONFIG0, piuconfig0);
	}

	printk("Node%ld RC%ld MPSS %luB, MRRS %luB, Piuconfig0 %#lx, ARI %s\n",
			node, rc_index, (1UL << smallest_max_payload) << 7,
			(1UL << max_read_size) << 7, piuconfig0,
			rc_ari_disabled ? "disabled" : "enabled");

	/* Now, set the max_payload_size for all devices to that value. */
	bus = top;
	next = top->devices.next;
	for (;;) {
		if (next == &bus->devices) {
			/* end of this bus, go up or finish */
			if (bus == top)
				break;
			next = bus->self->bus_list.next;
			bus = bus->self->bus;
			continue;
		}
		dev = list_entry(next, struct pci_dev, bus_list);
		if (dev->subordinate) {
			/* this is a pci-pci bridge, do its devices next */
			next = dev->subordinate->devices.next;
			bus = dev->subordinate;
		} else
			next = dev->bus_list.next;

		pcie_caps_offset = dev->pcie_cap;
		if (pcie_caps_offset == 0)
			continue;

		pci_read_config_word(dev, pcie_caps_offset + PCI_EXP_DEVCTL, &devctl);
		devctl &= ~(PCI_EXP_DEVCTL_PAYLOAD | PCI_EXP_DEVCTL_READRQ);
		devctl |= new_values;
		pci_write_config_word(dev, pcie_caps_offset + PCI_EXP_DEVCTL, devctl);
	}

	return bus_max_num;
}

static int check_pci_linkup(unsigned long node, unsigned long index)
{
	unsigned long rc_debug;

	if (is_guest_or_emul()) {
		if (node == 0 && index == 0)
			return 0;
		else
			return 1;
	} else {
		rc_debug = read_piu_ior1(node, index, RCDEBUGINF1);
	}

	return !(rc_debug == 0x111);
}

static void set_rc_piu(unsigned long node, unsigned long index)
{
	unsigned int i __maybe_unused;
	unsigned int value;
	u32 rc_misc_ctrl;

	if (is_guest_or_emul())
		return;

	/* configure RC, set PCI-E root controller */
	write_rc_conf(node, index, RC_COMMAND, 0x00100007);
	write_rc_conf(node, index, RC_PORT_LINK_CTL, 0x1f0020);
	write_rc_conf(node, index, RC_EXP_DEVCTL, 0x2850);
	write_rc_conf(node, index, RC_EXP_DEVCTL2, 0x6);
	write_rc_conf(node, index, RC_ORDER_RULE_CTL, 0x0100);

	/* enable DBI_RO_WR_EN */
	rc_misc_ctrl = read_rc_conf(node, index, RC_MISC_CONTROL_1);
	write_rc_conf(node, index, RC_MISC_CONTROL_1, rc_misc_ctrl | 0x1);

	/* fix up DEVICE_ID_VENDOR_ID register */
	value = (PCI_DEVICE_ID_SW64_ROOT_BRIDGE << 16) | PCI_VENDOR_ID_JN;
	write_rc_conf(node, index, RC_VENDOR_ID, value);

	/* set PCI-E root class code */
	value = read_rc_conf(node, index, RC_REVISION_ID);
	write_rc_conf(node, index, RC_REVISION_ID, (PCI_CLASS_BRIDGE_HOST << 16) | value);

	/* disable DBI_RO_WR_EN */
	write_rc_conf(node, index, RC_MISC_CONTROL_1, rc_misc_ctrl);

	write_rc_conf(node, index, RC_PRIMARY_BUS, 0xffffff);
	write_piu_ior0(node, index, PIUCONFIG0, PIUCONFIG0_INIT_VAL);

	write_piu_ior1(node, index, PIUCONFIG1, 0x2);
	write_piu_ior1(node, index, ERRENABLE, -1);

	/* set DMA offset value PCITODMA_OFFSET */
	write_piu_ior0(node, index, EPDMABAR, PCITODMA_OFFSET);
	if (IS_ENABLED(CONFIG_PCI_MSI)) {
		write_piu_ior0(node, index, MSIADDR, MSIX_MSG_ADDR);
#ifdef CONFIG_UNCORE_XUELANG
			for (i = 0; i < 256; i++)
				write_piu_ior0(node, index, MSICONFIG0 + (i << 7), 0);
#endif
	}
}

static void set_intx(unsigned long node, unsigned long index,
			   unsigned long int_conf)
{
	if (is_guest_or_emul())
		return;

#if defined(CONFIG_UNCORE_XUELANG)
	write_piu_ior0(node, index, INTACONFIG, int_conf | (0x8UL << 10));
	write_piu_ior0(node, index, INTBCONFIG, int_conf | (0x4UL << 10));
	write_piu_ior0(node, index, INTCCONFIG, int_conf | (0x2UL << 10));
	write_piu_ior0(node, index, INTDCONFIG, int_conf | (0x1UL << 10));
#elif defined(CONFIG_UNCORE_JUNZHANG)
	write_piu_ior0(node, index, INTACONFIG, int_conf | (0x1UL << 10));
	write_piu_ior0(node, index, INTBCONFIG, int_conf | (0x2UL << 10));
	write_piu_ior0(node, index, INTCCONFIG, int_conf | (0x4UL << 10));
	write_piu_ior0(node, index, INTDCONFIG, int_conf | (0x8UL << 10));
#endif
}

static unsigned long get_rc_enable(unsigned long node)
{
	unsigned long rc_enable;

	if (is_guest_or_emul())
		return 1;

	rc_enable = sw64_io_read(node, IO_START);

	return rc_enable;
}

static int map_irq(const struct pci_dev *dev, u8 slot, u8 pin)
{
	struct pci_controller *hose = pci_bus_to_pci_controller(dev->bus);

	if (pci_pcie_type(dev) == PCI_EXP_TYPE_ROOT_PORT)
		return hose->service_irq;
	else
		return hose->int_irq;
}

static void hose_init(struct pci_controller *hose)
{
	unsigned long pci_io_base;

	hose->sparse_mem_base = 0;
	hose->sparse_io_base = 0;
	pci_io_base = IO_BASE | (hose->node << IO_NODE_SHIFT)
			      | PCI_BASE | (hose->index << IO_RC_SHIFT);

	hose->dense_mem_base = pci_io_base;
	hose->dense_io_base = pci_io_base | PCI_LEGACY_IO;
	hose->ep_config_space_base = __va(pci_io_base | PCI_EP_CFG);
	hose->rc_config_space_base = __va(pci_io_base | PCI_RC_CFG);

	hose->mem_space->start = pci_io_base + PCI_32BIT_MEMIO;
	hose->mem_space->end = hose->mem_space->start + PCI_32BIT_MEMIO_SIZE - 1;
	hose->mem_space->name = "pci memory space";
	hose->mem_space->flags = IORESOURCE_MEM;

	if (request_resource(&iomem_resource, hose->mem_space) < 0)
		pr_err("Failed to request MEM on hose %ld\n", hose->index);
	hose->pre_mem_space->start =  pci_io_base | PCI_64BIT_MEMIO;
	hose->pre_mem_space->end = hose->pre_mem_space->start + PCI_64BIT_MEMIO_SIZE - 1;
	hose->pre_mem_space->name = "pci pre mem space";
	hose->pre_mem_space->flags = IORESOURCE_MEM | IORESOURCE_PREFETCH | IORESOURCE_MEM_64;

	if (request_resource(&iomem_resource, hose->pre_mem_space) < 0)
		pr_err("Failed to request 64bit MEM on hose %ld\n", hose->index);
	hose->io_space->start = pci_io_base | PCI_LEGACY_IO;
	hose->io_space->end = hose->io_space->start + PCI_LEGACY_IO_SIZE - 1;
	hose->io_space->name = "pci io space";
	hose->io_space->flags = IORESOURCE_IO;

	if (request_resource(&ioport_resource, hose->io_space) < 0)
		pr_err("Failed to request IO on hose %ld\n", hose->index);
	hose->busn_space->name = "PCI busn";
	hose->busn_space->start = 0xff;
	hose->busn_space->end = 0xff;
	hose->busn_space->flags = IORESOURCE_BUS;
	hose->first_busno = hose->self_busno = hose->busn_space->start;
	hose->last_busno  = hose->busn_space->end;

	if (is_in_host()) {
		if (IS_ENABLED(CONFIG_PCI_MSI))
			memset(hose->piu_msiconfig, 0, 256/8);
	}
};

static struct sw64_pci_init_ops chip_pci_init_ops = {
	.map_irq = map_irq,
	.get_rc_enable = get_rc_enable,
	.hose_init = hose_init,
	.set_rc_piu = set_rc_piu,
	.check_pci_linkup = check_pci_linkup,
	.set_intx = set_intx,
};

void __init setup_chip_pci_ops(void)
{
	sw64_chip_init->pci_init = chip_pci_init_ops;
}

static unsigned long rc_linkup;
static struct pci_controller *head, **tail = &head;

static void pci_mark_rc_linkup(unsigned long node, unsigned long index)
{
	set_bit(node * 8 + index, &rc_linkup);
}

static int pci_get_rc_linkup(unsigned long node, unsigned long index)
{
	return test_bit(node * 8 + index, &rc_linkup);
}

/**
 * Link the specified pci controller to list
 */
extern struct pci_controller *hose_head;
static void pci_link_controller(struct pci_controller *hose)
{
	if (unlikely(!hose))
		return;

	*tail = hose;
	tail = &hose->next;

	if (!hose_head)
		hose_head = head;
}

struct pci_controller *bus_num_to_pci_controller(unsigned long bus_num)
{
	struct pci_controller *hose;

	for (hose = head; hose; hose = hose->next) {
		if (bus_num >= hose->first_busno && bus_num <= hose->last_busno)
			return hose;
	}

	return NULL;
}

struct pci_controller *pci_bus_to_pci_controller(const struct pci_bus *bus)
{
	struct pci_config_window *cfg = NULL;

	if (unlikely(!bus))
		return NULL;

	if (acpi_disabled)
		return (struct pci_controller *)(bus->sysdata);

	cfg = (struct pci_config_window *)bus->sysdata;
	return (struct pci_controller *)(cfg->priv);
}

/**
 *  PCIe Root Complex read config space operations
 */
static int sw64_pcie_read_rc_cfg(struct pci_bus *bus, unsigned int devfn,
		int where, int size, u32 *val)
{
	u32 data;
	struct pci_controller *hose = pci_bus_to_pci_controller(bus);
	void __iomem *cfg_iobase = hose->rc_config_space_base;

	if (IS_ENABLED(CONFIG_PCI_DEBUG))
		pr_debug("rc read addr:%px bus %d, devfn %#x, where %#x size=%d\t",
				cfg_iobase + ((where & ~3) << 5), bus->number, devfn, where, size);

	if ((uintptr_t)where & (size - 1)) {
		*val = 0;
		return PCIBIOS_BAD_REGISTER_NUMBER;
	}

	/**
	 * Workaround for sw6a chipset due to only support scan with devfn = 0,
	 * while sw6b does not have this limit.
	 */
	if (unlikely(devfn > 0)) {
		*val = ~0;
		return PCIBIOS_DEVICE_NOT_FOUND;
	}

	data = readl(cfg_iobase + ((where & ~3) << 5));

	switch (size) {
	case 1:
		*val = (data >> (8 * (where & 0x3))) & 0xff;
		break;
	case 2:
		*val = (data >> (8 * (where & 0x2))) & 0xffff;
		break;
	default:
		*val = data;
		break;
	}

	if (IS_ENABLED(CONFIG_PCI_DEBUG))
		pr_debug("*val %#x\n ", *val);

	return PCIBIOS_SUCCESSFUL;
}

/**
 * PCIe Root Complex write config space operations
 */
int sw64_pcie_write_rc_cfg(struct pci_bus *bus, unsigned int devfn,
		int where, int size, u32 val)
{
	u32 data;
	u32 shift = 8 * (where & 3);
	struct pci_controller *hose = pci_bus_to_pci_controller(bus);
	void __iomem *cfg_iobase = (void *)hose->rc_config_space_base;

	if ((uintptr_t)where & (size - 1))
		return PCIBIOS_BAD_REGISTER_NUMBER;

	switch (size) {
	case 1:
		data = readl(cfg_iobase + ((where & ~3) << 5));
		data &= ~(0xff << shift);
		data |= (val & 0xff) << shift;
		break;
	case 2:
		data = readl(cfg_iobase + ((where & ~3) << 5));
		data &= ~(0xffff << shift);
		data |= (val & 0xffff) << shift;
		break;
	default:
		data = val;
		break;
	}

	if (IS_ENABLED(CONFIG_PCI_DEBUG))
		pr_debug("rc write addr:%px bus %d, devfn %#x, where %#x *val %#x size %d\n",
				cfg_iobase + ((where & ~3) << 5), bus->number, devfn, where, val, size);

	writel(data, cfg_iobase + ((where & ~3) << 5));

	return PCIBIOS_SUCCESSFUL;
}

/**
 * sw64_pcie_valid_device - check if a valid device is present on bus
 * @bus  : PCI bus structure
 * @devfn: device/function
 *
 * @return: 'true' on success and 'false' if invalid device is found
 */
static bool sw64_pcie_valid_device(struct pci_bus *bus, unsigned int devfn)
{
	struct pci_controller *hose = pci_bus_to_pci_controller(bus);

	if (is_in_host()) {
		/* Only one device down on each root complex */
		if (bus->number == hose->self_busno && devfn > 0)
			return false;
	}

	return true;
}

/**
 * sw64_pcie_config_read - read val from config space of PCI host controller or device
 * @bus  : PCI bus structure
 * @devfn: device/function
 * @where: offset from base
 * @size : size of val
 * @val[out]: the value read from PCI host controller or device
 *
 * @return: Whether read operation success
 */
static int sw64_pcie_config_read(struct pci_bus *bus, unsigned int devfn,
		int where, int size, u32 *val)
{
	struct pci_controller *hose = pci_bus_to_pci_controller(bus);
	int ret = PCIBIOS_DEVICE_NOT_FOUND;

	if (is_guest_or_emul())
		return pci_generic_config_read(bus, devfn, where, size, val);

	hose->self_busno = hose->busn_space->start;

	if (unlikely(bus->number == hose->self_busno)) {
		ret = sw64_pcie_read_rc_cfg(bus, devfn, where, size, val);
	} else {
		if (pci_get_rc_linkup(hose->node, hose->index)) {
			ret = pci_generic_config_read(bus, devfn, where, size, val);
		} else {
			return ret;
		}
	}
	return ret;
}

/**
 * sw64_pcie_config_write - write val to config space of PCI host controller or device
 * @bus  : PCI bus structure
 * @devfn: device/function
 * @where: offset from base
 * @size : size of val
 * @val  : the value write to PCI host controller or device
 *
 * @return: Whether write operation success
 */
static int sw64_pcie_config_write(struct pci_bus *bus, unsigned int devfn,
		int where, int size, u32 val)
{
	struct pci_controller *hose = pci_bus_to_pci_controller(bus);

	if (is_guest_or_emul())
		return pci_generic_config_write(bus, devfn, where, size, val);

	hose->self_busno = hose->busn_space->start;

	if (unlikely(bus->number == hose->self_busno))
		return sw64_pcie_write_rc_cfg(bus, devfn, where, size, val);
	else
		return pci_generic_config_write(bus, devfn, where, size, val);
}

/**
 * sw64_pcie_map_bus - get configuration base address
 * @bus  : PCI bus structure
 * @devfn: device/function
 * @where: offset from base
 *
 * @return: base address of the configuration space needed to be
 * accessed.
 */
static void __iomem *sw64_pcie_map_bus(struct pci_bus *bus,
		unsigned int devfn, int where)
{
	struct pci_controller *hose = pci_bus_to_pci_controller(bus);
	void __iomem *cfg_iobase;
	unsigned long relbus;

	if (!sw64_pcie_valid_device(bus, devfn))
		return NULL;

	/**
	 * ECAM of sunway PCI host controller is slightly
	 * different from the standrad:
	 * [31:24]: bus number
	 * [23:19]: device number
	 * [18:16]: function number
	 * [15:12]: reserved
	 * [11:8] : extended config space registers
	 * [7:2]  : legacy config space registers
	 */
	relbus = (bus->number << 24) | (devfn << 16) | where;

	cfg_iobase = hose->ep_config_space_base + relbus;

	if (IS_ENABLED(CONFIG_PCI_DEBUG))
		pr_debug("addr:%px bus %d, devfn %d, where %d\n",
				cfg_iobase, bus->number, devfn, where);
	return cfg_iobase;
}

#ifdef CONFIG_ACPI
static int sw64_pci_ecam_init(struct pci_config_window *cfg)
{
	struct pci_controller *hose = NULL;

	hose = kzalloc(sizeof(*hose), GFP_KERNEL);
	if (!hose) {
		dev_err(dev, "out of memory when alloc mem for pci_controller\n");
		return -ENOMEM;
	}

	pci_link_controller(hose);
	cfg->priv = (void *)hose;

	return 0;
}

const struct pci_ecam_ops sw64_pci_ecam_ops = {
	.bus_shift = 24,
	.init      = sw64_pci_ecam_init,
	.pci_ops   = {
		.map_bus = sw64_pcie_map_bus,
		.read    = sw64_pcie_config_read,
		.write   = sw64_pcie_config_write,
	}
};
#endif
