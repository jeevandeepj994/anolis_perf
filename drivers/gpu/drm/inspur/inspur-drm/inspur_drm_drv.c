// SPDX-License-Identifier: GPL-2.0

#include <linux/console.h>
#include <linux/module.h>

#include <drm/drm_atomic_helper.h>
#include <drm/drm_crtc_helper.h>

#include "inspur_drm_drv.h"
#include "inspur_drm_regs.h"

#define MEM_SIZE_RESERVE4KVM 0x200000

static const struct file_operations inspur_fops = {
	.owner = THIS_MODULE,
	.open = drm_open,
	.release = drm_release,
	.unlocked_ioctl = drm_ioctl,
	.compat_ioctl = drm_compat_ioctl,
	.mmap = inspur_mmap,
	.poll = drm_poll,
	.read = drm_read,
	.llseek = no_llseek,
};

static irqreturn_t inspur_drm_interrupt(int irq, void *arg)
{
	struct drm_device *dev = (struct drm_device *)arg;
	struct inspur_drm_private *priv =
	    (struct inspur_drm_private *)dev->dev_private;
	u32 status;

	status = readl(priv->mmio + INSPUR_RAW_INTERRUPT);

	if (status & INSPUR_RAW_INTERRUPT_VBLANK(1)) {
		writel(INSPUR_RAW_INTERRUPT_VBLANK(1),
		       priv->mmio + INSPUR_RAW_INTERRUPT);
		drm_handle_vblank(dev, 0);
	}

	return IRQ_HANDLED;
}

static void inspur_remove_framebuffers(struct pci_dev *pdev)
{
	struct apertures_struct *ap;
	bool primary = false;

	ap = alloc_apertures(1);
	if (!ap)
		return;

	ap->ranges[0].base = pci_resource_start(pdev, 0);
	ap->ranges[0].size = pci_resource_len(pdev, 0);

#ifdef CONFIG_X86
	primary =
	    pdev->resource[PCI_ROM_RESOURCE].flags & IORESOURCE_ROM_SHADOW;
#endif
	drm_fb_helper_remove_conflicting_framebuffers(ap, "inspurdrmfb",
						      primary);

	kfree(ap);
}

static struct drm_driver inspur_driver = {
	.driver_features = DRIVER_GEM | DRIVER_MODESET | DRIVER_ATOMIC,
	.load = inspur_load,
	.unload = inspur_unload,
	.fops = &inspur_fops,
	.name = "inspur",
	.date = "20230912",
	.desc = "inspur drm driver",
	.major = 3,
	.minor = 0,
	.gem_free_object_unlocked = inspur_gem_free_object,
	.dumb_create = inspur_dumb_create,
	.dumb_map_offset = inspur_dumb_mmap_offset,
	.irq_handler = inspur_drm_interrupt,
};

static int __maybe_unused inspur_pm_suspend(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct drm_device *drm_dev = pci_get_drvdata(pdev);

	return drm_mode_config_helper_suspend(drm_dev);
}

static int __maybe_unused inspur_pm_resume(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct drm_device *drm_dev = pci_get_drvdata(pdev);

	return drm_mode_config_helper_resume(drm_dev);

}

static const struct dev_pm_ops inspur_pm_ops = {
	SET_SYSTEM_SLEEP_PM_OPS(inspur_pm_suspend,
				inspur_pm_resume)
};

static int inspur_kms_init(struct inspur_drm_private *priv)
{
	int ret;

	drm_mode_config_init(priv->dev);
	priv->mode_config_initialized = true;

	priv->dev->mode_config.min_width = 0;
	priv->dev->mode_config.min_height = 0;
	priv->dev->mode_config.max_width = 1920;
	priv->dev->mode_config.max_height = 1200;

	priv->dev->mode_config.fb_base = priv->fb_base;
	priv->dev->mode_config.preferred_depth = 32;
	priv->dev->mode_config.prefer_shadow = 1;
	priv->dev->mode_config.funcs = (void *)&inspur_mode_funcs;

	ret = inspur_de_init(priv);
	if (ret) {
		DRM_ERROR("failed to init de: %d\n", ret);
		return ret;
	}

	ret = inspur_vdac_init(priv);
	if (ret) {
		DRM_ERROR("failed to init vdac: %d\n", ret);
		return ret;
	}

	return 0;
}

static void inspur_kms_fini(struct inspur_drm_private *priv)
{
	if (priv->mode_config_initialized) {
		drm_mode_config_cleanup(priv->dev);
		priv->mode_config_initialized = false;
	}
}

/*
 * It can operate in one of three modes: 0, 1 or Sleep.
 */
void inspur_set_power_mode(struct inspur_drm_private *priv,
			   unsigned int power_mode)
{
	unsigned int control_value = 0;
	void __iomem *mmio = priv->mmio;
	unsigned int input = 1;

	if (power_mode > INSPUR_PW_MODE_CTL_MODE_SLEEP)
		return;

	if (power_mode == INSPUR_PW_MODE_CTL_MODE_SLEEP)
		input = 0;

	control_value = readl(mmio + INSPUR_POWER_MODE_CTRL);
	control_value &= ~(INSPUR_PW_MODE_CTL_MODE_MASK |
			   INSPUR_PW_MODE_CTL_OSC_INPUT_MASK);
	control_value |= INSPUR_FIELD(INSPUR_PW_MODE_CTL_MODE, power_mode);
	control_value |= INSPUR_FIELD(INSPUR_PW_MODE_CTL_OSC_INPUT, input);
	writel(control_value, mmio + INSPUR_POWER_MODE_CTRL);
}

void inspur_set_current_gate(struct inspur_drm_private *priv, unsigned int gate)
{
	unsigned int gate_reg;
	unsigned int mode;
	void __iomem *mmio = priv->mmio;

	/* Get current power mode. */
	mode = (readl(mmio + INSPUR_POWER_MODE_CTRL) &
		INSPUR_PW_MODE_CTL_MODE_MASK) >> INSPUR_PW_MODE_CTL_MODE_SHIFT;

	switch (mode) {
	case INSPUR_PW_MODE_CTL_MODE_MODE0:
		gate_reg = INSPUR_MODE0_GATE;
		break;

	case INSPUR_PW_MODE_CTL_MODE_MODE1:
		gate_reg = INSPUR_MODE1_GATE;
		break;

	default:
		gate_reg = INSPUR_MODE0_GATE;
		break;
	}
	writel(gate, mmio + gate_reg);
}

static void inspur_hw_config(struct inspur_drm_private *priv)
{
	unsigned int reg;

	/* On hardware reset, power mode 0 is default. */
	inspur_set_power_mode(priv, INSPUR_PW_MODE_CTL_MODE_MODE0);

	/* Enable display power gate & LOCALMEM power gate */
	reg = readl(priv->mmio + INSPUR_CURRENT_GATE);
	reg &= ~INSPUR_CURR_GATE_DISPLAY_MASK;
	reg &= ~INSPUR_CURR_GATE_LOCALMEM_MASK;
	reg |= INSPUR_CURR_GATE_DISPLAY(1);
	reg |= INSPUR_CURR_GATE_LOCALMEM(1);

	inspur_set_current_gate(priv, reg);

	/*
	 * Reset the memory controller. If the memory controller
	 * is not reset in chip,the system might hang when sw accesses
	 * the memory.The memory should be resetted after
	 * changing the MXCLK.
	 */
	reg = readl(priv->mmio + INSPUR_MISC_CTRL);
	reg &= ~INSPUR_MSCCTL_LOCALMEM_RESET_MASK;
	reg |= INSPUR_MSCCTL_LOCALMEM_RESET(0);
	writel(reg, priv->mmio + INSPUR_MISC_CTRL);

	reg &= ~INSPUR_MSCCTL_LOCALMEM_RESET_MASK;
	reg |= INSPUR_MSCCTL_LOCALMEM_RESET(1);

	writel(reg, priv->mmio + INSPUR_MISC_CTRL);
}

static int inspur_hw_map(struct inspur_drm_private *priv)
{
	struct drm_device *dev = priv->dev;
	struct pci_dev *pdev = dev->pdev;
	resource_size_t addr, size, ioaddr, iosize;

	ioaddr = pci_resource_start(pdev, 1);
	iosize = pci_resource_len(pdev, 1);
	priv->mmio = devm_ioremap_nocache(dev->dev, ioaddr, iosize);
	if (!priv->mmio) {
		DRM_ERROR("Cannot map mmio region\n");
		return -ENOMEM;
	}

	addr = pci_resource_start(pdev, 0);
	size = pci_resource_len(pdev, 0);
	priv->fb_map = devm_ioremap(dev->dev, addr, size);
	if (!priv->fb_map) {
		DRM_ERROR("Cannot map framebuffer\n");
		return -ENOMEM;
	}
	priv->fb_base = addr;
	priv->fb_size = size - MEM_SIZE_RESERVE4KVM;

	return 0;
}

static int inspur_hw_init(struct inspur_drm_private *priv)
{
	int ret;

	ret = inspur_hw_map(priv);
	if (ret)
		return ret;

	inspur_hw_config(priv);

	return 0;
}

void inspur_unload(struct drm_device *dev)
{
	struct inspur_drm_private *priv = dev->dev_private;

	inspur_fbdev_fini(priv);

	drm_atomic_helper_shutdown(dev);

	if (dev->irq_enabled)
		drm_irq_uninstall(dev);

	inspur_kms_fini(priv);
	inspur_mm_fini(priv);
	dev->dev_private = NULL;
}

int inspur_load(struct drm_device *dev, unsigned long flags)
{
	struct inspur_drm_private *priv;
	int ret;

	priv = devm_kzalloc(dev->dev, sizeof(*priv), GFP_KERNEL);
	if (!priv) {
		DRM_ERROR("no memory to allocate for inspur_drm_private\n");
		return -ENOMEM;
	}
	dev->dev_private = priv;
	priv->dev = dev;

	ret = inspur_hw_init(priv);
	if (ret)
		goto err;

	ret = inspur_mm_init(priv);
	if (ret)
		goto err;

	ret = inspur_kms_init(priv);
	if (ret)
		goto err;

	/* reset all the states of crtc/plane/encoder/connector */
	drm_mode_config_reset(dev);

	ret = inspur_fbdev_init(priv);
	if (ret) {
		DRM_ERROR("failed to initialize fbdev: %d\n", ret);
		goto err;
	}

	return 0;

err:
	inspur_unload(dev);
	DRM_ERROR("failed to initialize drm driver: %d\n", ret);
	return ret;
}

static int inspur_pci_probe(struct pci_dev *pdev,
			    const struct pci_device_id *ent)
{

	inspur_remove_framebuffers(pdev);

	return drm_get_pci_dev(pdev, ent, &inspur_driver);
}

static void inspur_pci_remove(struct pci_dev *pdev)
{
	struct drm_device *dev = pci_get_drvdata(pdev);

	drm_put_dev(dev);
	pci_disable_device(pdev);
}

static void inspur_pci_shutdown(struct pci_dev *pdev)
{
	inspur_pci_remove(pdev);
}

static struct pci_device_id inspur_pci_table[] = {
	{ 0x1bd4, 0x0750, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0 },
	{ 0, }
};

static struct pci_driver inspur_pci_driver = {
	.name = "inspur-drm",
	.id_table = inspur_pci_table,
	.probe = inspur_pci_probe,
	.remove = inspur_pci_remove,
	.shutdown = inspur_pci_shutdown,
	.driver.pm = &inspur_pm_ops,
};

static int __init inspur_init(void)
{
	return pci_register_driver(&inspur_pci_driver);
}

static void __exit inspur_exit(void)
{
	return pci_unregister_driver(&inspur_pci_driver);
}

module_init(inspur_init);
module_exit(inspur_exit);

MODULE_DEVICE_TABLE(pci, inspur_pci_table);
MODULE_AUTHOR("");
MODULE_DESCRIPTION("DRM Driver for InspurBMC");
MODULE_LICENSE("GPL v2");
MODULE_VERSION("3.0");
