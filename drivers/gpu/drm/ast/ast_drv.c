/*
 * Copyright 2012 Red Hat Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sub license, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDERS, AUTHORS AND/OR ITS SUPPLIERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
 * USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * The above copyright notice and this permission notice (including the
 * next paragraph) shall be included in all copies or substantial portions
 * of the Software.
 *
 */
/*
 * Authors: Dave Airlie <airlied@redhat.com>
 */

#include <linux/module.h>
#include <linux/pci.h>

#include <drm/drm_aperture.h>
#include <drm/drm_atomic_helper.h>
#include <drm/drm_drv.h>
#include <drm/drm_fbdev_generic.h>
#include <drm/drm_gem_shmem_helper.h>
#include <drm/drm_module.h>
#include <drm/drm_probe_helper.h>

#include "ast_drv.h"

static int ast_modeset = -1;

MODULE_PARM_DESC(modeset, "Disable/Enable modesetting");
module_param_named(modeset, ast_modeset, int, 0400);

/*
 * DRM driver
 */

DEFINE_DRM_GEM_FOPS(ast_fops);

#define DRM_AST_VRAM_TYPE_DEVICE 0x0
#define DRM_IOCTL_AST_VRAM_TYPE_DEVICE	DRM_IO(DRM_COMMAND_BASE\
	+ DRM_AST_VRAM_TYPE_DEVICE)

static int ast_ioctl_check_5c01_device(struct drm_device *dev, void *data,
				struct drm_file *file_priv)
{
	struct ast_device *ast = to_ast_device(dev);

	return ast->is_5c01_device ? 1 : 0;
}

static const struct drm_ioctl_desc ast_ioctls[] = {
	/* for test, none so far */
	DRM_IOCTL_DEF_DRV(AST_VRAM_TYPE_DEVICE, ast_ioctl_check_5c01_device,
						DRM_AUTH|DRM_UNLOCKED),
};

static const struct drm_driver ast_driver = {
	.driver_features = DRIVER_ATOMIC |
			   DRIVER_GEM |
			   DRIVER_MODESET,

	.ioctls = ast_ioctls,
	.num_ioctls = ARRAY_SIZE(ast_ioctls),
	.fops = &ast_fops,
	.name = DRIVER_NAME,
	.desc = DRIVER_DESC,
	.date = DRIVER_DATE,
	.major = DRIVER_MAJOR,
	.minor = DRIVER_MINOR,
	.patchlevel = DRIVER_PATCHLEVEL,

	DRM_GEM_SHMEM_DRIVER_OPS
};

/*
 * PCI driver
 */

#define PCI_VENDOR_ASPEED 0x1a03

#define AST_VGA_DEVICE(id, info) {		\
	.class = PCI_BASE_CLASS_DISPLAY << 16,	\
	.class_mask = 0xff0000,			\
	.vendor = PCI_VENDOR_ASPEED,			\
	.device = id,				\
	.subvendor = PCI_ANY_ID,		\
	.subdevice = PCI_ANY_ID,		\
	.driver_data = (unsigned long) info }

static const struct pci_device_id ast_pciidlist[] = {
	AST_VGA_DEVICE(PCI_CHIP_AST2000, NULL),
	AST_VGA_DEVICE(PCI_CHIP_AST2100, NULL),
	{0, 0, 0},
};

MODULE_DEVICE_TABLE(pci, ast_pciidlist);

static int ast_pci_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	struct ast_device *ast;
	struct drm_device *dev;
	int ret;

	ret = drm_aperture_remove_conflicting_pci_framebuffers(pdev, &ast_driver);
	if (ret)
		return ret;

	ret = pcim_enable_device(pdev);
	if (ret)
		return ret;

	ast = ast_device_create(&ast_driver, pdev, ent->driver_data);
	if (IS_ERR(ast))
		return PTR_ERR(ast);
	dev = &ast->base;

	ret = drm_dev_register(dev, ent->driver_data);
	if (ret)
		return ret;

	drm_fbdev_generic_setup(dev, 32);

	return 0;
}

static void ast_pci_remove(struct pci_dev *pdev)
{
	struct drm_device *dev = pci_get_drvdata(pdev);

	drm_dev_unregister(dev);
	drm_atomic_helper_shutdown(dev);
}

static int ast_drm_freeze(struct drm_device *dev)
{
	int error;

	error = drm_mode_config_helper_suspend(dev);
	if (error)
		return error;
	pci_save_state(to_pci_dev(dev->dev));
	return 0;
}

static int ast_drm_thaw(struct drm_device *dev)
{
	ast_post_gpu(dev);

	return drm_mode_config_helper_resume(dev);
}

static int ast_drm_resume(struct drm_device *dev)
{
	if (pci_enable_device(to_pci_dev(dev->dev)))
		return -EIO;

	return ast_drm_thaw(dev);
}

static int ast_pm_suspend(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct drm_device *ddev = pci_get_drvdata(pdev);
	int error;

	error = ast_drm_freeze(ddev);
	if (error)
		return error;

	pci_disable_device(pdev);
	pci_set_power_state(pdev, PCI_D3hot);
	return 0;
}

static int ast_pm_resume(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct drm_device *ddev = pci_get_drvdata(pdev);
	return ast_drm_resume(ddev);
}

static int ast_pm_freeze(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct drm_device *ddev = pci_get_drvdata(pdev);
	return ast_drm_freeze(ddev);
}

static int ast_pm_thaw(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct drm_device *ddev = pci_get_drvdata(pdev);
	return ast_drm_thaw(ddev);
}

static int ast_pm_poweroff(struct device *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct drm_device *ddev = pci_get_drvdata(pdev);

	return ast_drm_freeze(ddev);
}

static const struct dev_pm_ops ast_pm_ops = {
	.suspend = ast_pm_suspend,
	.resume = ast_pm_resume,
	.freeze = ast_pm_freeze,
	.thaw = ast_pm_thaw,
	.poweroff = ast_pm_poweroff,
	.restore = ast_pm_resume,
};

static struct pci_driver ast_pci_driver = {
	.name = DRIVER_NAME,
	.id_table = ast_pciidlist,
	.probe = ast_pci_probe,
	.remove = ast_pci_remove,
	.driver.pm = &ast_pm_ops,
};

drm_module_pci_driver_if_modeset(ast_pci_driver, ast_modeset);

MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
MODULE_LICENSE("GPL and additional rights");
