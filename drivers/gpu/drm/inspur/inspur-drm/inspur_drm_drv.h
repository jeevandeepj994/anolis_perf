/* SPDX-License-Identifier: GPL-2.0 */

#ifndef INSPUR_DRM_DRV_H
#define INSPUR_DRM_DRV_H

#include <drm/drmP.h>
#include <drm/drm_atomic.h>
#include <drm/drm_fb_helper.h>
#include <drm/drm_gem.h>
#include <drm/ttm/ttm_bo_driver.h>

struct inspur_framebuffer {
	struct drm_framebuffer fb;
	struct drm_gem_object *obj;
};

struct inspur_fbdev {
	struct drm_fb_helper helper;
	struct inspur_framebuffer *fb;
	int size;
};

struct inspur_cursor {
	struct inspur_bo *cursor_1;
	struct inspur_bo *cursor_2;
	struct inspur_bo *cursor_current;
};

struct inspur_drm_private {
	/* hw */
	void __iomem *mmio;
	void __iomem *fb_map;
	unsigned long fb_base;
	unsigned long fb_size;

	/* drm */
	struct drm_device *dev;
	bool mode_config_initialized;

	/* ttm */
	struct drm_global_reference mem_global_ref;
	struct ttm_bo_global_ref bo_global_ref;
	struct ttm_bo_device bdev;
	bool initialized;

	/* fbdev */
	struct inspur_fbdev *fbdev;
	bool mm_inited;

	/* hw cursor */
	struct inspur_cursor cursor;
};

#define to_inspur_framebuffer(x) container_of(x, struct inspur_framebuffer, fb)

struct inspur_bo {
	struct ttm_buffer_object bo;
	struct ttm_placement placement;
	struct ttm_bo_kmap_obj kmap;
	struct drm_gem_object gem;
	struct ttm_place placements[3];
	int pin_count;
};

static inline struct inspur_bo *inspur_bo(struct ttm_buffer_object *bo)
{
	return container_of(bo, struct inspur_bo, bo);
}

static inline struct inspur_bo *gem_to_inspur_bo(struct drm_gem_object *gem)
{
	return container_of(gem, struct inspur_bo, gem);
}

void inspur_set_power_mode(struct inspur_drm_private *priv,
			   unsigned int power_mode);
void inspur_set_current_gate(struct inspur_drm_private *priv,
			     unsigned int gate);
int inspur_load(struct drm_device *dev, unsigned long flags);
void inspur_unload(struct drm_device *dev);

int inspur_de_init(struct inspur_drm_private *priv);
int inspur_vdac_init(struct inspur_drm_private *priv);
int inspur_fbdev_init(struct inspur_drm_private *priv);
void inspur_fbdev_fini(struct inspur_drm_private *priv);

int inspur_gem_create(struct drm_device *dev, u32 size, bool iskernel,
		      struct drm_gem_object **obj);
struct inspur_framebuffer *inspur_framebuffer_init(struct drm_device *dev,
						   const struct drm_mode_fb_cmd2
						   *mode_cmd,
						   struct drm_gem_object *obj);

int inspur_mm_init(struct inspur_drm_private *inspur);
void inspur_mm_fini(struct inspur_drm_private *inspur);
int inspur_bo_pin(struct inspur_bo *bo, u32 pl_flag, u64 *gpu_addr);
int inspur_bo_unpin(struct inspur_bo *bo);
void inspur_gem_free_object(struct drm_gem_object *obj);
int inspur_bo_create(struct drm_device *dev, int size, int align, u32 flags,
		     struct inspur_bo **phibmcbo);
int inspur_dumb_create(struct drm_file *file, struct drm_device *dev,
		       struct drm_mode_create_dumb *args);
int inspur_dumb_mmap_offset(struct drm_file *file, struct drm_device *dev,
			    u32 handle, u64 *offset);
int inspur_mmap(struct file *filp, struct vm_area_struct *vma);

extern const struct drm_mode_config_funcs inspur_mode_funcs;

#endif
