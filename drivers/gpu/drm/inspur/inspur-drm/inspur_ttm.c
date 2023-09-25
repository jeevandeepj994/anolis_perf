// SPDX-License-Identifier: GPL-2.0

#include <drm/drm_atomic_helper.h>
#include <drm/ttm/ttm_page_alloc.h>

#include "inspur_drm_drv.h"

#define DRM_FILE_PAGE_OFFSET (0x100000000ULL >> PAGE_SHIFT)

static inline struct inspur_drm_private *inspur_bdev(struct ttm_bo_device *bd)
{
	return container_of(bd, struct inspur_drm_private, bdev);
}

static int inspur_ttm_mem_global_init(struct drm_global_reference *ref)
{
	return ttm_mem_global_init(ref->object);
}

static void inspur_ttm_mem_global_release(struct drm_global_reference *ref)
{
	ttm_mem_global_release(ref->object);
}

static int inspur_ttm_global_init(struct inspur_drm_private *inspur)
{
	int ret;

	inspur->mem_global_ref.global_type = DRM_GLOBAL_TTM_MEM;
	inspur->mem_global_ref.size = sizeof(struct ttm_mem_global);
	inspur->mem_global_ref.init = &inspur_ttm_mem_global_init;
	inspur->mem_global_ref.release = &inspur_ttm_mem_global_release;
	ret = drm_global_item_ref(&inspur->mem_global_ref);
	if (ret) {
		DRM_ERROR("could not get ref on ttm global: %d\n", ret);
		return ret;
	}

	inspur->bo_global_ref.mem_glob = inspur->mem_global_ref.object;
	inspur->bo_global_ref.ref.global_type = DRM_GLOBAL_TTM_BO;
	inspur->bo_global_ref.ref.size = sizeof(struct ttm_bo_global);
	inspur->bo_global_ref.ref.init = &ttm_bo_global_init;
	inspur->bo_global_ref.ref.release = &ttm_bo_global_release;
	ret = drm_global_item_ref(&inspur->bo_global_ref.ref);
	if (ret) {
		DRM_ERROR("failed setting up TTM BO subsystem: %d\n", ret);
		drm_global_item_unref(&inspur->mem_global_ref);
		return ret;
	}
	return 0;
}

static void inspur_ttm_global_release(struct inspur_drm_private *inspur)
{
	drm_global_item_unref(&inspur->bo_global_ref.ref);
	drm_global_item_unref(&inspur->mem_global_ref);
	inspur->mem_global_ref.release = NULL;
}

static void inspur_bo_ttm_destroy(struct ttm_buffer_object *tbo)
{
	struct inspur_bo *bo = container_of(tbo, struct inspur_bo, bo);

	drm_gem_object_release(&bo->gem);
	kfree(bo);
}

static bool inspur_ttm_bo_is_inspur_bo(struct ttm_buffer_object *bo)
{
	return bo->destroy == &inspur_bo_ttm_destroy;
}

static int
inspur_bo_init_mem_type(struct ttm_bo_device *bdev, u32 type,
			struct ttm_mem_type_manager *man)
{
	switch (type) {
	case TTM_PL_SYSTEM:
		man->flags = TTM_MEMTYPE_FLAG_MAPPABLE;
		man->available_caching = TTM_PL_MASK_CACHING;
		man->default_caching = TTM_PL_FLAG_CACHED;
		break;
	case TTM_PL_VRAM:
		man->func = &ttm_bo_manager_func;
		man->flags = TTM_MEMTYPE_FLAG_FIXED | TTM_MEMTYPE_FLAG_MAPPABLE;
		man->available_caching = TTM_PL_FLAG_UNCACHED | TTM_PL_FLAG_WC;
		man->default_caching = TTM_PL_FLAG_WC;
		break;
	default:
		DRM_ERROR("unsupported memory type %u\n", type);
		return -EINVAL;
	}
	return 0;
}

void inspur_ttm_placement(struct inspur_bo *bo, int domain)
{
	u32 count = 0;
	u32 i;

	bo->placement.placement = bo->placements;
	bo->placement.busy_placement = bo->placements;
	if (domain & TTM_PL_FLAG_VRAM)
		bo->placements[count++].flags = TTM_PL_FLAG_WC |
		    TTM_PL_FLAG_UNCACHED | TTM_PL_FLAG_VRAM;
	if (domain & TTM_PL_FLAG_SYSTEM)
		bo->placements[count++].flags = TTM_PL_MASK_CACHING |
		    TTM_PL_FLAG_SYSTEM;
	if (!count)
		bo->placements[count++].flags = TTM_PL_MASK_CACHING |
		    TTM_PL_FLAG_SYSTEM;

	bo->placement.num_placement = count;
	bo->placement.num_busy_placement = count;
	for (i = 0; i < count; i++) {
		bo->placements[i].fpfn = 0;
		bo->placements[i].lpfn = 0;
	}
}

static void
inspur_bo_evict_flags(struct ttm_buffer_object *bo, struct ttm_placement *pl)
{
	struct inspur_bo *inspurbo = inspur_bo(bo);

	if (!inspur_ttm_bo_is_inspur_bo(bo))
		return;

	inspur_ttm_placement(inspurbo, TTM_PL_FLAG_SYSTEM);
	*pl = inspurbo->placement;
}

static int inspur_bo_verify_access(struct ttm_buffer_object *bo,
				   struct file *filp)
{
	struct inspur_bo *inspurbo = inspur_bo(bo);

	return drm_vma_node_verify_access(&inspurbo->gem.vma_node,
					  filp->private_data);
}

static int inspur_ttm_io_mem_reserve(struct ttm_bo_device *bdev,
				     struct ttm_mem_reg *mem)
{
	struct ttm_mem_type_manager *man = &bdev->man[mem->mem_type];
	struct inspur_drm_private *inspur = inspur_bdev(bdev);

	mem->bus.addr = NULL;
	mem->bus.offset = 0;
	mem->bus.size = mem->num_pages << PAGE_SHIFT;
	mem->bus.base = 0;
	mem->bus.is_iomem = false;
	if (!(man->flags & TTM_MEMTYPE_FLAG_MAPPABLE))
		return -EINVAL;
	switch (mem->mem_type) {
	case TTM_PL_SYSTEM:
		/* system memory */
		return 0;
	case TTM_PL_VRAM:
		mem->bus.offset = mem->start << PAGE_SHIFT;
		mem->bus.base = pci_resource_start(inspur->dev->pdev, 0);
		mem->bus.is_iomem = true;
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

static void inspur_ttm_backend_destroy(struct ttm_tt *tt)
{
	ttm_tt_fini(tt);
	kfree(tt);
}

static struct ttm_backend_func inspur_tt_backend_func = {
	.destroy = &inspur_ttm_backend_destroy,
};

static struct ttm_tt *inspur_ttm_tt_create(struct ttm_buffer_object *bo,
					   uint32_t page_flags)
{
	struct ttm_tt *tt;
	int ret;

	tt = kzalloc(sizeof(*tt), GFP_KERNEL);
	if (!tt) {
		DRM_ERROR("failed to allocate ttm_tt\n");
		return NULL;
	}
	tt->func = &inspur_tt_backend_func;
	ret = ttm_tt_init(tt, bo, page_flags);
	if (ret) {
		DRM_ERROR("failed to initialize ttm_tt: %d\n", ret);
		kfree(tt);
		return NULL;
	}
	return tt;
}

static int inspur_ttm_tt_populate(struct ttm_tt *ttm,
				  struct ttm_operation_ctx *ctx)
{
	return ttm_pool_populate(ttm, ctx);
}

static void inspur_ttm_tt_unpopulate(struct ttm_tt *ttm)
{
	ttm_pool_unpopulate(ttm);
}

struct ttm_bo_driver inspur_bo_driver = {
	.ttm_tt_create = inspur_ttm_tt_create,
	.ttm_tt_populate = inspur_ttm_tt_populate,
	.ttm_tt_unpopulate = inspur_ttm_tt_unpopulate,
	.init_mem_type = inspur_bo_init_mem_type,
	.evict_flags = inspur_bo_evict_flags,
	.move = NULL,
	.verify_access = inspur_bo_verify_access,
	.io_mem_reserve = &inspur_ttm_io_mem_reserve,
	.io_mem_free = NULL,
};

int inspur_mm_init(struct inspur_drm_private *inspur)
{
	int ret;
	struct drm_device *dev = inspur->dev;
	struct ttm_bo_device *bdev = &inspur->bdev;

	ret = inspur_ttm_global_init(inspur);
	if (ret)
		return ret;

	ret = ttm_bo_device_init(&inspur->bdev,
				 inspur->bo_global_ref.ref.object,
				 &inspur_bo_driver,
				 dev->anon_inode->i_mapping,
				 DRM_FILE_PAGE_OFFSET, true);
	if (ret) {
		inspur_ttm_global_release(inspur);
		DRM_ERROR("error initializing bo driver: %d\n", ret);
		return ret;
	}

	ret = ttm_bo_init_mm(bdev, TTM_PL_VRAM, inspur->fb_size >> PAGE_SHIFT);
	if (ret) {
		inspur_ttm_global_release(inspur);
		DRM_ERROR("failed ttm VRAM init: %d\n", ret);
		return ret;
	}

	inspur->mm_inited = true;
	return 0;
}

void inspur_mm_fini(struct inspur_drm_private *inspur)
{
	if (!inspur->mm_inited)
		return;

	ttm_bo_device_release(&inspur->bdev);
	inspur_ttm_global_release(inspur);
	inspur->mm_inited = false;
}

static void inspur_bo_unref(struct inspur_bo **bo)
{
	struct ttm_buffer_object *tbo;

	if ((*bo) == NULL)
		return;

	tbo = &((*bo)->bo);
	ttm_bo_put(tbo);
	*bo = NULL;
}

int inspur_bo_create(struct drm_device *dev, int size, int align,
		     u32 flags, struct inspur_bo **pinspurbo)
{
	struct inspur_drm_private *inspur = dev->dev_private;
	struct inspur_bo *inspurbo;
	size_t acc_size;
	int ret;

	inspurbo = kzalloc(sizeof(*inspurbo), GFP_KERNEL);
	if (!inspurbo) {
		DRM_ERROR("failed to allocate inspurbo\n");
		return -ENOMEM;
	}
	ret = drm_gem_object_init(dev, &inspurbo->gem, size);
	if (ret) {
		DRM_ERROR("failed to initialize drm gem object: %d\n", ret);
		kfree(inspurbo);
		return ret;
	}

	inspurbo->bo.bdev = &inspur->bdev;

	inspur_ttm_placement(inspurbo, TTM_PL_FLAG_VRAM | TTM_PL_FLAG_SYSTEM);

	acc_size = ttm_bo_dma_acc_size(&inspur->bdev, size,
				       sizeof(struct inspur_bo));

	ret = ttm_bo_init(&inspur->bdev, &inspurbo->bo, size,
			  ttm_bo_type_device, &inspurbo->placement,
			  align >> PAGE_SHIFT, false, acc_size,
			  NULL, NULL, inspur_bo_ttm_destroy);
	if (ret) {
		inspur_bo_unref(&inspurbo);
		DRM_ERROR("failed to initialize ttm_bo: %d\n", ret);
		return ret;
	}

	*pinspurbo = inspurbo;
	return 0;
}

int inspur_bo_pin(struct inspur_bo *bo, u32 pl_flag, u64 *gpu_addr)
{

	int i, ret;
	struct ttm_operation_ctx ctx = { false, false };

	if (bo->pin_count) {
		bo->pin_count++;
		if (gpu_addr)
			*gpu_addr = bo->bo.offset;
		return 0;
	}

	inspur_ttm_placement(bo, pl_flag);
	for (i = 0; i < bo->placement.num_placement; i++)
		bo->placements[i].flags |= TTM_PL_FLAG_NO_EVICT;
	ret = ttm_bo_validate(&bo->bo, &bo->placement, &ctx);
	if (ret)
		return ret;

	bo->pin_count = 1;
	if (gpu_addr)
		*gpu_addr = bo->bo.offset;
	return 0;
}

int inspur_bo_unpin(struct inspur_bo *bo)
{
	int i, ret;
	struct ttm_operation_ctx ctx = { false, false };

	if (!bo->pin_count) {
		DRM_ERROR("unpin bad %p\n", bo);
		return 0;
	}
	bo->pin_count--;
	if (bo->pin_count)
		return 0;

	for (i = 0; i < bo->placement.num_placement; i++)
		bo->placements[i].flags &= ~TTM_PL_FLAG_NO_EVICT;
	ret = ttm_bo_validate(&bo->bo, &bo->placement, &ctx);
	if (ret) {
		DRM_ERROR("validate failed for unpin: %d\n", ret);
		return ret;
	}

	return 0;
}

int inspur_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct drm_file *file_priv;
	struct inspur_drm_private *inspur;

	if (unlikely(vma->vm_pgoff < DRM_FILE_PAGE_OFFSET))
		return -EINVAL;

	file_priv = filp->private_data;
	inspur = file_priv->minor->dev->dev_private;
	return ttm_bo_mmap(filp, vma, &inspur->bdev);
}

int inspur_gem_create(struct drm_device *dev, u32 size, bool iskernel,
		      struct drm_gem_object **obj)
{
	struct inspur_bo *inspurbo;
	int ret;

	*obj = NULL;

	size = PAGE_ALIGN(size);
	if (size == 0) {
		DRM_ERROR("error: zero size\n");
		return -EINVAL;
	}

	ret = inspur_bo_create(dev, size, 0, 0, &inspurbo);
	if (ret) {
		if (ret != -ERESTARTSYS)
			DRM_ERROR("failed to allocate GEM object: %d\n", ret);
		return ret;
	}
	*obj = &inspurbo->gem;
	return 0;
}

int inspur_dumb_create(struct drm_file *file, struct drm_device *dev,
		       struct drm_mode_create_dumb *args)
{
	struct drm_gem_object *gobj;
	u32 handle;
	int ret;

	args->pitch = ALIGN(args->width * DIV_ROUND_UP(args->bpp, 8), 16);
	args->size = args->pitch * args->height;

	ret = inspur_gem_create(dev, args->size, false, &gobj);
	if (ret) {
		DRM_ERROR("failed to create GEM object: %d\n", ret);
		return ret;
	}

	ret = drm_gem_handle_create(file, gobj, &handle);
	drm_gem_object_put_unlocked(gobj);
	if (ret) {
		DRM_ERROR("failed to unreference GEM object: %d\n", ret);
		return ret;
	}

	args->handle = handle;
	return 0;
}

void inspur_gem_free_object(struct drm_gem_object *obj)
{
	struct inspur_bo *inspurbo = gem_to_inspur_bo(obj);

	inspur_bo_unref(&inspurbo);
}

static u64 inspur_bo_mmap_offset(struct inspur_bo *bo)
{
	return drm_vma_node_offset_addr(&bo->bo.vma_node);
}

int inspur_dumb_mmap_offset(struct drm_file *file, struct drm_device *dev,
			    u32 handle, u64 *offset)
{
	struct drm_gem_object *obj;
	struct inspur_bo *bo;

	obj = drm_gem_object_lookup(file, handle);
	if (!obj)
		return -ENOENT;

	bo = gem_to_inspur_bo(obj);
	*offset = inspur_bo_mmap_offset(bo);

	drm_gem_object_put_unlocked(obj);
	return 0;
}

static void inspur_user_framebuffer_destroy(struct drm_framebuffer *fb)
{
	struct inspur_framebuffer *inspur_fb = to_inspur_framebuffer(fb);

	drm_gem_object_put_unlocked(inspur_fb->obj);
	drm_framebuffer_cleanup(fb);
	kfree(inspur_fb);
}

static const struct drm_framebuffer_funcs inspur_fb_funcs = {
	.destroy = inspur_user_framebuffer_destroy,
};

struct inspur_framebuffer *inspur_framebuffer_init(struct drm_device *dev,
						   const struct drm_mode_fb_cmd2
						   *mode_cmd,
						   struct drm_gem_object *obj)
{
	struct inspur_framebuffer *inspur_fb;
	int ret;

	inspur_fb = kzalloc(sizeof(*inspur_fb), GFP_KERNEL);
	if (!inspur_fb) {
		DRM_ERROR("failed to allocate inspur_fb\n");
		return ERR_PTR(-ENOMEM);
	}

	drm_helper_mode_fill_fb_struct(dev, &inspur_fb->fb, mode_cmd);
	inspur_fb->obj = obj;
	ret = drm_framebuffer_init(dev, &inspur_fb->fb, &inspur_fb_funcs);
	if (ret) {
		DRM_ERROR("drm_framebuffer_init failed: %d\n", ret);
		kfree(inspur_fb);
		return ERR_PTR(ret);
	}

	return inspur_fb;
}

static struct drm_framebuffer *inspur_user_framebuffer_create(struct drm_device
							      *dev,
							      struct drm_file
							      *filp,
							      const struct
							      drm_mode_fb_cmd2
							      *mode_cmd)
{
	struct drm_gem_object *obj;
	struct inspur_framebuffer *inspur_fb;

	DRM_DEBUG_DRIVER("%dx%d, format %c%c%c%c\n",
			 mode_cmd->width, mode_cmd->height,
			 (mode_cmd->pixel_format) & 0xff,
			 (mode_cmd->pixel_format >> 8) & 0xff,
			 (mode_cmd->pixel_format >> 16) & 0xff,
			 (mode_cmd->pixel_format >> 24) & 0xff);

	obj = drm_gem_object_lookup(filp, mode_cmd->handles[0]);
	if (!obj)
		return ERR_PTR(-ENOENT);

	inspur_fb = inspur_framebuffer_init(dev, mode_cmd, obj);
	if (IS_ERR(inspur_fb)) {
		drm_gem_object_put_unlocked(obj);
		return ERR_PTR((long)inspur_fb);
	}
	return &inspur_fb->fb;
}

const struct drm_mode_config_funcs inspur_mode_funcs = {
	.atomic_check = drm_atomic_helper_check,
	.atomic_commit = drm_atomic_helper_commit,
	.fb_create = inspur_user_framebuffer_create,
};
