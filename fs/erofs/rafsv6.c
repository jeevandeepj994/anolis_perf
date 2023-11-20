// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021-2023, Alibaba Cloud
 */
#include <linux/uio.h>
#include <linux/file.h>
#include "internal.h"

static ssize_t rafs_v6_read_chunk(struct super_block *sb,
				  struct iov_iter *to, u64 off, u64 size,
				  unsigned int device_id)
{
	struct iov_iter titer;
	ssize_t read = 0;
	struct erofs_map_dev mdev = {
		.m_deviceid = device_id,
		.m_pa = off,
	};
	int err;

	err = erofs_map_dev(sb, &mdev);
	if (err)
		return err;
	off = mdev.m_pa;
	do {
		ssize_t ret;

		if (iov_iter_is_pipe(to)) {
			iov_iter_pipe(&titer, READ, to->pipe, size - read);

			ret = vfs_iter_read(mdev.m_fp, &titer, &off, 0);
			pr_debug("pipe ret %ld off %llu size %llu read %ld\n",
				 ret, off, size, read);
			if (ret <= 0) {
				pr_err("%s: pipe failed to read blob ret %ld\n", __func__, ret);
				return ret;
			}
		} else if (iov_iter_is_kvec(to)) {
			if (!to->kvec->iov_len) {
				iov_iter_advance(to, 0);
				continue;
			}

			iov_iter_kvec(&titer, READ, to->kvec, 1, size - read);

			ret = vfs_iter_read(mdev.m_fp, &titer, &off, 0);
			pr_debug("kvec ret %ld off %llu size %llu read %ld\n",
				 ret, off, size, read);
			if (ret <= 0) {
				pr_err("%s: kvec failed to read blob ret %ld\n", __func__, ret);
				return ret;
			}
		} else {
			struct iovec iovec = iov_iter_iovec(to);

			if (!to->iov->iov_len) {
				iov_iter_advance(to, 0);
				continue;
			}

			if (iovec.iov_len > size - read)
				iovec.iov_len = size - read;

			pr_debug("%s: off %llu size %llu iov_len %lu blob_index %u\n",
				 __func__, off, size, iovec.iov_len, device_id);

			/* TODO async */
			iov_iter_init(&titer, READ, &iovec, 1, iovec.iov_len);
			ret = vfs_iter_read(mdev.m_fp, &titer, &off, 0);
			if (ret <= 0) {
				pr_err("%s: iovec failed to read blob ret %ld\n", __func__, ret);
				return ret;
			} else if (ret < iovec.iov_len) {
				return read;
			}
		}
		iov_iter_advance(to, ret);
		read += ret;
	} while (read < size);

	return read;
}

static ssize_t rafs_v6_file_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	struct erofs_map_blocks map = { 0 };
	ssize_t bytes = 0;
	u64 total = min_t(u64, iov_iter_count(to),
			  inode->i_size - iocb->ki_pos);

	while (total) {
		erofs_off_t pos = iocb->ki_pos;
		u64 delta, size;
		ssize_t read;

		if (map.m_la < pos || map.m_la + map.m_llen >= pos) {
			int err;

			map.m_la = pos;
			err = erofs_map_blocks(inode, &map);
			if (err)
				return err;
			if (map.m_la >= inode->i_size)
				break;
		}
		delta = pos - map.m_la;
		size = min_t(u64, map.m_llen - delta, total);
		pr_debug("inode i_size %llu pa %llu delta %llu size %llu",
			 inode->i_size, map.m_pa, delta, size);
		read = rafs_v6_read_chunk(inode->i_sb, to, map.m_pa + delta,
					  size, map.m_deviceid);
		if (read <= 0 || read < size) {
			erofs_err(inode->i_sb,
				  "short read %ld pos %llu size %llu @ nid %llu",
				  read, pos, size, EROFS_I(inode)->nid);
			return read < 0 ? read : -EIO;
		}
		iocb->ki_pos += read;
		bytes += read;
		total -= read;
	}
	return bytes;
}

static vm_fault_t rafs_v6_filemap_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	struct inode *inode = file_inode(vma->vm_file);
	pgoff_t npages, orig_pgoff = vmf->pgoff;
	erofs_off_t pos;
	struct erofs_map_blocks map = {0};
	struct erofs_map_dev mdev;
	struct vm_area_struct lower_vma;
	int err;
	vm_fault_t ret;

	npages = DIV_ROUND_UP(i_size_read(inode), PAGE_SIZE);
	if (unlikely(orig_pgoff >= npages))
		return VM_FAULT_SIGBUS;

	memcpy(&lower_vma, vmf->vma, sizeof(lower_vma));
	WARN_ON_ONCE(lower_vma.vm_private_data != vma->vm_private_data);

	/* TODO: check if chunk is available for us to read. */
	map.m_la = orig_pgoff << PAGE_SHIFT;
	pos = map.m_la;
	err = erofs_map_blocks(inode, &map);
	if (err)
		return vmf_error(err);

	mdev = (struct erofs_map_dev) {
		.m_deviceid = map.m_deviceid,
		.m_pa = map.m_pa,
	};
	err = erofs_map_dev(inode->i_sb, &mdev);
	if (err)
		return vmf_error(err);

	lower_vma.vm_file = mdev.m_fp;
	vmf->pgoff = (mdev.m_pa + (pos - map.m_la)) >> PAGE_SHIFT;
	vmf->vma = &lower_vma; /* override vma temporarily */
	ret = EROFS_I(inode)->lower_vm_ops->fault(vmf);
	vmf->vma = vma;
	vmf->pgoff = orig_pgoff;
	return ret;
}

static void rafs_v6_vm_close(struct vm_area_struct *vma)
{
	struct inode *inode;

	if (!vma || !vma->vm_file) {
		WARN_ON_ONCE(1);
		return;
	}

	inode = file_inode(vma->vm_file);
	if (EROFS_I(inode)->lower_vm_ops && EROFS_I(inode)->lower_vm_ops->close)
		EROFS_I(inode)->lower_vm_ops->close(vma);

	WARN_ON(vma->vm_private_data);
}

static void rafs_v6_vm_open(struct vm_area_struct *vma)
{
	struct inode *inode;

	if (!vma || !vma->vm_file) {
		WARN_ON_ONCE(1);
		return;
	}

	inode = file_inode(vma->vm_file);
	if (EROFS_I(inode)->lower_vm_ops && EROFS_I(inode)->lower_vm_ops->open)
		EROFS_I(inode)->lower_vm_ops->open(vma);
}

static const struct vm_operations_struct rafs_v6_vm_ops = {
	.fault	= rafs_v6_filemap_fault,
	.close	= rafs_v6_vm_close,
	.open	= rafs_v6_vm_open,
};

static int rafs_v6_file_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct inode *inode = file_inode(file);
	struct erofs_inode *vi = EROFS_I(inode);
	const struct vm_operations_struct *lower_vm_ops;
	struct file *realfile = EROFS_I_SB(inode)->bootstrap;
	int ret;

	if (!realfile || !realfile->f_op->mmap) {
		pr_err("%s: no bootstrap or mmap\n", __func__);
		return -EOPNOTSUPP;
	}

	ret = call_mmap(EROFS_I_SB(inode)->bootstrap, vma);
	if (ret) {
		pr_err("%s: call_mmap failed ret %d\n", __func__, ret);
		return ret;
	}

	/* set fs's vm_ops which is used in fault(). */
	lower_vm_ops = vma->vm_ops;

	if (vi->lower_vm_ops && vi->lower_vm_ops != lower_vm_ops) {
		WARN_ON_ONCE(1);
		return -EOPNOTSUPP;
	}
	/* fault() must exist in order to proceed. */
	if (!lower_vm_ops || !lower_vm_ops->fault) {
		WARN_ON_ONCE(1);
		return -EOPNOTSUPP;
	}
	vi->lower_vm_ops = lower_vm_ops;
	vma->vm_flags &= ~VM_HUGEPAGE;	/* dont use huge page */
	vma->vm_ops = &rafs_v6_vm_ops;
	return 0;
}

const struct file_operations rafs_v6_file_ro_fops = {
	.llseek		= generic_file_llseek,
	.read_iter	= rafs_v6_file_read_iter,
	.mmap		= rafs_v6_file_mmap,
//	.mmap		= generic_file_readonly_mmap,
	.splice_read	= generic_file_splice_read,
};

static int rafs_v6_readpage(struct file *file, struct page *page)
{
	struct kvec iov = {
		.iov_base	= page_address(page),
	};
	struct inode *inode = page->mapping->host;
	struct super_block *sb = inode->i_sb;
	erofs_off_t pos = page->index << PAGE_SHIFT;
	struct erofs_map_blocks map = { .m_la = pos };
	struct erofs_map_dev mdev;
	struct kiocb kiocb;
	struct iov_iter iter;
	int err;

	err = erofs_map_blocks(inode, &map);
	if (err)
		goto err_out;

	mdev = (struct erofs_map_dev) {
		.m_deviceid = map.m_deviceid,
		.m_pa = map.m_pa,
	};
	err = erofs_map_dev(sb, &mdev);
	if (err) {
		WARN_ON_ONCE(1);
		goto err_out;
	}

	/*
	 * mdev.m_fp should be bootstrap file if m_deviceid == 0, but
	 * it could change in the future.
	 */
	WARN_ON_ONCE(!map.m_deviceid && mdev.m_fp != EROFS_SB(sb)->bootstrap);

	iov.iov_len = min_t(u64, PAGE_SIZE, map.m_plen - (pos - map.m_la));
	init_sync_kiocb(&kiocb, mdev.m_fp);
	kiocb.ki_pos = map.m_pa + (pos - map.m_la);
	iov_iter_kvec(&iter, READ, &iov, 1, iov.iov_len);

	err = call_read_iter(mdev.m_fp, &kiocb, &iter);
	if (err < iov.iov_len) {
		if (err < 0)
			erofs_err(inode->i_sb, "%s: failed to read blob ret %d",
			       __func__, err);
		goto err_out;
	}
	if (iov.iov_len < PAGE_SIZE)
		memset(iov.iov_base + iov.iov_len, 0,
		       PAGE_SIZE - iov.iov_len);
	SetPageUptodate(page);
	unlock_page(page);
	return 0;
err_out:
	SetPageError(page);
	unlock_page(page);
	return err;
}

const struct address_space_operations rafs_v6_access_aops = {
	.readpage = rafs_v6_readpage,
};

void erofs_rafsv6_set_fops(struct inode *inode)
{
	inode->i_fop = &rafs_v6_file_ro_fops;
}

void erofs_rafsv6_set_aops(struct inode *inode)
{
	if (!S_ISREG(inode->i_mode))
		inode_nohighmem(inode);

	inode->i_mapping->a_ops = &rafs_v6_access_aops;
}
