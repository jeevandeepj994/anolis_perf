/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2008  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

#include "fuse_i.h"

#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs_context.h>

#define FUSE_CTL_SUPER_MAGIC 0x65735543

#define PRINT_LINE(buff, remain, ...)					\
	do {								\
		if (remain) {                                           \
			size_t used = snprintf(buff, remain, ##__VA_ARGS__); \
			if (used >= remain) {				\
				remain = 0;				\
				buff = NULL;				\
			} else {					\
				remain -= used;				\
				buff += used;				\
			}						\
		}                                                       \
	} while (0)

#define PRINT_HEADER(buff, remain, header)	\
	PRINT_LINE(buff, remain, header)

#define PRINT_REQ(buff, remain,  req)                                   \
	PRINT_LINE(buff, remain,					\
		"unique:%llu opcode:%u nodeid:%llu pid:%u flags:%lu sent_time:%llu\n", \
		req->in.h.unique, req->in.h.opcode, req->in.h.nodeid,	\
		req->in.h.pid, req->flags, req->send_time)

#define PRINT_STATS(__opname, fc, remain, buff)				\
	do {								\
		uint64_t tot_time = atomic64_read(&fc->stats.req_time[__opname]); \
		uint64_t cnt = atomic64_read(&fc->stats.req_cnts[__opname]); \
		PRINT_LINE(buff, remain, "%s: "				\
			"total reqs: %llu, "				\
			"tot_time_avg: %llu\n",				\
			# __opname,					\
			cnt,						\
			tot_time / (cnt + 1));				\
	} while (0)

/*
 * This is non-NULL when the single instance of the control filesystem
 * exists.  Protected by fuse_mutex
 */
static struct super_block *fuse_control_sb;

static struct fuse_conn *fuse_ctl_file_conn_get(struct file *file)
{
	struct fuse_conn *fc;
	mutex_lock(&fuse_mutex);
	fc = file_inode(file)->i_private;
	if (fc)
		fc = fuse_conn_get(fc);
	mutex_unlock(&fuse_mutex);
	return fc;
}

static ssize_t fuse_conn_stats_write(struct file *file, const char __user *buffer,
				size_t count, loff_t *f_pos)
{
	int i;
	struct fuse_conn *fc = fuse_ctl_file_conn_get(file);

	if (!fc)
		return 0;

	for (i = 0; i < FUSE_OP_MAX; i++) {
		atomic64_set(&fc->stats.req_time[i], 0);
		atomic64_set(&fc->stats.req_cnts[i], 0);
	}
	fuse_conn_put(fc);

	return count;
}

static ssize_t fuse_conn_stats_read(struct file *file, char __user *buf,
				size_t len, loff_t *ppos)
{
	char *data;
	char *buff;
	uint64_t remain = PAGE_SIZE;
	ssize_t ret;
	struct fuse_conn *fc = fuse_ctl_file_conn_get(file);

	if (!fc)
		return 0;

	data = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!data) {
		fuse_conn_put(fc);
		return 0;
	}
	buff = data;

	PRINT_STATS(FUSE_LOOKUP, fc, remain, buff);
	PRINT_STATS(FUSE_MKNOD, fc, remain, buff);
	PRINT_STATS(FUSE_MKDIR, fc, remain, buff);
	PRINT_STATS(FUSE_OPEN, fc, remain, buff);
	PRINT_STATS(FUSE_CREATE, fc, remain, buff);
	PRINT_STATS(FUSE_WRITE, fc, remain, buff);
	PRINT_STATS(FUSE_GETATTR, fc, remain, buff);
	PRINT_STATS(FUSE_SETATTR, fc, remain, buff);
	PRINT_STATS(FUSE_ACCESS, fc, remain, buff);
	PRINT_STATS(FUSE_UNLINK, fc, remain, buff);
	PRINT_STATS(FUSE_RMDIR, fc, remain, buff);
	PRINT_STATS(FUSE_RENAME, fc, remain, buff);
	PRINT_STATS(FUSE_RELEASE, fc, remain, buff);
	PRINT_STATS(FUSE_FLUSH, fc, remain, buff);
	PRINT_STATS(FUSE_FSYNC, fc, remain, buff);
	PRINT_STATS(FUSE_READ, fc, remain, buff);
	PRINT_STATS(FUSE_READDIR, fc, remain, buff);
	PRINT_STATS(FUSE_READDIRPLUS, fc, remain, buff);
	PRINT_STATS(FUSE_SUMMARY, fc, remain, buff);

	fuse_conn_put(fc);
	ret = simple_read_from_buffer(buf, len, ppos, data, PAGE_SIZE - remain);
	kfree(data);

	return ret;
}

static ssize_t fuse_conn_abort_write(struct file *file, const char __user *buf,
				     size_t count, loff_t *ppos)
{
	struct fuse_conn *fc = fuse_ctl_file_conn_get(file);
	if (fc) {
		if (fc->abort_err)
			fc->aborted = true;
		fuse_abort_conn(fc);
		fuse_conn_put(fc);
	}
	return count;
}

static ssize_t fuse_conn_flush_write(struct file *file, const char __user *buf,
					 size_t count, loff_t *ppos)
{
	struct fuse_conn *fc = fuse_ctl_file_conn_get(file);

	if (fc) {
		fuse_flush_pq(fc);
		fuse_conn_put(fc);
	}
	return count;
}

static ssize_t fuse_conn_resend_write(struct file *file, const char __user *buf,
				     size_t count, loff_t *ppos)
{
	struct fuse_conn *fc = fuse_ctl_file_conn_get(file);

	if (fc) {
		fuse_resend_pqueue(fc);
		fuse_conn_put(fc);
	}
	return count;
}

static ssize_t fuse_conn_waiting_read(struct file *file, char __user *buf,
				      size_t len, loff_t *ppos)
{
	char tmp[32];
	size_t size;

	if (!*ppos) {
		long value;
		struct fuse_conn *fc = fuse_ctl_file_conn_get(file);
		if (!fc)
			return 0;

		value = atomic_read(&fc->num_waiting);
		file->private_data = (void *)value;
		fuse_conn_put(fc);
	}
	size = sprintf(tmp, "%ld\n", (long)file->private_data);
	return simple_read_from_buffer(buf, len, ppos, tmp, size);
}

static ssize_t fuse_conn_waiting_req_debug(struct file *file, char __user *buf,
					size_t len, loff_t *ppos)
{
	struct fuse_conn *fc;
	struct fuse_dev *fud;
	struct fuse_req *req;
	struct fuse_iqueue *fiq;
	char *data;
	char *buff;
	size_t remain = PAGE_SIZE;
	int ret;
	unsigned int i;

	if (*ppos)
		return 0;

	data = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!data)
		return 0;
	buff = data;

	fc = fuse_ctl_file_conn_get(file);
	if (!fc)
		return 0;

	spin_lock(&fc->lock);
	if (!fc->connected)
		goto out;

	fiq = &fc->iq;
	list_for_each_entry(fud, &fc->devices, entry) {
		struct fuse_pqueue *fpq = &fud->pq;

		spin_lock(&fpq->lock);
		if (fpq->connected) {
			PRINT_HEADER(buff, remain, "io_queue >>>>>>\n");
			list_for_each_entry(req, &fpq->io, list) {
				PRINT_REQ(buff, remain, req);
			}
			PRINT_HEADER(buff, remain, "<<<<<<\n");
			PRINT_HEADER(buff, remain, "processing_queue >>>>>>\n");
			for (i = 0; i < FUSE_PQ_HASH_SIZE; i++) {
				list_for_each_entry(req, &fpq->processing[i], list) {
					PRINT_REQ(buff, remain, req);
				}
			}
			PRINT_HEADER(buff, remain, "<<<<<<\n");
		}
		spin_unlock(&fpq->lock);
	}

out:
	spin_unlock(&fc->lock);
	fuse_conn_put(fc);
	ret = simple_read_from_buffer(buf, len, ppos, data, PAGE_SIZE - remain);
	kfree(data);

	return ret;
}

static ssize_t fuse_conn_limit_read(struct file *file, char __user *buf,
				    size_t len, loff_t *ppos, unsigned val)
{
	char tmp[32];
	size_t size = sprintf(tmp, "%u\n", val);

	return simple_read_from_buffer(buf, len, ppos, tmp, size);
}

static ssize_t fuse_conn_limit_write(struct file *file, const char __user *buf,
				     size_t count, loff_t *ppos, unsigned *val,
				     unsigned global_limit)
{
	unsigned long t;
	unsigned limit = (1 << 16) - 1;
	int err;

	if (*ppos)
		return -EINVAL;

	err = kstrtoul_from_user(buf, count, 0, &t);
	if (err)
		return err;

	if (!capable(CAP_SYS_ADMIN))
		limit = min(limit, global_limit);

	if (t > limit)
		return -EINVAL;

	*val = t;

	return count;
}

static ssize_t fuse_conn_max_background_read(struct file *file,
					     char __user *buf, size_t len,
					     loff_t *ppos)
{
	struct fuse_conn *fc;
	unsigned val;

	fc = fuse_ctl_file_conn_get(file);
	if (!fc)
		return 0;

	val = READ_ONCE(fc->max_background);
	fuse_conn_put(fc);

	return fuse_conn_limit_read(file, buf, len, ppos, val);
}

static ssize_t fuse_conn_max_background_write(struct file *file,
					      const char __user *buf,
					      size_t count, loff_t *ppos)
{
	unsigned val;
	ssize_t ret;

	ret = fuse_conn_limit_write(file, buf, count, ppos, &val,
				    max_user_bgreq);
	if (ret > 0) {
		struct fuse_conn *fc = fuse_ctl_file_conn_get(file);
		if (fc) {
			spin_lock(&fc->bg_lock);
			fc->max_background = val;
			fc->blocked = fc->num_background >= fc->max_background;
			if (!fc->blocked)
				wake_up(&fc->blocked_waitq);
			spin_unlock(&fc->bg_lock);
			fuse_conn_put(fc);
		}
	}

	return ret;
}

static ssize_t fuse_conn_congestion_threshold_read(struct file *file,
						   char __user *buf, size_t len,
						   loff_t *ppos)
{
	struct fuse_conn *fc;
	unsigned val;

	fc = fuse_ctl_file_conn_get(file);
	if (!fc)
		return 0;

	val = READ_ONCE(fc->congestion_threshold);
	fuse_conn_put(fc);

	return fuse_conn_limit_read(file, buf, len, ppos, val);
}

static ssize_t fuse_conn_congestion_threshold_write(struct file *file,
						    const char __user *buf,
						    size_t count, loff_t *ppos)
{
	unsigned val;
	struct fuse_conn *fc;
	struct fuse_mount *fm;
	ssize_t ret;

	ret = fuse_conn_limit_write(file, buf, count, ppos, &val,
				    max_user_congthresh);
	if (ret <= 0)
		goto out;
	fc = fuse_ctl_file_conn_get(file);
	if (!fc)
		goto out;

	down_read(&fc->killsb);
	spin_lock(&fc->bg_lock);
	fc->congestion_threshold = val;

	/*
	 * Get any fuse_mount belonging to this fuse_conn; s_bdi is
	 * shared between all of them
	 */

	if (!list_empty(&fc->mounts)) {
		fm = list_first_entry(&fc->mounts, struct fuse_mount, fc_entry);
		if (fc->num_background < fc->congestion_threshold) {
			clear_bdi_congested(fm->sb->s_bdi, BLK_RW_SYNC);
			clear_bdi_congested(fm->sb->s_bdi, BLK_RW_ASYNC);
		} else {
			set_bdi_congested(fm->sb->s_bdi, BLK_RW_SYNC);
			set_bdi_congested(fm->sb->s_bdi, BLK_RW_ASYNC);
		}
	}
	spin_unlock(&fc->bg_lock);
	up_read(&fc->killsb);
	fuse_conn_put(fc);
out:
	return ret;
}

static ssize_t fuse_conn_passthrough_read(struct file *file,
					  char __user *buf,
					  size_t len, loff_t *ppos)
{
	struct fuse_conn *fc;
	char tmp[32];
	char *result;
	size_t size;

	fc = fuse_ctl_file_conn_get(file);
	if (!fc)
		return 0;

	if (!fc->passthrough)
		result = "incapable";
	else if (!fc->passthrough_enabled)
		result = "disabled";
	else
		result = "enabled";

	fuse_conn_put(fc);
	size = sprintf(tmp, "%s\n", result);
	return simple_read_from_buffer(buf, len, ppos, tmp, size);
}

static ssize_t fuse_conn_passthrough_write(struct file *file,
					   const char __user *buf,
					   size_t count, loff_t *ppos)
{
	struct fuse_conn *fc = NULL;
	unsigned long val;
	ssize_t ret = -EINVAL;
	bool enabled;

	if (*ppos)
		goto out;

	ret = kstrtoul_from_user(buf, count, 0, &val);
	if (ret)
		goto out;

	/* fuse_ctl_file_conn_get->mutex implies full memory barrier */
	fc = fuse_ctl_file_conn_get(file);
	if (!fc || !fc->passthrough) {
		ret = -EINVAL;
		goto out;
	}

	enabled = READ_ONCE(fc->passthrough_enabled);

	if (val > 0 && !enabled)
		WRITE_ONCE(fc->passthrough_enabled, true);
	else if (!val && enabled)
		WRITE_ONCE(fc->passthrough_enabled, false);

	ret = count;

out:
	if (fc)
		fuse_conn_put(fc);
	return ret;
}

static int fuse_io_metrics_open(struct inode *inode, struct file *file)
{
	/* inode->i_private is fuse_conn as being set in fuse_ctl_add_dentry */
	return single_open(file, fuse_io_metrics_show, inode->i_private);
}

static ssize_t fuse_io_metrics_write(struct file *file,
				     const char __user *buf,
				     size_t count, loff_t *ppos)
{
	struct fuse_conn *fc;
	u64 target_ns;
	int ret = -EINVAL;

	if (*ppos)
		goto out;

	ret = kstrtoull_from_user(buf, count, 0, &target_ns);
	if (ret < 0)
		goto out;

	if (target_ns * 100 < target_ns) {
		ret = -EOVERFLOW;
		goto out;
	}
	fc = fuse_ctl_file_conn_get(file);
	if (fc) {
		fuse_io_counter_set_latency_target(fc->io_counter, target_ns);
		fuse_conn_put(fc);
	}
	ret = count;

out:
	return ret;
}

static const struct file_operations fuse_io_metrics_fops = {
	.open = fuse_io_metrics_open,
	.read = seq_read,
	.write = fuse_io_metrics_write,
	.llseek = seq_lseek,
	.release = single_release,
};

static const struct file_operations fuse_ctl_abort_ops = {
	.open = nonseekable_open,
	.write = fuse_conn_abort_write,
	.llseek = no_llseek,
};

static const struct file_operations fuse_ctl_flush_ops = {
	.open = nonseekable_open,
	.write = fuse_conn_flush_write,
	.llseek = no_llseek,
};

static const struct file_operations fuse_ctl_resend_ops = {
	.open = nonseekable_open,
	.write = fuse_conn_resend_write,
	.llseek = no_llseek,
};

static const struct file_operations fuse_ctl_waiting_ops = {
	.open = nonseekable_open,
	.read = fuse_conn_waiting_read,
	.llseek = no_llseek,
};

static const struct file_operations fuse_ctl_waiting_debug_ops = {
	.open = nonseekable_open,
	.read = fuse_conn_waiting_req_debug,
	.llseek = no_llseek,
};

static const struct file_operations fuse_conn_max_background_ops = {
	.open = nonseekable_open,
	.read = fuse_conn_max_background_read,
	.write = fuse_conn_max_background_write,
	.llseek = no_llseek,
};

static const struct file_operations fuse_conn_stats_ops = {
	.open = nonseekable_open,
	.read = fuse_conn_stats_read,
	.write = fuse_conn_stats_write,
	.llseek = no_llseek,
};

static const struct file_operations fuse_conn_congestion_threshold_ops = {
	.open = nonseekable_open,
	.read = fuse_conn_congestion_threshold_read,
	.write = fuse_conn_congestion_threshold_write,
	.llseek = no_llseek,
};

static const struct file_operations fuse_conn_passthrough_ops = {
	.open = nonseekable_open,
	.read = fuse_conn_passthrough_read,
	.write = fuse_conn_passthrough_write,
	.llseek = no_llseek,
};

static struct dentry *fuse_ctl_add_dentry(struct dentry *parent,
					  struct fuse_conn *fc,
					  const char *name,
					  int mode, int nlink,
					  const struct inode_operations *iop,
					  const struct file_operations *fop)
{
	struct dentry *dentry;
	struct inode *inode;

	BUG_ON(fc->ctl_ndents >= FUSE_CTL_NUM_DENTRIES);
	dentry = d_alloc_name(parent, name);
	if (!dentry)
		return NULL;

	inode = new_inode(fuse_control_sb);
	if (!inode) {
		dput(dentry);
		return NULL;
	}

	inode->i_ino = get_next_ino();
	inode->i_mode = mode;
	inode->i_uid = fc->user_id;
	inode->i_gid = fc->group_id;
	inode->i_atime = inode->i_mtime = inode->i_ctime = current_time(inode);
	/* setting ->i_op to NULL is not allowed */
	if (iop)
		inode->i_op = iop;
	inode->i_fop = fop;
	set_nlink(inode, nlink);
	inode->i_private = fc;
	d_add(dentry, inode);

	fc->ctl_dentry[fc->ctl_ndents++] = dentry;

	return dentry;
}

/*
 * Add a connection to the control filesystem (if it exists).  Caller
 * must hold fuse_mutex
 */
int fuse_ctl_add_conn(struct fuse_conn *fc)
{
	struct dentry *parent;
	char name[32];

	if (!fuse_control_sb || fc->no_control)
		return 0;

	parent = fuse_control_sb->s_root;
	inc_nlink(d_inode(parent));
	sprintf(name, "%u", fc->dev);
	parent = fuse_ctl_add_dentry(parent, fc, name, S_IFDIR | 0500, 2,
				     &simple_dir_inode_operations,
				     &simple_dir_operations);
	if (!parent)
		goto err;

	if (!fuse_ctl_add_dentry(parent, fc, "waiting", S_IFREG | 0400, 1,
				 NULL, &fuse_ctl_waiting_ops) ||
	    !fuse_ctl_add_dentry(parent, fc, "waiting_debug", S_IFREG | 0400, 1,
				 NULL, &fuse_ctl_waiting_debug_ops) ||
	    !fuse_ctl_add_dentry(parent, fc, "abort", S_IFREG | 0200, 1,
				 NULL, &fuse_ctl_abort_ops) ||
	    !fuse_ctl_add_dentry(parent, fc, "flush", S_IFREG | 0200, 1,
				 NULL, &fuse_ctl_flush_ops) ||
	    !fuse_ctl_add_dentry(parent, fc, "resend", S_IFREG | 0200, 1,
				 NULL, &fuse_ctl_resend_ops) ||
	    !fuse_ctl_add_dentry(parent, fc, "stats", S_IFREG | 0600, 1,
				 NULL, &fuse_conn_stats_ops) ||
	    !fuse_ctl_add_dentry(parent, fc, "max_background", S_IFREG | 0600,
				 1, NULL, &fuse_conn_max_background_ops) ||
	    !fuse_ctl_add_dentry(parent, fc, "passthrough", S_IFREG | 0600,
				 1, NULL, &fuse_conn_passthrough_ops) ||
	    !fuse_ctl_add_dentry(parent, fc, "passthrough_metrics", S_IFREG | 0600,
				 1, NULL, &fuse_io_metrics_fops) ||
	    !fuse_ctl_add_dentry(parent, fc, "congestion_threshold",
				 S_IFREG | 0600, 1, NULL,
				 &fuse_conn_congestion_threshold_ops))
		goto err;

	return 0;

 err:
	fuse_ctl_remove_conn(fc);
	return -ENOMEM;
}

/*
 * Remove a connection from the control filesystem (if it exists).
 * Caller must hold fuse_mutex
 */
void fuse_ctl_remove_conn(struct fuse_conn *fc)
{
	int i;

	if (!fuse_control_sb || fc->no_control)
		return;

	for (i = fc->ctl_ndents - 1; i >= 0; i--) {
		struct dentry *dentry = fc->ctl_dentry[i];
		d_inode(dentry)->i_private = NULL;
		if (!i) {
			/* Get rid of submounts: */
			d_invalidate(dentry);
		}
		dput(dentry);
	}
	drop_nlink(d_inode(fuse_control_sb->s_root));
}

static int fuse_ctl_fill_super(struct super_block *sb, struct fs_context *fctx)
{
	static const struct tree_descr empty_descr = {""};
	struct fuse_conn *fc;
	int err;

	err = simple_fill_super(sb, FUSE_CTL_SUPER_MAGIC, &empty_descr);
	if (err)
		return err;

	mutex_lock(&fuse_mutex);
	BUG_ON(fuse_control_sb);
	fuse_control_sb = sb;
	list_for_each_entry(fc, &fuse_conn_list, entry) {
		err = fuse_ctl_add_conn(fc);
		if (err) {
			fuse_control_sb = NULL;
			mutex_unlock(&fuse_mutex);
			return err;
		}
	}
	mutex_unlock(&fuse_mutex);

	return 0;
}

static int fuse_ctl_get_tree(struct fs_context *fc)
{
	return get_tree_single(fc, fuse_ctl_fill_super);
}

static const struct fs_context_operations fuse_ctl_context_ops = {
	.get_tree	= fuse_ctl_get_tree,
};

static int fuse_ctl_init_fs_context(struct fs_context *fc)
{
	fc->ops = &fuse_ctl_context_ops;
	return 0;
}

static void fuse_ctl_kill_sb(struct super_block *sb)
{
	struct fuse_conn *fc;

	mutex_lock(&fuse_mutex);
	fuse_control_sb = NULL;
	list_for_each_entry(fc, &fuse_conn_list, entry)
		fc->ctl_ndents = 0;
	mutex_unlock(&fuse_mutex);

	kill_litter_super(sb);
}

static struct file_system_type fuse_ctl_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "fusectl",
	.init_fs_context = fuse_ctl_init_fs_context,
	.kill_sb	= fuse_ctl_kill_sb,
};
MODULE_ALIAS_FS("fusectl");

int __init fuse_ctl_init(void)
{
	return register_filesystem(&fuse_ctl_fs_type);
}

void __exit fuse_ctl_cleanup(void)
{
	unregister_filesystem(&fuse_ctl_fs_type);
}
