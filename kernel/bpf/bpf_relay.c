// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Alibaba Cloud
 *
 * relay interface only used by bpf. To use it, please
 * echo following cmds to /sys/kernel/debug/relay_ebpf:
 * - Create:
 * create <dir_name> <file_name> bufnum <n> bufsize <n(k/m/...)> percpu <on/off>
 * - Remove:
 * remove <dir_name> <file_name>
 *
 * Also `cat` can be used to show the current relay files, one entry each line
 * - Show: cat /sys/kernel/debug/relay_ebpf
 * => id dir_name file_name bufnum bufsize percpu
 *
 * The field "id" is a unique identifier for each relay channel, which is
 * needed by bpf helper to write into the channel.
 */

#include <linux/debugfs.h>
#include <linux/kernel.h>
#include <linux/dcache.h>
#include <linux/filter.h>
#include <linux/relay.h>
#include <linux/init.h>
#include <linux/bpf.h>
#include <linux/err.h>
#include <linux/fs.h>

/* dynamic array to maintain relay channels, with number limit RCHAN_NUM_MAX */
static struct rchan **rchan_array;
static size_t array_capacity;
#define RCHAN_NUM_MAX 32

/* use to protect relay_ebpf, which makes sure that relay_ebpf process one
 * command at a time.
 */
static DEFINE_MUTEX(relay_file_lock);

/* handle the extension of relay array */
static int relay_array_extend(size_t new_size)
{
	struct rchan **new_array, **old;
	size_t new_capacity;

	/* Calculate new capacity with a simple growth strategy */
	new_capacity = (new_size > array_capacity * 2) ? new_size : (array_capacity * 2);

	/* Compare with RCHAN_NUM_MAX, the max capacity */
	if (new_capacity > RCHAN_NUM_MAX)
		new_capacity = RCHAN_NUM_MAX;

	/* Do nothing if new capacity is not larger than old */
	if (new_capacity <= array_capacity)
		return -EINVAL;

	/* Allocate and init new array with new capacity */
	new_array = kcalloc(new_capacity, sizeof(*rchan_array), GFP_KERNEL);
	if (!new_array)
		return -ENOMEM;

	if (rchan_array)
		memcpy(new_array, rchan_array,
		       array_capacity * sizeof(*rchan_array));

	/* update rchan_array with rcu */
	old = rcu_dereference_protected(rchan_array,
					lockdep_is_held(&relay_file_lock));
	rcu_assign_pointer(rchan_array, new_array);
	synchronize_rcu();

	array_capacity = new_capacity;
	kfree(old);

	pr_info("bpf-relay: rchan_array extend to size %zu\n", new_capacity);
	return 0;
}

/* return the idx of target relay channel if exists, return -1 if not */
static int relay_array_lookup(const char *dirname, const char *filename)
{
	const char *fname, *dname;
	int i;

	for (i = 0; i < array_capacity; ++i) {
		if (!rchan_array[i])
			continue;

		fname = rchan_array[i]->base_filename;
		dname = rchan_array[i]->parent->d_name.name;

		if (strcmp(dname, dirname) == 0 &&
		    strcmp(fname, filename) == 0)
			return i;
	}

	return -1;
}

/* get the next usable id, return -1 if there is no id left */
static int relay_array_get_id(void)
{
	int i;

	for (i = 0; i < array_capacity; ++i) {
		if (!rchan_array[i])
			return i;
	}

	/* if extend needed but fails, return -1 */
	if (i >= array_capacity) {
		if (relay_array_extend(i + 1))
			return -1;
	}

	return i;
}

/* relay callbacks used by all relay files */
static struct dentry *create_buf_file_handler(const char *filename,
					      struct dentry *parent,
					      umode_t mode,
					      struct rchan_buf *buf,
					      int *is_global)
{
	char final_fname[NAME_MAX];

	strcpy(final_fname, filename);
	if (buf->chan->private_data) {
		*is_global = 1;

		/* if it is global, remove the last cpu_id 0 */
		final_fname[strlen(filename) - 1] = '\0';
	}

	return debugfs_create_file(final_fname, mode, parent, buf,
				   &relay_file_operations);
}

static int remove_buf_file_handler(struct dentry *dentry)
{
	debugfs_remove(dentry);
	return 0;
}

static int subbuf_start(struct rchan_buf *buf,
			void *subbuf,
			void *prev_subbuf,
			size_t prev_padding)
{
	return 1;
}

static struct rchan_callbacks relay_callbacks = {
	.create_buf_file = create_buf_file_handler,
	.remove_buf_file = remove_buf_file_handler,
	.subbuf_start    = subbuf_start,
};

static int bpf_relay_create(const char *dir_name, const char *file_name,
			    unsigned long bufnum, unsigned long bufsize,
			    void *is_global, int index)
{
	struct dentry *dir;
	struct rchan *rch;
	int dir_create = 0;
	int ret = 0;

	if (index >= array_capacity || index < 0) {
		pr_info("bpf-relay: create fail, index %d out of range\n",
			index);
		return -EINVAL;
	}

	/* check if this relay channel already exists */
	if (relay_array_lookup(dir_name, file_name) != -1) {
		pr_info("bpf-relay: create fail, channel already exists\n");
		return -EEXIST;
	}

	/* find if the dir already exists, if not, create it */
	dir = debugfs_lookup(dir_name, NULL);
	if (!dir) {
		dir = debugfs_create_dir(dir_name, NULL);
		if (IS_ERR(dir))
			return PTR_ERR(dir);
		dir_create = 1;

	} else if (!S_ISDIR(dir->d_inode->i_mode)) {
		pr_info("bpf-relay: create fail, %s is not a directory\n",
			dir_name);
		return -EINVAL;
	}

	rch = relay_open(file_name, dir, bufsize, bufnum,
			 &relay_callbacks, is_global);
	if (!rch) {
		if (dir_create)
			debugfs_remove_recursive(dir);
		pr_info("bpf-relay: create fail, relay_open fail\n");
		return -ENOMEM;
	}

	rcu_assign_pointer(rchan_array[index], rch);
	pr_info("bpf-relay: create finished, id=%d\n", index);
	return 0;
}

static int handle_create(const char *buf)
{
	char dir_name[NAME_MAX], file_name[NAME_MAX], bsize_str[20], percpu[4];
	unsigned long bufnum, bufsize;
	static unsigned char global_flag;
	unsigned char *is_global;
	int ret;

	ret = sscanf(buf, " create %s %s bufnum %lu bufsize %s percpu %4s",
		     dir_name, file_name, &bufnum, bsize_str, percpu);
	if (ret != 5) {
		pr_info("bpf-relay: create fail, get args failed\n");
		return -EINVAL;
	}

	/* parse arguments */
	bufsize = (unsigned long)memparse(bsize_str, NULL);

	/* by passing a valid pointer as private_data for relay channel,
	 * we mark the channel as global, see create_buf_file_handler()
	 */
	is_global = NULL;
	if (strcmp(percpu, "off") == 0)
		is_global = &global_flag;

	ret = relay_array_get_id();
	if (ret < 0) {
		pr_info("bpf-relay: create fail, no id left\n");
		return -ENOMEM;
	}

	/* create common relay chan according to args */
	return bpf_relay_create(dir_name, file_name, bufnum, bufsize,
				is_global, ret);
}

static ssize_t relay_ebpf_write(struct file *file,
				const char __user *user_buf,
				size_t count, loff_t *ppos)
{
	char cmd[10], buf[128];
	int ret;

	if (!count || count >= sizeof(buf))
		return -EINVAL;

	if (copy_from_user(&buf, user_buf, count))
		return -EFAULT;

	/* parse cmd */
	buf[count] = '\0';
	ret = sscanf(buf, " %s", cmd);
	if (ret != 1) {
		pr_info("bpf-relay: write fail, get cmd failed\n");
		return -EINVAL;
	}

	mutex_lock(&relay_file_lock);
	if (strcmp(cmd, "create") == 0) {
		ret = handle_create(buf);
		if (!ret)
			ret = count;
	} else {
		pr_info("bpf-relay: write fail, invalid cmd\n");
		ret = -EINVAL;
	}

	mutex_unlock(&relay_file_lock);
	return ret;
}

static const struct file_operations relay_ebpf_fops = {
	.write = relay_ebpf_write,
};

/* create relay-ebpf file, rchan_array is created with "create" cmd */
static int __init bpf_relay_init(void)
{
	if (!debugfs_create_file("relay_ebpf", 0644, NULL, NULL,
				 &relay_ebpf_fops)) {
		pr_err("bpf-relay: debugfs create relay_ebpf fail\n");
		return -ENOMEM;
	}

	return 0;
}
late_initcall(bpf_relay_init);
