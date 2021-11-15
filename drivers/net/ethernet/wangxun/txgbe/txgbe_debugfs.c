// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2015 - 2022 Beijing WangXun Technology Co., Ltd. */

#include "txgbe.h"

#include <linux/debugfs.h>
#include <linux/module.h>

static struct dentry *txgbe_dbg_root;
static int txgbe_data_mode;

static char txgbe_dbg_reg_ops_buf[256] = "";

static ssize_t
txgbe_dbg_reg_ops_read(struct file *filp, char __user *buffer,
		       size_t count, loff_t *ppos)
{
	struct txgbe_adapter *adapter = filp->private_data;
	char *buf;
	int len;

	/* don't allow partial reads */
	if (*ppos != 0)
		return 0;

	buf = kasprintf(GFP_KERNEL, "%s: mode=0x%08x\n%s\n",
			adapter->netdev->name, txgbe_data_mode,
			txgbe_dbg_reg_ops_buf);
	if (!buf)
		return -ENOMEM;

	if (count < strlen(buf)) {
		kfree(buf);
		return -ENOSPC;
	}

	len = simple_read_from_buffer(buffer, count, ppos, buf, strlen(buf));

	kfree(buf);
	return len;
}

static const struct file_operations txgbe_dbg_reg_ops_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read =  txgbe_dbg_reg_ops_read,
};

static char txgbe_dbg_netdev_ops_buf[256] = "";

static ssize_t
txgbe_dbg_netdev_ops_read(struct file *filp,
			  char __user *buffer,
			  size_t count, loff_t *ppos)
{
	struct txgbe_adapter *adapter = filp->private_data;
	char *buf;
	int len;

	/* don't allow partial reads */
	if (*ppos != 0)
		return 0;

	buf = kasprintf(GFP_KERNEL, "%s: mode=0x%08x\n%s\n",
			adapter->netdev->name, txgbe_data_mode,
			txgbe_dbg_netdev_ops_buf);
	if (!buf)
		return -ENOMEM;

	if (count < strlen(buf)) {
		kfree(buf);
		return -ENOSPC;
	}

	len = simple_read_from_buffer(buffer, count, ppos, buf, strlen(buf));

	kfree(buf);
	return len;
}

static const struct file_operations txgbe_dbg_netdev_ops_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = txgbe_dbg_netdev_ops_read,
};

/**
 * txgbe_dbg_adapter_init - setup the debugfs directory for the adapter
 * @adapter: the adapter that is starting up
 **/
void txgbe_dbg_adapter_init(struct txgbe_adapter *adapter)
{
	const char *name = pci_name(adapter->pdev);
	struct dentry *pfile;

	adapter->txgbe_dbg_adapter = debugfs_create_dir(name, txgbe_dbg_root);
	if (!adapter->txgbe_dbg_adapter) {
		dev_err(&adapter->pdev->dev,
			"debugfs entry for %s failed\n", name);
		return;
	}

	pfile = debugfs_create_file("reg_ops", 0600,
				    adapter->txgbe_dbg_adapter, adapter,
				    &txgbe_dbg_reg_ops_fops);
	if (!pfile)
		dev_err(&adapter->pdev->dev,
			"debugfs reg_ops for %s failed\n", name);

	pfile = debugfs_create_file("netdev_ops", 0600,
				    adapter->txgbe_dbg_adapter, adapter,
				    &txgbe_dbg_netdev_ops_fops);
	if (!pfile)
		dev_err(&adapter->pdev->dev,
			"debugfs netdev_ops for %s failed\n", name);
}

/**
 * txgbe_dbg_adapter_exit - clear out the adapter's debugfs entries
 * @adapter: the adapter that is exiting
 **/
void txgbe_dbg_adapter_exit(struct txgbe_adapter *adapter)
{
	debugfs_remove_recursive(adapter->txgbe_dbg_adapter);
	adapter->txgbe_dbg_adapter = NULL;
}

/**
 * txgbe_dbg_init - start up debugfs for the driver
 **/
void txgbe_dbg_init(void)
{
	txgbe_dbg_root = debugfs_create_dir(txgbe_driver_name, NULL);
	if (!txgbe_dbg_root)
		pr_err("init of debugfs failed\n");
}

/**
 * txgbe_dbg_exit - clean out the driver's debugfs entries
 **/
void txgbe_dbg_exit(void)
{
	debugfs_remove_recursive(txgbe_dbg_root);
}
