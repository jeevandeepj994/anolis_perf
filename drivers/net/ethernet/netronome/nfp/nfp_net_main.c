// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright (C) 2015-2018 Netronome Systems, Inc. */

/*
 * nfp_net_main.c
 * Netronome network device driver: Main entry point
 * Authors: Jakub Kicinski <jakub.kicinski@netronome.com>
 *          Alejandro Lucero <alejandro.lucero@netronome.com>
 *          Jason McMullan <jason.mcmullan@netronome.com>
 *          Rolf Neugebauer <rolf.neugebauer@netronome.com>
 */

#include <linux/etherdevice.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/lockdep.h>
#include <linux/pci.h>
#include <linux/pci_regs.h>
#include <linux/random.h>
#include <linux/rtnetlink.h>

#include "nfpcore/nfp.h"
#include "nfpcore/nfp_cpp.h"
#include "nfpcore/nfp_dev.h"
#include "nfpcore/nfp_nffw.h"
#include "nfpcore/nfp_nsp.h"
#include "nfpcore/nfp6000_pcie.h"
#include "nfp_app.h"
#include "nfp_net_ctrl.h"
#include "nfp_net_sriov.h"
#include "nfp_net.h"
#include "nfp_main.h"
#include "nfp_port.h"

#define NFP_PF_CSR_SLICE_SIZE	(32 * 1024)

/**
 * nfp_net_get_mac_addr() - Get the MAC address.
 * @pf:       NFP PF handle
 * @netdev:   net_device to set MAC address on
 * @port:     NFP port structure
 *
 * First try to get the MAC address from NSP ETH table. If that
 * fails generate a random address.
 */
void
nfp_net_get_mac_addr(struct nfp_pf *pf, struct net_device *netdev,
		     struct nfp_port *port)
{
	struct nfp_eth_table_port *eth_port;

	eth_port = __nfp_port_get_eth_port(port);
	if (!eth_port) {
		eth_hw_addr_random(netdev);
		return;
	}

	eth_hw_addr_set(netdev, eth_port->mac_addr);
	ether_addr_copy(netdev->perm_addr, eth_port->mac_addr);
}

static struct nfp_eth_table_port *
nfp_net_find_port(struct nfp_eth_table *eth_tbl, unsigned int index)
{
	int i;

	for (i = 0; eth_tbl && i < eth_tbl->count; i++)
		if (eth_tbl->ports[i].index == index)
			return &eth_tbl->ports[i];

	return NULL;
}

static int nfp_net_pf_get_num_ports(struct nfp_pf *pf)
{
	return nfp_pf_rtsym_read_optional(pf, "nfd_cfg_pf%u_num_ports", 1);
}

static void nfp_net_pf_free_vnic(struct nfp_pf *pf, struct nfp_net *nn)
{
	if (nfp_net_is_data_vnic(nn))
		nfp_app_vnic_free(pf->app, nn);
	nfp_port_free(nn->port);
	list_del(&nn->vnic_list);
	pf->num_vnics--;
	nfp_net_free(nn);
}

static void nfp_net_pf_free_vnics(struct nfp_pf *pf)
{
	struct nfp_net *nn, *next;

	list_for_each_entry_safe(nn, next, &pf->vnics, vnic_list)
		if (nfp_net_is_data_vnic(nn))
			nfp_net_pf_free_vnic(pf, nn);
}

static struct nfp_net *
nfp_net_pf_alloc_vnic(struct nfp_pf *pf, bool needs_netdev,
		      void __iomem *ctrl_bar, void __iomem *qc_bar,
		      int stride, unsigned int id)
{
	u32 tx_base, rx_base, n_tx_rings, n_rx_rings;
	struct nfp_net *nn;
	int err;

	tx_base = readl(ctrl_bar + NFP_NET_CFG_START_TXQ);
	rx_base = readl(ctrl_bar + NFP_NET_CFG_START_RXQ);
	n_tx_rings = readl(ctrl_bar + NFP_NET_CFG_MAX_TXRINGS);
	n_rx_rings = readl(ctrl_bar + NFP_NET_CFG_MAX_RXRINGS);

	/* Allocate and initialise the vNIC */
	nn = nfp_net_alloc(pf->pdev, pf->dev_info, ctrl_bar, needs_netdev,
			   n_tx_rings, n_rx_rings);
	if (IS_ERR(nn))
		return nn;

	nn->app = pf->app;
	nn->tx_bar = qc_bar + tx_base * NFP_QCP_QUEUE_ADDR_SZ;
	nn->rx_bar = qc_bar + rx_base * NFP_QCP_QUEUE_ADDR_SZ;
	nn->dp.is_vf = 0;
	nn->stride_rx = stride;
	nn->stride_tx = stride;

	if (needs_netdev) {
		err = nfp_app_vnic_alloc(pf->app, nn, id);
		if (err) {
			nfp_net_free(nn);
			return ERR_PTR(err);
		}
	}

	pf->num_vnics++;
	list_add_tail(&nn->vnic_list, &pf->vnics);

	return nn;
}

static int
nfp_net_pf_init_vnic(struct nfp_pf *pf, struct nfp_net *nn, unsigned int id)
{
	int err;

	nn->id = pf->multi_pf.en ? pf->multi_pf.id : id;

	if (nn->port) {
		err = nfp_devlink_port_register(pf->app, nn->port);
		if (err)
			return err;
	}

	err = nfp_net_init(nn);
	if (err)
		goto err_devlink_port_clean;

	nfp_net_debugfs_vnic_add(nn, pf->ddir);

	nfp_net_info(nn);

	if (nfp_net_is_data_vnic(nn)) {
		err = nfp_app_vnic_init(pf->app, nn);
		if (err)
			goto err_debugfs_vnic_clean;
	}

	return 0;

err_debugfs_vnic_clean:
	nfp_net_debugfs_dir_clean(&nn->debugfs_dir);
	nfp_net_clean(nn);
err_devlink_port_clean:
	if (nn->port)
		nfp_devlink_port_unregister(nn->port);
	return err;
}

static int
nfp_net_pf_alloc_vnics(struct nfp_pf *pf, void __iomem *ctrl_bar,
		       void __iomem *qc_bar, int stride)
{
	struct nfp_net *nn;
	unsigned int i;
	int err;

	for (i = 0; i < pf->max_data_vnics; i++) {
		nn = nfp_net_pf_alloc_vnic(pf, true, ctrl_bar, qc_bar,
					   stride, pf->multi_pf.en ? pf->multi_pf.id : i);
		if (IS_ERR(nn)) {
			err = PTR_ERR(nn);
			goto err_free_prev;
		}

		if (nn->port)
			nn->port->link_cb = nfp_net_refresh_port_table;

		ctrl_bar += NFP_PF_CSR_SLICE_SIZE;

		/* Kill the vNIC if app init marked it as invalid */
		if (nn->port && nn->port->type == NFP_PORT_INVALID)
			nfp_net_pf_free_vnic(pf, nn);
	}

	if (list_empty(&pf->vnics))
		return -ENODEV;

	return 0;

err_free_prev:
	nfp_net_pf_free_vnics(pf);
	return err;
}

static void nfp_net_pf_clean_vnic(struct nfp_pf *pf, struct nfp_net *nn)
{
	if (nfp_net_is_data_vnic(nn))
		nfp_app_vnic_clean(pf->app, nn);
	nfp_net_debugfs_dir_clean(&nn->debugfs_dir);
	nfp_net_clean(nn);
	if (nn->port)
		nfp_devlink_port_unregister(nn->port);
}

static int nfp_net_pf_alloc_irqs(struct nfp_pf *pf)
{
	unsigned int wanted_irqs, num_irqs, vnics_left, irqs_left;
	struct nfp_net *nn;

	/* Get MSI-X vectors */
	wanted_irqs = 0;
	list_for_each_entry(nn, &pf->vnics, vnic_list)
		wanted_irqs += NFP_NET_NON_Q_VECTORS + nn->dp.num_r_vecs;
	pf->irq_entries = kcalloc(wanted_irqs, sizeof(*pf->irq_entries),
				  GFP_KERNEL);
	if (!pf->irq_entries)
		return -ENOMEM;

	num_irqs = nfp_net_irqs_alloc(pf->pdev, pf->irq_entries,
				      NFP_NET_MIN_VNIC_IRQS * pf->num_vnics,
				      wanted_irqs);
	if (!num_irqs) {
		nfp_warn(pf->cpp, "Unable to allocate MSI-X vectors\n");
		kfree(pf->irq_entries);
		return -ENOMEM;
	}

	/* Distribute IRQs to vNICs */
	irqs_left = num_irqs;
	vnics_left = pf->num_vnics;
	list_for_each_entry(nn, &pf->vnics, vnic_list) {
		unsigned int n;

		n = min(NFP_NET_NON_Q_VECTORS + nn->dp.num_r_vecs,
			DIV_ROUND_UP(irqs_left, vnics_left));
		nfp_net_irqs_assign(nn, &pf->irq_entries[num_irqs - irqs_left],
				    n);
		irqs_left -= n;
		vnics_left--;
	}

	return 0;
}

static void nfp_net_pf_free_irqs(struct nfp_pf *pf)
{
	nfp_net_irqs_disable(pf->pdev);
	kfree(pf->irq_entries);
}

static int nfp_net_pf_init_vnics(struct nfp_pf *pf)
{
	struct nfp_net *nn;
	unsigned int id;
	int err;

	/* Finish vNIC init and register */
	id = 0;
	list_for_each_entry(nn, &pf->vnics, vnic_list) {
		if (!nfp_net_is_data_vnic(nn))
			continue;
		err = nfp_net_pf_init_vnic(pf, nn, id);
		if (err)
			goto err_prev_deinit;

		id++;
	}

	return 0;

err_prev_deinit:
	list_for_each_entry_continue_reverse(nn, &pf->vnics, vnic_list)
		if (nfp_net_is_data_vnic(nn))
			nfp_net_pf_clean_vnic(pf, nn);
	return err;
}

static void nfp_net_pf_clean_vnics(struct nfp_pf *pf)
{
	struct nfp_net *nn;

	list_for_each_entry(nn, &pf->vnics, vnic_list) {
		if (nfp_net_is_data_vnic(nn))
			nfp_net_pf_clean_vnic(pf, nn);
	}
}

static int
nfp_net_pf_app_init(struct nfp_pf *pf, u8 __iomem *qc_bar, unsigned int stride)
{
	struct devlink *devlink = priv_to_devlink(pf);
	u8 __iomem *ctrl_bar;
	int err;

	pf->app = nfp_app_alloc(pf, nfp_net_pf_get_app_id(pf));
	if (IS_ERR(pf->app))
		return PTR_ERR(pf->app);

	devl_lock(devlink);
	err = nfp_app_init(pf->app);
	devl_unlock(devlink);
	if (err)
		goto err_free;

	if (!nfp_app_needs_ctrl_vnic(pf->app))
		return 0;

	ctrl_bar = nfp_pf_map_rtsym(pf, "net.ctrl", "_pf%u_net_ctrl_bar",
				    NFP_PF_CSR_SLICE_SIZE, &pf->ctrl_vnic_bar);
	if (IS_ERR(ctrl_bar)) {
		nfp_err(pf->cpp, "Failed to find ctrl vNIC memory symbol\n");
		err = PTR_ERR(ctrl_bar);
		goto err_app_clean;
	}

	pf->ctrl_vnic =	nfp_net_pf_alloc_vnic(pf, false, ctrl_bar, qc_bar,
					      stride, 0);
	if (IS_ERR(pf->ctrl_vnic)) {
		err = PTR_ERR(pf->ctrl_vnic);
		goto err_unmap;
	}

	return 0;

err_unmap:
	nfp_cpp_area_release_free(pf->ctrl_vnic_bar);
err_app_clean:
	devl_lock(devlink);
	nfp_app_clean(pf->app);
	devl_unlock(devlink);
err_free:
	nfp_app_free(pf->app);
	pf->app = NULL;
	return err;
}

static void nfp_net_pf_app_clean(struct nfp_pf *pf)
{
	struct devlink *devlink = priv_to_devlink(pf);

	if (pf->ctrl_vnic) {
		nfp_net_pf_free_vnic(pf, pf->ctrl_vnic);
		nfp_cpp_area_release_free(pf->ctrl_vnic_bar);
	}

	devl_lock(devlink);
	nfp_app_clean(pf->app);
	devl_unlock(devlink);

	nfp_app_free(pf->app);
	pf->app = NULL;
}

static int nfp_net_pf_app_start_ctrl(struct nfp_pf *pf)
{
	int err;

	if (!pf->ctrl_vnic)
		return 0;
	err = nfp_net_pf_init_vnic(pf, pf->ctrl_vnic, 0);
	if (err)
		return err;

	err = nfp_ctrl_open(pf->ctrl_vnic);
	if (err)
		goto err_clean_ctrl;

	return 0;

err_clean_ctrl:
	nfp_net_pf_clean_vnic(pf, pf->ctrl_vnic);
	return err;
}

static void nfp_net_pf_app_stop_ctrl(struct nfp_pf *pf)
{
	if (!pf->ctrl_vnic)
		return;
	nfp_ctrl_close(pf->ctrl_vnic);
	nfp_net_pf_clean_vnic(pf, pf->ctrl_vnic);
}

static int nfp_net_pf_app_start(struct nfp_pf *pf)
{
	int err;

	err = nfp_net_pf_app_start_ctrl(pf);
	if (err)
		return err;

	err = nfp_app_start(pf->app, pf->ctrl_vnic);
	if (err)
		goto err_ctrl_stop;

	if (pf->num_vfs) {
		err = nfp_app_sriov_enable(pf->app, pf->num_vfs);
		if (err)
			goto err_app_stop;
	}

	return 0;

err_app_stop:
	nfp_app_stop(pf->app);
err_ctrl_stop:
	nfp_net_pf_app_stop_ctrl(pf);
	return err;
}

static void nfp_net_pf_app_stop(struct nfp_pf *pf)
{
	if (pf->num_vfs)
		nfp_app_sriov_disable(pf->app);
	nfp_app_stop(pf->app);
	nfp_net_pf_app_stop_ctrl(pf);
}

static void nfp_net_pci_unmap_mem(struct nfp_pf *pf)
{
	if (pf->vfcfg_tbl2_area)
		nfp_cpp_area_release_free(pf->vfcfg_tbl2_area);
	if (pf->vf_cfg_bar)
		nfp_cpp_area_release_free(pf->vf_cfg_bar);
	if (pf->mac_stats_bar)
		nfp_cpp_area_release_free(pf->mac_stats_bar);
	nfp_cpp_area_release_free(pf->qc_area);
	nfp_cpp_area_release_free(pf->data_vnic_bar);
}

static int nfp_net_pci_map_mem(struct nfp_pf *pf)
{
	u32 min_size, cpp_id;
	u8 __iomem *mem;
	int err;

	min_size = pf->max_data_vnics * NFP_PF_CSR_SLICE_SIZE;
	mem = nfp_pf_map_rtsym(pf, "net.bar0", "_pf%d_net_bar0",
			       min_size, &pf->data_vnic_bar);
	if (IS_ERR(mem)) {
		nfp_err(pf->cpp, "Failed to find data vNIC memory symbol\n");
		return PTR_ERR(mem);
	}

	if (pf->eth_tbl) {
		min_size =  NFP_MAC_STATS_SIZE * (pf->eth_tbl->max_index + 1);
		pf->mac_stats_mem = nfp_rtsym_map(pf->rtbl, "_mac_stats",
						  "net.macstats", min_size,
						  &pf->mac_stats_bar);
		if (IS_ERR(pf->mac_stats_mem)) {
			if (PTR_ERR(pf->mac_stats_mem) != -ENOENT) {
				err = PTR_ERR(pf->mac_stats_mem);
				goto err_unmap_ctrl;
			}
			pf->mac_stats_mem = NULL;
		}
	}

	pf->vf_cfg_mem = nfp_pf_map_rtsym_offset(pf, "net.vfcfg", "_pf%d_net_vf_bar",
						 NFP_NET_CFG_BAR_SZ * pf->multi_pf.vf_fid,
						 NFP_NET_CFG_BAR_SZ * pf->limit_vfs,
						 &pf->vf_cfg_bar);
	if (IS_ERR(pf->vf_cfg_mem)) {
		if (PTR_ERR(pf->vf_cfg_mem) != -ENOENT) {
			err = PTR_ERR(pf->vf_cfg_mem);
			goto err_unmap_mac_stats;
		}
		pf->vf_cfg_mem = NULL;
	}

	min_size = NFP_NET_VF_CFG_SZ * (pf->limit_vfs + pf->multi_pf.vf_fid) +
		   NFP_NET_VF_CFG_MB_SZ;
	pf->vfcfg_tbl2 = nfp_pf_map_rtsym(pf, "net.vfcfg_tbl2",
					  "_pf%d_net_vf_cfg2",
					  min_size, &pf->vfcfg_tbl2_area);
	if (IS_ERR(pf->vfcfg_tbl2)) {
		if (PTR_ERR(pf->vfcfg_tbl2) != -ENOENT) {
			err = PTR_ERR(pf->vfcfg_tbl2);
			goto err_unmap_vf_cfg;
		}
		pf->vfcfg_tbl2 = NULL;
	}

	cpp_id = NFP_CPP_ISLAND_ID(0, NFP_CPP_ACTION_RW, 0, 0);
	mem = nfp_cpp_map_area(pf->cpp, "net.qc", cpp_id,
			       nfp_qcp_queue_offset(pf->dev_info, 0),
			       pf->dev_info->qc_area_sz, &pf->qc_area);
	if (IS_ERR(mem)) {
		nfp_err(pf->cpp, "Failed to map Queue Controller area.\n");
		err = PTR_ERR(mem);
		goto err_unmap_vfcfg_tbl2;
	}

	return 0;

err_unmap_vfcfg_tbl2:
	if (pf->vfcfg_tbl2_area)
		nfp_cpp_area_release_free(pf->vfcfg_tbl2_area);
err_unmap_vf_cfg:
	if (pf->vf_cfg_bar)
		nfp_cpp_area_release_free(pf->vf_cfg_bar);
err_unmap_mac_stats:
	if (pf->mac_stats_bar)
		nfp_cpp_area_release_free(pf->mac_stats_bar);
err_unmap_ctrl:
	nfp_cpp_area_release_free(pf->data_vnic_bar);
	return err;
}

static const unsigned int lr_to_speed[] = {
	[NFP_NET_CFG_STS_LINK_RATE_UNSUPPORTED]	= 0,
	[NFP_NET_CFG_STS_LINK_RATE_UNKNOWN]	= SPEED_UNKNOWN,
	[NFP_NET_CFG_STS_LINK_RATE_1G]		= SPEED_1000,
	[NFP_NET_CFG_STS_LINK_RATE_10G]		= SPEED_10000,
	[NFP_NET_CFG_STS_LINK_RATE_25G]		= SPEED_25000,
	[NFP_NET_CFG_STS_LINK_RATE_40G]		= SPEED_40000,
	[NFP_NET_CFG_STS_LINK_RATE_50G]		= SPEED_50000,
	[NFP_NET_CFG_STS_LINK_RATE_100G]	= SPEED_100000,
};

unsigned int nfp_net_lr2speed(unsigned int linkrate)
{
	if (linkrate < ARRAY_SIZE(lr_to_speed))
		return lr_to_speed[linkrate];

	return SPEED_UNKNOWN;
}

unsigned int nfp_net_speed2lr(unsigned int speed)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(lr_to_speed); i++) {
		if (speed == lr_to_speed[i])
			return i;
	}

	return NFP_NET_CFG_STS_LINK_RATE_UNKNOWN;
}

static void nfp_net_notify_port_speed(struct nfp_port *port)
{
	struct net_device *netdev = port->netdev;
	struct nfp_net *nn;
	u16 sts;

	if (!nfp_netdev_is_nfp_net(netdev))
		return;

	nn = netdev_priv(netdev);
	sts = nn_readw(nn, NFP_NET_CFG_STS);

	if (!(sts & NFP_NET_CFG_STS_LINK)) {
		nn_writew(nn, NFP_NET_CFG_STS_NSP_LINK_RATE, NFP_NET_CFG_STS_LINK_RATE_UNKNOWN);
		return;
	}

	nn_writew(nn, NFP_NET_CFG_STS_NSP_LINK_RATE, nfp_net_speed2lr(port->eth_port->speed));
}

static int
nfp_net_eth_port_update(struct nfp_cpp *cpp, struct nfp_port *port,
			struct nfp_eth_table *eth_table)
{
	struct nfp_eth_table_port *eth_port;

	ASSERT_RTNL();

	eth_port = nfp_net_find_port(eth_table, port->eth_id);
	if (!eth_port) {
		set_bit(NFP_PORT_CHANGED, &port->flags);
		nfp_warn(cpp, "Warning: port #%d not present after reconfig\n",
			 port->eth_id);
		return -EIO;
	}
	if (eth_port->override_changed) {
		nfp_warn(cpp, "Port #%d config changed, unregistering. Driver reload required before port will be operational again.\n", port->eth_id);
		port->type = NFP_PORT_INVALID;
	}

	memcpy(port->eth_port, eth_port, sizeof(*eth_port));
	nfp_net_notify_port_speed(port);

	return 0;
}

int nfp_net_refresh_port_table_sync(struct nfp_pf *pf)
{
	struct devlink *devlink = priv_to_devlink(pf);
	struct nfp_eth_table *eth_table;
	struct nfp_net *nn, *next;
	struct nfp_port *port;
	int err;

	devl_assert_locked(devlink);

	/* Check for nfp_net_pci_remove() racing against us */
	if (list_empty(&pf->vnics))
		return 0;

	/* Update state of all ports */
	rtnl_lock();
	list_for_each_entry(port, &pf->ports, port_list)
		clear_bit(NFP_PORT_CHANGED, &port->flags);

	eth_table = nfp_eth_read_ports(pf->cpp);
	if (!eth_table) {
		list_for_each_entry(port, &pf->ports, port_list)
			if (__nfp_port_get_eth_port(port))
				set_bit(NFP_PORT_CHANGED, &port->flags);
		rtnl_unlock();
		nfp_err(pf->cpp, "Error refreshing port config!\n");
		return -EIO;
	}

	list_for_each_entry(port, &pf->ports, port_list)
		if (__nfp_port_get_eth_port(port))
			nfp_net_eth_port_update(pf->cpp, port, eth_table);
	rtnl_unlock();

	kfree(eth_table);

	/* Resync repr state. This may cause reprs to be removed. */
	err = nfp_reprs_resync_phys_ports(pf->app);
	if (err)
		return err;

	/* Shoot off the ports which became invalid */
	list_for_each_entry_safe(nn, next, &pf->vnics, vnic_list) {
		if (!nn->port || nn->port->type != NFP_PORT_INVALID)
			continue;

		nfp_net_pf_clean_vnic(pf, nn);
		nfp_net_pf_free_vnic(pf, nn);
	}

	return 0;
}

static void nfp_net_refresh_vnics(struct work_struct *work)
{
	struct nfp_pf *pf = container_of(work, struct nfp_pf,
					 port_refresh_work);
	struct devlink *devlink = priv_to_devlink(pf);

	devl_lock(devlink);
	nfp_net_refresh_port_table_sync(pf);
	devl_unlock(devlink);
}

void nfp_net_refresh_port_table(struct nfp_port *port)
{
	struct nfp_pf *pf = port->app->pf;

	set_bit(NFP_PORT_CHANGED, &port->flags);

	queue_work(pf->wq, &pf->port_refresh_work);
}

int nfp_net_refresh_eth_port(struct nfp_port *port)
{
	struct nfp_cpp *cpp = port->app->cpp;
	struct nfp_eth_table *eth_table;
	int ret;

	clear_bit(NFP_PORT_CHANGED, &port->flags);

	eth_table = nfp_eth_read_ports(cpp);
	if (!eth_table) {
		set_bit(NFP_PORT_CHANGED, &port->flags);
		nfp_err(cpp, "Error refreshing port state table!\n");
		return -EIO;
	}

	ret = nfp_net_eth_port_update(cpp, port, eth_table);

	kfree(eth_table);

	return ret;
}

static int nfp_net_pre_init(struct nfp_pf *pf, int *stride)
{
	struct nfp_net_fw_version fw_ver;
	struct nfp_cpp_area *area;
	u8 __iomem *ctrl_bar;
	int err = 0;

	ctrl_bar = nfp_pf_map_rtsym(pf, NULL, "_pf%d_net_bar0", NFP_PF_CSR_SLICE_SIZE, &area);
	if (IS_ERR(ctrl_bar)) {
		nfp_err(pf->cpp, "Failed to find data vNIC memory symbol\n");
		return pf->fw_loaded ? PTR_ERR(ctrl_bar) : 1;
	}

	nfp_net_get_fw_version(&fw_ver, ctrl_bar);
	if (fw_ver.extend & NFP_NET_CFG_VERSION_RESERVED_MASK ||
	    fw_ver.class != NFP_NET_CFG_VERSION_CLASS_GENERIC) {
		nfp_err(pf->cpp, "Unknown Firmware ABI %d.%d.%d.%d\n",
			fw_ver.extend, fw_ver.class,
			fw_ver.major, fw_ver.minor);
		err = -EINVAL;
		goto end;
	}

	/* Determine stride */
	if (nfp_net_fw_ver_eq(&fw_ver, 0, 0, 0, 1)) {
		*stride = 2;
		nfp_warn(pf->cpp, "OBSOLETE Firmware detected - VF isolation not available\n");
	} else {
		switch (fw_ver.major) {
		case 1 ... 5:
			*stride = 4;
			break;
		default:
			nfp_err(pf->cpp, "Unsupported Firmware ABI %d.%d.%d.%d\n",
				fw_ver.extend, fw_ver.class,
				fw_ver.major, fw_ver.minor);
			err = -EINVAL;
			goto end;
		}
	}

	if (!pf->multi_pf.en)
		goto end;

	/* Enable multi-PF. */
	if (readl(ctrl_bar + NFP_NET_CFG_CAP_WORD1) & NFP_NET_CFG_CTRL_MULTI_PF) {
		unsigned long long addr;
		u32 cfg_q, cpp_id, ret;
		unsigned long timeout;

		writel(NFP_NET_CFG_CTRL_MULTI_PF, ctrl_bar + NFP_NET_CFG_CTRL_WORD1);
		writel(NFP_NET_CFG_UPDATE_GEN, ctrl_bar + NFP_NET_CFG_UPDATE);

		/* Config queue is next to txq. */
		cfg_q = readl(ctrl_bar + NFP_NET_CFG_START_TXQ) + 1;
		addr = nfp_qcp_queue_offset(pf->dev_info, cfg_q) + NFP_QCP_QUEUE_ADD_WPTR;
		cpp_id = NFP_CPP_ISLAND_ID(0, NFP_CPP_ACTION_RW, 0, 0);
		err = nfp_cpp_writel(pf->cpp, cpp_id, addr, 1);
		if (err)
			goto end;

		timeout = jiffies + HZ * NFP_NET_POLL_TIMEOUT;
		while ((ret = readl(ctrl_bar + NFP_NET_CFG_UPDATE))) {
			if (ret & NFP_NET_CFG_UPDATE_ERR) {
				nfp_err(pf->cpp, "Enalbe multi-PF failed\n");
				err = -EIO;
				break;
			}

			usleep_range(250, 500);
			if (time_is_before_eq_jiffies(timeout)) {
				nfp_err(pf->cpp, "Enalbe multi-PF timeout\n");
				err = -ETIMEDOUT;
				break;
			}
		};
	} else {
		nfp_err(pf->cpp, "Loaded firmware doesn't support multi-PF\n");
		err = -EINVAL;
	}

end:
	nfp_cpp_area_release_free(area);
	return err;
}

/*
 * PCI device functions
 */
int nfp_net_pci_probe(struct nfp_pf *pf)
{
	struct devlink *devlink = priv_to_devlink(pf);
	u8 __iomem *ctrl_bar, *qc_bar;
	int stride = 0;
	int err;

	INIT_WORK(&pf->port_refresh_work, nfp_net_refresh_vnics);

	if (!pf->rtbl) {
		nfp_err(pf->cpp, "No %s, giving up.\n",
			pf->fw_loaded ? "symbol table" : "firmware found");
		return -EINVAL;
	}

	err = nfp_net_pre_init(pf, &stride);
	if (err)
		return err;

	pf->max_data_vnics = nfp_net_pf_get_num_ports(pf);
	if ((int)pf->max_data_vnics < 0)
		return pf->max_data_vnics;
	if (pf->multi_pf.en && pf->max_data_vnics != 1) {
		nfp_err(pf->cpp, "Only one data_vnic per PF is supported in multiple PF setup, please update FW.\n");
		return -EPERM;
	}

	err = nfp_net_pci_map_mem(pf);
	if (err)
		return err;

	ctrl_bar = nfp_cpp_area_iomem(pf->data_vnic_bar);
	qc_bar = nfp_cpp_area_iomem(pf->qc_area);
	if (!ctrl_bar || !qc_bar) {
		err = -EIO;
		goto err_unmap;
	}

	err = nfp_net_pf_app_init(pf, qc_bar, stride);
	if (err)
		goto err_unmap;

	err = nfp_shared_buf_register(pf);
	if (err)
		goto err_devlink_unreg;

	devl_lock(devlink);
	err = nfp_devlink_params_register(pf);
	if (err)
		goto err_shared_buf_unreg;

	pf->ddir = nfp_net_debugfs_device_add(pf->pdev);

	/* Allocate the vnics and do basic init */
	err = nfp_net_pf_alloc_vnics(pf, ctrl_bar, qc_bar, stride);
	if (err)
		goto err_clean_ddir;

	err = nfp_net_pf_alloc_irqs(pf);
	if (err)
		goto err_free_vnics;

	err = nfp_net_pf_app_start(pf);
	if (err)
		goto err_free_irqs;

	err = nfp_net_pf_init_vnics(pf);
	if (err)
		goto err_stop_app;

	err = nfp_net_pf_init_sriov(pf);
	if (err)
		goto err_clean_vnics;

	devl_unlock(devlink);
	devlink_register(devlink);

	return 0;

err_clean_vnics:
	nfp_net_pf_clean_vnics(pf);
err_stop_app:
	nfp_net_pf_app_stop(pf);
err_free_irqs:
	nfp_net_pf_free_irqs(pf);
err_free_vnics:
	nfp_net_pf_free_vnics(pf);
err_clean_ddir:
	nfp_net_debugfs_dir_clean(&pf->ddir);
	nfp_devlink_params_unregister(pf);
err_shared_buf_unreg:
	devl_unlock(devlink);
	nfp_shared_buf_unregister(pf);
err_devlink_unreg:
	cancel_work_sync(&pf->port_refresh_work);
	nfp_net_pf_app_clean(pf);
err_unmap:
	nfp_net_pci_unmap_mem(pf);
	return err;
}

void nfp_net_pci_remove(struct nfp_pf *pf)
{
	struct devlink *devlink = priv_to_devlink(pf);
	struct nfp_net *nn, *next;

	devlink_unregister(priv_to_devlink(pf));
	devl_lock(devlink);
	list_for_each_entry_safe(nn, next, &pf->vnics, vnic_list) {
		if (!nfp_net_is_data_vnic(nn))
			continue;
		nfp_net_pf_clean_vnic(pf, nn);
		nfp_net_pf_free_vnic(pf, nn);
	}

	nfp_net_pf_app_stop(pf);
	/* stop app first, to avoid double free of ctrl vNIC's ddir */
	nfp_net_debugfs_dir_clean(&pf->ddir);

	nfp_devlink_params_unregister(pf);

	devl_unlock(devlink);

	nfp_shared_buf_unregister(pf);

	nfp_net_pf_free_irqs(pf);
	nfp_net_pf_app_clean(pf);
	nfp_net_pci_unmap_mem(pf);

	cancel_work_sync(&pf->port_refresh_work);
}
