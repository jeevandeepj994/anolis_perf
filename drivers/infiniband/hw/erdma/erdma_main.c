// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB

/* Authors: Cheng Xu <chengyou@linux.alibaba.com> */
/*          Kai Shen <kaishen@linux.alibaba.com> */
/* Copyright (c) 2020-2022, Alibaba Group. */

#include <linux/cdev.h>
#include <linux/errno.h>
#include <linux/if_arp.h>
#include <linux/inetdevice.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/pci.h>
#include <linux/rtnetlink.h>
#include <linux/etherdevice.h>

#include <net/addrconf.h>
#include <net/net_namespace.h>

#include <rdma/ib_verbs.h>
#include <rdma/ib_user_verbs.h>
#include <uapi/rdma/erdma-abi.h>

#include "erdma.h"
#include "erdma_cm.h"
#include "erdma_debug.h"
#include "erdma_hw.h"
#include "erdma_ioctl.h"
#include "erdma_stats.h"
#include "erdma_verbs.h"

MODULE_AUTHOR("Cheng Xu <chengyou@linux.alibaba.com>");
MODULE_DESCRIPTION("Alibaba elasticRDMA adapter driver");
MODULE_LICENSE("Dual BSD/GPL");

__u32 dprint_mask;
module_param(dprint_mask, uint, 0644);
MODULE_PARM_DESC(dprint_mask, "debug information print level");

bool compat_mode;
module_param(compat_mode, bool, 0444);
MODULE_PARM_DESC(compat_mode, "compat mode support");

static unsigned int vector_num = ERDMA_NUM_MSIX_VEC;
module_param(vector_num, uint, 0444);
MODULE_PARM_DESC(vector_num, "number of compeletion vectors");

static int erdma_device_register(struct erdma_dev *dev)
{
	struct ib_device *ibdev = &dev->ibdev;
	int ret;

	memset(ibdev->name, 0, IB_DEVICE_NAME_MAX);
	/*
	 * In Ali ECS environment, ENI's mac address is unique in VPC.
	 * So, generating the ibdev's name from mac address of the binded
	 * netdev.
	 */
	ret = snprintf(ibdev->name, IB_DEVICE_NAME_MAX, "%s_%.2x%.2x%.2x",
		       DRV_MODULE_NAME, dev->attrs.peer_addr[3],
		       dev->attrs.peer_addr[4], dev->attrs.peer_addr[5]);
	if (ret < 0)
		return ret;

	addrconf_addr_eui48((u8 *)&ibdev->node_guid, dev->netdev->dev_addr);

	ibdev->phys_port_cnt = 1;
	ret = ib_device_set_netdev(ibdev, dev->netdev, 1);
	if (ret)
		return ret;
	ret = ib_register_device(ibdev, ibdev->name, &dev->pdev->dev);
	if (ret) {
		dev_err(&dev->pdev->dev,
			"ib_register_device(%s) failed: ret = %d\n",
			ibdev->name, ret);
		return ret;
	}

	dprint(DBG_DM,
	       " Registered '%s' for interface '%s',HWaddr=%02x.%02x.%02x.%02x.%02x.%02x\n",
	       ibdev->name, dev->netdev->name, *(__u8 *)dev->netdev->dev_addr,
	       *((__u8 *)dev->netdev->dev_addr + 1),
	       *((__u8 *)dev->netdev->dev_addr + 2),
	       *((__u8 *)dev->netdev->dev_addr + 3),
	       *((__u8 *)dev->netdev->dev_addr + 4),
	       *((__u8 *)dev->netdev->dev_addr + 5));

	dev->is_registered = 1;

	return 0;
}

int erdma_find_netdev_and_register_ibdev(struct erdma_dev *dev)
{
	struct net *net;
	struct net_device *ndev;

	rtnl_lock();
	down_read(&net_rwsem);
	for_each_net(net)
		for_each_netdev(net, ndev) {
			if (ether_addr_equal_unaligned(ndev->perm_addr, dev->attrs.peer_addr)) {
				dev->netdev = ndev;
				break;
			}
		}
	up_read(&net_rwsem);
	rtnl_unlock();

	if (dev->netdev)
		return erdma_device_register(dev);

	return -ENODEV;
}

static void erdma_device_deregister(struct erdma_dev *edev)
{
	int i;

	ib_unregister_device(&edev->ibdev);

	WARN_ON(atomic_read(&edev->num_ctx));
	WARN_ON(atomic_read(&edev->num_cep));
	i = 0;

	while (!list_empty(&edev->cep_list)) {
		struct erdma_cep *cep =
			list_entry(edev->cep_list.next, struct erdma_cep, devq);
		list_del(&cep->devq);
		dprint(DBG_ON, ": Free CEP (0x%p), state: %d\n", cep,
		       cep->state);
		kfree(cep);
		i++;
	}
	if (i)
		pr_warn("erdma device deregister: free'd %d CEPs\n", i);
}

static int erdma_netdev_event(struct notifier_block *nb, unsigned long event,
			      void *arg)
{
	struct net_device *netdev = netdev_notifier_info_to_dev(arg);
	struct erdma_dev *dev = container_of(nb, struct erdma_dev, netdev_nb);

	dprint(DBG_CTRL, " netdev:%s,ns:%p: Event %lu to erdma_dev %p\n",
	       netdev->name, dev_net(netdev), event, dev);

	if ((dev->netdev == NULL && event != NETDEV_REGISTER) ||
	    (dev->netdev != NULL && dev->netdev != netdev))
		return NOTIFY_DONE;

	switch (event) {
	case NETDEV_UP:
		dev->state = IB_PORT_ACTIVE;
		erdma_port_event(dev, IB_EVENT_PORT_ACTIVE);
		break;
	case NETDEV_DOWN:
		dev->state = IB_PORT_DOWN;
		erdma_port_event(dev, IB_EVENT_PORT_ERR);
		break;
	case NETDEV_REGISTER:
		if (!compat_mode &&
		    ether_addr_equal_unaligned(netdev->perm_addr,
					       dev->attrs.peer_addr)) {
			dev->netdev = netdev;
			dev->state = IB_PORT_INIT;
			if (!dev->is_registered) {
				dprint(DBG_DM,
					": new erdma lowlevel device for %s\n",
					netdev->name);
				erdma_device_register(dev);
			}
		}
		break;
	case NETDEV_UNREGISTER:
	case NETDEV_CHANGEADDR:
	case NETDEV_CHANGEMTU:
	case NETDEV_GOING_DOWN:
	case NETDEV_CHANGE:
	default:
		break;
	}

	return NOTIFY_OK;
}

static irqreturn_t erdma_comm_irq_handler(int irq, void *data)
{
	struct erdma_dev *dev = data;

	erdma_cmdq_completion_handler(&dev->cmdq);
	erdma_aeq_event_handler(dev);

	return IRQ_HANDLED;
}

static void erdma_dwqe_resource_init(struct erdma_dev *dev)
{
	int total_pages, type0, type1;

	dev->attrs.grp_num = erdma_reg_read32(dev, ERDMA_REGS_GRP_NUM_REG);

	if (dev->attrs.grp_num < 4)
		dev->attrs.disable_dwqe = true;
	else
		dev->attrs.disable_dwqe = false;

	/* One page contains 4 goups. */
	total_pages = dev->attrs.grp_num * 4;

	if (dev->attrs.grp_num >= ERDMA_DWQE_MAX_GRP_CNT) {
		dev->attrs.grp_num = ERDMA_DWQE_MAX_GRP_CNT;
		type0 = ERDMA_DWQE_TYPE0_CNT;
		type1 = ERDMA_DWQE_TYPE1_CNT / ERDMA_DWQE_TYPE1_CNT_PER_PAGE;
	} else {
		type1 = total_pages / 3;
		type0 = total_pages - type1 - 1;
	}

	dev->attrs.dwqe_pages = type0;
	dev->attrs.dwqe_entries = type1 * ERDMA_DWQE_TYPE1_CNT_PER_PAGE;

	dev_info(&dev->pdev->dev, "grp_num:%d, total pages:%d, type0:%d, type1:%d, type1_db_cnt:%d\n",
		dev->attrs.grp_num, total_pages, type0, type1, type1 * 16);
}

static int erdma_request_vectors(struct erdma_dev *dev)
{
	int expect_irq_num = min(num_possible_cpus() + 1, vector_num);
	dev->attrs.irq_num = pci_alloc_irq_vectors(dev->pdev, 1, expect_irq_num,
						   PCI_IRQ_MSIX);
	if (dev->attrs.irq_num <= 0) {
		dev_err(&dev->pdev->dev, "request irq vectors failed(%d)\n",
			dev->attrs.irq_num);
		return -ENOSPC;
	}

	return 0;
}

static int erdma_comm_irq_init(struct erdma_dev *dev)
{
	snprintf(dev->comm_irq.name, ERDMA_IRQNAME_SIZE, "erdma-common@pci:%s",
		 pci_name(dev->pdev));
	dev->comm_irq.msix_vector =
		pci_irq_vector(dev->pdev, ERDMA_MSIX_VECTOR_CMDQ);

	cpumask_set_cpu(cpumask_first(cpumask_of_pcibus(dev->pdev->bus)),
			&dev->comm_irq.affinity_hint_mask);
	irq_set_affinity_hint(dev->comm_irq.msix_vector,
			      &dev->comm_irq.affinity_hint_mask);

	return request_irq(dev->comm_irq.msix_vector, erdma_comm_irq_handler, 0,
			   dev->comm_irq.name, dev);
}

static void erdma_comm_irq_uninit(struct erdma_dev *dev)
{
	irq_set_affinity_hint(dev->comm_irq.msix_vector, NULL);
	free_irq(dev->comm_irq.msix_vector, dev);
}

static int erdma_device_init(struct erdma_dev *dev, struct pci_dev *pdev)
{
	int ret;

	erdma_dwqe_resource_init(dev);

	ret = dma_set_mask_and_coherent(&pdev->dev,
					 DMA_BIT_MASK(ERDMA_PCI_WIDTH));
	if (ret)
		return ret;

	dma_set_max_seg_size(&pdev->dev, UINT_MAX);

	return 0;
}

static void erdma_device_uninit(struct erdma_dev *dev)
{
	u32 ctrl = FIELD_PREP(ERDMA_REG_DEV_CTRL_RESET_MASK, 1);

	erdma_reg_write32(dev, ERDMA_REGS_DEV_CTRL_REG, ctrl);
}

static const struct pci_device_id erdma_pci_tbl[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_ALIBABA, 0x107f) },
	{}
};

static int erdma_probe_dev(struct pci_dev *pdev)
{
	int err;
	struct erdma_dev *dev;
	u32 version;
	int bars;

	err = pci_enable_device(pdev);
	if (err) {
		dev_err(&pdev->dev, "pci_enable_device failed(%d)\n", err);
		return err;
	}

	pci_set_master(pdev);

	dev = ib_alloc_device(erdma_dev, ibdev);
	if (!dev) {
		dev_err(&pdev->dev, "ib_alloc_device failed\n");
		err = -ENOMEM;
		goto err_disable_device;
	}

	pci_set_drvdata(pdev, dev);
	dev->pdev = pdev;
	dev->attrs.numa_node = dev_to_node(&pdev->dev);

	bars = pci_select_bars(pdev, IORESOURCE_MEM);
	err = pci_request_selected_regions(pdev, bars, DRV_MODULE_NAME);
	if (bars != ERDMA_BAR_MASK || err) {
		err = err ? err : -EINVAL;
		goto err_ib_device_release;
	}

	dev->func_bar_addr = pci_resource_start(pdev, ERDMA_FUNC_BAR);
	dev->func_bar_len = pci_resource_len(pdev, ERDMA_FUNC_BAR);

	dev->func_bar =
		devm_ioremap(&pdev->dev, dev->func_bar_addr, dev->func_bar_len);
	if (!dev->func_bar) {
		dev_err(&pdev->dev, "devm_ioremap failed.\n");
		err = -EFAULT;
		goto err_release_bars;
	}

	version = erdma_reg_read32(dev, ERDMA_REGS_VERSION_REG);
	if (version == 0) {
		/* we knows that it is a non-functional function. */
		err = -ENODEV;
		goto err_iounmap_func_bar;
	}

	err = erdma_device_init(dev, pdev);
	if (err)
		goto err_iounmap_func_bar;

	err = erdma_request_vectors(dev);
	if (err)
		goto err_iounmap_func_bar;

	err = erdma_comm_irq_init(dev);
	if (err)
		goto err_free_vectors;

	err = erdma_aeq_init(dev);
	if (err)
		goto err_uninit_comm_irq;

	err = erdma_cmdq_init(dev);
	if (err)
		goto err_uninit_aeq;

	err = erdma_ceqs_init(dev);
	if (err)
		goto err_uninit_cmdq;

	msleep(500);

	erdma_finish_cmdq_init(dev);

	return 0;

err_uninit_cmdq:
	erdma_device_uninit(dev);
	erdma_cmdq_destroy(dev);

err_uninit_aeq:
	erdma_aeq_destroy(dev);

err_uninit_comm_irq:
	erdma_comm_irq_uninit(dev);

err_free_vectors:
	pci_free_irq_vectors(dev->pdev);

err_iounmap_func_bar:
	devm_iounmap(&pdev->dev, dev->func_bar);

err_release_bars:
	pci_release_selected_regions(pdev, bars);

err_ib_device_release:
	ib_dealloc_device(&dev->ibdev);

err_disable_device:
	pci_disable_device(pdev);

	return err;
}

static void erdma_remove_dev(struct pci_dev *pdev)
{
	struct erdma_dev *dev = pci_get_drvdata(pdev);

	erdma_ceqs_uninit(dev);

	erdma_device_uninit(dev);

	erdma_cmdq_destroy(dev);
	erdma_aeq_destroy(dev);
	erdma_comm_irq_uninit(dev);
	pci_free_irq_vectors(dev->pdev);

	devm_iounmap(&pdev->dev, dev->func_bar);
	pci_release_selected_regions(pdev, ERDMA_BAR_MASK);

	ib_dealloc_device(&dev->ibdev);

	pci_disable_device(pdev);
}

static void erdma_stats_init(struct erdma_dev *dev)
{
	atomic64_t *s = (atomic64_t *)&dev->stats;
	int i;

	for (i = 0; i < sizeof(dev->stats) / sizeof(*s); i++, s++)
		atomic64_set(s, 0);
}

static int erdma_check_version(struct erdma_dev *dev)
{
	u8 fw_major = (dev->attrs.fw_version >> 16);
	u8 fw_medium = (dev->attrs.fw_version >> 8);

	return (fw_major != ERDMA_MAJOR_VER || fw_medium != ERDMA_MEDIUM_VER) ? -1 : 0;
}

#define ERDMA_GET_CAP(name, cap) FIELD_GET(ERDMA_CMD_DEV_CAP_##name##_MASK, cap)

static int erdma_dev_attrs_init(struct erdma_dev *dev)
{
	int err;
	u64 req_hdr, cap0, cap1;

	erdma_cmdq_build_reqhdr(&req_hdr, CMDQ_SUBMOD_RDMA,
				CMDQ_OPCODE_QUERY_DEVICE);

	err = erdma_post_cmd_wait(&dev->cmdq, &req_hdr, sizeof(req_hdr), &cap0,
				  &cap1);
	if (err)
		return err;

	dev->attrs.max_cqe = 1 << ERDMA_GET_CAP(MAX_CQE, cap0);
	dev->attrs.max_mr_size = 1ULL << ERDMA_GET_CAP(MAX_MR_SIZE, cap0);
	dev->attrs.max_mw = 1 << ERDMA_GET_CAP(MAX_MW, cap1);
	dev->attrs.max_recv_wr = 1 << ERDMA_GET_CAP(MAX_RECV_WR, cap0);
	dev->attrs.local_dma_key = ERDMA_GET_CAP(DMA_LOCAL_KEY, cap1);
	dev->attrs.cc = ERDMA_GET_CAP(DEFAULT_CC, cap1);
	dev->attrs.max_qp = ERDMA_NQP_PER_QBLOCK * ERDMA_GET_CAP(QBLOCK, cap1);
	dev->attrs.max_mr = dev->attrs.max_qp << 1;
	dev->attrs.max_cq = dev->attrs.max_qp << 1;

	dev->attrs.max_send_wr = ERDMA_MAX_SEND_WR;
	dev->attrs.max_ord = ERDMA_MAX_ORD;
	dev->attrs.max_ird = ERDMA_MAX_IRD;
	dev->attrs.max_send_sge = ERDMA_MAX_SEND_SGE;
	dev->attrs.max_recv_sge = ERDMA_MAX_RECV_SGE;
	dev->attrs.max_sge_rd = ERDMA_MAX_SGE_RD;
	dev->attrs.max_pd = ERDMA_MAX_PD;

	dev->res_cb[ERDMA_RES_TYPE_PD].max_cap = ERDMA_MAX_PD;
	dev->res_cb[ERDMA_RES_TYPE_STAG_IDX].max_cap = dev->attrs.max_mr;

	erdma_cmdq_build_reqhdr(&req_hdr, CMDQ_SUBMOD_COMMON,
				CMDQ_OPCODE_QUERY_FW_INFO);

	err = erdma_post_cmd_wait(&dev->cmdq, &req_hdr, sizeof(req_hdr), &cap0,
				  &cap1);
	if (!err)
		dev->attrs.fw_version =
			FIELD_GET(ERDMA_CMD_INFO0_FW_VER_MASK, cap0);

	return erdma_check_version(dev);
}

static int erdma_res_cb_init(struct erdma_dev *dev)
{
	int i, j;

	for (i = 0; i < ERDMA_RES_CNT; i++) {
		dev->res_cb[i].next_alloc_idx = 1;
		spin_lock_init(&dev->res_cb[i].lock);
		dev->res_cb[i].bitmap =
			kcalloc(BITS_TO_LONGS(dev->res_cb[i].max_cap),
				sizeof(unsigned long), GFP_KERNEL);
		/* We will free the memory in erdma_res_cb_free */
		if (!dev->res_cb[i].bitmap)
			goto err;
	}

	return 0;

err:
	for (j = 0; j < i; j++)
		kfree(dev->res_cb[j].bitmap);

	return -ENOMEM;
}

static void erdma_res_cb_free(struct erdma_dev *dev)
{
	int i;

	for (i = 0; i < ERDMA_RES_CNT; i++)
		kfree(dev->res_cb[i].bitmap);
}

static const struct ib_device_ops erdma_device_ops = {
	.owner = THIS_MODULE,
	.driver_id = RDMA_DRIVER_ERDMA,
	.uverbs_abi_ver = ERDMA_ABI_VERSION,
	.alloc_hw_stats = erdma_alloc_hw_stats,
	.alloc_mr = erdma_ib_alloc_mr,
	.alloc_pd = erdma_alloc_pd,
	.alloc_ucontext = erdma_alloc_ucontext,
	.create_cq = erdma_create_cq,
	.create_qp = erdma_kzalloc_qp,
	.dealloc_pd = erdma_dealloc_pd,
	.dealloc_ucontext = erdma_dealloc_ucontext,
	.dereg_mr = erdma_dereg_mr,
	.destroy_cq = erdma_destroy_cq,
	.destroy_qp = erdma_destroy_qp,
	.disassociate_ucontext = erdma_disassociate_ucontext,
	.get_dma_mr = erdma_get_dma_mr,
	.get_hw_stats = erdma_get_hw_stats,
	.get_port_immutable = erdma_get_port_immutable,
	.iw_accept = erdma_accept,
	.iw_add_ref = erdma_qp_get_ref,
	.iw_connect = erdma_connect,
	.iw_create_listen = erdma_create_listen,
	.iw_destroy_listen = erdma_destroy_listen,
	.iw_get_qp = erdma_get_ibqp,
	.iw_reject = erdma_reject,
	.iw_rem_ref = erdma_qp_put_ref,
	.map_mr_sg = erdma_map_mr_sg,
	.mmap = erdma_mmap,
	.mmap_free = erdma_mmap_free,
	.modify_qp = erdma_modify_qp,
	.post_recv = erdma_post_recv,
	.post_send = erdma_post_send,
	.poll_cq = erdma_poll_cq,
	.query_device = erdma_query_device,
	.query_gid = erdma_query_gid,
	.query_port = erdma_query_port,
	.query_qp = erdma_query_qp,
	.req_notify_cq = erdma_req_notify_cq,
	.reg_user_mr = erdma_reg_user_mr,
	.get_netdev = erdma_get_netdev,
	.drain_sq = erdma_drain_sq,
	.drain_rq = erdma_drain_rq,
	.query_pkey = erdma_query_pkey,

	INIT_RDMA_OBJ_SIZE(ib_cq, erdma_cq, ibcq),
	INIT_RDMA_OBJ_SIZE(ib_pd, erdma_pd, ibpd),
	INIT_RDMA_OBJ_SIZE(ib_ucontext, erdma_ucontext, ibucontext),
};

static const struct ib_device_ops erdma_compat_ops = {
	.get_link_layer = erdma_get_link_layer,
	.query_pkey = erdma_query_pkey
};

static int erdma_ib_device_add(struct pci_dev *pdev)
{
	struct erdma_dev *dev = pci_get_drvdata(pdev);
	struct ib_device *ibdev = &dev->ibdev;
	u64 mac;
	int ret = 0;

	dprint(DBG_INIT, "init erdma_dev(%p)\n", dev);

	erdma_stats_init(dev);

	ret = erdma_dev_attrs_init(dev);
	if (ret)
		return ret;

	ibdev->uverbs_cmd_mask |=
		(1ull << IB_USER_VERBS_CMD_GET_CONTEXT) |
		(1ull << IB_USER_VERBS_CMD_QUERY_DEVICE) |
		(1ull << IB_USER_VERBS_CMD_QUERY_PORT) |
		(1ull << IB_USER_VERBS_CMD_ALLOC_PD) |
		(1ull << IB_USER_VERBS_CMD_DEALLOC_PD) |
		(1ull << IB_USER_VERBS_CMD_REG_MR) |
		(1ull << IB_USER_VERBS_CMD_DEREG_MR) |
		(1ull << IB_USER_VERBS_CMD_CREATE_COMP_CHANNEL) |
		(1ull << IB_USER_VERBS_CMD_CREATE_CQ) |
		(1ull << IB_USER_VERBS_CMD_DESTROY_CQ) |
		(1ull << IB_USER_VERBS_CMD_CREATE_QP) |
		(1ull << IB_USER_VERBS_CMD_QUERY_QP) |
		(1ull << IB_USER_VERBS_CMD_MODIFY_QP) |
		(1ull << IB_USER_VERBS_CMD_DESTROY_QP);

	if (compat_mode)
		ibdev->node_type = RDMA_NODE_IB_CA;
	else
		ibdev->node_type = RDMA_NODE_RNIC;
	memcpy(ibdev->node_desc, ERDMA_NODE_DESC, sizeof(ERDMA_NODE_DESC));

	/*
	 * Current model (one-to-one device association):
	 * One ERDMA device per net_device or, equivalently,
	 * per physical port.
	 */
	ibdev->phys_port_cnt = 1;
	ibdev->num_comp_vectors = dev->attrs.irq_num - 1;
	ibdev->dev.parent = &pdev->dev;

	ib_set_device_ops(ibdev, &erdma_device_ops);
	if (compat_mode)
		ib_set_device_ops(ibdev, &erdma_compat_ops);

	INIT_LIST_HEAD(&dev->cep_list);

	spin_lock_init(&dev->lock);
	xa_init_flags(&dev->qp_xa, XA_FLAGS_ALLOC1);
	xa_init_flags(&dev->cq_xa, XA_FLAGS_ALLOC1);
	dev->next_alloc_cqn = 1;
	dev->next_alloc_qpn = 1;

	ret = erdma_res_cb_init(dev);
	if (ret)
		return ret;

	spin_lock_init(&dev->db_bitmap_lock);
	bitmap_zero(dev->sdb_page, ERDMA_DWQE_TYPE0_CNT);
	bitmap_zero(dev->sdb_entry, ERDMA_DWQE_TYPE1_CNT);

	atomic_set(&dev->num_ctx, 0);

	dprint(DBG_INIT, "ib device create ok.\n");

	mac = erdma_reg_read32(dev, ERDMA_REGS_NETDEV_MAC_L_REG);
	mac |= (u64)erdma_reg_read32(dev, ERDMA_REGS_NETDEV_MAC_H_REG) << 32;

	dev_info(&dev->pdev->dev, "assoc netdev mac addr is 0x%llx.\n",
		 mac);

	u64_to_ether_addr(mac, dev->attrs.peer_addr);
	dev->netdev = NULL;

	if (compat_mode) {
		ret = erdma_find_netdev_and_register_ibdev(dev);
		if (ret)
			goto err_out;
	}

	dev->netdev_nb.notifier_call = erdma_netdev_event;
	ret = register_netdevice_notifier(&dev->netdev_nb);
	if (ret)
		goto err_out;

	return 0;

err_out:
	if (dev->is_registered && compat_mode)
		ib_unregister_device(&dev->ibdev);

	xa_destroy(&dev->qp_xa);
	xa_destroy(&dev->cq_xa);

	erdma_res_cb_free(dev);

	return ret;
}

static void erdma_ib_device_remove(struct pci_dev *pdev)
{
	struct erdma_dev *dev = pci_get_drvdata(pdev);

	unregister_netdevice_notifier(&dev->netdev_nb);

	if (dev->is_registered) {
		erdma_device_deregister(dev);
		dev->is_registered = 0;
	}

	erdma_res_cb_free(dev);
	xa_destroy(&dev->qp_xa);
	xa_destroy(&dev->cq_xa);
}

static int erdma_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	int ret;

	ret = erdma_probe_dev(pdev);
	if (ret)
		return ret;

	ret = erdma_ib_device_add(pdev);
	if (ret) {
		erdma_remove_dev(pdev);
		return ret;
	}

	return 0;
}

static void erdma_remove(struct pci_dev *pdev)
{
	erdma_ib_device_remove(pdev);
	erdma_remove_dev(pdev);
}

static struct pci_driver erdma_pci_driver = {
	.name = DRV_MODULE_NAME,
	.id_table = erdma_pci_tbl,
	.probe = erdma_probe,
	.remove = erdma_remove
};

MODULE_DEVICE_TABLE(pci, erdma_pci_tbl);

static __init int erdma_init_module(void)
{
	int ret;

	ret = erdma_cm_init();
	if (ret)
		return ret;

	ret = erdma_chrdev_init();
	if (ret)
		goto uninit_cm;

	ret = pci_register_driver(&erdma_pci_driver);
	if (ret) {
		pr_err("Couldn't register erdma driver.\n");
		goto uninit_chrdev;
	}

	return ret;

uninit_chrdev:
	erdma_chrdev_destroy();

uninit_cm:
	erdma_cm_exit();

	return ret;
}

static void __exit erdma_exit_module(void)
{
	pci_unregister_driver(&erdma_pci_driver);
	erdma_chrdev_destroy();
	erdma_cm_exit();
}

module_init(erdma_init_module);
module_exit(erdma_exit_module);
