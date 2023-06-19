// SPDX-License-Identifier: GPL-2.0

#include <linux/dma-mapping.h>
#include <linux/module.h>
#include <net/addrconf.h>
#include <rdma/ib_addr.h>
#include <rdma/ib_cache.h>
#include <rdma/ib_mad.h>
#include <rdma/uverbs_ioctl.h>

#include "erdma_verbs.h"

bool compat_mode;
module_param(compat_mode, bool, 0444);
MODULE_PARM_DESC(compat_mode, "compat mode support");

u16 reserve_ports_base = 0x7790;
module_param(reserve_ports_base, ushort, 0444);
MODULE_PARM_DESC(reserve_ports_base, "ports reserved in RoCE mode");


int erdma_create_ah(struct ib_ah *ibah,
		    struct rdma_ah_init_attr *init_attr,
		    struct ib_udata *udata)
{
	return -EOPNOTSUPP;
}


int erdma_destroy_ah(struct ib_ah *ibah, u32 flags)
{

	return -EOPNOTSUPP;
}

int erdma_query_pkey(struct ib_device *ibdev, port_t port, u16 index, u16 *pkey)
{
	if (index > 0)
		return -EINVAL;

	*pkey = 0xffff;
	return 0;
}

enum rdma_link_layer erdma_get_link_layer(struct ib_device *dev,
					  port_t port_num)
{
	return IB_LINK_LAYER_ETHERNET;
}

int erdma_add_gid(const struct ib_gid_attr *attr, void **context)
{
	return 0;
}

int erdma_del_gid(const struct ib_gid_attr *attr, void **context)
{
	return 0;
}

void erdma_gen_port_from_qpn(u32 sip, u32 dip, u32 lqpn, u32 rqpn, u16 *sport,
			     u16 *dport)
{
	/* select lqpn 0, select rqpn 1 */
	u32 select_type = 1;

	lqpn &= 0xFFFFF;
	rqpn &= 0xFFFFF;

	if (dip < sip || (dip == sip && lqpn < rqpn))
		select_type = 0;

	if (select_type) {
		*sport = reserve_ports_base + upper_16_bits(rqpn);
		*dport = lower_16_bits(rqpn);
	} else {
		*dport = reserve_ports_base + upper_16_bits(lqpn);
		*sport = lower_16_bits(lqpn);
	}
}

static int erdma_av_from_attr(struct erdma_qp *qp, struct ib_qp_attr *attr)
{
	struct rdma_ah_attr *ah_attr = &attr->ah_attr;
	const struct ib_gid_attr *sgid_attr = ah_attr->grh.sgid_attr;
	enum rdma_network_type ntype;
	union ib_gid sgid;

	if (ah_attr->type != RDMA_AH_ATTR_TYPE_ROCE) {
		ibdev_dbg(&qp->dev->ibdev, "unsupport ah_attr type %u.\n",
			  ah_attr->type);
		return -EOPNOTSUPP;
	}

	ntype = rdma_gid_attr_network_type(sgid_attr);
	sgid = sgid_attr->gid;

	ibdev_dbg(&qp->dev->ibdev, "gid type:%u, sgid: %pI6\n", ntype,
		  sgid.raw);

	rdma_gid2ip((struct sockaddr *)&qp->attrs.laddr, &sgid);
	rdma_gid2ip((struct sockaddr *)&qp->attrs.raddr,
		    &rdma_ah_read_grh(ah_attr)->dgid);

	ibdev_dbg(&qp->dev->ibdev, "dgid: %pI6\n",
		  rdma_ah_read_grh(ah_attr)->dgid.raw);

	ibdev_dbg(&qp->dev->ibdev, "laddr:0x%x\n",
		  ntohl(qp->attrs.laddr.in.sin_addr.s_addr));
	ibdev_dbg(&qp->dev->ibdev, "raddr:0x%x\n",
		  ntohl(qp->attrs.raddr.in.sin_addr.s_addr));
	return 0;
}

int erdma_handle_compat_attr(struct erdma_qp *qp, struct ib_qp_attr *attr,
			     int attr_mask)
{
	ibdev_dbg(&qp->dev->ibdev, "attr mask: %x, av: %d, state:%d\n",
		  attr_mask, attr_mask & IB_QP_AV, attr_mask & IB_QP_STATE);

	if (attr_mask & IB_QP_AV)
		erdma_av_from_attr(qp, attr);

	if (attr_mask & IB_QP_DEST_QPN) {
		ibdev_dbg(&qp->dev->ibdev, "get remote qpn %u\n",
			  attr->dest_qp_num);
		qp->attrs.remote_qp_num = attr->dest_qp_num;
	}

	if (attr_mask & IB_QP_SQ_PSN) {
		ibdev_dbg(&qp->dev->ibdev, "get sqsn:%u\n", attr->sq_psn);
		qp->attrs.sq_psn = attr->sq_psn;
	}

	if (attr_mask & IB_QP_RQ_PSN) {
		ibdev_dbg(&qp->dev->ibdev, "get rqsn:%u\n", attr->rq_psn);
		qp->attrs.rq_psn = attr->rq_psn;
	}

	return 0;
}

struct socket *rsvd_sock[16];

static int erdma_port_init(void)
{
	struct sockaddr_in laddr;
	int ret = 0, i, j;

	for (i = 0; i < 16; i++) {
		ret = __sock_create(current->nsproxy->net_ns, AF_INET,
				    SOCK_STREAM, IPPROTO_TCP, &rsvd_sock[i], 1);
		if (ret < 0)
			goto err_out;
		memset(&laddr, 0, sizeof(struct sockaddr_in));
		laddr.sin_port = htons(reserve_ports_base + i);
		ret = rsvd_sock[i]->ops->bind(rsvd_sock[i],
					      (struct sockaddr *)&laddr,
					      sizeof(struct sockaddr_in));
		if (ret) {
			sock_release(rsvd_sock[i]);
			goto err_out;
		}
	}

	return 0;

err_out:
	for (j = 0; j < i; j++)
		sock_release(rsvd_sock[j]);

	return ret;
}

static void erdma_port_release(void)
{
	int i;

	if (!compat_mode)
		return;

	for (i = 0; i < 16; i++)
		sock_release(rsvd_sock[i]);
}

int erdma_compat_init(void)
{
	int ret;

	if (!compat_mode)
		return 0;


	ret = erdma_port_init();

	return ret;
}

void erdma_compat_exit(void)
{
	if (!compat_mode)
		return;

	erdma_port_release();

}
