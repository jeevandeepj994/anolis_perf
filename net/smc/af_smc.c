// SPDX-License-Identifier: GPL-2.0-only
/*
 *  Shared Memory Communications over RDMA (SMC-R) and RoCE
 *
 *  AF_SMC protocol family socket handler keeping the AF_INET sock address type
 *  applies to SOCK_STREAM sockets only
 *  offers an alternative communication option for TCP-protocol sockets
 *  applicable with RoCE-cards only
 *
 *  Initial restrictions:
 *    - support for alternate links postponed
 *
 *  Copyright IBM Corp. 2016, 2018
 *
 *  Author(s):  Ursula Braun <ubraun@linux.vnet.ibm.com>
 *              based on prototype from Frank Blaschka
 */

#define KMSG_COMPONENT "smc"
#define pr_fmt(fmt) KMSG_COMPONENT ": " fmt

#include <linux/module.h>
#include <linux/socket.h>
#include <linux/workqueue.h>
#include <linux/in.h>
#include <linux/sched/signal.h>
#include <linux/if_vlan.h>
#include <linux/rcupdate_wait.h>
#include <linux/ctype.h>
#include <linux/splice.h>

#include <net/sock.h>
#include <net/tcp.h>
#include <net/smc.h>
#include <asm/ioctls.h>

#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/protocol.h>
#include <net/inet_common.h>
#include <net/transp_v6.h>
#include "smc_netns.h"

#include "smc.h"
#include "smc_clc.h"
#include "smc_llc.h"
#include "smc_cdc.h"
#include "smc_core.h"
#include "smc_ib.h"
#include "smc_ism.h"
#include "smc_pnet.h"
#include "smc_netlink.h"
#include "smc_tx.h"
#include "smc_rx.h"
#include "smc_close.h"
#include "smc_stats.h"
#include "smc_tracepoint.h"
#include "smc_sysctl.h"
#include "smc_inet.h"
#include "smc_loopback.h"

static DEFINE_MUTEX(smc_server_lgr_pending);	/* serialize link group
						 * creation on server
						 */
static DEFINE_MUTEX(smc_client_lgr_pending);	/* serialize link group
						 * creation on client
						 */

static struct workqueue_struct	*smc_tcp_ls_wq;	/* wq for tcp listen work */
struct workqueue_struct	*smc_hs_wq;	/* wq for handshake work */
struct workqueue_struct	*smc_close_wq;	/* wq for close work */

static void smc_tcp_listen_work(struct work_struct *);
static void smc_connect_work(struct work_struct *);

static int smc_inet_sock_do_handshake(struct sock *sk, bool sk_locked, bool sync);

static void __smc_inet_sock_sort_csk_queue(struct sock *parent, int *tcp_cnt, int *smc_cnt);
static int smc_inet_sock_sort_csk_queue(struct sock *parent);

/* default use reserve_mode */
bool reserve_mode = true;

/* default disable SMC-D loopback */
bool loopback_enable;
module_param(loopback_enable, bool, 0444);
MODULE_PARM_DESC(loopback_enable, "Enable SMC-D loopback support");

/* rsvd_ports_base must less than (u16 MAX - 8) */
u16 rsvd_ports_base = SMC_IWARP_RSVD_PORTS_BASE;
module_param(rsvd_ports_base, ushort, 0444);
MODULE_PARM_DESC(rsvd_ports_base, "base of rsvd ports for reserve_mode");

static int smc_sock_should_select_smc(const struct smc_sock *smc, struct sockaddr *addr)
{
	const struct smc_sock_negotiator_ops *ops;
	int ret;

	rcu_read_lock();
	ops = READ_ONCE(smc->negotiator_ops);

	/* No negotiator_ops supply or no negotiate func set,
	 * always pass it.
	 */
	if (!ops || !ops->negotiate) {
		rcu_read_unlock();
		return SK_PASS;
	}

	ret = ops->negotiate((struct sock *)&smc->sk, addr);
	rcu_read_unlock();
	return ret;
}

static void smc_sock_perform_collecting_info(const struct smc_sock *smc, int timing)
{
	const struct smc_sock_negotiator_ops *ops;

	rcu_read_lock();
	ops = READ_ONCE(smc->negotiator_ops);

	if (!ops || !ops->collect_info) {
		rcu_read_unlock();
		return;
	}

	ops->collect_info((struct sock *)&smc->sk, timing);
	rcu_read_unlock();
}

int smc_nl_dump_hs_limitation(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct smc_nl_dmp_ctx *cb_ctx = smc_nl_dmp_ctx(cb);
	void *hdr;

	if (cb_ctx->pos[0])
		goto out;

	hdr = genlmsg_put(skb, NETLINK_CB(cb->skb).portid, cb->nlh->nlmsg_seq,
			  &smc_gen_nl_family, NLM_F_MULTI,
			  SMC_NETLINK_DUMP_HS_LIMITATION);
	if (!hdr)
		return -ENOMEM;

	if (nla_put_u8(skb, SMC_NLA_HS_LIMITATION_ENABLED,
		       sock_net(skb->sk)->smc.limit_smc_hs))
		goto err;

	genlmsg_end(skb, hdr);
	cb_ctx->pos[0] = 1;
out:
	return skb->len;
err:
	genlmsg_cancel(skb, hdr);
	return -EMSGSIZE;
}

int smc_nl_enable_hs_limitation(struct sk_buff *skb, struct genl_info *info)
{
	sock_net(skb->sk)->smc.limit_smc_hs = true;
	return 0;
}

int smc_nl_disable_hs_limitation(struct sk_buff *skb, struct genl_info *info)
{
	sock_net(skb->sk)->smc.limit_smc_hs = false;
	return 0;
}

static void smc_set_keepalive(struct sock *sk, int val)
{
	struct smc_sock *smc = smc_sk(sk);

	smc->clcsock->sk->sk_prot->keepalive(smc->clcsock->sk, val);
}

static struct sock *smc_tcp_syn_recv_sock(const struct sock *sk,
					  struct sk_buff *skb,
					  struct request_sock *req,
					  struct dst_entry *dst,
					  struct request_sock *req_unhash,
					  bool *own_req)
{
	struct smc_sock *smc;
	struct sock *child;

	smc = smc_clcsock_user_data(sk);
	if (unlikely(!smc))
		goto drop;

	if (READ_ONCE(sk->sk_ack_backlog) + atomic_read(&smc->queued_smc_hs) >
				sk->sk_max_ack_backlog)
		goto drop;

	if (sk_acceptq_is_full(&smc->sk)) {
		NET_INC_STATS(sock_net(sk), LINUX_MIB_LISTENOVERFLOWS);
		goto drop;
	}

	/* passthrough to original syn recv sock fct */
	child = smc->ori_af_ops->syn_recv_sock(sk, skb, req, dst, req_unhash,
					       own_req);
	/* child must not inherit smc or its ops */
	if (child) {
		rcu_assign_sk_user_data(child, NULL);

		/* v4-mapped sockets don't inherit parent ops. Don't restore. */
		if (inet_csk(child)->icsk_af_ops == inet_csk(sk)->icsk_af_ops)
			inet_csk(child)->icsk_af_ops = smc->ori_af_ops;
	}
	return child;

drop:
	dst_release(dst);
	tcp_listendrop(sk);
	return NULL;
}

static bool smc_hs_congested(const struct sock *sk)
{
	struct smc_sock *smc;
	int tcp_cnt, smc_cnt;

	smc = smc_clcsock_user_data(sk);

	if (!smc)
		return true;

	if (workqueue_congested(WORK_CPU_UNBOUND, smc_hs_wq))
		return true;

	if (!smc_sock_should_select_smc(smc, NULL))
		return true;

	/* only works for inet sock */
	if (smc_sock_is_inet_sock(&smc->sk)) {
		__smc_inet_sock_sort_csk_queue(&smc->sk, &tcp_cnt, &smc_cnt);
		smc_cnt += atomic_read(&smc->queued_smc_hs);
		if (!smc_inet_sock_is_under_presure(&smc->sk)) {
			if (smc_cnt > (sk->sk_max_ack_backlog >> 1)) {
				smc_inet_sock_under_presure(&smc->sk);
				return true;
			}
		} else {
			if (smc_cnt > (sk->sk_max_ack_backlog >> 2))
				return true;
			/* leave the presure state */
			smc_inet_sock_leave_presure(&smc->sk);
		}
	}

	return false;
}

static struct smc_hashinfo smc_v4_hashinfo = {
	.lock = __RW_LOCK_UNLOCKED(smc_v4_hashinfo.lock),
};

static struct smc_hashinfo smc_v6_hashinfo = {
	.lock = __RW_LOCK_UNLOCKED(smc_v6_hashinfo.lock),
};

int smc_hash_sk(struct sock *sk)
{
	struct smc_hashinfo *h = sk->sk_prot->h.smc_hash;
	struct hlist_head *head;

	head = &h->ht;

	write_lock_bh(&h->lock);
	sk_add_node(sk, head);
	sock_prot_inuse_add(sock_net(sk), sk->sk_prot, 1);
	write_unlock_bh(&h->lock);

	return 0;
}
EXPORT_SYMBOL_GPL(smc_hash_sk);

void smc_unhash_sk(struct sock *sk)
{
	struct smc_hashinfo *h = sk->sk_prot->h.smc_hash;

	write_lock_bh(&h->lock);
	if (sk_del_node_init(sk))
		sock_prot_inuse_add(sock_net(sk), sk->sk_prot, -1);
	write_unlock_bh(&h->lock);
}
EXPORT_SYMBOL_GPL(smc_unhash_sk);

/* This will be called before user really release sock_lock. So do the
 * work which we didn't do because of user hold the sock_lock in the
 * BH context
 */
static void smc_release_cb(struct sock *sk)
{
	struct smc_sock *smc = smc_sk(sk);

	if (smc->conn.tx_in_release_sock) {
		smc_tx_pending(&smc->conn);
		smc->conn.tx_in_release_sock = false;
	}
}

struct proto smc_proto = {
	.name		= "SMC",
	.owner		= THIS_MODULE,
	.keepalive	= smc_set_keepalive,
	.hash		= smc_hash_sk,
	.unhash		= smc_unhash_sk,
	.release_cb	= smc_release_cb,
	.obj_size	= sizeof(struct smc_sock),
	.h.smc_hash	= &smc_v4_hashinfo,
	.slab_flags	= SLAB_TYPESAFE_BY_RCU,
};
EXPORT_SYMBOL_GPL(smc_proto);

struct proto smc_proto6 = {
	.name		= "SMC6",
	.owner		= THIS_MODULE,
	.keepalive	= smc_set_keepalive,
	.hash		= smc_hash_sk,
	.unhash		= smc_unhash_sk,
	.release_cb	= smc_release_cb,
	.obj_size	= sizeof(struct smc_sock),
	.h.smc_hash	= &smc_v6_hashinfo,
	.slab_flags	= SLAB_TYPESAFE_BY_RCU,
};
EXPORT_SYMBOL_GPL(smc_proto6);

static void smc_fback_restore_callbacks(struct smc_sock *smc)
{
	struct sock *clcsk = smc->clcsock->sk;

	if (!clcsk)
		return;

	write_lock_bh(&clcsk->sk_callback_lock);
	clcsk->sk_user_data = NULL;

	smc_clcsock_restore_cb(&clcsk->sk_state_change, &smc->clcsk_state_change);
	smc_clcsock_restore_cb(&clcsk->sk_data_ready, &smc->clcsk_data_ready);
	smc_clcsock_restore_cb(&clcsk->sk_write_space, &smc->clcsk_write_space);
	smc_clcsock_restore_cb(&clcsk->sk_error_report, &smc->clcsk_error_report);

	write_unlock_bh(&clcsk->sk_callback_lock);
}

static void smc_restore_fallback_changes(struct smc_sock *smc)
{
	if (smc->clcsock->file) { /* non-accepted sockets have no file yet */
		smc->clcsock->file->private_data = smc->sk.sk_socket;
		smc->clcsock->file = NULL;
		smc_fback_restore_callbacks(smc);
	}
}

static int __smc_release(struct smc_sock *smc)
{
	struct sock *sk = &smc->sk;
	int rc = 0;

	if (!smc->use_fallback) {
		rc = smc_close_active(smc);
		smc_sock_set_flag(sk, SOCK_DEAD);
		sk->sk_shutdown |= SHUTDOWN_MASK;
	} else {
		if (smc_sk_state(sk) != SMC_CLOSED) {
			if (smc_sk_state(sk) != SMC_LISTEN &&
			    smc_sk_state(sk) != SMC_INIT)
				sock_put(sk); /* passive closing */
			if (smc_sk_state(sk) == SMC_LISTEN) {
				/* wake up clcsock accept */
				rc = kernel_sock_shutdown(smc->clcsock,
							  SHUT_RDWR);
			}
			smc_sk_set_state(sk, SMC_CLOSED);
			sk->sk_state_change(sk);
		}
		smc_restore_fallback_changes(smc);
	}

	sk->sk_prot->unhash(sk);

	if (smc_sk_state(sk) == SMC_CLOSED) {
		if (smc->clcsock) {
			release_sock(sk);
			smc_clcsock_release(smc);
			lock_sock(sk);
		}
		if (!smc->use_fallback)
			smc_conn_free(&smc->conn);
	}

	return rc;
}

static int smc_release(struct socket *sock)
{
	struct sock *sk = sock->sk;
	struct smc_sock *smc;
	int old_state, rc = 0;

	if (!sk)
		goto out;

	sock_hold(sk); /* sock_put below */
	smc = smc_sk(sk);

	old_state = smc_sk_state(sk);

	/* trigger info gathering if needed.*/
	smc_sock_perform_collecting_info(smc, SMC_SOCK_CLOSED_TIMING);

	/* cleanup for a dangling non-blocking connect */
	if (smc->connect_nonblock && old_state == SMC_INIT)
		tcp_abort(smc->clcsock->sk, ECONNABORTED);

	if (smc->connect_nonblock && cancel_work_sync(&smc->connect_work))
		sock_put(&smc->sk); /* sock_hold in smc_connect for passive closing */

	if (smc_sk_state(sk) == SMC_LISTEN)
		/* smc_close_non_accepted() is called and acquires
		 * sock lock for child sockets again
		 */
		lock_sock_nested(sk, SINGLE_DEPTH_NESTING);
	else
		lock_sock(sk);

	if ((old_state == SMC_INIT || smc->conn.killed) &&
	    smc_sk_state(sk) == SMC_ACTIVE && !smc->use_fallback)
		smc_close_active_abort(smc);

	rc = __smc_release(smc);

	/* detach socket */
	sock_orphan(sk);
	sock->sk = NULL;
	release_sock(sk);

	sock_put(sk); /* sock_hold above */
	sock_put(sk); /* final sock_put */
out:
	return rc;
}

static void smc_destruct(struct sock *sk)
{
	if (smc_sk(sk)->original_sk_destruct)
		smc_sk(sk)->original_sk_destruct(sk);

	/* for inet sock, sk here MUST be non accepted */
	if (smc_sock_is_inet_sock(sk) && !smc_inet_sock_is_active_open(sk) &&
	    (isck_smc_negotiation_load(smc_sk(sk)) == SMC_NEGOTIATION_TBD))
		goto out;

	smc_sock_cleanup_negotiator_ops(smc_sk(sk), /* in release */ 1);

out:
	if (smc_sk_state(sk) != SMC_CLOSED)
		return;
	if (!smc_sock_flag(sk, SOCK_DEAD))
		return;

	sk_refcnt_debug_dec(sk);
}

static inline void smc_sock_init_common(struct sock *sk)
{
	struct smc_sock *smc = smc_sk(sk);

	smc_sk_set_state(sk, SMC_INIT);
	INIT_DELAYED_WORK(&smc->conn.tx_work, smc_tx_work);
	spin_lock_init(&smc->conn.send_lock);
	mutex_init(&smc->clcsock_release_lock);
}

static void smc_sock_init_passive(struct sock *par, struct sock *sk)
{
	struct smc_sock *parent = smc_sk(par);
	struct sock *clcsk;

	smc_sock_init_common(sk);
	smc_sk(sk)->listen_smc = parent;
	/* restore the smc_sk_sndbuf before handshake */
	smc_sk(sk)->smc_sk_sndbuf = READ_ONCE(sock_net(sk)->smc.sysctl_wmem);

	smc_sock_clone_negotiator_ops(par, sk);

	clcsk = smc_sock_is_inet_sock(sk) ? sk : smc_sk(sk)->clcsock->sk;

	if (tcp_sk(clcsk)->syn_smc) {
		smc_sk(sk)->smc_negotiated = 1;
		atomic_inc(&parent->queued_smc_hs);
		/* memory barrier */
		smp_mb__after_atomic();
	}
}

static void smc_sock_init(struct sock *sk, struct net *net)
{
	struct smc_sock *smc = smc_sk(sk);

	smc_sock_init_common(sk);
	INIT_WORK(&smc->connect_work, smc_connect_work);
	INIT_WORK(&smc->tcp_listen_work, smc_tcp_listen_work);
	INIT_LIST_HEAD(&smc->accept_q);
	spin_lock_init(&smc->accept_q_lock);
	WRITE_ONCE(sk->sk_sndbuf, READ_ONCE(net->smc.sysctl_wmem));
	WRITE_ONCE(sk->sk_rcvbuf, READ_ONCE(net->smc.sysctl_rmem));
	smc->limit_smc_hs = net->smc.limit_smc_hs;
	smc_sock_assign_negotiator_ops(smc, "anolis");

	/* already set (for inet sock), save the original */
	if (sk->sk_destruct)
		smc->original_sk_destruct = sk->sk_destruct;
	sk_refcnt_debug_inc(sk);
	sk->sk_destruct = smc_destruct;
}

static struct sock *smc_sock_alloc(struct net *net, struct socket *sock,
				   int protocol)
{
	struct proto *prot;
	struct sock *sk;

	prot = (protocol == SMCPROTO_SMC6) ? &smc_proto6 : &smc_proto;
	sk = sk_alloc(net, PF_SMC, GFP_KERNEL, prot, 0);
	if (!sk)
		return NULL;

	sock_init_data(sock, sk); /* sets sk_refcnt to 1 */
	sk->sk_protocol = protocol;
	smc_sock_init(sk, net);
	sk->sk_prot->hash(sk);
	return sk;
}

static int smc_bind(struct socket *sock, struct sockaddr *uaddr,
		    int addr_len)
{
	struct sockaddr_in *addr = (struct sockaddr_in *)uaddr;
	struct sock *sk = sock->sk;
	struct smc_sock *smc;
	int rc;

	smc = smc_sk(sk);

	/* replicate tests from inet_bind(), to be safe wrt. future changes */
	rc = -EINVAL;
	if (addr_len < sizeof(struct sockaddr_in))
		goto out;

	rc = -EAFNOSUPPORT;
	if (addr->sin_family != AF_INET &&
	    addr->sin_family != AF_INET6 &&
	    addr->sin_family != AF_UNSPEC)
		goto out;
	/* accept AF_UNSPEC (mapped to AF_INET) only if s_addr is INADDR_ANY */
	if (addr->sin_family == AF_UNSPEC &&
	    addr->sin_addr.s_addr != htonl(INADDR_ANY))
		goto out;

	lock_sock(sk);

	/* Check if socket is already active */
	rc = -EINVAL;
	if (smc_sk_state(sk) != SMC_INIT || smc->connect_nonblock)
		goto out_rel;

	smc->clcsock->sk->sk_reuse = sk->sk_reuse;
	smc->clcsock->sk->sk_reuseport = sk->sk_reuseport;
	rc = kernel_bind(smc->clcsock, uaddr, addr_len);

out_rel:
	release_sock(sk);
out:
	return rc;
}

static void smc_copy_sock_settings(struct sock *nsk, struct sock *osk,
				   unsigned long mask)
{
	/* no need for inet smc */
	if (smc_sock_is_inet_sock(nsk))
		return;

	/* options we don't get control via setsockopt for */
	nsk->sk_type = osk->sk_type;
	nsk->sk_sndbuf = osk->sk_sndbuf;
	nsk->sk_rcvbuf = osk->sk_rcvbuf;
	nsk->sk_sndtimeo = osk->sk_sndtimeo;
	nsk->sk_rcvtimeo = osk->sk_rcvtimeo;
	nsk->sk_mark = osk->sk_mark;
	nsk->sk_priority = osk->sk_priority;
	nsk->sk_rcvlowat = osk->sk_rcvlowat;
	nsk->sk_bound_dev_if = osk->sk_bound_dev_if;
	nsk->sk_err = osk->sk_err;

	nsk->sk_flags &= ~mask;
	nsk->sk_flags |= osk->sk_flags & mask;
}

#define SK_FLAGS_SMC_TO_CLC ((1UL << SOCK_URGINLINE) | \
			     (1UL << SOCK_KEEPOPEN) | \
			     (1UL << SOCK_LINGER) | \
			     (1UL << SOCK_BROADCAST) | \
			     (1UL << SOCK_TIMESTAMP) | \
			     (1UL << SOCK_DBG) | \
			     (1UL << SOCK_RCVTSTAMP) | \
			     (1UL << SOCK_RCVTSTAMPNS) | \
			     (1UL << SOCK_LOCALROUTE) | \
			     (1UL << SOCK_TIMESTAMPING_RX_SOFTWARE) | \
			     (1UL << SOCK_RXQ_OVFL) | \
			     (1UL << SOCK_WIFI_STATUS) | \
			     (1UL << SOCK_NOFCS) | \
			     (1UL << SOCK_FILTER_LOCKED) | \
			     (1UL << SOCK_TSTAMP_NEW))
/* copy only relevant settings and flags of SOL_SOCKET level from smc to
 * clc socket (since smc is not called for these options from net/core)
 */
static void smc_copy_sock_settings_to_clc(struct smc_sock *smc)
{
	smc_copy_sock_settings(smc->clcsock->sk, &smc->sk, SK_FLAGS_SMC_TO_CLC);
}

#define SK_FLAGS_CLC_TO_SMC ((1UL << SOCK_URGINLINE) | \
			     (1UL << SOCK_KEEPOPEN) | \
			     (1UL << SOCK_LINGER) | \
			     (1UL << SOCK_DBG))
/* copy only settings and flags relevant for smc from clc to smc socket */
static void smc_copy_sock_settings_to_smc(struct smc_sock *smc)
{
	smc_copy_sock_settings(&smc->sk, smc->clcsock->sk, SK_FLAGS_CLC_TO_SMC);
}

/* register the new vzalloced sndbuf on all links */
static int smcr_lgr_reg_sndbufs(struct smc_link *link,
				struct smc_buf_desc *snd_desc)
{
	struct smc_link_group *lgr = link->lgr;
	int i, rc = 0;

	if (!snd_desc->is_vm)
		return -EINVAL;

	/* protect against parallel smcr_link_reg_buf() */
	down_write(&lgr->llc_conf_mutex);
	for (i = 0; i < SMC_LINKS_PER_LGR_MAX; i++) {
		if (!smc_link_active(&lgr->lnk[i]))
			continue;
		rc = smcr_link_reg_buf(&lgr->lnk[i], snd_desc);
		if (rc)
			break;
	}
	up_write(&lgr->llc_conf_mutex);
	return rc;
}

/* register the new rmb on all links */
static int smcr_lgr_reg_rmbs(struct smc_link *link,
			     struct smc_buf_desc *rmb_desc)
{
	struct smc_link_group *lgr = link->lgr;
	bool do_slow = false;
	int i, rc = 0;

	rc = smc_llc_flow_initiate(lgr, SMC_LLC_FLOW_RKEY);
	if (rc)
		return rc;

	down_read(&lgr->llc_conf_mutex);
	for (i = 0; i < SMC_LINKS_PER_LGR_MAX; i++) {
		if (!smc_link_active(&lgr->lnk[i]))
			continue;
		if (!rmb_desc->is_reg_mr[link->link_idx]) {
			up_read(&lgr->llc_conf_mutex);
			goto slow_path;
		}
	}
	/* mr register already */
	goto fast_path;
slow_path:
	do_slow = true;
	/* protect against parallel smc_llc_cli_rkey_exchange() and
	 * parallel smcr_link_reg_buf()
	 */
	down_write(&lgr->llc_conf_mutex);
	for (i = 0; i < SMC_LINKS_PER_LGR_MAX; i++) {
		if (!smc_link_active(&lgr->lnk[i]))
			continue;
		rc = smcr_link_reg_buf(&lgr->lnk[i], rmb_desc);
		if (rc)
			goto out;
	}
fast_path:
	/* exchange confirm_rkey msg with peer */
	rc = smc_llc_do_confirm_rkey(link, rmb_desc);
	if (rc) {
		rc = -EFAULT;
		goto out;
	}
	rmb_desc->is_conf_rkey = true;
out:
	do_slow ? up_write(&lgr->llc_conf_mutex) : up_read(&lgr->llc_conf_mutex);
	smc_llc_flow_stop(lgr, &lgr->llc_flow_lcl);
	return rc;
}

static int smcr_clnt_conf_first_link(struct smc_sock *smc)
{
	struct smc_link *link = smc->conn.lnk;
	struct smc_llc_qentry *qentry;
	int rc;

	/* receive CONFIRM LINK request from server over RoCE fabric */
	qentry = smc_llc_wait(link->lgr, NULL, 2 * SMC_LLC_WAIT_TIME,
			      SMC_LLC_CONFIRM_LINK);
	if (!qentry) {
		struct smc_clc_msg_decline dclc;

		rc = smc_clc_wait_msg(smc, &dclc, sizeof(dclc),
				      SMC_CLC_DECLINE, CLC_WAIT_TIME_SHORT);
		return rc == -EAGAIN ? SMC_CLC_DECL_TIMEOUT_CL : rc;
	}
	smc_llc_save_peer_uid(qentry);
	rc = smc_llc_eval_conf_link(qentry, SMC_LLC_REQ);
	smc_llc_flow_qentry_del(&link->lgr->llc_flow_lcl);
	if (rc)
		return SMC_CLC_DECL_RMBE_EC;

	rc = smc_ib_modify_qp_rts(link);
	if (rc)
		return SMC_CLC_DECL_ERR_RDYLNK;

	smc_wr_remember_qp_attr(link);

	/* reg the sndbuf if it was vzalloced */
	if (smc->conn.sndbuf_desc->is_vm) {
		if (smcr_link_reg_buf(link, smc->conn.sndbuf_desc))
			return SMC_CLC_DECL_ERR_REGBUF;
	}

	/* reg the rmb */
	if (smcr_link_reg_buf(link, smc->conn.rmb_desc))
		return SMC_CLC_DECL_ERR_REGBUF;

	/* confirm_rkey is implicit on 1st contact */
	smc->conn.rmb_desc->is_conf_rkey = true;

	/* send CONFIRM LINK response over RoCE fabric */
	rc = smc_llc_send_confirm_link(link, SMC_LLC_RESP);
	if (rc < 0)
		return SMC_CLC_DECL_TIMEOUT_CL;

	smc_llc_link_active(link);
	smcr_lgr_set_type(link->lgr, SMC_LGR_SINGLE);

	if (link->lgr->max_links > 1) {
		/* optional 2nd link, receive ADD LINK request from server */
		qentry = smc_llc_wait(link->lgr, NULL, SMC_LLC_WAIT_TIME,
				      SMC_LLC_ADD_LINK);
		if (!qentry) {
			struct smc_clc_msg_decline dclc;

			rc = smc_clc_wait_msg(smc, &dclc, sizeof(dclc),
					      SMC_CLC_DECLINE, CLC_WAIT_TIME_SHORT);
			if (rc == -EAGAIN)
				rc = 0; /* no DECLINE received, go with one link */
			return rc;
		}
		smc_llc_flow_qentry_clr(&link->lgr->llc_flow_lcl);
		smc_llc_cli_add_link(link, qentry);
	}
	return 0;
}

static bool smc_isascii(char *hostname)
{
	int i;

	for (i = 0; i < SMC_MAX_HOSTNAME_LEN; i++)
		if (!isascii(hostname[i]))
			return false;
	return true;
}

static void smc_conn_save_peer_info_fce(struct smc_sock *smc,
					struct smc_clc_msg_accept_confirm *clc)
{
	struct smc_clc_msg_accept_confirm_v2 *clc_v2 =
		(struct smc_clc_msg_accept_confirm_v2 *)clc;
	struct smc_clc_first_contact_ext *fce;
	int clc_v2_len;

	if (clc->hdr.version == SMC_V1 ||
	    !(clc->hdr.typev2 & SMC_FIRST_CONTACT_MASK))
		return;

	if (smc->conn.lgr->is_smcd) {
		memcpy(smc->conn.lgr->negotiated_eid, clc_v2->d1.eid,
		       SMC_MAX_EID_LEN);
		clc_v2_len = offsetofend(struct smc_clc_msg_accept_confirm_v2,
					 d1);
	} else {
		memcpy(smc->conn.lgr->negotiated_eid, clc_v2->r1.eid,
		       SMC_MAX_EID_LEN);
		clc_v2_len = offsetofend(struct smc_clc_msg_accept_confirm_v2,
					 r1);
	}
	fce = (struct smc_clc_first_contact_ext *)(((u8 *)clc_v2) + clc_v2_len);
	smc->conn.lgr->peer_os = fce->os_type;
	smc->conn.lgr->peer_smc_release = fce->release;
	if (smc_isascii(fce->hostname))
		memcpy(smc->conn.lgr->peer_hostname, fce->hostname,
		       SMC_MAX_HOSTNAME_LEN);
}

static void smcr_conn_save_peer_info(struct smc_sock *smc,
				     struct smc_clc_msg_accept_confirm *clc)
{
	int bufsize = smc_uncompress_bufsize(clc->r0.rmbe_size);

	smc->conn.peer_rmbe_idx = clc->r0.rmbe_idx;
	smc->conn.local_tx_ctrl.token = ntohl(clc->r0.rmbe_alert_token);
	smc->conn.peer_rmbe_size = bufsize;
	atomic_set(&smc->conn.peer_rmbe_space, smc->conn.peer_rmbe_size);
	smc->conn.tx_off = bufsize * (smc->conn.peer_rmbe_idx - 1);
}

static void smcd_conn_save_peer_info(struct smc_sock *smc,
				     struct smc_clc_msg_accept_confirm *clc)
{
	int bufsize = smc_uncompress_bufsize(clc->d0.dmbe_size);

	smc->conn.peer_rmbe_idx = clc->d0.dmbe_idx;
	smc->conn.peer_token = clc->d0.token;
	/* msg header takes up space in the buffer */
	smc->conn.peer_rmbe_size = bufsize - sizeof(struct smcd_cdc_msg);
	atomic_set(&smc->conn.peer_rmbe_space, smc->conn.peer_rmbe_size);
	smc->conn.tx_off = bufsize * smc->conn.peer_rmbe_idx;
}

static void smc_conn_save_peer_info(struct smc_sock *smc,
				    struct smc_clc_msg_accept_confirm *clc)
{
	if (smc->conn.lgr->is_smcd)
		smcd_conn_save_peer_info(smc, clc);
	else
		smcr_conn_save_peer_info(smc, clc);
	smc_conn_save_peer_info_fce(smc, clc);
}

static void smc_link_save_peer_info(struct smc_link *link,
				    struct smc_clc_msg_accept_confirm *clc,
				    struct smc_init_info *ini)
{
	link->peer_qpn = ntoh24(clc->r0.qpn);
	memcpy(link->peer_gid, ini->peer_gid, SMC_GID_SIZE);
	memcpy(link->peer_mac, ini->peer_mac, sizeof(link->peer_mac));
	link->peer_psn = ntoh24(clc->r0.psn);
	link->peer_mtu = clc->r0.qp_mtu;
	link->credits_enable = (ini->vendor_opt_valid && ini->credits_en &&
				clc->r0.init_credits) ? 1 : 0;
	if (link->credits_enable) {
		atomic_set(&link->peer_rq_credits, clc->r0.init_credits);
		/* set peer rq credits watermark, if less than init_credits * 2/3,
		 * then credit announcement is needed.
		 */
		link->peer_cr_watermark_low =
			max(clc->r0.init_credits * 2 / 3, 1);
	}
}

static void smc_stat_inc_fback_rsn_cnt(struct smc_sock *smc,
				       struct smc_stats_fback *fback_arr)
{
	int cnt;

	for (cnt = 0; cnt < SMC_MAX_FBACK_RSN_CNT; cnt++) {
		if (fback_arr[cnt].fback_code == smc->fallback_rsn) {
			fback_arr[cnt].count++;
			break;
		}
		if (!fback_arr[cnt].fback_code) {
			fback_arr[cnt].fback_code = smc->fallback_rsn;
			fback_arr[cnt].count++;
			break;
		}
	}
}

static void smc_stat_fallback(struct smc_sock *smc)
{
	struct net *net = sock_net(&smc->sk);

	spin_lock_bh(&net->smc.mutex_fback_rsn);
	if (smc->listen_smc) {
		smc_stat_inc_fback_rsn_cnt(smc, net->smc.fback_rsn->srv);
		net->smc.fback_rsn->srv_fback_cnt++;
	} else {
		smc_stat_inc_fback_rsn_cnt(smc, net->smc.fback_rsn->clnt);
		net->smc.fback_rsn->clnt_fback_cnt++;
	}
	spin_unlock_bh(&net->smc.mutex_fback_rsn);
}

/* must be called under rcu read lock */
static void smc_fback_wakeup_waitqueue(struct smc_sock *smc, void *key)
{
	struct socket_wq *wq;
	__poll_t flags;

	wq = rcu_dereference(smc->sk.sk_wq);
	if (!skwq_has_sleeper(wq))
		return;

	/* wake up smc sk->sk_wq */
	if (!key) {
		/* sk_state_change */
		wake_up_interruptible_all(&wq->wait);
	} else {
		flags = key_to_poll(key);
		if (flags & (EPOLLIN | EPOLLOUT))
			/* sk_data_ready or sk_write_space */
			wake_up_interruptible_sync_poll(&wq->wait, flags);
		else if (flags & EPOLLERR)
			/* sk_error_report */
			wake_up_interruptible_poll(&wq->wait, flags);
	}
}

static int smc_fback_mark_woken(wait_queue_entry_t *wait,
				unsigned int mode, int sync, void *key)
{
	struct smc_mark_woken *mark =
		container_of(wait, struct smc_mark_woken, wait_entry);

	mark->woken = true;
	mark->key = key;
	return 0;
}

static void smc_fback_forward_wakeup(struct smc_sock *smc, struct sock *clcsk,
				     void (*clcsock_callback)(struct sock *sk))
{
	struct smc_mark_woken mark = { .woken = false };
	struct socket_wq *wq;

	init_waitqueue_func_entry(&mark.wait_entry,
				  smc_fback_mark_woken);
	rcu_read_lock();
	wq = rcu_dereference(clcsk->sk_wq);
	if (!wq)
		goto out;
	add_wait_queue(sk_sleep(clcsk), &mark.wait_entry);
	clcsock_callback(clcsk);
	remove_wait_queue(sk_sleep(clcsk), &mark.wait_entry);

	if (mark.woken)
		smc_fback_wakeup_waitqueue(smc, mark.key);
out:
	rcu_read_unlock();
}

static void smc_fback_state_change(struct sock *clcsk)
{
	struct smc_sock *smc;

	read_lock_bh(&clcsk->sk_callback_lock);
	smc = smc_clcsock_user_data(clcsk);
	if (smc)
		smc_fback_forward_wakeup(smc, clcsk,
					 smc->clcsk_state_change);
	read_unlock_bh(&clcsk->sk_callback_lock);
}

static void smc_fback_data_ready(struct sock *clcsk)
{
	struct smc_sock *smc;

	read_lock_bh(&clcsk->sk_callback_lock);
	smc = smc_clcsock_user_data(clcsk);
	if (smc)
		smc_fback_forward_wakeup(smc, clcsk,
					 smc->clcsk_data_ready);
	read_unlock_bh(&clcsk->sk_callback_lock);
}

static void smc_fback_write_space(struct sock *clcsk)
{
	struct smc_sock *smc;

	read_lock_bh(&clcsk->sk_callback_lock);
	smc = smc_clcsock_user_data(clcsk);
	if (smc)
		smc_fback_forward_wakeup(smc, clcsk,
					 smc->clcsk_write_space);
	read_unlock_bh(&clcsk->sk_callback_lock);
}

static void smc_fback_error_report(struct sock *clcsk)
{
	struct smc_sock *smc;

	read_lock_bh(&clcsk->sk_callback_lock);
	smc = smc_clcsock_user_data(clcsk);
	if (smc)
		smc_fback_forward_wakeup(smc, clcsk,
					 smc->clcsk_error_report);
	read_unlock_bh(&clcsk->sk_callback_lock);
}

static void smc_fback_replace_callbacks(struct smc_sock *smc)
{
	struct sock *clcsk = smc->clcsock->sk;

	write_lock_bh(&clcsk->sk_callback_lock);
	clcsk->sk_user_data = (void *)((uintptr_t)smc | SK_USER_DATA_NOCOPY);

	smc_clcsock_replace_cb(&clcsk->sk_state_change, smc_fback_state_change,
			       &smc->clcsk_state_change);
	smc_clcsock_replace_cb(&clcsk->sk_data_ready, smc_fback_data_ready,
			       &smc->clcsk_data_ready);
	smc_clcsock_replace_cb(&clcsk->sk_write_space, smc_fback_write_space,
			       &smc->clcsk_write_space);
	smc_clcsock_replace_cb(&clcsk->sk_error_report, smc_fback_error_report,
			       &smc->clcsk_error_report);

	write_unlock_bh(&clcsk->sk_callback_lock);
}

static int smc_switch_to_fallback(struct smc_sock *smc, int reason_code)
{
	int rc = 0;

	/* no need protected by clcsock_release_lock, move head */
	smc->use_fallback = true;
	smc->fallback_rsn = reason_code;
	smc_stat_fallback(smc);
	trace_smc_switch_to_fallback(smc, reason_code);

	/* inet sock  */
	if (smc_sock_is_inet_sock(&smc->sk))
		return 0;

	/* smc sock */
	mutex_lock(&smc->clcsock_release_lock);
	if (!smc->clcsock) {
		rc = -EBADF;
		goto out;
	}

	if (smc->sk.sk_socket && smc->sk.sk_socket->file) {
		smc->clcsock->file = smc->sk.sk_socket->file;
		smc->clcsock->file->private_data = smc->clcsock;
		smc->clcsock->wq.fasync_list =
			smc->sk.sk_socket->wq.fasync_list;

		/* There might be some wait entries remaining
		 * in smc sk->sk_wq and they should be woken up
		 * as clcsock's wait queue is woken up.
		 */
		smc_fback_replace_callbacks(smc);
	}
out:
	mutex_unlock(&smc->clcsock_release_lock);
	return rc;
}

/* fall back during connect */
static int smc_connect_fallback(struct smc_sock *smc, int reason_code)
{
	struct net *net = sock_net(&smc->sk);
	int rc = 0;

	rc = smc_switch_to_fallback(smc, reason_code);
	if (rc) { /* fallback fails */
		this_cpu_inc(net->smc.smc_stats->clnt_hshake_err_cnt);
		if (smc_sk_state(&smc->sk) == SMC_INIT)
			sock_put(&smc->sk); /* passive closing */
		return rc;
	}
	smc_copy_sock_settings_to_clc(smc);
	smc->connect_nonblock = 0;
	if (smc_sk_state(&smc->sk) == SMC_INIT)
		smc_sk_set_state(&smc->sk, SMC_ACTIVE);
	return 0;
}

/* decline and fall back during connect */
static int smc_connect_decline_fallback(struct smc_sock *smc, int reason_code,
					u8 version)
{
	struct net *net = sock_net(&smc->sk);
	int rc;

	if (reason_code < 0) { /* error, fallback is not possible */
		this_cpu_inc(net->smc.smc_stats->clnt_hshake_err_cnt);
		if (smc_sk_state(&smc->sk) == SMC_INIT)
			sock_put(&smc->sk); /* passive closing */
		return reason_code;
	}

	if (reason_code != SMC_CLC_DECL_PEERDECL) {
		rc = smc_clc_send_decline(smc, reason_code, version);
		if (rc < 0) {
			this_cpu_inc(net->smc.smc_stats->clnt_hshake_err_cnt);
			if (smc_sk_state(&smc->sk) == SMC_INIT)
				sock_put(&smc->sk); /* passive closing */
			return rc;
		}
	}
	return smc_connect_fallback(smc, reason_code);
}

static void smc_conn_abort(struct smc_sock *smc, int local_first)
{
	struct smc_connection *conn = &smc->conn;
	struct smc_link_group *lgr = conn->lgr;
	bool lgr_valid = false;

	if (smc_conn_lgr_valid(conn))
		lgr_valid = true;

	smc_conn_free(conn);
	if (local_first && lgr_valid)
		smc_lgr_cleanup_early(lgr);
}

/* check if there is a rdma device available for this connection. */
/* called for connect and listen */
static int smc_find_rdma_device(struct smc_sock *smc, struct smc_init_info *ini)
{
	/* PNET table look up: search active ib_device and port
	 * within same PNETID that also contains the ethernet device
	 * used for the internal TCP socket
	 */
	smc_pnet_find_roce_resource(smc->clcsock->sk, ini);
	if (!ini->check_smcrv2 && !ini->ib_dev)
		return SMC_CLC_DECL_NOSMCRDEV;
	if (ini->check_smcrv2 && !ini->smcrv2.ib_dev_v2)
		return SMC_CLC_DECL_NOSMCRDEV;
	return 0;
}

/* check if there is an ISM device available for this connection. */
/* called for connect and listen */
static int smc_find_ism_device(struct smc_sock *smc, struct smc_init_info *ini)
{
	/* Find ISM device with same PNETID as connecting interface  */
	smc_pnet_find_ism_resource(smc->clcsock->sk, ini);
	if (!ini->ism_dev[0])
		return SMC_CLC_DECL_NOSMCDDEV;
	else
		ini->ism_chid[0] = smc_ism_get_chid(ini->ism_dev[0]);
	return 0;
}

/* is chid unique for the ism devices that are already determined? */
static bool smc_find_ism_v2_is_unique_chid(u16 chid, struct smc_init_info *ini,
					   int cnt)
{
	int i = (!ini->ism_dev[0]) ? 1 : 0;

	for (; i < cnt; i++)
		if (ini->ism_chid[i] == chid)
			return false;
	return true;
}

/* determine possible V2 ISM devices (either without PNETID or with PNETID plus
 * PNETID matching net_device)
 */
static int smc_find_ism_v2_device_clnt(struct smc_sock *smc,
				       struct smc_init_info *ini)
{
	int rc = SMC_CLC_DECL_NOSMCDDEV;
	struct smcd_dev *smcd;
	int i = 1;
	u16 chid;

	if (smcd_indicated(ini->smc_type_v1))
		rc = 0;		/* already initialized for V1 */
	mutex_lock(&smcd_dev_list.mutex);
	list_for_each_entry(smcd, &smcd_dev_list.list, list) {
		if (smcd->going_away || smcd == ini->ism_dev[0])
			continue;
		chid = smc_ism_get_chid(smcd);
		if (!smc_find_ism_v2_is_unique_chid(chid, ini, i))
			continue;
		if (!smc_pnet_is_pnetid_set(smcd->pnetid) ||
		    smc_pnet_is_ndev_pnetid(sock_net(&smc->sk), smcd->pnetid)) {
			ini->ism_dev[i] = smcd;
			ini->ism_chid[i] = chid;
			ini->is_smcd = true;
			rc = 0;
			i++;
			if (i > SMC_MAX_ISM_DEVS)
				break;
		}
	}
	mutex_unlock(&smcd_dev_list.mutex);
	ini->ism_offered_cnt = i - 1;
	if (!ini->ism_dev[0] && !ini->ism_dev[1])
		ini->smcd_version = 0;

	return rc;
}

/* Check for VLAN ID and register it on ISM device just for CLC handshake */
static int smc_connect_ism_vlan_setup(struct smc_sock *smc,
				      struct smc_init_info *ini)
{
	if (ini->vlan_id && smc_ism_get_vlan(ini->ism_dev[0], ini->vlan_id))
		return SMC_CLC_DECL_ISMVLANERR;
	return 0;
}

static int smc_find_proposal_devices(struct smc_sock *smc,
				     struct smc_init_info *ini)
{
	int rc = 0;

	/* check if there is an ism device available */
	if (!(ini->smcd_version & SMC_V1) ||
	    smc_find_ism_device(smc, ini) ||
	    smc_connect_ism_vlan_setup(smc, ini))
		ini->smcd_version &= ~SMC_V1;
	/* else ISM V1 is supported for this connection */

	/* check if there is an rdma device available */
	if (!(ini->smcr_version & SMC_V1) ||
	    smc_find_rdma_device(smc, ini))
		ini->smcr_version &= ~SMC_V1;
	/* else RDMA is supported for this connection */

	/* make sure SMC_V1 ibdev still available */
	if (ini->smcr_version & SMC_V1) {
		mutex_lock(&smc_ib_devices.mutex);
		if (list_empty(&ini->ib_dev->list)) {
			ini->ib_dev = NULL;
			ini->ib_port = 0;
			ini->smcr_version &= ~SMC_V1;
		} else {
			/* put in __smc_connect */
			smc_ib_get_pending_device(ini->ib_dev);
		}
		mutex_unlock(&smc_ib_devices.mutex);
	}

	ini->smc_type_v1 = smc_indicated_type(ini->smcd_version & SMC_V1,
					      ini->smcr_version & SMC_V1);

	/* check if there is an ism v2 device available */
	if (!(ini->smcd_version & SMC_V2) ||
	    !smc_ism_is_v2_capable() ||
	    smc_find_ism_v2_device_clnt(smc, ini))
		ini->smcd_version &= ~SMC_V2;

	/* check if there is an rdma v2 device available */
	ini->check_smcrv2 = true;
	ini->smcrv2.saddr = smc->clcsock->sk->sk_rcv_saddr;
	if (!(ini->smcr_version & SMC_V2) ||
	    smc->clcsock->sk->sk_family != AF_INET ||
	    !smc_clc_ueid_count() ||
	    smc_find_rdma_device(smc, ini))
		ini->smcr_version &= ~SMC_V2;
	ini->check_smcrv2 = false;

	/* make sure SMC_V2 ibdev still available */
	if (ini->smcr_version & SMC_V2) {
		mutex_lock(&smc_ib_devices.mutex);
		if (list_empty(&ini->smcrv2.ib_dev_v2->list)) {
			ini->smcrv2.ib_dev_v2 = NULL;
			ini->smcrv2.ib_port_v2 = 0;
			ini->smcr_version &= ~SMC_V2;
		} else {
			/* put in __smc_connect */
			smc_ib_get_pending_device(ini->smcrv2.ib_dev_v2);
		}
		mutex_unlock(&smc_ib_devices.mutex);
	}

	ini->smc_type_v2 = smc_indicated_type(ini->smcd_version & SMC_V2,
					      ini->smcr_version & SMC_V2);

	/* if neither ISM nor RDMA are supported, fallback */
	if (ini->smc_type_v1 == SMC_TYPE_N && ini->smc_type_v2 == SMC_TYPE_N)
		rc = SMC_CLC_DECL_NOSMCDEV;

	return rc;
}

/* cleanup temporary VLAN ID registration used for CLC handshake. If ISM is
 * used, the VLAN ID will be registered again during the connection setup.
 */
static int smc_connect_ism_vlan_cleanup(struct smc_sock *smc,
					struct smc_init_info *ini)
{
	if (!smcd_indicated(ini->smc_type_v1))
		return 0;
	if (ini->vlan_id && smc_ism_put_vlan(ini->ism_dev[0], ini->vlan_id))
		return SMC_CLC_DECL_CNFERR;
	return 0;
}

#define SMC_CLC_MAX_ACCEPT_LEN \
	(sizeof(struct smc_clc_msg_accept_confirm_v2) + \
	 sizeof(struct smc_clc_first_contact_ext_v2x) + \
	 sizeof(struct smc_clc_msg_trail))

/* CLC handshake during connect */
static int smc_connect_clc(struct smc_sock *smc,
			   struct smc_clc_msg_accept_confirm_v2 *aclc2,
			   struct smc_init_info *ini)
{
	int rc = 0;

	/* do inband token exchange */
	rc = smc_clc_send_proposal(smc, ini);
	if (rc)
		return rc;
	/* receive SMC Accept CLC message */
	return smc_clc_wait_msg(smc, aclc2, SMC_CLC_MAX_ACCEPT_LEN,
				SMC_CLC_ACCEPT, CLC_WAIT_TIME);
}

void smc_fill_gid_list(struct smc_link_group *lgr,
		       struct smc_gidlist *gidlist,
		       struct smc_ib_device *known_dev, u8 *known_gid)
{
	struct smc_init_info *alt_ini = NULL;

	memset(gidlist, 0, sizeof(*gidlist));
	memcpy(gidlist->list[gidlist->len++], known_gid, SMC_GID_SIZE);

	alt_ini = kzalloc(sizeof(*alt_ini), GFP_KERNEL);
	if (!alt_ini)
		goto out;

	alt_ini->vlan_id = lgr->vlan_id;
	alt_ini->check_smcrv2 = true;
	alt_ini->smcrv2.saddr = lgr->saddr;
	smc_pnet_find_alt_roce(lgr, alt_ini, known_dev);

	if (!alt_ini->smcrv2.ib_dev_v2)
		goto out;

	memcpy(gidlist->list[gidlist->len++], alt_ini->smcrv2.ib_gid_v2,
	       SMC_GID_SIZE);

out:
	kfree(alt_ini);
}

static int smc_connect_rdma_v2_prepare(struct smc_sock *smc,
				       struct smc_clc_msg_accept_confirm *aclc,
				       struct smc_init_info *ini)
{
	struct smc_clc_msg_accept_confirm_v2 *clc_v2 =
		(struct smc_clc_msg_accept_confirm_v2 *)aclc;
	struct smc_clc_first_contact_ext *fce =
		(struct smc_clc_first_contact_ext *)
			(((u8 *)clc_v2) + sizeof(*clc_v2));
	struct net *net = sock_net(&smc->sk);
	int rc;

	if (!ini->first_contact_peer || aclc->hdr.version == SMC_V1)
		return 0;

	if (fce->v2_direct) {
		memcpy(ini->smcrv2.nexthop_mac, &aclc->r0.lcl.mac, ETH_ALEN);
		ini->smcrv2.uses_gateway = false;
	} else {
		if (smc_ib_find_route(net, smc->clcsock->sk->sk_rcv_saddr,
				      smc_ib_gid_to_ipv4(aclc->r0.lcl.gid),
				      ini->smcrv2.nexthop_mac,
				      &ini->smcrv2.uses_gateway))
			return SMC_CLC_DECL_NOROUTE;
		if (!ini->smcrv2.uses_gateway) {
			/* mismatch: peer claims indirect, but its direct */
			return SMC_CLC_DECL_NOINDIRECT;
		}
	}

	if (fce->release > SMC_RELEASE)
		return SMC_CLC_DECL_VERSMISMAT;
	ini->release_ver = fce->release;
	rc = smc_clc_cli_v2x_features_validate(smc, fce, ini);
	if (rc)
		return rc;

	return 0;
}

/* setup for RDMA connection of client */
static int smc_connect_rdma(struct smc_sock *smc,
			    struct smc_clc_msg_accept_confirm *aclc,
			    struct smc_init_info *ini)
{
	int i, reason_code = 0;
	struct smc_link *link;
	u8 *eid = NULL;

	ini->is_smcd = false;
	ini->ib_clcqpn = ntoh24(aclc->r0.qpn);
	ini->first_contact_peer = aclc->hdr.typev2 & SMC_FIRST_CONTACT_MASK;
	memcpy(ini->peer_systemid, aclc->r0.lcl.id_for_peer, SMC_SYSTEMID_LEN);
	memcpy(ini->peer_gid, aclc->r0.lcl.gid, SMC_GID_SIZE);
	memcpy(ini->peer_mac, aclc->r0.lcl.mac, ETH_ALEN);
	ini->max_conns = SMC_RMBS_PER_LGR_MAX;
	ini->max_links = SMC_LINKS_ADD_LNK_MAX;

	reason_code = smc_connect_rdma_v2_prepare(smc, aclc, ini);
	if (reason_code)
		return reason_code;

	smc_lgr_pending_lock(ini, &smc_client_lgr_pending);
	reason_code = smc_conn_create(smc, ini);
	if (reason_code) {
		smc_lgr_pending_unlock(ini, &smc_client_lgr_pending);
		return reason_code;
	}

	smc_conn_save_peer_info(smc, aclc);

	if (ini->first_contact_local) {
		link = smc->conn.lnk;
	} else {
		/* set link that was assigned by server */
		link = NULL;
		for (i = 0; i < SMC_LINKS_PER_LGR_MAX; i++) {
			struct smc_link *l = &smc->conn.lgr->lnk[i];

			if (l->peer_qpn == ntoh24(aclc->r0.qpn) &&
			    !memcmp(l->peer_gid, &aclc->r0.lcl.gid,
				    SMC_GID_SIZE) &&
			    (aclc->hdr.version > SMC_V1 ||
			     !memcmp(l->peer_mac, &aclc->r0.lcl.mac,
				     sizeof(l->peer_mac)))) {
				link = l;
				break;
			}
		}
		if (!link) {
			reason_code = SMC_CLC_DECL_NOSRVLINK;
			goto connect_abort;
		}
		smc_switch_link_and_count(&smc->conn, link);
	}

	/* create send buffer and rmb */
	if (smc_buf_create(smc, false)) {
		reason_code = SMC_CLC_DECL_MEM;
		goto connect_abort;
	}

	if (ini->first_contact_local)
		smc_link_save_peer_info(link, aclc, ini);

	if (smc_rmb_rtoken_handling(&smc->conn, link, aclc)) {
		reason_code = SMC_CLC_DECL_ERR_RTOK;
		goto connect_abort;
	}

	smc_close_init(smc);
	smc_rx_init(smc);

	if (ini->first_contact_local) {
		if (smc_ib_ready_link(link)) {
			reason_code = SMC_CLC_DECL_ERR_RDYLNK;
			goto connect_abort;
		}
	} else {
		if (smc_llc_announce_credits(link, SMC_LLC_RESP, true)) {
			reason_code = SMC_CLC_DECL_CREDITSERR;
			goto connect_abort;
		}

		/* reg sendbufs if they were vzalloced */
		if (smc->conn.sndbuf_desc->is_vm) {
			if (smcr_lgr_reg_sndbufs(link, smc->conn.sndbuf_desc)) {
				reason_code = SMC_CLC_DECL_ERR_REGBUF;
				goto connect_abort;
			}
		}
		if (smcr_lgr_reg_rmbs(link, smc->conn.rmb_desc)) {
			reason_code = SMC_CLC_DECL_ERR_REGBUF;
			goto connect_abort;
		}
	}

	if (aclc->hdr.version > SMC_V1) {
		struct smc_clc_msg_accept_confirm_v2 *clc_v2 =
			(struct smc_clc_msg_accept_confirm_v2 *)aclc;

		eid = clc_v2->r1.eid;
		if (ini->first_contact_local)
			smc_fill_gid_list(link->lgr, &ini->smcrv2.gidlist,
					  link->smcibdev, link->gid);
	}

	reason_code = smc_clc_send_confirm(smc, ini->first_contact_local,
					   aclc->hdr.version, eid, ini);
	if (reason_code)
		goto connect_abort;

	smc_tx_init(smc);

	if (ini->first_contact_local) {
		/* QP confirmation over RoCE fabric */
		smc_llc_flow_initiate(link->lgr, SMC_LLC_FLOW_ADD_LINK);
		reason_code = smcr_clnt_conf_first_link(smc);
		smc_llc_flow_stop(link->lgr, &link->lgr->llc_flow_lcl);
		if (reason_code)
			goto connect_abort;
	}
	smc_lgr_pending_unlock(ini, &smc_client_lgr_pending);

	smc_copy_sock_settings_to_clc(smc);
	smc->connect_nonblock = 0;
	if (smc_sk_state(&smc->sk) == SMC_INIT)
		smc_sk_set_state(&smc->sk, SMC_ACTIVE);

	return 0;
connect_abort:
	smc_conn_abort(smc, ini->first_contact_local);
	smc_lgr_pending_unlock(ini, &smc_client_lgr_pending);
	smc->connect_nonblock = 0;

	return reason_code;
}

/* The server has chosen one of the proposed ISM devices for the communication.
 * Determine from the CHID of the received CLC ACCEPT the ISM device chosen.
 */
static int
smc_v2_determine_accepted_chid(struct smc_clc_msg_accept_confirm_v2 *aclc,
			       struct smc_init_info *ini)
{
	int i;

	for (i = 0; i < ini->ism_offered_cnt + 1; i++) {
		if (ini->ism_chid[i] == ntohs(aclc->d1.chid)) {
			ini->ism_selected = i;
			return 0;
		}
	}

	return -EPROTO;
}

/* setup for ISM connection of client */
static int smc_connect_ism(struct smc_sock *smc,
			   struct smc_clc_msg_accept_confirm *aclc,
			   struct smc_init_info *ini)
{
	u8 *eid = NULL;
	int rc = 0;

	ini->is_smcd = true;
	ini->first_contact_peer = aclc->hdr.typev2 & SMC_FIRST_CONTACT_MASK;

	if (aclc->hdr.version == SMC_V2) {
		struct smc_clc_msg_accept_confirm_v2 *aclc_v2 =
			(struct smc_clc_msg_accept_confirm_v2 *)aclc;

		if (ini->first_contact_peer) {
			struct smc_clc_first_contact_ext *fce =
				smc_get_clc_first_contact_ext(aclc_v2, true);

			if (fce->release > SMC_RELEASE)
				return SMC_CLC_DECL_VERSMISMAT;
			ini->release_ver = fce->release;
			rc = smc_clc_cli_v2x_features_validate(smc, fce, ini);
			if (rc)
				return rc;
		}

		rc = smc_v2_determine_accepted_chid(aclc_v2, ini);
		if (rc)
			return rc;
	}
	ini->ism_peer_gid[ini->ism_selected] = aclc->d0.gid;

	/* there is only one lgr role for SMC-D; use server lock */
	smc_lgr_pending_lock(ini, &smc_server_lgr_pending);
	rc = smc_conn_create(smc, ini);
	if (rc) {
		smc_lgr_pending_unlock(ini, &smc_server_lgr_pending);
		return rc;
	}

	/* Create send and receive buffers */
	rc = smc_buf_create(smc, true);
	if (rc) {
		rc = (rc == -ENOSPC) ? SMC_CLC_DECL_MAX_DMB : SMC_CLC_DECL_MEM;
		goto connect_abort;
	}

	smc_conn_save_peer_info(smc, aclc);

	if (smc_ism_dmb_mappable(smc->conn.lgr->smcd)) {
		rc = smcd_buf_attach(smc);
		if (rc)
			goto connect_abort;
	}
	smc_close_init(smc);
	smc_rx_init(smc);
	smc_tx_init(smc);

	if (aclc->hdr.version > SMC_V1) {
		struct smc_clc_msg_accept_confirm_v2 *clc_v2 =
			(struct smc_clc_msg_accept_confirm_v2 *)aclc;

		eid = clc_v2->d1.eid;
	}

	rc = smc_clc_send_confirm(smc, ini->first_contact_local,
				  aclc->hdr.version, eid, ini);
	if (rc)
		goto connect_abort;
	smc_lgr_pending_unlock(ini, &smc_server_lgr_pending);

	smc_copy_sock_settings_to_clc(smc);
	smc->connect_nonblock = 0;
	if (smc_sk_state(&smc->sk) == SMC_INIT)
		smc_sk_set_state(&smc->sk, SMC_ACTIVE);

	return 0;
connect_abort:
	smc_conn_abort(smc, ini->first_contact_local);
	smc_lgr_pending_unlock(ini, &smc_server_lgr_pending);
	smc->connect_nonblock = 0;

	return rc;
}

/* check if received accept type and version matches a proposed one */
static int smc_connect_check_aclc(struct smc_init_info *ini,
				  struct smc_clc_msg_accept_confirm *aclc)
{
	if (aclc->hdr.typev1 != SMC_TYPE_R &&
	    aclc->hdr.typev1 != SMC_TYPE_D)
		return SMC_CLC_DECL_MODEUNSUPP;

	if (aclc->hdr.version >= SMC_V2) {
		if ((aclc->hdr.typev1 == SMC_TYPE_R &&
		     !smcr_indicated(ini->smc_type_v2)) ||
		    (aclc->hdr.typev1 == SMC_TYPE_D &&
		     !smcd_indicated(ini->smc_type_v2)))
			return SMC_CLC_DECL_MODEUNSUPP;
	} else {
		if ((aclc->hdr.typev1 == SMC_TYPE_R &&
		     !smcr_indicated(ini->smc_type_v1)) ||
		    (aclc->hdr.typev1 == SMC_TYPE_D &&
		     !smcd_indicated(ini->smc_type_v1)))
			return SMC_CLC_DECL_MODEUNSUPP;
	}

	return 0;
}

/* perform steps before actually connecting */
static int __smc_connect(struct smc_sock *smc)
{
	u8 version = smc_ism_is_v2_capable() ? SMC_V2 : SMC_V1;
	struct smc_clc_msg_accept_confirm_v2 *aclc2;
	struct smc_clc_msg_accept_confirm *aclc;
	struct smc_init_info *ini = NULL;
	u8 *buf = NULL;
	int rc = 0;

	if (smc->use_fallback)
		return smc_connect_fallback(smc, smc->fallback_rsn);

	/* if peer has not signalled SMC-capability, fall back */
	if (!tcp_sk(smc->clcsock->sk)->syn_smc)
		return smc_connect_fallback(smc, SMC_CLC_DECL_PEERNOSMC);

	/* IPSec connections opt out of SMC optimizations */
	if (using_ipsec(smc))
		return smc_connect_decline_fallback(smc, SMC_CLC_DECL_IPSEC,
						    version);

	ini = kzalloc(sizeof(*ini), GFP_KERNEL);
	if (!ini)
		return smc_connect_decline_fallback(smc, SMC_CLC_DECL_MEM,
						    version);

	ini->smcd_version = SMC_V1 | SMC_V2;
	ini->smcr_version = SMC_V1 | SMC_V2;
	ini->smc_type_v1 = SMC_TYPE_B;
	ini->smc_type_v2 = SMC_TYPE_B;

	/* get vlan id from IP device */
	if (smc_vlan_by_tcpsk(smc->clcsock, ini)) {
		ini->smcd_version &= ~SMC_V1;
		ini->smcr_version = 0;
		ini->smc_type_v1 = SMC_TYPE_N;
		if (!ini->smcd_version) {
			rc = SMC_CLC_DECL_GETVLANERR;
			goto fallback;
		}
	}

	rc = smc_find_proposal_devices(smc, ini);
	if (rc)
		goto fallback;

	buf = kzalloc(SMC_CLC_MAX_ACCEPT_LEN, GFP_KERNEL);
	if (!buf) {
		rc = SMC_CLC_DECL_MEM;
		goto fallback;
	}
	aclc2 = (struct smc_clc_msg_accept_confirm_v2 *)buf;
	aclc = (struct smc_clc_msg_accept_confirm *)aclc2;

	/* perform CLC handshake */
	rc = smc_connect_clc(smc, aclc2, ini);
	if (rc) {
		/* -EAGAIN on timeout, see tcp_recvmsg() */
		if (rc == -EAGAIN) {
			rc = -ETIMEDOUT;
			smc->sk.sk_err = ETIMEDOUT;
		}
		goto vlan_cleanup;
	}

	/* check if smc modes and versions of CLC proposal and accept match */
	rc = smc_connect_check_aclc(ini, aclc);
	version = aclc->hdr.version == SMC_V1 ? SMC_V1 : SMC_V2;
	if (rc)
		goto vlan_cleanup;

	/* depending on previous steps, connect using rdma or ism */
	if (aclc->hdr.typev1 == SMC_TYPE_R) {
		ini->smcr_version = version;
		rc = smc_connect_rdma(smc, aclc, ini);
	} else if (aclc->hdr.typev1 == SMC_TYPE_D) {
		ini->smcd_version = version;
		rc = smc_connect_ism(smc, aclc, ini);
	}
	if (rc)
		goto vlan_cleanup;

	if (ini->smcrv2.ib_dev_v2)
		smc_ib_put_pending_device(ini->smcrv2.ib_dev_v2);
	if (ini->ib_dev)
		smc_ib_put_pending_device(ini->ib_dev);
	SMC_STAT_CLNT_SUCC_INC(sock_net(smc->clcsock->sk), aclc);
	smc_connect_ism_vlan_cleanup(smc, ini);
	kfree(buf);
	kfree(ini);
	return 0;

vlan_cleanup:
	smc_connect_ism_vlan_cleanup(smc, ini);
	kfree(buf);
fallback:
	if (ini->smcrv2.ib_dev_v2)
		smc_ib_put_pending_device(ini->smcrv2.ib_dev_v2);
	if (ini->ib_dev)
		smc_ib_put_pending_device(ini->ib_dev);
	kfree(ini);
	return smc_connect_decline_fallback(smc, rc, version);
}

static void smc_connect_work(struct work_struct *work)
{
	struct smc_sock *smc = container_of(work, struct smc_sock,
					    connect_work);
	long timeo = smc->sk.sk_sndtimeo;
	int rc = 0;

	if (!timeo)
		timeo = MAX_SCHEDULE_TIMEOUT;
	lock_sock(smc->clcsock->sk);
	if (smc->clcsock->sk->sk_err) {
		smc->sk.sk_err = smc->clcsock->sk->sk_err;
	} else if ((1 << smc->clcsock->sk->sk_state) &
					(TCPF_SYN_SENT | TCPF_SYN_RECV)) {
		rc = sk_stream_wait_connect(smc->clcsock->sk, &timeo);
		if ((rc == -EPIPE) &&
		    ((1 << smc->clcsock->sk->sk_state) &
					(TCPF_ESTABLISHED | TCPF_CLOSE_WAIT)))
			rc = 0;
	}
	release_sock(smc->clcsock->sk);
	lock_sock(&smc->sk);
	if (rc != 0 || smc->sk.sk_err) {
		smc_sk_set_state(&smc->sk, SMC_CLOSED);
		if (rc == -EPIPE || rc == -EAGAIN)
			smc->sk.sk_err = EPIPE;
		else if (signal_pending(current))
			smc->sk.sk_err = -sock_intr_errno(timeo);
		sock_put(&smc->sk); /* passive closing */
		goto out;
	}

	rc = __smc_connect(smc);
	if (rc < 0)
		smc->sk.sk_err = -rc;

out:
	if (!smc_sock_flag(&smc->sk, SOCK_DEAD)) {
		if (smc->sk.sk_err) {
			smc->sk.sk_state_change(&smc->sk);
		} else { /* allow polling before and after fallback decision */
			smc->clcsock->sk->sk_write_space(smc->clcsock->sk);
			smc->sk.sk_write_space(&smc->sk);
		}
	}
	release_sock(&smc->sk);
}

static int smc_connect(struct socket *sock, struct sockaddr *addr,
		       int alen, int flags)
{
	struct sock *sk = sock->sk;
	struct smc_sock *smc;
	int rc = -EINVAL;

	smc = smc_sk(sk);

	/* separate smc parameter checking to be safe */
	if (alen < sizeof(addr->sa_family))
		goto out_err;
	if (addr->sa_family != AF_INET && addr->sa_family != AF_INET6)
		goto out_err;

	lock_sock(sk);
	switch (sock->state) {
	default:
		rc = -EINVAL;
		goto out;
	case SS_CONNECTED:
		rc = smc_sk_state(sk) == SMC_ACTIVE ? -EISCONN : -EINVAL;
		goto out;
	case SS_CONNECTING:
		if (smc_sk_state(sk) == SMC_ACTIVE)
			goto connected;
		break;
	case SS_UNCONNECTED:
		sock->state = SS_CONNECTING;
		break;
	}

	switch (smc_sk_state(sk)) {
	default:
		goto out;
	case SMC_CLOSED:
		rc = sock_error(sk) ? : -ECONNABORTED;
		sock->state = SS_UNCONNECTED;
		goto out;
	case SMC_ACTIVE:
		rc = -EISCONN;
		goto out;
	case SMC_INIT:
		break;
	}

	if (!smc->clcsock ||
	    (smc->clcsock && !smc->clcsock->sk)) {
		rc = -EBADF;
		goto out;
	}

	if (smc->connect_nonblock) {
		rc = -EALREADY;
		goto out;
	}

	smc_copy_sock_settings_to_clc(smc);

	if (smc_sock_is_inet_sock(sk)) {
		write_lock_bh(&sk->sk_callback_lock);
		if (smc_inet_sock_set_syn_smc_locked(sk,
						     smc_sock_should_select_smc(smc, addr)
						     == SK_PASS)) {
			if (flags & O_NONBLOCK)
				smc_clcsock_replace_cb(&sk->sk_state_change,
						       smc_inet_sock_state_change,
						       &smc->clcsk_state_change);
			/* restore the smc_sk_sndbuf before connect */
			smc->smc_sk_sndbuf = READ_ONCE(sk->sk_sndbuf);
		} else if (!tcp_sk(sk)->syn_smc && !smc->use_fallback) {
			smc_switch_to_fallback(smc, /* active fallback */ SMC_CLC_DECL_ACTIVE);
		}
		write_unlock_bh(&sk->sk_callback_lock);
	} else if (smc_sock_should_select_smc(smc, addr) != SK_PASS) {
		tcp_sk(smc->clcsock->sk)->syn_smc = 0;
		smc_switch_to_fallback(smc, /* active fallback */ SMC_CLC_DECL_ACTIVE);
	} else {
		tcp_sk(smc->clcsock->sk)->syn_smc = 1;
	}

	rc = kernel_connect(smc->clcsock, addr, alen, flags);
	if (rc && rc != -EINPROGRESS)
		goto out;

	if (smc->use_fallback) {
		sock->state = rc ? SS_CONNECTING : SS_CONNECTED;
		goto out;
	}

	/* for inet sock */
	if (smc_sock_is_inet_sock(sk)) {
		if (flags & O_NONBLOCK) {
			write_lock_bh(&sk->sk_callback_lock);
			if (smc_inet_sock_check_smc(sk) || smc_inet_sock_check_fallback(sk)) {
				rc = 0;
			} else {
				smc->connect_nonblock = 1;
				rc = -EINPROGRESS;
			}
			write_unlock_bh(&sk->sk_callback_lock);
		} else {
			write_lock_bh(&sk->sk_callback_lock);
again:
			switch (isck_smc_negotiation_load(smc)) {
			case SMC_NEGOTIATION_TBD:
				/* already abort */
				if (isck_smc_negotiation_get_flags(smc_sk(sk)) &
								   SMC_NEGOTIATION_ABORT_FLAG) {
					rc = -ECONNABORTED;
					break;
				}
				smc_inet_sock_move_state_locked(sk, SMC_NEGOTIATION_TBD,
								SMC_NEGOTIATION_PREPARE_SMC);
				write_unlock_bh(&sk->sk_callback_lock);
do_handshake:
				rc = smc_inet_sock_do_handshake(sk, /* sk_locked */ true,
								true);
				write_lock_bh(&sk->sk_callback_lock);
				break;
			case SMC_NEGOTIATION_PREPARE_SMC:
				write_unlock_bh(&sk->sk_callback_lock);
				/* cancel success */
				if (cancel_work_sync(&smc->connect_work))
					goto do_handshake;
				write_lock_bh(&sk->sk_callback_lock);
				goto again;
			case SMC_NEGOTIATION_NO_SMC:
			case SMC_NEGOTIATION_SMC:
				rc = 0;
				break;
			}
			write_unlock_bh(&sk->sk_callback_lock);
			if (!rc)
				goto connected;
		}
		goto out;
	}

	sock_hold(&smc->sk); /* sock put in passive closing */

	if (flags & O_NONBLOCK) {
		if (queue_work(smc_hs_wq, &smc->connect_work))
			smc->connect_nonblock = 1;
		rc = -EINPROGRESS;
		goto out;
	} else {
		rc = __smc_connect(smc);
		if (rc < 0)
			goto out;
	}

connected:
	rc = 0;
	sock->state = SS_CONNECTED;
out:
	release_sock(sk);
out_err:
	return rc;
}

static int smc_clcsock_accept(struct smc_sock *lsmc, struct smc_sock **new_smc)
{
	struct socket *new_clcsock = NULL;
	struct sock *lsk = &lsmc->sk;
	struct sock *new_sk;
	int rc = -EINVAL;

	release_sock(lsk);
	new_sk = smc_sock_alloc(sock_net(lsk), NULL, lsk->sk_protocol);
	if (!new_sk) {
		rc = -ENOMEM;
		lsk->sk_err = ENOMEM;
		*new_smc = NULL;
		lock_sock(lsk);
		goto out;
	}
	*new_smc = smc_sk(new_sk);

	mutex_lock(&lsmc->clcsock_release_lock);
	if (lsmc->clcsock)
		rc = kernel_accept(lsmc->clcsock, &new_clcsock, SOCK_NONBLOCK);
	mutex_unlock(&lsmc->clcsock_release_lock);
	lock_sock(lsk);
	if  (rc < 0 && rc != -EAGAIN)
		lsk->sk_err = -rc;
	if (rc < 0 || smc_sk_state(lsk) == SMC_CLOSED) {
		new_sk->sk_prot->unhash(new_sk);
		mutex_lock(&lsmc->clcsock_release_lock);
		if (new_clcsock)
			sock_release(new_clcsock);
		smc_sk_set_state(new_sk, SMC_CLOSED);
		smc_sock_set_flag(new_sk, SOCK_DEAD);
		mutex_unlock(&lsmc->clcsock_release_lock);
		sock_put(new_sk); /* final */
		*new_smc = NULL;
		goto out;
	}

	/* new clcsock has inherited the smc listen-specific sk_data_ready
	 * function; switch it back to the original sk_data_ready function
	 */
	new_clcsock->sk->sk_data_ready = lsmc->clcsk_data_ready;

	/* if new clcsock has also inherited the fallback-specific callback
	 * functions, switch them back to the original ones.
	 */
	if (lsmc->use_fallback) {
		if (lsmc->clcsk_state_change)
			new_clcsock->sk->sk_state_change = lsmc->clcsk_state_change;
		if (lsmc->clcsk_write_space)
			new_clcsock->sk->sk_write_space = lsmc->clcsk_write_space;
		if (lsmc->clcsk_error_report)
			new_clcsock->sk->sk_error_report = lsmc->clcsk_error_report;
	}

	(*new_smc)->clcsock = new_clcsock;
out:
	return rc;
}

/* add a just created sock to the accept queue of the listen sock as
 * candidate for a following socket accept call from user space
 */
static void smc_accept_enqueue(struct sock *parent, struct sock *sk)
{
	struct smc_sock *par = smc_sk(parent);

	sock_hold(sk); /* sock_put in smc_accept_unlink () */
	spin_lock(&par->accept_q_lock);
	list_add_tail(&smc_sk(sk)->accept_q, &par->accept_q);
	if (!smc_sock_is_inet_sock(sk))
		sk_acceptq_added(parent);
	spin_unlock(&par->accept_q_lock);
}

/* remove a socket from the accept queue of its parental listening socket */
static void smc_accept_unlink(struct sock *sk)
{
	struct smc_sock *par = smc_sk(sk)->listen_smc;

	spin_lock(&par->accept_q_lock);
	list_del_init(&smc_sk(sk)->accept_q);
	if (!smc_sock_is_inet_sock(sk))
		sk_acceptq_removed(&smc_sk(sk)->listen_smc->sk);
	spin_unlock(&par->accept_q_lock);
	sock_put(sk); /* sock_hold in smc_accept_enqueue */
}

static inline bool smc_accept_queue_empty(struct sock *sk)
{
	return list_empty(&smc_sk(sk)->accept_q);
}

/* remove a sock from the accept queue to bind it to a new socket created
 * for a socket accept call from user space
 */
struct sock *smc_accept_dequeue(struct sock *parent,
				struct socket *new_sock)
{
	struct smc_sock *isk, *n;
	struct sock *new_sk;

	list_for_each_entry_safe(isk, n, &smc_sk(parent)->accept_q, accept_q) {
		new_sk = (struct sock *)isk;

		smc_accept_unlink(new_sk);
		if (smc_sk_state(new_sk) == SMC_CLOSED) {
			if (smc_sock_is_inet_sock(parent)) {
				tcp_close(new_sk, 0);
				continue;
			}
			new_sk->sk_prot->unhash(new_sk);
			if (isk->clcsock) {
				sock_release(isk->clcsock);
				isk->clcsock = NULL;
			}
			sock_put(new_sk); /* final */
			continue;
		}
		if (new_sock) {
			sock_graft(new_sk, new_sock);
			new_sock->state = SS_CONNECTED;
			if (isk->use_fallback) {
				smc_sk(new_sk)->clcsock->file = new_sock->file;
				isk->clcsock->file->private_data = isk->clcsock;
			}
		}
		return new_sk;
	}
	return NULL;
}

/* clean up for a created but never accepted sock */
void smc_close_non_accepted(struct sock *sk)
{
	struct smc_sock *smc = smc_sk(sk);

	sock_hold(sk); /* sock_put below */
	lock_sock(sk);
	if (smc_sock_is_inet_sock(sk)) {
		if (!smc_inet_sock_check_fallback(sk))
			smc_close_active(smc);
		smc_sock_set_flag(sk, SOCK_DEAD);
		release_sock(sk);
		tcp_close(sk, 0);
		lock_sock(sk);
		if (smc_sk_state(sk) == SMC_CLOSED)
			smc_conn_free(&smc->conn);
	} else {
		if (!sk->sk_lingertime)
			/* wait for peer closing */
			sk->sk_lingertime = SMC_MAX_STREAM_WAIT_TIMEOUT;
		__smc_release(smc);
	}
	release_sock(sk);
	sock_put(sk); /* sock_hold above */
	if (!smc_sock_is_inet_sock(sk))
		sock_put(sk); /* final sock_put */
}

static int smcr_serv_conf_first_link(struct smc_sock *smc)
{
	struct smc_link *link = smc->conn.lnk;
	struct smc_llc_qentry *qentry;
	int rc;

	/* reg the sndbuf if it was vzalloced*/
	if (smc->conn.sndbuf_desc->is_vm) {
		if (smcr_link_reg_buf(link, smc->conn.sndbuf_desc))
			return SMC_CLC_DECL_ERR_REGBUF;
	}

	/* reg the rmb */
	if (smcr_link_reg_buf(link, smc->conn.rmb_desc))
		return SMC_CLC_DECL_ERR_REGBUF;

	/* send CONFIRM LINK request to client over the RoCE fabric */
	rc = smc_llc_send_confirm_link(link, SMC_LLC_REQ);
	if (rc < 0)
		return SMC_CLC_DECL_TIMEOUT_CL;

	/* receive CONFIRM LINK response from client over the RoCE fabric */
	qentry = smc_llc_wait(link->lgr, link, SMC_LLC_WAIT_TIME,
			      SMC_LLC_CONFIRM_LINK);
	if (!qentry) {
		struct smc_clc_msg_decline dclc;

		rc = smc_clc_wait_msg(smc, &dclc, sizeof(dclc),
				      SMC_CLC_DECLINE, CLC_WAIT_TIME_SHORT);
		return rc == -EAGAIN ? SMC_CLC_DECL_TIMEOUT_CL : rc;
	}
	smc_llc_save_peer_uid(qentry);
	rc = smc_llc_eval_conf_link(qentry, SMC_LLC_RESP);
	smc_llc_flow_qentry_del(&link->lgr->llc_flow_lcl);
	if (rc)
		return SMC_CLC_DECL_RMBE_EC;

	/* confirm_rkey is implicit on 1st contact */
	smc->conn.rmb_desc->is_conf_rkey = true;

	smc_llc_link_active(link);
	smcr_lgr_set_type(link->lgr, SMC_LGR_SINGLE);

	if (link->lgr->max_links > 1) {
		down_write(&link->lgr->llc_conf_mutex);
		/* initial contact - try to establish second link */
		smc_llc_srv_add_link(link, NULL);
		up_write(&link->lgr->llc_conf_mutex);
	}
	return 0;
}

/* listen worker: finish */
static void smc_listen_out(struct smc_sock *new_smc)
{
	struct smc_sock *lsmc = new_smc->listen_smc;
	struct sock *newsmcsk = &new_smc->sk;

	if (new_smc->smc_negotiated)
		atomic_dec(&lsmc->queued_smc_hs);

	if (smc_sock_is_inet_sock(newsmcsk))
		smc_inet_sock_move_state(newsmcsk,
					 SMC_NEGOTIATION_PREPARE_SMC,
					 new_smc->use_fallback &&
					 smc_sk_state(newsmcsk) == SMC_ACTIVE ?
					 SMC_NEGOTIATION_NO_SMC :
					 SMC_NEGOTIATION_SMC);

	if (smc_sk_state(&lsmc->sk) == SMC_LISTEN) {
		lock_sock_nested(&lsmc->sk, SINGLE_DEPTH_NESTING);
		smc_accept_enqueue(&lsmc->sk, newsmcsk);
		release_sock(&lsmc->sk);
	} else { /* no longer listening */
		smc_close_non_accepted(newsmcsk);
	}

	/* Wake up accept */
	lsmc->sk.sk_data_ready(&lsmc->sk);
	sock_put(&lsmc->sk); /* sock_hold in smc_tcp_listen_work */
}

/* listen worker: finish in state connected */
static void smc_listen_out_connected(struct smc_sock *new_smc)
{
	struct sock *newsmcsk = &new_smc->sk;

	lock_sock(newsmcsk);
	if (smc_sk_state(newsmcsk) == SMC_INIT)
		smc_sk_set_state(newsmcsk, SMC_ACTIVE);
	release_sock(newsmcsk);

	smc_listen_out(new_smc);
}

/* listen worker: finish in error state */
static void smc_listen_out_err(struct smc_sock *new_smc)
{
	struct sock *newsmcsk = &new_smc->sk;
	struct net *net = sock_net(newsmcsk);

	this_cpu_inc(net->smc.smc_stats->srv_hshake_err_cnt);

	lock_sock(newsmcsk);
	if (smc_sk_state(newsmcsk) != SMC_CLOSED &&
	    smc_sk_state(newsmcsk) != SMC_PROCESSABORT)
		sock_put(&new_smc->sk); /* passive closing */
	smc_sk_set_state(newsmcsk, SMC_CLOSED);
	release_sock(newsmcsk);

	smc_listen_out(new_smc);
}

/* listen worker: decline and fall back if possible */
static void smc_listen_decline(struct smc_sock *new_smc, int reason_code,
			       int local_first, u8 version)
{
	/* RDMA setup failed, switch back to TCP */
	smc_conn_abort(new_smc, local_first);
	if (reason_code < 0 ||
	    smc_switch_to_fallback(new_smc, reason_code)) {
		/* error, no fallback possible */
		smc_listen_out_err(new_smc);
		return;
	}
	if (reason_code && reason_code != SMC_CLC_DECL_PEERDECL) {
		if (smc_clc_send_decline(new_smc, reason_code, version) < 0) {
			smc_listen_out_err(new_smc);
			return;
		}
	}
	smc_listen_out_connected(new_smc);
}

/* listen worker: version checking */
static int smc_listen_v2_check(struct smc_sock *new_smc,
			       struct smc_clc_msg_proposal *pclc,
			       struct smc_init_info *ini)
{
	struct smc_clc_smcd_v2_extension *pclc_smcd_v2_ext;
	struct smc_clc_v2_extension *pclc_v2_ext;
	int rc = SMC_CLC_DECL_PEERNOSMC;

	ini->smc_type_v1 = pclc->hdr.typev1;
	ini->smc_type_v2 = pclc->hdr.typev2;
	ini->smcd_version = smcd_indicated(ini->smc_type_v1) ? SMC_V1 : 0;
	ini->smcr_version = smcr_indicated(ini->smc_type_v1) ? SMC_V1 : 0;
	if (pclc->hdr.version > SMC_V1) {
		if (smcd_indicated(ini->smc_type_v2))
			ini->smcd_version |= SMC_V2;
		if (smcr_indicated(ini->smc_type_v2))
			ini->smcr_version |= SMC_V2;
	}
	if (!(ini->smcd_version & SMC_V2) && !(ini->smcr_version & SMC_V2)) {
		rc = SMC_CLC_DECL_PEERNOSMC;
		goto out;
	}
	pclc_v2_ext = smc_get_clc_v2_ext(pclc);
	if (!pclc_v2_ext) {
		ini->smcd_version &= ~SMC_V2;
		ini->smcr_version &= ~SMC_V2;
		rc = SMC_CLC_DECL_NOV2EXT;
		goto out;
	}
	pclc_smcd_v2_ext = smc_get_clc_smcd_v2_ext(pclc_v2_ext);
	if (ini->smcd_version & SMC_V2) {
		if (!smc_ism_is_v2_capable()) {
			ini->smcd_version &= ~SMC_V2;
			rc = SMC_CLC_DECL_NOISM2SUPP;
		} else if (!pclc_smcd_v2_ext) {
			ini->smcd_version &= ~SMC_V2;
			rc = SMC_CLC_DECL_NOV2DEXT;
		} else if (!pclc_v2_ext->hdr.eid_cnt &&
			   !pclc_v2_ext->hdr.flag.seid) {
			ini->smcd_version &= ~SMC_V2;
			rc = SMC_CLC_DECL_NOUEID;
		}
	}
	if (ini->smcr_version & SMC_V2) {
		if (!pclc_v2_ext->hdr.eid_cnt) {
			ini->smcr_version &= ~SMC_V2;
			rc = SMC_CLC_DECL_NOUEID;
		}
	}

	ini->release_ver = pclc_v2_ext->hdr.flag.release;
	if (pclc_v2_ext->hdr.flag.release > SMC_RELEASE)
		ini->release_ver = SMC_RELEASE;

out:
	if (!ini->smcd_version && !ini->smcr_version)
		return rc;

	return 0;
}

/* listen worker: check prefixes */
static int smc_listen_prfx_check(struct smc_sock *new_smc,
				 struct smc_clc_msg_proposal *pclc)
{
	struct smc_clc_msg_proposal_prefix *pclc_prfx;
	struct socket *newclcsock = new_smc->clcsock;

	if (pclc->hdr.typev1 == SMC_TYPE_N)
		return 0;
	pclc_prfx = smc_clc_proposal_get_prefix(pclc);
	if (smc_clc_prfx_match(newclcsock, pclc_prfx))
		return SMC_CLC_DECL_DIFFPREFIX;

	return 0;
}

/* listen worker: initialize connection and buffers */
static int smc_listen_rdma_init(struct smc_sock *new_smc,
				struct smc_init_info *ini)
{
	int rc;

	/* allocate connection / link group */
	rc = smc_conn_create(new_smc, ini);
	if (rc)
		return rc;

	/* create send buffer and rmb */
	if (smc_buf_create(new_smc, false)) {
		smc_conn_abort(new_smc, ini->first_contact_local);
		return SMC_CLC_DECL_MEM;
	}

	return 0;
}

/* listen worker: initialize connection and buffers for SMC-D */
static int smc_listen_ism_init(struct smc_sock *new_smc,
			       struct smc_init_info *ini)
{
	int rc;

	rc = smc_conn_create(new_smc, ini);
	if (rc)
		return rc;

	/* Create send and receive buffers */
	rc = smc_buf_create(new_smc, true);
	if (rc) {
		smc_conn_abort(new_smc, ini->first_contact_local);
		return (rc == -ENOSPC) ? SMC_CLC_DECL_MAX_DMB :
					 SMC_CLC_DECL_MEM;
	}

	return 0;
}

static bool smc_is_already_selected(struct smcd_dev *smcd,
				    struct smc_init_info *ini,
				    int matches)
{
	int i;

	for (i = 0; i < matches; i++)
		if (smcd == ini->ism_dev[i])
			return true;

	return false;
}

/* check for ISM devices matching proposed ISM devices */
static void smc_check_ism_v2_match(struct smc_init_info *ini,
				   u16 proposed_chid, u64 proposed_gid,
				   unsigned int *matches)
{
	struct smcd_dev *smcd;

	list_for_each_entry(smcd, &smcd_dev_list.list, list) {
		if (smcd->going_away)
			continue;
		if (smc_is_already_selected(smcd, ini, *matches))
			continue;
		if (smc_ism_get_chid(smcd) == proposed_chid &&
		    !smc_ism_cantalk(proposed_gid, ISM_RESERVED_VLANID, smcd)) {
			ini->ism_peer_gid[*matches] = proposed_gid;
			ini->ism_dev[*matches] = smcd;
			(*matches)++;
			break;
		}
	}
}

static void smc_find_ism_store_rc(u32 rc, struct smc_init_info *ini)
{
	if (!ini->rc)
		ini->rc = rc;
}

static void smc_find_ism_v2_device_serv(struct smc_sock *new_smc,
					struct smc_clc_msg_proposal *pclc,
					struct smc_init_info *ini)
{
	struct smc_clc_smcd_v2_extension *smcd_v2_ext;
	struct smc_clc_v2_extension *smc_v2_ext;
	struct smc_clc_msg_smcd *pclc_smcd;
	unsigned int matches = 0;
	u8 smcd_version;
	u8 *eid = NULL;
	int i, rc;

	if (!(ini->smcd_version & SMC_V2) || !smcd_indicated(ini->smc_type_v2))
		goto not_found;

	pclc_smcd = smc_get_clc_msg_smcd(pclc);
	smc_v2_ext = smc_get_clc_v2_ext(pclc);
	smcd_v2_ext = smc_get_clc_smcd_v2_ext(smc_v2_ext);

	mutex_lock(&smcd_dev_list.mutex);
	if (pclc_smcd->ism.chid)
		/* check for ISM device matching proposed native ISM device */
		smc_check_ism_v2_match(ini, ntohs(pclc_smcd->ism.chid),
				       ntohll(pclc_smcd->ism.gid), &matches);
	for (i = 1; i <= smc_v2_ext->hdr.ism_gid_cnt; i++) {
		/* check for ISM devices matching proposed non-native ISM
		 * devices
		 */
		smc_check_ism_v2_match(ini,
				       ntohs(smcd_v2_ext->gidchid[i - 1].chid),
				       ntohll(smcd_v2_ext->gidchid[i - 1].gid),
				       &matches);
	}
	mutex_unlock(&smcd_dev_list.mutex);

	if (!ini->ism_dev[0]) {
		smc_find_ism_store_rc(SMC_CLC_DECL_NOSMCD2DEV, ini);
		goto not_found;
	}

	smc_ism_get_system_eid(&eid);
	if (!smc_clc_match_eid(ini->negotiated_eid, smc_v2_ext,
			       smcd_v2_ext->system_eid, eid))
		goto not_found;

	/* separate - outside the smcd_dev_list.lock */
	smcd_version = ini->smcd_version;
	for (i = 0; i < matches; i++) {
		ini->smcd_version = SMC_V2;
		ini->is_smcd = true;
		ini->ism_selected = i;
		rc = smc_listen_ism_init(new_smc, ini);
		if (rc) {
			smc_find_ism_store_rc(rc, ini);
			/* try next active ISM device */
			continue;
		}
		return; /* matching and usable V2 ISM device found */
	}
	/* no V2 ISM device could be initialized */
	ini->smcd_version = smcd_version;	/* restore original value */
	ini->negotiated_eid[0] = 0;

not_found:
	ini->smcd_version &= ~SMC_V2;
	ini->ism_dev[0] = NULL;
	ini->is_smcd = false;
}

static void smc_find_ism_v1_device_serv(struct smc_sock *new_smc,
					struct smc_clc_msg_proposal *pclc,
					struct smc_init_info *ini)
{
	struct smc_clc_msg_smcd *pclc_smcd = smc_get_clc_msg_smcd(pclc);
	int rc = 0;

	/* check if ISM V1 is available */
	if (!(ini->smcd_version & SMC_V1) || !smcd_indicated(ini->smc_type_v1))
		goto not_found;
	ini->is_smcd = true; /* prepare ISM check */
	ini->ism_peer_gid[0] = ntohll(pclc_smcd->ism.gid);
	rc = smc_find_ism_device(new_smc, ini);
	if (rc)
		goto not_found;
	ini->ism_selected = 0;
	rc = smc_listen_ism_init(new_smc, ini);
	if (!rc)
		return;		/* V1 ISM device found */

not_found:
	smc_find_ism_store_rc(rc, ini);
	ini->smcd_version &= ~SMC_V1;
	ini->ism_dev[0] = NULL;
	ini->is_smcd = false;
}

/* listen worker: register buffers */
static int smc_listen_rdma_reg(struct smc_sock *new_smc, bool local_first)
{
	struct smc_connection *conn = &new_smc->conn;

	if (!local_first) {
		/* reg sendbufs if they were vzalloced */
		if (conn->sndbuf_desc->is_vm) {
			if (smcr_lgr_reg_sndbufs(conn->lnk,
						 conn->sndbuf_desc))
				return SMC_CLC_DECL_ERR_REGBUF;
		}
		if (smcr_lgr_reg_rmbs(conn->lnk, conn->rmb_desc))
			return SMC_CLC_DECL_ERR_REGBUF;
	}

	return 0;
}

static void smc_find_rdma_v2_device_serv(struct smc_sock *new_smc,
					 struct smc_clc_msg_proposal *pclc,
					 struct smc_init_info *ini)
{
	struct smc_clc_v2_extension *smc_v2_ext;
	u8 smcr_version;
	int rc;

	if (!(ini->smcr_version & SMC_V2) || !smcr_indicated(ini->smc_type_v2))
		goto not_found;

	smc_v2_ext = smc_get_clc_v2_ext(pclc);
	if (!smc_clc_match_eid(ini->negotiated_eid, smc_v2_ext, NULL, NULL))
		goto not_found;

	/* prepare RDMA check */
	memcpy(ini->peer_systemid, pclc->lcl.id_for_peer, SMC_SYSTEMID_LEN);
	memcpy(ini->peer_gid, smc_v2_ext->roce, SMC_GID_SIZE);
	memcpy(ini->peer_mac, pclc->lcl.mac, ETH_ALEN);
	ini->check_smcrv2 = true;
	ini->smcrv2.clc_sk = new_smc->clcsock->sk;
	ini->smcrv2.saddr = new_smc->clcsock->sk->sk_rcv_saddr;
	ini->smcrv2.daddr = smc_ib_gid_to_ipv4(smc_v2_ext->roce);
	rc = smc_find_rdma_device(new_smc, ini);
	if (rc) {
		smc_find_ism_store_rc(rc, ini);
		goto not_found;
	}
	/* make sure SMC_V2 ibdev still available */
	mutex_lock(&smc_ib_devices.mutex);
	if (list_empty(&ini->smcrv2.ib_dev_v2->list)) {
		smc_find_ism_store_rc(SMC_CLC_DECL_NOSMCRDEV, ini);
		mutex_unlock(&smc_ib_devices.mutex);
		goto not_found;
	} else {
		/* put below or in smc_listen_work */
		smc_ib_get_pending_device(ini->smcrv2.ib_dev_v2);
	}
	mutex_unlock(&smc_ib_devices.mutex);

	if (!ini->smcrv2.uses_gateway)
		memcpy(ini->smcrv2.nexthop_mac, pclc->lcl.mac, ETH_ALEN);

	smcr_version = ini->smcr_version;
	ini->smcr_version = SMC_V2;
	rc = smc_listen_rdma_init(new_smc, ini);
	if (!rc) {
		rc = smc_listen_rdma_reg(new_smc, ini->first_contact_local);
		if (rc)
			smc_conn_abort(new_smc, ini->first_contact_local);
	}
	if (!rc)
		return;
	ini->smcr_version = smcr_version;
	smc_find_ism_store_rc(rc, ini);
	smc_ib_put_pending_device(ini->smcrv2.ib_dev_v2);

not_found:
	ini->smcr_version &= ~SMC_V2;
	ini->smcrv2.ib_dev_v2 = NULL;
	ini->check_smcrv2 = false;
}

static int smc_find_rdma_v1_device_serv(struct smc_sock *new_smc,
					struct smc_clc_msg_proposal *pclc,
					struct smc_init_info *ini)
{
	int rc;

	if (!(ini->smcr_version & SMC_V1) || !smcr_indicated(ini->smc_type_v1))
		return SMC_CLC_DECL_NOSMCDEV;

	/* prepare RDMA check */
	memcpy(ini->peer_systemid, pclc->lcl.id_for_peer, SMC_SYSTEMID_LEN);
	memcpy(ini->peer_gid, pclc->lcl.gid, SMC_GID_SIZE);
	memcpy(ini->peer_mac, pclc->lcl.mac, ETH_ALEN);
	rc = smc_find_rdma_device(new_smc, ini);
	if (rc) {
		/* no RDMA device found */
		return SMC_CLC_DECL_NOSMCDEV;
	}
	/* make sure SMC_V1 ibdev still available */
	mutex_lock(&smc_ib_devices.mutex);
	if (list_empty(&ini->ib_dev->list)) {
		ini->ib_dev = NULL;
		ini->ib_port = 0;
		mutex_unlock(&smc_ib_devices.mutex);
		return SMC_CLC_DECL_NOSMCDEV;
	}
	/* put in smc_listen_work */
	smc_ib_get_pending_device(ini->ib_dev);
	mutex_unlock(&smc_ib_devices.mutex);

	rc = smc_listen_rdma_init(new_smc, ini);
	if (rc)
		return rc;
	return smc_listen_rdma_reg(new_smc, ini->first_contact_local);
}

/* determine the local device matching to proposal */
static int smc_listen_find_device(struct smc_sock *new_smc,
				  struct smc_clc_msg_proposal *pclc,
				  struct smc_init_info *ini)
{
	int prfx_rc;

	/* check for ISM device matching V2 proposed device */
	smc_find_ism_v2_device_serv(new_smc, pclc, ini);
	if (ini->ism_dev[0])
		return 0;

	/* check for matching IP prefix and subnet length (V1) */
	prfx_rc = smc_listen_prfx_check(new_smc, pclc);
	if (prfx_rc)
		smc_find_ism_store_rc(prfx_rc, ini);

	/* get vlan id from IP device */
	if (smc_vlan_by_tcpsk(new_smc->clcsock, ini))
		return ini->rc ?: SMC_CLC_DECL_GETVLANERR;

	/* check for ISM device matching V1 proposed device */
	if (!prfx_rc)
		smc_find_ism_v1_device_serv(new_smc, pclc, ini);
	if (ini->ism_dev[0])
		return 0;

	if (!smcr_indicated(pclc->hdr.typev1) &&
	    !smcr_indicated(pclc->hdr.typev2))
		/* skip RDMA and decline */
		return ini->rc ?: SMC_CLC_DECL_NOSMCDDEV;

	/* check if RDMA V2 is available */
	smc_find_rdma_v2_device_serv(new_smc, pclc, ini);
	if (ini->smcrv2.ib_dev_v2)
		return 0;

	/* check if RDMA V1 is available */
	if (!prfx_rc) {
		int rc;

		rc = smc_find_rdma_v1_device_serv(new_smc, pclc, ini);
		smc_find_ism_store_rc(rc, ini);
		return (!rc) ? 0 : ini->rc;
	}
	return SMC_CLC_DECL_NOSMCDEV;
}

/* listen worker: finish RDMA setup */
static int smc_listen_rdma_finish(struct smc_sock *new_smc,
				  struct smc_clc_msg_accept_confirm *cclc,
				  bool local_first,
				  struct smc_init_info *ini)
{
	struct smc_link *link = new_smc->conn.lnk;
	int reason_code = 0;

	if (local_first)
		smc_link_save_peer_info(link, cclc, ini);

	if (smc_rmb_rtoken_handling(&new_smc->conn, link, cclc))
		return SMC_CLC_DECL_ERR_RTOK;

	if (local_first) {
		if (smc_ib_ready_link(link))
			return SMC_CLC_DECL_ERR_RDYLNK;
		/* QP confirmation over RoCE fabric */
		smc_llc_flow_initiate(link->lgr, SMC_LLC_FLOW_ADD_LINK);
		reason_code = smcr_serv_conf_first_link(new_smc);
		smc_llc_flow_stop(link->lgr, &link->lgr->llc_flow_lcl);
	}
	return reason_code;
}

/* setup for connection of server */
static void smc_listen_work(struct work_struct *work)
{
	struct smc_sock *new_smc = container_of(work, struct smc_sock,
						smc_listen_work);
	struct socket *newclcsock = new_smc->clcsock;
	struct smc_clc_msg_accept_confirm *cclc;
	struct smc_clc_msg_proposal_area *buf;
	struct smc_clc_msg_proposal *pclc;
	struct smc_init_info *ini = NULL;
	u8 proposal_version = SMC_V1;
	u8 accept_version;
	int rc = 0;

	if (smc_sk_state(&new_smc->listen_smc->sk) != SMC_LISTEN)
		return smc_listen_out_err(new_smc);

	if (new_smc->use_fallback) {
		smc_listen_out_connected(new_smc);
		return;
	}

	/* check if peer is smc capable */
	if (!tcp_sk(newclcsock->sk)->syn_smc) {
		rc = smc_switch_to_fallback(new_smc, SMC_CLC_DECL_PEERNOSMC);
		if (rc)
			smc_listen_out_err(new_smc);
		else
			smc_listen_out_connected(new_smc);
		return;
	}

	/* do inband token exchange -
	 * wait for and receive SMC Proposal CLC message
	 */
	buf = kzalloc(sizeof(*buf), GFP_KERNEL);
	if (!buf) {
		rc = SMC_CLC_DECL_MEM;
		goto out_decl;
	}
	pclc = (struct smc_clc_msg_proposal *)buf;
	rc = smc_clc_wait_msg(new_smc, pclc, sizeof(*buf),
			      SMC_CLC_PROPOSAL, CLC_WAIT_TIME);
	if (rc)
		goto out_decl;

	if (pclc->hdr.version > SMC_V1)
		proposal_version = SMC_V2;

	/* IPSec connections opt out of SMC optimizations */
	if (using_ipsec(new_smc)) {
		rc = SMC_CLC_DECL_IPSEC;
		goto out_decl;
	}

	ini = kzalloc(sizeof(*ini), GFP_KERNEL);
	if (!ini) {
		rc = SMC_CLC_DECL_MEM;
		goto out_decl;
	}

	/* initial version checking */
	rc = smc_listen_v2_check(new_smc, pclc, ini);
	if (rc)
		goto out_decl;

	rc = smc_clc_srv_v2x_features_validate(new_smc, pclc, ini);
	if (rc)
		goto out_decl;

	smc_lgr_pending_lock(ini, &smc_server_lgr_pending);
	smc_close_init(new_smc);
	smc_rx_init(new_smc);
	smc_tx_init(new_smc);

	/* determine ISM or RoCE device used for connection */
	rc = smc_listen_find_device(new_smc, pclc, ini);
	if (rc)
		goto out_unlock;

	/* send SMC Accept CLC message */
	accept_version = ini->is_smcd ? ini->smcd_version : ini->smcr_version;
	rc = smc_clc_send_accept(new_smc, ini->first_contact_local,
				 accept_version, ini->negotiated_eid, ini);
	if (rc)
		goto out_unlock;

	/* SMC-D does not need this lock any more */
	if (ini->is_smcd)
		smc_lgr_pending_unlock(ini, &smc_server_lgr_pending);

	/* receive SMC Confirm CLC message */
	memset(buf, 0, sizeof(*buf));
	cclc = (struct smc_clc_msg_accept_confirm *)buf;
	rc = smc_clc_wait_msg(new_smc, cclc, sizeof(*buf),
			      SMC_CLC_CONFIRM, CLC_WAIT_TIME);
	if (rc) {
		if (!ini->is_smcd)
			goto out_unlock;
		goto out_decl;
	}

	rc = smc_clc_v2x_features_confirm_check(cclc, ini);
	if (rc) {
		if (!ini->is_smcd)
			goto out_unlock;
		goto out_decl;
	}

	/* fce smc release version is needed in smc_listen_rdma_finish,
	 * so save fce info here.
	 */
	smc_conn_save_peer_info_fce(new_smc, cclc);

	/* finish worker */
	if (!ini->is_smcd) {
		rc = smc_listen_rdma_finish(new_smc, cclc,
					    ini->first_contact_local, ini);
		if (rc)
			goto out_unlock;
		smc_lgr_pending_unlock(ini, &smc_server_lgr_pending);
	}
	if (ini->smcrv2.ib_dev_v2)
		smc_ib_put_pending_device(ini->smcrv2.ib_dev_v2);
	if (ini->ib_dev)
		smc_ib_put_pending_device(ini->ib_dev);
	smc_conn_save_peer_info(new_smc, cclc);

	if (ini->is_smcd &&
	    smc_ism_dmb_mappable(new_smc->conn.lgr->smcd)) {
		rc = smcd_buf_attach(new_smc);
		if (rc)
			goto out_decl;
	}

	smc_listen_out_connected(new_smc);
	if (newclcsock->sk)
		SMC_STAT_SERV_SUCC_INC(sock_net(newclcsock->sk), ini);
	goto out_free;

out_unlock:
	if (ini->smcrv2.ib_dev_v2)
		smc_ib_put_pending_device(ini->smcrv2.ib_dev_v2);
	if (ini->ib_dev)
		smc_ib_put_pending_device(ini->ib_dev);
	smc_lgr_pending_unlock(ini, &smc_server_lgr_pending);
out_decl:
	smc_listen_decline(new_smc, rc, ini ? ini->first_contact_local : 0,
			   proposal_version);
out_free:
	kfree(ini);
	kfree(buf);
}

static void smc_tcp_listen_work(struct work_struct *work)
{
	struct smc_sock *lsmc = container_of(work, struct smc_sock,
					     tcp_listen_work);
	struct sock *lsk = &lsmc->sk;
	struct smc_sock *new_smc;
	int rc = 0;

	lock_sock(lsk);
	while (smc_sk_state(lsk) == SMC_LISTEN) {
		rc = smc_clcsock_accept(lsmc, &new_smc);
		if (rc) /* clcsock accept queue empty or error */
			goto out;
		if (!new_smc)
			continue;

		smc_sock_init_passive(lsk, &new_smc->sk);

		new_smc->use_fallback = lsmc->use_fallback;
		new_smc->fallback_rsn = lsmc->fallback_rsn;
		sock_hold(lsk); /* sock_put in smc_listen_work */
		INIT_WORK(&new_smc->smc_listen_work, smc_listen_work);
		smc_copy_sock_settings_to_smc(new_smc);
		new_smc->sk.sk_sndbuf = lsmc->sk.sk_sndbuf;
		new_smc->sk.sk_rcvbuf = lsmc->sk.sk_rcvbuf;
		sock_hold(&new_smc->sk); /* sock_put in passive closing */
		if (!queue_work(smc_hs_wq, &new_smc->smc_listen_work))
			sock_put(&new_smc->sk);
	}

out:
	release_sock(lsk);
	sock_put(&lsmc->sk); /* sock_hold in smc_clcsock_data_ready() */
}

static void smc_clcsock_data_ready(struct sock *listen_clcsock)
{
	struct smc_sock *lsmc;

	read_lock_bh(&listen_clcsock->sk_callback_lock);
	lsmc = smc_clcsock_user_data(listen_clcsock);
	if (!lsmc)
		goto out;
	lsmc->clcsk_data_ready(listen_clcsock);
	if (smc_sk_state(&lsmc->sk) == SMC_LISTEN) {
		sock_hold(&lsmc->sk); /* sock_put in smc_tcp_listen_work() */
		if (!queue_work(smc_tcp_ls_wq, &lsmc->tcp_listen_work))
			sock_put(&lsmc->sk);
	}
out:
	read_unlock_bh(&listen_clcsock->sk_callback_lock);
}

static inline void smc_init_listen(struct smc_sock *smc)
{
	struct sock *clcsk;

	clcsk = smc_sock_is_inet_sock(&smc->sk) ? &smc->sk : smc->clcsock->sk;

	/* save original sk_data_ready function and establish
	 * smc-specific sk_data_ready function
	 */
	write_lock_bh(&clcsk->sk_callback_lock);
	clcsk->sk_user_data =
		(void *)((uintptr_t)smc | SK_USER_DATA_NOCOPY);
	smc_clcsock_replace_cb(&clcsk->sk_data_ready,
			       smc_clcsock_data_ready, &smc->clcsk_data_ready);
	write_unlock_bh(&clcsk->sk_callback_lock);

	if (!smc_sock_is_inet_sock(&smc->sk)) {
		/* save original ops */
		smc->ori_af_ops = inet_csk(clcsk)->icsk_af_ops;

		smc->af_ops = *smc->ori_af_ops;
		smc->af_ops.syn_recv_sock = smc_tcp_syn_recv_sock;

		inet_csk(clcsk)->icsk_af_ops = &smc->af_ops;
	}

	if (smc->limit_smc_hs)
		tcp_sk(clcsk)->smc_hs_congested = smc_hs_congested;
}

static int smc_listen(struct socket *sock, int backlog)
{
	struct sock *sk = sock->sk;
	struct smc_sock *smc;
	int rc;

	smc = smc_sk(sk);
	lock_sock(sk);

	rc = -EINVAL;
	if ((smc_sk_state(sk) != SMC_INIT && smc_sk_state(sk) != SMC_LISTEN) ||
	    smc->connect_nonblock || sock->state != SS_UNCONNECTED)
		goto out;

	rc = 0;
	if (smc_sk_state(sk) == SMC_LISTEN) {
		sk->sk_max_ack_backlog = backlog;
		goto out;
	}
	/* some socket options are handled in core, so we could not apply
	 * them to the clc socket -- copy smc socket options to clc socket
	 */
	smc_copy_sock_settings_to_clc(smc);
	if (!smc->use_fallback)
		tcp_sk(smc->clcsock->sk)->syn_smc = 1;

	smc_init_listen(smc);

	rc = kernel_listen(smc->clcsock, backlog);
	if (rc) {
		write_lock_bh(&smc->clcsock->sk->sk_callback_lock);
		smc_clcsock_restore_cb(&smc->clcsock->sk->sk_data_ready,
				       &smc->clcsk_data_ready);
		smc->clcsock->sk->sk_user_data = NULL;
		write_unlock_bh(&smc->clcsock->sk->sk_callback_lock);
		goto out;
	}
	sk->sk_max_ack_backlog = backlog;
	sk->sk_ack_backlog = 0;
	smc_sk_set_state(sk, SMC_LISTEN);

out:
	release_sock(sk);
	return rc;
}

static struct sock *__smc_accept(struct sock *sk, struct socket *new_sock,
				 int flags, int *err, bool kern)
{
	DECLARE_WAITQUEUE(wait, current);
	struct sock *nsk = NULL;
	struct smc_sock *lsmc;
	long timeo;
	int rc = 0;

	lsmc = smc_sk(sk);
	lock_sock(sk);

	if (smc_sk_state(&lsmc->sk) != SMC_LISTEN) {
		rc = -EINVAL;
		release_sock(sk);
		goto out;
	}

	/* Wait for an incoming connection */
	timeo = sock_rcvtimeo(sk, flags & O_NONBLOCK);
	add_wait_queue_exclusive(sk_sleep(sk), &wait);
	while (!(nsk = smc_accept_dequeue(sk, new_sock))) {
		set_current_state(TASK_INTERRUPTIBLE);
		if (!timeo) {
			rc = -EAGAIN;
			break;
		}
		release_sock(sk);
		timeo = schedule_timeout(timeo);
		/* wakeup by sk_data_ready in smc_listen_work() */
		sched_annotate_sleep();
		lock_sock(sk);
		if (signal_pending(current)) {
			rc = sock_intr_errno(timeo);
			break;
		}
	}
	set_current_state(TASK_RUNNING);
	remove_wait_queue(sk_sleep(sk), &wait);

	if (!rc)
		rc = sock_error(nsk);
	release_sock(sk);
	if (rc)
		goto out;

	if (lsmc->sockopt_defer_accept && !(flags & O_NONBLOCK)) {
		/* wait till data arrives on the socket */
		timeo = msecs_to_jiffies(lsmc->sockopt_defer_accept *
								MSEC_PER_SEC);
		if (smc_sk(nsk)->use_fallback) {
			struct sock *clcsk = smc_sk(nsk)->clcsock->sk;

			lock_sock(clcsk);
			if (skb_queue_empty(&clcsk->sk_receive_queue))
				sk_wait_data(clcsk, &timeo, NULL);
			release_sock(clcsk);
		} else if (!atomic_read(&smc_sk(nsk)->conn.bytes_to_rcv)) {
			lock_sock(nsk);
			smc_rx_wait(smc_sk(nsk), &timeo, smc_rx_data_available);
			release_sock(nsk);
		}
	}

out:
	*err = rc;
	return nsk;
}

static int smc_accept(struct socket *sock, struct socket *new_sock,
		      int flags, bool kern)
{
	struct sock *sk = sock->sk;
	int error;

	sock_hold(sk);
	__smc_accept(sk, new_sock, flags, &error, kern);
	sock_put(sk);

	return error;
}

static int smc_getname(struct socket *sock, struct sockaddr *addr,
		       int peer)
{
	struct smc_sock *smc;

	if (peer && (smc_sk_state(sock->sk) != SMC_ACTIVE) &&
	    (smc_sk_state(sock->sk) != SMC_APPCLOSEWAIT1))
		return -ENOTCONN;

	smc = smc_sk(sock->sk);

	return smc->clcsock->ops->getname(smc->clcsock, addr, peer);
}

static int smc_sendmsg(struct socket *sock, struct msghdr *msg, size_t len)
{
	struct sock *sk = sock->sk;
	struct smc_sock *smc;
	int rc;

	smc = smc_sk(sk);
	lock_sock(sk);

	/* SMC does not support connect with fastopen */
	if (msg->msg_flags & MSG_FASTOPEN) {
		/* not connected yet, fallback */
		if (smc_sk_state(sk) == SMC_INIT && !smc->connect_nonblock) {
			rc = smc_switch_to_fallback(smc, SMC_CLC_DECL_OPTUNSUPP);
			if (rc)
				goto out;
		} else {
			rc = -EINVAL;
			goto out;
		}
	} else if ((smc_sk_state(sk) != SMC_ACTIVE) &&
		   (smc_sk_state(sk) != SMC_APPCLOSEWAIT1) &&
		   (smc_sk_state(sk) != SMC_INIT)) {
		rc = -EPIPE;
		goto out;
	}

	if (smc->use_fallback) {
		rc = smc->clcsock->ops->sendmsg(smc->clcsock, msg, len);
	} else {
		rc = smc_tx_sendmsg(smc, msg, len);
		SMC_STAT_TX_PAYLOAD(smc, len, rc);
	}
out:
	release_sock(sk);
	return rc;
}

static int smc_recvmsg(struct socket *sock, struct msghdr *msg, size_t len,
		       int flags)
{
	struct sock *sk = sock->sk;
	struct smc_sock *smc;
	int rc = -ENOTCONN;

	smc = smc_sk(sk);
	lock_sock(sk);
	if (smc_sk_state(sk) == SMC_CLOSED && smc_has_rcv_shutdown(sk)) {
		/* socket was connected before, no more data to read */
		rc = 0;
		goto out;
	}
	if ((smc_sk_state(sk) == SMC_INIT) ||
	    (smc_sk_state(sk) == SMC_LISTEN) ||
	    (smc_sk_state(sk) == SMC_CLOSED))
		goto out;

	if (smc_sk_state(sk) == SMC_PEERFINCLOSEWAIT) {
		rc = 0;
		goto out;
	}

	if (smc->use_fallback) {
		rc = smc->clcsock->ops->recvmsg(smc->clcsock, msg, len, flags);
	} else {
		msg->msg_namelen = 0;
		rc = smc_rx_recvmsg(smc, msg, NULL, len, flags);
		SMC_STAT_RX_PAYLOAD(smc, rc, rc);
	}

out:
	release_sock(sk);
	return rc;
}

static inline __poll_t smc_accept_poll(struct sock *parent)
{
	if (!smc_accept_queue_empty(parent))
		return EPOLLIN | EPOLLRDNORM;

	return 0;
}

static __poll_t smc_poll(struct file *file, struct socket *sock,
			     poll_table *wait)
{
	struct sock *sk = sock->sk;
	struct smc_sock *smc;
	__poll_t mask = 0;

	if (!sk)
		return EPOLLNVAL;

	smc = smc_sk(sock->sk);
	if (smc->use_fallback) {
		/* delegate to CLC child sock */
		mask = smc->clcsock->ops->poll(file, smc->clcsock, wait);
		sk->sk_err = smc->clcsock->sk->sk_err;
	} else {
		if (smc_sk_state(sk) != SMC_CLOSED)
			sock_poll_wait(file, sock, wait);
		if (sk->sk_err)
			mask |= EPOLLERR;
		if ((sk->sk_shutdown == SHUTDOWN_MASK) ||
		    (smc_sk_state(sk) == SMC_CLOSED))
			mask |= EPOLLHUP;
		if (smc_sk_state(sk) == SMC_LISTEN) {
			/* woken up by sk_data_ready in smc_listen_work() */
			mask |= smc_accept_poll(sk);
		} else if (smc->use_fallback) { /* as result of connect_work()*/
			mask |= smc->clcsock->ops->poll(file, smc->clcsock,
							   wait);
			sk->sk_err = smc->clcsock->sk->sk_err;
		} else {
			if ((smc_sk_state(sk) != SMC_INIT &&
			     atomic_read(&smc->conn.sndbuf_space)) ||
			    sk->sk_shutdown & SEND_SHUTDOWN) {
				mask |= EPOLLOUT | EPOLLWRNORM;
			} else {
				sk_set_bit(SOCKWQ_ASYNC_NOSPACE, sk);
				set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
			}
			if (atomic_read(&smc->conn.bytes_to_rcv))
				mask |= EPOLLIN | EPOLLRDNORM;
			if (smc_has_rcv_shutdown(sk))
				mask |= EPOLLIN | EPOLLRDNORM | EPOLLRDHUP;
			if (smc_sk_state(sk) == SMC_APPCLOSEWAIT1)
				mask |= EPOLLIN;
			if (smc->conn.urg_state == SMC_URG_VALID)
				mask |= EPOLLPRI;
		}
	}

	return mask;
}

static int smc_shutdown(struct socket *sock, int how)
{
	struct sock *sk = sock->sk;
	bool do_shutdown = true;
	struct smc_sock *smc;
	int rc = -EINVAL;
	int old_state;
	int rc1 = 0;

	smc = smc_sk(sk);

	if ((how < SHUT_RD) || (how > SHUT_RDWR))
		return rc;

	lock_sock(sk);

	if (sock->state == SS_CONNECTING) {
		if (smc_sk_state(sk) == SMC_ACTIVE)
			sock->state = SS_CONNECTED;
		else if (smc_sk_state(sk) == SMC_PEERCLOSEWAIT1 ||
			 smc_sk_state(sk) == SMC_PEERCLOSEWAIT2 ||
			 smc_sk_state(sk) == SMC_APPCLOSEWAIT1 ||
			 smc_sk_state(sk) == SMC_APPCLOSEWAIT2 ||
			 smc_sk_state(sk) == SMC_APPFINCLOSEWAIT)
			sock->state = SS_DISCONNECTING;
	}

	rc = -ENOTCONN;
	if ((smc_sk_state(sk) != SMC_ACTIVE) &&
	    (smc_sk_state(sk) != SMC_PEERCLOSEWAIT1) &&
	    (smc_sk_state(sk) != SMC_PEERCLOSEWAIT2) &&
	    (smc_sk_state(sk) != SMC_APPCLOSEWAIT1) &&
	    (smc_sk_state(sk) != SMC_APPCLOSEWAIT2) &&
	    (smc_sk_state(sk) != SMC_APPFINCLOSEWAIT))
		goto out;
	if (smc->use_fallback) {
		rc = kernel_sock_shutdown(smc->clcsock, how);
		sk->sk_shutdown = smc->clcsock->sk->sk_shutdown;
		if (sk->sk_shutdown == SHUTDOWN_MASK) {
			smc_sk_set_state(sk, SMC_CLOSED);
			sk->sk_socket->state = SS_UNCONNECTED;
			sock_put(sk);
		}
		goto out;
	}
	switch (how) {
	case SHUT_RDWR:		/* shutdown in both directions */
		old_state = smc_sk_state(sk);
		rc = smc_close_active(smc);
		if (old_state == SMC_ACTIVE &&
		    smc_sk_state(sk) == SMC_PEERCLOSEWAIT1)
			do_shutdown = false;
		break;
	case SHUT_WR:
		rc = smc_close_shutdown_write(smc);
		break;
	case SHUT_RD:
		rc = 0;
		/* nothing more to do because peer is not involved */
		break;
	}
	if (do_shutdown && smc->clcsock)
		rc1 = kernel_sock_shutdown(smc->clcsock, how);
	/* map sock_shutdown_cmd constants to sk_shutdown value range */
	sk->sk_shutdown |= how + 1;

	if (smc_sk_state(sk) == SMC_CLOSED)
		sock->state = SS_UNCONNECTED;
	else
		sock->state = SS_DISCONNECTING;
out:
	release_sock(sk);
	return rc ? rc : rc1;
}

static int __smc_getsockopt(struct socket *sock, int level, int optname,
			    char __user *optval, int __user *optlen)
{
	struct smc_sock *smc;
	int val, len;

	smc = smc_sk(sock->sk);

	if (get_user(len, optlen))
		return -EFAULT;

	len = min_t(int, len, sizeof(int));

	if (len < 0)
		return -EINVAL;

	switch (optname) {
	case SMC_LIMIT_HS:
		val = smc->limit_smc_hs;
		break;
	default:
		return -EOPNOTSUPP;
	}

	if (put_user(len, optlen))
		return -EFAULT;
	if (copy_to_user(optval, &val, len))
		return -EFAULT;

	return 0;
}

static int __smc_setsockopt(struct socket *sock, int level, int optname,
			    sockptr_t optval, unsigned int optlen)
{
	struct sock *sk = sock->sk;
	struct smc_sock *smc;
	int val, rc;

	smc = smc_sk(sk);

	lock_sock(sk);
	switch (optname) {
	case SMC_LIMIT_HS:
		if (optlen < sizeof(int)) {
			rc = -EINVAL;
			break;
		}
		if (copy_from_sockptr(&val, optval, sizeof(int))) {
			rc = -EFAULT;
			break;
		}

		smc->limit_smc_hs = !!val;
		rc = 0;
		break;
	default:
		rc = -EOPNOTSUPP;
		break;
	}
	release_sock(sk);

	return rc;
}

/* When an unsupported sockopt is found,
 * SMC should try it best to fallback. If fallback is not possible,
 * an error should be explicitly returned.
 */
static inline bool smc_is_unsupport_tcp_sockopt(int optname)
{
	switch (optname) {
	case TCP_FASTOPEN:
	case TCP_FASTOPEN_CONNECT:
	case TCP_FASTOPEN_KEY:
	case TCP_FASTOPEN_NO_COOKIE:
	case TCP_ULP:
		return true;
	}
	return false;
}

/* Return true if smc might modify the semantics of
 * the imcoming TCP options. Specifically, it includes
 * unsupported TCP options.
 */
static inline bool smc_need_override_tcp_sockopt(struct sock *sk, int optname)
{
	switch (optname) {
	case TCP_NODELAY:
	case TCP_CORK:
		if (smc_sk_state(sk) == SMC_INIT ||
		    smc_sk_state(sk) == SMC_LISTEN ||
		    smc_sk_state(sk) == SMC_CLOSED)
			return false;
		fallthrough;
	case TCP_DEFER_ACCEPT:
		return true;
	default:
		break;
	}
	return smc_is_unsupport_tcp_sockopt(optname);
}

static int smc_setsockopt_takeover(struct socket *sock, int level, int optname,
				   sockptr_t optval, unsigned int optlen)
{
	struct sock *sk = sock->sk;
	struct smc_sock *smc;
	int val, rc = 0;

	smc = smc_sk(sk);

	/* Obviously, the logic bellow requires the level to be TCP_SOL */
	if (level != SOL_TCP)
		return 0;

	/* fast path, just go away if no extra action needed */
	if (!smc_need_override_tcp_sockopt(sk, optname))
		return 0;

	if (optlen < sizeof(int))
		return -EINVAL;
	if (copy_from_sockptr(&val, optval, sizeof(int)))
		return -EFAULT;

	lock_sock(sk);
	if (smc->use_fallback)
		goto out;
	switch (optname) {
	case TCP_NODELAY:
		if (smc_sk_state(sk) != SMC_INIT &&
		    smc_sk_state(sk) != SMC_LISTEN &&
		    smc_sk_state(sk) != SMC_CLOSED) {
			if (val) {
				SMC_STAT_INC(smc, ndly_cnt);
				smc_tx_pending(&smc->conn);
				cancel_delayed_work(&smc->conn.tx_work);
			}
		}
		break;
	case TCP_CORK:
		if (smc_sk_state(sk) != SMC_INIT &&
		    smc_sk_state(sk) != SMC_LISTEN &&
		    smc_sk_state(sk) != SMC_CLOSED) {
			if (!val) {
				SMC_STAT_INC(smc, cork_cnt);
				smc_tx_pending(&smc->conn);
				cancel_delayed_work(&smc->conn.tx_work);
			}
		}
		break;
	case TCP_DEFER_ACCEPT:
		smc->sockopt_defer_accept = val;
		break;
	default:
		if (smc_is_unsupport_tcp_sockopt(optname)) {
			/* option not supported by SMC */
			if (smc_sk_state(sk) == SMC_INIT && !smc->connect_nonblock)
				rc = smc_switch_to_fallback(smc, SMC_CLC_DECL_OPTUNSUPP);
			else
				rc = -EINVAL;
		}
		break;
	}
out:
	release_sock(sk);
	return rc;
}

static int smc_setsockopt(struct socket *sock, int level, int optname,
			  sockptr_t optval, unsigned int optlen)
{
	struct sock *sk = sock->sk;
	struct smc_sock *smc;
	int rc;

	if (level == SOL_TCP && optname == TCP_ULP)
		return -EOPNOTSUPP;
	else if (level == SOL_SMC)
		return __smc_setsockopt(sock, level, optname, optval, optlen);

	smc = smc_sk(sk);

	/* generic setsockopts reaching us here always apply to the
	 * CLC socket
	 */
	mutex_lock(&smc->clcsock_release_lock);
	if (!smc->clcsock) {
		mutex_unlock(&smc->clcsock_release_lock);
		return -EBADF;
	}
	if (unlikely(!smc->clcsock->ops->setsockopt))
		rc = -EOPNOTSUPP;
	else
		rc = smc->clcsock->ops->setsockopt(smc->clcsock, level, optname,
						   optval, optlen);
	if (smc->clcsock->sk->sk_err) {
		sk->sk_err = smc->clcsock->sk->sk_err;
		sk->sk_error_report(sk);
	}
	mutex_unlock(&smc->clcsock_release_lock);

	return rc ?: smc_setsockopt_takeover(sock, level, optname, optval, optlen);
}

static int smc_getsockopt(struct socket *sock, int level, int optname,
			  char __user *optval, int __user *optlen)
{
	struct smc_sock *smc;
	int rc;

	if (level == SOL_SMC)
		return __smc_getsockopt(sock, level, optname, optval, optlen);

	smc = smc_sk(sock->sk);
	mutex_lock(&smc->clcsock_release_lock);
	if (!smc->clcsock) {
		mutex_unlock(&smc->clcsock_release_lock);
		return -EBADF;
	}
	/* socket options apply to the CLC socket */
	if (unlikely(!smc->clcsock->ops->getsockopt)) {
		mutex_unlock(&smc->clcsock_release_lock);
		return -EOPNOTSUPP;
	}
	rc = smc->clcsock->ops->getsockopt(smc->clcsock, level, optname,
					   optval, optlen);
	mutex_unlock(&smc->clcsock_release_lock);
	return rc;
}

static int smc_ioctl(struct socket *sock, unsigned int cmd,
		     unsigned long arg)
{
	union smc_host_cursor cons, urg;
	struct smc_connection *conn;
	struct smc_sock *smc;
	int answ;

	smc = smc_sk(sock->sk);
	conn = &smc->conn;
	lock_sock(&smc->sk);
	if (smc->use_fallback) {
		if (!smc->clcsock) {
			release_sock(&smc->sk);
			return -EBADF;
		}
		answ = smc->clcsock->ops->ioctl(smc->clcsock, cmd, arg);
		release_sock(&smc->sk);
		return answ;
	}
	switch (cmd) {
	case SIOCINQ: /* same as FIONREAD */
		if (smc_sk_state(&smc->sk) == SMC_LISTEN) {
			release_sock(&smc->sk);
			return -EINVAL;
		}
		if (smc_sk_state(&smc->sk) == SMC_INIT ||
		    smc_sk_state(&smc->sk) == SMC_CLOSED)
			answ = 0;
		else
			answ = atomic_read(&smc->conn.bytes_to_rcv);
		break;
	case SIOCOUTQ:
		/* output queue size (not send + not acked) */
		if (smc_sk_state(&smc->sk) == SMC_LISTEN) {
			release_sock(&smc->sk);
			return -EINVAL;
		}
		if (smc_sk_state(&smc->sk) == SMC_INIT ||
		    smc_sk_state(&smc->sk) == SMC_CLOSED)
			answ = 0;
		else
			answ = smc->conn.sndbuf_desc->len -
					atomic_read(&smc->conn.sndbuf_space);
		break;
	case SIOCOUTQNSD:
		/* output queue size (not send only) */
		if (smc_sk_state(&smc->sk) == SMC_LISTEN) {
			release_sock(&smc->sk);
			return -EINVAL;
		}
		if (smc_sk_state(&smc->sk) == SMC_INIT ||
		    smc_sk_state(&smc->sk) == SMC_CLOSED)
			answ = 0;
		else
			answ = smc_tx_prepared_sends(&smc->conn);
		break;
	case SIOCATMARK:
		if (smc_sk_state(&smc->sk) == SMC_LISTEN) {
			release_sock(&smc->sk);
			return -EINVAL;
		}
		if (smc_sk_state(&smc->sk) == SMC_INIT ||
		    smc_sk_state(&smc->sk) == SMC_CLOSED) {
			answ = 0;
		} else {
			smc_curs_copy(&cons, &conn->local_tx_ctrl.cons, conn);
			smc_curs_copy(&urg, &conn->urg_curs, conn);
			answ = smc_curs_diff(conn->rmb_desc->len,
					     &cons, &urg) == 1;
		}
		break;
	default:
		release_sock(&smc->sk);
		return -ENOIOCTLCMD;
	}
	release_sock(&smc->sk);

	return put_user(answ, (int __user *)arg);
}

static ssize_t smc_sendpage(struct socket *sock, struct page *page,
			    int offset, size_t size, int flags)
{
	struct sock *sk = sock->sk;
	struct smc_sock *smc;
	int rc = -EPIPE;

	smc = smc_sk(sk);
	lock_sock(sk);
	if (smc_sk_state(sk) != SMC_ACTIVE) {
		release_sock(sk);
		goto out;
	}
	release_sock(sk);
	if (smc->use_fallback) {
		rc = kernel_sendpage(smc->clcsock, page, offset,
				     size, flags);
	} else {
		lock_sock(sk);
		rc = smc_tx_sendpage(smc, page, offset, size, flags);
		release_sock(sk);
		SMC_STAT_INC(smc, sendpage_cnt);
	}

out:
	return rc;
}

/* Map the affected portions of the rmbe into an spd, note the number of bytes
 * to splice in conn->splice_pending, and press 'go'. Delays consumer cursor
 * updates till whenever a respective page has been fully processed.
 * Note that subsequent recv() calls have to wait till all splice() processing
 * completed.
 */
static ssize_t smc_splice_read(struct socket *sock, loff_t *ppos,
			       struct pipe_inode_info *pipe, size_t len,
			       unsigned int flags)
{
	struct sock *sk = sock->sk;
	struct smc_sock *smc;
	int rc = -ENOTCONN;

	smc = smc_sk(sk);
	lock_sock(sk);
	if (smc_sk_state(sk) == SMC_CLOSED && (smc_has_rcv_shutdown(sk))) {
		/* socket was connected before, no more data to read */
		rc = 0;
		goto out;
	}
	if (smc_sk_state(sk) == SMC_INIT ||
	    smc_sk_state(sk) == SMC_LISTEN ||
	    smc_sk_state(sk) == SMC_CLOSED)
		goto out;

	if (smc_sk_state(sk) == SMC_PEERFINCLOSEWAIT) {
		rc = 0;
		goto out;
	}

	if (smc->use_fallback) {
		rc = smc->clcsock->ops->splice_read(smc->clcsock, ppos,
						    pipe, len, flags);
	} else {
		if (*ppos) {
			rc = -ESPIPE;
			goto out;
		}
		if (flags & SPLICE_F_NONBLOCK)
			flags = MSG_DONTWAIT;
		else
			flags = 0;
		SMC_STAT_INC(smc, splice_cnt);
		rc = smc_rx_recvmsg(smc, NULL, pipe, len, flags);
	}
out:
	release_sock(sk);

	return rc;
}

/* must look like tcp */
static const struct proto_ops smc_sock_ops = {
	.family		= PF_SMC,
	.owner		= THIS_MODULE,
	.release	= smc_release,
	.bind		= smc_bind,
	.connect	= smc_connect,
	.socketpair	= sock_no_socketpair,
	.accept		= smc_accept,
	.getname	= smc_getname,
	.poll		= smc_poll,
	.ioctl		= smc_ioctl,
	.listen		= smc_listen,
	.shutdown	= smc_shutdown,
	.setsockopt	= smc_setsockopt,
	.getsockopt	= smc_getsockopt,
	.sendmsg	= smc_sendmsg,
	.recvmsg	= smc_recvmsg,
	.mmap		= sock_no_mmap,
	.sendpage	= smc_sendpage,
	.splice_read	= smc_splice_read,
};

static int smc_create(struct net *net, struct socket *sock, int protocol,
		      int kern)
{
	int family = (protocol == SMCPROTO_SMC6) ? PF_INET6 : PF_INET;
	struct smc_sock *smc;
	struct sock *sk;
	int rc;

	rc = -ESOCKTNOSUPPORT;
	if (sock->type != SOCK_STREAM)
		goto out;

	rc = -EPROTONOSUPPORT;
	if (protocol != SMCPROTO_SMC && protocol != SMCPROTO_SMC6)
		goto out;

	rc = -ENOBUFS;
	sock->ops = &smc_sock_ops;
	sock->state = SS_UNCONNECTED;
	sk = smc_sock_alloc(net, sock, protocol);
	if (!sk)
		goto out;

	/* create internal TCP socket for CLC handshake and fallback */
	smc = smc_sk(sk);
	smc->use_fallback = false; /* assume rdma capability first */
	smc->fallback_rsn = 0;

	rc = sock_create_kern(net, family, SOCK_STREAM, IPPROTO_TCP,
			      &smc->clcsock);
	if (rc) {
		sk_common_release(sk);
		goto out;
	}

out:
	return rc;
}

static const struct net_proto_family smc_sock_family_ops = {
	.family	= PF_SMC,
	.owner	= THIS_MODULE,
	.create	= smc_create,
};

static int smc_net_reserve_ports(struct net *net)
{
	struct smc_ib_device *smcibdev;
	struct ib_device *ibdev;
	int rc = 0;

	if (!reserve_mode)
		return 0;
	atomic_set(&net->smc.iwarp_cnt, 0);
	memset(net->smc.rsvd_sock, 0, sizeof(net->smc.rsvd_sock));

	mutex_lock(&smc_ib_devices.mutex);
	list_for_each_entry(smcibdev, &smc_ib_devices.list, list) {
		ibdev = smcibdev->ibdev;
		if (!smc_ib_is_iwarp(ibdev, 1))
			continue;
		if (!rdma_dev_access_netns(ibdev, net))
			continue;
		if (atomic_inc_return(&net->smc.iwarp_cnt) > 1)
			continue;
		/* first iwarp device */
		rc = smcr_iw_net_reserve_ports(net);
		if (rc) {
			atomic_set(&net->smc.iwarp_cnt, 0);
			break;
		}
	}
	mutex_unlock(&smc_ib_devices.mutex);
	return rc;
}

static void smc_net_release_ports(struct net *net)
{
	if (!reserve_mode)
		return;
	if (atomic_read(&net->smc.iwarp_cnt) &&
	    net->smc.rsvd_sock[0])
		smcr_iw_net_release_ports(net);
}

unsigned int smc_net_id;

static __net_init int smc_net_init(struct net *net)
{
	int rc;

	rc = smc_net_reserve_ports(net);
	if (rc)
		return rc;
	rc = smc_sysctl_net_init(net);
	if (rc)
		goto release_ports;
	rc = smc_pnet_net_init(net);
	if (rc)
		goto release_ports;
	return 0;

release_ports:
	smc_net_release_ports(net);
	return rc;
}

static void __net_exit smc_net_exit(struct net *net)
{
	smc_net_release_ports(net);
	smc_sysctl_net_exit(net);
	smc_pnet_net_exit(net);
}

static __net_init int smc_net_stat_init(struct net *net)
{
	return smc_stats_init(net);
}

static void __net_exit smc_net_stat_exit(struct net *net)
{
	smc_stats_exit(net);
}

static struct pernet_operations smc_net_ops = {
	.init = smc_net_init,
	.exit = smc_net_exit,
	.id   = &smc_net_id,
	.size = sizeof(struct smc_net),
};

static struct pernet_operations smc_net_stat_ops = {
	.init = smc_net_stat_init,
	.exit = smc_net_stat_exit,
};

static int __smc_inet_connect_work_locked(struct smc_sock *smc)
{
	int rc;

	rc = __smc_connect(smc);
	if (rc < 0)
		smc->sk.sk_err = -rc;

	smc_inet_sock_move_state(&smc->sk, SMC_NEGOTIATION_PREPARE_SMC,
				 (smc->use_fallback &&
				 smc_sk_state(&smc->sk) == SMC_ACTIVE) ?
				 SMC_NEGOTIATION_NO_SMC : SMC_NEGOTIATION_SMC);

	if (!smc_sock_flag(&smc->sk, SOCK_DEAD)) {
		if (smc->sk.sk_err)
			smc->sk.sk_state_change(&smc->sk);
		else
			smc->sk.sk_write_space(&smc->sk);
	}

	return rc;
}

static void smc_inet_connect_work(struct work_struct *work)
{
	struct smc_sock *smc = container_of(work, struct smc_sock,
					connect_work);

	sock_hold(&smc->sk);		/* sock put bellow */
	lock_sock(&smc->sk);
	__smc_inet_connect_work_locked(smc);
	release_sock(&smc->sk);
	sock_put(&smc->sk);			/* sock hold above */
}

static void smc_inet_listen_work(struct work_struct *work)
{
	struct smc_sock *smc = container_of(work, struct smc_sock,
					smc_listen_work);
	struct sock *sk = &smc->sk;

	/* Initialize accompanying socket */
	smc_inet_sock_init_accompany_socket(sk);

	/* current smc sock has not bee accept yet. */
	rcu_assign_pointer(sk->sk_wq, &smc_sk(sk)->accompany_socket.wq);
	smc_listen_work(work);

}

/* caller MUST not access sk after smc_inet_sock_do_handshake
 * is invoked unless a sock_hold() has performed beforehand.
 */
static int smc_inet_sock_do_handshake(struct sock *sk, bool sk_locked, bool sync)
{
	struct smc_sock *smc = smc_sk(sk);
	int rc = 0;

	if (smc_inet_sock_is_active_open(sk)) {
		INIT_WORK(&smc->connect_work, smc_inet_connect_work);
		if (!sync) {
			queue_work(smc_hs_wq, &smc->connect_work);
			return 0;
		}
		if (sk_locked)
			return __smc_inet_connect_work_locked(smc);
		lock_sock(sk);
		rc = __smc_inet_connect_work_locked(smc);
		release_sock(sk);
		return rc;
	}

	INIT_WORK(&smc->smc_listen_work, smc_inet_listen_work);
	/* protected listen_smc during smc_inet_listen_work */
	sock_hold(&smc->listen_smc->sk);

	if (!sync) {
		queue_work(smc_hs_wq, &smc->smc_listen_work);
	} else {
		smc_inet_listen_work(&smc->smc_listen_work);
	}
	/* listen work has no retval */
	return 0;
}

void smc_inet_sock_state_change(struct sock *sk)
{
	struct smc_sock *smc = smc_sk(sk);
	int cur;

	if (sk->sk_err || (1 << sk->sk_state) & (TCPF_CLOSE_WAIT | TCPF_ESTABLISHED)) {
		write_lock_bh(&sk->sk_callback_lock);

		/* resume sk_state_change */
		sk->sk_state_change = smc->clcsk_state_change;

		/* cause by abort */
		if (isck_smc_negotiation_get_flags(smc_sk(sk)) & SMC_NEGOTIATION_ABORT_FLAG)
			goto out_unlock;

		if (isck_smc_negotiation_load(smc) != SMC_NEGOTIATION_TBD)
			goto out_unlock;

		cur = smc_inet_sock_move_state_locked(sk, SMC_NEGOTIATION_TBD,
						      (tcp_sk(sk)->syn_smc &&
						      !sk->sk_err) ?
						      SMC_NEGOTIATION_PREPARE_SMC :
						      SMC_NEGOTIATION_NO_SMC);

		if (cur == SMC_NEGOTIATION_PREPARE_SMC) {
			smc_inet_sock_do_handshake(sk, /* not locked */ false, /* async */ false);
		} else if (cur == SMC_NEGOTIATION_NO_SMC) {
			smc->use_fallback = true;
			smc->fallback_rsn = SMC_CLC_DECL_PEERNOSMC;
			smc_stat_fallback(smc);
			trace_smc_switch_to_fallback(smc, SMC_CLC_DECL_PEERNOSMC);
			smc->connect_nonblock = 0;
			smc_sk_set_state(&smc->sk, SMC_ACTIVE);
		}
out_unlock:
		write_unlock_bh(&sk->sk_callback_lock);
	}

	smc->clcsk_state_change(sk);
}

int smc_inet_init_sock(struct sock *sk)
{
	struct smc_sock *smc = smc_sk(sk);
	int rc;

#if IS_ENABLED(CONFIG_IPV6)
	if (sk->sk_family == PF_INET6) {
		memcpy(&((struct tcp6_sock *)sk)->inet6, inet_sk(sk)->pinet6,
		       sizeof(struct ipv6_pinfo));
		inet_sk(sk)->pinet6 = (struct ipv6_pinfo *)(((u8 *)sk) +
			sizeof(struct tcp6_sock) - sizeof(struct ipv6_pinfo));
	}
#endif

	/* Call tcp init sock first */
	rc = smc_inet_get_tcp_prot(sk->sk_family)->init(sk);
	if (rc)
		return rc;

	/* init common smc sock */
	smc_sock_init(sk, sock_net(sk));

	/* IPPROTO_SMC does not exist in network, we MUST
	 * reset it to IPPROTO_TCP before connect.
	 */
	sk->sk_protocol = IPPROTO_TCP;

	/* Initialize smc_sock state */
	smc_sk_set_state(sk, SMC_INIT);

	/* built link */
	smc_inet_sock_init_accompany_socket(sk);

	/* Initialize negotiation state, see more details in
	 * enum smc_inet_sock_negotiation_state.
	 */
	isck_smc_negotiation_store(smc, SMC_NEGOTIATION_TBD);

	return 0;
}

void smc_inet_sock_proto_release_cb(struct sock *sk)
{
	tcp_release_cb(sk);

	/* smc_release_cb only works for socks who identified
	 * as SMC. Note listen sock will also return here.
	 */
	if (!smc_inet_sock_check_smc(sk))
		return;

	smc_release_cb(sk);
}

int smc_inet_connect(struct socket *sock, struct sockaddr *addr,
		     int alen, int flags)
{
	return smc_connect(sock, addr, alen, flags);
}

int smc_inet_setsockopt(struct socket *sock, int level, int optname,
			sockptr_t optval, unsigned int optlen)
{
	struct sock *sk = sock->sk;
	struct smc_sock *smc;
	bool fallback;
	int rc;

	smc = smc_sk(sk);
	fallback = smc_inet_sock_check_fallback(sk);

	if (level == SOL_SMC)
		return __smc_setsockopt(sock, level, optname, optval, optlen);

	/* Note that we always need to check if it's an unsupported
	 * options before set it to the given value via sock_common_setsockopt().
	 * This is because if we set it after we found it is not supported to smc and
	 * we have no idea to fallback, we have to report this error to userspace.
	 * However, the user might find it is set correctly via sock_common_getsockopt().
	 */
	if (!fallback && level == SOL_TCP && smc_is_unsupport_tcp_sockopt(optname)) {
		/* can not fallback, but with not-supported option */
		if (!smc_inet_sock_try_disable_smc(sk, SMC_NEGOTIATION_NOT_SUPPORT_FLAG))
			return -EOPNOTSUPP;
		fallback = true;
		smc_switch_to_fallback(smc_sk(sk), SMC_CLC_DECL_OPTUNSUPP);
	}

	/* call original setsockopt */
	rc = sock_common_setsockopt(sock, level, optname, optval, optlen);
	if (rc)
		return rc;

	/* already be fallback */
	if (fallback)
		return 0;

	/* deliver to smc if needed */
	return smc_setsockopt_takeover(sock, level, optname, optval, optlen);
}

int smc_inet_getsockopt(struct socket *sock, int level, int optname,
			char __user *optval, int __user *optlen)
{
	if (level == SOL_SMC)
		return __smc_getsockopt(sock, level, optname, optval, optlen);

	/* smc_getsockopt is just a wrap on sock_common_getsockopt
	 * So we don't need to reuse it.
	 */
	return sock_common_getsockopt(sock, level, optname, optval, optlen);
}

int smc_inet_ioctl(struct socket *sock, unsigned int cmd,
		   unsigned long arg)
{
	struct sock *sk = sock->sk;
	int rc;

	if (smc_inet_sock_check_fallback(sk))
fallback:
		return smc_call_inet_sock_ops(sk, inet_ioctl, inet6_ioctl, sock, cmd, arg);

	rc = smc_ioctl(sock, cmd, arg);
	if (unlikely(smc_sk(sk)->use_fallback))
		goto fallback;

	return rc;
}

int smc_inet_sendmsg(struct socket *sock, struct msghdr *msg, size_t len)
{
	struct sock *sk = sock->sk;
	struct smc_sock *smc;
	int rc;

	smc = smc_sk(sk);

	/* Send before connected, might be fastopen or user's incorrect usage, but
	 * whatever, in either case, we do not need to replace it with SMC any more.
	 * If it dues to user's incorrect usage, then it is also an error for TCP.
	 * Users should correct that error themselves.
	 */
	if (smc_inet_sock_access_check(sk) == SMC_NEGOTIATION_NO_SMC)
		goto no_smc;

	rc = smc_sendmsg(sock, msg, len);
	if (likely(!smc->use_fallback))
		return rc;

	/* Fallback during smc_sendmsg */
no_smc:
	return smc_call_inet_sock_ops(sk, inet_sendmsg, inet6_sendmsg, sock, msg, len);
}

int smc_inet_recvmsg(struct socket *sock, struct msghdr *msg, size_t len,
		     int flags)
{
	struct sock *sk = sock->sk;
	struct smc_sock *smc;
	int rc;

	smc = smc_sk(sk);

	/* Recv before connection goes established, it's okay for TCP but not
	 * support in SMC（see smc_recvmsg), we should try our best to fallback
	 * if passible.
	 */
	if (smc_inet_sock_access_check(sk) == SMC_NEGOTIATION_NO_SMC)
		goto no_smc;

	rc = smc_recvmsg(sock, msg, len, flags);
	if (likely(!smc->use_fallback))
		return rc;

	/* Fallback during smc_recvmsg */
no_smc:
	return smc_call_inet_sock_ops(sk, inet_recvmsg, inet6_recvmsg, sock, msg, len, flags);
}

ssize_t smc_inet_sendpage(struct socket *sock, struct page *page,
			  int offset, size_t size, int flags)
{
	struct sock *sk = sock->sk;
	struct smc_sock *smc;
	int rc;

	smc = smc_sk(sk);

	/* same reason with smc_recvmsg */
	if (smc_inet_sock_access_check(sk) == SMC_NEGOTIATION_NO_SMC)
		goto no_smc;

	rc = smc_sendpage(sock, page, offset, size, flags);
	if (likely(!smc->use_fallback))
		return rc;

	/* Fallback during smc_sendpage */
no_smc:
	return inet_sendpage(sock, page, offset, size, flags);
}

ssize_t smc_inet_splice_read(struct socket *sock, loff_t *ppos,
			     struct pipe_inode_info *pipe, size_t len,
			     unsigned int flags)
{
	struct sock *sk = sock->sk;
	struct smc_sock *smc;
	int rc;

	smc = smc_sk(sk);

	if (smc_inet_sock_access_check(sk) == SMC_NEGOTIATION_NO_SMC)
		goto no_smc;

	rc = smc_splice_read(sock, ppos, pipe, len, flags);
	if (likely(!smc->use_fallback))
		return rc;

	/* Fallback during smc_splice_read */
no_smc:
	return tcp_splice_read(sock, ppos, pipe, len, flags);
}

static inline __poll_t smc_inet_listen_poll(struct file *file, struct socket *sock,
					    poll_table *wait)
{
	__poll_t mask;

	mask = tcp_poll(file, sock, wait);
	/* no tcp sock */
	if (!(smc_inet_sock_sort_csk_queue(sock->sk) & SMC_REQSK_TCP))
		mask &= ~(EPOLLIN | EPOLLRDNORM);
	mask |= smc_accept_poll(sock->sk);
	return mask;
}

__poll_t smc_inet_poll(struct file *file, struct socket *sock, poll_table *wait)
{
	struct sock *sk = sock->sk;
	__poll_t mask;

	if (smc_inet_sock_check_fallback_fast(sk))
no_smc:
		return tcp_poll(file, sock, wait);

	/* special case */
	if (inet_sk_state_load(sk) == TCP_LISTEN)
		return smc_inet_listen_poll(file, sock, wait);

	mask = smc_poll(file, sock, wait);
	if (smc_sk(sk)->use_fallback)
		goto no_smc;

	return mask;
}

int smc_inet_shutdown(struct socket *sock, int how)
{
	struct sock *sk = sock->sk;
	struct smc_sock *smc;
	int rc;

	smc = smc_sk(sk);

	/* All state changes of sock are handled by inet_shutdown,
	 * smc only needs to be responsible for
	 * executing the corresponding semantics.
	 */
	rc = inet_shutdown(sock, how);
	if (rc)
		return rc;

	/* shutdown during SMC_NEGOTIATION_TBD, we can force it to be
	 * fallback.
	 */
	if (smc_inet_sock_try_disable_smc(sk, SMC_NEGOTIATION_ABORT_FLAG))
		return 0;

	/* executing the corresponding semantics if can not be fallback */
	lock_sock(sk);
	switch (how) {
	case SHUT_RDWR:		/* shutdown in both directions */
		rc = smc_close_active(smc);
		break;
	case SHUT_WR:
		rc = smc_close_shutdown_write(smc);
		break;
	case SHUT_RD:
		rc = 0;
		/* nothing more to do because peer is not involved */
		break;
	}
	release_sock(sk);
	return rc;
}

int smc_inet_release(struct socket *sock)
{
	struct sock *sk = sock->sk;
	struct smc_sock *smc;
	int old_state, rc;
	bool do_free = false;

	if (!sk)
		return 0;

	smc = smc_sk(sk);

	/* trigger info gathering if needed.*/
	smc_sock_perform_collecting_info(smc, SMC_SOCK_CLOSED_TIMING);

	old_state = smc_sk_state(sk);

	sock_hold(sk);	/* sock put bellow */

	smc_inet_sock_try_disable_smc(sk, SMC_NEGOTIATION_ABORT_FLAG);

	/* check fallback ? */
	if (smc_inet_sock_check_fallback(sk)) {
		if (smc_sk_state(sk) == SMC_ACTIVE)
			sock_put(sk);	/* sock put for passive closing */
		smc_sock_set_flag(sk, SOCK_DEAD);
		smc_sk_set_state(sk, SMC_CLOSED);
		goto out;
	}

	if (smc->connect_nonblock && cancel_work_sync(&smc->connect_work))
		sock_put(&smc->sk); /* sock_hold for passive closing */

	if (smc_sk_state(sk) == SMC_LISTEN)
		/* smc_close_non_accepted() is called and acquires
		 * sock lock for child sockets again
		 */
		lock_sock_nested(sk, SINGLE_DEPTH_NESTING);
	else
		lock_sock(sk);

	if (smc->conn.killed && !smc->use_fallback)
		smc_close_active_abort(smc);

	if (!smc->use_fallback) {
		/* ret of smc_close_active do not need return to userspace */
		smc_close_active(smc);
		do_free = true;
	} else {
		if (smc_sk_state(sk) == SMC_ACTIVE)
			sock_put(sk);	 /* sock put for passive closing */
		smc_sk_set_state(sk, SMC_CLOSED);
	}
	smc_sock_set_flag(sk, SOCK_DEAD);

	release_sock(sk);
out:
	/* release tcp sock */
	rc = smc_call_inet_sock_ops(sk, inet_release, inet6_release, sock);

	if (do_free) {
		lock_sock(sk);
		if (smc_sk_state(sk) == SMC_CLOSED)
			smc_conn_free(&smc->conn);
		release_sock(sk);
	}
	sock_put(sk);	/* sock hold above */
	return rc;
}

static inline struct request_sock *smc_inet_reqsk_get_safe_tail_0(struct sock *parent)
{
	struct request_sock_queue *queue = &inet_csk(parent)->icsk_accept_queue;
	struct request_sock *req = queue->rskq_accept_head;

	if (req && smc_sk(req->sk)->ordered && tcp_sk(req->sk)->syn_smc == 0)
		return smc_sk(parent)->tail_0;

	return NULL;
}

static inline struct request_sock *smc_inet_reqsk_get_safe_tail_1(struct sock *parent)
{
	struct request_sock_queue *queue = &inet_csk(parent)->icsk_accept_queue;
	struct request_sock *tail_0 = smc_inet_reqsk_get_safe_tail_0(parent);
	struct request_sock *req;

	if (tail_0)
		req = tail_0->dl_next;
	else
		req = queue->rskq_accept_head;

	if (req && smc_sk(req->sk)->ordered && tcp_sk(req->sk)->syn_smc)
		return smc_sk(parent)->tail_1;

	return NULL;
}

static inline void smc_reqsk_queue_remove_locked(struct request_sock_queue *queue)
{
	struct request_sock *req;

	req = queue->rskq_accept_head;
	if (req) {
		WRITE_ONCE(queue->rskq_accept_head, req->dl_next);
		if (!queue->rskq_accept_head)
			queue->rskq_accept_tail = NULL;
	}
}

static inline void smc_reqsk_queue_add_locked(struct request_sock_queue *queue,
					      struct request_sock *req)
{
	req->dl_next = NULL;
	if (!queue->rskq_accept_head)
		WRITE_ONCE(queue->rskq_accept_head, req);
	else
		queue->rskq_accept_tail->dl_next = req;
	queue->rskq_accept_tail = req;
}

static inline void smc_reqsk_queue_join_locked(struct request_sock_queue *to,
					       struct request_sock_queue *from)
{
	if (reqsk_queue_empty(from))
		return;

	if (reqsk_queue_empty(to)) {
		to->rskq_accept_head = from->rskq_accept_head;
		to->rskq_accept_tail = from->rskq_accept_tail;
	} else {
		to->rskq_accept_tail->dl_next = from->rskq_accept_head;
		to->rskq_accept_tail = from->rskq_accept_tail;
	}

	from->rskq_accept_head = NULL;
	from->rskq_accept_tail = NULL;
}

static inline void smc_reqsk_queue_cut_locked(struct request_sock_queue *queue,
					      struct request_sock *tail,
					      struct request_sock_queue *split)
{
	if (!tail) {
		split->rskq_accept_tail = queue->rskq_accept_tail;
		split->rskq_accept_head = queue->rskq_accept_head;
		queue->rskq_accept_tail = NULL;
		queue->rskq_accept_head = NULL;
		return;
	}

	if (tail == queue->rskq_accept_tail) {
		split->rskq_accept_tail = NULL;
		split->rskq_accept_head = NULL;
		return;
	}

	split->rskq_accept_head = tail->dl_next;
	split->rskq_accept_tail = queue->rskq_accept_tail;
	queue->rskq_accept_tail = tail;
	tail->dl_next = NULL;
}

static inline void __smc_inet_sock_sort_csk_queue(struct sock *parent, int *tcp_cnt, int *smc_cnt)
{
	struct request_sock_queue  queue_smc, queue_free;
	struct smc_sock *par = smc_sk(parent);
	struct request_sock_queue *queue;
	struct request_sock *req;
	int cnt0, cnt1;

	queue = &inet_csk(parent)->icsk_accept_queue;

	spin_lock_bh(&queue->rskq_lock);

	par->tail_0 = smc_inet_reqsk_get_safe_tail_0(parent);
	par->tail_1 = smc_inet_reqsk_get_safe_tail_1(parent);

	cnt0 = par->tail_0 ? smc_sk(par->tail_0->sk)->queued_cnt : 0;
	cnt1 = par->tail_1 ? smc_sk(par->tail_1->sk)->queued_cnt : 0;

	smc_reqsk_queue_cut_locked(queue, par->tail_0, &queue_smc);
	smc_reqsk_queue_cut_locked(&queue_smc, par->tail_1, &queue_free);

	/* scan all queue_free and re-add it */
	while ((req = queue_free.rskq_accept_head)) {
		smc_sk(req->sk)->ordered = 1;
		smc_reqsk_queue_remove_locked(&queue_free);
		/* It's not good at timecast, but better to understand */
		if (tcp_sk(req->sk)->syn_smc) {
			smc_reqsk_queue_add_locked(&queue_smc, req);
			cnt1++;
		} else {
			smc_reqsk_queue_add_locked(queue, req);
			cnt0++;
		}
	}
	/* update tail */
	par->tail_0 = queue->rskq_accept_tail;
	par->tail_1 = queue_smc.rskq_accept_tail;

	/* join queue */
	smc_reqsk_queue_join_locked(queue, &queue_smc);

	if (par->tail_0)
		smc_sk(par->tail_0->sk)->queued_cnt = cnt0;

	if (par->tail_1)
		smc_sk(par->tail_1->sk)->queued_cnt = cnt1;

	*tcp_cnt = cnt0;
	*smc_cnt = cnt1;

	spin_unlock_bh(&queue->rskq_lock);
}

static int smc_inet_sock_sort_csk_queue(struct sock *parent)
{
	int smc_cnt, tcp_cnt;
	int mask = 0;

	__smc_inet_sock_sort_csk_queue(parent, &tcp_cnt, &smc_cnt);
	if (tcp_cnt)
		mask |= SMC_REQSK_TCP;
	if (smc_cnt)
		mask |= SMC_REQSK_SMC;

	return mask;
}

/* Wait for an incoming connection, avoid race conditions. This must be called
 * with the socket locked.
 */
static int smc_inet_csk_wait_for_connect(struct sock *sk, long *timeo)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	DEFINE_WAIT(wait);
	int err;

	lock_sock(sk);

	/* True wake-one mechanism for incoming connections: only
	 * one process gets woken up, not the 'whole herd'.
	 * Since we do not 'race & poll' for established sockets
	 * anymore, the common case will execute the loop only once.
	 *
	 * Subtle issue: "add_wait_queue_exclusive()" will be added
	 * after any current non-exclusive waiters, and we know that
	 * it will always _stay_ after any new non-exclusive waiters
	 * because all non-exclusive waiters are added at the
	 * beginning of the wait-queue. As such, it's ok to "drop"
	 * our exclusiveness temporarily when we get woken up without
	 * having to remove and re-insert us on the wait queue.
	 */
	for (;;) {
		prepare_to_wait_exclusive(sk_sleep(sk), &wait,
					  TASK_INTERRUPTIBLE);
		release_sock(sk);
		if (smc_accept_queue_empty(sk) && reqsk_queue_empty(&icsk->icsk_accept_queue))
			*timeo = schedule_timeout(*timeo);
		sched_annotate_sleep();
		lock_sock(sk);
		err = 0;
		if (!reqsk_queue_empty(&icsk->icsk_accept_queue))
			break;
		if (!smc_accept_queue_empty(sk))
			break;
		err = -EINVAL;
		if (sk->sk_state != TCP_LISTEN)
			break;
		err = sock_intr_errno(*timeo);
		if (signal_pending(current))
			break;
		err = -EAGAIN;
		if (!*timeo)
			break;
	}
	finish_wait(sk_sleep(sk), &wait);
	release_sock(sk);
	return err;
}

struct sock *__smc_inet_csk_accept(struct sock *sk, int flags, int *err, bool kern, int next_state)
{
	struct sock *child;
	int cur;

	child = inet_csk_accept(sk, flags | O_NONBLOCK, err, kern);
	if (child) {
		smc_sk(child)->listen_smc = smc_sk(sk);

		/* depends on syn_smc if next_state not specify */
		if (next_state == SMC_NEGOTIATION_TBD)
			next_state = tcp_sk(child)->syn_smc ? SMC_NEGOTIATION_PREPARE_SMC :
				SMC_NEGOTIATION_NO_SMC;

		cur = smc_inet_sock_move_state(child, SMC_NEGOTIATION_TBD,
					       next_state);
		switch (cur) {
		case SMC_NEGOTIATION_NO_SMC:
			smc_sk_set_state(child, SMC_ACTIVE);
			if (!smc_sk(child)->use_fallback)
				smc_switch_to_fallback(smc_sk(child), SMC_CLC_DECL_PEERNOSMC);
			smc_sock_clone_negotiator_ops(sk, child);
			break;
		case SMC_NEGOTIATION_PREPARE_SMC:
			/* init as passive open smc sock */
			smc_sock_init_passive(sk, child);
			break;
		default:
			break;
		}
	}
	return child;
}

struct sock *smc_inet_csk_accept(struct sock *sk, int flags, int *err, bool kern)
{
	struct sock *child;
	long timeo;

	timeo = sock_rcvtimeo(sk, flags & O_NONBLOCK);

again:
	/* has smc sock */
	if (!smc_accept_queue_empty(sk)) {
		child = __smc_accept(sk, NULL, flags | O_NONBLOCK, err, kern);
		if (child)
			return child;
	}

	child = __smc_inet_csk_accept(sk, flags | O_NONBLOCK, err, kern, SMC_NEGOTIATION_TBD);
	if (child) {
		/* not smc sock */
		if (smc_inet_sock_check_fallback_fast(child))
			return child;
		/* smc sock */
		smc_inet_sock_do_handshake(child, /* sk not locked */ false, /* sync */ false);
		*err = -EAGAIN;
		child = NULL;
	}

	if (*err == -EAGAIN && timeo) {
		*err = smc_inet_csk_wait_for_connect(sk, &timeo);
		if (*err == 0)
			goto again;
	}

	return NULL;
}

static void smc_inet_tcp_listen_work(struct work_struct *work)
{
	struct smc_sock *lsmc = container_of(work, struct smc_sock,
					     tcp_listen_work);
	struct sock *lsk = &lsmc->sk;
	struct sock *child;
	int error = 0;

	while (smc_sk_state(lsk) == SMC_LISTEN &&
	       (smc_inet_sock_sort_csk_queue(lsk) & SMC_REQSK_SMC)) {
		child = __smc_inet_csk_accept(lsk, O_NONBLOCK, &error, 1,
					      SMC_NEGOTIATION_PREPARE_SMC);
		if (!child || error)
			break;

		/* run handshake for child
		 * If child is a fallback connection, run a sync handshake to eliminate
		 * the impact of queue_work().
		 */
		smc_inet_sock_do_handshake(child, /* sk not locked */ false,
					   !tcp_sk(child)->syn_smc);
	}
}

static void smc_inet_sock_data_ready(struct sock *sk)
{
	struct smc_sock *smc = smc_sk(sk);
	int mask;

	if (inet_sk_state_load(sk) == TCP_LISTEN) {
		mask = smc_inet_sock_sort_csk_queue(sk);
		if (mask & SMC_REQSK_TCP || !smc_accept_queue_empty(sk))
			smc->clcsk_data_ready(sk);
		if (mask & SMC_REQSK_SMC)
			queue_work(smc_tcp_ls_wq, &smc->tcp_listen_work);
	} else {
		write_lock_bh(&sk->sk_callback_lock);
		sk->sk_data_ready = smc->clcsk_data_ready;
		write_unlock_bh(&sk->sk_callback_lock);
		smc->clcsk_data_ready(sk);
	}
}

int smc_inet_listen(struct socket *sock, int backlog)
{
	struct sock *sk = sock->sk;
	bool need_init = false;
	struct smc_sock *smc;

	smc = smc_sk(sk);

	write_lock_bh(&sk->sk_callback_lock);
	/* still wish to accept smc sock */
	if (isck_smc_negotiation_load(smc) == SMC_NEGOTIATION_TBD) {
		need_init = tcp_sk(sk)->syn_smc = 1;
		isck_smc_negotiation_set_flags(smc, SMC_NEGOTIATION_LISTEN_FLAG);
	}
	write_unlock_bh(&sk->sk_callback_lock);

	if (need_init) {
		lock_sock(sk);
		if (smc_sk_state(sk) == SMC_INIT)  {
			smc_init_listen(smc);
			INIT_WORK(&smc->tcp_listen_work, smc_inet_tcp_listen_work);
			smc_clcsock_replace_cb(&sk->sk_data_ready, smc_inet_sock_data_ready,
					       &smc->clcsk_data_ready);
			smc_sk_set_state(sk, SMC_LISTEN);
		}
		release_sock(sk);
	}
	return inet_listen(sock, backlog);
}

static int __init smc_init(void)
{
	int rc;

	if (reserve_mode) {
		pr_info_ratelimited("smc: load SMC module with reserve_mode\n");
		if (rsvd_ports_base >
		    (U16_MAX - SMC_IWARP_RSVD_PORTS_NUM)) {
			pr_info_ratelimited("smc: reserve_mode with invalid "
					    "ports base\n");
			return -EINVAL;
		}
	}

	rc = register_pernet_subsys(&smc_net_ops);
	if (rc)
		return rc;

	rc = register_pernet_subsys(&smc_net_stat_ops);
	if (rc)
		goto out_pernet_subsys;

	rc = smc_ism_init();
	if (rc)
		goto out_pernet_subsys_stat;
	smc_clc_init();

	rc = smc_nl_init();
	if (rc)
		goto out_ism;

	rc = smc_pnet_init();
	if (rc)
		goto out_nl;

	rc = -ENOMEM;

	smc_tcp_ls_wq = alloc_workqueue("smc_tcp_ls_wq", 0, 0);
	if (!smc_tcp_ls_wq)
		goto out_pnet;

	smc_hs_wq = alloc_workqueue("smc_hs_wq", 0, 0);
	if (!smc_hs_wq)
		goto out_alloc_tcp_ls_wq;

	smc_close_wq = alloc_workqueue("smc_close_wq", 0, 0);
	if (!smc_close_wq)
		goto out_alloc_hs_wq;

	rc = smc_core_init();
	if (rc) {
		pr_err("%s: smc_core_init fails with %d\n", __func__, rc);
		goto out_alloc_wqs;
	}

	rc = smc_llc_init();
	if (rc) {
		pr_err("%s: smc_llc_init fails with %d\n", __func__, rc);
		goto out_core;
	}

	rc = smc_cdc_init();
	if (rc) {
		pr_err("%s: smc_cdc_init fails with %d\n", __func__, rc);
		goto out_core;
	}

	rc = proto_register(&smc_proto, 1);
	if (rc) {
		pr_err("%s: proto_register(v4) fails with %d\n", __func__, rc);
		goto out_core;
	}

	rc = proto_register(&smc_proto6, 1);
	if (rc) {
		pr_err("%s: proto_register(v6) fails with %d\n", __func__, rc);
		goto out_proto;
	}

	rc = sock_register(&smc_sock_family_ops);
	if (rc) {
		pr_err("%s: sock_register fails with %d\n", __func__, rc);
		goto out_proto6;
	}
	INIT_HLIST_HEAD(&smc_v4_hashinfo.ht);
	INIT_HLIST_HEAD(&smc_v6_hashinfo.ht);

	rc = smc_ib_register_client();
	if (rc) {
		pr_err("%s: ib_register fails with %d\n", __func__, rc);
		goto out_sock;
	}

	rc = smc_loopback_init();
	if (rc) {
		pr_err("%s: smc_loopback_init fails with %d\n", __func__, rc);
		goto out_ib;
	}

	/* init smc inet sock related proto and proto_ops */
	rc = smc_inet_sock_init();
	if (!rc) {
		/* registe smc inet proto */
		rc = proto_register(&smc_inet_prot, 1);
		if (rc) {
			pr_err("%s: proto_register smc_inet_prot fails with %d\n", __func__, rc);
			goto out_lo;
		}
		/* no return value */
		inet_register_protosw(&smc_inet_protosw);
#if IS_ENABLED(CONFIG_IPV6)
		/* register smc inet6 proto */
		rc = proto_register(&smc_inet6_prot, 1);
		if (rc) {
			pr_err("%s: proto_register smc_inet6_prot fails with %d\n", __func__, rc);
			goto out_proto_register;
		}
		/* no return value */
		inet6_register_protosw(&smc_inet6_protosw);
#endif
	}

	static_branch_enable(&tcp_have_smc);
	return 0;
out_proto_register:
	inet_unregister_protosw(&smc_inet_protosw);
	proto_unregister(&smc_inet_prot);
out_lo:
	smc_loopback_exit();
out_ib:
	smc_ib_unregister_client();
out_sock:
	sock_unregister(PF_SMC);
out_proto6:
	proto_unregister(&smc_proto6);
out_proto:
	proto_unregister(&smc_proto);
out_core:
	smc_core_exit();
out_alloc_wqs:
	destroy_workqueue(smc_close_wq);
out_alloc_hs_wq:
	destroy_workqueue(smc_hs_wq);
out_alloc_tcp_ls_wq:
	destroy_workqueue(smc_tcp_ls_wq);
out_pnet:
	smc_pnet_exit();
out_nl:
	smc_nl_exit();
out_ism:
	smc_clc_exit();
	smc_ism_exit();
out_pernet_subsys_stat:
	unregister_pernet_subsys(&smc_net_stat_ops);
out_pernet_subsys:
	unregister_pernet_subsys(&smc_net_ops);

	return rc;
}

static void __exit smc_exit(void)
{
	static_branch_disable(&tcp_have_smc);
	inet_unregister_protosw(&smc_inet_protosw);
#if IS_ENABLED(CONFIG_IPV6)
	inet6_unregister_protosw(&smc_inet6_protosw);
#endif
	sock_unregister(PF_SMC);
	smc_core_exit();
	smc_loopback_exit();
	smc_ib_unregister_client();
	smc_ism_exit();
	destroy_workqueue(smc_close_wq);
	destroy_workqueue(smc_tcp_ls_wq);
	destroy_workqueue(smc_hs_wq);
	proto_unregister(&smc_proto6);
	proto_unregister(&smc_proto);
	proto_unregister(&smc_inet_prot);
#if IS_ENABLED(CONFIG_IPV6)
	proto_unregister(&smc_inet6_prot);
#endif
	smc_pnet_exit();
	smc_nl_exit();
	smc_clc_exit();
	unregister_pernet_subsys(&smc_net_stat_ops);
	unregister_pernet_subsys(&smc_net_ops);
	rcu_barrier();
}

module_init(smc_init);
module_exit(smc_exit);

MODULE_AUTHOR("Ursula Braun <ubraun@linux.vnet.ibm.com>");
MODULE_DESCRIPTION("smc socket address family");
MODULE_LICENSE("GPL");
MODULE_ALIAS_NETPROTO(PF_SMC);
/* It seems that this macro has different
 * understanding of enum type(IPPROTO_SMC or SOCK_STREAM)
 */
MODULE_ALIAS_NET_PF_PROTO_TYPE(PF_INET, 263, 1);
MODULE_ALIAS_NET_PF_PROTO_TYPE(PF_INET6, 263, 1);
MODULE_ALIAS_GENL_FAMILY(SMC_GENL_FAMILY_NAME);
