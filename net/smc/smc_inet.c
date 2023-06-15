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
 */

#include <net/sock.h>
#include <net/inet_common.h>

#include "smc_inet.h"

static struct timewait_sock_ops smc_timewait_sock_ops = {
	.twsk_obj_size		= sizeof(struct tcp_timewait_sock),
	.twsk_unique		= tcp_twsk_unique,
	.twsk_destructor	= tcp_twsk_destructor,
};

struct proto smc_inet_prot = {
	.name			= "SMC",
	.owner			= THIS_MODULE,
	.close			= tcp_close,
	.pre_connect	= NULL,
	.connect		= tcp_v4_connect,
	.disconnect		= tcp_disconnect,
	.accept			= smc_inet_csk_accept,
	.ioctl			= tcp_ioctl,
	.init			= smc_inet_init_sock,
	.destroy		= tcp_v4_destroy_sock,
	.shutdown		= tcp_shutdown,
	.setsockopt		= tcp_setsockopt,
	.getsockopt		= tcp_getsockopt,
	.keepalive		= tcp_set_keepalive,
	.recvmsg		= tcp_recvmsg,
	.sendmsg		= tcp_sendmsg,
	.sendpage		= tcp_sendpage,
	.backlog_rcv	= tcp_v4_do_rcv,
	.release_cb		= smc_inet_sock_proto_release_cb,
	.hash			= inet_hash,
	.unhash			= inet_unhash,
	.get_port		= inet_csk_get_port,
	.enter_memory_pressure	= tcp_enter_memory_pressure,
	.leave_memory_pressure	= tcp_leave_memory_pressure,
	.stream_memory_free	= tcp_stream_memory_free,
	.sockets_allocated	= &tcp_sockets_allocated,
	.orphan_count		= &tcp_orphan_count,
	.memory_allocated	= &tcp_memory_allocated,
	.memory_pressure	= &tcp_memory_pressure,
	.sysctl_mem		= sysctl_tcp_mem,
	.sysctl_wmem_offset	= offsetof(struct net, ipv4.sysctl_tcp_wmem),
	.sysctl_rmem_offset	= offsetof(struct net, ipv4.sysctl_tcp_rmem),
	.max_header		= MAX_TCP_HEADER,
	.obj_size		= sizeof(struct smc_sock),
	.slab_flags		= SLAB_TYPESAFE_BY_RCU,
	.twsk_prot		= &smc_timewait_sock_ops,
	/* tcp_conn_request will use tcp_request_sock_ops */
	.rsk_prot		= NULL,
	.h.hashinfo		= &tcp_hashinfo,
	.no_autobind		= true,
	.diag_destroy		= tcp_abort,
};

const struct proto_ops smc_inet_stream_ops = {
	.family		   = PF_INET,
	.flags		   = PROTO_CMSG_DATA_ONLY,
	.owner		   = THIS_MODULE,
	.release	   = smc_inet_release,
	.bind		   = inet_bind,
	.connect	   = smc_inet_connect,
	.socketpair	   = sock_no_socketpair,
	.accept		   = inet_accept,
	.getname	   = inet_getname,
	.poll		   = smc_inet_poll,
	.ioctl		   = smc_inet_ioctl,
	.gettstamp	   = sock_gettstamp,
	.listen		   = smc_inet_listen,
	.shutdown	   = smc_inet_shutdown,
	.setsockopt	   = smc_inet_setsockopt,
	.getsockopt	   = smc_inet_getsockopt,
	.sendmsg	   = smc_inet_sendmsg,
	.recvmsg	   = smc_inet_recvmsg,
#ifdef CONFIG_MMU
	.mmap		   = tcp_mmap,
#endif
	.sendpage	   = smc_inet_sendpage,
	.splice_read	   = smc_inet_splice_read,
	.read_sock	   = tcp_read_sock,
	.sendmsg_locked    = tcp_sendmsg_locked,
	.sendpage_locked   = tcp_sendpage_locked,
	.peek_len	   = tcp_peek_len,
#ifdef CONFIG_COMPAT
	.compat_ioctl	   = inet_compat_ioctl,
#endif
	.set_rcvlowat	   = tcp_set_rcvlowat,
};

struct inet_protosw smc_inet_protosw = {
	.type       = SOCK_STREAM,
	.protocol   = IPPROTO_SMC,
	.prot   = &smc_inet_prot,
	.ops    = &smc_inet_stream_ops,
	.flags  = INET_PROTOSW_ICSK,
};

#if IS_ENABLED(CONFIG_IPV6)
struct proto smc_inet6_prot = {
	.name			= "SMCv6",
	.owner			= THIS_MODULE,
	.close			= tcp_close,
	.pre_connect	= NULL,
	.connect		= NULL,
	.disconnect		= tcp_disconnect,
	.accept			= smc_inet_csk_accept,
	.ioctl			= tcp_ioctl,
	.init			= smc_inet_init_sock,
	.destroy		= NULL,
	.shutdown		= tcp_shutdown,
	.setsockopt		= tcp_setsockopt,
	.getsockopt		= tcp_getsockopt,
	.keepalive		= tcp_set_keepalive,
	.recvmsg		= tcp_recvmsg,
	.sendmsg		= tcp_sendmsg,
	.sendpage		= tcp_sendpage,
	.backlog_rcv		= NULL,
	.release_cb		= smc_inet_sock_proto_release_cb,
	.hash			= NULL,
	.unhash			= inet_unhash,
	.get_port		= inet_csk_get_port,
	.enter_memory_pressure	= tcp_enter_memory_pressure,
	.leave_memory_pressure	= tcp_leave_memory_pressure,
	.stream_memory_free	= tcp_stream_memory_free,
	.sockets_allocated	= &tcp_sockets_allocated,
	.memory_allocated	= &tcp_memory_allocated,
	.memory_pressure	= &tcp_memory_pressure,
	.orphan_count		= &tcp_orphan_count,
	.sysctl_mem		= sysctl_tcp_mem,
	.sysctl_wmem_offset	= offsetof(struct net, ipv4.sysctl_tcp_wmem),
	.sysctl_rmem_offset	= offsetof(struct net, ipv4.sysctl_tcp_rmem),
	.max_header		= MAX_TCP_HEADER,
	.obj_size		= sizeof(struct smc_sock),
	.slab_flags		= SLAB_TYPESAFE_BY_RCU,
	.twsk_prot		= &smc_timewait_sock_ops,
	/* tcp_conn_request will use tcp_request_sock_ops */
	.rsk_prot		= NULL,
	.h.hashinfo		= &tcp_hashinfo,
	.no_autobind		= true,
	.diag_destroy		= tcp_abort,
};

const struct proto_ops smc_inet6_stream_ops = {
	.family		   = PF_INET6,
	.flags		   = PROTO_CMSG_DATA_ONLY,
	.owner		   = THIS_MODULE,
	.release	   = smc_inet_release,
	.bind		   = inet6_bind,
	.connect	   = smc_inet_connect,	/* ok		*/
	.socketpair	   = sock_no_socketpair,	/* a do nothing	*/
	.accept		   = inet_accept,		/* ok		*/
	.getname	   = inet6_getname,
	.poll		   = smc_inet_poll,			/* ok		*/
	.ioctl		   = smc_inet_ioctl,		/* must change  */
	.gettstamp	   = sock_gettstamp,
	.listen		   = smc_inet_listen,		/* ok		*/
	.shutdown	   = smc_inet_shutdown,		/* ok		*/
	.setsockopt	   = smc_inet_setsockopt,	/* ok		*/
	.getsockopt	   = smc_inet_getsockopt,	/* ok		*/
	.sendmsg	   = smc_inet_sendmsg,		/* retpoline's sake */
	.recvmsg	   = smc_inet_recvmsg,		/* retpoline's sake */
#ifdef CONFIG_MMU
	.mmap		   = tcp_mmap,
#endif
	.sendpage	   = smc_inet_sendpage,
	.sendmsg_locked    = tcp_sendmsg_locked,
	.sendpage_locked   = tcp_sendpage_locked,
	.splice_read	   = smc_inet_splice_read,
	.read_sock	   = tcp_read_sock,
	.peek_len	   = tcp_peek_len,
#ifdef CONFIG_COMPAT
	.compat_ioctl	   = inet6_compat_ioctl,
#endif
	.set_rcvlowat	   = tcp_set_rcvlowat,
};

struct inet_protosw smc_inet6_protosw = {
	.type       = SOCK_STREAM,
	.protocol   = IPPROTO_SMC,
	.prot   = &smc_inet6_prot,
	.ops    = &smc_inet6_stream_ops,
	.flags  = INET_PROTOSW_ICSK,
};
#endif

int smc_inet_sock_switch_negotiation_state_locked(struct sock *sk, int except, int target)
{
	struct smc_sock *smc = smc_sk(sk);
	int cur;

	cur = isck_smc_negotiation_load(smc);
	if (cur != except)
		return cur;

	switch (cur) {
	case SMC_NEGOTIATION_TBD:
		switch (target) {
		case SMC_NEGOTIATION_PREPARE_SMC:
			/* same as passive closing */
			sock_hold(sk);
			fallthrough;
		case SMC_NEGOTIATION_NO_SMC:
			isck_smc_negotiation_store(smc, target);
			return target;
		default:
			break;
		}
		break;
	case SMC_NEGOTIATION_PREPARE_SMC:
		switch (target) {
		case SMC_NEGOTIATION_NO_SMC:
			sock_put(sk);	/* sock hold in SMC_NEGOTIATION_PREPARE_SMC */
			fallthrough;
		case SMC_NEGOTIATION_SMC:
			isck_smc_negotiation_store(smc, target);
			return target;
		default:
			break;
		}
		break;
	default:
		break;
	}

	return cur;
}

int smc_inet_sock_init(void)
{
	struct proto *tcp_v4prot;
#if IS_ENABLED(CONFIG_IPV6)
	struct proto *tcp_v6prot;
#endif

	tcp_v4prot = smc_inet_get_tcp_prot(PF_INET);
	if (unlikely(!tcp_v4prot))
		return -EINVAL;

#if IS_ENABLED(CONFIG_IPV6)
	tcp_v6prot = smc_inet_get_tcp_prot(PF_INET6);
	if (unlikely(!tcp_v6prot))
		return -EINVAL;
#endif

	/* INET sock has a issues here. twsk will hold the reference of the this module,
	 * so it may be found that the SMC module cannot be uninstalled after the test program ends,
	 * But eventually, twsk will release the reference of the module.
	 * This may affect some old test cases if they try to remove the module immediately after
	 * completing their test.
	 */

	/* Complete the full prot and proto_ops to
	 * ensure consistency with TCP. Some symbols here have not been exported,
	 * so that we have to assign it here.
	 */
	smc_inet_prot.pre_connect = tcp_v4prot->pre_connect;

#if IS_ENABLED(CONFIG_IPV6)
	smc_inet6_prot.pre_connect = tcp_v6prot->pre_connect;
	smc_inet6_prot.connect = tcp_v6prot->connect;
	smc_inet6_prot.init = tcp_v6prot->init;
	smc_inet6_prot.destroy = tcp_v6prot->destroy;
	smc_inet6_prot.backlog_rcv = tcp_v6prot->backlog_rcv;
	smc_inet6_prot.hash = tcp_v6prot->hash;
#endif
	return 0;
}

int smc_inet_init_sock(struct sock *sk) { return  0; }

void smc_inet_sock_proto_release_cb(struct sock *sk) {}

int smc_inet_connect(struct socket *sock, struct sockaddr *addr,
		     int alen, int flags)
{
	return -EOPNOTSUPP;
}

int smc_inet_setsockopt(struct socket *sock, int level, int optname,
			sockptr_t optval, unsigned int optlen)
{
	return -EOPNOTSUPP;
}

int smc_inet_getsockopt(struct socket *sock, int level, int optname,
			char __user *optval, int __user *optlen)
{
	return -EOPNOTSUPP;
}

int smc_inet_ioctl(struct socket *sock, unsigned int cmd,
		   unsigned long arg)
{
	return -EOPNOTSUPP;
}

int smc_inet_sendmsg(struct socket *sock, struct msghdr *msg, size_t len)
{
	return -EOPNOTSUPP;
}

int smc_inet_recvmsg(struct socket *sock, struct msghdr *msg, size_t len,
		     int flags)
{
	return -EOPNOTSUPP;
}

ssize_t smc_inet_sendpage(struct socket *sock, struct page *page,
			  int offset, size_t size, int flags)
{
	return -EOPNOTSUPP;
}

ssize_t smc_inet_splice_read(struct socket *sock, loff_t *ppos,
			     struct pipe_inode_info *pipe, size_t len,
			     unsigned int flags)
{
	return -EOPNOTSUPP;
}

__poll_t smc_inet_poll(struct file *file, struct socket *sock, poll_table *wait)
{
	return 0;
}

struct sock *smc_inet_csk_accept(struct sock *sk, int flags, int *err, bool kern)
{
	return NULL;
}

int smc_inet_listen(struct socket *sock, int backlog)
{
	return -EOPNOTSUPP;
}

int smc_inet_shutdown(struct socket *sock, int how)
{
	return -EOPNOTSUPP;
}

int smc_inet_release(struct socket *sock)
{
	return -EOPNOTSUPP;
}

static int smc_inet_clcsock_sendmsg(struct socket *sock, struct msghdr *msg, size_t len)
{
	struct sock *sk = sock->sk;
	struct smc_sock *smc;

	smc = smc_sk(sock->sk);

	if (current_work() == &smc->smc_listen_work)
		return tcp_sendmsg(sk, msg, len);

	/* smc_inet_clcsock_sendmsg only works for smc handshaking
	 * fallback sendmsg should process by smc_inet_sendmsg.
	 * see more details in smc_inet_sendmsg().
	 */
	if (smc->use_fallback)
		return -EOPNOTSUPP;

	/* It is difficult for us to determine whether the current sk is locked.
	 * Therefore, we rely on the implementation of conenct_work() implementation, which
	 * is locked always.
	 */
	return tcp_sendmsg_locked(sk, msg, len);
}

static int smc_inet_clcsock_recvmsg(struct socket *sock, struct msghdr *msg, size_t len,
				    int flags)
{
	struct sock *sk = sock->sk;
	struct smc_sock *smc;
	int addr_len, err;
	long timeo;

	smc = smc_sk(sock->sk);

	/* smc_inet_clcsock_recvmsg only works for smc handshaking
	 * fallback recvmsg should process by smc_inet_recvmsg.
	 */
	if (smc->use_fallback)
		return -EOPNOTSUPP;

	if (likely(!(flags & MSG_ERRQUEUE)))
		sock_rps_record_flow(sk);

	timeo = sock_rcvtimeo(sk, flags & MSG_DONTWAIT);

	if (current_work() == &smc->smc_listen_work) {
		err = tcp_recvmsg(sk, msg, len, flags & MSG_DONTWAIT,
				  flags & ~MSG_DONTWAIT, &addr_len);
	} else {
		/* Locked, see more details in smc_inet_clcsock_sendmsg() */
		release_sock(sock->sk);
		err = tcp_recvmsg(sk, msg, len, flags & MSG_DONTWAIT,
				  flags & ~MSG_DONTWAIT, &addr_len);
		lock_sock(sock->sk);
		/* since we release sock before, there might be state changed */
		if (smc_sk_state(&smc->sk) != SMC_INIT)
			err = -EPIPE;
	}

	if (err >= 0)
		msg->msg_namelen = addr_len;

	return err;
}

static ssize_t smc_inet_clcsock_sendpage(struct socket *sock, struct page *page, int offset,
					 size_t size, int flags)
{
	/* fallback sendpage should process by smc_inet_sendpage.  */
	return -EOPNOTSUPP;
}

static ssize_t smc_inet_clcsock_splice_read(struct socket *sock, loff_t *ppos,
					    struct pipe_inode_info *pipe, size_t len,
					    unsigned int flags)
{
	/* fallback splice_read should process by smc_inet_splice_read.  */
	return -EOPNOTSUPP;
}

static int smc_inet_clcsock_connect(struct socket *sock, struct sockaddr *addr,
				    int alen, int flags)
{
	/* smc_connect will lock the sock->sk */
	return __inet_stream_connect(sock, addr, alen, flags, 0);
}

static int smc_inet_clcsock_shutdown(struct socket *sock, int how)
{
	/* shutdown could call from smc_close_active, we should
	 * not fail it.
	 */
	return 0;
}

static int smc_inet_clcsock_release(struct socket *sock)
{
	/* shutdown could call from smc_close_active, we should
	 * not fail it.
	 */
	return 0;
}

static int smc_inet_clcsock_getname(struct socket *sock, struct sockaddr *addr,
				    int peer)
{
	return sock->sk->sk_family == PF_INET ? inet_getname(sock, addr, peer) :
#if IS_ENABLED(CONFIG_IPV6)
		inet6_getname(sock, addr, peer);
#else
		-EINVAL;
#endif
}

static __poll_t smc_inet_clcsock_poll(struct file *file, struct socket *sock,
				      poll_table *wait)
{
	return 0;
}

const struct proto_ops smc_inet_clcsock_ops = {
	.family			= PF_UNSPEC,
	.flags			= PROTO_CMSG_DATA_ONLY,
	/* It is not a real ops, its lifecycle is bound to the SMC module. */
	.owner			= NULL,
	.release		= smc_inet_clcsock_release,
	.getname		= smc_inet_clcsock_getname,
	.connect		= smc_inet_clcsock_connect,
	.shutdown		= smc_inet_clcsock_shutdown,
	.sendmsg		= smc_inet_clcsock_sendmsg,
	.recvmsg		= smc_inet_clcsock_recvmsg,
	.sendpage		= smc_inet_clcsock_sendpage,
	.splice_read	= smc_inet_clcsock_splice_read,
	.poll			= smc_inet_clcsock_poll,
};
