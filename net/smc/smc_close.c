// SPDX-License-Identifier: GPL-2.0
/*
 *  Shared Memory Communications over RDMA (SMC-R) and RoCE
 *
 *  Socket Closing - normal and abnormal
 *
 *  Copyright IBM Corp. 2016
 *
 *  Author(s):  Ursula Braun <ubraun@linux.vnet.ibm.com>
 */

#include <linux/workqueue.h>
#include <linux/sched/signal.h>

#include <net/sock.h>
#include <net/tcp.h>

#include "smc.h"
#include "smc_tx.h"
#include "smc_wr.h"
#include "smc_cdc.h"
#include "smc_close.h"
#include "smc_inet.h"

/* release the clcsock that is assigned to the smc_sock */
void smc_clcsock_release(struct smc_sock *smc)
{
	struct socket *tcp;

	if (smc_sock_is_inet_sock(&smc->sk))
		return;

	if (smc->listen_smc && current_work() != &smc->smc_listen_work)
		cancel_work_sync(&smc->smc_listen_work);
	mutex_lock(&smc->clcsock_release_lock);
	if (smc->clcsock) {
		tcp = smc->clcsock;
		smc->clcsock = NULL;
		sock_release(tcp);
	}
	mutex_unlock(&smc->clcsock_release_lock);
}

static void smc_close_cleanup_listen(struct sock *parent)
{
	struct sock *sk;

	/* Close non-accepted connections */
	while ((sk = smc_accept_dequeue(parent, NULL)))
		smc_close_non_accepted(sk);
}

/* wait for sndbuf data being transmitted */
static void smc_close_stream_wait(struct smc_sock *smc, long timeout)
{
	DEFINE_WAIT_FUNC(wait, woken_wake_function);
	struct sock *sk = &smc->sk;

	if (!timeout)
		return;

	if (!smc_tx_prepared_sends(&smc->conn))
		return;

	/* Send out corked data remaining in sndbuf */
	smc_tx_pending(&smc->conn);

	smc->wait_close_tx_prepared = 1;
	add_wait_queue(sk_sleep(sk), &wait);
	while (!signal_pending(current) && timeout) {
		int rc;

		rc = sk_wait_event(sk, &timeout,
				   !smc_tx_prepared_sends(&smc->conn) ||
				   READ_ONCE(sk->sk_err) == ECONNABORTED ||
				   READ_ONCE(sk->sk_err) == ECONNRESET ||
				   smc->conn.killed,
				   &wait);
		if (rc)
			break;
	}
	remove_wait_queue(sk_sleep(sk), &wait);
	smc->wait_close_tx_prepared = 0;
}

void smc_close_wake_tx_prepared(struct smc_sock *smc)
{
	if (smc->wait_close_tx_prepared)
		/* wake up socket closing */
		smc->sk.sk_state_change(&smc->sk);
}

static int smc_close_wr(struct smc_connection *conn)
{
	conn->local_tx_ctrl.conn_state_flags.peer_done_writing = 1;

	if (conn->lgr->use_rwwi)
		return smc_tx_rdma_write_with_no_data_rwwi(conn);
	else
		return smc_cdc_get_slot_and_msg_send(conn);
}

static int smc_close_final(struct smc_connection *conn)
{
	if (atomic_read(&conn->bytes_to_rcv))
		conn->local_tx_ctrl.conn_state_flags.peer_conn_abort = 1;
	else
		conn->local_tx_ctrl.conn_state_flags.peer_conn_closed = 1;
	if (conn->killed)
		return -EPIPE;

	if (conn->lgr->use_rwwi)
		return smc_tx_rdma_write_with_no_data_rwwi(conn);
	else
		return smc_cdc_get_slot_and_msg_send(conn);
}

int smc_close_abort(struct smc_connection *conn)
{
	conn->local_tx_ctrl.conn_state_flags.peer_conn_abort = 1;

	if (conn->lgr->use_rwwi)
		return smc_tx_rdma_write_with_no_data_rwwi(conn);
	else
		return smc_cdc_get_slot_and_msg_send(conn);
}

static void smc_close_cancel_work(struct smc_sock *smc)
{
	struct sock *sk = &smc->sk;

	release_sock(sk);
	cancel_work_sync(&smc->conn.close_work);
	cancel_delayed_work_sync(&smc->conn.tx_work);
	lock_sock(sk);
}

/* terminate smc socket abnormally - active abort
 * link group is terminated, i.e. RDMA communication no longer possible
 */
void smc_close_active_abort(struct smc_sock *smc)
{
	struct sock *sk = &smc->sk;
	bool release_clcsock = false;

	if (smc_sk_state(sk) != SMC_INIT) {
		/* sock locked */
		if (smc_sock_is_inet_sock(sk)) {
			sk->sk_err = ECONNABORTED;
			/* This barrier is coupled with smp_rmb() in tcp_poll() */
			smp_wmb();
			sk->sk_error_report(sk);
		} else if (smc->clcsock && smc->clcsock->sk) {
			sk->sk_err = ECONNABORTED;
			tcp_abort(smc->clcsock->sk, ECONNABORTED);
		}
	}

	switch (smc_sk_state(sk)) {
	case SMC_ACTIVE:
	case SMC_APPCLOSEWAIT1:
	case SMC_APPCLOSEWAIT2:
		smc_sk_set_state(sk, SMC_PEERABORTWAIT);
		smc_close_cancel_work(smc);
		if (smc_sk_state(sk) != SMC_PEERABORTWAIT)
			break;
		smc_sk_set_state(sk, SMC_CLOSED);
		sock_put(sk); /* (postponed) passive closing */
		break;
	case SMC_PEERCLOSEWAIT1:
	case SMC_PEERCLOSEWAIT2:
	case SMC_PEERFINCLOSEWAIT:
		smc_sk_set_state(sk, SMC_PEERABORTWAIT);
		smc_close_cancel_work(smc);
		if (smc_sk_state(sk) != SMC_PEERABORTWAIT)
			break;
		smc_sk_set_state(sk, SMC_CLOSED);
		smc_conn_free(&smc->conn);
		release_clcsock = true;
		sock_put(sk); /* passive closing */
		break;
	case SMC_PROCESSABORT:
	case SMC_APPFINCLOSEWAIT:
		smc_sk_set_state(sk, SMC_PEERABORTWAIT);
		smc_close_cancel_work(smc);
		if (smc_sk_state(sk) != SMC_PEERABORTWAIT)
			break;
		smc_sk_set_state(sk, SMC_CLOSED);
		smc_conn_free(&smc->conn);
		release_clcsock = true;
		break;
	case SMC_INIT:
	case SMC_PEERABORTWAIT:
	case SMC_CLOSED:
		break;
	}

	smc_sock_set_flag(sk, SOCK_DEAD);
	sk->sk_state_change(sk);

	if (release_clcsock) {
		release_sock(sk);
		smc_clcsock_release(smc);
		lock_sock(sk);
	}
}

static inline bool smc_close_sent_any_close(struct smc_connection *conn)
{
	return conn->local_tx_ctrl.conn_state_flags.peer_conn_abort ||
	       conn->local_tx_ctrl.conn_state_flags.peer_conn_closed;
}

int smc_close_active(struct smc_sock *smc)
{
	struct smc_cdc_conn_state_flags *txflags =
		&smc->conn.local_tx_ctrl.conn_state_flags;
	struct smc_connection *conn = &smc->conn;
	struct sock *sk = &smc->sk;
	int old_state;
	long timeout;
	int rc = 0;
	int rc1 = 0;

	timeout = current->flags & PF_EXITING ?
		  0 : smc_sock_flag(sk, SOCK_LINGER) ?
		      sk->sk_lingertime : SMC_MAX_STREAM_WAIT_TIMEOUT;

	old_state = smc_sk_state(sk);
again:
	switch (smc_sk_state(sk)) {
	case SMC_INIT:
		smc_sk_set_state(sk, SMC_CLOSED);
		break;
	case SMC_LISTEN:
		smc_sk_set_state(sk, SMC_CLOSED);
		sk->sk_state_change(sk); /* wake up accept */
		if (smc->clcsock && smc->clcsock->sk) {
			write_lock_bh(&smc->clcsock->sk->sk_callback_lock);
			smc_clcsock_restore_cb(&smc->clcsock->sk->sk_data_ready,
					       &smc->clcsk_data_ready);
			smc->clcsock->sk->sk_user_data = NULL;
			write_unlock_bh(&smc->clcsock->sk->sk_callback_lock);
			rc = kernel_sock_shutdown(smc->clcsock, SHUT_RDWR);
		}
		smc_close_cleanup_listen(sk);
		release_sock(sk);
		flush_work(&smc->tcp_listen_work);
		lock_sock(sk);
		break;
	case SMC_ACTIVE:
		smc_close_stream_wait(smc, timeout);
		release_sock(sk);
		cancel_delayed_work_sync(&conn->tx_work);
		lock_sock(sk);
		if (smc_sk_state(sk) == SMC_ACTIVE) {
			/* send close request */
			rc = smc_close_final(conn);
			smc_sk_set_state(sk, SMC_PEERCLOSEWAIT1);

			/* actively shutdown clcsock before peer close it,
			 * prevent peer from entering TIME_WAIT state.
			 */
			if (smc->clcsock && smc->clcsock->sk) {
				rc1 = kernel_sock_shutdown(smc->clcsock,
							   SHUT_RDWR);
				rc = rc ? rc : rc1;
			}
		} else {
			/* peer event has changed the state */
			goto again;
		}
		break;
	case SMC_APPFINCLOSEWAIT:
		/* socket already shutdown wr or both (active close) */
		if (txflags->peer_done_writing &&
		    !smc_close_sent_any_close(conn)) {
			/* just shutdown wr done, send close request */
			rc = smc_close_final(conn);
		}
		smc_sk_set_state(sk, SMC_CLOSED);
		break;
	case SMC_APPCLOSEWAIT1:
	case SMC_APPCLOSEWAIT2:
		if (!smc_cdc_rxed_any_close(conn))
			smc_close_stream_wait(smc, timeout);
		release_sock(sk);
		cancel_delayed_work_sync(&conn->tx_work);
		lock_sock(sk);
		if (smc_sk_state(sk) != SMC_APPCLOSEWAIT1 &&
		    smc_sk_state(sk) != SMC_APPCLOSEWAIT2)
			goto again;
		/* confirm close from peer */
		rc = smc_close_final(conn);
		if (smc_cdc_rxed_any_close(conn)) {
			/* peer has closed the socket already */
			smc_sk_set_state(sk, SMC_CLOSED);
			sock_put(sk); /* postponed passive closing */
		} else {
			/* peer has just issued a shutdown write */
			smc_sk_set_state(sk, SMC_PEERFINCLOSEWAIT);
		}
		break;
	case SMC_PEERCLOSEWAIT1:
	case SMC_PEERCLOSEWAIT2:
		if (txflags->peer_done_writing &&
		    !smc_close_sent_any_close(conn)) {
			/* just shutdown wr done, send close request */
			rc = smc_close_final(conn);
		}
		/* peer sending PeerConnectionClosed will cause transition */
		break;
	case SMC_PEERFINCLOSEWAIT:
		/* peer sending PeerConnectionClosed will cause transition */
		break;
	case SMC_PROCESSABORT:
		rc = smc_close_abort(conn);
		smc_sk_set_state(sk, SMC_CLOSED);
		break;
	case SMC_PEERABORTWAIT:
		smc_sk_set_state(sk, SMC_CLOSED);
		break;
	case SMC_CLOSED:
		/* nothing to do, add tracing in future patch */
		break;
	}

	if (old_state != smc_sk_state(sk))
		sk->sk_state_change(sk);
	return rc;
}

static void smc_close_passive_abort_received(struct smc_sock *smc)
{
	struct smc_cdc_conn_state_flags *txflags =
		&smc->conn.local_tx_ctrl.conn_state_flags;
	struct sock *sk = &smc->sk;

	switch (smc_sk_state(sk)) {
	case SMC_INIT:
	case SMC_ACTIVE:
	case SMC_APPCLOSEWAIT1:
		smc_sk_set_state(sk, SMC_PROCESSABORT);
		sock_put(sk); /* passive closing */
		break;
	case SMC_APPFINCLOSEWAIT:
		smc_sk_set_state(sk, SMC_PROCESSABORT);
		break;
	case SMC_PEERCLOSEWAIT1:
	case SMC_PEERCLOSEWAIT2:
		if (txflags->peer_done_writing &&
		    !smc_close_sent_any_close(&smc->conn))
			/* just shutdown, but not yet closed locally */
			smc_sk_set_state(sk, SMC_PROCESSABORT);
		else
			smc_sk_set_state(sk, SMC_CLOSED);
		sock_put(sk); /* passive closing */
		break;
	case SMC_APPCLOSEWAIT2:
	case SMC_PEERFINCLOSEWAIT:
		smc_sk_set_state(sk, SMC_CLOSED);
		sock_put(sk); /* passive closing */
		break;
	case SMC_PEERABORTWAIT:
		smc_sk_set_state(sk, SMC_CLOSED);
		break;
	case SMC_PROCESSABORT:
	/* nothing to do, add tracing in future patch */
		break;
	}
}

/* Either some kind of closing has been received: peer_conn_closed,
 * peer_conn_abort, or peer_done_writing
 * or the link group of the connection terminates abnormally.
 */
static void smc_close_passive_work(struct work_struct *work)
{
	struct smc_connection *conn = container_of(work,
						   struct smc_connection,
						   close_work);
	struct smc_sock *smc = container_of(conn, struct smc_sock, conn);
	struct smc_cdc_conn_state_flags *rxflags;
	bool release_clcsock = false;
	struct sock *sk = &smc->sk;
	int old_state;

	lock_sock(sk);
	old_state = smc_sk_state(sk);

	rxflags = &conn->local_rx_ctrl.conn_state_flags;
	if (rxflags->peer_conn_abort) {
		/* peer has not received all data */
		smc_close_passive_abort_received(smc);
		release_sock(sk);
		cancel_delayed_work_sync(&conn->tx_work);
		lock_sock(sk);
		goto wakeup;
	}

	switch (smc_sk_state(sk)) {
	case SMC_INIT:
		smc_sk_set_state(sk, SMC_APPCLOSEWAIT1);
		break;
	case SMC_ACTIVE:
		smc_sk_set_state(sk, SMC_APPCLOSEWAIT1);
		/* postpone sock_put() for passive closing to cover
		 * received SEND_SHUTDOWN as well
		 */
		break;
	case SMC_PEERCLOSEWAIT1:
		if (rxflags->peer_done_writing)
			smc_sk_set_state(sk, SMC_PEERCLOSEWAIT2);
		fallthrough;
		/* to check for closing */
	case SMC_PEERCLOSEWAIT2:
		if (!smc_cdc_rxed_any_close(conn))
			break;
		if (smc_sock_flag(sk, SOCK_DEAD) &&
		    smc_close_sent_any_close(conn)) {
			/* smc_release has already been called locally */
			smc_sk_set_state(sk, SMC_CLOSED);
		} else {
			/* just shutdown, but not yet closed locally */
			smc_sk_set_state(sk, SMC_APPFINCLOSEWAIT);
		}
		sock_put(sk); /* passive closing */
		break;
	case SMC_PEERFINCLOSEWAIT:
		if (smc_cdc_rxed_any_close(conn)) {
			smc_sk_set_state(sk, SMC_CLOSED);
			sock_put(sk); /* passive closing */
		}
		break;
	case SMC_APPCLOSEWAIT1:
	case SMC_APPCLOSEWAIT2:
		/* postpone sock_put() for passive closing to cover
		 * received SEND_SHUTDOWN as well
		 */
		break;
	case SMC_APPFINCLOSEWAIT:
	case SMC_PEERABORTWAIT:
	case SMC_PROCESSABORT:
	case SMC_CLOSED:
		/* nothing to do, add tracing in future patch */
		break;
	}

wakeup:
	sk->sk_data_ready(sk); /* wakeup blocked rcvbuf consumers */
	sk->sk_write_space(sk); /* wakeup blocked sndbuf producers */

	if (old_state != smc_sk_state(sk)) {
		sk->sk_state_change(sk);
		if ((smc_sk_state(sk) == SMC_CLOSED) &&
		    (smc_sock_flag(sk, SOCK_DEAD) || !sk->sk_socket)) {
			smc_conn_free(conn);
			if (smc->clcsock)
				release_clcsock = true;
		}
	}
	release_sock(sk);
	if (release_clcsock)
		smc_clcsock_release(smc);
	sock_put(sk); /* sock_hold done by schedulers of close_work */
}

int smc_close_shutdown_write(struct smc_sock *smc)
{
	struct smc_connection *conn = &smc->conn;
	struct sock *sk = &smc->sk;
	int old_state;
	long timeout;
	int rc = 0;

	timeout = current->flags & PF_EXITING ?
		  0 : smc_sock_flag(sk, SOCK_LINGER) ?
		      sk->sk_lingertime : SMC_MAX_STREAM_WAIT_TIMEOUT;

	old_state = smc_sk_state(sk);
again:
	switch (smc_sk_state(sk)) {
	case SMC_ACTIVE:
		smc_close_stream_wait(smc, timeout);
		release_sock(sk);
		cancel_delayed_work_sync(&conn->tx_work);
		lock_sock(sk);
		if (smc_sk_state(sk) != SMC_ACTIVE)
			goto again;
		/* send close wr request */
		rc = smc_close_wr(conn);
		smc_sk_set_state(sk, SMC_PEERCLOSEWAIT1);
		break;
	case SMC_APPCLOSEWAIT1:
		/* passive close */
		if (!smc_cdc_rxed_any_close(conn))
			smc_close_stream_wait(smc, timeout);
		release_sock(sk);
		cancel_delayed_work_sync(&conn->tx_work);
		lock_sock(sk);
		if (smc_sk_state(sk) != SMC_APPCLOSEWAIT1)
			goto again;
		/* confirm close from peer */
		rc = smc_close_wr(conn);
		smc_sk_set_state(sk, SMC_APPCLOSEWAIT2);
		break;
	case SMC_APPCLOSEWAIT2:
	case SMC_PEERFINCLOSEWAIT:
	case SMC_PEERCLOSEWAIT1:
	case SMC_PEERCLOSEWAIT2:
	case SMC_APPFINCLOSEWAIT:
	case SMC_PROCESSABORT:
	case SMC_PEERABORTWAIT:
		/* nothing to do, add tracing in future patch */
		break;
	}

	if (old_state != smc_sk_state(sk))
		sk->sk_state_change(sk);
	return rc;
}

/* Initialize close properties on connection establishment. */
void smc_close_init(struct smc_sock *smc)
{
	INIT_WORK(&smc->conn.close_work, smc_close_passive_work);
}
