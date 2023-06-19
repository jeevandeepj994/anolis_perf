// SPDX-License-Identifier: GPL-2.0-only

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define AF_SMC			(43)
#define AF_INET			(2)
#define SMC_LISTEN		(10)
#define SMC_SOCK_CLOSED_TIMING	(0)

#define min(a, b) ((a) < (b) ? (a) : (b))

char _license[] SEC("license") = "GPL";

static __always_inline struct smc_sock *smc_sk(struct sock *sk)
{
	return (struct smc_sock *)sk;
}

struct smc_strategy {
	/* 0 for deny; 1 for auto; 2 for allow */
	__u8    mode;
	/* reserver */
	__u8   reserved1;
	/* how many rounds for long cc */
	__u16	rtt_threshold;
	/* For every productivity[0] connections with
	 * productivity[1] long connections,
	 * generate one credits. When productivity[0] is 0, it is equivalent to
	 * every productivity[1] long connections can generate one credits.
	 */
	__u16	smc_productivity[2];
	__u16   tcp_productivity[2];
	/* max value of credits, limit the totol smc-r */
	__u32   max_credits;
	/* max burst in one slice */
	__u32	max_pacing_burst;
	/* fixed pacing delta */
	__u64	pacing_delta;
};

struct smc_prediction {
	/* smc_strategy for this predictor */
	struct smc_strategy strategy;
	/* count to allow smc */
	__u32 credits;
	__u32 pacing_burst;
	/* produce */
	__u16 smc_producer[2];
	__u16 tcp_producer[2];
	__u16 tcp_continuous_hits;
	/* last pick timestamp */
	__u64 last_tstamp;
	/* protection for smc_prediction */
	struct bpf_spin_lock lock;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u16);
	__type(value, struct smc_prediction);
} negotiator_map SEC(".maps");


static inline struct smc_prediction *smc_prediction_get(__u16 key, __u64 tstamp)
{
	struct smc_prediction *smc_predictor;

	smc_predictor = bpf_map_lookup_elem(&negotiator_map, &key);
	return smc_predictor;
}

int SEC("struct_ops/bpf_smc_negotiate")
BPF_PROG(bpf_smc_negotiate, struct sock *sk)
{
	struct smc_prediction *smc_predictor;
	struct tcp_sock *tp;
	__u64 now;
	__u16 key;

	/* client side */
	if (sk == NULL || sk->__sk_common.skc_state != SMC_LISTEN) {
		/* use Global smc_predictor */
		key = 0;
	} else {	/* server side */
		tp = bpf_skc_to_tcp_sock(sk);
		if (!tp)
			goto error;
		key = tp->inet_conn.icsk_inet.sk.__sk_common.skc_num;
	}

	smc_predictor = smc_prediction_get(key, bpf_jiffies64());
	/* whitelist mode */
	if (!smc_predictor)
		return SK_DROP;

#define DENYLIST_MODE	(0)
#define AUTO_MODE	(1)
#define ALLOWLIST_MODE	(2)
	switch (smc_predictor->strategy.mode) {
	case AUTO_MODE:
		break;
	case ALLOWLIST_MODE:
		return SK_PASS;
	case DENYLIST_MODE:
	default:
		return  SK_DROP;
	}
#undef ALLOWLIST_MODE
#undef AUTO_MODE
#undef DENYLIST_MODE

	now = bpf_jiffies64();

	bpf_spin_lock(&smc_predictor->lock);
	if (!smc_predictor->credits)
		goto out_locked_drop;
out_locked_pass:
	/* pacing incoming rate */
	if (now - smc_predictor->last_tstamp < smc_predictor->strategy.pacing_delta) {
pacing:
		if (!smc_predictor->pacing_burst)
			goto out_locked_drop;
		smc_predictor->pacing_burst--;
	} else {
		smc_predictor->last_tstamp = now;
		smc_predictor->pacing_burst = smc_predictor->strategy.max_pacing_burst;
		goto pacing;
	}
	smc_predictor->credits--;
	bpf_spin_unlock(&smc_predictor->lock);
	return SK_PASS;
out_locked_drop:
	bpf_spin_unlock(&smc_predictor->lock);
error:
	return SK_DROP;
}

void SEC("struct_ops/bpf_smc_collect_info")
BPF_PROG(bpf_smc_collect_info, struct sock *sk, int timing)
{
	bool match = false, smc_traffic = false;
	struct smc_prediction *smc_predictor;
	struct smc_sock *smc;
	struct tcp_sock *tp;

	/* no info can collect */
	if (sk == NULL)
		return;

	/* only fouces on closed */
	if (timing != SMC_SOCK_CLOSED_TIMING)
		return;

	/* every full smc sock should contains a tcp sock */
	tp = bpf_skc_to_tcp_sock(sk);
	if (!tp)
		return;

	/* get */
	smc_predictor = smc_prediction_get(tp->inet_conn.icsk_inet.sk.__sk_common.skc_num, 0);
	/* whitelist mode */
	if (!smc_predictor)
		return;

	/* smc sock */
	if (sk->__sk_common.skc_family == AF_SMC) {
		smc = smc_sk(sk);
		if (smc->use_fallback)
			goto fallback;
		smc_traffic = true;
		/* full rtt  */
		match = smc->conn.tx_cdc_seq > smc_predictor->strategy.rtt_threshold;
	} else {
fallback:
		match = tp->data_segs_out > tp->snd_cwnd * smc_predictor->strategy.rtt_threshold;
	}

	bpf_spin_lock(&smc_predictor->lock);
	if (smc_traffic) {
		if (++smc_predictor->smc_producer[0] >
				smc_predictor->strategy.smc_productivity[0]) {
			/* burst trafiic */
			if (smc_predictor->smc_producer[1] <
					smc_predictor->strategy.smc_productivity[1])
				smc_predictor->credits = 0;
			goto reset_smc_producer;
		}
		if (match) {
			/* return back credits */
			smc_predictor->credits++;
			if (++smc_predictor->smc_producer[1] >=
					smc_predictor->strategy.smc_productivity[1]) {
				smc_predictor->credits = min(smc_predictor->strategy.max_credits,
					smc_predictor->credits + 1);
reset_smc_producer:
				smc_predictor->smc_producer[0] = 0;
				smc_predictor->smc_producer[1] = 0;
			}
		}
	} else {
		/* only update when no credits */
		if (++smc_predictor->tcp_producer[0] >
				smc_predictor->strategy.tcp_productivity[0]) {
			smc_predictor->tcp_continuous_hits = 0;
			goto reset_tcp_producer;
		}
		if (match) {
			if (++smc_predictor->tcp_producer[1]
					>= smc_predictor->strategy.tcp_productivity[1]) {
				smc_predictor->credits +=
					min(smc_predictor->strategy.tcp_productivity[1],
						1 << smc_predictor->tcp_continuous_hits++);
				smc_predictor->credits = min(smc_predictor->credits,
						smc_predictor->strategy.max_credits);
reset_tcp_producer:
				smc_predictor->tcp_producer[0] = 0;
				smc_predictor->tcp_producer[1] = 0;

			}
		}
	}
	bpf_spin_unlock(&smc_predictor->lock);
error:
	return;
}

SEC(".struct_ops")
struct smc_sock_negotiator_ops smc_negotiator = {
	.name = "anolis",
	.negotiate	= (void *)bpf_smc_negotiate,
	.collect_info	= (void *)bpf_smc_collect_info,
};
