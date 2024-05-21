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
	/* low = 0, hi = 1, N = 2 */
	__u16	smc_productivity[4];
	__u16   tcp_productivity[4];
#define LOW_WATER_LEVEL(domain)		domain##_productivity[0]
#define HI_WATER_LEVEL(domain)		domain##_productivity[1]
#define EVERY_N(domain)			domain##_productivity[2]
	/* max value of credits, limit the totol smc-r */
	__u32   max_credits;
	/* Initial value of credits */
	__u32	initial_credits;
	/* max burst in one slice */
	__u32	max_pacing_burst;
	/* fixed pacing delta */
	__u64	pacing_delta;
};

/* maps for smc_strategy */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u16);
	__type(value, struct smc_strategy);
} smc_strategies SEC(".maps");

struct smc_prediction {
	/* count to allow smc */
	__u32 credits;
	__u32 pacing_burst;
	/* count for smc conn */
	__u16 count_total_smc_conn;
	__u16 count_matched_smc_conn;
	/* count fot tcp conn */
	__u16 count_total_tcp_conn;
	__u16 count_matched_tcp_conn;
	/* last pick timestamp */
	__u64 last_tstamp;
	/* protection for smc_prediction */
	struct bpf_spin_lock lock;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u16);
	__type(value, struct smc_prediction);
} smc_predictors SEC(".maps");

static inline struct smc_prediction *smc_prediction_get(__u16 key, struct smc_strategy *strategy)
{
	struct smc_prediction *smc_predictor;

	smc_predictor = bpf_map_lookup_elem(&smc_predictors, &key);
	if (!smc_predictor) {
		struct smc_prediction init = {
			.credits = strategy->initial_credits,
		};
		bpf_map_update_elem(&smc_predictors, &key, &init, BPF_NOEXIST);
		smc_predictor = bpf_map_lookup_elem(&smc_predictors, &key);
	}
	return smc_predictor;
}

static inline struct smc_strategy *smc_strategy_get(__u16 key)
{
	struct smc_strategy *strategy;

	strategy = bpf_map_lookup_elem(&smc_strategies, &key);
	if (!strategy && key != 0) {
		/* search for default */
		key = 0;
		strategy = bpf_map_lookup_elem(&smc_strategies, &key);
	}
	return strategy;
}

int SEC("struct_ops/bpf_smc_negotiate")
BPF_PROG(bpf_smc_negotiate, struct sock *sk)
{
	struct smc_prediction *smc_predictor;
	struct smc_strategy *strategy;
	struct smc_sock *smc;
	struct tcp_sock *tp;
	__u64 now;
	__u16 key;

	if (!sk)
		return SK_DROP;

	smc = smc_sk(sk);

	/* for client side */
	if (!smc->listen_smc && smc->sk.__sk_common.skc_state != SMC_LISTEN) {
		/* client always say yes */
		return SK_PASS;
	}

	/* every full smc sock should contains a tcp sock */
	tp = bpf_skc_to_tcp_sock(sk);

	/* local port as key */
	key = tp ? tp->inet_conn.icsk_inet.sk.__sk_common.skc_num : 0;

	strategy = smc_strategy_get(key);
	if (!strategy)
		return SK_DROP;

#define DENYLIST_MODE	(0)
#define AUTO_MODE		(1)
#define ALLOWLIST_MODE	(2)
	switch (strategy->mode) {
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

	smc_predictor = smc_prediction_get(key, strategy);
	if (!smc_predictor)
		return SK_DROP;

	now = bpf_jiffies64();

	bpf_spin_lock(&smc_predictor->lock);
	if (!smc_predictor->credits)
		goto out_locked_drop;
out_locked_pass:
	/* pacing incoming rate */
	if (now - smc_predictor->last_tstamp < strategy->pacing_delta) {
pacing:
		if (!smc_predictor->pacing_burst)
			goto out_locked_drop;
		smc_predictor->pacing_burst--;
	} else {
		smc_predictor->last_tstamp = now;
		smc_predictor->pacing_burst = strategy->max_pacing_burst;
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
	struct smc_strategy *strategy;
	struct smc_sock *smc;
	struct tcp_sock *tp;
	__u64 delta = 0;
	__u16 key;

	/* smc sock */
	smc = smc_sk(sk);
	if (!smc)
		return;

	/* only fouces on closed */
	if (timing != SMC_SOCK_CLOSED_TIMING)
		return;

	/* every full smc sock should contains a tcp sock */
	tp = bpf_skc_to_tcp_sock(sk);
	if (!tp)
		return;

	if (!smc->listen_smc)
		/* only monitor passive open for server */
		return;

	/* local port as key */
	key = tp->inet_conn.icsk_inet.sk.__sk_common.skc_num;
	if (key == 0)
		return;

	strategy = smc_strategy_get(key);
	if (!strategy)
		return;

	smc_predictor = smc_prediction_get(key, strategy);
	if (!smc_predictor)
		return;

	switch (sk->__sk_common.skc_family) {
	case AF_INET:
		if (sk != &tp->inet_conn.icsk_inet.sk)
			return;
	case AF_SMC:
		if (!smc->use_fallback) {
			smc_traffic = true;
			/* full rtt*/
			match = smc->conn.tx_cdc_seq > strategy->rtt_threshold;
			break;
		}
	default:
		match = tp->data_segs_out > tp->snd_cwnd * strategy->rtt_threshold;
		break;
	}

	bpf_spin_lock(&smc_predictor->lock);
	if (smc_traffic) {
		/* matched smc connection */
		if (match)
			++smc_predictor->count_matched_smc_conn;
		/* For every N smc connection，matched connection in
		 * [0, LOW_WATER_LEVEL)			: smc_predictor->credits >> 1;
		 * [LOW_WATER_LEVEL, HI_WATER_LEVEL)	: no impact;
		 * [HI_WATER_LEVEL, )			: inc smc_predictor->credits
		 */
		if (++smc_predictor->count_total_smc_conn >= strategy->EVERY_N(smc)) {
			/* fast down-grade */
			if (smc_predictor->count_matched_smc_conn < strategy->LOW_WATER_LEVEL(smc))
				smc_predictor->credits = smc_predictor->credits >> 1;
			else if (smc_predictor->count_matched_smc_conn >=
					strategy->HI_WATER_LEVEL(smc))
				/* return back */
				smc_predictor->credits = min(smc_predictor->credits + 1,
					strategy->max_credits);
			/* reset smc_producer */
			smc_predictor->count_total_smc_conn = 0;
			smc_predictor->count_matched_smc_conn = 0;
		}
	} else {
		if (match)
			/* matched tcp connection */
			++smc_predictor->count_matched_tcp_conn;
		/* For every N tcp connection，matched connection in
		 * [0, LOW_WATER_LEVEL)			: no impact
		 * [LOW_WATER_LEVEL, HI_WATER_LEVEL)	: inc smc_predictor->credits
		 * [HI_WATER_LEVEL, )			: add smc_predictor->credits by n.
		 */
		if (++smc_predictor->count_total_tcp_conn >= strategy->EVERY_N(tcp)) {
			if (smc_predictor->count_matched_tcp_conn >= strategy->HI_WATER_LEVEL(tcp))
				delta = smc_predictor->count_matched_tcp_conn;
			else if (smc_predictor->count_matched_tcp_conn >=
					strategy->LOW_WATER_LEVEL(tcp))
				delta = 1;
			smc_predictor->credits = min(smc_predictor->credits + delta,
				strategy->max_credits);
			/* reset tcp_producer */
			smc_predictor->count_total_tcp_conn = 0;
			smc_predictor->count_matched_tcp_conn = 0;
		}
	}
	bpf_spin_unlock(&smc_predictor->lock);
error:
	return;
}

SEC(".struct_ops")
struct smc_sock_negotiator_ops anolis_smc = {
	.name = "anolis",
	.negotiate	= (void *)bpf_smc_negotiate,
	.collect_info	= (void *)bpf_smc_collect_info,
};
