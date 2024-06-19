// SPDX-License-Identifier: GPL-2.0-only

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define AF_SMC (43)
#define AF_INET (2)
#define SMC_LISTEN (10)
#define SMC_SOCK_CLOSED_TIMING (0)

char _license[] SEC("license") = "GPL";

int SEC("struct_ops/bpf_smc_negotiate")
	BPF_PROG(bpf_smc_negotiate, struct sock *sk)
{
	return SK_DROP;
}

void SEC("struct_ops/bpf_smc_collect_info")
	BPF_PROG(bpf_smc_collect_info, struct sock *sk, int timing)
{
	struct tcp_sock *tp;
	__u16 key;

	/* only fouces on closed */
	if (timing != SMC_SOCK_CLOSED_TIMING)
		return;
	/* every full smc sock should contains a tcp sock */
	tp = bpf_skc_to_tcp_sock(sk);
	if (!tp)
		return;

	/* local port as key */
	key = tp->inet_conn.icsk_inet.sk.__sk_common.skc_num;
	if (key == 0)
		return;

	bpf_printk("bpf_smc_collect_info recv port %d\n", key);
	return;
}

SEC(".struct_ops")
struct smc_sock_negotiator_ops anolis_smc = {
	.name = "anolis",
	.negotiate = (void *)bpf_smc_negotiate,
	.collect_info = (void *)bpf_smc_collect_info,
};
