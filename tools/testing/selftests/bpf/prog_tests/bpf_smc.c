// SPDX-License-Identifier: GPL-2.0

#include <linux/err.h>
#include <netinet/tcp.h>
#include <test_progs.h>
#include "network_helpers.h"
#include "bpf_smc.skel.h"

#define SOL_SMC 286
#define SMC_NEGOTIATOR 2

void test_load(void)
{
	struct bpf_smc *smc_skel;
	struct bpf_link *link;

	smc_skel = bpf_smc__open_and_load();
	if (!ASSERT_OK_PTR(smc_skel, "skel_open"))
		return;

	link = bpf_map__attach_struct_ops(smc_skel->maps.anolis_smc);
	if (!ASSERT_OK_PTR(link, "bpf_map__attach_struct_ops"))
		goto error;

	bpf_link__destroy(link);
error:
	bpf_smc__destroy(smc_skel);
}

void test_bpf_smc(void)
{
	if (test__start_subtest("load"))
		test_load();
}
