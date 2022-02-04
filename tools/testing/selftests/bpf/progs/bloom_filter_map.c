// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Facebook */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

struct bpf_map;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1000);
} map_random_data SEC(".maps");

struct map_bloom_type {
	__uint(type, BPF_MAP_TYPE_BLOOM_FILTER);
	__type(value, __u32);
	__uint(max_entries, 10000);
	__uint(map_extra, 5);
} map_bloom SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__type(key, int);
	__type(value, int);
	__uint(max_entries, 1);
	__array(values, struct map_bloom_type);
} outer_map SEC(".maps");

int error = 0;

static void check_elem(struct bpf_map *map)
{
	int err, i, key, *map_random_val;

	for (i = 0; i < 1000; i++) {
		key = i;
		map_random_val = bpf_map_lookup_elem(&map_random_data, &key);
		if (!map_random_val) {
			error |= 2;
			return;
		}
		err = bpf_map_peek_elem(map, map_random_val);
		if (err) {
			error |= 1;
			return;
		}
	}
}

SEC("fentry/" SYS_PREFIX "sys_getpgid")
int inner_map(void *ctx)
{
	struct bpf_map *inner_map;
	int key = 0;

	inner_map = bpf_map_lookup_elem(&outer_map, &key);
	if (!inner_map) {
		error |= 2;
		return 0;
	}

	check_elem(inner_map);

	return 0;
}

SEC("fentry/" SYS_PREFIX "sys_getpgid")
int check_bloom(void *ctx)
{
	check_elem(&map_bloom);

	return 0;
}
