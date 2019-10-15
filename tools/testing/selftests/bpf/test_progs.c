/* Copyright (c) 2017 Facebook
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <signal.h>
#include <sched.h>

#include <linux/types.h>
typedef __u16 __sum16;
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/filter.h>
#include <linux/perf_event.h>
#include <linux/unistd.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/nbd.h>

#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <pthread.h>
#include <linux/bpf.h>
#include <linux/err.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "test_iptunnel_common.h"
#include "bpf_util.h"
#include "bpf_endian.h"
#include "bpf_rlimit.h"
#include "trace_helpers.h"
#include "flow_dissector_load.h"

static int error_cnt, pass_cnt;
static bool jit_enabled;
bool verifier_stats = false;

#define MAGIC_BYTES 123

#ifdef __x86_64__
#define SYS_KPROBE_NAME "__x64_sys_nanosleep"
#else
#define SYS_KPROBE_NAME "sys_nanosleep"
#endif

#ifndef IP_MF
#define IP_MF 0x2000
#endif

/* ipv4 test vector */
static struct {
	struct ethhdr eth;
	struct iphdr iph;
	struct tcphdr tcp;
} __packed pkt_v4 = {
	.eth.h_proto = __bpf_constant_htons(ETH_P_IP),
	.iph.ihl = 5,
	.iph.protocol = IPPROTO_TCP,
	.iph.tot_len = __bpf_constant_htons(MAGIC_BYTES),
	.tcp.urg_ptr = 123,
	.tcp.doff = 5,
};

/* ipv6 test vector */
static struct {
	struct ethhdr eth;
	struct ipv6hdr iph;
	struct tcphdr tcp;
} __packed pkt_v6 = {
	.eth.h_proto = __bpf_constant_htons(ETH_P_IPV6),
	.iph.nexthdr = IPPROTO_TCP,
	.iph.payload_len = __bpf_constant_htons(MAGIC_BYTES),
	.tcp.urg_ptr = 123,
	.tcp.doff = 5,
};

#define _CHECK(condition, tag, duration, format...) ({			\
	int __ret = !!(condition);					\
	if (__ret) {							\
		error_cnt++;						\
		printf("%s:FAIL:%s ", __func__, tag);			\
		printf(format);						\
	} else {							\
		pass_cnt++;						\
		printf("%s:PASS:%s %d nsec\n", __func__, tag, duration);\
	}								\
	__ret;								\
})

#define CHECK(condition, tag, format...) \
	_CHECK(condition, tag, duration, format)
#define CHECK_ATTR(condition, tag, format...) \
	_CHECK(condition, tag, tattr.duration, format)

static int bpf_find_map(const char *test, struct bpf_object *obj,
			const char *name)
{
	struct bpf_map *map;

	map = bpf_object__find_map_by_name(obj, name);
	if (!map) {
		printf("%s:FAIL:map '%s' not found\n", test, name);
		error_cnt++;
		return -1;
	}
	return bpf_map__fd(map);
}

static void test_pkt_access(void)
{
	const char *file = "./test_pkt_access.o";
	struct bpf_object *obj;
	__u32 duration, retval;
	int err, prog_fd;

	err = bpf_prog_load(file, BPF_PROG_TYPE_SCHED_CLS, &obj, &prog_fd);
	if (err) {
		error_cnt++;
		return;
	}

	err = bpf_prog_test_run(prog_fd, 100000, &pkt_v4, sizeof(pkt_v4),
				NULL, NULL, &retval, &duration);
	CHECK(err || retval, "ipv4",
	      "err %d errno %d retval %d duration %d\n",
	      err, errno, retval, duration);

	err = bpf_prog_test_run(prog_fd, 100000, &pkt_v6, sizeof(pkt_v6),
				NULL, NULL, &retval, &duration);
	CHECK(err || retval, "ipv6",
	      "err %d errno %d retval %d duration %d\n",
	      err, errno, retval, duration);
	bpf_object__close(obj);
}

static void test_prog_run_xattr(void)
{
	const char *file = "./test_pkt_access.o";
	struct bpf_object *obj;
	char buf[10];
	int err;
	struct bpf_prog_test_run_attr tattr = {
		.repeat = 1,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
		.data_out = buf,
		.data_size_out = 5,
	};

	err = bpf_prog_load(file, BPF_PROG_TYPE_SCHED_CLS, &obj,
			    &tattr.prog_fd);
	if (CHECK_ATTR(err, "load", "err %d errno %d\n", err, errno))
		return;

	memset(buf, 0, sizeof(buf));

	err = bpf_prog_test_run_xattr(&tattr);
	CHECK_ATTR(err != -1 || errno != ENOSPC || tattr.retval, "run",
	      "err %d errno %d retval %d\n", err, errno, tattr.retval);

	CHECK_ATTR(tattr.data_size_out != sizeof(pkt_v4), "data_size_out",
	      "incorrect output size, want %lu have %u\n",
	      sizeof(pkt_v4), tattr.data_size_out);

	CHECK_ATTR(buf[5] != 0, "overflow",
	      "BPF_PROG_TEST_RUN ignored size hint\n");

	tattr.data_out = NULL;
	tattr.data_size_out = 0;
	errno = 0;

	err = bpf_prog_test_run_xattr(&tattr);
	CHECK_ATTR(err || errno || tattr.retval, "run_no_output",
	      "err %d errno %d retval %d\n", err, errno, tattr.retval);

	tattr.data_size_out = 1;
	err = bpf_prog_test_run_xattr(&tattr);
	CHECK_ATTR(err != -EINVAL, "run_wrong_size_out", "err %d\n", err);

	bpf_object__close(obj);
}

static void test_xdp(void)
{
	struct vip key4 = {.protocol = 6, .family = AF_INET};
	struct vip key6 = {.protocol = 6, .family = AF_INET6};
	struct iptnl_info value4 = {.family = AF_INET};
	struct iptnl_info value6 = {.family = AF_INET6};
	const char *file = "./test_xdp.o";
	struct bpf_object *obj;
	char buf[128];
	struct ipv6hdr *iph6 = (void *)buf + sizeof(struct ethhdr);
	struct iphdr *iph = (void *)buf + sizeof(struct ethhdr);
	__u32 duration, retval, size;
	int err, prog_fd, map_fd;

	err = bpf_prog_load(file, BPF_PROG_TYPE_XDP, &obj, &prog_fd);
	if (err) {
		error_cnt++;
		return;
	}

	map_fd = bpf_find_map(__func__, obj, "vip2tnl");
	if (map_fd < 0)
		goto out;
	bpf_map_update_elem(map_fd, &key4, &value4, 0);
	bpf_map_update_elem(map_fd, &key6, &value6, 0);

	err = bpf_prog_test_run(prog_fd, 1, &pkt_v4, sizeof(pkt_v4),
				buf, &size, &retval, &duration);

	CHECK(err || retval != XDP_TX || size != 74 ||
	      iph->protocol != IPPROTO_IPIP, "ipv4",
	      "err %d errno %d retval %d size %d\n",
	      err, errno, retval, size);

	err = bpf_prog_test_run(prog_fd, 1, &pkt_v6, sizeof(pkt_v6),
				buf, &size, &retval, &duration);
	CHECK(err || retval != XDP_TX || size != 114 ||
	      iph6->nexthdr != IPPROTO_IPV6, "ipv6",
	      "err %d errno %d retval %d size %d\n",
	      err, errno, retval, size);
out:
	bpf_object__close(obj);
}

static void test_xdp_adjust_tail(void)
{
	const char *file = "./test_adjust_tail.o";
	struct bpf_object *obj;
	char buf[128];
	__u32 duration, retval, size;
	int err, prog_fd;

	err = bpf_prog_load(file, BPF_PROG_TYPE_XDP, &obj, &prog_fd);
	if (err) {
		error_cnt++;
		return;
	}

	err = bpf_prog_test_run(prog_fd, 1, &pkt_v4, sizeof(pkt_v4),
				buf, &size, &retval, &duration);

	CHECK(err || retval != XDP_DROP,
	      "ipv4", "err %d errno %d retval %d size %d\n",
	      err, errno, retval, size);

	err = bpf_prog_test_run(prog_fd, 1, &pkt_v6, sizeof(pkt_v6),
				buf, &size, &retval, &duration);
	CHECK(err || retval != XDP_TX || size != 54,
	      "ipv6", "err %d errno %d retval %d size %d\n",
	      err, errno, retval, size);
	bpf_object__close(obj);
}



#define MAGIC_VAL 0x1234
#define NUM_ITER 100000
#define VIP_NUM 5

static void test_l4lb(const char *file)
{
	unsigned int nr_cpus = bpf_num_possible_cpus();
	struct vip key = {.protocol = 6};
	struct vip_meta {
		__u32 flags;
		__u32 vip_num;
	} value = {.vip_num = VIP_NUM};
	__u32 stats_key = VIP_NUM;
	struct vip_stats {
		__u64 bytes;
		__u64 pkts;
	} stats[nr_cpus];
	struct real_definition {
		union {
			__be32 dst;
			__be32 dstv6[4];
		};
		__u8 flags;
	} real_def = {.dst = MAGIC_VAL};
	__u32 ch_key = 11, real_num = 3;
	__u32 duration, retval, size;
	int err, i, prog_fd, map_fd;
	__u64 bytes = 0, pkts = 0;
	struct bpf_object *obj;
	char buf[128];
	u32 *magic = (u32 *)buf;

	err = bpf_prog_load(file, BPF_PROG_TYPE_SCHED_CLS, &obj, &prog_fd);
	if (err) {
		error_cnt++;
		return;
	}

	map_fd = bpf_find_map(__func__, obj, "vip_map");
	if (map_fd < 0)
		goto out;
	bpf_map_update_elem(map_fd, &key, &value, 0);

	map_fd = bpf_find_map(__func__, obj, "ch_rings");
	if (map_fd < 0)
		goto out;
	bpf_map_update_elem(map_fd, &ch_key, &real_num, 0);

	map_fd = bpf_find_map(__func__, obj, "reals");
	if (map_fd < 0)
		goto out;
	bpf_map_update_elem(map_fd, &real_num, &real_def, 0);

	err = bpf_prog_test_run(prog_fd, NUM_ITER, &pkt_v4, sizeof(pkt_v4),
				buf, &size, &retval, &duration);
	CHECK(err || retval != 7/*TC_ACT_REDIRECT*/ || size != 54 ||
	      *magic != MAGIC_VAL, "ipv4",
	      "err %d errno %d retval %d size %d magic %x\n",
	      err, errno, retval, size, *magic);

	err = bpf_prog_test_run(prog_fd, NUM_ITER, &pkt_v6, sizeof(pkt_v6),
				buf, &size, &retval, &duration);
	CHECK(err || retval != 7/*TC_ACT_REDIRECT*/ || size != 74 ||
	      *magic != MAGIC_VAL, "ipv6",
	      "err %d errno %d retval %d size %d magic %x\n",
	      err, errno, retval, size, *magic);

	map_fd = bpf_find_map(__func__, obj, "stats");
	if (map_fd < 0)
		goto out;
	bpf_map_lookup_elem(map_fd, &stats_key, stats);
	for (i = 0; i < nr_cpus; i++) {
		bytes += stats[i].bytes;
		pkts += stats[i].pkts;
	}
	if (bytes != MAGIC_BYTES * NUM_ITER * 2 || pkts != NUM_ITER * 2) {
		error_cnt++;
		printf("test_l4lb:FAIL:stats %lld %lld\n", bytes, pkts);
	}
out:
	bpf_object__close(obj);
}

static void test_l4lb_all(void)
{
	const char *file1 = "./test_l4lb.o";
	const char *file2 = "./test_l4lb_noinline.o";

	test_l4lb(file1);
	test_l4lb(file2);
}

static void test_xdp_noinline(void)
{
	const char *file = "./test_xdp_noinline.o";
	unsigned int nr_cpus = bpf_num_possible_cpus();
	struct vip key = {.protocol = 6};
	struct vip_meta {
		__u32 flags;
		__u32 vip_num;
	} value = {.vip_num = VIP_NUM};
	__u32 stats_key = VIP_NUM;
	struct vip_stats {
		__u64 bytes;
		__u64 pkts;
	} stats[nr_cpus];
	struct real_definition {
		union {
			__be32 dst;
			__be32 dstv6[4];
		};
		__u8 flags;
	} real_def = {.dst = MAGIC_VAL};
	__u32 ch_key = 11, real_num = 3;
	__u32 duration, retval, size;
	int err, i, prog_fd, map_fd;
	__u64 bytes = 0, pkts = 0;
	struct bpf_object *obj;
	char buf[128];
	u32 *magic = (u32 *)buf;

	err = bpf_prog_load(file, BPF_PROG_TYPE_XDP, &obj, &prog_fd);
	if (err) {
		error_cnt++;
		return;
	}

	map_fd = bpf_find_map(__func__, obj, "vip_map");
	if (map_fd < 0)
		goto out;
	bpf_map_update_elem(map_fd, &key, &value, 0);

	map_fd = bpf_find_map(__func__, obj, "ch_rings");
	if (map_fd < 0)
		goto out;
	bpf_map_update_elem(map_fd, &ch_key, &real_num, 0);

	map_fd = bpf_find_map(__func__, obj, "reals");
	if (map_fd < 0)
		goto out;
	bpf_map_update_elem(map_fd, &real_num, &real_def, 0);

	err = bpf_prog_test_run(prog_fd, NUM_ITER, &pkt_v4, sizeof(pkt_v4),
				buf, &size, &retval, &duration);
	CHECK(err || retval != 1 || size != 54 ||
	      *magic != MAGIC_VAL, "ipv4",
	      "err %d errno %d retval %d size %d magic %x\n",
	      err, errno, retval, size, *magic);

	err = bpf_prog_test_run(prog_fd, NUM_ITER, &pkt_v6, sizeof(pkt_v6),
				buf, &size, &retval, &duration);
	CHECK(err || retval != 1 || size != 74 ||
	      *magic != MAGIC_VAL, "ipv6",
	      "err %d errno %d retval %d size %d magic %x\n",
	      err, errno, retval, size, *magic);

	map_fd = bpf_find_map(__func__, obj, "stats");
	if (map_fd < 0)
		goto out;
	bpf_map_lookup_elem(map_fd, &stats_key, stats);
	for (i = 0; i < nr_cpus; i++) {
		bytes += stats[i].bytes;
		pkts += stats[i].pkts;
	}
	if (bytes != MAGIC_BYTES * NUM_ITER * 2 || pkts != NUM_ITER * 2) {
		error_cnt++;
		printf("test_xdp_noinline:FAIL:stats %lld %lld\n", bytes, pkts);
	}
out:
	bpf_object__close(obj);
}

static void test_tcp_estats(void)
{
	const char *file = "./test_tcp_estats.o";
	int err, prog_fd;
	struct bpf_object *obj;
	__u32 duration = 0;

	err = bpf_prog_load(file, BPF_PROG_TYPE_TRACEPOINT, &obj, &prog_fd);
	CHECK(err, "", "err %d errno %d\n", err, errno);
	if (err) {
		error_cnt++;
		return;
	}

	bpf_object__close(obj);
}

static inline __u64 ptr_to_u64(const void *ptr)
{
	return (__u64) (unsigned long) ptr;
}

static bool is_jit_enabled(void)
{
	const char *jit_sysctl = "/proc/sys/net/core/bpf_jit_enable";
	bool enabled = false;
	int sysctl_fd;

	sysctl_fd = open(jit_sysctl, 0, O_RDONLY);
	if (sysctl_fd != -1) {
		char tmpc;

		if (read(sysctl_fd, &tmpc, sizeof(tmpc)) == 1)
			enabled = (tmpc != '0');
		close(sysctl_fd);
	}

	return enabled;
}

static void test_bpf_obj_id(void)
{
	const __u64 array_magic_value = 0xfaceb00c;
	const __u32 array_key = 0;
	const int nr_iters = 2;
	const char *file = "./test_obj_id.o";
	const char *expected_prog_name = "test_obj_id";
	const char *expected_map_name = "test_map_id";
	const __u64 nsec_per_sec = 1000000000;

	struct bpf_object *objs[nr_iters];
	int prog_fds[nr_iters], map_fds[nr_iters];
	/* +1 to test for the info_len returned by kernel */
	struct bpf_prog_info prog_infos[nr_iters + 1];
	struct bpf_map_info map_infos[nr_iters + 1];
	/* Each prog only uses one map. +1 to test nr_map_ids
	 * returned by kernel.
	 */
	__u32 map_ids[nr_iters + 1];
	char jited_insns[128], xlated_insns[128], zeros[128];
	__u32 i, next_id, info_len, nr_id_found, duration = 0;
	struct timespec real_time_ts, boot_time_ts;
	int err = 0;
	__u64 array_value;
	uid_t my_uid = getuid();
	time_t now, load_time;

	err = bpf_prog_get_fd_by_id(0);
	CHECK(err >= 0 || errno != ENOENT,
	      "get-fd-by-notexist-prog-id", "err %d errno %d\n", err, errno);

	err = bpf_map_get_fd_by_id(0);
	CHECK(err >= 0 || errno != ENOENT,
	      "get-fd-by-notexist-map-id", "err %d errno %d\n", err, errno);

	for (i = 0; i < nr_iters; i++)
		objs[i] = NULL;

	/* Check bpf_obj_get_info_by_fd() */
	bzero(zeros, sizeof(zeros));
	for (i = 0; i < nr_iters; i++) {
		now = time(NULL);
		err = bpf_prog_load(file, BPF_PROG_TYPE_SOCKET_FILTER,
				    &objs[i], &prog_fds[i]);
		/* test_obj_id.o is a dumb prog. It should never fail
		 * to load.
		 */
		if (err)
			error_cnt++;
		assert(!err);

		/* Insert a magic value to the map */
		map_fds[i] = bpf_find_map(__func__, objs[i], "test_map_id");
		assert(map_fds[i] >= 0);
		err = bpf_map_update_elem(map_fds[i], &array_key,
					  &array_magic_value, 0);
		assert(!err);

		/* Check getting map info */
		info_len = sizeof(struct bpf_map_info) * 2;
		bzero(&map_infos[i], info_len);
		err = bpf_obj_get_info_by_fd(map_fds[i], &map_infos[i],
					     &info_len);
		if (CHECK(err ||
			  map_infos[i].type != BPF_MAP_TYPE_ARRAY ||
			  map_infos[i].key_size != sizeof(__u32) ||
			  map_infos[i].value_size != sizeof(__u64) ||
			  map_infos[i].max_entries != 1 ||
			  map_infos[i].map_flags != 0 ||
			  info_len != sizeof(struct bpf_map_info) ||
			  strcmp((char *)map_infos[i].name, expected_map_name),
			  "get-map-info(fd)",
			  "err %d errno %d type %d(%d) info_len %u(%Zu) key_size %u value_size %u max_entries %u map_flags %X name %s(%s)\n",
			  err, errno,
			  map_infos[i].type, BPF_MAP_TYPE_ARRAY,
			  info_len, sizeof(struct bpf_map_info),
			  map_infos[i].key_size,
			  map_infos[i].value_size,
			  map_infos[i].max_entries,
			  map_infos[i].map_flags,
			  map_infos[i].name, expected_map_name))
			goto done;

		/* Check getting prog info */
		info_len = sizeof(struct bpf_prog_info) * 2;
		bzero(&prog_infos[i], info_len);
		bzero(jited_insns, sizeof(jited_insns));
		bzero(xlated_insns, sizeof(xlated_insns));
		prog_infos[i].jited_prog_insns = ptr_to_u64(jited_insns);
		prog_infos[i].jited_prog_len = sizeof(jited_insns);
		prog_infos[i].xlated_prog_insns = ptr_to_u64(xlated_insns);
		prog_infos[i].xlated_prog_len = sizeof(xlated_insns);
		prog_infos[i].map_ids = ptr_to_u64(map_ids + i);
		prog_infos[i].nr_map_ids = 2;
		err = clock_gettime(CLOCK_REALTIME, &real_time_ts);
		assert(!err);
		err = clock_gettime(CLOCK_BOOTTIME, &boot_time_ts);
		assert(!err);
		err = bpf_obj_get_info_by_fd(prog_fds[i], &prog_infos[i],
					     &info_len);
		load_time = (real_time_ts.tv_sec - boot_time_ts.tv_sec)
			+ (prog_infos[i].load_time / nsec_per_sec);
		if (CHECK(err ||
			  prog_infos[i].type != BPF_PROG_TYPE_SOCKET_FILTER ||
			  info_len != sizeof(struct bpf_prog_info) ||
			  (jit_enabled && !prog_infos[i].jited_prog_len) ||
			  (jit_enabled &&
			   !memcmp(jited_insns, zeros, sizeof(zeros))) ||
			  !prog_infos[i].xlated_prog_len ||
			  !memcmp(xlated_insns, zeros, sizeof(zeros)) ||
			  load_time < now - 60 || load_time > now + 60 ||
			  prog_infos[i].created_by_uid != my_uid ||
			  prog_infos[i].nr_map_ids != 1 ||
			  *(int *)(long)prog_infos[i].map_ids != map_infos[i].id ||
			  strcmp((char *)prog_infos[i].name, expected_prog_name),
			  "get-prog-info(fd)",
			  "err %d errno %d i %d type %d(%d) info_len %u(%Zu) jit_enabled %d jited_prog_len %u xlated_prog_len %u jited_prog %d xlated_prog %d load_time %lu(%lu) uid %u(%u) nr_map_ids %u(%u) map_id %u(%u) name %s(%s)\n",
			  err, errno, i,
			  prog_infos[i].type, BPF_PROG_TYPE_SOCKET_FILTER,
			  info_len, sizeof(struct bpf_prog_info),
			  jit_enabled,
			  prog_infos[i].jited_prog_len,
			  prog_infos[i].xlated_prog_len,
			  !!memcmp(jited_insns, zeros, sizeof(zeros)),
			  !!memcmp(xlated_insns, zeros, sizeof(zeros)),
			  load_time, now,
			  prog_infos[i].created_by_uid, my_uid,
			  prog_infos[i].nr_map_ids, 1,
			  *(int *)(long)prog_infos[i].map_ids, map_infos[i].id,
			  prog_infos[i].name, expected_prog_name))
			goto done;
	}

	/* Check bpf_prog_get_next_id() */
	nr_id_found = 0;
	next_id = 0;
	while (!bpf_prog_get_next_id(next_id, &next_id)) {
		struct bpf_prog_info prog_info = {};
		__u32 saved_map_id;
		int prog_fd;

		info_len = sizeof(prog_info);

		prog_fd = bpf_prog_get_fd_by_id(next_id);
		if (prog_fd < 0 && errno == ENOENT)
			/* The bpf_prog is in the dead row */
			continue;
		if (CHECK(prog_fd < 0, "get-prog-fd(next_id)",
			  "prog_fd %d next_id %d errno %d\n",
			  prog_fd, next_id, errno))
			break;

		for (i = 0; i < nr_iters; i++)
			if (prog_infos[i].id == next_id)
				break;

		if (i == nr_iters)
			continue;

		nr_id_found++;

		/* Negative test:
		 * prog_info.nr_map_ids = 1
		 * prog_info.map_ids = NULL
		 */
		prog_info.nr_map_ids = 1;
		err = bpf_obj_get_info_by_fd(prog_fd, &prog_info, &info_len);
		if (CHECK(!err || errno != EFAULT,
			  "get-prog-fd-bad-nr-map-ids", "err %d errno %d(%d)",
			  err, errno, EFAULT))
			break;
		bzero(&prog_info, sizeof(prog_info));
		info_len = sizeof(prog_info);

		saved_map_id = *(int *)((long)prog_infos[i].map_ids);
		prog_info.map_ids = prog_infos[i].map_ids;
		prog_info.nr_map_ids = 2;
		err = bpf_obj_get_info_by_fd(prog_fd, &prog_info, &info_len);
		prog_infos[i].jited_prog_insns = 0;
		prog_infos[i].xlated_prog_insns = 0;
		CHECK(err || info_len != sizeof(struct bpf_prog_info) ||
		      memcmp(&prog_info, &prog_infos[i], info_len) ||
		      *(int *)(long)prog_info.map_ids != saved_map_id,
		      "get-prog-info(next_id->fd)",
		      "err %d errno %d info_len %u(%Zu) memcmp %d map_id %u(%u)\n",
		      err, errno, info_len, sizeof(struct bpf_prog_info),
		      memcmp(&prog_info, &prog_infos[i], info_len),
		      *(int *)(long)prog_info.map_ids, saved_map_id);
		close(prog_fd);
	}
	CHECK(nr_id_found != nr_iters,
	      "check total prog id found by get_next_id",
	      "nr_id_found %u(%u)\n",
	      nr_id_found, nr_iters);

	/* Check bpf_map_get_next_id() */
	nr_id_found = 0;
	next_id = 0;
	while (!bpf_map_get_next_id(next_id, &next_id)) {
		struct bpf_map_info map_info = {};
		int map_fd;

		info_len = sizeof(map_info);

		map_fd = bpf_map_get_fd_by_id(next_id);
		if (map_fd < 0 && errno == ENOENT)
			/* The bpf_map is in the dead row */
			continue;
		if (CHECK(map_fd < 0, "get-map-fd(next_id)",
			  "map_fd %d next_id %u errno %d\n",
			  map_fd, next_id, errno))
			break;

		for (i = 0; i < nr_iters; i++)
			if (map_infos[i].id == next_id)
				break;

		if (i == nr_iters)
			continue;

		nr_id_found++;

		err = bpf_map_lookup_elem(map_fd, &array_key, &array_value);
		assert(!err);

		err = bpf_obj_get_info_by_fd(map_fd, &map_info, &info_len);
		CHECK(err || info_len != sizeof(struct bpf_map_info) ||
		      memcmp(&map_info, &map_infos[i], info_len) ||
		      array_value != array_magic_value,
		      "check get-map-info(next_id->fd)",
		      "err %d errno %d info_len %u(%Zu) memcmp %d array_value %llu(%llu)\n",
		      err, errno, info_len, sizeof(struct bpf_map_info),
		      memcmp(&map_info, &map_infos[i], info_len),
		      array_value, array_magic_value);

		close(map_fd);
	}
	CHECK(nr_id_found != nr_iters,
	      "check total map id found by get_next_id",
	      "nr_id_found %u(%u)\n",
	      nr_id_found, nr_iters);

done:
	for (i = 0; i < nr_iters; i++)
		bpf_object__close(objs[i]);
}

static void test_pkt_md_access(void)
{
	const char *file = "./test_pkt_md_access.o";
	struct bpf_object *obj;
	__u32 duration, retval;
	int err, prog_fd;

	err = bpf_prog_load(file, BPF_PROG_TYPE_SCHED_CLS, &obj, &prog_fd);
	if (err) {
		error_cnt++;
		return;
	}

	err = bpf_prog_test_run(prog_fd, 10, &pkt_v4, sizeof(pkt_v4),
				NULL, NULL, &retval, &duration);
	CHECK(err || retval, "",
	      "err %d errno %d retval %d duration %d\n",
	      err, errno, retval, duration);

	bpf_object__close(obj);
}

static void test_obj_name(void)
{
	struct {
		const char *name;
		int success;
		int expected_errno;
	} tests[] = {
		{ "", 1, 0 },
		{ "_123456789ABCDE", 1, 0 },
		{ "_123456789ABCDEF", 0, EINVAL },
		{ "_123456789ABCD\n", 0, EINVAL },
	};
	struct bpf_insn prog[] = {
		BPF_ALU64_IMM(BPF_MOV, BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	__u32 duration = 0;
	int i;

	for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
		size_t name_len = strlen(tests[i].name) + 1;
		union bpf_attr attr;
		size_t ncopy;
		int fd;

		/* test different attr.prog_name during BPF_PROG_LOAD */
		ncopy = name_len < sizeof(attr.prog_name) ?
			name_len : sizeof(attr.prog_name);
		bzero(&attr, sizeof(attr));
		attr.prog_type = BPF_PROG_TYPE_SCHED_CLS;
		attr.insn_cnt = 2;
		attr.insns = ptr_to_u64(prog);
		attr.license = ptr_to_u64("");
		memcpy(attr.prog_name, tests[i].name, ncopy);

		fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
		CHECK((tests[i].success && fd < 0) ||
		      (!tests[i].success && fd != -1) ||
		      (!tests[i].success && errno != tests[i].expected_errno),
		      "check-bpf-prog-name",
		      "fd %d(%d) errno %d(%d)\n",
		       fd, tests[i].success, errno, tests[i].expected_errno);

		if (fd != -1)
			close(fd);

		/* test different attr.map_name during BPF_MAP_CREATE */
		ncopy = name_len < sizeof(attr.map_name) ?
			name_len : sizeof(attr.map_name);
		bzero(&attr, sizeof(attr));
		attr.map_type = BPF_MAP_TYPE_ARRAY;
		attr.key_size = 4;
		attr.value_size = 4;
		attr.max_entries = 1;
		attr.map_flags = 0;
		memcpy(attr.map_name, tests[i].name, ncopy);
		fd = syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
		CHECK((tests[i].success && fd < 0) ||
		      (!tests[i].success && fd != -1) ||
		      (!tests[i].success && errno != tests[i].expected_errno),
		      "check-bpf-map-name",
		      "fd %d(%d) errno %d(%d)\n",
		      fd, tests[i].success, errno, tests[i].expected_errno);

		if (fd != -1)
			close(fd);
	}
}

static void test_tp_attach_query(void)
{
	const int num_progs = 3;
	int i, j, bytes, efd, err, prog_fd[num_progs], pmu_fd[num_progs];
	__u32 duration = 0, info_len, saved_prog_ids[num_progs];
	const char *file = "./test_tracepoint.o";
	struct perf_event_query_bpf *query;
	struct perf_event_attr attr = {};
	struct bpf_object *obj[num_progs];
	struct bpf_prog_info prog_info;
	char buf[256];

	snprintf(buf, sizeof(buf),
		 "/sys/kernel/debug/tracing/events/sched/sched_switch/id");
	efd = open(buf, O_RDONLY, 0);
	if (CHECK(efd < 0, "open", "err %d errno %d\n", efd, errno))
		return;
	bytes = read(efd, buf, sizeof(buf));
	close(efd);
	if (CHECK(bytes <= 0 || bytes >= sizeof(buf),
		  "read", "bytes %d errno %d\n", bytes, errno))
		return;

	attr.config = strtol(buf, NULL, 0);
	attr.type = PERF_TYPE_TRACEPOINT;
	attr.sample_type = PERF_SAMPLE_RAW | PERF_SAMPLE_CALLCHAIN;
	attr.sample_period = 1;
	attr.wakeup_events = 1;

	query = malloc(sizeof(*query) + sizeof(__u32) * num_progs);
	for (i = 0; i < num_progs; i++) {
		err = bpf_prog_load(file, BPF_PROG_TYPE_TRACEPOINT, &obj[i],
				    &prog_fd[i]);
		if (CHECK(err, "prog_load", "err %d errno %d\n", err, errno))
			goto cleanup1;

		bzero(&prog_info, sizeof(prog_info));
		prog_info.jited_prog_len = 0;
		prog_info.xlated_prog_len = 0;
		prog_info.nr_map_ids = 0;
		info_len = sizeof(prog_info);
		err = bpf_obj_get_info_by_fd(prog_fd[i], &prog_info, &info_len);
		if (CHECK(err, "bpf_obj_get_info_by_fd", "err %d errno %d\n",
			  err, errno))
			goto cleanup1;
		saved_prog_ids[i] = prog_info.id;

		pmu_fd[i] = syscall(__NR_perf_event_open, &attr, -1 /* pid */,
				    0 /* cpu 0 */, -1 /* group id */,
				    0 /* flags */);
		if (CHECK(pmu_fd[i] < 0, "perf_event_open", "err %d errno %d\n",
			  pmu_fd[i], errno))
			goto cleanup2;
		err = ioctl(pmu_fd[i], PERF_EVENT_IOC_ENABLE, 0);
		if (CHECK(err, "perf_event_ioc_enable", "err %d errno %d\n",
			  err, errno))
			goto cleanup3;

		if (i == 0) {
			/* check NULL prog array query */
			query->ids_len = num_progs;
			err = ioctl(pmu_fd[i], PERF_EVENT_IOC_QUERY_BPF, query);
			if (CHECK(err || query->prog_cnt != 0,
				  "perf_event_ioc_query_bpf",
				  "err %d errno %d query->prog_cnt %u\n",
				  err, errno, query->prog_cnt))
				goto cleanup3;
		}

		err = ioctl(pmu_fd[i], PERF_EVENT_IOC_SET_BPF, prog_fd[i]);
		if (CHECK(err, "perf_event_ioc_set_bpf", "err %d errno %d\n",
			  err, errno))
			goto cleanup3;

		if (i == 1) {
			/* try to get # of programs only */
			query->ids_len = 0;
			err = ioctl(pmu_fd[i], PERF_EVENT_IOC_QUERY_BPF, query);
			if (CHECK(err || query->prog_cnt != 2,
				  "perf_event_ioc_query_bpf",
				  "err %d errno %d query->prog_cnt %u\n",
				  err, errno, query->prog_cnt))
				goto cleanup3;

			/* try a few negative tests */
			/* invalid query pointer */
			err = ioctl(pmu_fd[i], PERF_EVENT_IOC_QUERY_BPF,
				    (struct perf_event_query_bpf *)0x1);
			if (CHECK(!err || errno != EFAULT,
				  "perf_event_ioc_query_bpf",
				  "err %d errno %d\n", err, errno))
				goto cleanup3;

			/* no enough space */
			query->ids_len = 1;
			err = ioctl(pmu_fd[i], PERF_EVENT_IOC_QUERY_BPF, query);
			if (CHECK(!err || errno != ENOSPC || query->prog_cnt != 2,
				  "perf_event_ioc_query_bpf",
				  "err %d errno %d query->prog_cnt %u\n",
				  err, errno, query->prog_cnt))
				goto cleanup3;
		}

		query->ids_len = num_progs;
		err = ioctl(pmu_fd[i], PERF_EVENT_IOC_QUERY_BPF, query);
		if (CHECK(err || query->prog_cnt != (i + 1),
			  "perf_event_ioc_query_bpf",
			  "err %d errno %d query->prog_cnt %u\n",
			  err, errno, query->prog_cnt))
			goto cleanup3;
		for (j = 0; j < i + 1; j++)
			if (CHECK(saved_prog_ids[j] != query->ids[j],
				  "perf_event_ioc_query_bpf",
				  "#%d saved_prog_id %x query prog_id %x\n",
				  j, saved_prog_ids[j], query->ids[j]))
				goto cleanup3;
	}

	i = num_progs - 1;
	for (; i >= 0; i--) {
 cleanup3:
		ioctl(pmu_fd[i], PERF_EVENT_IOC_DISABLE);
 cleanup2:
		close(pmu_fd[i]);
 cleanup1:
		bpf_object__close(obj[i]);
	}
	free(query);
}

static int compare_map_keys(int map1_fd, int map2_fd)
{
	__u32 key, next_key;
	char val_buf[PERF_MAX_STACK_DEPTH *
		     sizeof(struct bpf_stack_build_id)];
	int err;

	err = bpf_map_get_next_key(map1_fd, NULL, &key);
	if (err)
		return err;
	err = bpf_map_lookup_elem(map2_fd, &key, val_buf);
	if (err)
		return err;

	while (bpf_map_get_next_key(map1_fd, &key, &next_key) == 0) {
		err = bpf_map_lookup_elem(map2_fd, &next_key, val_buf);
		if (err)
			return err;

		key = next_key;
	}
	if (errno != ENOENT)
		return -1;

	return 0;
}

static int compare_stack_ips(int smap_fd, int amap_fd, int stack_trace_len)
{
	__u32 key, next_key, *cur_key_p, *next_key_p;
	char *val_buf1, *val_buf2;
	int i, err = 0;

	val_buf1 = malloc(stack_trace_len);
	val_buf2 = malloc(stack_trace_len);
	cur_key_p = NULL;
	next_key_p = &key;
	while (bpf_map_get_next_key(smap_fd, cur_key_p, next_key_p) == 0) {
		err = bpf_map_lookup_elem(smap_fd, next_key_p, val_buf1);
		if (err)
			goto out;
		err = bpf_map_lookup_elem(amap_fd, next_key_p, val_buf2);
		if (err)
			goto out;
		for (i = 0; i < stack_trace_len; i++) {
			if (val_buf1[i] != val_buf2[i]) {
				err = -1;
				goto out;
			}
		}
		key = *next_key_p;
		cur_key_p = &key;
		next_key_p = &next_key;
	}
	if (errno != ENOENT)
		err = -1;

out:
	free(val_buf1);
	free(val_buf2);
	return err;
}

static void test_stacktrace_map()
{
	int control_map_fd, stackid_hmap_fd, stackmap_fd, stack_amap_fd;
	const char *file = "./test_stacktrace_map.o";
	int bytes, efd, err, pmu_fd, prog_fd, stack_trace_len;
	struct perf_event_attr attr = {};
	__u32 key, val, duration = 0;
	struct bpf_object *obj;
	char buf[256];

	err = bpf_prog_load(file, BPF_PROG_TYPE_TRACEPOINT, &obj, &prog_fd);
	if (CHECK(err, "prog_load", "err %d errno %d\n", err, errno))
		return;

	/* Get the ID for the sched/sched_switch tracepoint */
	snprintf(buf, sizeof(buf),
		 "/sys/kernel/debug/tracing/events/sched/sched_switch/id");
	efd = open(buf, O_RDONLY, 0);
	if (CHECK(efd < 0, "open", "err %d errno %d\n", efd, errno))
		goto close_prog;

	bytes = read(efd, buf, sizeof(buf));
	close(efd);
	if (bytes <= 0 || bytes >= sizeof(buf))
		goto close_prog;

	/* Open the perf event and attach bpf progrram */
	attr.config = strtol(buf, NULL, 0);
	attr.type = PERF_TYPE_TRACEPOINT;
	attr.sample_type = PERF_SAMPLE_RAW | PERF_SAMPLE_CALLCHAIN;
	attr.sample_period = 1;
	attr.wakeup_events = 1;
	pmu_fd = syscall(__NR_perf_event_open, &attr, -1 /* pid */,
			 0 /* cpu 0 */, -1 /* group id */,
			 0 /* flags */);
	if (CHECK(pmu_fd < 0, "perf_event_open", "err %d errno %d\n",
		  pmu_fd, errno))
		goto close_prog;

	err = ioctl(pmu_fd, PERF_EVENT_IOC_ENABLE, 0);
	if (err)
		goto disable_pmu;

	err = ioctl(pmu_fd, PERF_EVENT_IOC_SET_BPF, prog_fd);
	if (err)
		goto disable_pmu;

	/* find map fds */
	control_map_fd = bpf_find_map(__func__, obj, "control_map");
	if (control_map_fd < 0)
		goto disable_pmu;

	stackid_hmap_fd = bpf_find_map(__func__, obj, "stackid_hmap");
	if (stackid_hmap_fd < 0)
		goto disable_pmu;

	stackmap_fd = bpf_find_map(__func__, obj, "stackmap");
	if (stackmap_fd < 0)
		goto disable_pmu;

	stack_amap_fd = bpf_find_map(__func__, obj, "stack_amap");
	if (stack_amap_fd < 0)
		goto disable_pmu;

	/* give some time for bpf program run */
	sleep(1);

	/* disable stack trace collection */
	key = 0;
	val = 1;
	bpf_map_update_elem(control_map_fd, &key, &val, 0);

	/* for every element in stackid_hmap, we can find a corresponding one
	 * in stackmap, and vise versa.
	 */
	err = compare_map_keys(stackid_hmap_fd, stackmap_fd);
	if (CHECK(err, "compare_map_keys stackid_hmap vs. stackmap",
		  "err %d errno %d\n", err, errno))
		goto disable_pmu_noerr;

	err = compare_map_keys(stackmap_fd, stackid_hmap_fd);
	if (CHECK(err, "compare_map_keys stackmap vs. stackid_hmap",
		  "err %d errno %d\n", err, errno))
		goto disable_pmu_noerr;

	stack_trace_len = PERF_MAX_STACK_DEPTH * sizeof(__u64);
	err = compare_stack_ips(stackmap_fd, stack_amap_fd, stack_trace_len);
	if (CHECK(err, "compare_stack_ips stackmap vs. stack_amap",
		  "err %d errno %d\n", err, errno))
		goto disable_pmu_noerr;

	goto disable_pmu_noerr;
disable_pmu:
	error_cnt++;
disable_pmu_noerr:
	ioctl(pmu_fd, PERF_EVENT_IOC_DISABLE);
	close(pmu_fd);
close_prog:
	bpf_object__close(obj);
}

static void test_stacktrace_map_raw_tp()
{
	int control_map_fd, stackid_hmap_fd, stackmap_fd;
	const char *file = "./test_stacktrace_map.o";
	int efd, err, prog_fd;
	__u32 key, val, duration = 0;
	struct bpf_object *obj;

	err = bpf_prog_load(file, BPF_PROG_TYPE_RAW_TRACEPOINT, &obj, &prog_fd);
	if (CHECK(err, "prog_load raw tp", "err %d errno %d\n", err, errno))
		return;

	efd = bpf_raw_tracepoint_open("sched_switch", prog_fd);
	if (CHECK(efd < 0, "raw_tp_open", "err %d errno %d\n", efd, errno))
		goto close_prog;

	/* find map fds */
	control_map_fd = bpf_find_map(__func__, obj, "control_map");
	if (control_map_fd < 0)
		goto close_prog;

	stackid_hmap_fd = bpf_find_map(__func__, obj, "stackid_hmap");
	if (stackid_hmap_fd < 0)
		goto close_prog;

	stackmap_fd = bpf_find_map(__func__, obj, "stackmap");
	if (stackmap_fd < 0)
		goto close_prog;

	/* give some time for bpf program run */
	sleep(1);

	/* disable stack trace collection */
	key = 0;
	val = 1;
	bpf_map_update_elem(control_map_fd, &key, &val, 0);

	/* for every element in stackid_hmap, we can find a corresponding one
	 * in stackmap, and vise versa.
	 */
	err = compare_map_keys(stackid_hmap_fd, stackmap_fd);
	if (CHECK(err, "compare_map_keys stackid_hmap vs. stackmap",
		  "err %d errno %d\n", err, errno))
		goto close_prog;

	err = compare_map_keys(stackmap_fd, stackid_hmap_fd);
	if (CHECK(err, "compare_map_keys stackmap vs. stackid_hmap",
		  "err %d errno %d\n", err, errno))
		goto close_prog;

	goto close_prog_noerr;
close_prog:
	error_cnt++;
close_prog_noerr:
	bpf_object__close(obj);
}

static int extract_build_id(char *build_id, size_t size)
{
	FILE *fp;
	char *line = NULL;
	size_t len = 0;

	fp = popen("readelf -n ./urandom_read | grep 'Build ID'", "r");
	if (fp == NULL)
		return -1;

	if (getline(&line, &len, fp) == -1)
		goto err;
	fclose(fp);

	if (len > size)
		len = size;
	memcpy(build_id, line, len);
	build_id[len] = '\0';
	return 0;
err:
	fclose(fp);
	return -1;
}

static void test_stacktrace_build_id(void)
{
	int control_map_fd, stackid_hmap_fd, stackmap_fd, stack_amap_fd;
	const char *file = "./test_stacktrace_build_id.o";
	int bytes, efd, err, pmu_fd, prog_fd, stack_trace_len;
	struct perf_event_attr attr = {};
	__u32 key, previous_key, val, duration = 0;
	struct bpf_object *obj;
	char buf[256];
	int i, j;
	struct bpf_stack_build_id id_offs[PERF_MAX_STACK_DEPTH];
	int build_id_matches = 0;
	int retry = 1;

retry:
	err = bpf_prog_load(file, BPF_PROG_TYPE_TRACEPOINT, &obj, &prog_fd);
	if (CHECK(err, "prog_load", "err %d errno %d\n", err, errno))
		goto out;

	/* Get the ID for the sched/sched_switch tracepoint */
	snprintf(buf, sizeof(buf),
		 "/sys/kernel/debug/tracing/events/random/urandom_read/id");
	efd = open(buf, O_RDONLY, 0);
	if (CHECK(efd < 0, "open", "err %d errno %d\n", efd, errno))
		goto close_prog;

	bytes = read(efd, buf, sizeof(buf));
	close(efd);
	if (CHECK(bytes <= 0 || bytes >= sizeof(buf),
		  "read", "bytes %d errno %d\n", bytes, errno))
		goto close_prog;

	/* Open the perf event and attach bpf progrram */
	attr.config = strtol(buf, NULL, 0);
	attr.type = PERF_TYPE_TRACEPOINT;
	attr.sample_type = PERF_SAMPLE_RAW | PERF_SAMPLE_CALLCHAIN;
	attr.sample_period = 1;
	attr.wakeup_events = 1;
	pmu_fd = syscall(__NR_perf_event_open, &attr, -1 /* pid */,
			 0 /* cpu 0 */, -1 /* group id */,
			 0 /* flags */);
	if (CHECK(pmu_fd < 0, "perf_event_open", "err %d errno %d\n",
		  pmu_fd, errno))
		goto close_prog;

	err = ioctl(pmu_fd, PERF_EVENT_IOC_ENABLE, 0);
	if (CHECK(err, "perf_event_ioc_enable", "err %d errno %d\n",
		  err, errno))
		goto close_pmu;

	err = ioctl(pmu_fd, PERF_EVENT_IOC_SET_BPF, prog_fd);
	if (CHECK(err, "perf_event_ioc_set_bpf", "err %d errno %d\n",
		  err, errno))
		goto disable_pmu;

	/* find map fds */
	control_map_fd = bpf_find_map(__func__, obj, "control_map");
	if (CHECK(control_map_fd < 0, "bpf_find_map control_map",
		  "err %d errno %d\n", err, errno))
		goto disable_pmu;

	stackid_hmap_fd = bpf_find_map(__func__, obj, "stackid_hmap");
	if (CHECK(stackid_hmap_fd < 0, "bpf_find_map stackid_hmap",
		  "err %d errno %d\n", err, errno))
		goto disable_pmu;

	stackmap_fd = bpf_find_map(__func__, obj, "stackmap");
	if (CHECK(stackmap_fd < 0, "bpf_find_map stackmap", "err %d errno %d\n",
		  err, errno))
		goto disable_pmu;

	stack_amap_fd = bpf_find_map(__func__, obj, "stack_amap");
	if (CHECK(stack_amap_fd < 0, "bpf_find_map stack_amap",
		  "err %d errno %d\n", err, errno))
		goto disable_pmu;

	assert(system("dd if=/dev/urandom of=/dev/zero count=4 2> /dev/null")
	       == 0);
	assert(system("./urandom_read") == 0);
	/* disable stack trace collection */
	key = 0;
	val = 1;
	bpf_map_update_elem(control_map_fd, &key, &val, 0);

	/* for every element in stackid_hmap, we can find a corresponding one
	 * in stackmap, and vise versa.
	 */
	err = compare_map_keys(stackid_hmap_fd, stackmap_fd);
	if (CHECK(err, "compare_map_keys stackid_hmap vs. stackmap",
		  "err %d errno %d\n", err, errno))
		goto disable_pmu;

	err = compare_map_keys(stackmap_fd, stackid_hmap_fd);
	if (CHECK(err, "compare_map_keys stackmap vs. stackid_hmap",
		  "err %d errno %d\n", err, errno))
		goto disable_pmu;

	err = extract_build_id(buf, 256);

	if (CHECK(err, "get build_id with readelf",
		  "err %d errno %d\n", err, errno))
		goto disable_pmu;

	err = bpf_map_get_next_key(stackmap_fd, NULL, &key);
	if (CHECK(err, "get_next_key from stackmap",
		  "err %d, errno %d\n", err, errno))
		goto disable_pmu;

	do {
		char build_id[64];

		err = bpf_map_lookup_elem(stackmap_fd, &key, id_offs);
		if (CHECK(err, "lookup_elem from stackmap",
			  "err %d, errno %d\n", err, errno))
			goto disable_pmu;
		for (i = 0; i < PERF_MAX_STACK_DEPTH; ++i)
			if (id_offs[i].status == BPF_STACK_BUILD_ID_VALID &&
			    id_offs[i].offset != 0) {
				for (j = 0; j < 20; ++j)
					sprintf(build_id + 2 * j, "%02x",
						id_offs[i].build_id[j] & 0xff);
				if (strstr(buf, build_id) != NULL)
					build_id_matches = 1;
			}
		previous_key = key;
	} while (bpf_map_get_next_key(stackmap_fd, &previous_key, &key) == 0);

	/* stack_map_get_build_id_offset() is racy and sometimes can return
	 * BPF_STACK_BUILD_ID_IP instead of BPF_STACK_BUILD_ID_VALID;
	 * try it one more time.
	 */
	if (build_id_matches < 1 && retry--) {
		ioctl(pmu_fd, PERF_EVENT_IOC_DISABLE);
		close(pmu_fd);
		bpf_object__close(obj);
		printf("%s:WARN:Didn't find expected build ID from the map, retrying\n",
		       __func__);
		goto retry;
	}

	if (CHECK(build_id_matches < 1, "build id match",
		  "Didn't find expected build ID from the map\n"))
		goto disable_pmu;

	stack_trace_len = PERF_MAX_STACK_DEPTH
		* sizeof(struct bpf_stack_build_id);
	err = compare_stack_ips(stackmap_fd, stack_amap_fd, stack_trace_len);
	CHECK(err, "compare_stack_ips stackmap vs. stack_amap",
	      "err %d errno %d\n", err, errno);

disable_pmu:
	ioctl(pmu_fd, PERF_EVENT_IOC_DISABLE);

close_pmu:
	close(pmu_fd);

close_prog:
	bpf_object__close(obj);

out:
	return;
}

static void test_stacktrace_build_id_nmi(void)
{
	int control_map_fd, stackid_hmap_fd, stackmap_fd, stack_amap_fd;
	const char *file = "./test_stacktrace_build_id.o";
	int err, pmu_fd, prog_fd;
	struct perf_event_attr attr = {
		.sample_freq = 5000,
		.freq = 1,
		.type = PERF_TYPE_HARDWARE,
		.config = PERF_COUNT_HW_CPU_CYCLES,
	};
	__u32 key, previous_key, val, duration = 0;
	struct bpf_object *obj;
	char buf[256];
	int i, j;
	struct bpf_stack_build_id id_offs[PERF_MAX_STACK_DEPTH];
	int build_id_matches = 0;
	int retry = 1;

retry:
	err = bpf_prog_load(file, BPF_PROG_TYPE_PERF_EVENT, &obj, &prog_fd);
	if (CHECK(err, "prog_load", "err %d errno %d\n", err, errno))
		return;

	pmu_fd = syscall(__NR_perf_event_open, &attr, -1 /* pid */,
			 0 /* cpu 0 */, -1 /* group id */,
			 0 /* flags */);
	if (CHECK(pmu_fd < 0, "perf_event_open",
		  "err %d errno %d. Does the test host support PERF_COUNT_HW_CPU_CYCLES?\n",
		  pmu_fd, errno))
		goto close_prog;

	err = ioctl(pmu_fd, PERF_EVENT_IOC_ENABLE, 0);
	if (CHECK(err, "perf_event_ioc_enable", "err %d errno %d\n",
		  err, errno))
		goto close_pmu;

	err = ioctl(pmu_fd, PERF_EVENT_IOC_SET_BPF, prog_fd);
	if (CHECK(err, "perf_event_ioc_set_bpf", "err %d errno %d\n",
		  err, errno))
		goto disable_pmu;

	/* find map fds */
	control_map_fd = bpf_find_map(__func__, obj, "control_map");
	if (CHECK(control_map_fd < 0, "bpf_find_map control_map",
		  "err %d errno %d\n", err, errno))
		goto disable_pmu;

	stackid_hmap_fd = bpf_find_map(__func__, obj, "stackid_hmap");
	if (CHECK(stackid_hmap_fd < 0, "bpf_find_map stackid_hmap",
		  "err %d errno %d\n", err, errno))
		goto disable_pmu;

	stackmap_fd = bpf_find_map(__func__, obj, "stackmap");
	if (CHECK(stackmap_fd < 0, "bpf_find_map stackmap", "err %d errno %d\n",
		  err, errno))
		goto disable_pmu;

	stack_amap_fd = bpf_find_map(__func__, obj, "stack_amap");
	if (CHECK(stack_amap_fd < 0, "bpf_find_map stack_amap",
		  "err %d errno %d\n", err, errno))
		goto disable_pmu;

	assert(system("dd if=/dev/urandom of=/dev/zero count=4 2> /dev/null")
	       == 0);
	assert(system("taskset 0x1 ./urandom_read 100000") == 0);
	/* disable stack trace collection */
	key = 0;
	val = 1;
	bpf_map_update_elem(control_map_fd, &key, &val, 0);

	/* for every element in stackid_hmap, we can find a corresponding one
	 * in stackmap, and vise versa.
	 */
	err = compare_map_keys(stackid_hmap_fd, stackmap_fd);
	if (CHECK(err, "compare_map_keys stackid_hmap vs. stackmap",
		  "err %d errno %d\n", err, errno))
		goto disable_pmu;

	err = compare_map_keys(stackmap_fd, stackid_hmap_fd);
	if (CHECK(err, "compare_map_keys stackmap vs. stackid_hmap",
		  "err %d errno %d\n", err, errno))
		goto disable_pmu;

	err = extract_build_id(buf, 256);

	if (CHECK(err, "get build_id with readelf",
		  "err %d errno %d\n", err, errno))
		goto disable_pmu;

	err = bpf_map_get_next_key(stackmap_fd, NULL, &key);
	if (CHECK(err, "get_next_key from stackmap",
		  "err %d, errno %d\n", err, errno))
		goto disable_pmu;

	do {
		char build_id[64];

		err = bpf_map_lookup_elem(stackmap_fd, &key, id_offs);
		if (CHECK(err, "lookup_elem from stackmap",
			  "err %d, errno %d\n", err, errno))
			goto disable_pmu;
		for (i = 0; i < PERF_MAX_STACK_DEPTH; ++i)
			if (id_offs[i].status == BPF_STACK_BUILD_ID_VALID &&
			    id_offs[i].offset != 0) {
				for (j = 0; j < 20; ++j)
					sprintf(build_id + 2 * j, "%02x",
						id_offs[i].build_id[j] & 0xff);
				if (strstr(buf, build_id) != NULL)
					build_id_matches = 1;
			}
		previous_key = key;
	} while (bpf_map_get_next_key(stackmap_fd, &previous_key, &key) == 0);

	/* stack_map_get_build_id_offset() is racy and sometimes can return
	 * BPF_STACK_BUILD_ID_IP instead of BPF_STACK_BUILD_ID_VALID;
	 * try it one more time.
	 */
	if (build_id_matches < 1 && retry--) {
		ioctl(pmu_fd, PERF_EVENT_IOC_DISABLE);
		close(pmu_fd);
		bpf_object__close(obj);
		printf("%s:WARN:Didn't find expected build ID from the map, retrying\n",
		       __func__);
		goto retry;
	}

	if (CHECK(build_id_matches < 1, "build id match",
		  "Didn't find expected build ID from the map\n"))
		goto disable_pmu;

	/*
	 * We intentionally skip compare_stack_ips(). This is because we
	 * only support one in_nmi() ips-to-build_id translation per cpu
	 * at any time, thus stack_amap here will always fallback to
	 * BPF_STACK_BUILD_ID_IP;
	 */

disable_pmu:
	ioctl(pmu_fd, PERF_EVENT_IOC_DISABLE);

close_pmu:
	close(pmu_fd);

close_prog:
	bpf_object__close(obj);
}

#define MAX_CNT_RAWTP	10ull
#define MAX_STACK_RAWTP	100
struct get_stack_trace_t {
	int pid;
	int kern_stack_size;
	int user_stack_size;
	int user_stack_buildid_size;
	__u64 kern_stack[MAX_STACK_RAWTP];
	__u64 user_stack[MAX_STACK_RAWTP];
	struct bpf_stack_build_id user_stack_buildid[MAX_STACK_RAWTP];
};

static int get_stack_print_output(void *data, int size)
{
	bool good_kern_stack = false, good_user_stack = false;
	const char *nonjit_func = "___bpf_prog_run";
	struct get_stack_trace_t *e = data;
	int i, num_stack;
	static __u64 cnt;
	struct ksym *ks;

	cnt++;

	if (size < sizeof(struct get_stack_trace_t)) {
		__u64 *raw_data = data;
		bool found = false;

		num_stack = size / sizeof(__u64);
		/* If jit is enabled, we do not have a good way to
		 * verify the sanity of the kernel stack. So we
		 * just assume it is good if the stack is not empty.
		 * This could be improved in the future.
		 */
		if (jit_enabled) {
			found = num_stack > 0;
		} else {
			for (i = 0; i < num_stack; i++) {
				ks = ksym_search(raw_data[i]);
				if (strcmp(ks->name, nonjit_func) == 0) {
					found = true;
					break;
				}
			}
		}
		if (found) {
			good_kern_stack = true;
			good_user_stack = true;
		}
	} else {
		num_stack = e->kern_stack_size / sizeof(__u64);
		if (jit_enabled) {
			good_kern_stack = num_stack > 0;
		} else {
			for (i = 0; i < num_stack; i++) {
				ks = ksym_search(e->kern_stack[i]);
				if (strcmp(ks->name, nonjit_func) == 0) {
					good_kern_stack = true;
					break;
				}
			}
		}
		if (e->user_stack_size > 0 && e->user_stack_buildid_size > 0)
			good_user_stack = true;
	}
	if (!good_kern_stack || !good_user_stack)
		return LIBBPF_PERF_EVENT_ERROR;

	if (cnt == MAX_CNT_RAWTP)
		return LIBBPF_PERF_EVENT_DONE;

	return LIBBPF_PERF_EVENT_CONT;
}

static void test_get_stack_raw_tp(void)
{
	const char *file = "./test_get_stack_rawtp.o";
	int i, efd, err, prog_fd, pmu_fd, perfmap_fd;
	struct perf_event_attr attr = {};
	struct timespec tv = {0, 10};
	__u32 key = 0, duration = 0;
	struct bpf_object *obj;

	err = bpf_prog_load(file, BPF_PROG_TYPE_RAW_TRACEPOINT, &obj, &prog_fd);
	if (CHECK(err, "prog_load raw tp", "err %d errno %d\n", err, errno))
		return;

	efd = bpf_raw_tracepoint_open("sys_enter", prog_fd);
	if (CHECK(efd < 0, "raw_tp_open", "err %d errno %d\n", efd, errno))
		goto close_prog;

	perfmap_fd = bpf_find_map(__func__, obj, "perfmap");
	if (CHECK(perfmap_fd < 0, "bpf_find_map", "err %d errno %d\n",
		  perfmap_fd, errno))
		goto close_prog;

	err = load_kallsyms();
	if (CHECK(err < 0, "load_kallsyms", "err %d errno %d\n", err, errno))
		goto close_prog;

	attr.sample_type = PERF_SAMPLE_RAW;
	attr.type = PERF_TYPE_SOFTWARE;
	attr.config = PERF_COUNT_SW_BPF_OUTPUT;
	pmu_fd = syscall(__NR_perf_event_open, &attr, getpid()/*pid*/, -1/*cpu*/,
			 -1/*group_fd*/, 0);
	if (CHECK(pmu_fd < 0, "perf_event_open", "err %d errno %d\n", pmu_fd,
		  errno))
		goto close_prog;

	err = bpf_map_update_elem(perfmap_fd, &key, &pmu_fd, BPF_ANY);
	if (CHECK(err < 0, "bpf_map_update_elem", "err %d errno %d\n", err,
		  errno))
		goto close_prog;

	err = ioctl(pmu_fd, PERF_EVENT_IOC_ENABLE, 0);
	if (CHECK(err < 0, "ioctl PERF_EVENT_IOC_ENABLE", "err %d errno %d\n",
		  err, errno))
		goto close_prog;

	err = perf_event_mmap(pmu_fd);
	if (CHECK(err < 0, "perf_event_mmap", "err %d errno %d\n", err, errno))
		goto close_prog;

	/* trigger some syscall action */
	for (i = 0; i < MAX_CNT_RAWTP; i++)
		nanosleep(&tv, NULL);

	err = perf_event_poller(pmu_fd, get_stack_print_output);
	if (CHECK(err < 0, "perf_event_poller", "err %d errno %d\n", err, errno))
		goto close_prog;

	goto close_prog_noerr;
close_prog:
	error_cnt++;
close_prog_noerr:
	bpf_object__close(obj);
}

static void test_task_fd_query_rawtp(void)
{
	const char *file = "./test_get_stack_rawtp.o";
	__u64 probe_offset, probe_addr;
	__u32 len, prog_id, fd_type;
	struct bpf_object *obj;
	int efd, err, prog_fd;
	__u32 duration = 0;
	char buf[256];

	err = bpf_prog_load(file, BPF_PROG_TYPE_RAW_TRACEPOINT, &obj, &prog_fd);
	if (CHECK(err, "prog_load raw tp", "err %d errno %d\n", err, errno))
		return;

	efd = bpf_raw_tracepoint_open("sys_enter", prog_fd);
	if (CHECK(efd < 0, "raw_tp_open", "err %d errno %d\n", efd, errno))
		goto close_prog;

	/* query (getpid(), efd) */
	len = sizeof(buf);
	err = bpf_task_fd_query(getpid(), efd, 0, buf, &len, &prog_id,
				&fd_type, &probe_offset, &probe_addr);
	if (CHECK(err < 0, "bpf_task_fd_query", "err %d errno %d\n", err,
		  errno))
		goto close_prog;

	err = fd_type == BPF_FD_TYPE_RAW_TRACEPOINT &&
	      strcmp(buf, "sys_enter") == 0;
	if (CHECK(!err, "check_results", "fd_type %d tp_name %s\n",
		  fd_type, buf))
		goto close_prog;

	/* test zero len */
	len = 0;
	err = bpf_task_fd_query(getpid(), efd, 0, buf, &len, &prog_id,
				&fd_type, &probe_offset, &probe_addr);
	if (CHECK(err < 0, "bpf_task_fd_query (len = 0)", "err %d errno %d\n",
		  err, errno))
		goto close_prog;
	err = fd_type == BPF_FD_TYPE_RAW_TRACEPOINT &&
	      len == strlen("sys_enter");
	if (CHECK(!err, "check_results", "fd_type %d len %u\n", fd_type, len))
		goto close_prog;

	/* test empty buffer */
	len = sizeof(buf);
	err = bpf_task_fd_query(getpid(), efd, 0, 0, &len, &prog_id,
				&fd_type, &probe_offset, &probe_addr);
	if (CHECK(err < 0, "bpf_task_fd_query (buf = 0)", "err %d errno %d\n",
		  err, errno))
		goto close_prog;
	err = fd_type == BPF_FD_TYPE_RAW_TRACEPOINT &&
	      len == strlen("sys_enter");
	if (CHECK(!err, "check_results", "fd_type %d len %u\n", fd_type, len))
		goto close_prog;

	/* test smaller buffer */
	len = 3;
	err = bpf_task_fd_query(getpid(), efd, 0, buf, &len, &prog_id,
				&fd_type, &probe_offset, &probe_addr);
	if (CHECK(err >= 0 || errno != ENOSPC, "bpf_task_fd_query (len = 3)",
		  "err %d errno %d\n", err, errno))
		goto close_prog;
	err = fd_type == BPF_FD_TYPE_RAW_TRACEPOINT &&
	      len == strlen("sys_enter") &&
	      strcmp(buf, "sy") == 0;
	if (CHECK(!err, "check_results", "fd_type %d len %u\n", fd_type, len))
		goto close_prog;

	goto close_prog_noerr;
close_prog:
	error_cnt++;
close_prog_noerr:
	bpf_object__close(obj);
}

static void test_task_fd_query_tp_core(const char *probe_name,
				       const char *tp_name)
{
	const char *file = "./test_tracepoint.o";
	int err, bytes, efd, prog_fd, pmu_fd;
	struct perf_event_attr attr = {};
	__u64 probe_offset, probe_addr;
	__u32 len, prog_id, fd_type;
	struct bpf_object *obj;
	__u32 duration = 0;
	char buf[256];

	err = bpf_prog_load(file, BPF_PROG_TYPE_TRACEPOINT, &obj, &prog_fd);
	if (CHECK(err, "bpf_prog_load", "err %d errno %d\n", err, errno))
		goto close_prog;

	snprintf(buf, sizeof(buf),
		 "/sys/kernel/debug/tracing/events/%s/id", probe_name);
	efd = open(buf, O_RDONLY, 0);
	if (CHECK(efd < 0, "open", "err %d errno %d\n", efd, errno))
		goto close_prog;
	bytes = read(efd, buf, sizeof(buf));
	close(efd);
	if (CHECK(bytes <= 0 || bytes >= sizeof(buf), "read",
		  "bytes %d errno %d\n", bytes, errno))
		goto close_prog;

	attr.config = strtol(buf, NULL, 0);
	attr.type = PERF_TYPE_TRACEPOINT;
	attr.sample_type = PERF_SAMPLE_RAW;
	attr.sample_period = 1;
	attr.wakeup_events = 1;
	pmu_fd = syscall(__NR_perf_event_open, &attr, -1 /* pid */,
			 0 /* cpu 0 */, -1 /* group id */,
			 0 /* flags */);
	if (CHECK(err, "perf_event_open", "err %d errno %d\n", err, errno))
		goto close_pmu;

	err = ioctl(pmu_fd, PERF_EVENT_IOC_ENABLE, 0);
	if (CHECK(err, "perf_event_ioc_enable", "err %d errno %d\n", err,
		  errno))
		goto close_pmu;

	err = ioctl(pmu_fd, PERF_EVENT_IOC_SET_BPF, prog_fd);
	if (CHECK(err, "perf_event_ioc_set_bpf", "err %d errno %d\n", err,
		  errno))
		goto close_pmu;

	/* query (getpid(), pmu_fd) */
	len = sizeof(buf);
	err = bpf_task_fd_query(getpid(), pmu_fd, 0, buf, &len, &prog_id,
				&fd_type, &probe_offset, &probe_addr);
	if (CHECK(err < 0, "bpf_task_fd_query", "err %d errno %d\n", err,
		  errno))
		goto close_pmu;

	err = (fd_type == BPF_FD_TYPE_TRACEPOINT) && !strcmp(buf, tp_name);
	if (CHECK(!err, "check_results", "fd_type %d tp_name %s\n",
		  fd_type, buf))
		goto close_pmu;

	close(pmu_fd);
	goto close_prog_noerr;

close_pmu:
	close(pmu_fd);
close_prog:
	error_cnt++;
close_prog_noerr:
	bpf_object__close(obj);
}

static void test_task_fd_query_tp(void)
{
	test_task_fd_query_tp_core("sched/sched_switch",
				   "sched_switch");
	test_task_fd_query_tp_core("syscalls/sys_enter_read",
				   "sys_enter_read");
}

static int libbpf_debug_print(enum libbpf_print_level level,
			      const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;

	return vfprintf(stderr, format, args);
}

static void test_reference_tracking()
{
	const char *file = "./test_sk_lookup_kern.o";
	struct bpf_object *obj;
	struct bpf_program *prog;
	__u32 duration = 0;
	int err = 0;

	obj = bpf_object__open(file);
	if (IS_ERR(obj)) {
		error_cnt++;
		return;
	}

	bpf_object__for_each_program(prog, obj) {
		const char *title;

		/* Ignore .text sections */
		title = bpf_program__title(prog, false);
		if (strstr(title, ".text") != NULL)
			continue;

		bpf_program__set_type(prog, BPF_PROG_TYPE_SCHED_CLS);

		/* Expect verifier failure if test name has 'fail' */
		if (strstr(title, "fail") != NULL) {
			libbpf_set_print(NULL);
			err = !bpf_program__load(prog, "GPL", 0);
			libbpf_set_print(libbpf_debug_print);
		} else {
			err = bpf_program__load(prog, "GPL", 0);
		}
		CHECK(err, title, "\n");
	}
	bpf_object__close(obj);
}

enum {
	QUEUE,
	STACK,
};

static void test_queue_stack_map(int type)
{
	const int MAP_SIZE = 32;
	__u32 vals[MAP_SIZE], duration, retval, size, val;
	int i, err, prog_fd, map_in_fd, map_out_fd;
	char file[32], buf[128];
	struct bpf_object *obj;
	struct iphdr *iph = (void *)buf + sizeof(struct ethhdr);

	/* Fill test values to be used */
	for (i = 0; i < MAP_SIZE; i++)
		vals[i] = rand();

	if (type == QUEUE)
		strncpy(file, "./test_queue_map.o", sizeof(file));
	else if (type == STACK)
		strncpy(file, "./test_stack_map.o", sizeof(file));
	else
		return;

	err = bpf_prog_load(file, BPF_PROG_TYPE_SCHED_CLS, &obj, &prog_fd);
	if (err) {
		error_cnt++;
		return;
	}

	map_in_fd = bpf_find_map(__func__, obj, "map_in");
	if (map_in_fd < 0)
		goto out;

	map_out_fd = bpf_find_map(__func__, obj, "map_out");
	if (map_out_fd < 0)
		goto out;

	/* Push 32 elements to the input map */
	for (i = 0; i < MAP_SIZE; i++) {
		err = bpf_map_update_elem(map_in_fd, NULL, &vals[i], 0);
		if (err) {
			error_cnt++;
			goto out;
		}
	}

	/* The eBPF program pushes iph.saddr in the output map,
	 * pops the input map and saves this value in iph.daddr
	 */
	for (i = 0; i < MAP_SIZE; i++) {
		if (type == QUEUE) {
			val = vals[i];
			pkt_v4.iph.saddr = vals[i] * 5;
		} else if (type == STACK) {
			val = vals[MAP_SIZE - 1 - i];
			pkt_v4.iph.saddr = vals[MAP_SIZE - 1 - i] * 5;
		}

		err = bpf_prog_test_run(prog_fd, 1, &pkt_v4, sizeof(pkt_v4),
					buf, &size, &retval, &duration);
		if (err || retval || size != sizeof(pkt_v4) ||
		    iph->daddr != val)
			break;
	}

	CHECK(err || retval || size != sizeof(pkt_v4) || iph->daddr != val,
	      "bpf_map_pop_elem",
	      "err %d errno %d retval %d size %d iph->daddr %u\n",
	      err, errno, retval, size, iph->daddr);

	/* Queue is empty, program should return TC_ACT_SHOT */
	err = bpf_prog_test_run(prog_fd, 1, &pkt_v4, sizeof(pkt_v4),
				buf, &size, &retval, &duration);
	CHECK(err || retval != 2 /* TC_ACT_SHOT */|| size != sizeof(pkt_v4),
	      "check-queue-stack-map-empty",
	      "err %d errno %d retval %d size %d\n",
	      err, errno, retval, size);

	/* Check that the program pushed elements correctly */
	for (i = 0; i < MAP_SIZE; i++) {
		err = bpf_map_lookup_and_delete_elem(map_out_fd, NULL, &val);
		if (err || val != vals[i] * 5)
			break;
	}

	CHECK(i != MAP_SIZE && (err || val != vals[i] * 5),
	      "bpf_map_push_elem", "err %d value %u\n", err, val);

out:
	pkt_v4.iph.saddr = 0;
	bpf_object__close(obj);
}

#define CHECK_FLOW_KEYS(desc, got, expected)				\
	CHECK_ATTR(memcmp(&got, &expected, sizeof(got)) != 0,		\
	      desc,							\
	      "nhoff=%u/%u "						\
	      "thoff=%u/%u "						\
	      "addr_proto=0x%x/0x%x "					\
	      "is_frag=%u/%u "						\
	      "is_first_frag=%u/%u "					\
	      "is_encap=%u/%u "						\
	      "ip_proto=0x%x/0x%x "					\
	      "n_proto=0x%x/0x%x "					\
	      "flow_label=0x%x/0x%x "					\
	      "sport=%u/%u "						\
	      "dport=%u/%u\n",						\
	      got.nhoff, expected.nhoff,				\
	      got.thoff, expected.thoff,				\
	      got.addr_proto, expected.addr_proto,			\
	      got.is_frag, expected.is_frag,				\
	      got.is_first_frag, expected.is_first_frag,		\
	      got.is_encap, expected.is_encap,				\
	      got.ip_proto, expected.ip_proto,				\
	      got.n_proto, expected.n_proto,				\
	      got.flow_label, expected.flow_label,			\
	      got.sport, expected.sport,				\
	      got.dport, expected.dport)

struct ipv4_pkt {
	struct ethhdr eth;
	struct iphdr iph;
	struct tcphdr tcp;
} __packed;

struct ipip_pkt {
	struct ethhdr eth;
	struct iphdr iph;
	struct iphdr iph_inner;
	struct tcphdr tcp;
} __packed;

struct svlan_ipv4_pkt {
	struct ethhdr eth;
	__u16 vlan_tci;
	__u16 vlan_proto;
	struct iphdr iph;
	struct tcphdr tcp;
} __packed;

struct ipv6_pkt {
	struct ethhdr eth;
	struct ipv6hdr iph;
	struct tcphdr tcp;
} __packed;

struct ipv6_frag_pkt {
	struct ethhdr eth;
	struct ipv6hdr iph;
	struct frag_hdr {
		__u8 nexthdr;
		__u8 reserved;
		__be16 frag_off;
		__be32 identification;
	} ipf;
	struct tcphdr tcp;
} __packed;

struct dvlan_ipv6_pkt {
	struct ethhdr eth;
	__u16 vlan_tci;
	__u16 vlan_proto;
	__u16 vlan_tci2;
	__u16 vlan_proto2;
	struct ipv6hdr iph;
	struct tcphdr tcp;
} __packed;

struct test {
	const char *name;
	union {
		struct ipv4_pkt ipv4;
		struct svlan_ipv4_pkt svlan_ipv4;
		struct ipip_pkt ipip;
		struct ipv6_pkt ipv6;
		struct ipv6_frag_pkt ipv6_frag;
		struct dvlan_ipv6_pkt dvlan_ipv6;
	} pkt;
	struct bpf_flow_keys keys;
	__u32 flags;
};

#define VLAN_HLEN	4

struct test tests[] = {
	{
		.name = "ipv4",
		.pkt.ipv4 = {
			.eth.h_proto = __bpf_constant_htons(ETH_P_IP),
			.iph.ihl = 5,
			.iph.protocol = IPPROTO_TCP,
			.iph.tot_len = __bpf_constant_htons(MAGIC_BYTES),
			.tcp.doff = 5,
			.tcp.source = 80,
			.tcp.dest = 8080,
		},
		.keys = {
			.nhoff = ETH_HLEN,
			.thoff = ETH_HLEN + sizeof(struct iphdr),
			.addr_proto = ETH_P_IP,
			.ip_proto = IPPROTO_TCP,
			.n_proto = __bpf_constant_htons(ETH_P_IP),
			.sport = 80,
			.dport = 8080,
		},
	},
	{
		.name = "ipv6",
		.pkt.ipv6 = {
			.eth.h_proto = __bpf_constant_htons(ETH_P_IPV6),
			.iph.nexthdr = IPPROTO_TCP,
			.iph.payload_len = __bpf_constant_htons(MAGIC_BYTES),
			.tcp.doff = 5,
			.tcp.source = 80,
			.tcp.dest = 8080,
		},
		.keys = {
			.nhoff = ETH_HLEN,
			.thoff = ETH_HLEN + sizeof(struct ipv6hdr),
			.addr_proto = ETH_P_IPV6,
			.ip_proto = IPPROTO_TCP,
			.n_proto = __bpf_constant_htons(ETH_P_IPV6),
			.sport = 80,
			.dport = 8080,
		},
	},
	{
		.name = "802.1q-ipv4",
		.pkt.svlan_ipv4 = {
			.eth.h_proto = __bpf_constant_htons(ETH_P_8021Q),
			.vlan_proto = __bpf_constant_htons(ETH_P_IP),
			.iph.ihl = 5,
			.iph.protocol = IPPROTO_TCP,
			.iph.tot_len = __bpf_constant_htons(MAGIC_BYTES),
			.tcp.doff = 5,
			.tcp.source = 80,
			.tcp.dest = 8080,
		},
		.keys = {
			.nhoff = ETH_HLEN + VLAN_HLEN,
			.thoff = ETH_HLEN + VLAN_HLEN + sizeof(struct iphdr),
			.addr_proto = ETH_P_IP,
			.ip_proto = IPPROTO_TCP,
			.n_proto = __bpf_constant_htons(ETH_P_IP),
			.sport = 80,
			.dport = 8080,
		},
	},
	{
		.name = "802.1ad-ipv6",
		.pkt.dvlan_ipv6 = {
			.eth.h_proto = __bpf_constant_htons(ETH_P_8021AD),
			.vlan_proto = __bpf_constant_htons(ETH_P_8021Q),
			.vlan_proto2 = __bpf_constant_htons(ETH_P_IPV6),
			.iph.nexthdr = IPPROTO_TCP,
			.iph.payload_len = __bpf_constant_htons(MAGIC_BYTES),
			.tcp.doff = 5,
			.tcp.source = 80,
			.tcp.dest = 8080,
		},
		.keys = {
			.nhoff = ETH_HLEN + VLAN_HLEN * 2,
			.thoff = ETH_HLEN + VLAN_HLEN * 2 +
				sizeof(struct ipv6hdr),
			.addr_proto = ETH_P_IPV6,
			.ip_proto = IPPROTO_TCP,
			.n_proto = __bpf_constant_htons(ETH_P_IPV6),
			.sport = 80,
			.dport = 8080,
		},
	},
	{
		.name = "ipv4-frag",
		.pkt.ipv4 = {
			.eth.h_proto = __bpf_constant_htons(ETH_P_IP),
			.iph.ihl = 5,
			.iph.protocol = IPPROTO_TCP,
			.iph.tot_len = __bpf_constant_htons(MAGIC_BYTES),
			.iph.frag_off = __bpf_constant_htons(IP_MF),
			.tcp.doff = 5,
			.tcp.source = 80,
			.tcp.dest = 8080,
		},
		.keys = {
			.flags = BPF_FLOW_DISSECTOR_F_PARSE_1ST_FRAG,
			.nhoff = ETH_HLEN,
			.thoff = ETH_HLEN + sizeof(struct iphdr),
			.addr_proto = ETH_P_IP,
			.ip_proto = IPPROTO_TCP,
			.n_proto = __bpf_constant_htons(ETH_P_IP),
			.is_frag = true,
			.is_first_frag = true,
			.sport = 80,
			.dport = 8080,
		},
		.flags = BPF_FLOW_DISSECTOR_F_PARSE_1ST_FRAG,
	},
	{
		.name = "ipv4-no-frag",
		.pkt.ipv4 = {
			.eth.h_proto = __bpf_constant_htons(ETH_P_IP),
			.iph.ihl = 5,
			.iph.protocol = IPPROTO_TCP,
			.iph.tot_len = __bpf_constant_htons(MAGIC_BYTES),
			.iph.frag_off = __bpf_constant_htons(IP_MF),
			.tcp.doff = 5,
			.tcp.source = 80,
			.tcp.dest = 8080,
		},
		.keys = {
			.nhoff = ETH_HLEN,
			.thoff = ETH_HLEN + sizeof(struct iphdr),
			.addr_proto = ETH_P_IP,
			.ip_proto = IPPROTO_TCP,
			.n_proto = __bpf_constant_htons(ETH_P_IP),
			.is_frag = true,
			.is_first_frag = true,
		},
	},
	{
		.name = "ipv6-frag",
		.pkt.ipv6_frag = {
			.eth.h_proto = __bpf_constant_htons(ETH_P_IPV6),
			.iph.nexthdr = IPPROTO_FRAGMENT,
			.iph.payload_len = __bpf_constant_htons(MAGIC_BYTES),
			.ipf.nexthdr = IPPROTO_TCP,
			.tcp.doff = 5,
			.tcp.source = 80,
			.tcp.dest = 8080,
		},
		.keys = {
			.flags = BPF_FLOW_DISSECTOR_F_PARSE_1ST_FRAG,
			.nhoff = ETH_HLEN,
			.thoff = ETH_HLEN + sizeof(struct ipv6hdr) +
				sizeof(struct frag_hdr),
			.addr_proto = ETH_P_IPV6,
			.ip_proto = IPPROTO_TCP,
			.n_proto = __bpf_constant_htons(ETH_P_IPV6),
			.is_frag = true,
			.is_first_frag = true,
			.sport = 80,
			.dport = 8080,
		},
		.flags = BPF_FLOW_DISSECTOR_F_PARSE_1ST_FRAG,
	},
	{
		.name = "ipv6-no-frag",
		.pkt.ipv6_frag = {
			.eth.h_proto = __bpf_constant_htons(ETH_P_IPV6),
			.iph.nexthdr = IPPROTO_FRAGMENT,
			.iph.payload_len = __bpf_constant_htons(MAGIC_BYTES),
			.ipf.nexthdr = IPPROTO_TCP,
			.tcp.doff = 5,
			.tcp.source = 80,
			.tcp.dest = 8080,
		},
		.keys = {
			.nhoff = ETH_HLEN,
			.thoff = ETH_HLEN + sizeof(struct ipv6hdr) +
				sizeof(struct frag_hdr),
			.addr_proto = ETH_P_IPV6,
			.ip_proto = IPPROTO_TCP,
			.n_proto = __bpf_constant_htons(ETH_P_IPV6),
			.is_frag = true,
			.is_first_frag = true,
		},
	},
	{
		.name = "ipv6-flow-label",
		.pkt.ipv6 = {
			.eth.h_proto = __bpf_constant_htons(ETH_P_IPV6),
			.iph.nexthdr = IPPROTO_TCP,
			.iph.payload_len = __bpf_constant_htons(MAGIC_BYTES),
			.iph.flow_lbl = { 0xb, 0xee, 0xef },
			.tcp.doff = 5,
			.tcp.source = 80,
			.tcp.dest = 8080,
		},
		.keys = {
			.nhoff = ETH_HLEN,
			.thoff = ETH_HLEN + sizeof(struct ipv6hdr),
			.addr_proto = ETH_P_IPV6,
			.ip_proto = IPPROTO_TCP,
			.n_proto = __bpf_constant_htons(ETH_P_IPV6),
			.sport = 80,
			.dport = 8080,
			.flow_label = __bpf_constant_htonl(0xbeeef),
		},
	},
	{
		.name = "ipv6-no-flow-label",
		.pkt.ipv6 = {
			.eth.h_proto = __bpf_constant_htons(ETH_P_IPV6),
			.iph.nexthdr = IPPROTO_TCP,
			.iph.payload_len = __bpf_constant_htons(MAGIC_BYTES),
			.iph.flow_lbl = { 0xb, 0xee, 0xef },
			.tcp.doff = 5,
			.tcp.source = 80,
			.tcp.dest = 8080,
		},
		.keys = {
			.flags = BPF_FLOW_DISSECTOR_F_STOP_AT_FLOW_LABEL,
			.nhoff = ETH_HLEN,
			.thoff = ETH_HLEN + sizeof(struct ipv6hdr),
			.addr_proto = ETH_P_IPV6,
			.ip_proto = IPPROTO_TCP,
			.n_proto = __bpf_constant_htons(ETH_P_IPV6),
			.flow_label = __bpf_constant_htonl(0xbeeef),
		},
		.flags = BPF_FLOW_DISSECTOR_F_STOP_AT_FLOW_LABEL,
	},
	{
		.name = "ipip-encap",
		.pkt.ipip = {
			.eth.h_proto = __bpf_constant_htons(ETH_P_IP),
			.iph.ihl = 5,
			.iph.protocol = IPPROTO_IPIP,
			.iph.tot_len = __bpf_constant_htons(MAGIC_BYTES),
			.iph_inner.ihl = 5,
			.iph_inner.protocol = IPPROTO_TCP,
			.iph_inner.tot_len =
				__bpf_constant_htons(MAGIC_BYTES) -
				sizeof(struct iphdr),
			.tcp.doff = 5,
			.tcp.source = 80,
			.tcp.dest = 8080,
		},
		.keys = {
			.nhoff = 0,
			.nhoff = ETH_HLEN,
			.thoff = ETH_HLEN + sizeof(struct iphdr) +
				sizeof(struct iphdr),
			.addr_proto = ETH_P_IP,
			.ip_proto = IPPROTO_TCP,
			.n_proto = __bpf_constant_htons(ETH_P_IP),
			.is_encap = true,
			.sport = 80,
			.dport = 8080,
		},
	},
	{
		.name = "ipip-no-encap",
		.pkt.ipip = {
			.eth.h_proto = __bpf_constant_htons(ETH_P_IP),
			.iph.ihl = 5,
			.iph.protocol = IPPROTO_IPIP,
			.iph.tot_len = __bpf_constant_htons(MAGIC_BYTES),
			.iph_inner.ihl = 5,
			.iph_inner.protocol = IPPROTO_TCP,
			.iph_inner.tot_len =
				__bpf_constant_htons(MAGIC_BYTES) -
				sizeof(struct iphdr),
			.tcp.doff = 5,
			.tcp.source = 80,
			.tcp.dest = 8080,
		},
		.keys = {
			.flags = BPF_FLOW_DISSECTOR_F_STOP_AT_ENCAP,
			.nhoff = ETH_HLEN,
			.thoff = ETH_HLEN + sizeof(struct iphdr),
			.addr_proto = ETH_P_IP,
			.ip_proto = IPPROTO_IPIP,
			.n_proto = __bpf_constant_htons(ETH_P_IP),
			.is_encap = true,
		},
		.flags = BPF_FLOW_DISSECTOR_F_STOP_AT_ENCAP,
	},

};

static int create_tap(const char *ifname)
{
	struct ifreq ifr = {
		.ifr_flags = IFF_TAP | IFF_NO_PI | IFF_NAPI | IFF_NAPI_FRAGS,
	};
	int fd, ret;

	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	fd = open("/dev/net/tun", O_RDWR);
	if (fd < 0)
		return -1;

	ret = ioctl(fd, TUNSETIFF, &ifr);
	if (ret)
		return -1;

	return fd;
}

static int tx_tap(int fd, void *pkt, size_t len)
{
	struct iovec iov[] = {
		{
			.iov_len = len,
			.iov_base = pkt,
		},
	};
	return writev(fd, iov, ARRAY_SIZE(iov));
}

static int ifup(const char *ifname)
{
	struct ifreq ifr = {};
	int sk, ret;

	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	sk = socket(PF_INET, SOCK_DGRAM, 0);
	if (sk < 0)
		return -1;

	ret = ioctl(sk, SIOCGIFFLAGS, &ifr);
	if (ret) {
		close(sk);
		return -1;
	}

	ifr.ifr_flags |= IFF_UP;
	ret = ioctl(sk, SIOCSIFFLAGS, &ifr);
	if (ret) {
		close(sk);
		return -1;
	}

	close(sk);
	return 0;
}

static void test_flow_dissector(void)
{
	int i, err, prog_fd, keys_fd = -1, tap_fd;
	struct bpf_object *obj;
	__u32 duration = 0;

	err = bpf_flow_load(&obj, "./bpf_flow.o", "flow_dissector",
			    "jmp_table", "last_dissection", &prog_fd, &keys_fd);
	if (err) {
		error_cnt++;
		return;
	}

	for (i = 0; i < ARRAY_SIZE(tests); i++) {
		struct bpf_flow_keys flow_keys;
		struct bpf_prog_test_run_attr tattr = {
			.prog_fd = prog_fd,
			.data_in = &tests[i].pkt,
			.data_size_in = sizeof(tests[i].pkt),
			.data_out = &flow_keys,
		};
		static struct bpf_flow_keys ctx = {};

		if (tests[i].flags) {
			tattr.ctx_in = &ctx;
			tattr.ctx_size_in = sizeof(ctx);
			ctx.flags = tests[i].flags;
		}

		err = bpf_prog_test_run_xattr(&tattr);
		CHECK_ATTR(tattr.data_size_out != sizeof(flow_keys) ||
			   err || tattr.retval != 1,
			   tests[i].name,
			   "err %d errno %d retval %d duration %d size %u/%lu\n",
			   err, errno, tattr.retval, tattr.duration,
			   tattr.data_size_out, sizeof(flow_keys));
		CHECK_FLOW_KEYS(tests[i].name, flow_keys, tests[i].keys);
	}

	/* Do the same tests but for skb-less flow dissector.
	 * We use a known path in the net/tun driver that calls
	 * eth_get_headlen and we manually export bpf_flow_keys
	 * via BPF map in this case.
	 */

	err = bpf_prog_attach(prog_fd, 0, BPF_FLOW_DISSECTOR, 0);
	CHECK(err, "bpf_prog_attach", "err %d errno %d\n", err, errno);

	tap_fd = create_tap("tap0");
	CHECK(tap_fd < 0, "create_tap", "tap_fd %d errno %d\n", tap_fd, errno);
	err = ifup("tap0");
	CHECK(err, "ifup", "err %d errno %d\n", err, errno);

	for (i = 0; i < ARRAY_SIZE(tests); i++) {
		/* Keep in sync with 'flags' from eth_get_headlen. */
		__u32 eth_get_headlen_flags =
			BPF_FLOW_DISSECTOR_F_PARSE_1ST_FRAG;
		struct bpf_prog_test_run_attr tattr = {};
		struct bpf_flow_keys flow_keys = {};
		__u32 key = (__u32)(tests[i].keys.sport) << 16 |
			    tests[i].keys.dport;

		/* For skb-less case we can't pass input flags; run
		 * only the tests that have a matching set of flags.
		 */

		if (tests[i].flags != eth_get_headlen_flags)
			continue;

		err = tx_tap(tap_fd, &tests[i].pkt, sizeof(tests[i].pkt));
		CHECK(err < 0, "tx_tap", "err %d errno %d\n", err, errno);

		err = bpf_map_lookup_elem(keys_fd, &key, &flow_keys);
		CHECK_ATTR(err, tests[i].name, "bpf_map_lookup_elem %d\n", err);

		CHECK_ATTR(err, tests[i].name, "skb-less err %d\n", err);
		CHECK_FLOW_KEYS(tests[i].name, flow_keys, tests[i].keys);

		err = bpf_map_delete_elem(keys_fd, &key);
		CHECK_ATTR(err, tests[i].name, "bpf_map_delete_elem %d\n", err);
	}

	close(tap_fd);
	bpf_prog_detach(prog_fd, BPF_FLOW_DISSECTOR);
	bpf_object__close(obj);
}

static void *test_spin_lock(void *arg)
{
	__u32 duration, retval;
	int err, prog_fd = *(u32 *) arg;

	err = bpf_prog_test_run(prog_fd, 10000, &pkt_v4, sizeof(pkt_v4),
				NULL, NULL, &retval, &duration);
	CHECK(err || retval, "",
	      "err %d errno %d retval %d duration %d\n",
	      err, errno, retval, duration);
	pthread_exit(arg);
}

static void test_spinlock(void)
{
	const char *file = "./test_spin_lock.o";
	pthread_t thread_id[4];
	struct bpf_object *obj = NULL;
	int prog_fd;
	int err = 0, i;
	void *ret;

	err = bpf_prog_load(file, BPF_PROG_TYPE_CGROUP_SKB, &obj, &prog_fd);
	if (err) {
		printf("test_spin_lock:bpf_prog_load errno %d\n", errno);
		goto close_prog;
	}
	for (i = 0; i < 4; i++)
		assert(pthread_create(&thread_id[i], NULL,
				      &test_spin_lock, &prog_fd) == 0);
	for (i = 0; i < 4; i++)
		assert(pthread_join(thread_id[i], &ret) == 0 &&
		       ret == (void *)&prog_fd);
	goto close_prog_noerr;
close_prog:
	error_cnt++;
close_prog_noerr:
	bpf_object__close(obj);
}

static void *parallel_map_access(void *arg)
{
	int err, map_fd = *(u32 *) arg;
	int vars[17], i, j, rnd, key = 0;

	for (i = 0; i < 10000; i++) {
		err = bpf_map_lookup_elem_flags(map_fd, &key, vars, BPF_F_LOCK);
		if (err) {
			printf("lookup failed\n");
			error_cnt++;
			goto out;
		}
		if (vars[0] != 0) {
			printf("lookup #%d var[0]=%d\n", i, vars[0]);
			error_cnt++;
			goto out;
		}
		rnd = vars[1];
		for (j = 2; j < 17; j++) {
			if (vars[j] == rnd)
				continue;
			printf("lookup #%d var[1]=%d var[%d]=%d\n",
			       i, rnd, j, vars[j]);
			error_cnt++;
			goto out;
		}
	}
out:
	pthread_exit(arg);
}

static void test_map_lock(void)
{
	const char *file = "./test_map_lock.o";
	int prog_fd, map_fd[2], vars[17] = {};
	pthread_t thread_id[6];
	struct bpf_object *obj = NULL;
	int err = 0, key = 0, i;
	void *ret;

	err = bpf_prog_load(file, BPF_PROG_TYPE_CGROUP_SKB, &obj, &prog_fd);
	if (err) {
		printf("test_map_lock:bpf_prog_load errno %d\n", errno);
		goto close_prog;
	}
	map_fd[0] = bpf_find_map(__func__, obj, "hash_map");
	if (map_fd[0] < 0)
		goto close_prog;
	map_fd[1] = bpf_find_map(__func__, obj, "array_map");
	if (map_fd[1] < 0)
		goto close_prog;

	bpf_map_update_elem(map_fd[0], &key, vars, BPF_F_LOCK);

	for (i = 0; i < 4; i++)
		assert(pthread_create(&thread_id[i], NULL,
				      &test_spin_lock, &prog_fd) == 0);
	for (i = 4; i < 6; i++)
		assert(pthread_create(&thread_id[i], NULL,
				      &parallel_map_access, &map_fd[i - 4]) == 0);
	for (i = 0; i < 4; i++)
		assert(pthread_join(thread_id[i], &ret) == 0 &&
		       ret == (void *)&prog_fd);
	for (i = 4; i < 6; i++)
		assert(pthread_join(thread_id[i], &ret) == 0 &&
		       ret == (void *)&map_fd[i - 4]);
	goto close_prog_noerr;
close_prog:
	error_cnt++;
close_prog_noerr:
	bpf_object__close(obj);
}

static void sigalrm_handler(int s) {}
static struct sigaction sigalrm_action = {
	.sa_handler = sigalrm_handler,
};

static void test_signal_pending(enum bpf_prog_type prog_type)
{
	struct bpf_insn prog[4096];
	struct itimerval timeo = {
		.it_value.tv_usec = 100000, /* 100ms */
	};
	__u32 duration, retval;
	int prog_fd;
	int err;
	int i;

	for (i = 0; i < ARRAY_SIZE(prog); i++)
		prog[i] = BPF_ALU64_IMM(BPF_MOV, BPF_REG_0, 0);
	prog[ARRAY_SIZE(prog) - 1] = BPF_EXIT_INSN();

	prog_fd = bpf_load_program(prog_type, prog, ARRAY_SIZE(prog),
				   "GPL", 0, NULL, 0);
	CHECK(prog_fd < 0, "test-run", "errno %d\n", errno);

	err = sigaction(SIGALRM, &sigalrm_action, NULL);
	CHECK(err, "test-run-signal-sigaction", "errno %d\n", errno);

	err = setitimer(ITIMER_REAL, &timeo, NULL);
	CHECK(err, "test-run-signal-timer", "errno %d\n", errno);

	err = bpf_prog_test_run(prog_fd, 0xffffffff, &pkt_v4, sizeof(pkt_v4),
				NULL, NULL, &retval, &duration);
	CHECK(duration > 500000000, /* 500ms */
	      "test-run-signal-duration",
	      "duration %dns > 500ms\n",
	      duration);

	signal(SIGALRM, SIG_DFL);
}

static int libbpf_debug_print_verifier_scale(enum libbpf_print_level level,
			      const char *format, va_list args)
{
	if (level != LIBBPF_DEBUG)
		return vfprintf(stderr, format, args);

	if (!strstr(format, "verifier log"))
		return 0;
	return vfprintf(stderr, "%s", args);
}

static int check_load(const char *file, enum bpf_prog_type type)
{
	struct bpf_prog_load_attr attr;
	struct bpf_object *obj = NULL;
	int err, prog_fd;

	memset(&attr, 0, sizeof(struct bpf_prog_load_attr));
	attr.file = file;
	attr.prog_type = type;
	attr.log_level = 4;
	err = bpf_prog_load_xattr(&attr, &obj, &prog_fd);
	bpf_object__close(obj);
	if (err)
		error_cnt++;
	return err;
}

void test_bpf_verif_scale(void)
{
	const char *sched_cls[] = {
		"./test_verif_scale1.o", "./test_verif_scale2.o", "./test_verif_scale3.o",
	};
	const char *raw_tp[] = {
		/* full unroll by llvm */
		"./pyperf50.o",	"./pyperf100.o", "./pyperf180.o",

		/* partial unroll. llvm will unroll loop ~150 times.
		 * C loop count -> 600.
		 * Asm loop count -> 4.
		 * 16k insns in loop body.
		 * Total of 5 such loops. Total program size ~82k insns.
		 */
		"./pyperf600.o",

		/* no unroll at all.
		 * C loop count -> 600.
		 * ASM loop count -> 600.
		 * ~110 insns in loop body.
		 * Total of 5 such loops. Total program size ~1500 insns.
		 */
		"./pyperf600_nounroll.o",

		"./loop1.o", "./loop2.o",

		/* partial unroll. 19k insn in a loop.
		 * Total program size 20.8k insn.
		 * ~350k processed_insns
		 */
		"./strobemeta.o",

		/* no unroll, tiny loops */
		"./strobemeta_nounroll1.o",
		"./strobemeta_nounroll2.o",
	};
	const char *cg_sysctl[] = {
		"./test_sysctl_loop1.o", "./test_sysctl_loop2.o",
	};
	int err, i;

	if (verifier_stats)
		libbpf_set_print(libbpf_debug_print_verifier_scale);

	err = check_load("./loop3.o", BPF_PROG_TYPE_RAW_TRACEPOINT);
	printf("test_scale:loop3:%s\n", err ? (error_cnt--, "OK") : "FAIL");

	for (i = 0; i < ARRAY_SIZE(sched_cls); i++) {
		err = check_load(sched_cls[i], BPF_PROG_TYPE_SCHED_CLS);
		printf("test_scale:%s:%s\n", sched_cls[i], err ? "FAIL" : "OK");
	}

	for (i = 0; i < ARRAY_SIZE(raw_tp); i++) {
		err = check_load(raw_tp[i], BPF_PROG_TYPE_RAW_TRACEPOINT);
		printf("test_scale:%s:%s\n", raw_tp[i], err ? "FAIL" : "OK");
	}

	for (i = 0; i < ARRAY_SIZE(cg_sysctl); i++) {
		err = check_load(cg_sysctl[i], BPF_PROG_TYPE_CGROUP_SYSCTL);
		printf("test_scale:%s:%s\n", cg_sysctl[i], err ? "FAIL" : "OK");
	}
	err = check_load("./test_xdp_loop.o", BPF_PROG_TYPE_XDP);
	printf("test_scale:test_xdp_loop:%s\n", err ? "FAIL" : "OK");

	err = check_load("./test_seg6_loop.o", BPF_PROG_TYPE_LWT_SEG6LOCAL);
	printf("test_scale:test_seg6_loop:%s\n", err ? "FAIL" : "OK");
}

static void test_global_data_number(struct bpf_object *obj, __u32 duration)
{
	int i, err, map_fd;
	uint64_t num;

	map_fd = bpf_find_map(__func__, obj, "result_number");
	if (map_fd < 0) {
		error_cnt++;
		return;
	}

	struct {
		char *name;
		uint32_t key;
		uint64_t num;
	} tests[] = {
		{ "relocate .bss reference",     0, 0 },
		{ "relocate .data reference",    1, 42 },
		{ "relocate .rodata reference",  2, 24 },
		{ "relocate .bss reference",     3, 0 },
		{ "relocate .data reference",    4, 0xffeeff },
		{ "relocate .rodata reference",  5, 0xabab },
		{ "relocate .bss reference",     6, 1234 },
		{ "relocate .bss reference",     7, 0 },
		{ "relocate .rodata reference",  8, 0xab },
		{ "relocate .rodata reference",  9, 0x1111111111111111 },
		{ "relocate .rodata reference", 10, ~0 },
	};

	for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
		err = bpf_map_lookup_elem(map_fd, &tests[i].key, &num);
		CHECK(err || num != tests[i].num, tests[i].name,
		      "err %d result %lx expected %lx\n",
		      err, num, tests[i].num);
	}
}

static void test_global_data_string(struct bpf_object *obj, __u32 duration)
{
	int i, err, map_fd;
	char str[32];

	map_fd = bpf_find_map(__func__, obj, "result_string");
	if (map_fd < 0) {
		error_cnt++;
		return;
	}

	struct {
		char *name;
		uint32_t key;
		char str[32];
	} tests[] = {
		{ "relocate .rodata reference", 0, "abcdefghijklmnopqrstuvwxyz" },
		{ "relocate .data reference",   1, "abcdefghijklmnopqrstuvwxyz" },
		{ "relocate .bss reference",    2, "" },
		{ "relocate .data reference",   3, "abcdexghijklmnopqrstuvwxyz" },
		{ "relocate .bss reference",    4, "\0\0hello" },
	};

	for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
		err = bpf_map_lookup_elem(map_fd, &tests[i].key, str);
		CHECK(err || memcmp(str, tests[i].str, sizeof(str)),
		      tests[i].name, "err %d result \'%s\' expected \'%s\'\n",
		      err, str, tests[i].str);
	}
}

struct foo {
	__u8  a;
	__u32 b;
	__u64 c;
};

static void test_global_data_struct(struct bpf_object *obj, __u32 duration)
{
	int i, err, map_fd;
	struct foo val;

	map_fd = bpf_find_map(__func__, obj, "result_struct");
	if (map_fd < 0) {
		error_cnt++;
		return;
	}

	struct {
		char *name;
		uint32_t key;
		struct foo val;
	} tests[] = {
		{ "relocate .rodata reference", 0, { 42, 0xfefeefef, 0x1111111111111111ULL, } },
		{ "relocate .bss reference",    1, { } },
		{ "relocate .rodata reference", 2, { } },
		{ "relocate .data reference",   3, { 41, 0xeeeeefef, 0x2111111111111111ULL, } },
	};

	for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
		err = bpf_map_lookup_elem(map_fd, &tests[i].key, &val);
		CHECK(err || memcmp(&val, &tests[i].val, sizeof(val)),
		      tests[i].name, "err %d result { %u, %u, %llu } expected { %u, %u, %llu }\n",
		      err, val.a, val.b, val.c, tests[i].val.a, tests[i].val.b, tests[i].val.c);
	}
}

static void test_global_data_rdonly(struct bpf_object *obj, __u32 duration)
{
	int err = -ENOMEM, map_fd, zero = 0;
	struct bpf_map *map;
	__u8 *buff;

	map = bpf_object__find_map_by_name(obj, "test_glo.rodata");
	if (!map || !bpf_map__is_internal(map)) {
		error_cnt++;
		return;
	}

	map_fd = bpf_map__fd(map);
	if (map_fd < 0) {
		error_cnt++;
		return;
	}

	buff = malloc(bpf_map__def(map)->value_size);
	if (buff)
		err = bpf_map_update_elem(map_fd, &zero, buff, 0);
	free(buff);
	CHECK(!err || errno != EPERM, "test .rodata read-only map",
	      "err %d errno %d\n", err, errno);
}

void test_global_data(void)
{
	const char *file = "./test_global_data.o";
	__u32 duration = 0, retval;
	struct bpf_object *obj;
	int err, prog_fd;

	err = bpf_prog_load(file, BPF_PROG_TYPE_SCHED_CLS, &obj, &prog_fd);
	if (CHECK(err, "load program", "error %d loading %s\n", err, file))
		return;

	err = bpf_prog_test_run(prog_fd, 1, &pkt_v4, sizeof(pkt_v4),
				NULL, NULL, &retval, &duration);
	CHECK(err || retval, "pass global data run",
	      "err %d errno %d retval %d duration %d\n",
	      err, errno, retval, duration);

	test_global_data_number(obj, duration);
	test_global_data_string(obj, duration);
	test_global_data_struct(obj, duration);
	test_global_data_rdonly(obj, duration);

	bpf_object__close(obj);
}

static void test_flow_dissector_load_bytes(void)
{
	struct bpf_flow_keys flow_keys;
	__u32 duration = 0, retval, size;
	struct bpf_insn prog[] = {
		// BPF_REG_1 - 1st argument: context
		// BPF_REG_2 - 2nd argument: offset, start at first byte
		BPF_MOV64_IMM(BPF_REG_2, 0),
		// BPF_REG_3 - 3rd argument: destination, reserve byte on stack
		BPF_ALU64_REG(BPF_MOV, BPF_REG_3, BPF_REG_10),
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, -1),
		// BPF_REG_4 - 4th argument: copy one byte
		BPF_MOV64_IMM(BPF_REG_4, 1),
		// bpf_skb_load_bytes(ctx, sizeof(pkt_v4), ptr, 1)
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0,
			     BPF_FUNC_skb_load_bytes),
		BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 2),
		// if (ret == 0) return BPF_DROP (2)
		BPF_MOV64_IMM(BPF_REG_0, BPF_DROP),
		BPF_EXIT_INSN(),
		// if (ret != 0) return BPF_OK (0)
		BPF_MOV64_IMM(BPF_REG_0, BPF_OK),
		BPF_EXIT_INSN(),
	};
	int fd, err;

	/* make sure bpf_skb_load_bytes is not allowed from skb-less context
	 */
	fd = bpf_load_program(BPF_PROG_TYPE_FLOW_DISSECTOR, prog,
			      ARRAY_SIZE(prog), "GPL", 0, NULL, 0);
	CHECK(fd < 0,
	      "flow_dissector-bpf_skb_load_bytes-load",
	      "fd %d errno %d\n",
	      fd, errno);

	err = bpf_prog_test_run(fd, 1, &pkt_v4, sizeof(pkt_v4),
				&flow_keys, &size, &retval, &duration);
	CHECK(size != sizeof(flow_keys) || err || retval != 1,
	      "flow_dissector-bpf_skb_load_bytes",
	      "err %d errno %d retval %d duration %d size %u/%zu\n",
	      err, errno, retval, duration, size, sizeof(flow_keys));

	if (fd >= -1)
		close(fd);
}

static void test_raw_tp_writable_reject_nbd_invalid(void)
{
	__u32 duration = 0;
	char error[4096];
	int bpf_fd = -1, tp_fd = -1;

	const struct bpf_insn program[] = {
		/* r6 is our tp buffer */
		BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_1, 0),
		/* one byte beyond the end of the nbd_request struct */
		BPF_LDX_MEM(BPF_B, BPF_REG_0, BPF_REG_6,
			    sizeof(struct nbd_request)),
		BPF_EXIT_INSN(),
	};

	struct bpf_load_program_attr load_attr = {
		.prog_type = BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE,
		.license = "GPL v2",
		.insns = program,
		.insns_cnt = sizeof(program) / sizeof(struct bpf_insn),
		.log_level = 2,
	};

	bpf_fd = bpf_load_program_xattr(&load_attr, error, sizeof(error));
	if (CHECK(bpf_fd < 0, "bpf_raw_tracepoint_writable load",
		  "failed: %d errno %d\n", bpf_fd, errno))
		return;

	tp_fd = bpf_raw_tracepoint_open("nbd_send_request", bpf_fd);
	if (CHECK(tp_fd >= 0, "bpf_raw_tracepoint_writable open",
		  "erroneously succeeded\n"))
		goto out_bpffd;

	close(tp_fd);
out_bpffd:
	close(bpf_fd);
}

static void test_raw_tp_writable_test_run(void)
{
	__u32 duration = 0;
	char error[4096];

	const struct bpf_insn trace_program[] = {
		BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_1, 0),
		BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_6, 0),
		BPF_MOV64_IMM(BPF_REG_0, 42),
		BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};

	struct bpf_load_program_attr load_attr = {
		.prog_type = BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE,
		.license = "GPL v2",
		.insns = trace_program,
		.insns_cnt = sizeof(trace_program) / sizeof(struct bpf_insn),
		.log_level = 2,
	};

	int bpf_fd = bpf_load_program_xattr(&load_attr, error, sizeof(error));
	if (CHECK(bpf_fd < 0, "bpf_raw_tracepoint_writable loaded",
		  "failed: %d errno %d\n", bpf_fd, errno))
		return;

	const struct bpf_insn skb_program[] = {
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};

	struct bpf_load_program_attr skb_load_attr = {
		.prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
		.license = "GPL v2",
		.insns = skb_program,
		.insns_cnt = sizeof(skb_program) / sizeof(struct bpf_insn),
	};

	int filter_fd =
		bpf_load_program_xattr(&skb_load_attr, error, sizeof(error));
	if (CHECK(filter_fd < 0, "test_program_loaded", "failed: %d errno %d\n",
		  filter_fd, errno))
		goto out_bpffd;

	int tp_fd = bpf_raw_tracepoint_open("bpf_test_finish", bpf_fd);
	if (CHECK(tp_fd < 0, "bpf_raw_tracepoint_writable opened",
		  "failed: %d errno %d\n", tp_fd, errno))
		goto out_filterfd;

	char test_skb[128] = {
		0,
	};

	__u32 prog_ret;
	int err = bpf_prog_test_run(filter_fd, 1, test_skb, sizeof(test_skb), 0,
				    0, &prog_ret, 0);
	CHECK(err != 42, "test_run",
	      "tracepoint did not modify return value\n");
	CHECK(prog_ret != 0, "test_run_ret",
	      "socket_filter did not return 0\n");

	close(tp_fd);

	err = bpf_prog_test_run(filter_fd, 1, test_skb, sizeof(test_skb), 0, 0,
				&prog_ret, 0);
	CHECK(err != 0, "test_run_notrace",
	      "test_run failed with %d errno %d\n", err, errno);
	CHECK(prog_ret != 0, "test_run_ret_notrace",
	      "socket_filter did not return 0\n");

out_filterfd:
	close(filter_fd);
out_bpffd:
	close(bpf_fd);
}

static volatile int sigusr1_received = 0;

static void sigusr1_handler(int signum)
{
	sigusr1_received++;
}

static int test_send_signal_common(struct perf_event_attr *attr,
				    int prog_type,
				    const char *test_name)
{
	int err = -1, pmu_fd, prog_fd, info_map_fd, status_map_fd;
	const char *file = "./test_send_signal_kern.o";
	struct bpf_object *obj = NULL;
	int pipe_c2p[2], pipe_p2c[2];
	__u32 key = 0, duration = 0;
	char buf[256];
	pid_t pid;
	__u64 val;

	if (CHECK(pipe(pipe_c2p), test_name,
		  "pipe pipe_c2p error: %s\n", strerror(errno)))
		goto no_fork_done;

	if (CHECK(pipe(pipe_p2c), test_name,
		  "pipe pipe_p2c error: %s\n", strerror(errno))) {
		close(pipe_c2p[0]);
		close(pipe_c2p[1]);
		goto no_fork_done;
	}

	pid = fork();
	if (CHECK(pid < 0, test_name, "fork error: %s\n", strerror(errno))) {
		close(pipe_c2p[0]);
		close(pipe_c2p[1]);
		close(pipe_p2c[0]);
		close(pipe_p2c[1]);
		goto no_fork_done;
	}

	if (pid == 0) {
		/* install signal handler and notify parent */
		signal(SIGUSR1, sigusr1_handler);

		close(pipe_c2p[0]); /* close read */
		close(pipe_p2c[1]); /* close write */

		/* notify parent signal handler is installed */
		write(pipe_c2p[1], buf, 1);

		/* make sure parent enabled bpf program to send_signal */
		read(pipe_p2c[0], buf, 1);

		/* wait a little for signal handler */
		sleep(1);

		if (sigusr1_received)
			write(pipe_c2p[1], "2", 1);
		else
			write(pipe_c2p[1], "0", 1);

		/* wait for parent notification and exit */
		read(pipe_p2c[0], buf, 1);

		close(pipe_c2p[1]);
		close(pipe_p2c[0]);
		exit(0);
	}

	close(pipe_c2p[1]); /* close write */
	close(pipe_p2c[0]); /* close read */

	err = bpf_prog_load(file, prog_type, &obj, &prog_fd);
	if (CHECK(err < 0, test_name, "bpf_prog_load error: %s\n",
		  strerror(errno)))
		goto prog_load_failure;

	pmu_fd = syscall(__NR_perf_event_open, attr, pid, -1,
			 -1 /* group id */, 0 /* flags */);
	if (CHECK(pmu_fd < 0, test_name, "perf_event_open error: %s\n",
		  strerror(errno))) {
		err = -1;
		goto close_prog;
	}

	err = ioctl(pmu_fd, PERF_EVENT_IOC_ENABLE, 0);
	if (CHECK(err < 0, test_name, "ioctl perf_event_ioc_enable error: %s\n",
		  strerror(errno)))
		goto disable_pmu;

	err = ioctl(pmu_fd, PERF_EVENT_IOC_SET_BPF, prog_fd);
	if (CHECK(err < 0, test_name, "ioctl perf_event_ioc_set_bpf error: %s\n",
		  strerror(errno)))
		goto disable_pmu;

	err = -1;
	info_map_fd = bpf_object__find_map_fd_by_name(obj, "info_map");
	if (CHECK(info_map_fd < 0, test_name, "find map %s error\n", "info_map"))
		goto disable_pmu;

	status_map_fd = bpf_object__find_map_fd_by_name(obj, "status_map");
	if (CHECK(status_map_fd < 0, test_name, "find map %s error\n", "status_map"))
		goto disable_pmu;

	/* wait until child signal handler installed */
	read(pipe_c2p[0], buf, 1);

	/* trigger the bpf send_signal */
	key = 0;
	val = (((__u64)(SIGUSR1)) << 32) | pid;
	bpf_map_update_elem(info_map_fd, &key, &val, 0);

	/* notify child that bpf program can send_signal now */
	write(pipe_p2c[1], buf, 1);

	/* wait for result */
	err = read(pipe_c2p[0], buf, 1);
	if (CHECK(err < 0, test_name, "reading pipe error: %s\n", strerror(errno)))
		goto disable_pmu;
	if (CHECK(err == 0, test_name, "reading pipe error: size 0\n")) {
		err = -1;
		goto disable_pmu;
	}

	err = CHECK(buf[0] != '2', test_name, "incorrect result\n");

	/* notify child safe to exit */
	write(pipe_p2c[1], buf, 1);

disable_pmu:
	close(pmu_fd);
close_prog:
	bpf_object__close(obj);
prog_load_failure:
	close(pipe_c2p[0]);
	close(pipe_p2c[1]);
	wait(NULL);
no_fork_done:
	return err;
}

static int test_send_signal_tracepoint(void)
{
	const char *id_path = "/sys/kernel/debug/tracing/events/syscalls/sys_enter_nanosleep/id";
	struct perf_event_attr attr = {
		.type = PERF_TYPE_TRACEPOINT,
		.sample_type = PERF_SAMPLE_RAW | PERF_SAMPLE_CALLCHAIN,
		.sample_period = 1,
		.wakeup_events = 1,
	};
	__u32 duration = 0;
	int bytes, efd;
	char buf[256];

	efd = open(id_path, O_RDONLY, 0);
	if (CHECK(efd < 0, "tracepoint",
		  "open syscalls/sys_enter_nanosleep/id failure: %s\n",
		  strerror(errno)))
		return -1;

	bytes = read(efd, buf, sizeof(buf));
	close(efd);
	if (CHECK(bytes <= 0 || bytes >= sizeof(buf), "tracepoint",
		  "read syscalls/sys_enter_nanosleep/id failure: %s\n",
		  strerror(errno)))
		return -1;

	attr.config = strtol(buf, NULL, 0);

	return test_send_signal_common(&attr, BPF_PROG_TYPE_TRACEPOINT, "tracepoint");
}

static int test_send_signal_nmi(void)
{
	struct perf_event_attr attr = {
		.sample_freq = 50,
		.freq = 1,
		.type = PERF_TYPE_HARDWARE,
		.config = PERF_COUNT_HW_CPU_CYCLES,
	};

	return test_send_signal_common(&attr, BPF_PROG_TYPE_PERF_EVENT, "perf_event");
}

static void test_send_signal(void)
{
	int ret = 0;

	ret |= test_send_signal_tracepoint();
	ret |= test_send_signal_nmi();
	if (!ret)
		printf("test_send_signal:OK\n");
	else
		printf("test_send_signal:FAIL\n");
}

static void on_sample(void *ctx, int cpu, void *data, __u32 size)
{
	int cpu_data = *(int *)data, duration = 0;
	cpu_set_t *cpu_seen = ctx;

	if (cpu_data != cpu)
		CHECK(cpu_data != cpu, "check_cpu_data",
		      "cpu_data %d != cpu %d\n", cpu_data, cpu);

	CPU_SET(cpu, cpu_seen);
}

static void test_perf_buffer(void)
{
	int err, prog_fd, nr_cpus, i, duration = 0;
	const char *prog_name = "kprobe/sys_nanosleep";
	const char *file = "./test_perf_buffer.o";
	struct perf_buffer_opts pb_opts = {};
	struct bpf_map *perf_buf_map;
	cpu_set_t cpu_set, cpu_seen;
	struct bpf_program *prog;
	struct bpf_object *obj;
	struct perf_buffer *pb;
	struct bpf_link *link;

	nr_cpus = libbpf_num_possible_cpus();
	if (CHECK(nr_cpus < 0, "nr_cpus", "err %d\n", nr_cpus))
		return;

	/* load program */
	err = bpf_prog_load(file, BPF_PROG_TYPE_KPROBE, &obj, &prog_fd);
	if (CHECK(err, "obj_load", "err %d errno %d\n", err, errno))
		return;

	prog = bpf_object__find_program_by_title(obj, prog_name);
	if (CHECK(!prog, "find_probe", "prog '%s' not found\n", prog_name))
		goto out_close;

	/* load map */
	perf_buf_map = bpf_object__find_map_by_name(obj, "perf_buf_map");
	if (CHECK(!perf_buf_map, "find_perf_buf_map", "not found\n"))
		goto out_close;

	/* attach kprobe */
	link = bpf_program__attach_kprobe(prog, false /* retprobe */,
					  SYS_KPROBE_NAME);
	if (CHECK(IS_ERR(link), "attach_kprobe", "err %ld\n", PTR_ERR(link)))
		goto out_close;

	/* set up perf buffer */
	pb_opts.sample_cb = on_sample;
	pb_opts.ctx = &cpu_seen;
	pb = perf_buffer__new(bpf_map__fd(perf_buf_map), 1, &pb_opts);
	if (CHECK(IS_ERR(pb), "perf_buf__new", "err %ld\n", PTR_ERR(pb)))
		goto out_detach;

	/* trigger kprobe on every CPU */
	CPU_ZERO(&cpu_seen);
	for (i = 0; i < nr_cpus; i++) {
		CPU_ZERO(&cpu_set);
		CPU_SET(i, &cpu_set);

		err = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set),
					     &cpu_set);
		if (err && CHECK(err, "set_affinity", "cpu #%d, err %d\n",
				 i, err))
			goto out_detach;

		usleep(1);
	}

	/* read perf buffer */
	err = perf_buffer__poll(pb, 100);
	if (CHECK(err < 0, "perf_buffer__poll", "err %d\n", err))
		goto out_free_pb;

	if (CHECK(CPU_COUNT(&cpu_seen) != nr_cpus, "seen_cpu_cnt",
		  "expect %d, seen %d\n", nr_cpus, CPU_COUNT(&cpu_seen)))
		goto out_free_pb;

out_free_pb:
	perf_buffer__free(pb);
out_detach:
	bpf_link__destroy(link);
out_close:
	bpf_object__close(obj);
}

#include "progs/core_reloc_types.h"

#define STRUCT_TO_CHAR_PTR(struct_name) (const char *)&(struct struct_name)

#define FLAVORS_DATA(struct_name) STRUCT_TO_CHAR_PTR(struct_name) {	\
	.a = 42,							\
	.b = 0xc001,							\
	.c = 0xbeef,							\
}

#define FLAVORS_CASE_COMMON(name)					\
	.case_name = #name,						\
	.bpf_obj_file = "test_core_reloc_flavors.o",			\
	.btf_src_file = "btf__core_reloc_" #name ".o"			\

#define FLAVORS_CASE(name) {						\
	FLAVORS_CASE_COMMON(name),					\
	.input = FLAVORS_DATA(core_reloc_##name),			\
	.input_len = sizeof(struct core_reloc_##name),			\
	.output = FLAVORS_DATA(core_reloc_flavors),			\
	.output_len = sizeof(struct core_reloc_flavors),		\
}

#define FLAVORS_ERR_CASE(name) {					\
	FLAVORS_CASE_COMMON(name),					\
	.fails = true,							\
}

#define NESTING_DATA(struct_name) STRUCT_TO_CHAR_PTR(struct_name) {	\
	.a = { .a = { .a = 42 } },					\
	.b = { .b = { .b = 0xc001 } },					\
}

#define NESTING_CASE_COMMON(name)					\
	.case_name = #name,						\
	.bpf_obj_file = "test_core_reloc_nesting.o",			\
	.btf_src_file = "btf__core_reloc_" #name ".o"

#define NESTING_CASE(name) {						\
	NESTING_CASE_COMMON(name),					\
	.input = NESTING_DATA(core_reloc_##name),			\
	.input_len = sizeof(struct core_reloc_##name),			\
	.output = NESTING_DATA(core_reloc_nesting),			\
	.output_len = sizeof(struct core_reloc_nesting)			\
}

#define NESTING_ERR_CASE(name) {					\
	NESTING_CASE_COMMON(name),					\
	.fails = true,							\
}

#define ARRAYS_DATA(struct_name) STRUCT_TO_CHAR_PTR(struct_name) {	\
	.a = { [2] = 1 },						\
	.b = { [1] = { [2] = { [3] = 2 } } },				\
	.c = { [1] = { .c =  3 } },					\
	.d = { [0] = { [0] = { .d = 4 } } },				\
}

#define ARRAYS_CASE_COMMON(name)					\
	.case_name = #name,						\
	.bpf_obj_file = "test_core_reloc_arrays.o",			\
	.btf_src_file = "btf__core_reloc_" #name ".o"

#define ARRAYS_CASE(name) {						\
	ARRAYS_CASE_COMMON(name),					\
	.input = ARRAYS_DATA(core_reloc_##name),			\
	.input_len = sizeof(struct core_reloc_##name),			\
	.output = STRUCT_TO_CHAR_PTR(core_reloc_arrays_output) {	\
		.a2   = 1,						\
		.b123 = 2,						\
		.c1c  = 3,						\
		.d00d = 4,						\
	},								\
	.output_len = sizeof(struct core_reloc_arrays_output)		\
}

#define ARRAYS_ERR_CASE(name) {						\
	ARRAYS_CASE_COMMON(name),					\
	.fails = true,							\
}

#define PRIMITIVES_DATA(struct_name) STRUCT_TO_CHAR_PTR(struct_name) {	\
	.a = 1,								\
	.b = 2,								\
	.c = 3,								\
	.d = (void *)4,							\
	.f = (void *)5,							\
}

#define PRIMITIVES_CASE_COMMON(name)					\
	.case_name = #name,						\
	.bpf_obj_file = "test_core_reloc_primitives.o",			\
	.btf_src_file = "btf__core_reloc_" #name ".o"

#define PRIMITIVES_CASE(name) {						\
	PRIMITIVES_CASE_COMMON(name),					\
	.input = PRIMITIVES_DATA(core_reloc_##name),			\
	.input_len = sizeof(struct core_reloc_##name),			\
	.output = PRIMITIVES_DATA(core_reloc_primitives),		\
	.output_len = sizeof(struct core_reloc_primitives),		\
}

#define PRIMITIVES_ERR_CASE(name) {					\
	PRIMITIVES_CASE_COMMON(name),					\
	.fails = true,							\
}

#define MODS_CASE(name) {						\
	.case_name = #name,						\
	.bpf_obj_file = "test_core_reloc_mods.o",			\
	.btf_src_file = "btf__core_reloc_" #name ".o",			\
	.input = STRUCT_TO_CHAR_PTR(core_reloc_##name) {		\
		.a = 1,							\
		.b = 2,							\
		.c = (void *)3,						\
		.d = (void *)4,						\
		.e = { [2] = 5 },					\
		.f = { [1] = 6 },					\
		.g = { .x = 7 },					\
		.h = { .y = 8 },					\
	},								\
	.input_len = sizeof(struct core_reloc_##name),			\
	.output = STRUCT_TO_CHAR_PTR(core_reloc_mods_output) {		\
		.a = 1, .b = 2, .c = 3, .d = 4,				\
		.e = 5, .f = 6, .g = 7, .h = 8,				\
	},								\
	.output_len = sizeof(struct core_reloc_mods_output),		\
}

#define PTR_AS_ARR_CASE(name) {						\
	.case_name = #name,						\
	.bpf_obj_file = "test_core_reloc_ptr_as_arr.o",			\
	.btf_src_file = "btf__core_reloc_" #name ".o",			\
	.input = (const char *)&(struct core_reloc_##name []){		\
		{ .a = 1 },						\
		{ .a = 2 },						\
		{ .a = 3 },						\
	},								\
	.input_len = 3 * sizeof(struct core_reloc_##name),		\
	.output = STRUCT_TO_CHAR_PTR(core_reloc_ptr_as_arr) {		\
		.a = 3,							\
	},								\
	.output_len = sizeof(struct core_reloc_ptr_as_arr),		\
}

#define INTS_DATA(struct_name) STRUCT_TO_CHAR_PTR(struct_name) {	\
	.u8_field = 1,							\
	.s8_field = 2,							\
	.u16_field = 3,							\
	.s16_field = 4,							\
	.u32_field = 5,							\
	.s32_field = 6,							\
	.u64_field = 7,							\
	.s64_field = 8,							\
}

#define INTS_CASE_COMMON(name)						\
	.case_name = #name,						\
	.bpf_obj_file = "test_core_reloc_ints.o",			\
	.btf_src_file = "btf__core_reloc_" #name ".o"

#define INTS_CASE(name) {						\
	INTS_CASE_COMMON(name),						\
	.input = INTS_DATA(core_reloc_##name),				\
	.input_len = sizeof(struct core_reloc_##name),			\
	.output = INTS_DATA(core_reloc_ints),				\
	.output_len = sizeof(struct core_reloc_ints),			\
}

#define INTS_ERR_CASE(name) {						\
	INTS_CASE_COMMON(name),						\
	.fails = true,							\
}

#define EXISTENCE_DATA(struct_name) STRUCT_TO_CHAR_PTR(struct_name) {	\
	.a = 42,							\
}

#define EXISTENCE_CASE_COMMON(name)					\
	.case_name = #name,						\
	.bpf_obj_file = "test_core_reloc_existence.o",			\
	.btf_src_file = "btf__core_reloc_" #name ".o",			\
	.relaxed_core_relocs = true					\

#define EXISTENCE_ERR_CASE(name) {					\
	EXISTENCE_CASE_COMMON(name),					\
	.fails = true,							\
}

struct core_reloc_test_case {
	const char *case_name;
	const char *bpf_obj_file;
	const char *btf_src_file;
	const char *input;
	int input_len;
	const char *output;
	int output_len;
	bool fails;
	bool relaxed_core_relocs;
};

static struct core_reloc_test_case test_cases[] = {
	/* validate we can find kernel image and use its BTF for relocs */
	{
		.case_name = "kernel",
		.bpf_obj_file = "test_core_reloc_kernel.o",
		.btf_src_file = NULL, /* load from /lib/modules/$(uname -r) */
		.input = "",
		.input_len = 0,
		.output = STRUCT_TO_CHAR_PTR(core_reloc_kernel_output) {
			.valid = { 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, },
			.comm = "test_progs\0\0\0\0\0",
			.comm_len = 11,
		},
		.output_len = sizeof(struct core_reloc_kernel_output),
	},

	/* validate BPF program can use multiple flavors to match against
	 * single target BTF type
	 */
	FLAVORS_CASE(flavors),

	FLAVORS_ERR_CASE(flavors__err_wrong_name),

	/* various struct/enum nesting and resolution scenarios */
	NESTING_CASE(nesting),
	NESTING_CASE(nesting___anon_embed),
	NESTING_CASE(nesting___struct_union_mixup),
	NESTING_CASE(nesting___extra_nesting),
	NESTING_CASE(nesting___dup_compat_types),

	NESTING_ERR_CASE(nesting___err_missing_field),
	NESTING_ERR_CASE(nesting___err_array_field),
	NESTING_ERR_CASE(nesting___err_missing_container),
	NESTING_ERR_CASE(nesting___err_nonstruct_container),
	NESTING_ERR_CASE(nesting___err_array_container),
	NESTING_ERR_CASE(nesting___err_dup_incompat_types),
	NESTING_ERR_CASE(nesting___err_partial_match_dups),
	NESTING_ERR_CASE(nesting___err_too_deep),

	/* various array access relocation scenarios */
	ARRAYS_CASE(arrays),
	ARRAYS_CASE(arrays___diff_arr_dim),
	ARRAYS_CASE(arrays___diff_arr_val_sz),

	ARRAYS_ERR_CASE(arrays___err_too_small),
	ARRAYS_ERR_CASE(arrays___err_too_shallow),
	ARRAYS_ERR_CASE(arrays___err_non_array),
	ARRAYS_ERR_CASE(arrays___err_wrong_val_type1),
	ARRAYS_ERR_CASE(arrays___err_wrong_val_type2),

	/* enum/ptr/int handling scenarios */
	PRIMITIVES_CASE(primitives),
	PRIMITIVES_CASE(primitives___diff_enum_def),
	PRIMITIVES_CASE(primitives___diff_func_proto),
	PRIMITIVES_CASE(primitives___diff_ptr_type),

	PRIMITIVES_ERR_CASE(primitives___err_non_enum),
	PRIMITIVES_ERR_CASE(primitives___err_non_int),
	PRIMITIVES_ERR_CASE(primitives___err_non_ptr),

	/* const/volatile/restrict and typedefs scenarios */
	MODS_CASE(mods),
	MODS_CASE(mods___mod_swap),
	MODS_CASE(mods___typedefs),

	/* handling "ptr is an array" semantics */
	PTR_AS_ARR_CASE(ptr_as_arr),
	PTR_AS_ARR_CASE(ptr_as_arr___diff_sz),

	/* int signedness/sizing/bitfield handling */
	INTS_CASE(ints),
	INTS_CASE(ints___bool),
	INTS_CASE(ints___reverse_sign),

	INTS_ERR_CASE(ints___err_bitfield),
	INTS_ERR_CASE(ints___err_wrong_sz_8),
	INTS_ERR_CASE(ints___err_wrong_sz_16),
	INTS_ERR_CASE(ints___err_wrong_sz_32),
	INTS_ERR_CASE(ints___err_wrong_sz_64),

	/* validate edge cases of capturing relocations */
	{
		.case_name = "misc",
		.bpf_obj_file = "test_core_reloc_misc.o",
		.btf_src_file = "btf__core_reloc_misc.o",
		.input = (const char *)&(struct core_reloc_misc_extensible[]){
			{ .a = 1 },
			{ .a = 2 }, /* not read */
			{ .a = 3 },
		},
		.input_len = 4 * sizeof(int),
		.output = STRUCT_TO_CHAR_PTR(core_reloc_misc_output) {
			.a = 1,
			.b = 1,
			.c = 0, /* BUG in clang, should be 3 */
		},
		.output_len = sizeof(struct core_reloc_misc_output),
	},

	/* validate field existence checks */
	{
		EXISTENCE_CASE_COMMON(existence),
		.input = STRUCT_TO_CHAR_PTR(core_reloc_existence) {
			.a = 1,
			.b = 2,
			.c = 3,
			.arr = { 4 },
			.s = { .x = 5 },
		},
		.input_len = sizeof(struct core_reloc_existence),
		.output = STRUCT_TO_CHAR_PTR(core_reloc_existence_output) {
			.a_exists = 1,
			.b_exists = 1,
			.c_exists = 1,
			.arr_exists = 1,
			.s_exists = 1,
			.a_value = 1,
			.b_value = 2,
			.c_value = 3,
			.arr_value = 4,
			.s_value = 5,
		},
		.output_len = sizeof(struct core_reloc_existence_output),
	},
	{
		EXISTENCE_CASE_COMMON(existence___minimal),
		.input = STRUCT_TO_CHAR_PTR(core_reloc_existence___minimal) {
			.a = 42,
		},
		.input_len = sizeof(struct core_reloc_existence),
		.output = STRUCT_TO_CHAR_PTR(core_reloc_existence_output) {
			.a_exists = 1,
			.b_exists = 0,
			.c_exists = 0,
			.arr_exists = 0,
			.s_exists = 0,
			.a_value = 42,
			.b_value = 0xff000002u,
			.c_value = 0xff000003u,
			.arr_value = 0xff000004u,
			.s_value = 0xff000005u,
		},
		.output_len = sizeof(struct core_reloc_existence_output),
	},

	EXISTENCE_ERR_CASE(existence__err_int_sz),
	EXISTENCE_ERR_CASE(existence__err_int_type),
	EXISTENCE_ERR_CASE(existence__err_int_kind),
	EXISTENCE_ERR_CASE(existence__err_arr_kind),
	EXISTENCE_ERR_CASE(existence__err_arr_value_type),
	EXISTENCE_ERR_CASE(existence__err_struct_type),
};

struct data {
	char in[256];
	char out[256];
};

static void test_core_reloc(void)
{
	const char *probe_name = "raw_tracepoint/sys_enter";
	struct bpf_object_load_attr load_attr = {};
	struct core_reloc_test_case *test_case;
	int err, duration = 0, i, equal;
	struct bpf_link *link = NULL;
	struct bpf_map *data_map;
	struct bpf_program *prog;
	struct bpf_object *obj;
	const int zero = 0;
	struct data data;

	for (i = 0; i < ARRAY_SIZE(test_cases); i++) {
		test_case = &test_cases[i];

		LIBBPF_OPTS(bpf_object_open_opts, opts,
			.relaxed_core_relocs = test_case->relaxed_core_relocs,
		);

		obj = bpf_object__open_file(test_case->bpf_obj_file, &opts);
		if (CHECK(IS_ERR_OR_NULL(obj), "obj_open",
			  "failed to open '%s': %ld\n",
			  test_case->bpf_obj_file, PTR_ERR(obj)))
			continue;

		prog = bpf_object__find_program_by_title(obj, probe_name);
		if (CHECK(!prog, "find_probe",
			  "prog '%s' not found\n", probe_name))
			goto cleanup;
		bpf_program__set_type(prog, BPF_PROG_TYPE_RAW_TRACEPOINT);

		load_attr.obj = obj;
		load_attr.log_level = 0;
		load_attr.target_btf_path = test_case->btf_src_file;
		err = bpf_object__load_xattr(&load_attr);
		if (test_case->fails) {
			CHECK(!err, "obj_load_fail",
			      "should fail to load prog '%s'\n", probe_name);
			goto cleanup;
		} else {
			if (CHECK(err, "obj_load",
				  "failed to load prog '%s': %d\n",
				  probe_name, err))
				goto cleanup;
		}

		link = bpf_program__attach_raw_tracepoint(prog, "sys_enter");
		if (CHECK(IS_ERR(link), "attach_raw_tp", "err %ld\n",
			  PTR_ERR(link)))
			goto cleanup;

		data_map = bpf_object__find_map_by_name(obj, "test_cor.bss");
		if (CHECK(!data_map, "find_data_map", "data map not found\n"))
			goto cleanup;

		memset(&data, 0, sizeof(data));
		memcpy(data.in, test_case->input, test_case->input_len);

		err = bpf_map_update_elem(bpf_map__fd(data_map),
					  &zero, &data, 0);
		if (CHECK(err, "update_data_map",
			  "failed to update .data map: %d\n", err))
			goto cleanup;

		/* trigger test run */
		usleep(1);

		err = bpf_map_lookup_elem(bpf_map__fd(data_map), &zero, &data);
		if (CHECK(err, "get_result",
			  "failed to get output data: %d\n", err))
			goto cleanup;

		equal = memcmp(data.out, test_case->output,
			       test_case->output_len) == 0;
		if (CHECK(!equal, "check_result",
			  "input/output data don't match\n")) {
			int j;

			for (j = 0; j < test_case->input_len; j++) {
				printf("input byte #%d: 0x%02hhx\n",
				       j, test_case->input[j]);
			}
			for (j = 0; j < test_case->output_len; j++) {
				printf("output byte #%d: EXP 0x%02hhx GOT 0x%02hhx\n",
				       j, test_case->output[j], data.out[j]);
			}
			goto cleanup;
		}

cleanup:
		if (!IS_ERR_OR_NULL(link)) {
			bpf_link__destroy(link);
			link = NULL;
		}
		bpf_object__close(obj);
	}
}

int main(int ac, char **av)
{
	srand(time(NULL));

	jit_enabled = is_jit_enabled();

	if (ac == 2 && strcmp(av[1], "-s") == 0)
		verifier_stats = true;

	test_pkt_access();
	test_prog_run_xattr();
	test_xdp();
	test_xdp_adjust_tail();
	test_l4lb_all();
	test_xdp_noinline();
	test_tcp_estats();
	test_bpf_obj_id();
	test_pkt_md_access();
	test_obj_name();
	test_tp_attach_query();
	test_stacktrace_map();
	test_stacktrace_build_id();
	test_stacktrace_build_id_nmi();
	test_stacktrace_map_raw_tp();
	test_get_stack_raw_tp();
	test_task_fd_query_rawtp();
	test_task_fd_query_tp();
	test_reference_tracking();
	test_queue_stack_map(QUEUE);
	test_queue_stack_map(STACK);
	test_flow_dissector();
	test_flow_dissector_load_bytes();
	test_spinlock();
	test_map_lock();
	test_signal_pending(BPF_PROG_TYPE_SOCKET_FILTER);
	test_signal_pending(BPF_PROG_TYPE_FLOW_DISSECTOR);
	test_bpf_verif_scale();
	test_global_data();
	test_raw_tp_writable_reject_nbd_invalid();
	test_raw_tp_writable_test_run();
	test_send_signal();
	test_perf_buffer();
	test_core_reloc();

	printf("Summary: %d PASSED, %d FAILED\n", pass_cnt, error_cnt);
	return error_cnt ? EXIT_FAILURE : EXIT_SUCCESS;
}
