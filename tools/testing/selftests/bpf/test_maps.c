/*
 * Testsuite for eBPF maps
 *
 * Copyright (c) 2014 PLUMgrid, http://plumgrid.com
 * Copyright (c) 2016 Facebook
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>

#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <netinet/in.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/compiler.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "test_btf.h"
#include "bpf_util.h"
#include "bpf_rlimit.h"

#ifndef ENOTSUPP
#define ENOTSUPP 524
#endif

static int skips;

static int map_flags;

#define CHECK(condition, tag, format...) ({				\
	int __ret = !!(condition);					\
	if (__ret) {							\
		printf("%s(%d):FAIL:%s ", __func__, __LINE__, tag);	\
		printf(format);						\
		exit(-1);						\
	}								\
})

static void test_hashmap(int task, void *data)
{
	long long key, next_key, first_key, value;
	int fd;

	fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(key), sizeof(value),
			    2, map_flags);
	if (fd < 0) {
		printf("Failed to create hashmap '%s'!\n", strerror(errno));
		exit(1);
	}

	key = 1;
	value = 1234;
	/* Insert key=1 element. */
	assert(bpf_map_update_elem(fd, &key, &value, BPF_ANY) == 0);

	value = 0;
	/* BPF_NOEXIST means add new element if it doesn't exist. */
	assert(bpf_map_update_elem(fd, &key, &value, BPF_NOEXIST) == -1 &&
	       /* key=1 already exists. */
	       errno == EEXIST);

	/* -1 is an invalid flag. */
	assert(bpf_map_update_elem(fd, &key, &value, -1) == -1 &&
	       errno == EINVAL);

	/* Check that key=1 can be found. */
	assert(bpf_map_lookup_elem(fd, &key, &value) == 0 && value == 1234);

	key = 2;
	/* Check that key=2 is not found. */
	assert(bpf_map_lookup_elem(fd, &key, &value) == -1 && errno == ENOENT);

	/* BPF_EXIST means update existing element. */
	assert(bpf_map_update_elem(fd, &key, &value, BPF_EXIST) == -1 &&
	       /* key=2 is not there. */
	       errno == ENOENT);

	/* Insert key=2 element. */
	assert(bpf_map_update_elem(fd, &key, &value, BPF_NOEXIST) == 0);

	/* key=1 and key=2 were inserted, check that key=0 cannot be
	 * inserted due to max_entries limit.
	 */
	key = 0;
	assert(bpf_map_update_elem(fd, &key, &value, BPF_NOEXIST) == -1 &&
	       errno == E2BIG);

	/* Update existing element, though the map is full. */
	key = 1;
	assert(bpf_map_update_elem(fd, &key, &value, BPF_EXIST) == 0);
	key = 2;
	assert(bpf_map_update_elem(fd, &key, &value, BPF_ANY) == 0);
	key = 3;
	assert(bpf_map_update_elem(fd, &key, &value, BPF_NOEXIST) == -1 &&
	       errno == E2BIG);

	/* Check that key = 0 doesn't exist. */
	key = 0;
	assert(bpf_map_delete_elem(fd, &key) == -1 && errno == ENOENT);

	/* Iterate over two elements. */
	assert(bpf_map_get_next_key(fd, NULL, &first_key) == 0 &&
	       (first_key == 1 || first_key == 2));
	assert(bpf_map_get_next_key(fd, &key, &next_key) == 0 &&
	       (next_key == first_key));
	assert(bpf_map_get_next_key(fd, &next_key, &next_key) == 0 &&
	       (next_key == 1 || next_key == 2) &&
	       (next_key != first_key));
	assert(bpf_map_get_next_key(fd, &next_key, &next_key) == -1 &&
	       errno == ENOENT);

	/* Delete both elements. */
	key = 1;
	assert(bpf_map_delete_elem(fd, &key) == 0);
	key = 2;
	assert(bpf_map_delete_elem(fd, &key) == 0);
	assert(bpf_map_delete_elem(fd, &key) == -1 && errno == ENOENT);

	key = 0;
	/* Check that map is empty. */
	assert(bpf_map_get_next_key(fd, NULL, &next_key) == -1 &&
	       errno == ENOENT);
	assert(bpf_map_get_next_key(fd, &key, &next_key) == -1 &&
	       errno == ENOENT);

	close(fd);
}

static void test_hashmap_sizes(int task, void *data)
{
	int fd, i, j;

	for (i = 1; i <= 512; i <<= 1)
		for (j = 1; j <= 1 << 18; j <<= 1) {
			fd = bpf_create_map(BPF_MAP_TYPE_HASH, i, j,
					    2, map_flags);
			if (fd < 0) {
				if (errno == ENOMEM)
					return;
				printf("Failed to create hashmap key=%d value=%d '%s'\n",
				       i, j, strerror(errno));
				exit(1);
			}
			close(fd);
			usleep(10); /* give kernel time to destroy */
		}
}

static void test_hashmap_percpu(int task, void *data)
{
	unsigned int nr_cpus = bpf_num_possible_cpus();
	BPF_DECLARE_PERCPU(long, value);
	long long key, next_key, first_key;
	int expected_key_mask = 0;
	int fd, i;

	fd = bpf_create_map(BPF_MAP_TYPE_PERCPU_HASH, sizeof(key),
			    sizeof(bpf_percpu(value, 0)), 2, map_flags);
	if (fd < 0) {
		printf("Failed to create hashmap '%s'!\n", strerror(errno));
		exit(1);
	}

	for (i = 0; i < nr_cpus; i++)
		bpf_percpu(value, i) = i + 100;

	key = 1;
	/* Insert key=1 element. */
	assert(!(expected_key_mask & key));
	assert(bpf_map_update_elem(fd, &key, value, BPF_ANY) == 0);
	expected_key_mask |= key;

	/* BPF_NOEXIST means add new element if it doesn't exist. */
	assert(bpf_map_update_elem(fd, &key, value, BPF_NOEXIST) == -1 &&
	       /* key=1 already exists. */
	       errno == EEXIST);

	/* -1 is an invalid flag. */
	assert(bpf_map_update_elem(fd, &key, value, -1) == -1 &&
	       errno == EINVAL);

	/* Check that key=1 can be found. Value could be 0 if the lookup
	 * was run from a different CPU.
	 */
	bpf_percpu(value, 0) = 1;
	assert(bpf_map_lookup_elem(fd, &key, value) == 0 &&
	       bpf_percpu(value, 0) == 100);

	key = 2;
	/* Check that key=2 is not found. */
	assert(bpf_map_lookup_elem(fd, &key, value) == -1 && errno == ENOENT);

	/* BPF_EXIST means update existing element. */
	assert(bpf_map_update_elem(fd, &key, value, BPF_EXIST) == -1 &&
	       /* key=2 is not there. */
	       errno == ENOENT);

	/* Insert key=2 element. */
	assert(!(expected_key_mask & key));
	assert(bpf_map_update_elem(fd, &key, value, BPF_NOEXIST) == 0);
	expected_key_mask |= key;

	/* key=1 and key=2 were inserted, check that key=0 cannot be
	 * inserted due to max_entries limit.
	 */
	key = 0;
	assert(bpf_map_update_elem(fd, &key, value, BPF_NOEXIST) == -1 &&
	       errno == E2BIG);

	/* Check that key = 0 doesn't exist. */
	assert(bpf_map_delete_elem(fd, &key) == -1 && errno == ENOENT);

	/* Iterate over two elements. */
	assert(bpf_map_get_next_key(fd, NULL, &first_key) == 0 &&
	       ((expected_key_mask & first_key) == first_key));
	while (!bpf_map_get_next_key(fd, &key, &next_key)) {
		if (first_key) {
			assert(next_key == first_key);
			first_key = 0;
		}
		assert((expected_key_mask & next_key) == next_key);
		expected_key_mask &= ~next_key;

		assert(bpf_map_lookup_elem(fd, &next_key, value) == 0);

		for (i = 0; i < nr_cpus; i++)
			assert(bpf_percpu(value, i) == i + 100);

		key = next_key;
	}
	assert(errno == ENOENT);

	/* Update with BPF_EXIST. */
	key = 1;
	assert(bpf_map_update_elem(fd, &key, value, BPF_EXIST) == 0);

	/* Delete both elements. */
	key = 1;
	assert(bpf_map_delete_elem(fd, &key) == 0);
	key = 2;
	assert(bpf_map_delete_elem(fd, &key) == 0);
	assert(bpf_map_delete_elem(fd, &key) == -1 && errno == ENOENT);

	key = 0;
	/* Check that map is empty. */
	assert(bpf_map_get_next_key(fd, NULL, &next_key) == -1 &&
	       errno == ENOENT);
	assert(bpf_map_get_next_key(fd, &key, &next_key) == -1 &&
	       errno == ENOENT);

	close(fd);
}

static int helper_fill_hashmap(int max_entries)
{
	int i, fd, ret;
	long long key, value;

	fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(key), sizeof(value),
			    max_entries, map_flags);
	CHECK(fd < 0,
	      "failed to create hashmap",
	      "err: %s, flags: 0x%x\n", strerror(errno), map_flags);

	for (i = 0; i < max_entries; i++) {
		key = i; value = key;
		ret = bpf_map_update_elem(fd, &key, &value, BPF_NOEXIST);
		CHECK(ret != 0,
		      "can't update hashmap",
		      "err: %s\n", strerror(ret));
	}

	return fd;
}

static void test_hashmap_walk(int task, void *data)
{
	int fd, i, max_entries = 1000;
	long long key, value, next_key;
	bool next_key_valid = true;

	fd = helper_fill_hashmap(max_entries);

	for (i = 0; bpf_map_get_next_key(fd, !i ? NULL : &key,
					 &next_key) == 0; i++) {
		key = next_key;
		assert(bpf_map_lookup_elem(fd, &key, &value) == 0);
	}

	assert(i == max_entries);

	assert(bpf_map_get_next_key(fd, NULL, &key) == 0);
	for (i = 0; next_key_valid; i++) {
		next_key_valid = bpf_map_get_next_key(fd, &key, &next_key) == 0;
		assert(bpf_map_lookup_elem(fd, &key, &value) == 0);
		value++;
		assert(bpf_map_update_elem(fd, &key, &value, BPF_EXIST) == 0);
		key = next_key;
	}

	assert(i == max_entries);

	for (i = 0; bpf_map_get_next_key(fd, !i ? NULL : &key,
					 &next_key) == 0; i++) {
		key = next_key;
		assert(bpf_map_lookup_elem(fd, &key, &value) == 0);
		assert(value - 1 == key);
	}

	assert(i == max_entries);
	close(fd);
}

static void test_hashmap_zero_seed(void)
{
	int i, first, second, old_flags;
	long long key, next_first, next_second;

	old_flags = map_flags;
	map_flags |= BPF_F_ZERO_SEED;

	first = helper_fill_hashmap(3);
	second = helper_fill_hashmap(3);

	for (i = 0; ; i++) {
		void *key_ptr = !i ? NULL : &key;

		if (bpf_map_get_next_key(first, key_ptr, &next_first) != 0)
			break;

		CHECK(bpf_map_get_next_key(second, key_ptr, &next_second) != 0,
		      "next_key for second map must succeed",
		      "key_ptr: %p", key_ptr);
		CHECK(next_first != next_second,
		      "keys must match",
		      "i: %d first: %lld second: %lld\n", i,
		      next_first, next_second);

		key = next_first;
	}

	map_flags = old_flags;
	close(first);
	close(second);
}

static void test_arraymap(int task, void *data)
{
	int key, next_key, fd;
	long long value;

	fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(key), sizeof(value),
			    2, 0);
	if (fd < 0) {
		printf("Failed to create arraymap '%s'!\n", strerror(errno));
		exit(1);
	}

	key = 1;
	value = 1234;
	/* Insert key=1 element. */
	assert(bpf_map_update_elem(fd, &key, &value, BPF_ANY) == 0);

	value = 0;
	assert(bpf_map_update_elem(fd, &key, &value, BPF_NOEXIST) == -1 &&
	       errno == EEXIST);

	/* Check that key=1 can be found. */
	assert(bpf_map_lookup_elem(fd, &key, &value) == 0 && value == 1234);

	key = 0;
	/* Check that key=0 is also found and zero initialized. */
	assert(bpf_map_lookup_elem(fd, &key, &value) == 0 && value == 0);

	/* key=0 and key=1 were inserted, check that key=2 cannot be inserted
	 * due to max_entries limit.
	 */
	key = 2;
	assert(bpf_map_update_elem(fd, &key, &value, BPF_EXIST) == -1 &&
	       errno == E2BIG);

	/* Check that key = 2 doesn't exist. */
	assert(bpf_map_lookup_elem(fd, &key, &value) == -1 && errno == ENOENT);

	/* Iterate over two elements. */
	assert(bpf_map_get_next_key(fd, NULL, &next_key) == 0 &&
	       next_key == 0);
	assert(bpf_map_get_next_key(fd, &key, &next_key) == 0 &&
	       next_key == 0);
	assert(bpf_map_get_next_key(fd, &next_key, &next_key) == 0 &&
	       next_key == 1);
	assert(bpf_map_get_next_key(fd, &next_key, &next_key) == -1 &&
	       errno == ENOENT);

	/* Delete shouldn't succeed. */
	key = 1;
	assert(bpf_map_delete_elem(fd, &key) == -1 && errno == EINVAL);

	close(fd);
}

static void test_arraymap_percpu(int task, void *data)
{
	unsigned int nr_cpus = bpf_num_possible_cpus();
	BPF_DECLARE_PERCPU(long, values);
	int key, next_key, fd, i;

	fd = bpf_create_map(BPF_MAP_TYPE_PERCPU_ARRAY, sizeof(key),
			    sizeof(bpf_percpu(values, 0)), 2, 0);
	if (fd < 0) {
		printf("Failed to create arraymap '%s'!\n", strerror(errno));
		exit(1);
	}

	for (i = 0; i < nr_cpus; i++)
		bpf_percpu(values, i) = i + 100;

	key = 1;
	/* Insert key=1 element. */
	assert(bpf_map_update_elem(fd, &key, values, BPF_ANY) == 0);

	bpf_percpu(values, 0) = 0;
	assert(bpf_map_update_elem(fd, &key, values, BPF_NOEXIST) == -1 &&
	       errno == EEXIST);

	/* Check that key=1 can be found. */
	assert(bpf_map_lookup_elem(fd, &key, values) == 0 &&
	       bpf_percpu(values, 0) == 100);

	key = 0;
	/* Check that key=0 is also found and zero initialized. */
	assert(bpf_map_lookup_elem(fd, &key, values) == 0 &&
	       bpf_percpu(values, 0) == 0 &&
	       bpf_percpu(values, nr_cpus - 1) == 0);

	/* Check that key=2 cannot be inserted due to max_entries limit. */
	key = 2;
	assert(bpf_map_update_elem(fd, &key, values, BPF_EXIST) == -1 &&
	       errno == E2BIG);

	/* Check that key = 2 doesn't exist. */
	assert(bpf_map_lookup_elem(fd, &key, values) == -1 && errno == ENOENT);

	/* Iterate over two elements. */
	assert(bpf_map_get_next_key(fd, NULL, &next_key) == 0 &&
	       next_key == 0);
	assert(bpf_map_get_next_key(fd, &key, &next_key) == 0 &&
	       next_key == 0);
	assert(bpf_map_get_next_key(fd, &next_key, &next_key) == 0 &&
	       next_key == 1);
	assert(bpf_map_get_next_key(fd, &next_key, &next_key) == -1 &&
	       errno == ENOENT);

	/* Delete shouldn't succeed. */
	key = 1;
	assert(bpf_map_delete_elem(fd, &key) == -1 && errno == EINVAL);

	close(fd);
}

static void test_arraymap_percpu_many_keys(void)
{
	unsigned int nr_cpus = bpf_num_possible_cpus();
	BPF_DECLARE_PERCPU(long, values);
	/* nr_keys is not too large otherwise the test stresses percpu
	 * allocator more than anything else
	 */
	unsigned int nr_keys = 2000;
	int key, fd, i;

	fd = bpf_create_map(BPF_MAP_TYPE_PERCPU_ARRAY, sizeof(key),
			    sizeof(bpf_percpu(values, 0)), nr_keys, 0);
	if (fd < 0) {
		printf("Failed to create per-cpu arraymap '%s'!\n",
		       strerror(errno));
		exit(1);
	}

	for (i = 0; i < nr_cpus; i++)
		bpf_percpu(values, i) = i + 10;

	for (key = 0; key < nr_keys; key++)
		assert(bpf_map_update_elem(fd, &key, values, BPF_ANY) == 0);

	for (key = 0; key < nr_keys; key++) {
		for (i = 0; i < nr_cpus; i++)
			bpf_percpu(values, i) = 0;

		assert(bpf_map_lookup_elem(fd, &key, values) == 0);

		for (i = 0; i < nr_cpus; i++)
			assert(bpf_percpu(values, i) == i + 10);
	}

	close(fd);
}

static void test_devmap(int task, void *data)
{
	int fd;
	__u32 key, value;

	fd = bpf_create_map(BPF_MAP_TYPE_DEVMAP, sizeof(key), sizeof(value),
			    2, 0);
	if (fd < 0) {
		printf("Failed to create arraymap '%s'!\n", strerror(errno));
		exit(1);
	}

	close(fd);
}

static void test_devmap_hash(unsigned int task, void *data)
{
	int fd;
	__u32 key, value;

	fd = bpf_create_map(BPF_MAP_TYPE_DEVMAP_HASH, sizeof(key), sizeof(value),
			    2, 0);
	if (fd < 0) {
		printf("Failed to create devmap_hash '%s'!\n", strerror(errno));
		exit(1);
	}

	close(fd);
}

static void test_queuemap(int task, void *data)
{
	const int MAP_SIZE = 32;
	__u32 vals[MAP_SIZE + MAP_SIZE/2], val;
	int fd, i;

	/* Fill test values to be used */
	for (i = 0; i < MAP_SIZE + MAP_SIZE/2; i++)
		vals[i] = rand();

	/* Invalid key size */
	fd = bpf_create_map(BPF_MAP_TYPE_QUEUE, 4, sizeof(val), MAP_SIZE,
			    map_flags);
	assert(fd < 0 && errno == EINVAL);

	fd = bpf_create_map(BPF_MAP_TYPE_QUEUE, 0, sizeof(val), MAP_SIZE,
			    map_flags);
	/* Queue map does not support BPF_F_NO_PREALLOC */
	if (map_flags & BPF_F_NO_PREALLOC) {
		assert(fd < 0 && errno == EINVAL);
		return;
	}
	if (fd < 0) {
		printf("Failed to create queuemap '%s'!\n", strerror(errno));
		exit(1);
	}

	/* Push MAP_SIZE elements */
	for (i = 0; i < MAP_SIZE; i++)
		assert(bpf_map_update_elem(fd, NULL, &vals[i], 0) == 0);

	/* Check that element cannot be pushed due to max_entries limit */
	assert(bpf_map_update_elem(fd, NULL, &val, 0) == -1 &&
	       errno == E2BIG);

	/* Peek element */
	assert(bpf_map_lookup_elem(fd, NULL, &val) == 0 && val == vals[0]);

	/* Replace half elements */
	for (i = MAP_SIZE; i < MAP_SIZE + MAP_SIZE/2; i++)
		assert(bpf_map_update_elem(fd, NULL, &vals[i], BPF_EXIST) == 0);

	/* Pop all elements */
	for (i = MAP_SIZE/2; i < MAP_SIZE + MAP_SIZE/2; i++)
		assert(bpf_map_lookup_and_delete_elem(fd, NULL, &val) == 0 &&
		       val == vals[i]);

	/* Check that there are not elements left */
	assert(bpf_map_lookup_and_delete_elem(fd, NULL, &val) == -1 &&
	       errno == ENOENT);

	/* Check that non supported functions set errno to EINVAL */
	assert(bpf_map_delete_elem(fd, NULL) == -1 && errno == EINVAL);
	assert(bpf_map_get_next_key(fd, NULL, NULL) == -1 && errno == EINVAL);

	close(fd);
}

static void test_stackmap(int task, void *data)
{
	const int MAP_SIZE = 32;
	__u32 vals[MAP_SIZE + MAP_SIZE/2], val;
	int fd, i;

	/* Fill test values to be used */
	for (i = 0; i < MAP_SIZE + MAP_SIZE/2; i++)
		vals[i] = rand();

	/* Invalid key size */
	fd = bpf_create_map(BPF_MAP_TYPE_STACK, 4, sizeof(val), MAP_SIZE,
			    map_flags);
	assert(fd < 0 && errno == EINVAL);

	fd = bpf_create_map(BPF_MAP_TYPE_STACK, 0, sizeof(val), MAP_SIZE,
			    map_flags);
	/* Stack map does not support BPF_F_NO_PREALLOC */
	if (map_flags & BPF_F_NO_PREALLOC) {
		assert(fd < 0 && errno == EINVAL);
		return;
	}
	if (fd < 0) {
		printf("Failed to create stackmap '%s'!\n", strerror(errno));
		exit(1);
	}

	/* Push MAP_SIZE elements */
	for (i = 0; i < MAP_SIZE; i++)
		assert(bpf_map_update_elem(fd, NULL, &vals[i], 0) == 0);

	/* Check that element cannot be pushed due to max_entries limit */
	assert(bpf_map_update_elem(fd, NULL, &val, 0) == -1 &&
	       errno == E2BIG);

	/* Peek element */
	assert(bpf_map_lookup_elem(fd, NULL, &val) == 0 && val == vals[i - 1]);

	/* Replace half elements */
	for (i = MAP_SIZE; i < MAP_SIZE + MAP_SIZE/2; i++)
		assert(bpf_map_update_elem(fd, NULL, &vals[i], BPF_EXIST) == 0);

	/* Pop all elements */
	for (i = MAP_SIZE + MAP_SIZE/2 - 1; i >= MAP_SIZE/2; i--)
		assert(bpf_map_lookup_and_delete_elem(fd, NULL, &val) == 0 &&
		       val == vals[i]);

	/* Check that there are not elements left */
	assert(bpf_map_lookup_and_delete_elem(fd, NULL, &val) == -1 &&
	       errno == ENOENT);

	/* Check that non supported functions set errno to EINVAL */
	assert(bpf_map_delete_elem(fd, NULL) == -1 && errno == EINVAL);
	assert(bpf_map_get_next_key(fd, NULL, NULL) == -1 && errno == EINVAL);

	close(fd);
}

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <linux/err.h>
#define SOCKMAP_PARSE_PROG "./sockmap_parse_prog.o"
#define SOCKMAP_VERDICT_PROG "./sockmap_verdict_prog.o"
#define SOCKMAP_TCP_MSG_PROG "./sockmap_tcp_msg_prog.o"
static void test_sockmap(int tasks, void *data)
{
	struct bpf_map *bpf_map_rx, *bpf_map_tx, *bpf_map_msg, *bpf_map_break;
	int map_fd_msg = 0, map_fd_rx = 0, map_fd_tx = 0, map_fd_break;
	int ports[] = {50200, 50201, 50202, 50204};
	int err, i, fd, udp, sfd[6] = {0xdeadbeef};
	u8 buf[20] = {0x0, 0x5, 0x3, 0x2, 0x1, 0x0};
	int parse_prog, verdict_prog, msg_prog;
	struct sockaddr_in addr;
	int one = 1, s, sc, rc;
	struct bpf_object *obj;
	struct timeval to;
	__u32 key, value;
	pid_t pid[tasks];
	fd_set w;

	/* Create some sockets to use with sockmap */
	for (i = 0; i < 2; i++) {
		sfd[i] = socket(AF_INET, SOCK_STREAM, 0);
		if (sfd[i] < 0)
			goto out;
		err = setsockopt(sfd[i], SOL_SOCKET, SO_REUSEADDR,
				 (char *)&one, sizeof(one));
		if (err) {
			printf("failed to setsockopt\n");
			goto out;
		}
		err = ioctl(sfd[i], FIONBIO, (char *)&one);
		if (err < 0) {
			printf("failed to ioctl\n");
			goto out;
		}
		memset(&addr, 0, sizeof(struct sockaddr_in));
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = inet_addr("127.0.0.1");
		addr.sin_port = htons(ports[i]);
		err = bind(sfd[i], (struct sockaddr *)&addr, sizeof(addr));
		if (err < 0) {
			printf("failed to bind: err %i: %i:%i\n",
			       err, i, sfd[i]);
			goto out;
		}
		err = listen(sfd[i], 32);
		if (err < 0) {
			printf("failed to listen\n");
			goto out;
		}
	}

	for (i = 2; i < 4; i++) {
		sfd[i] = socket(AF_INET, SOCK_STREAM, 0);
		if (sfd[i] < 0)
			goto out;
		err = setsockopt(sfd[i], SOL_SOCKET, SO_REUSEADDR,
				 (char *)&one, sizeof(one));
		if (err) {
			printf("set sock opt\n");
			goto out;
		}
		memset(&addr, 0, sizeof(struct sockaddr_in));
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = inet_addr("127.0.0.1");
		addr.sin_port = htons(ports[i - 2]);
		err = connect(sfd[i], (struct sockaddr *)&addr, sizeof(addr));
		if (err) {
			printf("failed to connect\n");
			goto out;
		}
	}


	for (i = 4; i < 6; i++) {
		sfd[i] = accept(sfd[i - 4], NULL, NULL);
		if (sfd[i] < 0) {
			printf("accept failed\n");
			goto out;
		}
	}

	/* Test sockmap with connected sockets */
	fd = bpf_create_map(BPF_MAP_TYPE_SOCKMAP,
			    sizeof(key), sizeof(value),
			    6, 0);
	if (fd < 0) {
		if (!bpf_probe_map_type(BPF_MAP_TYPE_SOCKMAP, 0)) {
			printf("%s SKIP (unsupported map type BPF_MAP_TYPE_SOCKMAP)\n",
			       __func__);
			skips++;
			for (i = 0; i < 6; i++)
				close(sfd[i]);
			return;
		}

		printf("Failed to create sockmap %i\n", fd);
		goto out_sockmap;
	}

	/* Test update with unsupported UDP socket */
	udp = socket(AF_INET, SOCK_DGRAM, 0);
	i = 0;
	err = bpf_map_update_elem(fd, &i, &udp, BPF_ANY);
	if (!err) {
		printf("Failed socket SOCK_DGRAM allowed '%i:%i'\n",
		       i, udp);
		goto out_sockmap;
	}

	/* Test update without programs */
	for (i = 0; i < 6; i++) {
		err = bpf_map_update_elem(fd, &i, &sfd[i], BPF_ANY);
		if (i < 2 && !err) {
			printf("Allowed update sockmap '%i:%i' not in ESTABLISHED\n",
			       i, sfd[i]);
			goto out_sockmap;
		} else if (i >= 2 && err) {
			printf("Failed noprog update sockmap '%i:%i'\n",
			       i, sfd[i]);
			goto out_sockmap;
		}
	}

	/* Test attaching/detaching bad fds */
	err = bpf_prog_attach(-1, fd, BPF_SK_SKB_STREAM_PARSER, 0);
	if (!err) {
		printf("Failed invalid parser prog attach\n");
		goto out_sockmap;
	}

	err = bpf_prog_attach(-1, fd, BPF_SK_SKB_STREAM_VERDICT, 0);
	if (!err) {
		printf("Failed invalid verdict prog attach\n");
		goto out_sockmap;
	}

	err = bpf_prog_attach(-1, fd, BPF_SK_MSG_VERDICT, 0);
	if (!err) {
		printf("Failed invalid msg verdict prog attach\n");
		goto out_sockmap;
	}

	err = bpf_prog_attach(-1, fd, __MAX_BPF_ATTACH_TYPE, 0);
	if (!err) {
		printf("Failed unknown prog attach\n");
		goto out_sockmap;
	}

	err = bpf_prog_detach(fd, BPF_SK_SKB_STREAM_PARSER);
	if (!err) {
		printf("Failed empty parser prog detach\n");
		goto out_sockmap;
	}

	err = bpf_prog_detach(fd, BPF_SK_SKB_STREAM_VERDICT);
	if (!err) {
		printf("Failed empty verdict prog detach\n");
		goto out_sockmap;
	}

	err = bpf_prog_detach(fd, BPF_SK_MSG_VERDICT);
	if (!err) {
		printf("Failed empty msg verdict prog detach\n");
		goto out_sockmap;
	}

	err = bpf_prog_detach(fd, __MAX_BPF_ATTACH_TYPE);
	if (!err) {
		printf("Detach invalid prog successful\n");
		goto out_sockmap;
	}

	/* Load SK_SKB program and Attach */
	err = bpf_prog_load(SOCKMAP_PARSE_PROG,
			    BPF_PROG_TYPE_SK_SKB, &obj, &parse_prog);
	if (err) {
		printf("Failed to load SK_SKB parse prog\n");
		goto out_sockmap;
	}

	err = bpf_prog_load(SOCKMAP_TCP_MSG_PROG,
			    BPF_PROG_TYPE_SK_MSG, &obj, &msg_prog);
	if (err) {
		printf("Failed to load SK_SKB msg prog\n");
		goto out_sockmap;
	}

	err = bpf_prog_load(SOCKMAP_VERDICT_PROG,
			    BPF_PROG_TYPE_SK_SKB, &obj, &verdict_prog);
	if (err) {
		printf("Failed to load SK_SKB verdict prog\n");
		goto out_sockmap;
	}

	bpf_map_rx = bpf_object__find_map_by_name(obj, "sock_map_rx");
	if (IS_ERR(bpf_map_rx)) {
		printf("Failed to load map rx from verdict prog\n");
		goto out_sockmap;
	}

	map_fd_rx = bpf_map__fd(bpf_map_rx);
	if (map_fd_rx < 0) {
		printf("Failed to get map rx fd\n");
		goto out_sockmap;
	}

	bpf_map_tx = bpf_object__find_map_by_name(obj, "sock_map_tx");
	if (IS_ERR(bpf_map_tx)) {
		printf("Failed to load map tx from verdict prog\n");
		goto out_sockmap;
	}

	map_fd_tx = bpf_map__fd(bpf_map_tx);
	if (map_fd_tx < 0) {
		printf("Failed to get map tx fd\n");
		goto out_sockmap;
	}

	bpf_map_msg = bpf_object__find_map_by_name(obj, "sock_map_msg");
	if (IS_ERR(bpf_map_msg)) {
		printf("Failed to load map msg from msg_verdict prog\n");
		goto out_sockmap;
	}

	map_fd_msg = bpf_map__fd(bpf_map_msg);
	if (map_fd_msg < 0) {
		printf("Failed to get map msg fd\n");
		goto out_sockmap;
	}

	bpf_map_break = bpf_object__find_map_by_name(obj, "sock_map_break");
	if (IS_ERR(bpf_map_break)) {
		printf("Failed to load map tx from verdict prog\n");
		goto out_sockmap;
	}

	map_fd_break = bpf_map__fd(bpf_map_break);
	if (map_fd_break < 0) {
		printf("Failed to get map tx fd\n");
		goto out_sockmap;
	}

	err = bpf_prog_attach(parse_prog, map_fd_break,
			      BPF_SK_SKB_STREAM_PARSER, 0);
	if (!err) {
		printf("Allowed attaching SK_SKB program to invalid map\n");
		goto out_sockmap;
	}

	err = bpf_prog_attach(parse_prog, map_fd_rx,
		      BPF_SK_SKB_STREAM_PARSER, 0);
	if (err) {
		printf("Failed stream parser bpf prog attach\n");
		goto out_sockmap;
	}

	err = bpf_prog_attach(verdict_prog, map_fd_rx,
			      BPF_SK_SKB_STREAM_VERDICT, 0);
	if (err) {
		printf("Failed stream verdict bpf prog attach\n");
		goto out_sockmap;
	}

	err = bpf_prog_attach(msg_prog, map_fd_msg, BPF_SK_MSG_VERDICT, 0);
	if (err) {
		printf("Failed msg verdict bpf prog attach\n");
		goto out_sockmap;
	}

	err = bpf_prog_attach(verdict_prog, map_fd_rx,
			      __MAX_BPF_ATTACH_TYPE, 0);
	if (!err) {
		printf("Attached unknown bpf prog\n");
		goto out_sockmap;
	}

	/* Test map update elem afterwards fd lives in fd and map_fd */
	for (i = 2; i < 6; i++) {
		err = bpf_map_update_elem(map_fd_rx, &i, &sfd[i], BPF_ANY);
		if (err) {
			printf("Failed map_fd_rx update sockmap %i '%i:%i'\n",
			       err, i, sfd[i]);
			goto out_sockmap;
		}
		err = bpf_map_update_elem(map_fd_tx, &i, &sfd[i], BPF_ANY);
		if (err) {
			printf("Failed map_fd_tx update sockmap %i '%i:%i'\n",
			       err, i, sfd[i]);
			goto out_sockmap;
		}
	}

	/* Test map delete elem and remove send/recv sockets */
	for (i = 2; i < 4; i++) {
		err = bpf_map_delete_elem(map_fd_rx, &i);
		if (err) {
			printf("Failed delete sockmap rx %i '%i:%i'\n",
			       err, i, sfd[i]);
			goto out_sockmap;
		}
		err = bpf_map_delete_elem(map_fd_tx, &i);
		if (err) {
			printf("Failed delete sockmap tx %i '%i:%i'\n",
			       err, i, sfd[i]);
			goto out_sockmap;
		}
	}

	/* Put sfd[2] (sending fd below) into msg map to test sendmsg bpf */
	i = 0;
	err = bpf_map_update_elem(map_fd_msg, &i, &sfd[2], BPF_ANY);
	if (err) {
		printf("Failed map_fd_msg update sockmap %i\n", err);
		goto out_sockmap;
	}

	/* Test map send/recv */
	for (i = 0; i < 2; i++) {
		buf[0] = i;
		buf[1] = 0x5;
		sc = send(sfd[2], buf, 20, 0);
		if (sc < 0) {
			printf("Failed sockmap send\n");
			goto out_sockmap;
		}

		FD_ZERO(&w);
		FD_SET(sfd[3], &w);
		to.tv_sec = 30;
		to.tv_usec = 0;
		s = select(sfd[3] + 1, &w, NULL, NULL, &to);
		if (s == -1) {
			perror("Failed sockmap select()");
			goto out_sockmap;
		} else if (!s) {
			printf("Failed sockmap unexpected timeout\n");
			goto out_sockmap;
		}

		if (!FD_ISSET(sfd[3], &w)) {
			printf("Failed sockmap select/recv\n");
			goto out_sockmap;
		}

		rc = recv(sfd[3], buf, sizeof(buf), 0);
		if (rc < 0) {
			printf("Failed sockmap recv\n");
			goto out_sockmap;
		}
	}

	/* Negative null entry lookup from datapath should be dropped */
	buf[0] = 1;
	buf[1] = 12;
	sc = send(sfd[2], buf, 20, 0);
	if (sc < 0) {
		printf("Failed sockmap send\n");
		goto out_sockmap;
	}

	/* Push fd into same slot */
	i = 2;
	err = bpf_map_update_elem(fd, &i, &sfd[i], BPF_NOEXIST);
	if (!err) {
		printf("Failed allowed sockmap dup slot BPF_NOEXIST\n");
		goto out_sockmap;
	}

	err = bpf_map_update_elem(fd, &i, &sfd[i], BPF_ANY);
	if (err) {
		printf("Failed sockmap update new slot BPF_ANY\n");
		goto out_sockmap;
	}

	err = bpf_map_update_elem(fd, &i, &sfd[i], BPF_EXIST);
	if (err) {
		printf("Failed sockmap update new slot BPF_EXIST\n");
		goto out_sockmap;
	}

	/* Delete the elems without programs */
	for (i = 2; i < 6; i++) {
		err = bpf_map_delete_elem(fd, &i);
		if (err) {
			printf("Failed delete sockmap %i '%i:%i'\n",
			       err, i, sfd[i]);
		}
	}

	/* Test having multiple maps open and set with programs on same fds */
	err = bpf_prog_attach(parse_prog, fd,
			      BPF_SK_SKB_STREAM_PARSER, 0);
	if (err) {
		printf("Failed fd bpf parse prog attach\n");
		goto out_sockmap;
	}
	err = bpf_prog_attach(verdict_prog, fd,
			      BPF_SK_SKB_STREAM_VERDICT, 0);
	if (err) {
		printf("Failed fd bpf verdict prog attach\n");
		goto out_sockmap;
	}

	for (i = 4; i < 6; i++) {
		err = bpf_map_update_elem(fd, &i, &sfd[i], BPF_ANY);
		if (!err) {
			printf("Failed allowed duplicate programs in update ANY sockmap %i '%i:%i'\n",
			       err, i, sfd[i]);
			goto out_sockmap;
		}
		err = bpf_map_update_elem(fd, &i, &sfd[i], BPF_NOEXIST);
		if (!err) {
			printf("Failed allowed duplicate program in update NOEXIST sockmap  %i '%i:%i'\n",
			       err, i, sfd[i]);
			goto out_sockmap;
		}
		err = bpf_map_update_elem(fd, &i, &sfd[i], BPF_EXIST);
		if (!err) {
			printf("Failed allowed duplicate program in update EXIST sockmap  %i '%i:%i'\n",
			       err, i, sfd[i]);
			goto out_sockmap;
		}
	}

	/* Test tasks number of forked operations */
	for (i = 0; i < tasks; i++) {
		pid[i] = fork();
		if (pid[i] == 0) {
			for (i = 0; i < 6; i++) {
				bpf_map_delete_elem(map_fd_tx, &i);
				bpf_map_delete_elem(map_fd_rx, &i);
				bpf_map_update_elem(map_fd_tx, &i,
						    &sfd[i], BPF_ANY);
				bpf_map_update_elem(map_fd_rx, &i,
						    &sfd[i], BPF_ANY);
			}
			exit(0);
		} else if (pid[i] == -1) {
			printf("Couldn't spawn #%d process!\n", i);
			exit(1);
		}
	}

	for (i = 0; i < tasks; i++) {
		int status;

		assert(waitpid(pid[i], &status, 0) == pid[i]);
		assert(status == 0);
	}

	err = bpf_prog_detach2(parse_prog, map_fd_rx, __MAX_BPF_ATTACH_TYPE);
	if (!err) {
		printf("Detached an invalid prog type.\n");
		goto out_sockmap;
	}

	err = bpf_prog_detach2(parse_prog, map_fd_rx, BPF_SK_SKB_STREAM_PARSER);
	if (err) {
		printf("Failed parser prog detach\n");
		goto out_sockmap;
	}

	err = bpf_prog_detach2(verdict_prog, map_fd_rx, BPF_SK_SKB_STREAM_VERDICT);
	if (err) {
		printf("Failed parser prog detach\n");
		goto out_sockmap;
	}

	/* Test map close sockets and empty maps */
	for (i = 0; i < 6; i++) {
		bpf_map_delete_elem(map_fd_tx, &i);
		bpf_map_delete_elem(map_fd_rx, &i);
		close(sfd[i]);
	}
	close(fd);
	close(map_fd_rx);
	bpf_object__close(obj);
	return;
out:
	for (i = 0; i < 6; i++)
		close(sfd[i]);
	printf("Failed to create sockmap '%i:%s'!\n", i, strerror(errno));
	exit(1);
out_sockmap:
	for (i = 0; i < 6; i++) {
		if (map_fd_tx)
			bpf_map_delete_elem(map_fd_tx, &i);
		if (map_fd_rx)
			bpf_map_delete_elem(map_fd_rx, &i);
		close(sfd[i]);
	}
	close(fd);
	exit(1);
}

#define MAPINMAP_PROG "./test_map_in_map.o"
static void test_map_in_map(void)
{
	struct bpf_object *obj;
	struct bpf_map *map;
	int mim_fd, fd, err;
	int pos = 0;

	obj = bpf_object__open(MAPINMAP_PROG);

	fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(int), sizeof(int),
			    2, 0);
	if (fd < 0) {
		printf("Failed to create hashmap '%s'!\n", strerror(errno));
		exit(1);
	}

	map = bpf_object__find_map_by_name(obj, "mim_array");
	if (IS_ERR(map)) {
		printf("Failed to load array of maps from test prog\n");
		goto out_map_in_map;
	}
	err = bpf_map__set_inner_map_fd(map, fd);
	if (err) {
		printf("Failed to set inner_map_fd for array of maps\n");
		goto out_map_in_map;
	}

	map = bpf_object__find_map_by_name(obj, "mim_hash");
	if (IS_ERR(map)) {
		printf("Failed to load hash of maps from test prog\n");
		goto out_map_in_map;
	}
	err = bpf_map__set_inner_map_fd(map, fd);
	if (err) {
		printf("Failed to set inner_map_fd for hash of maps\n");
		goto out_map_in_map;
	}

	bpf_object__load(obj);

	map = bpf_object__find_map_by_name(obj, "mim_array");
	if (IS_ERR(map)) {
		printf("Failed to load array of maps from test prog\n");
		goto out_map_in_map;
	}
	mim_fd = bpf_map__fd(map);
	if (mim_fd < 0) {
		printf("Failed to get descriptor for array of maps\n");
		goto out_map_in_map;
	}

	err = bpf_map_update_elem(mim_fd, &pos, &fd, 0);
	if (err) {
		printf("Failed to update array of maps\n");
		goto out_map_in_map;
	}

	map = bpf_object__find_map_by_name(obj, "mim_hash");
	if (IS_ERR(map)) {
		printf("Failed to load hash of maps from test prog\n");
		goto out_map_in_map;
	}
	mim_fd = bpf_map__fd(map);
	if (mim_fd < 0) {
		printf("Failed to get descriptor for hash of maps\n");
		goto out_map_in_map;
	}

	err = bpf_map_update_elem(mim_fd, &pos, &fd, 0);
	if (err) {
		printf("Failed to update hash of maps\n");
		goto out_map_in_map;
	}

	close(fd);
	bpf_object__close(obj);
	return;

out_map_in_map:
	close(fd);
	exit(1);
}

#define MAP_SIZE (32 * 1024)

static void test_map_large(void)
{
	struct bigkey {
		int a;
		char b[116];
		long long c;
	} key;
	int fd, i, value;

	fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(key), sizeof(value),
			    MAP_SIZE, map_flags);
	if (fd < 0) {
		printf("Failed to create large map '%s'!\n", strerror(errno));
		exit(1);
	}

	for (i = 0; i < MAP_SIZE; i++) {
		key = (struct bigkey) { .c = i };
		value = i;

		assert(bpf_map_update_elem(fd, &key, &value, BPF_NOEXIST) == 0);
	}

	key.c = -1;
	assert(bpf_map_update_elem(fd, &key, &value, BPF_NOEXIST) == -1 &&
	       errno == E2BIG);

	/* Iterate through all elements. */
	assert(bpf_map_get_next_key(fd, NULL, &key) == 0);
	key.c = -1;
	for (i = 0; i < MAP_SIZE; i++)
		assert(bpf_map_get_next_key(fd, &key, &key) == 0);
	assert(bpf_map_get_next_key(fd, &key, &key) == -1 && errno == ENOENT);

	key.c = 0;
	assert(bpf_map_lookup_elem(fd, &key, &value) == 0 && value == 0);
	key.a = 1;
	assert(bpf_map_lookup_elem(fd, &key, &value) == -1 && errno == ENOENT);

	close(fd);
}

#define run_parallel(N, FN, DATA) \
	printf("Fork %d tasks to '" #FN "'\n", N); \
	__run_parallel(N, FN, DATA)

static void __run_parallel(int tasks, void (*fn)(int task, void *data),
			   void *data)
{
	pid_t pid[tasks];
	int i;

	for (i = 0; i < tasks; i++) {
		pid[i] = fork();
		if (pid[i] == 0) {
			fn(i, data);
			exit(0);
		} else if (pid[i] == -1) {
			printf("Couldn't spawn #%d process!\n", i);
			exit(1);
		}
	}

	for (i = 0; i < tasks; i++) {
		int status;

		assert(waitpid(pid[i], &status, 0) == pid[i]);
		assert(status == 0);
	}
}

static void test_map_stress(void)
{
	run_parallel(100, test_hashmap, NULL);
	run_parallel(100, test_hashmap_percpu, NULL);
	run_parallel(100, test_hashmap_sizes, NULL);
	run_parallel(100, test_hashmap_walk, NULL);

	run_parallel(100, test_arraymap, NULL);
	run_parallel(100, test_arraymap_percpu, NULL);
}

#define TASKS 1024

#define DO_UPDATE 1
#define DO_DELETE 0

static void test_update_delete(int fn, void *data)
{
	int do_update = ((int *)data)[1];
	int fd = ((int *)data)[0];
	int i, key, value;

	for (i = fn; i < MAP_SIZE; i += TASKS) {
		key = value = i;

		if (do_update) {
			assert(bpf_map_update_elem(fd, &key, &value,
						   BPF_NOEXIST) == 0);
			assert(bpf_map_update_elem(fd, &key, &value,
						   BPF_EXIST) == 0);
		} else {
			assert(bpf_map_delete_elem(fd, &key) == 0);
		}
	}
}

static void test_map_parallel(void)
{
	int i, fd, key = 0, value = 0;
	int data[2];

	fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(key), sizeof(value),
			    MAP_SIZE, map_flags);
	if (fd < 0) {
		printf("Failed to create map for parallel test '%s'!\n",
		       strerror(errno));
		exit(1);
	}

	/* Use the same fd in children to add elements to this map:
	 * child_0 adds key=0, key=1024, key=2048, ...
	 * child_1 adds key=1, key=1025, key=2049, ...
	 * child_1023 adds key=1023, ...
	 */
	data[0] = fd;
	data[1] = DO_UPDATE;
	run_parallel(TASKS, test_update_delete, data);

	/* Check that key=0 is already there. */
	assert(bpf_map_update_elem(fd, &key, &value, BPF_NOEXIST) == -1 &&
	       errno == EEXIST);

	/* Check that all elements were inserted. */
	assert(bpf_map_get_next_key(fd, NULL, &key) == 0);
	key = -1;
	for (i = 0; i < MAP_SIZE; i++)
		assert(bpf_map_get_next_key(fd, &key, &key) == 0);
	assert(bpf_map_get_next_key(fd, &key, &key) == -1 && errno == ENOENT);

	/* Another check for all elements */
	for (i = 0; i < MAP_SIZE; i++) {
		key = MAP_SIZE - i - 1;

		assert(bpf_map_lookup_elem(fd, &key, &value) == 0 &&
		       value == key);
	}

	/* Now let's delete all elemenets in parallel. */
	data[1] = DO_DELETE;
	run_parallel(TASKS, test_update_delete, data);

	/* Nothing should be left. */
	key = -1;
	assert(bpf_map_get_next_key(fd, NULL, &key) == -1 && errno == ENOENT);
	assert(bpf_map_get_next_key(fd, &key, &key) == -1 && errno == ENOENT);
}

static void test_map_rdonly(void)
{
	int fd, key = 0, value = 0;

	fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(key), sizeof(value),
			    MAP_SIZE, map_flags | BPF_F_RDONLY);
	if (fd < 0) {
		printf("Failed to create map for read only test '%s'!\n",
		       strerror(errno));
		exit(1);
	}

	key = 1;
	value = 1234;
	/* Insert key=1 element. */
	assert(bpf_map_update_elem(fd, &key, &value, BPF_ANY) == -1 &&
	       errno == EPERM);

	/* Check that key=2 is not found. */
	assert(bpf_map_lookup_elem(fd, &key, &value) == -1 && errno == ENOENT);
	assert(bpf_map_get_next_key(fd, &key, &value) == -1 && errno == ENOENT);
}

static void test_map_wronly(void)
{
	int fd, key = 0, value = 0;

	fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(key), sizeof(value),
			    MAP_SIZE, map_flags | BPF_F_WRONLY);
	if (fd < 0) {
		printf("Failed to create map for read only test '%s'!\n",
		       strerror(errno));
		exit(1);
	}

	key = 1;
	value = 1234;
	/* Insert key=1 element. */
	assert(bpf_map_update_elem(fd, &key, &value, BPF_ANY) == 0);

	/* Check that key=2 is not found. */
	assert(bpf_map_lookup_elem(fd, &key, &value) == -1 && errno == EPERM);
	assert(bpf_map_get_next_key(fd, &key, &value) == -1 && errno == EPERM);
}

static void prepare_reuseport_grp(int type, int map_fd,
				  __s64 *fds64, __u64 *sk_cookies,
				  unsigned int n)
{
	socklen_t optlen, addrlen;
	struct sockaddr_in6 s6;
	const __u32 index0 = 0;
	const int optval = 1;
	unsigned int i;
	u64 sk_cookie;
	__s64 fd64;
	int err;

	s6.sin6_family = AF_INET6;
	s6.sin6_addr = in6addr_any;
	s6.sin6_port = 0;
	addrlen = sizeof(s6);
	optlen = sizeof(sk_cookie);

	for (i = 0; i < n; i++) {
		fd64 = socket(AF_INET6, type, 0);
		CHECK(fd64 == -1, "socket()",
		      "sock_type:%d fd64:%lld errno:%d\n",
		      type, fd64, errno);

		err = setsockopt(fd64, SOL_SOCKET, SO_REUSEPORT,
				 &optval, sizeof(optval));
		CHECK(err == -1, "setsockopt(SO_REUSEPORT)",
		      "err:%d errno:%d\n", err, errno);

		/* reuseport_array does not allow unbound sk */
		err = bpf_map_update_elem(map_fd, &index0, &fd64,
					  BPF_ANY);
		CHECK(err != -1 || errno != EINVAL,
		      "reuseport array update unbound sk",
		      "sock_type:%d err:%d errno:%d\n",
		      type, err, errno);

		err = bind(fd64, (struct sockaddr *)&s6, sizeof(s6));
		CHECK(err == -1, "bind()",
		      "sock_type:%d err:%d errno:%d\n", type, err, errno);

		if (i == 0) {
			err = getsockname(fd64, (struct sockaddr *)&s6,
					  &addrlen);
			CHECK(err == -1, "getsockname()",
			      "sock_type:%d err:%d errno:%d\n",
			      type, err, errno);
		}

		err = getsockopt(fd64, SOL_SOCKET, SO_COOKIE, &sk_cookie,
				 &optlen);
		CHECK(err == -1, "getsockopt(SO_COOKIE)",
		      "sock_type:%d err:%d errno:%d\n", type, err, errno);

		if (type == SOCK_STREAM) {
			/*
			 * reuseport_array does not allow
			 * non-listening tcp sk.
			 */
			err = bpf_map_update_elem(map_fd, &index0, &fd64,
						  BPF_ANY);
			CHECK(err != -1 || errno != EINVAL,
			      "reuseport array update non-listening sk",
			      "sock_type:%d err:%d errno:%d\n",
			      type, err, errno);
			err = listen(fd64, 0);
			CHECK(err == -1, "listen()",
			      "sock_type:%d, err:%d errno:%d\n",
			      type, err, errno);
		}

		fds64[i] = fd64;
		sk_cookies[i] = sk_cookie;
	}
}

static void test_reuseport_array(void)
{
#define REUSEPORT_FD_IDX(err, last) ({ (err) ? last : !last; })

	const __u32 array_size = 4, index0 = 0, index3 = 3;
	int types[2] = { SOCK_STREAM, SOCK_DGRAM }, type;
	__u64 grpa_cookies[2], sk_cookie, map_cookie;
	__s64 grpa_fds64[2] = { -1, -1 }, fd64 = -1;
	const __u32 bad_index = array_size;
	int map_fd, err, t, f;
	__u32 fds_idx = 0;
	int fd;

	map_fd = bpf_create_map(BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
				sizeof(__u32), sizeof(__u64), array_size, 0);
	CHECK(map_fd == -1, "reuseport array create",
	      "map_fd:%d, errno:%d\n", map_fd, errno);

	/* Test lookup/update/delete with invalid index */
	err = bpf_map_delete_elem(map_fd, &bad_index);
	CHECK(err != -1 || errno != E2BIG, "reuseport array del >=max_entries",
	      "err:%d errno:%d\n", err, errno);

	err = bpf_map_update_elem(map_fd, &bad_index, &fd64, BPF_ANY);
	CHECK(err != -1 || errno != E2BIG,
	      "reuseport array update >=max_entries",
	      "err:%d errno:%d\n", err, errno);

	err = bpf_map_lookup_elem(map_fd, &bad_index, &map_cookie);
	CHECK(err != -1 || errno != ENOENT,
	      "reuseport array update >=max_entries",
	      "err:%d errno:%d\n", err, errno);

	/* Test lookup/delete non existence elem */
	err = bpf_map_lookup_elem(map_fd, &index3, &map_cookie);
	CHECK(err != -1 || errno != ENOENT,
	      "reuseport array lookup not-exist elem",
	      "err:%d errno:%d\n", err, errno);
	err = bpf_map_delete_elem(map_fd, &index3);
	CHECK(err != -1 || errno != ENOENT,
	      "reuseport array del not-exist elem",
	      "err:%d errno:%d\n", err, errno);

	for (t = 0; t < ARRAY_SIZE(types); t++) {
		type = types[t];

		prepare_reuseport_grp(type, map_fd, grpa_fds64,
				      grpa_cookies, ARRAY_SIZE(grpa_fds64));

		/* Test BPF_* update flags */
		/* BPF_EXIST failure case */
		err = bpf_map_update_elem(map_fd, &index3, &grpa_fds64[fds_idx],
					  BPF_EXIST);
		CHECK(err != -1 || errno != ENOENT,
		      "reuseport array update empty elem BPF_EXIST",
		      "sock_type:%d err:%d errno:%d\n",
		      type, err, errno);
		fds_idx = REUSEPORT_FD_IDX(err, fds_idx);

		/* BPF_NOEXIST success case */
		err = bpf_map_update_elem(map_fd, &index3, &grpa_fds64[fds_idx],
					  BPF_NOEXIST);
		CHECK(err == -1,
		      "reuseport array update empty elem BPF_NOEXIST",
		      "sock_type:%d err:%d errno:%d\n",
		      type, err, errno);
		fds_idx = REUSEPORT_FD_IDX(err, fds_idx);

		/* BPF_EXIST success case. */
		err = bpf_map_update_elem(map_fd, &index3, &grpa_fds64[fds_idx],
					  BPF_EXIST);
		CHECK(err == -1,
		      "reuseport array update same elem BPF_EXIST",
		      "sock_type:%d err:%d errno:%d\n", type, err, errno);
		fds_idx = REUSEPORT_FD_IDX(err, fds_idx);

		/* BPF_NOEXIST failure case */
		err = bpf_map_update_elem(map_fd, &index3, &grpa_fds64[fds_idx],
					  BPF_NOEXIST);
		CHECK(err != -1 || errno != EEXIST,
		      "reuseport array update non-empty elem BPF_NOEXIST",
		      "sock_type:%d err:%d errno:%d\n",
		      type, err, errno);
		fds_idx = REUSEPORT_FD_IDX(err, fds_idx);

		/* BPF_ANY case (always succeed) */
		err = bpf_map_update_elem(map_fd, &index3, &grpa_fds64[fds_idx],
					  BPF_ANY);
		CHECK(err == -1,
		      "reuseport array update same sk with BPF_ANY",
		      "sock_type:%d err:%d errno:%d\n", type, err, errno);

		fd64 = grpa_fds64[fds_idx];
		sk_cookie = grpa_cookies[fds_idx];

		/* The same sk cannot be added to reuseport_array twice */
		err = bpf_map_update_elem(map_fd, &index3, &fd64, BPF_ANY);
		CHECK(err != -1 || errno != EBUSY,
		      "reuseport array update same sk with same index",
		      "sock_type:%d err:%d errno:%d\n",
		      type, err, errno);

		err = bpf_map_update_elem(map_fd, &index0, &fd64, BPF_ANY);
		CHECK(err != -1 || errno != EBUSY,
		      "reuseport array update same sk with different index",
		      "sock_type:%d err:%d errno:%d\n",
		      type, err, errno);

		/* Test delete elem */
		err = bpf_map_delete_elem(map_fd, &index3);
		CHECK(err == -1, "reuseport array delete sk",
		      "sock_type:%d err:%d errno:%d\n",
		      type, err, errno);

		/* Add it back with BPF_NOEXIST */
		err = bpf_map_update_elem(map_fd, &index3, &fd64, BPF_NOEXIST);
		CHECK(err == -1,
		      "reuseport array re-add with BPF_NOEXIST after del",
		      "sock_type:%d err:%d errno:%d\n", type, err, errno);

		/* Test cookie */
		err = bpf_map_lookup_elem(map_fd, &index3, &map_cookie);
		CHECK(err == -1 || sk_cookie != map_cookie,
		      "reuseport array lookup re-added sk",
		      "sock_type:%d err:%d errno:%d sk_cookie:0x%llx map_cookie:0x%llxn",
		      type, err, errno, sk_cookie, map_cookie);

		/* Test elem removed by close() */
		for (f = 0; f < ARRAY_SIZE(grpa_fds64); f++)
			close(grpa_fds64[f]);
		err = bpf_map_lookup_elem(map_fd, &index3, &map_cookie);
		CHECK(err != -1 || errno != ENOENT,
		      "reuseport array lookup after close()",
		      "sock_type:%d err:%d errno:%d\n",
		      type, err, errno);
	}

	/* Test SOCK_RAW */
	fd64 = socket(AF_INET6, SOCK_RAW, IPPROTO_UDP);
	CHECK(fd64 == -1, "socket(SOCK_RAW)", "err:%d errno:%d\n",
	      err, errno);
	err = bpf_map_update_elem(map_fd, &index3, &fd64, BPF_NOEXIST);
	CHECK(err != -1 || errno != ENOTSUPP, "reuseport array update SOCK_RAW",
	      "err:%d errno:%d\n", err, errno);
	close(fd64);

	/* Close the 64 bit value map */
	close(map_fd);

	/* Test 32 bit fd */
	map_fd = bpf_create_map(BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
				sizeof(__u32), sizeof(__u32), array_size, 0);
	CHECK(map_fd == -1, "reuseport array create",
	      "map_fd:%d, errno:%d\n", map_fd, errno);
	prepare_reuseport_grp(SOCK_STREAM, map_fd, &fd64, &sk_cookie, 1);
	fd = fd64;
	err = bpf_map_update_elem(map_fd, &index3, &fd, BPF_NOEXIST);
	CHECK(err == -1, "reuseport array update 32 bit fd",
	      "err:%d errno:%d\n", err, errno);
	err = bpf_map_lookup_elem(map_fd, &index3, &map_cookie);
	CHECK(err != -1 || errno != ENOSPC,
	      "reuseport array lookup 32 bit fd",
	      "err:%d errno:%d\n", err, errno);
	close(fd);
	close(map_fd);
}

static struct bpf_create_map_attr xattr = {
	.name = "sk_storage_map",
	.map_type = BPF_MAP_TYPE_SK_STORAGE,
	.map_flags = BPF_F_NO_PREALLOC,
	.max_entries = 0,
	.key_size = 4,
	.value_size = 8,
	.btf_key_type_id = 1,
	.btf_value_type_id = 3,
	.btf_fd = -1,
};

static unsigned int nr_sk_threads_done;
static unsigned int nr_sk_threads_err;
static unsigned int nr_sk_per_thread = 4096;
static unsigned int nr_sk_threads = 4;
static int sk_storage_map = -1;
static unsigned int stop;
static int runtime_s = 5;

static bool is_stopped(void)
{
	return READ_ONCE(stop);
}

static unsigned int threads_err(void)
{
	return READ_ONCE(nr_sk_threads_err);
}

static void notify_thread_err(void)
{
	__sync_add_and_fetch(&nr_sk_threads_err, 1);
}

static bool wait_for_threads_err(void)
{
	while (!is_stopped() && !threads_err())
		usleep(500);

	return !is_stopped();
}

static unsigned int threads_done(void)
{
	return READ_ONCE(nr_sk_threads_done);
}

static void notify_thread_done(void)
{
	__sync_add_and_fetch(&nr_sk_threads_done, 1);
}

static void notify_thread_redo(void)
{
	__sync_sub_and_fetch(&nr_sk_threads_done, 1);
}

static bool wait_for_threads_done(void)
{
	while (threads_done() != nr_sk_threads && !is_stopped() &&
	       !threads_err())
		usleep(50);

	return !is_stopped() && !threads_err();
}

static bool wait_for_threads_redo(void)
{
	while (threads_done() && !is_stopped() && !threads_err())
		usleep(50);

	return !is_stopped() && !threads_err();
}

static bool wait_for_map(void)
{
	while (READ_ONCE(sk_storage_map) == -1 && !is_stopped())
		usleep(50);

	return !is_stopped();
}

static bool wait_for_map_close(void)
{
	while (READ_ONCE(sk_storage_map) != -1 && !is_stopped())
		;

	return !is_stopped();
}

static int load_btf(void)
{
	const char btf_str_sec[] = "\0bpf_spin_lock\0val\0cnt\0l";
	__u32 btf_raw_types[] = {
		/* int */
		BTF_TYPE_INT_ENC(0, BTF_INT_SIGNED, 0, 32, 4),  /* [1] */
		/* struct bpf_spin_lock */                      /* [2] */
		BTF_TYPE_ENC(1, BTF_INFO_ENC(BTF_KIND_STRUCT, 0, 1), 4),
		BTF_MEMBER_ENC(15, 1, 0), /* int val; */
		/* struct val */                                /* [3] */
		BTF_TYPE_ENC(15, BTF_INFO_ENC(BTF_KIND_STRUCT, 0, 2), 8),
		BTF_MEMBER_ENC(19, 1, 0), /* int cnt; */
		BTF_MEMBER_ENC(23, 2, 32),/* struct bpf_spin_lock l; */
	};
	struct btf_header btf_hdr = {
		.magic = BTF_MAGIC,
		.version = BTF_VERSION,
		.hdr_len = sizeof(struct btf_header),
		.type_len = sizeof(btf_raw_types),
		.str_off = sizeof(btf_raw_types),
		.str_len = sizeof(btf_str_sec),
	};
	__u8 raw_btf[sizeof(struct btf_header) + sizeof(btf_raw_types) +
		     sizeof(btf_str_sec)];

	memcpy(raw_btf, &btf_hdr, sizeof(btf_hdr));
	memcpy(raw_btf + sizeof(btf_hdr), btf_raw_types, sizeof(btf_raw_types));
	memcpy(raw_btf + sizeof(btf_hdr) + sizeof(btf_raw_types),
	       btf_str_sec, sizeof(btf_str_sec));

	return bpf_load_btf(raw_btf, sizeof(raw_btf), 0, 0, 0);
}

static int create_sk_storage_map(void)
{
	int btf_fd, map_fd;

	btf_fd = load_btf();
	CHECK(btf_fd == -1, "bpf_load_btf", "btf_fd:%d errno:%d\n",
	      btf_fd, errno);
	xattr.btf_fd = btf_fd;

	map_fd = bpf_create_map_xattr(&xattr);
	xattr.btf_fd = -1;
	close(btf_fd);
	CHECK(map_fd == -1,
	      "bpf_create_map_xattr()", "errno:%d\n", errno);

	return map_fd;
}

static void *insert_close_thread(void *arg)
{
	struct {
		int cnt;
		int lock;
	} value = { .cnt = 0xeB9F, .lock = 0, };
	int i, map_fd, err, *sk_fds;

	sk_fds = malloc(sizeof(*sk_fds) * nr_sk_per_thread);
	if (!sk_fds) {
		notify_thread_err();
		return ERR_PTR(-ENOMEM);
	}

	for (i = 0; i < nr_sk_per_thread; i++)
		sk_fds[i] = -1;

	while (!is_stopped()) {
		if (!wait_for_map())
			goto close_all;

		map_fd = READ_ONCE(sk_storage_map);
		for (i = 0; i < nr_sk_per_thread && !is_stopped(); i++) {
			sk_fds[i] = socket(AF_INET6, SOCK_STREAM, 0);
			if (sk_fds[i] == -1) {
				err = -errno;
				fprintf(stderr, "socket(): errno:%d\n", errno);
				goto errout;
			}
			err = bpf_map_update_elem(map_fd, &sk_fds[i], &value,
						  BPF_NOEXIST);
			if (err) {
				err = -errno;
				fprintf(stderr,
					"bpf_map_update_elem(): errno:%d\n",
					errno);
				goto errout;
			}
		}

		notify_thread_done();
		wait_for_map_close();

close_all:
		for (i = 0; i < nr_sk_per_thread; i++) {
			close(sk_fds[i]);
			sk_fds[i] = -1;
		}

		notify_thread_redo();
	}

	free(sk_fds);
	return NULL;

errout:
	for (i = 0; i < nr_sk_per_thread && sk_fds[i] != -1; i++)
		close(sk_fds[i]);
	free(sk_fds);
	notify_thread_err();
	return ERR_PTR(err);
}

static int do_sk_storage_map_stress_free(void)
{
	int i, map_fd = -1, err = 0, nr_threads_created = 0;
	pthread_t *sk_thread_ids;
	void *thread_ret;

	sk_thread_ids = malloc(sizeof(pthread_t) * nr_sk_threads);
	if (!sk_thread_ids) {
		fprintf(stderr, "malloc(sk_threads): NULL\n");
		return -ENOMEM;
	}

	for (i = 0; i < nr_sk_threads; i++) {
		err = pthread_create(&sk_thread_ids[i], NULL,
				     insert_close_thread, NULL);
		if (err) {
			err = -errno;
			goto done;
		}
		nr_threads_created++;
	}

	while (!is_stopped()) {
		map_fd = create_sk_storage_map();
		WRITE_ONCE(sk_storage_map, map_fd);

		if (!wait_for_threads_done())
			break;

		WRITE_ONCE(sk_storage_map, -1);
		close(map_fd);
		map_fd = -1;

		if (!wait_for_threads_redo())
			break;
	}

done:
	WRITE_ONCE(stop, 1);
	for (i = 0; i < nr_threads_created; i++) {
		pthread_join(sk_thread_ids[i], &thread_ret);
		if (IS_ERR(thread_ret) && !err) {
			err = PTR_ERR(thread_ret);
			fprintf(stderr, "threads#%u: err:%d\n", i, err);
		}
	}
	free(sk_thread_ids);

	if (map_fd != -1)
		close(map_fd);

	return err;
}

static void *update_thread(void *arg)
{
	struct {
		int cnt;
		int lock;
	} value = { .cnt = 0xeB9F, .lock = 0, };
	int map_fd = READ_ONCE(sk_storage_map);
	int sk_fd = *(int *)arg;
	int err = 0; /* Suppress compiler false alarm */

	while (!is_stopped()) {
		err = bpf_map_update_elem(map_fd, &sk_fd, &value, 0);
		if (err && errno != EAGAIN) {
			err = -errno;
			fprintf(stderr, "bpf_map_update_elem: %d %d\n",
				err, errno);
			break;
		}
	}

	if (!is_stopped()) {
		notify_thread_err();
		return ERR_PTR(err);
	}

	return NULL;
}

static void *delete_thread(void *arg)
{
	int map_fd = READ_ONCE(sk_storage_map);
	int sk_fd = *(int *)arg;
	int err = 0; /* Suppress compiler false alarm */

	while (!is_stopped()) {
		err = bpf_map_delete_elem(map_fd, &sk_fd);
		if (err && errno != ENOENT) {
			err = -errno;
			fprintf(stderr, "bpf_map_delete_elem: %d %d\n",
				err, errno);
			break;
		}
	}

	if (!is_stopped()) {
		notify_thread_err();
		return ERR_PTR(err);
	}

	return NULL;
}

static int do_sk_storage_map_stress_change(void)
{
	int i, sk_fd, map_fd = -1, err = 0, nr_threads_created = 0;
	pthread_t *sk_thread_ids;
	void *thread_ret;

	sk_thread_ids = malloc(sizeof(pthread_t) * nr_sk_threads);
	if (!sk_thread_ids) {
		fprintf(stderr, "malloc(sk_threads): NULL\n");
		return -ENOMEM;
	}

	sk_fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (sk_fd == -1) {
		err = -errno;
		goto done;
	}

	map_fd = create_sk_storage_map();
	WRITE_ONCE(sk_storage_map, map_fd);

	for (i = 0; i < nr_sk_threads; i++) {
		if (i & 0x1)
			err = pthread_create(&sk_thread_ids[i], NULL,
					     update_thread, &sk_fd);
		else
			err = pthread_create(&sk_thread_ids[i], NULL,
					     delete_thread, &sk_fd);
		if (err) {
			err = -errno;
			goto done;
		}
		nr_threads_created++;
	}

	wait_for_threads_err();

done:
	WRITE_ONCE(stop, 1);
	for (i = 0; i < nr_threads_created; i++) {
		pthread_join(sk_thread_ids[i], &thread_ret);
		if (IS_ERR(thread_ret) && !err) {
			err = PTR_ERR(thread_ret);
			fprintf(stderr, "threads#%u: err:%d\n", i, err);
		}
	}
	free(sk_thread_ids);

	if (sk_fd != -1)
		close(sk_fd);
	close(map_fd);

	return err;
}

static void stop_handler(int signum)
{
	if (signum != SIGALRM)
		printf("stopping...\n");
	WRITE_ONCE(stop, 1);
}

#define BPF_SK_STORAGE_MAP_TEST_NR_THREADS "BPF_SK_STORAGE_MAP_TEST_NR_THREADS"
#define BPF_SK_STORAGE_MAP_TEST_SK_PER_THREAD "BPF_SK_STORAGE_MAP_TEST_SK_PER_THREAD"
#define BPF_SK_STORAGE_MAP_TEST_RUNTIME_S "BPF_SK_STORAGE_MAP_TEST_RUNTIME_S"
#define BPF_SK_STORAGE_MAP_TEST_NAME "BPF_SK_STORAGE_MAP_TEST_NAME"

static void test_sk_storage_map_stress_free(void)
{
	struct rlimit rlim_old, rlim_new = {};
	int err;

	getrlimit(RLIMIT_NOFILE, &rlim_old);

	signal(SIGTERM, stop_handler);
	signal(SIGINT, stop_handler);
	if (runtime_s > 0) {
		signal(SIGALRM, stop_handler);
		alarm(runtime_s);
	}

	if (rlim_old.rlim_cur < nr_sk_threads * nr_sk_per_thread) {
		rlim_new.rlim_cur = nr_sk_threads * nr_sk_per_thread + 128;
		rlim_new.rlim_max = rlim_new.rlim_cur + 128;
		err = setrlimit(RLIMIT_NOFILE, &rlim_new);
		CHECK(err, "setrlimit(RLIMIT_NOFILE)", "rlim_new:%lu errno:%d",
		      rlim_new.rlim_cur, errno);
	}

	err = do_sk_storage_map_stress_free();

	signal(SIGTERM, SIG_DFL);
	signal(SIGINT, SIG_DFL);
	if (runtime_s > 0) {
		signal(SIGALRM, SIG_DFL);
		alarm(0);
	}

	if (rlim_new.rlim_cur)
		setrlimit(RLIMIT_NOFILE, &rlim_old);

	CHECK(err, "test_sk_storage_map_stress_free", "err:%d\n", err);
}

static void test_sk_storage_map_stress_change(void)
{
	int err;

	signal(SIGTERM, stop_handler);
	signal(SIGINT, stop_handler);
	if (runtime_s > 0) {
		signal(SIGALRM, stop_handler);
		alarm(runtime_s);
	}

	err = do_sk_storage_map_stress_change();

	signal(SIGTERM, SIG_DFL);
	signal(SIGINT, SIG_DFL);
	if (runtime_s > 0) {
		signal(SIGALRM, SIG_DFL);
		alarm(0);
	}

	CHECK(err, "test_sk_storage_map_stress_change", "err:%d\n", err);
}

static void test_sk_storage_map_basic(void)
{
	struct {
		int cnt;
		int lock;
	} value = { .cnt = 0xeB9f, .lock = 0, }, lookup_value;
	struct bpf_create_map_attr bad_xattr;
	int btf_fd, map_fd, sk_fd, err;

	btf_fd = load_btf();
	CHECK(btf_fd == -1, "bpf_load_btf", "btf_fd:%d errno:%d\n",
	      btf_fd, errno);
	xattr.btf_fd = btf_fd;

	sk_fd = socket(AF_INET6, SOCK_STREAM, 0);
	CHECK(sk_fd == -1, "socket()", "sk_fd:%d errno:%d\n",
	      sk_fd, errno);

	map_fd = bpf_create_map_xattr(&xattr);
	CHECK(map_fd == -1, "bpf_create_map_xattr(good_xattr)",
	      "map_fd:%d errno:%d\n", map_fd, errno);

	/* Add new elem */
	memcpy(&lookup_value, &value, sizeof(value));
	err = bpf_map_update_elem(map_fd, &sk_fd, &value,
				  BPF_NOEXIST | BPF_F_LOCK);
	CHECK(err, "bpf_map_update_elem(BPF_NOEXIST|BPF_F_LOCK)",
	      "err:%d errno:%d\n", err, errno);
	err = bpf_map_lookup_elem_flags(map_fd, &sk_fd, &lookup_value,
					BPF_F_LOCK);
	CHECK(err || lookup_value.cnt != value.cnt,
	      "bpf_map_lookup_elem_flags(BPF_F_LOCK)",
	      "err:%d errno:%d cnt:%x(%x)\n",
	      err, errno, lookup_value.cnt, value.cnt);

	/* Bump the cnt and update with BPF_EXIST | BPF_F_LOCK */
	value.cnt += 1;
	err = bpf_map_update_elem(map_fd, &sk_fd, &value,
				  BPF_EXIST | BPF_F_LOCK);
	CHECK(err, "bpf_map_update_elem(BPF_EXIST|BPF_F_LOCK)",
	      "err:%d errno:%d\n", err, errno);
	err = bpf_map_lookup_elem_flags(map_fd, &sk_fd, &lookup_value,
					BPF_F_LOCK);
	CHECK(err || lookup_value.cnt != value.cnt,
	      "bpf_map_lookup_elem_flags(BPF_F_LOCK)",
	      "err:%d errno:%d cnt:%x(%x)\n",
	      err, errno, lookup_value.cnt, value.cnt);

	/* Bump the cnt and update with BPF_EXIST */
	value.cnt += 1;
	err = bpf_map_update_elem(map_fd, &sk_fd, &value, BPF_EXIST);
	CHECK(err, "bpf_map_update_elem(BPF_EXIST)",
	      "err:%d errno:%d\n", err, errno);
	err = bpf_map_lookup_elem_flags(map_fd, &sk_fd, &lookup_value,
					BPF_F_LOCK);
	CHECK(err || lookup_value.cnt != value.cnt,
	      "bpf_map_lookup_elem_flags(BPF_F_LOCK)",
	      "err:%d errno:%d cnt:%x(%x)\n",
	      err, errno, lookup_value.cnt, value.cnt);

	/* Update with BPF_NOEXIST */
	value.cnt += 1;
	err = bpf_map_update_elem(map_fd, &sk_fd, &value,
				  BPF_NOEXIST | BPF_F_LOCK);
	CHECK(!err || errno != EEXIST,
	      "bpf_map_update_elem(BPF_NOEXIST|BPF_F_LOCK)",
	      "err:%d errno:%d\n", err, errno);
	err = bpf_map_update_elem(map_fd, &sk_fd, &value, BPF_NOEXIST);
	CHECK(!err || errno != EEXIST, "bpf_map_update_elem(BPF_NOEXIST)",
	      "err:%d errno:%d\n", err, errno);
	value.cnt -= 1;
	err = bpf_map_lookup_elem_flags(map_fd, &sk_fd, &lookup_value,
					BPF_F_LOCK);
	CHECK(err || lookup_value.cnt != value.cnt,
	      "bpf_map_lookup_elem_flags(BPF_F_LOCK)",
	      "err:%d errno:%d cnt:%x(%x)\n",
	      err, errno, lookup_value.cnt, value.cnt);

	/* Bump the cnt again and update with map_flags == 0 */
	value.cnt += 1;
	err = bpf_map_update_elem(map_fd, &sk_fd, &value, 0);
	CHECK(err, "bpf_map_update_elem()", "err:%d errno:%d\n",
	      err, errno);
	err = bpf_map_lookup_elem_flags(map_fd, &sk_fd, &lookup_value,
					BPF_F_LOCK);
	CHECK(err || lookup_value.cnt != value.cnt,
	      "bpf_map_lookup_elem_flags(BPF_F_LOCK)",
	      "err:%d errno:%d cnt:%x(%x)\n",
	      err, errno, lookup_value.cnt, value.cnt);

	/* Test delete elem */
	err = bpf_map_delete_elem(map_fd, &sk_fd);
	CHECK(err, "bpf_map_delete_elem()", "err:%d errno:%d\n",
	      err, errno);
	err = bpf_map_lookup_elem_flags(map_fd, &sk_fd, &lookup_value,
					BPF_F_LOCK);
	CHECK(!err || errno != ENOENT,
	      "bpf_map_lookup_elem_flags(BPF_F_LOCK)",
	      "err:%d errno:%d\n", err, errno);
	err = bpf_map_delete_elem(map_fd, &sk_fd);
	CHECK(!err || errno != ENOENT, "bpf_map_delete_elem()",
	      "err:%d errno:%d\n", err, errno);

	memcpy(&bad_xattr, &xattr, sizeof(xattr));
	bad_xattr.btf_key_type_id = 0;
	err = bpf_create_map_xattr(&bad_xattr);
	CHECK(!err || errno != EINVAL, "bap_create_map_xattr(bad_xattr)",
	      "err:%d errno:%d\n", err, errno);

	memcpy(&bad_xattr, &xattr, sizeof(xattr));
	bad_xattr.btf_key_type_id = 3;
	err = bpf_create_map_xattr(&bad_xattr);
	CHECK(!err || errno != EINVAL, "bap_create_map_xattr(bad_xattr)",
	      "err:%d errno:%d\n", err, errno);

	memcpy(&bad_xattr, &xattr, sizeof(xattr));
	bad_xattr.max_entries = 1;
	err = bpf_create_map_xattr(&bad_xattr);
	CHECK(!err || errno != EINVAL, "bap_create_map_xattr(bad_xattr)",
	      "err:%d errno:%d\n", err, errno);

	memcpy(&bad_xattr, &xattr, sizeof(xattr));
	bad_xattr.map_flags = 0;
	err = bpf_create_map_xattr(&bad_xattr);
	CHECK(!err || errno != EINVAL, "bap_create_map_xattr(bad_xattr)",
	      "err:%d errno:%d\n", err, errno);

	xattr.btf_fd = -1;
	close(btf_fd);
	close(map_fd);
	close(sk_fd);
}

static void test_sk_storage_map(void)
{
	const char *test_name, *env_opt;
	bool test_ran = false;

	test_name = getenv(BPF_SK_STORAGE_MAP_TEST_NAME);

	env_opt = getenv(BPF_SK_STORAGE_MAP_TEST_NR_THREADS);
	if (env_opt)
		nr_sk_threads = atoi(env_opt);

	env_opt = getenv(BPF_SK_STORAGE_MAP_TEST_SK_PER_THREAD);
	if (env_opt)
		nr_sk_per_thread = atoi(env_opt);

	env_opt = getenv(BPF_SK_STORAGE_MAP_TEST_RUNTIME_S);
	if (env_opt)
		runtime_s = atoi(env_opt);

	if (!test_name || !strcmp(test_name, "basic")) {
		test_sk_storage_map_basic();
		test_ran = true;
	}
	if (!test_name || !strcmp(test_name, "stress_free")) {
		test_sk_storage_map_stress_free();
		test_ran = true;
	}
	if (!test_name || !strcmp(test_name, "stress_change")) {
		test_sk_storage_map_stress_change();
		test_ran = true;
	}

	if (test_ran)
		printf("%s:PASS\n", __func__);
	else
		CHECK(1, "Invalid test_name", "%s\n", test_name);
}

static void run_all_tests(void)
{
	test_hashmap(0, NULL);
	test_hashmap_percpu(0, NULL);
	test_hashmap_walk(0, NULL);
	test_hashmap_zero_seed();

	test_arraymap(0, NULL);
	test_arraymap_percpu(0, NULL);

	test_arraymap_percpu_many_keys();

	test_devmap(0, NULL);
	test_devmap_hash(0, NULL);
	test_sockmap(0, NULL);

	test_map_large();
	test_map_parallel();
	test_map_stress();

	test_map_rdonly();
	test_map_wronly();

	test_reuseport_array();

	test_queuemap(0, NULL);
	test_stackmap(0, NULL);

	test_map_in_map();
}

int main(void)
{
	srand(time(NULL));

	map_flags = 0;
	run_all_tests();

	map_flags = BPF_F_NO_PREALLOC;
	run_all_tests();

	test_sk_storage_map();

	printf("test_maps: OK, %d SKIPPED\n", skips);
	return 0;
}
