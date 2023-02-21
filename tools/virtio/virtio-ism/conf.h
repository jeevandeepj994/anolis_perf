/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef __CONF_H__
#define __CONF_H__

#include <sys/mman.h>
#include <stdio.h>
#include <stddef.h>
#include <fcntl.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <poll.h>
#include <linux/virtio_ism.h>
#include <sys/time.h>
#include <pthread.h>
#include <stdarg.h>
#include <sys/types.h>	       /* See NOTES */
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <linux/compiler.h>

typedef int64_t u64;

struct conf {
	char *devpath;
	int (*handle)(void);
	u64 token;

	bool bilateral;
	int num;
	int nthread;
	int debug;
	char *write_msg;
	bool read_msg;
	int wait_sec;
	int commit;
	bool polling;
	char *ip;
	bool pp;
	int msgsize;
	int tp_chunks;
	int test_case;
};

struct msg {
	u64 token;
};

struct event {
	u64 ev;
	char padding[64];
	u64 done;
	char padding1[64];
};

enum {
	CASE_PP,
	CASE_PP_POLLING,
	CASE_TP,
	CASE_TP_POLLING,
	CASE_TP_POLLING_CHUNKS,
};

#define PAGE_SIZE (4*1024)
#define REGION_SIZE (1024 * 1024)

static inline void llog(const char *fmt, ...)
{
	va_list ap;
	char buf[512];
	int size;

	va_start(ap, fmt);
	size = vsprintf(buf, fmt, ap);
	va_end(ap);

	write(1, buf, size);
}


int server_handle(void);

void commit(int fd);
void *alloc(u64 *token, int *fdp);
void *attach(u64 token, int *_fd);

#endif
