// SPDX-License-Identifier: GPL-3.0+
// Copyright (C) 2026 Yang Xiuwei <yangxiuwei@kylinos.cn>
/*
 * IOPOLL direct read with a PI attribute. The fixed kernel completes it
 * with -EOPNOTSUPP.
 */
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <liburing.h>

#ifndef IORING_RW_ATTR_FLAG_PI
#define PI_URING_COMPAT
#define IORING_RW_ATTR_FLAG_PI (1U << 0)
struct io_uring_attr_pi {
	__u16 flags;
	__u16 app_tag;
	__u32 len;
	__u64 addr;
	__u64 seed;
	__u64 rsvd;
};
#endif

#ifndef IO_INTEGRITY_CHK_GUARD
#define IO_INTEGRITY_CHK_GUARD  (1U << 0)
#define IO_INTEGRITY_CHK_REFTAG (1U << 1)
#endif

#ifndef IORING_FEAT_RW_ATTR
#define IORING_FEAT_RW_ATTR	(1U << 16)
#endif

#define DATA_LEN 4096
#define META_LEN 64

static void on_alarm(int sig)
{
	(void)sig;
	dprintf(STDERR_FILENO, "timed out\n");
	_exit(1);
}

int main(int argc, char **argv)
{
	struct io_uring ring;
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	struct io_uring_attr_pi pi = {
		.flags = IO_INTEGRITY_CHK_GUARD | IO_INTEGRITY_CHK_REFTAG,
		.len = META_LEN,
		.seed = 1,
	};
	void *data, *meta;
	int fd, ret;

	if (argc != 2)
		return 1;

	signal(SIGALRM, on_alarm);
	alarm(10);

	fd = open(argv[1], O_RDONLY | O_DIRECT);
	if (fd < 0) {
		perror("open");
		return 1;
	}
	if (posix_memalign(&data, 4096, DATA_LEN) ||
	    posix_memalign(&meta, 4096, META_LEN)) {
		perror("posix_memalign");
		return 1;
	}
	pi.addr = (__u64)(uintptr_t)meta;

	ret = io_uring_queue_init(8, &ring, IORING_SETUP_IOPOLL);
	if (ret < 0) {
		fprintf(stderr, "queue_init: %s\n", strerror(-ret));
		return 1;
	}
	if (!(ring.features & IORING_FEAT_RW_ATTR))
		return 2;
	sqe = io_uring_get_sqe(&ring);
	if (!sqe)
		return 1;
	io_uring_prep_read(sqe, fd, data, DATA_LEN, 0);
#ifdef PI_URING_COMPAT
	sqe->__pad2[0] = IORING_RW_ATTR_FLAG_PI;
	sqe->addr3 = (__u64)&pi;
#else
	sqe->attr_type_mask = IORING_RW_ATTR_FLAG_PI;
	sqe->attr_ptr = (__u64)&pi;
#endif
	ret = io_uring_submit(&ring);
	if (ret < 1) {
		fprintf(stderr, "submit: %d\n", ret);
		return 1;
	}
	ret = io_uring_wait_cqe(&ring, &cqe);
	if (ret < 0) {
		fprintf(stderr, "wait: %s\n", strerror(-ret));
		return 1;
	}
	if (cqe->res != -EOPNOTSUPP) {
		fprintf(stderr, "cqe %d\n", cqe->res);
		return 1;
	}
	return 0;
}
