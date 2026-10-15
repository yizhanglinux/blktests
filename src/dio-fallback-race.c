// SPDX-License-Identifier: GPL-3.0+
/*
 * Copyright (C) 2026 Tal Zussman
 *
 * Race partial O_DIRECT writes to a block device against BLKBSZSET.
 *
 * Writer threads issue O_DIRECT pwritev() with a two-segment iovec whose
 * second segment is an unreadable PROT_NONE mapping. The direct path writes
 * the first segment, fails to pin the second and returns short, so the write
 * finishes as a buffered write through the direct I/O fallback. A second
 * thread toggles the second segment's protection so that some fallbacks get
 * past fault_in_iov_iter_readable() and reach the page cache, a third
 * populates the page cache with folios of the current block size, and a
 * fourth toggles the block size between 512 bytes and 64K with BLKBSZSET.
 *
 * The fallback has to run under i_rwsem like the plain buffered write path.
 * If it does not, it races set_blocksize() raising the mapping's minimum
 * folio order and adds a folio that is too small for the mapping, which a
 * CONFIG_DEBUG_VM kernel reports as a BUG. The caller checks dmesg.
 *
 * usage: dio-fallback-race <blockdev> <seconds>
 *
 * exit:  0 = ran for <seconds>
 *        1 = setup error
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <unistd.h>

#include <linux/fs.h>

#define GOOD		(8 * 1024)		/* written by the direct path */
#define BAD		(64 * 1024)		/* unreadable, forces a short write */
#define RANGE		(2 * 1024 * 1024)	/* keep the race on a few folios */
#define NR_WRITERS	2

#define SMALL_BS	512
#define LARGE_BS	(64 * 1024)

static const char *dev;
static long pgsz;
static char *badseg;
static int bszfd;
static volatile int stop;
static int failed;

/* partial direct write, finished as a buffered write by the fallback */
static void *writer(void *arg)
{
	struct iovec iov[2];
	off_t off = 0;
	char *good;
	int fd;

	fd = open(dev, O_RDWR | O_DIRECT);
	if (fd < 0) {
		perror("open");
		failed = 1;
		return NULL;
	}

	if (posix_memalign((void **)&good, pgsz, GOOD)) {
		perror("posix_memalign");
		failed = 1;
		goto out_close;
	}
	memset(good, 'A', GOOD);

	iov[0].iov_base = good;
	iov[0].iov_len = GOOD;
	iov[1].iov_base = badseg;
	iov[1].iov_len = BAD;

	while (!stop) {
		ssize_t n = pwritev(fd, iov, 2, off);

		if (n < 0) {
			perror("pwritev");
			failed = 1;
			break;
		}
		/* The direct part always lands; the fallback may add to it. */
		if (n < GOOD) {
			fprintf(stderr, "pwritev returned %zd, below %d\n", n,
				GOOD);
			failed = 1;
			break;
		}
		off = (off + GOOD) % RANGE;
	}

	free(good);
out_close:
	close(fd);
	return NULL;
}

/* let some fallbacks get past the fault-in and into the page cache */
static void *flipper(void *arg)
{
	while (!stop) {
		if (mprotect(badseg, BAD, PROT_READ | PROT_WRITE) ||
		    mprotect(badseg, BAD, PROT_NONE)) {
			perror("mprotect");
			failed = 1;
			break;
		}
	}

	return NULL;
}

/* populate the page cache with folios sized for the current block size */
static void *reader(void *arg)
{
	off_t off = 0;
	char *buf;
	int fd;

	fd = open(dev, O_RDONLY);
	if (fd < 0) {
		perror("open");
		failed = 1;
		return NULL;
	}

	buf = malloc(GOOD);
	if (!buf) {
		perror("malloc");
		failed = 1;
		goto out_close;
	}

	while (!stop) {
		if (pread(fd, buf, GOOD, off) < 0) {
			perror("pread");
			failed = 1;
			break;
		}
		readahead(fd, off, RANGE / 4);
		off = (off + GOOD) % RANGE;
	}

	free(buf);
out_close:
	close(fd);
	return NULL;
}

/* change i_blkbits and the mapping's minimum folio order underneath them */
static void *resizer(void *arg)
{
	int bs = SMALL_BS;

	while (!stop) {
		if (ioctl(bszfd, BLKBSZSET, &bs)) {
			perror("BLKBSZSET");
			failed = 1;
			break;
		}
		bs = bs == SMALL_BS ? LARGE_BS : SMALL_BS;
	}

	return NULL;
}

static int spawn(pthread_t *t, void *(*fn)(void *))
{
	int err = pthread_create(t, NULL, fn, NULL);

	if (err)
		fprintf(stderr, "pthread_create: %s\n", strerror(err));

	return err;
}

int main(int argc, char **argv)
{
	pthread_t writers[NR_WRITERS];
	pthread_t flipper_t, reader_t, resizer_t;
	int status = EXIT_FAILURE;
	int bs = LARGE_BS;
	int i;

	if (argc != 3) {
		fprintf(stderr, "usage: %s <blockdev> <seconds>\n", argv[0]);
		return EXIT_FAILURE;
	}

	dev = argv[1];

	pgsz = sysconf(_SC_PAGESIZE);
	if (pgsz < 0) {
		perror("sysconf");
		return EXIT_FAILURE;
	}

	bszfd = open(dev, O_RDONLY);
	if (bszfd < 0) {
		perror("open");
		return EXIT_FAILURE;
	}

	/*
	 * The minimum folio order only moves with block sizes above the page
	 * size, which needs BLK_MAX_BLOCK_SIZE above PAGE_SIZE, i.e.
	 * CONFIG_TRANSPARENT_HUGEPAGE.
	 */
	if (ioctl(bszfd, BLKBSZSET, &bs)) {
		perror("BLKBSZSET");
		goto out_close;
	}

	badseg = mmap(NULL, BAD, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (badseg == MAP_FAILED) {
		perror("mmap");
		goto out_close;
	}

	for (i = 0; i < NR_WRITERS; i++) {
		if (spawn(&writers[i], writer))
			return EXIT_FAILURE;
	}
	if (spawn(&flipper_t, flipper) || spawn(&reader_t, reader) ||
	    spawn(&resizer_t, resizer))
		return EXIT_FAILURE;

	sleep(atoi(argv[2]));
	stop = 1;

	for (i = 0; i < NR_WRITERS; i++)
		pthread_join(writers[i], NULL);
	pthread_join(flipper_t, NULL);
	pthread_join(reader_t, NULL);
	pthread_join(resizer_t, NULL);

	if (!failed)
		status = EXIT_SUCCESS;

	munmap(badseg, BAD);
out_close:
	close(bszfd);
	return status;
}
