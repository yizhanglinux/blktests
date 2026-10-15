// SPDX-License-Identifier: GPL-3.0+
/*
 * Copyright (C) 2026 Tal Zussman
 *
 * Race splice() from a block device against BLKBSZSET.
 *
 * Splicer threads splice from the device into a pipe while another thread
 * toggles the block size between 512 bytes and 64K with BLKBSZSET.
 *
 * The splice read path has to run under i_rwsem like the plain read path.
 * If it does not, it races set_blocksize() raising the mapping's minimum
 * folio order and adds a folio that is too small for the mapping, which a
 * CONFIG_DEBUG_VM kernel reports as a BUG. The caller checks dmesg.
 *
 * usage: splice-race <blockdev> <seconds>
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
#include <unistd.h>

#include <linux/fs.h>

#define CHUNK		(64 * 1024)
#define RANGE		(2 * 1024 * 1024)	/* keep the race on a few folios */
#define NR_SPLICERS	4

#define SMALL_BS	512
#define LARGE_BS	(64 * 1024)

static const char *dev;
static int bszfd;
static volatile int stop;
static int failed;

/* filemap_splice_read() from the device */
static void *splicer(void *arg)
{
	int pipefd[2];
	loff_t off = 0;
	char *sink;
	int fd;

	fd = open(dev, O_RDONLY);
	if (fd < 0) {
		perror("open");
		failed = 1;
		return NULL;
	}

	if (pipe(pipefd)) {
		perror("pipe");
		failed = 1;
		return NULL;
	}

	sink = malloc(CHUNK);
	if (!sink) {
		perror("malloc");
		failed = 1;
		return NULL;
	}

	while (!stop) {
		ssize_t n = splice(fd, &off, pipefd[1], NULL, CHUNK, 0);

		if (n < 0) {
			perror("splice");
			failed = 1;
			break;
		}

		/* drain the pipe so the next splice does not block on it */
		while (n > 0) {
			ssize_t d = read(pipefd[0], sink, n);

			if (d <= 0) {
				perror("read");
				failed = 1;
				return NULL;
			}
			n -= d;
		}

		if (off >= RANGE)
			off = 0;
	}

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
	pthread_t splicers[NR_SPLICERS];
	pthread_t resizer_t;
	int bs = LARGE_BS;
	int i;

	if (argc != 3) {
		fprintf(stderr, "usage: %s <blockdev> <seconds>\n", argv[0]);
		return EXIT_FAILURE;
	}

	dev = argv[1];

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
		return EXIT_FAILURE;
	}

	for (i = 0; i < NR_SPLICERS; i++) {
		if (spawn(&splicers[i], splicer))
			return EXIT_FAILURE;
	}
	if (spawn(&resizer_t, resizer))
		return EXIT_FAILURE;

	sleep(atoi(argv[2]));
	stop = 1;

	for (i = 0; i < NR_SPLICERS; i++)
		pthread_join(splicers[i], NULL);
	pthread_join(resizer_t, NULL);

	return failed ? EXIT_FAILURE : EXIT_SUCCESS;
}
