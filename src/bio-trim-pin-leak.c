// SPDX-License-Identifier: GPL-3.0+
/*
 * Copyright (C) 2026 Tal Zussman
 *
 * Check that a direct write trimmed to the logical block size unpins all the
 * pages it drops.
 *
 * Issue O_DIRECT pwritev() from a hugetlb mapping with a two-segment iovec
 * whose first segment ends half a block past a block boundary and whose
 * second segment is an unreadable PROT_NONE mapping. The direct path pins the
 * first segment, fails to pin the second and trims the bio down to a block
 * boundary. The trimmed tail spans several pages of one huge page, each with
 * its own pin. If the trim releases at most one of them, the huge page
 * never returns to the pool, which shows up as a drop in HugePages_Free.
 *
 * The tail is either its own bvec, when the first segment straddles two huge
 * pages, or the end of a larger one, when it sits inside a single huge page.
 * Each iteration issues one write of each kind. The direct I/O fallback
 * finishes the trimmed half block through the page cache, so each write
 * returns one and a half blocks.
 *
 * The tail only holds several pins when it spans several pages of a large
 * folio, so the device needs a logical block size of at least four pages and
 * the buffer comes from a hugetlb mapping.
 *
 * usage: bio-trim-pin-leak <blockdev> <iterations>
 *
 * exit:  0 = no huge pages leaked
 *        1 = setup error
 *        2 = huge pages leaked
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <unistd.h>

#include <linux/fs.h>

#define EXIT_LEAKED	2

static long meminfo(const char *key)
{
	char line[256];
	long val = -1;
	FILE *f;

	f = fopen("/proc/meminfo", "r");
	if (!f) {
		perror("fopen");
		return -1;
	}

	while (fgets(line, sizeof(line), f)) {
		if (!strncmp(line, key, strlen(key))) {
			val = strtol(line + strlen(key), NULL, 10);
			break;
		}
	}

	fclose(f);
	return val;
}

int main(int argc, char **argv)
{
	struct iovec iov[2];
	long pgsz, hpsz;
	long before, after;
	char *badseg;
	char *map;
	int lbs, iters;
	int status = EXIT_FAILURE;
	int fd, i;

	if (argc != 3) {
		fprintf(stderr, "usage: %s <blockdev> <iterations>\n", argv[0]);
		return EXIT_FAILURE;
	}

	iters = atoi(argv[2]);

	pgsz = sysconf(_SC_PAGESIZE);
	if (pgsz < 0) {
		perror("sysconf");
		return EXIT_FAILURE;
	}

	hpsz = meminfo("Hugepagesize:") * 1024;
	if (hpsz <= 0) {
		fprintf(stderr, "no hugetlb page size in /proc/meminfo\n");
		return EXIT_FAILURE;
	}

	fd = open(argv[1], O_RDWR | O_DIRECT);
	if (fd < 0) {
		perror("open");
		return EXIT_FAILURE;
	}

	if (ioctl(fd, BLKSSZGET, &lbs)) {
		perror("BLKSSZGET");
		goto out_close;
	}
	printf("logical block size: %d, page size: %ld, huge page size: %ld\n",
	       lbs, pgsz, hpsz);

	/*
	 * The trimmed tail is half a block, and it has to span at least two
	 * pages for a pin to leak.
	 */
	if (lbs < 4 * pgsz) {
		fprintf(stderr, "logical block size %d is below four pages\n",
			lbs);
		goto out_close;
	}
	if (hpsz < 2 * lbs) {
		fprintf(stderr, "huge page size %ld is below two blocks\n", hpsz);
		goto out_close;
	}

	badseg = mmap(NULL, lbs, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (badseg == MAP_FAILED) {
		perror("mmap");
		goto out_close;
	}

	before = meminfo("HugePages_Free:");
	if (before < 2 * iters + 2) {
		fprintf(stderr, "HugePages_Free is %ld, need at least %d\n",
			before, 2 * iters + 2);
		goto out_unmap;
	}

	for (i = 0; i < iters; i++) {
		map = mmap(NULL, 2 * hpsz, PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
		if (map == MAP_FAILED) {
			perror("mmap");
			goto out_unmap;
		}
		memset(map, 'A', 2 * hpsz);

		iov[0].iov_len = lbs + lbs / 2;
		iov[1].iov_base = badseg;
		iov[1].iov_len = lbs / 2;

		/*
		 * One block from the end of the first huge page and half a
		 * block from the start of the second, then an unreadable
		 * segment: the bio is trimmed by half a block, dropping the
		 * bvec pinned from the second huge page.
		 */
		iov[0].iov_base = map + hpsz - lbs;
		if (pwritev(fd, iov, 2, 0) != lbs + lbs / 2) {
			perror("pwritev");
			munmap(map, 2 * hpsz);
			goto out_unmap;
		}

		/*
		 * The same write from the start of the first huge page: the
		 * pinned segment is a single bvec, and the trim shrinks it
		 * by half a block instead of dropping one.
		 */
		iov[0].iov_base = map;
		if (pwritev(fd, iov, 2, 0) != lbs + lbs / 2) {
			perror("pwritev");
			munmap(map, 2 * hpsz);
			goto out_unmap;
		}

		if (munmap(map, 2 * hpsz)) {
			perror("munmap");
			goto out_unmap;
		}
	}

	after = meminfo("HugePages_Free:");
	printf("HugePages_Free: %ld -> %ld over %d iterations\n",
	       before, after, iters);

	if (after < before) {
		printf("%ld huge pages leaked\n", before - after);
		status = EXIT_LEAKED;
	} else {
		printf("no huge pages leaked\n");
		status = EXIT_SUCCESS;
	}

out_unmap:
	munmap(badseg, lbs);
out_close:
	close(fd);
	return status;
}
