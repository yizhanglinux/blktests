// SPDX-License-Identifier: GPL-3.0+
/* Copyright (C) 2026 0wnerD1ed */

#define _GNU_SOURCE

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

static int msb(unsigned int v)
{
	unsigned int b = 0;

	while (v >>= 1)
		b++;

	return b;
}

int main(int argc, char **argv)
{
	unsigned int block_size;
	unsigned char *p;
	long page_size;
	unsigned int dma_alignment;
	unsigned int dma_aligned_offset;
	ssize_t ret;
	int fd;

	if (argc != 3)
		return EXIT_FAILURE;

	page_size = sysconf(_SC_PAGESIZE);
	if (page_size <= 0)
		errx(EXIT_FAILURE, "invalid page size");

	dma_alignment = atoi(argv[2]);
	if (dma_alignment == 0)
		errx(EXIT_FAILURE, "unexpected dma_alignment");

	fd = open(argv[1], O_RDONLY | O_DIRECT);
	if (fd < 0)
		err(EXIT_FAILURE, "open %s", argv[1]);
	if (ioctl(fd, BLKSSZGET, &block_size))
		err(EXIT_FAILURE, "BLKSSZGET");

	dma_aligned_offset = 1 << (msb(dma_alignment) + 1);
	if (dma_aligned_offset >= block_size)
		errx(EXIT_FAILURE,
		     "unexpected dma_alignment %u for block size %u",
		     dma_alignment, block_size);

	p = mmap(NULL, 2 * page_size, PROT_READ | PROT_WRITE,
		 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p == MAP_FAILED)
		err(EXIT_FAILURE, "mmap");
	if (mprotect(p + page_size, page_size, PROT_NONE))
		err(EXIT_FAILURE, "mprotect");

	errno = 0;
	ret = pread(fd, p + page_size - dma_aligned_offset, block_size, 0);
	if (ret == -1 && errno == EFAULT)
		return EXIT_SUCCESS;
	errx(EXIT_FAILURE, "pread returned %zd (errno %d)", ret, errno);
}
