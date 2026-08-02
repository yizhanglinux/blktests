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

int main(int argc, char **argv)
{
	unsigned int block_size;
	unsigned char *p;
	long page_size;
	ssize_t ret;
	int fd;

	if (argc != 2)
		return EXIT_FAILURE;
	page_size = sysconf(_SC_PAGESIZE);
	if (page_size <= 0)
		errx(EXIT_FAILURE, "invalid page size");

	fd = open(argv[1], O_RDONLY | O_DIRECT);
	if (fd < 0)
		err(EXIT_FAILURE, "open %s", argv[1]);
	if (ioctl(fd, BLKSSZGET, &block_size))
		err(EXIT_FAILURE, "BLKSSZGET");

	p = mmap(NULL, 2 * page_size, PROT_READ | PROT_WRITE,
		 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p == MAP_FAILED)
		err(EXIT_FAILURE, "mmap");
	if (mprotect(p + page_size, page_size, PROT_NONE))
		err(EXIT_FAILURE, "mprotect");

	errno = 0;
	ret = pread(fd, p + page_size - 1, block_size, 0);
	if (ret == -1 && errno == EFAULT)
		return EXIT_SUCCESS;
	errx(EXIT_FAILURE, "pread returned %zd (errno %d)", ret, errno);
}
