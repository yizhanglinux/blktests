// SPDX-License-Identifier: GPL-3.0+
// Copyright (C) 2026 Andrea Parri

/*
 * Issue an NVMe admin read command into a buffer filled with a sentinel and
 * print the NVMe status and the number of bytes the command overwrote.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/nvme_ioctl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define SENTINEL	0xa5

static int parse_u32(const char *s, uint32_t *val)
{
	unsigned long v;
	char *end;

	errno = 0;
	v = strtoul(s, &end, 0);
	if (errno || end == s || *end || v > UINT32_MAX)
		return -1;
	*val = v;
	return 0;
}

int main(int argc, char **argv)
{
	struct nvme_passthru_cmd cmd = { };
	uint32_t opcode, cdw10, len, i, changed = 0;
	unsigned char *buf;
	void *p;
	int fd, ret;

	if (argc != 5 || parse_u32(argv[2], &opcode) || opcode > 0xff ||
	    parse_u32(argv[3], &cdw10) || parse_u32(argv[4], &len) || !len) {
		fprintf(stderr, "usage: %s /dev/nvmeX opcode cdw10 data-len\n",
			argv[0]);
		return 2;
	}

	/*
	 * Page-align the buffer so that the kernel maps it for the transfer
	 * instead of bouncing it: a bounce buffer is zero-filled and copied
	 * back even when the command fails, which would hide the sentinel.
	 */
	ret = posix_memalign(&p, 4096, len);
	if (ret) {
		fprintf(stderr, "posix_memalign: %s\n", strerror(ret));
		return 2;
	}
	buf = p;
	memset(buf, SENTINEL, len);

	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		perror(argv[1]);
		free(buf);
		return 2;
	}

	cmd.opcode = opcode;
	cmd.addr = (uintptr_t)buf;
	cmd.data_len = len;
	cmd.cdw10 = cdw10;

	ret = ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd);
	close(fd);
	if (ret < 0) {
		perror("NVME_IOCTL_ADMIN_CMD");
		free(buf);
		return 2;
	}

	for (i = 0; i < len; i++)
		if (buf[i] != SENTINEL)
			changed++;

	printf("%#x %u\n", ret, changed);
	free(buf);
	return 0;
}
