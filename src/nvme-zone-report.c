// SPDX-License-Identifier: GPL-3.0+
// Copyright (C) 2026 Andrea Parri

/* Check that unused bytes in an NVMe zone report are zeroed. */
#define _GNU_SOURCE
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/nvme_ioctl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define REPORT_LEN		4096
/*
 * Larger than the default RDMA in-capsule data size on 4 KiB page kernels.
 * nvme/073 skips RDMA on other page sizes, where this write could stay
 * inline rather than use buffers allocated and freed per command.
 */
#define POISON_LEN		8192
#define WRITE_OPCODE		0x01
#define ZONE_REPORT_OPCODE	0x7a
#define PARTIAL_REPORT		(1U << 16)
#define ZONE_REPORT_HEADER	64
#define ZONE_DESC_LEN		64
#define ZONE_START_OFFSET	16
#define NR_ATTEMPTS		64

static int poison_target(int fd, unsigned int iteration)
{
	unsigned char data[POISON_LEN];
	struct nvme_passthru_cmd cmd = {
		.opcode = WRITE_OPCODE,
		.nsid = 1,
		.addr = (uintptr_t)data,
		.data_len = sizeof(data),
		.cdw10 = iteration * (POISON_LEN / 512),
		.cdw12 = POISON_LEN / 512 - 1,
	};

	memset(data, 0x5a, sizeof(data));
	return ioctl(fd, NVME_IOCTL_IO_CMD, &cmd);
}

static uint64_t read_le64(const unsigned char *p)
{
	uint64_t value;

	memcpy(&value, p, sizeof(value));
	return le64toh(value);
}

int main(int argc, char **argv)
{
	unsigned char *report;
	unsigned long long slba;
	char *end;
	void *p;
	int fd, i, j, ret, rc = 0;

	if (argc != 3) {
		fprintf(stderr, "usage: %s /dev/nvmeXnY last-zone-slba\n",
			argv[0]);
		return 2;
	}

	errno = 0;
	slba = strtoull(argv[2], &end, 0);
	if (errno || *end) {
		fprintf(stderr, "invalid SLBA: %s\n", argv[2]);
		return 2;
	}

	/*
	 * Page-align the report so that the kernel maps it for the transfer
	 * instead of bouncing it: a bounce buffer is zero-filled, which would
	 * hide the sentinel and any bytes the target left unwritten.
	 */
	ret = posix_memalign(&p, 4096, REPORT_LEN);
	if (ret) {
		fprintf(stderr, "posix_memalign: %s\n", strerror(ret));
		return 2;
	}
	report = p;

	fd = open(argv[1], O_RDWR);
	if (fd < 0) {
		perror(argv[1]);
		free(report);
		return 2;
	}

	for (i = 0; i < NR_ATTEMPTS; i++) {
		struct nvme_passthru_cmd cmd = {
			.opcode = ZONE_REPORT_OPCODE,
			.nsid = 1,
			.addr = (uintptr_t)report,
			.data_len = REPORT_LEN,
			.cdw10 = (uint32_t)slba,
			.cdw11 = (uint32_t)(slba >> 32),
			.cdw12 = REPORT_LEN / 4 - 1,
			.cdw13 = PARTIAL_REPORT,
		};
		unsigned int nonzero = 0, stale = 0, poisoned = 0;
		unsigned char sentinel = i & 1 ? 0xa5 : 0x3c;

		ret = poison_target(fd, i);
		if (ret) {
			if (ret < 0)
				perror("poison_target");
			else
				fprintf(stderr, "poison write status: %#x\n", ret);
			rc = 2;
			goto out;
		}

		memset(report, sentinel, REPORT_LEN);
		ret = ioctl(fd, NVME_IOCTL_IO_CMD, &cmd);
		if (ret) {
			if (ret < 0)
				perror("NVME_IOCTL_IO_CMD");
			else
				fprintf(stderr, "NVMe status: %#x\n", ret);
			rc = 2;
			goto out;
		}

		if (read_le64(report) != 1 ||
		    read_le64(report + ZONE_REPORT_HEADER +
			      ZONE_START_OFFSET) != slba) {
			fprintf(stderr, "unexpected zone report header or SLBA\n");
			rc = 1;
			goto out;
		}

		for (j = 8; j < REPORT_LEN; j++) {
			if (j >= ZONE_REPORT_HEADER &&
			    j < ZONE_REPORT_HEADER + ZONE_DESC_LEN)
				continue;
			if (!report[j])
				continue;
			nonzero++;
			if (report[j] == sentinel)
				stale++;
			if (report[j] == 0x5a)
				poisoned++;
		}

		fprintf(stderr, "attempt %d: %u nonzero bytes "
			"(%u poison, %u sentinel)\n", i + 1, nonzero,
			poisoned, stale);
		if (nonzero) {
			rc = 1;
			goto out;
		}
	}

out:
	close(fd);
	free(report);
	return rc;
}
