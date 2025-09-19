// SPDX-License-Identifier: GPL-3.0+
// Copyright (C) 2025 Anuj Gupta

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <errno.h>

#ifndef FS_IOC_GETLBMD_CAP
#define FS_IOC_GETLBMD_CAP		_IOWR(0x15, 2, struct logical_block_metadata_cap)

#define	LBMD_PI_CAP_INTEGRITY		(1 << 0)

struct logical_block_metadata_cap {
	__u32	lbmd_flags;
	__u16	lbmd_interval;
	__u8	lbmd_size;
	__u8	lbmd_opaque_size;
	__u8	lbmd_opaque_offset;
	__u8	lbmd_pi_size;
	__u8	lbmd_pi_offset;
	__u8	lbmd_guard_tag_type;
	__u8	lbmd_app_tag_size;
	__u8	lbmd_ref_tag_size;
	__u8	lbmd_storage_tag_size;
	__u8	pad;
};
#endif

int main(int argc, char *argv[])
{
	if (argc != 2) {
		fprintf(stderr, "Usage: %s <block-device>\n", argv[0]);
		return 1;
	}

	const char *dev = argv[1];
	int fd = open(dev, O_RDONLY);

	if (fd < 0) {
		perror("open");
		return 1;
	}

	struct logical_block_metadata_cap cap = {};

	if (ioctl(fd, FS_IOC_GETLBMD_CAP, &cap) < 0) {
		perror("FS_IOC_GETLBMD_CAP");
		close(fd);
		return 1;
	}
	close(fd);

	if (!(cap.lbmd_flags & LBMD_PI_CAP_INTEGRITY)) {
		printf("unsupported\n");
		return 0;
	}

	printf("lbmd_flags=%u lbmd_interval=%u lbmd_size=%u\n",
	       cap.lbmd_flags, cap.lbmd_interval, cap.lbmd_size);
	return 0;
}
