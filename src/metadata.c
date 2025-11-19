// SPDX-License-Identifier: GPL-3.0+
/*
 * Copyright (c) 2025 Meta Platforms, Inc.  All Rights Reserved.
 *
 * Description: test userspace metadata
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <liburing.h>

#ifndef IORING_RW_ATTR_FLAG_PI
#define PI_URING_COMPAT
#define IORING_RW_ATTR_FLAG_PI  (1U << 0)
/* PI attribute information */
struct io_uring_attr_pi {
	__u16   flags;
	__u16   app_tag;
	__u32   len;
	__u64   addr;
	__u64   seed;
	__u64   rsvd;
};
#endif

#ifndef FS_IOC_GETLBMD_CAP
/* Protection info capability flags */
#define LBMD_PI_CAP_INTEGRITY           (1 << 0)
#define LBMD_PI_CAP_REFTAG              (1 << 1)

/* Checksum types for Protection Information */
#define LBMD_PI_CSUM_NONE               0
#define LBMD_PI_CSUM_IP                 1
#define LBMD_PI_CSUM_CRC16_T10DIF       2
#define LBMD_PI_CSUM_CRC64_NVME         4

/*
 * Logical block metadata capability descriptor
 * If the device does not support metadata, all the fields will be zero.
 * Applications must check lbmd_flags to determine whether metadata is
 * supported or not.
 */
struct logical_block_metadata_cap {
	/* Bitmask of logical block metadata capability flags */
	__u32	lbmd_flags;
	/*
	 * The amount of data described by each unit of logical block
	 * metadata
	 */
	__u16	lbmd_interval;
	/*
	 * Size in bytes of the logical block metadata associated with each
	 * interval
	 */
	__u8	lbmd_size;
	/*
	 * Size in bytes of the opaque block tag associated with each
	 * interval
	 */
	__u8	lbmd_opaque_size;
	/*
	 * Offset in bytes of the opaque block tag within the logical block
	 * metadata
	 */
	__u8	lbmd_opaque_offset;
	/* Size in bytes of the T10 PI tuple associated with each interval */
	__u8	lbmd_pi_size;
	/* Offset in bytes of T10 PI tuple within the logical block metadata */
	__u8	lbmd_pi_offset;
	/* T10 PI guard tag type */
	__u8	lbmd_guard_tag_type;
	/* Size in bytes of the T10 PI application tag */
	__u8	lbmd_app_tag_size;
	/* Size in bytes of the T10 PI reference tag */
	__u8	lbmd_ref_tag_size;
	/* Size in bytes of the T10 PI storage tag */
	__u8	lbmd_storage_tag_size;
	__u8	pad;
};

#define FS_IOC_GETLBMD_CAP                      _IOWR(0x15, 2, struct logical_block_metadata_cap)
#endif /* FS_IOC_GETLBMD_CAP */

#ifndef IO_INTEGRITY_CHK_GUARD
/* flags for integrity meta */
#define IO_INTEGRITY_CHK_GUARD          (1U << 0) /* enforce guard check */
#define IO_INTEGRITY_CHK_REFTAG         (1U << 1) /* enforce ref check */
#define IO_INTEGRITY_CHK_APPTAG         (1U << 2) /* enforce app check */
#endif /* IO_INTEGRITY_CHK_GUARD */

/* This size should guarantee at least one split */
#define DATA_SIZE (8 * 1024 * 1024)

static unsigned short lba_size;
static unsigned char metadata_size;
static unsigned char pi_size;
static unsigned char pi_offset;
static bool reftag_enabled;

static long pagesize;

struct t10_pi_tuple {
        __be16 guard_tag;       /* Checksum */
        __be16 app_tag;         /* Opaque storage */
        __be32 ref_tag;         /* Target LBA or indirect LBA */
};

struct crc64_pi_tuple {
        __be64 guard_tag;
        __be16 app_tag;
        __u8   ref_tag[6];
};

static int init_capabilities(int fd)
{
	struct logical_block_metadata_cap md_cap;
	int ret;

	ret = ioctl(fd, FS_IOC_GETLBMD_CAP, &md_cap);
	if (ret < 0) {
		perror("FS_IOC_GETLBMD_CAP");
		return ret;
	}

	lba_size = md_cap.lbmd_interval;
	metadata_size = md_cap.lbmd_size;
	pi_size = md_cap.lbmd_pi_size;
	pi_offset = md_cap.lbmd_pi_offset;
	reftag_enabled = md_cap.lbmd_flags & LBMD_PI_CAP_REFTAG;

	pagesize = sysconf(_SC_PAGE_SIZE);
	return 0;
}

static unsigned int swap(unsigned int value)
{
	return ((value >> 24) & 0x000000ff) |
		((value >> 8)  & 0x0000ff00) |
		((value << 8)  & 0x00ff0000) |
		((value << 24) & 0xff000000);
}

static inline void __put_unaligned_be48(const __u64 val, __u8 *p)
{
	*p++ = (val >> 40) & 0xff;
	*p++ = (val >> 32) & 0xff;
	*p++ = (val >> 24) & 0xff;
	*p++ = (val >> 16) & 0xff;
	*p++ = (val >> 8) & 0xff;
	*p++ = val & 0xff;
}

static inline void put_unaligned_be48(const __u64 val, void *p)
{
	__put_unaligned_be48(val, p);
}

static inline __u64 __get_unaligned_be48(const __u8 *p)
{
	return (__u64)p[0] << 40 | (__u64)p[1] << 32 | (__u64)p[2] << 24 |
		p[3] << 16 | p[4] << 8 | p[5];
}

static inline __u64 get_unaligned_be48(const void *p)
{
	return __get_unaligned_be48(p);
}

static void init_metadata(void *p, int intervals, int ref)
{
	int i, j;

	for (i = 0; i < intervals; i++, ref++) {
		int remaining = metadata_size - pi_offset;
		unsigned char *m = p;

		for (j = 0; j < pi_offset; j++)
			m[j] = (unsigned char)(ref + j + i);

		p += pi_offset;
		if (reftag_enabled) {
			if (pi_size == 8) {
				struct t10_pi_tuple *tuple = p;

				tuple->ref_tag = swap(ref);
				remaining -= sizeof(*tuple);
				p += sizeof(*tuple);
			} else if (pi_size == 16) {
				struct crc64_pi_tuple *tuple = p;

				__put_unaligned_be48(ref, tuple->ref_tag);
				remaining -= sizeof(*tuple);
				p += sizeof(*tuple);
			}
		}

		m = p;
		for (j = 0; j < remaining; j++)
			m[j] = (unsigned char)~(ref + j + i);

		p += remaining;
	}
}

static int check_metadata(void *p, int intervals, int ref)
{
	int i, j;

	for (i = 0; i < intervals; i++, ref++) {
		int remaining = metadata_size - pi_offset;
		unsigned char *m = p;

		for (j = 0; j < pi_offset; j++) {
			if (m[j] != (unsigned char)(ref + j + i)) {
				fprintf(stderr, "(pre)interval:%d byte:%d expected:%x got:%x\n",
					i, j, (unsigned char)(ref + j + i), m[j]);
				return -1;
			}
		}

		p += pi_offset;
		if (reftag_enabled) {
			if (pi_size == 8) {
				struct t10_pi_tuple *tuple = p;

				if (swap(tuple->ref_tag) != ref) {
					fprintf(stderr, "reftag interval:%d expected:%x got:%x\n",
						i, ref, swap(tuple->ref_tag));
					return -1;
				}

				remaining -= sizeof(*tuple);
				p += sizeof(*tuple);
			} else if (pi_size == 16) {
				struct crc64_pi_tuple *tuple = p;
				__u64 v = get_unaligned_be48(tuple->ref_tag);

				if (v != ref) {
					fprintf(stderr, "reftag interval:%d expected:%x got:%llx\n",
						i, ref, v);
					return -1;
				}
				remaining -= sizeof(*tuple);
				p += sizeof(*tuple);
			}
		}

		m = p;
		for (j = 0; j < remaining; j++) {
			if (m[j] != (unsigned char)~(ref + j + i)) {
				fprintf(stderr, "(post)interval:%d byte:%d expected:%x got:%x\n",
					i, j, (unsigned char)~(ref + j + i), m[j]);
				return -1;
			}
		}

		p += remaining;
	}

	return 0;
}

static void init_data(void *data, int offset)
{
	unsigned char *d = data;
	int i;

	for (i = 0; i < DATA_SIZE; i++)
		d[i] = (unsigned char)(0xaa + offset + i);
}

static int check_data(void *data, int offset)
{
	unsigned char *d = data;
	int i;

	for (i = 0; i < DATA_SIZE; i++)
		if (d[i] != (unsigned char)(0xaa + offset + i))
			return -1;

	return 0;
}

int main(int argc, char *argv[])
{
	int fd, ret, i, offset, intervals, metabuffer_size, metabuffer_tx_size;
	void *orig_data_buf, *orig_pi_buf, *data_buf;
	struct io_uring_cqe *cqes[2];
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	struct io_uring ring;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s <dev>\n", argv[0]);
		return 1;
	}

	fd = open(argv[1], O_RDWR | O_DIRECT);
	if (fd < 0) {
		perror("Failed to open device with O_DIRECT");
		return 1;
	}

	ret = init_capabilities(fd);
	if (ret < 0)
		return 1;
	if (lba_size == 0 || metadata_size == 0)
		return 1;

	intervals = DATA_SIZE / lba_size;
	metabuffer_tx_size = intervals * metadata_size;
	metabuffer_size = metabuffer_tx_size * 2;

	if (posix_memalign(&orig_data_buf, pagesize, DATA_SIZE)) {
		perror("posix_memalign failed for data buffer");
		ret = 1;
		goto close;
	}

	if (posix_memalign(&orig_pi_buf, pagesize, metabuffer_size)) {
		perror("posix_memalign failed for metadata buffer");
		ret = 1;
		goto free;
	}

	ret = io_uring_queue_init(8, &ring, 0);
	if (ret < 0) {
		perror("io_uring_queue_init failed");
		goto cleanup;
	}

	data_buf = orig_data_buf;
	for (offset = 0; offset < 512; offset++) {
		void *pi_buf = (char *)orig_pi_buf + offset * 4;
		struct io_uring_attr_pi pi_attr = {
			.addr = (__u64)pi_buf,
			.seed = offset,
			.len = metabuffer_tx_size,
		};

		if (reftag_enabled)
			pi_attr.flags = IO_INTEGRITY_CHK_REFTAG;

		init_data(data_buf, offset);
		init_metadata(pi_buf, intervals, offset);

		sqe = io_uring_get_sqe(&ring);
		if (!sqe) {
			fprintf(stderr, "Failed to get SQE\n");
			ret = 1;
			goto ring_exit;
		}

		io_uring_prep_write(sqe, fd, data_buf, DATA_SIZE, offset * lba_size * 8);
		io_uring_sqe_set_data(sqe, (void *)1L);

#ifdef PI_URING_COMPAT
		/* old liburing, use fields that overlap in the union */
		sqe->__pad2[0] = IORING_RW_ATTR_FLAG_PI;
		sqe->addr3 = (__u64)&pi_attr;
#else
		sqe->attr_type_mask = IORING_RW_ATTR_FLAG_PI;
		sqe->attr_ptr = (__u64)&pi_attr;
#endif
		ret = io_uring_submit(&ring);
		if (ret < 1) {
			perror("io_uring_submit failed (WRITE)");
			ret = 1;
			goto ring_exit;
		}

		ret = io_uring_wait_cqe(&ring, &cqe);
		if (ret < 0) {
			perror("io_uring_wait_cqe failed (WRITE)");
			ret = 1;
			goto ring_exit;
		}

		if (cqe->res < 0) {
			fprintf(stderr, "write failed at offset %d: %s\n",
				offset, strerror(-cqe->res));
			ret = 1;
			goto ring_exit;
		}

		io_uring_cqe_seen(&ring, cqe);

		memset(data_buf, 0, DATA_SIZE);
		memset(pi_buf, 0, metabuffer_tx_size);

		sqe = io_uring_get_sqe(&ring);
		if (!sqe) {
			fprintf(stderr, "failed to get SQE\n");
			ret = 1;
			goto ring_exit;
		}

		io_uring_prep_read(sqe, fd, data_buf, DATA_SIZE, offset * lba_size * 8);
		io_uring_sqe_set_data(sqe, (void *)2L);

#ifdef PI_URING_COMPAT
		sqe->__pad2[0] = IORING_RW_ATTR_FLAG_PI;
		sqe->addr3 = (__u64)&pi_attr;
#else
		sqe->attr_type_mask = IORING_RW_ATTR_FLAG_PI;
		sqe->attr_ptr = (__u64)&pi_attr;
#endif

		ret = io_uring_submit(&ring);
		if (ret < 1) {
			perror("io_uring_submit failed (read)");
			ret = 1;
			goto ring_exit;
		}

		ret = io_uring_wait_cqe(&ring, &cqe);
		if (ret < 0) {
			fprintf(stderr, "io_uring_wait_cqe failed (read): %s\n", strerror(-ret));
			ret = 1;
			goto ring_exit;
		}

		if (cqe->res < 0) {
			fprintf(stderr, "read failed at offset %d: %s\n",
				offset, strerror(-cqe->res));
			ret = 1;
			goto ring_exit;
		}

		ret = check_data(data_buf, offset);
		if (ret) {
			fprintf(stderr, "data corruption at offset %d\n",
				offset);
			ret = 1;
			goto ring_exit;
		}

		ret = check_metadata(pi_buf, intervals, offset);
		if (ret) {
			fprintf(stderr, "metadata corruption at offset %d\n",
				offset);
			ret = 1;
			goto ring_exit;
		}

		io_uring_cqe_seen(&ring, cqe);
	}

	memset(data_buf, 0, DATA_SIZE);
	for (i = 0; i < 2; i++) {
		sqe = io_uring_get_sqe(&ring);
		if (!sqe) {
			fprintf(stderr, "failed get sqe\n");
			ret = 1;
			goto ring_exit;
		}

		io_uring_prep_write(sqe, fd, data_buf, DATA_SIZE, DATA_SIZE * i);
		io_uring_sqe_set_data(sqe, (void *)(uintptr_t)i + 1);
	}

	ret = io_uring_submit(&ring);
	if (ret < 1) {
		fprintf(stderr, "failed to submit sqes\n");
		goto ring_exit;
	}
	ret = io_uring_wait_cqe_nr(&ring, cqes, 2);
	if (ret)
		fprintf(stderr, "failed to reap cqes\n");
ring_exit:
    io_uring_queue_exit(&ring);
cleanup:
    free(orig_pi_buf);
free:
    free(orig_data_buf);
close:
    close(fd);
    return ret;
}
