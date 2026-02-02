// SPDX-License-Identifier: GPL-3.0+
// Copyright (C) 2026 Swarna Prabhu, Samsung Electronics
/*
 * Simple test exercising the admin queue accesses via io_uring passthrough
 * commands.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <liburing.h>
#include <linux/nvme_ioctl.h>

#define NVME_IDENTIFY_ADMIN_CMD 0x06     /* Identify command using admin queue */
#define NVME_IDENTIFY_CNS_CTRL 0x01    /* Identify controller command to a NVME device */
struct nvme_id_ctrl {
	__le16 vid;
	__le16 ssvid;
	char sn[20];
	char mn[40];
	char fr[8];
	__u8 rab;
	__u8 ieee[3];
	char pad[4020];
};


int main(int argc, char **argv)
{
	int fd, ret;
	struct nvme_passthru_cmd *cmd;
	struct nvme_id_ctrl *nctrl;
	struct io_uring nvring;
	int queue_depth = 80;
	struct io_uring_sqe *sqe = NULL;
	struct io_uring_cqe *cqe = NULL;

	if (argc < 2) {
		fprintf(stderr, "usage: %s /dev/nvmeXnY\n", argv[0]);
		return -EINVAL;
	}

	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		perror("open");
		return -errno;
	}

	nctrl = (struct nvme_id_ctrl *)calloc(1, sizeof(struct nvme_id_ctrl));
	if (!nctrl) {
		fprintf(stderr, "Memory allocation failure\n");
		ret = -ENOMEM;
		goto free_fd;
	}

	ret = io_uring_queue_init(queue_depth, &nvring, IORING_SETUP_SQE128 | IORING_SETUP_CQE32);
	if (ret < 0) {
		fprintf(stderr, "Initialize io uring fail %d \n", ret);
		goto free_nctrl;
	}
	/* Prepare the SQE to use the IORING_OP_URING_CMD opcode */
	sqe = io_uring_get_sqe(&nvring);
	sqe->fd = fd;
	sqe->opcode = IORING_OP_URING_CMD;
	sqe->cmd_op = NVME_URING_CMD_ADMIN;

	cmd = (struct nvme_passthru_cmd *)&sqe->cmd;
	memset(cmd, 0, sizeof(*cmd));

	/* populate the cmd struct for the opcode */
	cmd->opcode = NVME_IDENTIFY_ADMIN_CMD;
	cmd->addr = (__u64)(uintptr_t)nctrl;
	cmd->data_len = sizeof(struct nvme_id_ctrl);
	cmd->cdw10 = NVME_IDENTIFY_CNS_CTRL;

	/*submit the SQE */
	io_uring_submit(&nvring);

	ret = io_uring_wait_cqe(&nvring, &cqe);

	if (ret < 0) {
		fprintf(stderr, "wait_cqe: %s\n", strerror(-ret));
	} else if (cqe && cqe->res < 0) {
		fprintf(stderr, "Command failed (cqe->res): %d\n", cqe->res);
		ret = cqe->res;
	} else {
		ret = 0;
	}

	if (cqe)
		io_uring_cqe_seen(&nvring, cqe);
	io_uring_queue_exit(&nvring);
free_nctrl:
	free(nctrl);
free_fd:
	close(fd);

	return ret;
}
