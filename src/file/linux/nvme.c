/*
 * nvme.c
 *
 * Copyright © 2023 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include <app_include.h>
#include <linux/nvme_ioctl.h>

#if defined(DEBUG)
#define RUNTIME_DEBUG 1
#else
#define RUNTIME_DEBUG 0
#endif

/*
 * Define the filename to be used for assertions.
 */
THIS_FILE("nvme");

static void nvme_get_identify_str_internal(char *dst, uint8_t *src_ptr, uint8_t *src_end)
{
	size_t length = src_end - src_ptr;
	memcpy(dst, src_ptr, length);
	dst[length] = 0;

	str_trim_whitespace(dst);
}

bool nvme_get_identify(struct file_t *dev_file, struct nvme_identify_t *identify)
{
	uint8_t data[4096];
	memset(data, 0, sizeof(data));

	struct nvme_passthru_cmd cmd;
	memset(&cmd, 0, sizeof(struct nvme_passthru_cmd));

	cmd.opcode = 0x06;
	cmd.addr = (uint64_t)(void *)data;
	cmd.data_len = sizeof(data);
	cmd.cdw10 = 1;

	if (ioctl(dev_file->fp, NVME_IOCTL_ADMIN_CMD, &cmd) < 0) {
		DEBUG_ERROR("ioctl failed (%d)", errno);
		return false;
	}
	if (cmd.result != 0) {
		DEBUG_ERROR("command failed (%u)", cmd.result);
		return false;
	}

	nvme_get_identify_str_internal(identify->model_str, data + 24, data + 64);
	nvme_get_identify_str_internal(identify->serial_str, data + 4, data + 24);
	return true;
}
