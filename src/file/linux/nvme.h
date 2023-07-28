/*
 * nvme.h
 *
 * Copyright © 2023 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

struct nvme_identify_t {
	char model_str[41];
	char serial_str[21];
};

extern bool nvme_get_identify(struct file_t *dev_file, struct nvme_identify_t *identify);
