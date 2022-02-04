/*
 * gpt.h
 *
 * Copyright © 2019 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

extern bool gpt_create_with_one_partition(struct file_t *dev_file);

extern int gpt_mbr_is_blank(struct file_t *dev_file);
extern bool gpt_mbr_wipe(struct file_t *dev_file);
