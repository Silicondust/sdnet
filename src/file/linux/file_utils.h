/*
 * file_utils.h
 *
 * Copyright © 2016 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

struct file_t {
	int fp;
	void *mmap_addr;
	size_t mmap_length;
};
