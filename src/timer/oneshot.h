/*
 * ./src/timer/oneshot.h
 *
 * Copyright © 2007-2011 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

typedef void (*oneshot_callback_t)(void *arg);

struct oneshot {
	struct oneshot *next;
	ticks_t callback_time;
	oneshot_callback_t callback;
	void *callback_arg;
};

extern void oneshot_init(struct oneshot *os);
extern void oneshot_attach(struct oneshot *os, ticks_t ticks, oneshot_callback_t callback, void *callback_arg);
extern void oneshot_attach_with_jitter(struct oneshot *os, ticks_t ticks, uint32_t jitter, oneshot_callback_t callback, void *callback_arg);
extern bool oneshot_detach(struct oneshot *os);
extern bool oneshot_is_attached(struct oneshot *os);
extern ticks_t oneshot_get_ticks_remaining(struct oneshot *os);

extern void oneshot_manager_init(void);
extern void oneshot_manager_start(void);
