/*
 * thread.h
 *
 * Copyright © 2012 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

struct thread_signal_t;
struct thread_public_context_t;

extern struct thread_signal_t *thread_signal_alloc(void);
extern void thread_signal_set(struct thread_signal_t *signal);

typedef void (*thread_execute_func_t)(void *arg);
extern void thread_start(thread_execute_func_t execute_func, void *execute_arg);
extern void thread_yield(void);
extern void thread_suspend_wait_for_signal(struct thread_signal_t *signal);
extern void thread_suspend_wait_for_signal_or_ticks(struct thread_signal_t *signal, ticks_t ticks);
extern void thread_suspend_wait_for_signal_or_timestamp(struct thread_signal_t *signal, ticks_t timestamp);
extern struct thread_public_context_t *thread_get_public_context(void);
extern void thread_external_thread_init(void);

extern bool thread_is_main_thread(void);
extern void thread_main_enter(void);
extern void thread_main_exit(void);
extern void thread_main_execute(thread_execute_func_t execute_func, void *execute_arg);

extern void thread_manager_init(void);
extern void thread_manager_start(void);
