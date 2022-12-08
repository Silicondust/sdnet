/*
 * thread.c
 *
 * Copyright © 2012 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include <os.h>

#if defined(DEBUG)
#define RUNTIME_DEBUG 1
#else
#define RUNTIME_DEBUG 0
#endif

THIS_FILE("thread");

struct thread_context_t {
	struct thread_public_context_t public_context;
	thread_execute_func_t execute_func;
	void *execute_arg;
	volatile bool main_thread;
};

struct thread_manager_t {
	struct spinlock thread_main_lock;
	DWORD context_tls;
	struct thread_context_t initial_context;
	bool started;
};

static struct thread_manager_t thread_manager;

static struct thread_context_t *thread_get_context_internal(void)
{
	return (struct thread_context_t *)TlsGetValue(thread_manager.context_tls);
}

struct thread_public_context_t *thread_get_public_context(void)
{
	struct thread_context_t *thread_context = thread_get_context_internal();
	return &thread_context->public_context;
}

bool thread_is_main_thread(void)
{
	struct thread_context_t *thread_context = thread_get_context_internal();
	return thread_context->main_thread;
}

void thread_main_execute(thread_execute_func_t execute_func, void *execute_arg)
{
	struct thread_context_t *thread_context = thread_get_context_internal();
	if (thread_context->main_thread) {
		execute_func(execute_arg);
		return;
	}

	spinlock_lock(&thread_manager.thread_main_lock);
	thread_context->main_thread = true;

	execute_func(execute_arg);

	thread_context->main_thread = false;
	spinlock_unlock(&thread_manager.thread_main_lock);
}

void thread_main_enter(void)
{
	struct thread_context_t *thread_context = thread_get_context_internal();
	spinlock_lock(&thread_manager.thread_main_lock);
	thread_context->main_thread = true;
}

void thread_main_exit(void)
{
	struct thread_context_t *thread_context = thread_get_context_internal();
	thread_context->main_thread = false;
	spinlock_unlock(&thread_manager.thread_main_lock);
}

static void thread_public_context_init(struct thread_public_context_t *context)
{
	CryptAcquireContext(&context->crypt_handle, 0, 0, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
	DEBUG_ASSERT(context->crypt_handle, "CryptAcquireContext failed");
}

static DWORD WINAPI thread_execute(void *arg)
{
	struct thread_context_t *thread_context = (struct thread_context_t *)arg;

	thread_public_context_init(&thread_context->public_context);
	TlsSetValue(thread_manager.context_tls, thread_context);

	thread_context->execute_func(thread_context->execute_arg);
	return 0;
}

void thread_start(thread_execute_func_t execute_func, void *execute_arg)
{
	DEBUG_ASSERT(thread_manager.started, "attempt to start thread before start");

	struct thread_context_t *thread_context = (struct thread_context_t *)heap_alloc_and_zero(sizeof(struct thread_context_t), PKG_OS, MEM_TYPE_OS_THREAD);
	if (!thread_context) {
		DEBUG_ASSERT(0, "out of memory");
		return;
	}

	thread_context->execute_func = execute_func;
	thread_context->execute_arg = execute_arg;

	DWORD thread_id;
	if (CreateThread(NULL, 0, thread_execute, thread_context, 0, &thread_id) == NULL) {
		DEBUG_ASSERT(0, "CreateThread failed (%08x)", GetLastError());
		return;
	}
}

void thread_manager_start(void)
{
	thread_manager.started = true;
}

void thread_manager_init(void)
{
	spinlock_init(&thread_manager.thread_main_lock, 65535);
	thread_manager.context_tls = TlsAlloc();

	struct thread_context_t *thread_context = &thread_manager.initial_context;
	thread_public_context_init(&thread_context->public_context);
	TlsSetValue(thread_manager.context_tls, thread_context);

	thread_main_enter();
}
