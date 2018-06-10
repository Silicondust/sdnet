/*
 * arch_generic.c
 *
 * Copyright © 2017 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
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

THIS_FILE("arch_dummy");

extern void *_init;
extern void *_fini;

addr_t arch_get_crash_pc(siginfo_t *si, void *context_addr)
{
	return 0;
}

addr_t arch_get_crash_sp(siginfo_t *si, void *context_addr)
{
	return (addr_t)__builtin_frame_address(0);
}

static addr_t arch_call_backtrace_internal(addr_t return_addr)
{
	if (return_addr < (addr_t)&_init) {
		return (addr_t)NULL;
	}
	if (return_addr >= (addr_t)&_fini) {
		return (addr_t)NULL;
	}

	return return_addr;
}

addr_t arch_call_backtrace(addr_t *psp)
{
	pthread_attr_t attr;
	if (pthread_getattr_np(pthread_self(), &attr) != 0) {
		DEBUG_ERROR("pthread_getattr_np failed");
		return 0;
	}

	void *stack_addr;
	size_t stack_size;
	if (pthread_attr_getstack(&attr, &stack_addr, &stack_size) != 0) {
		DEBUG_ERROR("pthread_attr_getstack failed");
		return 0;
	}

	addr_t stack_min = (addr_t)stack_addr;
	addr_t stack_max = (addr_t)stack_addr + stack_size;
	addr_t sp = *psp;

	if (sp < stack_min) {
		DEBUG_ERROR("sp %x not in range %x->%x", sp, stack_min, stack_max);
		return 0;
	}

	while (sp < stack_max) {
		addr_t return_addr = *(addr_t *)sp;
		addr_t backtrace_addr = arch_call_backtrace_internal(return_addr);
		if (backtrace_addr) {
			DEBUG_INFO("sp %x = backtrace %x", sp, backtrace_addr);
			*psp = sp + sizeof(addr_t);
			return backtrace_addr;
		}

		sp += sizeof(addr_t);
	}

	DEBUG_INFO("sp %x not in range %x->%x", sp, stack_min, stack_max);
	return 0;
}
