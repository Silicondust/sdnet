/*
 * ./src/linux/arch.h
 *
 * Copyright © 2013 Silicondust USA Inc. <www.silicondust.com>.  All rights reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

extern addr_t arch_get_crash_pc(siginfo_t *si, void *context_addr);
extern addr_t arch_get_crash_sp(siginfo_t *si, void *context_addr);
extern addr_t arch_call_backtrace(addr_t *psp);
