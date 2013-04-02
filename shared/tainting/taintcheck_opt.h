/*
Copyright (C) <2012> <Syracuse System Security (Sycure) Lab>

DECAF is based on QEMU, a whole-system emulator. You can redistribute
and modify it under the terms of the GNU GPL, version 3 or later,
but it is made available WITHOUT ANY WARRANTY. See the top-level
README file for more details.

For more information about DECAF and other softwares, see our
web site at:
http://sycurelab.ecs.syr.edu/

If you have any questions about DECAF,please post it on
http://code.google.com/p/decaf-platform/
*/
//Removed --Heng
//uncomment this
#ifndef TAINTCHECK_OPT_H_INCLUDED
#define TAINTCHECK_OPT_H_INCLUDED

#include <stdint.h> // AWH
//#include "shared/DECAF_main.h" // AWH
//#include "DECAF_target.h"
//#include "cpu.h" // AWH

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus


#define size_to_mask(size) ((1u << (size*8)) - 1u) //size<=4

#ifdef CONFIG_TCG_TAINT

static inline uint64_t taintcheck_register_check(int regid,int offset,int size,CPUState *env){
	int off = offset*8;
    return (size < 4) ? (env->taint_regs[regid]>>off)&size_to_mask(size):
    		env->taint_regs[regid]>>off;
}

uint64_t taintcheck_memory_check(uint32_t addr, int size);

uint64_t taintcheck_check_virtmem(uint32_t vaddr, uint32_t size);

void taintcheck_nic_writebuf(const uint32_t addr, const int size, const uint8_t * taint);

void taintcheck_nic_readbuf(const uint32_t addr, const int size, uint8_t *taint);

void taintcheck_nic_cleanbuf(const uint32_t addr, const int size);

#endif /* CONFIG_TCG_TAINT */
#ifdef __cplusplus
}
#endif // __cplusplus

#endif //TAINTCHECK_OPT_H_INCLUDED
