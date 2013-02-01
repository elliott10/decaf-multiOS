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
#ifndef _DECAF_MAIN_INTERNAL_H_
#define _DECAF_MAIN_INTERNAL_H_

#include "monitor.h"

//LOK: Separate data structure for DECAF commands and plugin commands
extern mon_cmd_t DECAF_mon_cmds[];
extern mon_cmd_t DECAF_info_cmds[];

/****** Functions used internally ******/
extern void DECAF_nic_receive(const uint8_t * buf, int size, int cur_pos, int start, int stop);
extern void DECAF_nic_send(uint32_t addr, int size, uint8_t * buf);
extern void DECAF_nic_in(uint32_t addr, int size);
extern void DECAF_nic_out(uint32_t addr, int size);
extern void DECAF_read_keystroke(void *s);
extern void DECAF_virtdev_init(void);
extern void DECAF_after_loadvm(const char *); // AWH void);
extern void DECAF_init(void);

#if 0 //LOK: Removed these for the new callback interface
extern int TEMU_block_begin(void);
extern void TEMU_insn_begin(uint32_t pc_start);
extern void TEMU_insn_end(void);
extern void TEMU_block_end(void);
#endif

#ifdef TEMU_LD_PHYS_CB
extern void TEMU_ld_phys_cb(target_ulong addr, int size);
#endif
#ifdef TEMU_ST_PHYS_CB
extern void TEMU_st_phys_cb(target_ulong addr, int size);
#endif

extern void DECAF_update_cpl(int cpl);
extern void DECAF_do_interrupt(int intno, int is_int, target_ulong next_eip);
extern void DECAF_after_iret_protected(void);
//extern void TEMU_update_cpustate(void);
extern void DECAF_loadvm(void *opaque);

#endif //_TEMU_MAIN_INTERNAL_H_
