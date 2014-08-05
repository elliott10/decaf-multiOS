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
/*
 * ucore_vmi.cpp
 *
 *  Created on: June 7, 2013
 *      Author: Kevin Wang, Heng Yin
 */

#include <inttypes.h>
#include <string>
#include <list>
#include <set>
#include <algorithm>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <tr1/unordered_map>
#include <tr1/unordered_set>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <queue>
#include <sys/time.h>
#include <math.h>
#include <glib.h>
#include <mcheck.h>
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
#include "cpu.h"
#include "config.h"
#include "hw/hw.h" // AWH
#include "qemu-timer.h"
#ifdef __cplusplus
};
#endif /* __cplusplus */

#include "DECAF_main.h"
#include "DECAF_target.h"
#include "vmi.h"
#include "ucore_vmi.h"
#include "linux_readelf.h"
#include "ucore_procinfo.h"
#include "hookapi.h"
#include "function_map.h"
#include "shared/utils/SimpleCallback.h"

using namespace std;
using namespace std::tr1;

#define BREAK_IF(x) if(x) break

#if defined(TARGET_I386)
#define get_new_modules get_new_modules_x86
#elif defined(TARGET_ARM)
#define get_new_modules get_new_modules_arm
#elif defined(TARGET_MIPS)
#define get_new_modules get_new_modules_mips
#else
#error Unknown target
#endif

// current ucore profile
static UcoreProcInfo UCORE_OFFSET_PROFILE = {"UCORE_VMI"};
#define uop UCORE_OFFSET_PROFILE
// _last_task_pid is used for reducing the memory reading process, when we trying to find a new process, the pid should
// be keeping growing by increment of 1, thus by tracking the pid of the last new process we found, we can speed up the
// process of finding new process. It is based on the fact that the task list is ordered by pid.
// NOTICE: one dangerous thing for this that when the pid is bigger than the "pid max limit", which is 32768 by default,
// this optimization will not work
//static uint32_t last_task_pid = 0;	// last detected task's pid (tgid)

//static process *kernel_proc = NULL;

/* Timer to check for proc exits */
static QEMUTimer *recon_timer = NULL;



// query if one vm page is resolved
static inline bool ucore_is_vm_page_resolved(process *proc, uint32_t addr)
{
	return (proc->resolved_pages.find(addr >> 12) != proc->resolved_pages.end());
}

static inline int ucore_unresolved_attempt(process *proc, uint32_t addr)
{
	unordered_map <uint32_t, int>::iterator iter = proc->unresolved_pages.find(addr>>12);
	if(iter == proc->unresolved_pages.end()) {
		proc->unresolved_pages[addr>>12] = 1;
		return 1;
	}
	iter->second++;

	return iter->second;
}


void ucore_extract_symbols_info(CPUState *env, uint32_t cr3, target_ulong start_addr, module * mod)
{
	if ( mod->symbols_extracted = read_elf_info(env, cr3, mod->name, start_addr, mod->size) ) {
		monitor_printf(default_mon, "mod %s (start_addr = 0x%08x, end_addr = 0x%08x) is extracted \n", mod->name, start_addr, (start_addr + mod->size));
	}
}


// process * find_new_process(CPUState *env, uint32_t cr3) __attribute__((optimize("O0")));
// scan the task list and find new process
static
process * ucore_find_new_process(CPUState *env) {
	
	//int count=0;
	gva_t proc_list_addr;
	gva_t list=NULL; 
	gva_t nextproc_list_link, nextproc_pid,nextproc_cr3; 
	gva_t mm=NULL; 
	char nextproc_name[20];
    const int MAX_LOOP_COUNT = 1024;
	process *proc;
	proc_list_addr = UCORE_OFFSET_PROFILE.proc_list;
	//DECAF_read_mem(env, proc_list_addr, 4, &prev_addr); //prev_list
 	//DECAF_read_mem(env, proc_list_addr+4, 4, &nextproc_list_link); //proc_list.next_list
	//monitor_printf(default_mon, "idleproc kernel thread @ [%08x] \n", UCORE_OFFSET_PROFILE.idleproc);
#if 0
	if(initproc_addr!=UCORE_OFFSET_PROFILE.initproc) {
		monitor_printf(default_mon, "ERROR get proc list prev_addr %08x, next_addr %8x \
					    initproc_addr %8x, initproc.list_link addr %8x\n", 
					    prev_addr, next_addr, 
						UCORE_OFFSET_PROFILE.initproc,
						UCORE_OFFSET_PROFILE.initproc+UCORE_OFFSET_PROFILE.ps_list_link);
		return NULL;
	}
	monitor_printf(default_mon, "SUCCESS get proc list");
	return NULL;
#endif
    nextproc_list_link=proc_list_addr; //proc_list.next_list
	// avoid infinite loop
	for (int count = MAX_LOOP_COUNT; count > 0; --count) {
		//get proc's list_link
		BREAK_IF(DECAF_read_mem(env, 
								nextproc_list_link+4,
								4,
								&nextproc_list_link) < 0);
		if(nextproc_list_link==proc_list_addr)  //finding process finished
			return NULL;
		//get proc's pid
		BREAK_IF(DECAF_read_mem(env, 
								nextproc_list_link-(uop.ps_list_link-uop.ps_pid),
								4,
								&nextproc_pid) < 0);
		proc=VMI_find_process_by_pid(nextproc_pid);
		if(proc==NULL) { //new proc
			//get proc's cr3
			BREAK_IF(DECAF_read_mem(env, 
									nextproc_list_link - (uop.ps_list_link-uop.ps_cr3),
									4,
									&nextproc_cr3) < 0);
			//get proc's name
			BREAK_IF(DECAF_read_mem(env,
									nextproc_list_link - (uop.ps_list_link-uop.ps_name),
									16, nextproc_name) < 0);
			process* pe = new process();
			pe->pid = nextproc_pid;
			pe->parent_pid = 0;
			pe->cr3 = nextproc_cr3;
			pe->EPROC_base_addr = nextproc_list_link-uop.ps_list_link; // store current task_struct's base address
			strncpy(pe->name,nextproc_name,16);
			VMI_create_process(pe);
			return pe;
		}
	}
    return (process *)NULL;
}

// for every tlb call back, we try finding new processes
// static
// void ucore_tlb_call_back(DECAF_Callback_Params *temp) __attribute__((optimize("O0")));
void ucore_tlb_call_back(DECAF_Callback_Params *temp)
{
	CPUState *ourenv = temp->tx.env;
	process *proc = ucore_find_new_process(ourenv);
}

// here we scan the task list in guest OS and sync ours with it
static void ucore_check_procexit(void *) {
        /* AWH - cpu_single_env is invalid outside of the main exec thread */
	CPUState *env = /* AWH cpu_single_env ? cpu_single_env :*/ first_cpu;
	qemu_mod_timer(recon_timer,
				   qemu_get_clock_ns(vm_clock) + get_ticks_per_sec() * 10);

	target_ulong next_task = UCORE_OFFSET_PROFILE.initproc;
	set<target_ulong> live_pids;
	set<target_ulong> vmi_pids;
	set<target_ulong> dead_pids;

	const int MAX_LOOP_COUNT = 1024;

	for(int i=0; i<MAX_LOOP_COUNT; i++)
	{
		target_ulong task_pid;
		BREAK_IF(DECAF_read_ptr(env,
			next_task + UCORE_OFFSET_PROFILE.ps_pid, 
			&task_pid) < 0);
		live_pids.insert(task_pid);

		BREAK_IF(DECAF_read_ptr(env,
			next_task + UCORE_OFFSET_PROFILE.ps_list_link + sizeof(target_ptr),
			&next_task) < 0);

		next_task -= UCORE_OFFSET_PROFILE.ps_list_link;
		if (next_task == UCORE_OFFSET_PROFILE.initproc)
		{
			break;
		}
	}

	unordered_map<uint32_t, process *>::iterator iter = process_pid_map.begin();
	for(; iter != process_pid_map.end(); iter++)
	{
		vmi_pids.insert(iter->first);
	}

	set_difference(vmi_pids.begin(), vmi_pids.end(), live_pids.begin(), live_pids.end(),
			inserter(dead_pids, dead_pids.end()));

	set<target_ulong>::iterator iter2;
	for(iter2 = dead_pids.begin(); iter2 != dead_pids.end(); iter2++)
	{
		VMI_remove_process(*iter2);
	}
}

// to see whether this is a ucore or not,
// the trick is to check the init_thread_info, init_task
int find_ucore(CPUState *env, uintptr_t insn_handle) {

	if(0 != ucore_load_proc_info(env, UCORE_OFFSET_PROFILE))
	{
		return 0;
	}
	
	monitor_printf(default_mon, "idleproc kernel thread @ 0x%08x \n", UCORE_OFFSET_PROFILE.idleproc);
    monitor_printf(default_mon, "initproc kernel thread @ 0x%08x \n", UCORE_OFFSET_PROFILE.initproc);
	monitor_printf(default_mon, "proc_list @ [%08x] \n", UCORE_OFFSET_PROFILE.proc_list);
	monitor_printf(default_mon, "sizeof_proc_struct @ %d \n", UCORE_OFFSET_PROFILE.sizeof_proc_struct);
    monitor_printf(default_mon, "ps field offset: list_link@ %d \n", UCORE_OFFSET_PROFILE.ps_list_link);
    monitor_printf(default_mon, "ps field offset: pid @ %d \n", UCORE_OFFSET_PROFILE.ps_pid);
    monitor_printf(default_mon, "ps field offset: mm @ %d \n", UCORE_OFFSET_PROFILE.ps_mm);
    monitor_printf(default_mon, "ps field offset: name @ %d \n", UCORE_OFFSET_PROFILE.ps_name);
	monitor_printf(default_mon, "ps field offset: cr3 @ %d \n", UCORE_OFFSET_PROFILE.ps_cr3);
	 
	VMI_guest_kernel_base = 0xc0000000;

	return (1);
}



// when we know this is a ucore
void ucore_vmi_init()
{

	DECAF_register_callback(DECAF_TLB_EXEC_CB, ucore_tlb_call_back, NULL);

	//recon_timer = qemu_new_timer_ns(vm_clock, ucore_check_procexit, 0);
	//qemu_mod_timer(recon_timer,
	//			   qemu_get_clock_ns(vm_clock) + get_ticks_per_sec() * 20);

}

