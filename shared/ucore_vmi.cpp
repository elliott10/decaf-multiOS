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
process * ucore_find_new_process(CPUState *env, uint32_t cr3) {
        return (process *)NULL;
#if 0
	uint32_t task_pid = 0, ts_parent_pid = 0, proc_cr3 = -1;
	const int MAX_LOOP_COUNT = 1024; // maximum loop count when trying to find a new process (will there be any?)
	process *right_proc = NULL;

	//static target_ulong _last_next_task = 0;// another way to speed up: when the last task remain the same, return immediately

	//uint32_t _last_task_pid = last_task_pid;
	target_ulong next_task, ts_real_parent, mm, task_pgd;
	next_task = UCORE_OFFSET_PROFILE.init_task_addr;

	// avoid infinite loop
	for (int count = MAX_LOOP_COUNT; count > 0; --count)
	{

		// NOTICE by reading next_task at the beginning, we are skipping the "swapper" task
		// highly likely ucore add the latest process to the tail of the linked list, so we go backward here
		BREAK_IF(DECAF_read_ptr(env, 
			next_task + (OFFSET_PROFILE.ts_tasks + sizeof(target_ptr)),
			&next_task) < 0);

		// NOTE - tasks is a list_head, so we need to minus offset to get the base address
		next_task -= OFFSET_PROFILE.ts_tasks;
/*		if (_last_next_task == next_task
				|| next_task == OFFSET_PROFILE.init_task_addr) {// we have traversed the whole link list, or no new process
			break;
		}*/

		if(OFFSET_PROFILE.init_task_addr == next_task)
		{
			break;
		}

		// read task pid, jump out directly when we fail
		BREAK_IF(DECAF_read_ptr(env,
			next_task + OFFSET_PROFILE.ts_tgid,
			&task_pid) < 0);

		BREAK_IF(DECAF_read_ptr(env,
			next_task + OFFSET_PROFILE.ts_mm,
			&mm) < 0);

		// // NOTICE kernel thread does not own a process address space, thus its mm is NULL. It uses active_mm instead
		// if (populate_mm_struct_offsets(env, mm, &OFFSET_PROFILE))
		// 	continue;	// try until we get it.

		if (mm != 0)
		{ 	// for user-processes
			// we read the value of active_mm into mm here
			BREAK_IF(DECAF_read_ptr(env,
					next_task + OFFSET_PROFILE.ts_mm + sizeof(target_ptr),
					&mm) < 0
					||
					DECAF_read_ptr(env,
					mm + OFFSET_PROFILE.mm_pgd,
					&task_pgd) < 0);

			proc_cr3 = DECAF_get_phys_addr(env, task_pgd);
		}
		else
		{	// for kernel threads
			proc_cr3 = -1;// when proc_cr3 is -1UL, we cannot find the process by findProcessByCR3(), but we still can do findProcessByPid()
		}

		if (!VMI_find_process_by_pgd(proc_cr3)) {
			// get parent task's base address
			BREAK_IF(DECAF_read_ptr(env,
					next_task + OFFSET_PROFILE.ts_real_parent,
					&ts_real_parent) < 0
					||
					DECAF_read_ptr(env,
					ts_real_parent + OFFSET_PROFILE.ts_tgid,
					&ts_parent_pid) < 0);

			process* pe = new process();
			pe->pid = task_pid;
			pe->parent_pid = ts_parent_pid;
			pe->cr3 = proc_cr3;
			pe->EPROC_base_addr = next_task; // store current task_struct's base address
			BREAK_IF(DECAF_read_mem(env,
					next_task + OFFSET_PROFILE.ts_comm,
					SIZEOF_COMM, pe->name) < 0);
			VMI_create_process(pe);

			//monitor_printf(default_mon, "new proc = %s, pid = %d, parent_pid = %d \n", pe->name, pe->pid, pe->parent_pid);
			if (cr3 == proc_cr3) {// for kernel thread, we are going to return NULL
				// NOTICE we may find multiple processes in this function, but we only return the current one
				right_proc = pe;
			}
		}
	}

	//last_task_pid = _last_task_pid;
	
	return right_proc;
#endif
}

// retrive symbols from specific process
static void ucore_retrive_symbols(CPUState *env, process * proc) {
	if (!proc || proc->cr3 == -1UL) return;	// unnecessary check
	for (unordered_map < uint32_t,module * >::iterator it = proc->module_list.begin();
		it != proc->module_list.end(); it++) {
		module *cur_mod = it->second;
		if (!cur_mod->symbols_extracted)
			ucore_extract_symbols_info(env, proc->cr3, it->first, cur_mod);
	}
}


// for every tlb call back, we try finding new processes
// static
// void ucore_tlb_call_back(DECAF_Callback_Params *temp) __attribute__((optimize("O0")));
void ucore_tlb_call_back(DECAF_Callback_Params *temp)
{
	CPUState *ourenv = temp->tx.env;
	uint32_t vaddr = temp->tx.vaddr;
	uint32_t pgd = -1;
	process *proc = NULL;
	bool found_new = false;
	pgd = DECAF_getPGD(ourenv);


	//TODO: kernel modules are not retrieved in the current implementation.
	if (DECAF_is_in_kernel(ourenv)) {
		//proc = kernel_proc;
	}
	else if ( (proc = VMI_find_process_by_pgd(pgd)) == NULL) {
		found_new = ((proc = ucore_find_new_process(ourenv, pgd)) != NULL);
	}

	if (proc) {	// we are not scanning modules for kernel threads, since kernel thread's cr3 is -1UL, the proc should be null

		if ( !ucore_is_vm_page_resolved(proc, vaddr) ) {
			char task_comm[SIZEOF_COMM];
			if ( !found_new
				&& !DECAF_read_mem(ourenv, proc->EPROC_base_addr + UCORE_OFFSET_PROFILE.ps_mm, SIZEOF_COMM, task_comm) 
				&& strncmp(proc->name, task_comm, SIZEOF_COMM) ) {
					strcpy(proc->name, task_comm);
					//message_p(proc, '^');
			}

			//get_new_modules(ourenv, proc);

			//If this page still cannot be resolved, we give up.
			if (!ucore_is_vm_page_resolved(proc, vaddr)) {
				int attempts = ucore_unresolved_attempt(proc, vaddr);
				if (attempts > 200)
					proc->resolved_pages.insert(vaddr>>12);
			}
		}

		// retrieve symbol information here
		//retrive_symbols(env, proc);
	}
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
	
	monitor_printf(default_mon, "idleproc kernel thread @ [%08x] \n", UCORE_OFFSET_PROFILE.idleproc);

	VMI_guest_kernel_base = 0xc0000000;

	return (1);
}



// when we know this is a ucore
void ucore_vmi_init()
{

	DECAF_register_callback(DECAF_TLB_EXEC_CB, ucore_tlb_call_back, NULL);

	recon_timer = qemu_new_timer_ns(vm_clock, ucore_check_procexit, 0);
	qemu_mod_timer(recon_timer,
				   qemu_get_clock_ns(vm_clock) + get_ticks_per_sec() * 20);

}

