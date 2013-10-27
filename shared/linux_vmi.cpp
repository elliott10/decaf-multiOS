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
 * linux_vmi.cpp
 *
 *  Created on: June 7, 2013
 *      Author: Heng Yin
 *  Updated on: August 29, 2013
 *          by: Kevin Wang
 */

#include <inttypes.h>
#include <string>
#include <list>
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

#ifdef __cplusplus
};
#endif /* __cplusplus */

#include "linux_vmi.h"
#include "linux_procinfo.h"
#include "hookapi.h"
#include "function_map.h"
#include "shared/procmod.h"
#include "shared/vmi.h"
#include "DECAF_main.h"
#include "DECAF_target.h"
#include "shared/utils/SimpleCallback.h"

using namespace std;
using namespace std::tr1;

#ifdef CONFIG_VMI_ENABLE

// current linux profile
static ProcInfo OFFSET_PROFILE = {"VMI"};

//static process *kernel_proc = NULL;

/* Timer to check for proc exits */
static QEMUTimer *recon_timer = NULL;

static inline int is_page_resolved(process *proc, uint32_t page_num)
{
	return (proc->resolved_pages.find(page_num>>12) != proc->resolved_pages.end());
}


static void message_p(process* proc, int operation) {
	char proc_mod_msg[512] = { '\0' };

	switch (operation) {
	case '+':
		snprintf(proc_mod_msg, sizeof(proc_mod_msg), "P + %d %d %08x %s\n",
				 proc->pid, proc->parent_pid, proc->cr3, proc->name);
		break;
	case '-':
		snprintf(proc_mod_msg, sizeof(proc_mod_msg), "P - %d %d %08x %s\n",
				 proc->pid, proc->parent_pid, proc->cr3, proc->name);
		break;
	case '^':
		snprintf(proc_mod_msg, sizeof(proc_mod_msg), "P ^ %d %d %08x %s\n",
				 proc->pid, proc->parent_pid, proc->cr3, proc->name);
	}
	handle_guest_message(proc_mod_msg);
}

static void message_m(uint32_t pid, uint32_t cr3, uint32_t base, module *pe) {
	char proc_mod_msg[612] = { '\0' };

	//char api_msg[2048] = {'\0'};
	//struct api_entry *api = NULL, *next = NULL;
	char name[32] = { '\0' };
	if (strlen(pe->name) == 0)
		return;
	uint32_t i = 0;
	while (pe->name[i]) {
		name[i] = tolower(pe->name[i]);
		i++;
	}
	//monitor_printf(default_mon,"%s\n", name);
	//monitor_printf(default_mon,"M %d %08x \"%s\" %08x %08x \"%s\"\n", pid, cr3, name, base, pe->size,pe->fullname);
	snprintf(proc_mod_msg, sizeof(proc_mod_msg),
			 "M %d %08x \"%s\" %08x %08x \"%s\"\n", pid, cr3, name, base,
			 pe->size, pe->fullname);
	handle_guest_message(proc_mod_msg);
}


static void message_p_d(dprocess* proc, int operation) {
	char proc_mod_msg[1024] = { '\0' };

	switch (operation) {
	case '+':
		snprintf(proc_mod_msg, sizeof(proc_mod_msg), "P + %d %d %08x %s\n",
				 proc->pid, proc->parent_pid, proc->cr3, proc->name);
		break;
	case '-':
		snprintf(proc_mod_msg, sizeof(proc_mod_msg), "P - %d %d %08x %s\n",
				 proc->pid, proc->parent_pid, proc->cr3, proc->name);
		break;
	case '^':
		snprintf(proc_mod_msg, sizeof(proc_mod_msg), "P ^ %d %d %08x %s\n",
				 proc->pid, proc->parent_pid, proc->cr3, proc->name);
	}
	handle_guest_message(proc_mod_msg);
}


static int dump_modules(CPUState *env, uint32_t cr3, module * mod, target_ulong start_addr) {
	char magicBytes[4];
	char filepath[64];

	if (DECAF_read_mem_with_pgd(env, cr3, start_addr, sizeof(magicBytes), magicBytes) < 0) {
		// memory is not ready yet
		return 0;
	}
	// read first 4 bytes, verify the magic bytes of ELF header first
	else if (!(magicBytes[0] == 0x7f && magicBytes[1] == 'E' && magicBytes[2] == 'L' && magicBytes[3] == 'F')) {
		// not valid an ELF
		return 0;
	}

	sprintf(filepath, "/tmp/%s", mod->name);
	FILE *fp = fopen(filepath, "w");
	if (fp == NULL) {
		monitor_printf(default_mon, "File cannot be opened for writing \n");
		return 0;
	}

	//DECAF_stop_vm();	// stop VM before dumping memory
	const target_ulong READ_PAGE_SIZE = 4096;	// how much to read every time?
	for (target_ulong i=0, readSize=0; i < mod->size; i += READ_PAGE_SIZE) {
		char mem_page[READ_PAGE_SIZE];
		readSize = mod->size - i;
		if (readSize > READ_PAGE_SIZE)
			readSize = READ_PAGE_SIZE;
		if (DECAF_read_mem_with_pgd(env, cr3, start_addr+i, readSize, mem_page) < 0) {
			fclose(fp);
			//DECAF_start_vm();
			//monitor_printf(default_mon, "READ FAILED \n");
			return 0;
		}
		fwrite(mem_page, 1, readSize, fp);
	}
	fclose(fp);
	//DECAF_start_vm();
	mod->symbols_extracted = true;	// mark as extracted
	monitor_printf(default_mon, "mod %s (start_addr = 0x%08x, end_addr = 0x%08x) is dumped \n", filepath, start_addr, (start_addr + mod->size));
	return 1;
}

void extract_symbols_info(CPUState *env, uint32_t cr3, target_ulong start_addr, module * mod) {
}

// get new module, basically reading from mm_struct
static void get_new_modules(CPUState* env, process * proc)
{

	target_ulong ts_mm, mm_mmap, vma_file, vma_next, f_dentry;
	const int MAX_LOOP_COUNT = 300;	// prevent infinite loop
	target_ulong vma_vm_start = 0, vma_vm_end = 0;
	static target_ulong last_vm_start = 0, last_vm_end = 0;
	char name[32], key[128];	// module file path
	static std::string last_mod_name;
	module* mod = NULL;
	std::string _name;

	if (DECAF_read_mem(env, proc->EPROC_base_addr + OFFSET_PROFILE.ts_mm, sizeof(target_ptr), &ts_mm) < 0)
		return;

	// read vma from mm first, then traverse mmap
	if (DECAF_read_mem(env, ts_mm + OFFSET_PROFILE.mm_mmap, sizeof(target_ptr), &mm_mmap) < 0)
		return;

	// starting from the first vm_area, read vm_file. NOTICE vm_area_struct can be null
	if ((vma_next = mm_mmap) == 0)
		return;

	// see if vm_area is populated already
	if (populate_vm_area_struct_offsets(env, vma_next, &OFFSET_PROFILE) < 0)
		return;

	for (size_t count = MAX_LOOP_COUNT; count--; ) {

		// read current vma's size
		if (DECAF_read_mem(env, vma_next + OFFSET_PROFILE.vma_vm_start, sizeof(target_ptr), &vma_vm_start) < 0)
			goto next;

		if (is_page_resolved(proc, vma_vm_start))
			goto next;

		if (DECAF_read_mem(env, vma_next + OFFSET_PROFILE.vma_vm_end, sizeof(target_ptr), &vma_vm_end) < 0)
			goto next;


		if (DECAF_read_mem(env, vma_next + OFFSET_PROFILE.vma_vm_file, sizeof(target_ptr), &vma_file) < 0 || !vma_file)
			goto next;

		if (getDentryFromFile(env, vma_file, &OFFSET_PROFILE))	// populate dentry offset
			goto next;

		if (DECAF_read_mem(env, vma_file + OFFSET_PROFILE.file_dentry, sizeof(target_ptr), &f_dentry) < 0 || !f_dentry)
			goto next;

		if (populate_dentry_struct_offsets(env, f_dentry, &OFFSET_PROFILE))
			goto next;

		// read small names
		if (DECAF_read_mem(env, f_dentry + OFFSET_PROFILE.dentry_d_iname, 32, name) < 0)
			goto next;

		name[31] = '\0';	// truncate long string
#if 1
		_name = name;
		if (!_name.length() || !(_name.find("lib")==0 && ( _name.find(".so.")!=std::string::npos || _name.find_last_of(".so")==_name.length()-3 )))
			goto next;

		// use module name for key
		//monitor_printf(default_mon, "\nlast lib = %s, vm_start = 0x%08x, vm_end = 0x%08x \n", last_mod_name.c_str(), last_vm_start, last_vm_end);
		//monitor_printf(default_mon, "new lib = %s, vm_start = 0x%08x, vm_end = 0x%08x \n", name, vma_vm_start, vma_vm_end);

		if (last_mod_name.length() == 0) { 	// for the first detected module
			last_vm_start = vma_vm_start;
			last_vm_end = vma_vm_end;
			last_mod_name = _name;
		}
		else if (last_mod_name.compare(_name) != 0 || vma_vm_start != last_vm_end) { // different modules, or when the module is loaded again
			// NOTICE the vm_next is sorted by address, according to Linux source code comment,
			// so the vma_vm_start should be equal to last_vm_end if they belong to the same module
			//sprintf(key, "%s_%x", last_mod_name.c_str(), last_vm_end - last_vm_start);
			strcpy(key, last_mod_name.c_str());
			//monitor_printf(default_mon, "mod_name %s \n", key);

			mod = findModule(key);
			if (!mod) {
				mod = new module();
				strcpy(mod->name, last_mod_name.c_str());
				mod->size = 0; // we update mod size later
				addModule(mod, key);
			}
			procmod_insert_modinfoV(proc->pid, last_vm_start, mod);
			message_m(proc->pid, proc->cr3, last_vm_start, mod);

			if (mod->size < last_vm_end - last_vm_start) { // the size may expand or shink at a later time
				mod->size = last_vm_end - last_vm_start;
				//monitor_printf(default_mon, "shared lib (%s, 0x%08x->0x%08x) is loaded to proc %s (pid = %d) \n", last_mod_name.c_str(), last_vm_start, last_vm_end, proc->name, proc->pid);
			}

			// try to dump modules here
			dump_modules(env, proc->cr3, mod, last_vm_start);

			last_vm_start = vma_vm_start;
			last_vm_end = vma_vm_end;
			last_mod_name = _name;
		}
		else if (last_mod_name.compare(_name) == 0) {
			if (last_vm_end == vma_vm_start)	// continous sections
				last_vm_end = vma_vm_end;	// extend vm area
			else if (last_vm_start == vma_vm_end)
				last_vm_start = vma_vm_start;
		}
#endif

next:
		if (DECAF_read_mem(env, vma_next + OFFSET_PROFILE.vma_vm_next, sizeof(target_ptr), &vma_next) < 0)
			break;
		if (!vma_next || vma_next == mm_mmap)
			break;
	}
}

static process * find_new_process(CPUState *env, uint32_t cr3) {
	uint32_t task_pid = 0, ts_parent_pid = 0;
	const int MAX_LOOP_COUNT = 300;
	// how are we going to traverse the task list? set this to zero we are traverse forward, set to sizeof(target_ptr) we will traverse backward
	// (according the list_head)
	const target_ulong TASKS_DIRECTION = sizeof(target_ptr);
	int count = MAX_LOOP_COUNT;	// avoid infinite loop
	process *right_proc = NULL, *proc = NULL;

	for (target_ulong next_task = OFFSET_PROFILE.init_task_addr, ts_real_parent, mm, task_pgd, proc_cr3;
		count-- ;
		) {

		// NOTICE by reading next_task at the beginning, we are skipping the "init" task
		// highly likely linux add the latest process to the tail of the linked list, so we go backward
		if (DECAF_read_mem(env, next_task + (OFFSET_PROFILE.ts_tasks + TASKS_DIRECTION), sizeof(target_ptr), &next_task) < 0)
			break;

		// NOTE - tasks is a list_head, so we need to minus offset to get the base address
		next_task -= OFFSET_PROFILE.ts_tasks;
		if (next_task == OFFSET_PROFILE.init_task_addr)	// loop back, we have traversed the whole link list
			break;

		// read task pid
		if (DECAF_read_mem(env, next_task + OFFSET_PROFILE.ts_tgid, sizeof(target_ulong), &task_pid) < 0)
			continue;

		if ( (proc = findProcessByPid(task_pid)) != NULL) 
			continue;


		if (DECAF_read_mem(env, next_task + OFFSET_PROFILE.ts_mm, sizeof(target_ptr), &mm) < 0)
			continue;

		if (mm == 0) {
			// NOTICE kernel thread does not own a process address space, thus its mm is NULL. It uses active_mm instead
			continue;
		}
		else if (populate_mm_struct_offsets(env, mm, &OFFSET_PROFILE) != 0)	// see if mm_struct offsets are populated. If not, do it now
			continue;	// try until we get it.

		if (DECAF_read_mem(env, next_task + OFFSET_PROFILE.ts_mm + sizeof(target_ptr), sizeof(target_ptr), &mm) < 0 || DECAF_read_mem(env, mm + OFFSET_PROFILE.mm_pgd, sizeof(target_ulong), &task_pgd) < 0)
			continue;

		proc_cr3 = DECAF_get_phys_addr(env, task_pgd);
		if (findProcessByCR3(proc_cr3))
			continue;

		// get parent task's base address
		if (DECAF_read_mem(env, next_task + OFFSET_PROFILE.ts_real_parent, sizeof(target_ptr), &ts_real_parent) < 0)
			continue;

		if (DECAF_read_mem(env, ts_real_parent + OFFSET_PROFILE.ts_tgid, sizeof(target_ulong), &ts_parent_pid) < 0)
			continue;

		//monitor_printf(default_mon, "pgd =%08x CR3=%08x, pgd_val=%08x\n", task_pgd, cr3, proc_cr3);

		process* pe = new process();
		pe->pid = task_pid;
		pe->parent_pid = ts_parent_pid;
		pe->cr3 = proc_cr3;
		pe->EPROC_base_addr = next_task; // store current task_struct's base address
		DECAF_read_mem(env, next_task + OFFSET_PROFILE.ts_comm, SIZEOF_COMM, pe->name);
		addProcV(pe);
		message_p(pe, '+');
		//monitor_printf(default_mon, "new proc = %s, pid = %d, parent_pid = %d \n", pe->name, pe->pid, pe->parent_pid);
		if (cr3 == proc_cr3) {
			right_proc = pe;
			break;	// once we find a new process, there is no point traverse the entire of linked list
		}
	}

	return right_proc;
}

// retrive symbols from specific process
static void retrive_symbols(CPUState *env, process * proc) {
	if (!proc)
		return;
	for (unordered_map < uint32_t,module * >::iterator it = proc->module_list.begin();
		it != proc->module_list.end(); it++) {
		module *cur_mod = it->second;
		if (!cur_mod->symbols_extracted)
			extract_symbols_info(env, proc->cr3, it->first, cur_mod);
	}
}

static void Linux_tlb_call_back(DECAF_Callback_Params *temp)
{
	CPUState *env = temp->tx.env;
	target_ulong vaddr = temp->tx.vaddr;
	uint32_t cr3 = DECAF_getPGD(env);
	process *proc = NULL;
	int found_new = 0;

	//TODO: kernel modules are not retrieved in the current implementation.
	if (DECAF_is_in_kernel()) {
		//proc = kernel_proc;
	} else {
		proc = findProcessByCR3(cr3);
		if (proc == NULL) {
			proc = find_new_process(env, cr3);
			if (proc) {
				found_new = 1;
			}
		}
	}

	if (proc) {
		if(!is_page_resolved(proc, vaddr)) {
			char task_comm[SIZEOF_COMM];
			if (!found_new) {
				DECAF_read_mem(env, proc->EPROC_base_addr + OFFSET_PROFILE.ts_comm, 
					SIZEOF_COMM, task_comm);
				if(strncmp(proc->name, task_comm, SIZEOF_COMM)) {
					//monitor_printf(default_mon, "update proc (%s -> %s), pid = %d \n", proc->name, task_comm, proc->pid);
					strcpy(proc->name, task_comm);
					message_p(proc, '^');
				} 
			}
			get_new_modules(env, proc);

			if (!is_page_resolved(proc, vaddr)) {
				if (proc->pending_pages.find(vaddr>>12) == proc->pending_pages.end())
					proc->pending_pages.insert(vaddr>>12);
				else {
					proc->pending_pages.erase(vaddr>>12);
					proc->resolved_pages.insert(vaddr>>12);
				}
			}

		}
		// retrive symbol information here
		retrive_symbols(env, proc);
	}
}

static void check_procexit(void *) {
	CPUState *env = cpu_single_env ? cpu_single_env : first_cpu;
	qemu_mod_timer(recon_timer,
				   qemu_get_clock_ns(vm_clock) + get_ticks_per_sec() * 30);
	size_t numofProc, task_pid = 0;
	dprocess *processes;
	target_ulong next_task = OFFSET_PROFILE.init_task_addr;
	processes = find_all_processes_infoV(&numofProc);
	dprocess *proc;
	unordered_set<uint32_t> taskPID_set;
	// store all tasks first
	taskPID_set.insert(0);	// init_task shall never be removed
	for (int i = 0; i < 512; i++) {	// limit loop round, avoid infinite loop
		if (DECAF_read_mem(env, next_task + OFFSET_PROFILE.ts_tasks, sizeof(target_ptr), &next_task) < 0)
			break;
		next_task -= OFFSET_PROFILE.ts_tasks;
		if (next_task == OFFSET_PROFILE.init_task_addr)
			break;
		if (DECAF_read_mem(env, next_task + OFFSET_PROFILE.ts_pid, sizeof(target_ulong), &task_pid) < 0)
			break;
		taskPID_set.insert(task_pid);	// push pid into a set
	}
	if (processes != NULL) {
		// what we do here is to traverse the running task list,
		// remove non-exist tasks
		for (size_t i = numofProc; i--; ) {
			proc = &processes[i];
			if (taskPID_set.find(proc->pid) == taskPID_set.end()) {	// remove when not found
				removeProcV(proc->pid);
				message_p_d(proc, '-');
				//monitor_printf(default_mon, "proc %s (pid = %d) is removed \n", proc->name, proc->pid);
			}
		}
	}
	delete[] processes;
}

// to see whether this is a Linux or not,
// the trick is to check the init_thread_info, init_task
int find_linux(CPUState *env, uintptr_t insn_handle) {
	target_ulong _thread_info = DECAF_getESP(env) & ~ (guestOS_THREAD_SIZE - 1);
	static target_ulong _last_thread_info = 0;

	// if current address is tested before, save time and do not try it again
	if (_thread_info == _last_thread_info || _thread_info <= 0x80000000)
		return 0;
	// first time run
	if (_last_thread_info == 0)
		memset(&OFFSET_PROFILE.init_task_addr, -1, sizeof(ProcInfo) - sizeof(OFFSET_PROFILE.strName));

	_last_thread_info = _thread_info;

	// try populate kernel offset, NOTICE we cannot get mm_struct offset yet
	if (populate_kernel_offsets(env, _thread_info, &OFFSET_PROFILE) != 0)
		return (0);
	
	monitor_printf(default_mon, "init_task @ [%08x] \n", OFFSET_PROFILE.init_task_addr);
	// it is firm that this is linux.  we can start extract process information here, but mm offsets may not be ready yet

	//printProcInfo(&OFFSET_PROFILE);

	return (1);
}

void linux_vmi_init()
{
	DECAF_register_callback(DECAF_TLB_EXEC_CB, Linux_tlb_call_back, NULL);

	recon_timer = qemu_new_timer_ns(vm_clock, check_procexit, 0);
	qemu_mod_timer(recon_timer,
				   qemu_get_clock_ns(vm_clock) + get_ticks_per_sec() * 30);
}
#endif /* CONFIG_VMI_ENABLE*/

