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

int enable_show_ucore_proc=1;

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

// get new module, basically reading from mm_struct
static void ucore_get_new_modules(CPUState* env, process * proc)
{
	target_ulong ts_mm, mm_mmap, vma_file, vma_next, f_dentry;
	const int MAX_LOOP_COUNT = 1024;	// prevent infinite loop
	target_ulong vma_vm_start = 0, vma_vm_end = 0, vma_vm_flags, vma_vm_pgoff;
	target_ulong last_vm_start = 0, last_vm_end = 0;
	char name[32], key[128];	// module file path
	string last_mod_name, mod_name;
	target_ulong mod_vm_start, mod_vm_end;
	module* mod = NULL;
	string _name;
	set<uint32_t> module_bases;
	bool finished_traversal = false;
	int mod_stage = 0;
	bool three_sections_found = false;
	static int offset_populated = 0, dentry_offset_populated = 0;
	const int VM_FLAGS_NONE = 0;
    mod_vm_start=0;
	mod = VMI_find_module_by_key(proc->name);
	if (!mod) {
		mod = new module();
		strncpy(mod->name, proc->name, 16);
		mod->name[31] = '\0';
		mod->size = 0x803000;
		VMI_add_module(mod, mod->name);
	}
    VMI_insert_module(proc->pid, mod_vm_start, mod);
	monitor_printf(default_mon, "ucore add module %s\n", mod->name);

	return;
}

//get idleproc
int ucore_find_idleproc(CPUState *env) {
	
	gva_t idleproc, idleproc_pid,idleproc_cr3; 
	char idleproc_name[20];
    const int MAX_LOOP_COUNT = 1024;
    static int got_idleproc=0;
	if(got_idleproc) return got_idleproc;
	// avoid infinite loop
	for (int count = MAX_LOOP_COUNT; count > 0; --count) {
		//get idleproc struct addr
		BREAK_IF(DECAF_read_mem(env, 
								uop.idleproc,
								4,
								&idleproc) < 0);
		//get idleproc's pid
		BREAK_IF(DECAF_read_mem(env, 
								idleproc + uop.ps_pid,
								4,
								&idleproc_pid) < 0);
		//get idleproc's cr3
		BREAK_IF(DECAF_read_mem(env, 
									idleproc  + uop.ps_cr3,
									4,
									&idleproc_cr3) < 0);
		//get idleproc's name
		BREAK_IF(DECAF_read_mem(env,
									idleproc + uop.ps_name,
									16, idleproc_name) < 0);
		//monitor_printf(default_mon, "ucore_find_idleproc　addr 0x%x, pid 0x%x, cr3 0x%x\n",
		//			   idleproc, idleproc_pid, idleproc_cr3);
        // store current proc_struct's base address
		if(strncmp(idleproc_name,"idle",5)==0) {
			 process* pe = new process();
			 pe->pid = idleproc_pid;
			 pe->parent_pid = 0;
			 pe->cr3 =  idleproc_cr3;
			 pe->EPROC_base_addr = uop.idleproc;
			 strncpy(pe->name,idleproc_name,16);
		     got_idleproc=1;
		     VMI_create_process(pe);
		     ucore_get_new_modules(env, pe);
			 monitor_printf(default_mon, "ucore_find_idleproc successfully\n");
			 return got_idleproc;
		}
	}
	return got_idleproc;
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
	proc_list_addr = uop.proc_list;

    nextproc_list_link=proc_list_addr; //proc_list.next_list

	
	//chy try find ucore idleproc. This method is not very good.
	ucore_find_idleproc(env);
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
			pe->EPROC_base_addr = nextproc_list_link-uop.ps_list_link; // store current proc_struct's base address
			strncpy(pe->name,nextproc_name,16);
			VMI_create_process(pe);

                        if(enable_show_ucore_proc) 
                          monitor_printf(default_mon, "ucore_find_new_process: forked proc pid %d name %s, cr3 %x\n",pe->pid,pe->name, pe->cr3);

			return pe;
		} 
                else {
			//now should be the exec proc.  Get proc's name 
			BREAK_IF(DECAF_read_mem(env,
									nextproc_list_link - (uop.ps_list_link-uop.ps_name),
									16, nextproc_name) < 0);
                        if( strncmp(proc->name,nextproc_name,16) != 0 ) {
                          //do_execv may processed, the proc->name should be changed.
						  strncpy(proc->name,nextproc_name,16);
						  //delelte proc  and re-add pe in VMI_create_process
						  process* pe = new process();
						  pe->pid = proc->pid;
						  pe->parent_pid = 0;
						  pe->cr3 = proc->cr3;
						  pe->EPROC_base_addr = proc->EPROC_base_addr; 		
						  strncpy(pe->name,proc->name,16);
						  VMI_create_process(pe);
						  
                          if(enable_show_ucore_proc) 
                            monitor_printf(default_mon, "ucore_find_new_process: do_execved proc pid %d name %s, cr3 %x\n",pe->pid,pe->name, pe->cr3);
						  return pe;
                        }
                        return NULL;
                }

                  
	}
    return (process *)NULL;
}

#if 0
//ucore_list_processes
int ucore_list_processes(void)
{
	CPUState *env = first_cpu;
	int count=0;
	gva_t task_struct;
	gva_t list; 
	gva_t pid; 
	gva_t mm; 
	gva_t list_addr;
	char name[20];

	task_struct = UCORE_OFFSET_PROFILE.proc_list;

	//DECAF_read_ptr(env, task_struct + 4, &task_struct); //pass the link list
	DECAF_read_ptr(env, task_struct, &task_struct); //pass the link list

	task_struct -= UCORE_OFFSET_PROFILE.ps_list_link;

	monitor_printf(default_mon, "\n***** UCORE Processes *****\n\n");

	while(1)
	{

		//target_ulong list = task_struct + UCORE_OFFSET_PROFILE.ps_list_link;
		//target_ulong pid = task_struct + UCORE_OFFSET_PROFILE.ps_pid;
		//target_ulong mm = task_struct + UCORE_OFFSET_PROFILE.ps_mm;
		//target_ulong name = task_struct + UCORE_OFFSET_PROFILE.ps_name;

		DECAF_read_ptr(env, UCORE_OFFSET_PROFILE.ps_list_link + task_struct, &list);
		DECAF_read_ptr(env, UCORE_OFFSET_PROFILE.ps_pid + task_struct, &pid);
		DECAF_read_ptr(env, UCORE_OFFSET_PROFILE.ps_mm + task_struct, &mm);
		DECAF_read_mem(env, UCORE_OFFSET_PROFILE.ps_name + task_struct, sizeof(name), name);

		monitor_printf(default_mon, "0x%x\t%3d\t0x%-8x\t%s\n", task_struct, pid, mm, name);

		count++;
		task_struct = list - UCORE_OFFSET_PROFILE.ps_list_link;

		BREAK_IF(UCORE_OFFSET_PROFILE.proc_list == list);

	}

	monitor_printf(default_mon, "\n***** A total of %d processes *****\n", count);

	return count;
}

#endif

// for every tlb call back, we try finding new processes
// static
// void ucore_tlb_call_back(DECAF_Callback_Params *temp) __attribute__((optimize("O0")));
void ucore_tlb_call_back(DECAF_Callback_Params *temp)
{
	CPUState *ourenv = temp->tx.env;
	uint32_t vaddr = temp->tx.vaddr;
	uint32_t pgd = -1;
	//process *proc = NULL;
	bool found_new = false;
	pgd = DECAF_getPGD(ourenv);

	/*
	if ( (proc = VMI_find_process_by_pgd(pgd)) == NULL) {
		found_new = ((proc = find_new_process(ourenv, pgd)) != NULL);
	}
	*/
        monitor_printf(default_mon, "ucore_get_PGD: %x\n",pgd);


	process *proc = ucore_find_new_process(ourenv);
	if(proc) { //fork or exec
		ucore_get_new_modules(ourenv, proc);
	}
}

// here we scan the task list in guest OS and sync ours with it
static void ucore_check_procexit(void *) {
        /* AWH - cpu_single_env is invalid outside of the main exec thread */
	CPUState *env = /* AWH cpu_single_env ? cpu_single_env :*/ first_cpu;
	qemu_mod_timer(recon_timer,
				   qemu_get_clock_ns(vm_clock) + get_ticks_per_sec() * 5);

        target_ulong next_proc = uop.proc_list;
	target_ulong proc_list_addr = next_proc;
        set<target_ulong> live_pids;
	set<target_ulong> vmi_pids;
	set<target_ulong> dead_pids;

	const int MAX_LOOP_COUNT = 1024;

	//chy add the idleproc will run forever
	live_pids.insert(0);
	for(int i=0; i<MAX_LOOP_COUNT; i++)
	{
                target_ulong proc_pid;
		//get proc's list_link
		BREAK_IF(DECAF_read_mem(env, next_proc + 4, 4, &next_proc) < 0);
		if(next_proc == proc_list_addr)  //finding process finished
			break;
		//get proc's pid
		BREAK_IF(DECAF_read_mem(env, next_proc-(uop.ps_list_link-uop.ps_pid), 4, &proc_pid) < 0);

		live_pids.insert(proc_pid);
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
          target_ulong pid;
          pid=*iter2;

	  process *proc;
          unordered_map < uint32_t, process * >::iterator iter =
    	  process_pid_map.find(pid);

          if(iter == process_pid_map.end())
    	     continue;

          proc = iter->second;

          if(enable_show_ucore_proc) 
               monitor_printf(default_mon, "exited proc pid %d name %s, cr3 %x\n",proc->pid,proc->name, proc->cr3);

	  VMI_remove_process(*iter2);
	}
}

static void ucore_parse_function(void)
{
	char * module="hello";
	char * fname[]={
	"cprintf" ,
	"fprintf" ,
	"print_bye" ,
	"print_hello" ,
	"print_me" ,
	"print_pgdir" ,
	"print_stat" ,
	"printfmt" ,
	"printnum" ,
	"snprintf" ,
	"sprintputch" ,
	"vcprintf" ,
	"vfprintf" ,
	"vprintfmt" ,
	"vsnprintf" ,
	"sys_write" ,
	"write" ,
	"myreadline" ,
	"read" ,
	"readdir" ,
	"sys_read" };
	target_ulong offset[]={
	0x008003e4,
	0x008004ce,
	0x008018c5,
	0x0080188c,
	0x008018a8,
	0x00800958,
	0x00800252,
	0x00800d03,
	0x00800b18,
	0x008011ce,
	0x00801199,
	0x008003a8,
	0x00800493,
	0x00800d3a,
	0x00801204,
	0x008006fc,
	0x00800146,
	0x008018e5,
	0x00800125,
	0x00800098,
	0x008006d3};

	int i, size=21;
	 monitor_printf(default_mon, "ucore_parse_function: insert functions\n");
	for (i=0;i<size;i++){
	    funcmap_insert_function(module, fname[i], offset[i]);
	}
}
// to see whether this is a ucore or not,
// the trick is to check the init_thread_info, init_task
int find_ucore(CPUState *env, uintptr_t insn_handle) {

	target_ulong ESP_info = DECAF_getESP(env);
	static target_ulong last_ESP_info = 0;

    //monitor_printf(default_mon, "ucore ESP: 0x%x \n", ESP_info);
	//to see whether ucore ESP is booting or not
	if (ESP_info == last_ESP_info || ESP_info < 0xc0000000)
		return 0;

	last_ESP_info = ESP_info;

    if(0 != ucore_load_proc_info(env, uop)){
	return 0;
    }
	
    monitor_printf(default_mon, "idleproc kernel thread @ 0x%08x \n", uop.idleproc);
    monitor_printf(default_mon, "initproc kernel thread @ 0x%08x \n", uop.initproc);
    monitor_printf(default_mon, "proc_list @ [%08x] \n", uop.proc_list);
    monitor_printf(default_mon, "sizeof_proc_struct @ %d \n", uop.sizeof_proc_struct);
    monitor_printf(default_mon, "ps field offset: list_link@ %d \n", uop.ps_list_link);
    monitor_printf(default_mon, "ps field offset: pid @ %d \n", uop.ps_pid);
    monitor_printf(default_mon, "ps field offset: mm @ %d \n", uop.ps_mm);
    monitor_printf(default_mon, "ps field offset: name @ %d \n", uop.ps_name);
    monitor_printf(default_mon, "ps field offset: cr3 @ %d \n", uop.ps_cr3);
	 
    VMI_guest_kernel_base = 0xc0000000;
    ucore_parse_function();
	ucore_find_idleproc(env);
    return (1);
}



// when we know this is a ucore
void ucore_vmi_init()
{

	DECAF_register_callback(DECAF_TLB_EXEC_CB, ucore_tlb_call_back, NULL);

	recon_timer = qemu_new_timer_ns(vm_clock, ucore_check_procexit, 0);
	qemu_mod_timer(recon_timer,
				   qemu_get_clock_ns(vm_clock) + get_ticks_per_sec() * 10);

}

