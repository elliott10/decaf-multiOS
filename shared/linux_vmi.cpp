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
#include "sqlite3/sqlite3.h"
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
#include "cpu.h"
#include "config.h"
#include "hw/hw.h" // AWH
#include "DECAF_main.h"
#include "DECAF_target.h"
#ifdef __cplusplus
};
#endif /* __cplusplus */

#include "linux_vmi.h"
#include "hookapi.h"
#include "read_linux.h"
#include "function_map.h"
#include "shared/procmod.h"
#include "shared/vmi.h"
#include "DECAF_main.h"
#include "shared/utils/SimpleCallback.h"

#ifdef CONFIG_VMI_ENABLE

#if 0
GHashTable *cr3_hashtable = NULL;
GHashTable *eproc_ht = NULL;
process *system_proc = NULL;
process *new_proc = NULL;

uint32_t gkpcr;
uint32_t GuestOS_index = 11;
uintptr_t block_handle = 0;
uint32_t system_cr3 = 0;
uint32_t file_sz;
uint32_t MAX = 500;
/* Timer to check for proc exits */
static QEMUTimer *recon_timer = NULL;
#endif

static inline int is_page_resolved(process *proc, uint32_t page_num)
{
	return (proc->resolved_pages.find(page_num>>12) != proc->resolved_pages.end());
}


static void message_p(process* proc, int operation) {
	char proc_mod_msg[512] = { '\0' };
	if (operation) {
		//monitor_printf(default_mon,"P + %d %d %08x %s\n", proc->pid, proc->parent_pid, proc->cr3, proc->name);
		snprintf(proc_mod_msg, sizeof(proc_mod_msg), "P + %d %d %08x %s\n",
				proc->pid, proc->parent_pid, proc->cr3, proc->name);
	} else {
		//monitor_printf(default_mon,"P - %d %d %08x %s\n", proc->pid, proc->parent_pid, proc->cr3, proc->name);
		snprintf(proc_mod_msg, sizeof(proc_mod_msg), "P - %d %d %08x %s\n",
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
	if (operation) {
		//monitor_printf(default_mon,"P + %d %d %08x %s\n", proc->pid, proc->parent_pid, proc->cr3, proc->name);
		sprintf(proc_mod_msg, "P + %d %d %08x %s\n", proc->pid,
				proc->parent_pid, proc->cr3, proc->name);
	} else {
		//monitor_printf(default_mon,"P - %d %d %08x %s\n", proc->pid, proc->parent_pid, proc->cr3, proc->name);
		sprintf(proc_mod_msg, "P - %d %d %08x %s\n", proc->pid,
				proc->parent_pid, proc->cr3, proc->name);
	}
	handle_guest_message(proc_mod_msg);
}



static void Linux_tlb_call_back(DECAF_Callback_Params *temp)
{
#if 0
	CPUState *env = temp->tx.env;
	target_ulong vaddr = temp->tx.vaddr;
	//struct cr3_info* cr3i = NULL;
	int newflag = 0;

	//target_ulong modules;
	uint32_t exit_page = 0;
	uint32_t cr3 = env->cr[3];

	process *proc = findProcessByCR3(cr3);
	if (proc == NULL) {
		//We see a new cr3
		//If this execution is in user land, then this is a new process.
		//Otherwise, it is just within the kernel execution, so we don't care.
		if (!DECAF_is_in_kernel()) {
			newflag = 1;

			//If we haven't found system process, do it now.
			if (system_proc == NULL) {
				system_proc = find_new_process(env, cr3);
				if(system_proc == NULL || strcasecmp(system_proc->name, "System")) {
					monitor_printf(default_mon,
							"System proc not found!!!\n");
					abort();
				}

				//update_kernel_modules(env, vaddr);

				proc = system_proc;
			} else {
				proc = find_new_process(env, cr3);
			}
		}
	}

	//getting_new_mods++;
	//monitor_printf(default_mon,"%d\n", getting_new_mods++);
	if (proc)
		get_new_modules(env, proc, vaddr);
#endif
}


void Linux_vmi_init()
{
	DECAF_register_callback(DECAF_TLB_EXEC_CB, Linux_tlb_call_back, NULL);

#if 0
	recon_timer = qemu_new_timer_ns(vm_clock, check_procexit, 0);
	qemu_mod_timer(recon_timer,
			qemu_get_clock_ns(vm_clock) + get_ticks_per_sec() * 30);
#endif

}
#endif /* CONFIG_VMI_ENABLE*/

