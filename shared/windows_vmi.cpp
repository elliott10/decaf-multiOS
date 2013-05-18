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
 * windows_vmi.c
 *
 *  Created on: Jun 8, 2012
 *      Author: haoru zhao
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
//#include "sysemu.h"

#ifdef __cplusplus
}
;
#endif /* __cplusplus */

#include "windows_vmi.h"
#include "hookapi.h"
#include "read_linux.h"
#include "function_map.h"
#include "shared/procmod.h"
#include "shared/vmi.h"
#include "DECAF_main.h"
#include "shared/utils/SimpleCallback.h"

#ifdef CONFIG_VMI_ENABLE

uint32_t present_in_vtable = 0;
uint32_t adding_to_vtable = 0;
uint32_t getting_new_mods = 0;
off_set xp_offset = { 0x18, 0x20, 0x2c, 0x88, 0x84, 0x174, 0x14c, 0x1a0, 0xc4,
		0x3c, 0x190, 0x1ec, 0x22c, 0x134, 0x78 };
off_set w7_offset = { 0x18, 0x20, 0x24, 0xb8, 0xb4, 0x16c, 0x140, 0x198, 0xf4,
		0x30, 0x188, 0x22c, 0x268, 0x128, 0xa8 };

static os_handle handle_funds[] = {
		{ WINXP_SP2, &xp_offset, 0, NULL, 0, 0, 0, },
		{ WINXP_SP3, &xp_offset, 0, NULL, 0, 0, 0, },
		{ WIN7_SP0, &w7_offset, 0, NULL, 0, 0, 0, },
		{ WIN7_SP1, &w7_offset, 0, NULL, 0, 0, 0, }, };

GHashTable *cr3_hashtable = NULL;
GHashTable *eproc_ht = NULL;
process *system_proc = NULL;
process *new_proc = NULL;
int rtflag = 0;
uint32_t gkpcr;
uint32_t GuestOS_index = 11;
uintptr_t block_handle = 0;
uint32_t system_cr3 = 0;
BYTE *recon_file_data_raw = 0;
uint32_t file_sz;
uint32_t MAX = 500;
unsigned long long insn_counter = 0;
/* Timer to check for proc exits */
static QEMUTimer *recon_timer = NULL;

static inline int is_page_resolved(process *proc, uint32_t page_num)
{
	return (proc->resolved_pages.find(page_num>>12) != proc->resolved_pages.end());
}


void message_p(process* proc, int operation) {
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

void message_m(uint32_t pid, uint32_t cr3, uint32_t base, module *pe) {
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

void message_p_d(dprocess* proc, int operation) {
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

static process * find_new_process(CPUState *env, uint32_t cr3) {
	uint32_t kdvb, psAPH, curr_proc, next_proc;
	process *pe;
	int found_new = 0;

	if (gkpcr == 0)
		return 0;

	DECAF_read_mem(env, gkpcr + KDVB_OFFSET, 4, &kdvb);
	DECAF_read_mem(env, kdvb + PSAPH_OFFSET, 4, &psAPH);
	DECAF_read_mem(env, psAPH, 4, &curr_proc);

	while (curr_proc != 0 && curr_proc != psAPH) {
		uint32_t pid, proc_cr3;
		uint32_t curr_proc_base = curr_proc
				- handle_funds[GuestOS_index].offset->PSAPL_OFFSET;

		DECAF_read_mem(env,
				curr_proc_base
						+ handle_funds[GuestOS_index].offset->PSAPID_OFFSET, 4,
				&pid);
		if (findProcessByPidH(pid) != 0) //we have seen this process
			goto next;

		DECAF_read_mem(env, curr_proc_base + 0x18, 4, &proc_cr3);
		if(cr3 != proc_cr3) //This is a new process, but not the current one. Skip it!
			goto next;

		//This is the one we are looking for
		pe = new process();
		pe->EPROC_base_addr = curr_proc_base;
		pe->pid = pid;
		pe->cr3 = proc_cr3;
		DECAF_read_mem(env, curr_proc_base + handle_funds[GuestOS_index].offset->PSAPNAME_OFFSET,
					NAMESIZE, pe->name);
		DECAF_read_mem(env,
					curr_proc_base
							+ handle_funds[GuestOS_index].offset->PSAPPID_OFFSET,
					4, &pe->parent_pid);
		addProcV(pe);
		message_p(pe, 1);
		return pe;

next:
		DECAF_read_mem(env, curr_proc, 4, &next_proc);
		if (curr_proc == next_proc) { //why do we need this check?
			break;
		}
		curr_proc = next_proc;
	}

	return NULL;

}

/*
static process *get_system_process(CPUState *env) {
	process *pe = NULL;
	//handle_funds[GuestOS_index].update_processlist();
	find_new_process(env, env->cr[3]);
	pe = findProcessByNameH("System");
	return pe;
}

static process* get_new_process() {
	//process *pe = NULL;
	int ret = handle_funds[GuestOS_index].update_processlist();
	if (ret == 1) {
		//monitor_printf(default_mon, "%d\tnew process...\n", GuestOS_index);
		return new_proc;
	} else
		return NULL;
}*/


//FIXME: this function may potentially overflow "buf" --Heng
static inline int readustr_with_cr3(uint32_t addr, uint32_t cr3, void *buf,
		CPUState *env) {
	uint32_t unicode_data[2];
	int i, j, unicode_len = 0;
	uint8_t unicode_str[MAX_UNICODE_LENGTH] = { '\0' };
	char *store = (char *) buf;

	if (cr3 != 0) {
		if (DECAF_memory_rw_with_cr3(env, cr3, addr, (void *) &unicode_data,
				sizeof(unicode_data), 0) < 0) {
			store[0] = '\0';
			goto done;
		}
	} else {
		if (DECAF_read_mem(env, addr, sizeof(unicode_data), unicode_data) < 0) {
			store[0] = '\0';
			goto done;
		}
	}

	unicode_len = (int) (unicode_data[0] & 0xFFFF);
	if (unicode_len > MAX_UNICODE_LENGTH)
		unicode_len = MAX_UNICODE_LENGTH;

	if (cr3 != 0) {
		if (DECAF_memory_rw_with_cr3(env, cr3, unicode_data[1],
				(void *) unicode_str, unicode_len, 0) < 0) {
			store[0] = '\0';
			goto done;
		}
	} else {
		if (DECAF_memory_rw(env, unicode_data[1], (void *) unicode_str,
				unicode_len, 0) < 0) {
			store[0] = '\0';
			goto done;
		}
	}

	for (i = 0, j = 0; i < unicode_len; i += 2, j++) {
		if (unicode_str[i] < 0x20 || unicode_str[i] > 0x7e) //Non_printable character
			break;

		store[j] = unicode_str[i];
	}
	store[j] = '\0';

done:
	return strlen(store);
}

static void update_kernel_modules(CPUState *env, target_ulong vaddr) {
	uint32_t kdvb, psLM, curr_mod, next_mod;
	uint32_t holder;
	module *curr_entry = NULL;

	if (gkpcr == 0)
		return;

	//If this page has been resolved, return immediately
	if (is_page_resolved(system_proc, vaddr))
		return;

	DECAF_read_mem(env, gkpcr + KDVB_OFFSET, 4, &kdvb);
	DECAF_read_mem(env, kdvb + PSLM_OFFSET, 4, &psLM);
	DECAF_read_mem(env, psLM, 4, &curr_mod);

	while (curr_mod != 0 && curr_mod != psLM) {
		uint32_t base = 0;
		DECAF_read_mem(env,
				curr_mod + handle_funds[GuestOS_index].offset->DLLBASE_OFFSET,
				4, &base); // dllbase  DLLBASE_OFFSET

		if (!is_page_resolved(system_proc, base)) {
			curr_entry = new module();
			DECAF_read_mem(env,
					curr_mod + handle_funds[GuestOS_index].offset->SIZE_OFFSET,
					4, &curr_entry->size); // dllsize  SIZE_OFFSET
			holder =
					readustr_with_cr3(
							curr_mod
									+ handle_funds[GuestOS_index].offset->DLLNAME_OFFSET,
							0, (curr_entry->name), env);
			readustr_with_cr3(curr_mod + 0x24, 0, curr_entry->fullname, env);
			procmod_insert_modinfoV(system_proc->pid, base, curr_entry);
			message_m(system_proc->pid, system_proc->cr3, base, curr_entry);

			if (!findModule(curr_entry->fullname))
				//found a new module, add it to our hash table
				addModule(curr_entry);
			else
				delete curr_entry;

		}

		DECAF_read_mem(env, curr_mod, 4, &next_mod);
		DECAF_read_mem(env, next_mod + 4, 4, &holder);
		if (holder != curr_mod) {
			monitor_printf(default_mon,
					"Something is wrong. Next->prev != curr. curr_mod = 0x%08x\n",
					curr_mod);
			break;
		}
		curr_mod = next_mod;
	}
}

static void update_loaded_user_mods_with_peb(CPUState* env, process *proc,
		uint32_t peb, target_ulong vaddr) {

	uint32_t cr3 = proc->cr3;
	uint32_t ldr, memlist, first_dll, curr_dll;
	module *curr_entry = NULL;

	int ret = 0;

	if (peb == 0x00)
		return;

	if (is_page_resolved(proc, vaddr))
		return;

	DECAF_memory_rw_with_cr3(env, cr3, peb + 0xc, (void *) &ldr, 4, 0);
	memlist = ldr + 0xc;
	DECAF_memory_rw_with_cr3(env, cr3, memlist, (void *) &first_dll, 4, 0);

	if (first_dll == 0)
		return;

	curr_dll = first_dll;
	int count;
	do {
		count++;
		uint32_t base = 0;
		if (DECAF_memory_rw_with_cr3(env, cr3, curr_dll + 0x18, &base, 4, 0)
				< 0)
			break;

		//FIXME: why do we check base > 0x00300000?
		if (base > 0x00300000 && !is_page_resolved(proc, base)) {
			curr_entry = new module();
			DECAF_memory_rw_with_cr3(env, cr3, curr_dll + 0x20,
					&curr_entry->size, 4, 0);
			readustr_with_cr3(curr_dll + 0x24, cr3, curr_entry->fullname, env);
			readustr_with_cr3(curr_dll + 0x2c, cr3, curr_entry->name, env);
			procmod_insert_modinfoV(proc->pid, base, curr_entry);
			message_m(proc->pid, cr3, base, curr_entry);
			if (!findModule(curr_entry->fullname))
				addModule(curr_entry);
			else
				delete curr_entry;

		}

		DECAF_memory_rw_with_cr3(env, cr3, curr_dll, (void *) &curr_dll, 4, 0);
	} while (curr_dll != 0 && curr_dll != first_dll && count < MAX);
}


static void get_new_modules(CPUState* env, process * proc, target_ulong vaddr) {

	uint32_t cr3 = proc->cr3;

	uint32_t base = 0, self = 0, pid = 0;
	if (proc == system_proc) {
		update_kernel_modules(env, vaddr);
	} else {
		base = env->segs[R_FS].base;
		DECAF_read_mem(env, base + 0x18, 4, &self);

		if (base != 0 && base == self) {
			//Why don't you use the offset table instead of these hard-coded offsets?
			uint32_t pid_addr = base + 0x20;
			DECAF_read_mem(env, pid_addr, 4, &pid);
			uint32_t peb_addr = base + 0x30;
			uint32_t peb;
			DECAF_read_mem(env, peb_addr, 4, &peb);
			update_loaded_user_mods_with_peb(env, proc, peb, vaddr);
		}
	}
}

void tlb_call_back(DECAF_Callback_Params *temp) {
	CPUState *env = temp->tx.env;
	target_ulong vaddr = temp->tx.vaddr;
	//struct cr3_info* cr3i = NULL;
	int newflag = 0;

	//target_ulong modules;
	uint32_t exit_page = 0;
	uint32_t cr3 = env->cr[3];

	//Heng: The control flow in this function was terrible. not clear what would happen in different cases.
	//goto statement makes it even worse. No comments for each case, making it hard to understand and maintain
	//the code in the future.

	//Heng: vim.cpp has defined hash table for cr3. why not just use it?
	//In particular, findcr3, insertcr3, addcr3info, etc.
	//By design, we put os-independent stuff in vmi.cpp. Windows_vmi.cpp only implements windows-specific stuff.
	//cr3i = (cr3_info *) g_hash_table_lookup(cr3_hashtable, (gpointer) cr3);	//to check for a new cr3
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
}

uint32_t get_kpcr() {
	uint32_t kpcr, selfpcr;
	CPUState *env;

	for (env = first_cpu; env != NULL; env = env->next_cpu) {
		if (env->cpu_index == 0) {
			break;
		}
	}

	kpcr = 0;
	cpu_memory_rw_debug(env, env->segs[R_FS].base + 0x1c, (uint8_t *) &selfpcr,
			4, 0);

	if (selfpcr == env->segs[R_FS].base) {
		kpcr = selfpcr;
	}
	return kpcr;
}

static void get_os_version(CPUState *env) {
	//uint32_t kdvb, CmNtCSDVersion, num_package;

	if (gkpcr == 0xffdff000) {
		//cpu_memory_rw_debug(env, gkpcr + 0x34, (uint8_t *) &kdvb, 4, 0);
		//cpu_memory_rw_debug(env, kdvb + 0x290, (uint8_t *) &CmNtCSDVersion, 4, 0); //CmNt version info
		//cpu_memory_rw_debug(env, CmNtCSDVersion, (uint8_t *) &num_package, 4, 0);
		//uint32_t num = num_package >> 8;
		//if (num == 0x02) {
		GuestOS_index = 0; //winxpsp2
		//} else if (num == 0x03) {
		//	GuestOS_index = 1; //winxpsp3
		//}
	} else {
		GuestOS_index = 2; //win7
	}

}


static uint32_t get_ntoskrnl_internal(uint32_t curr_page, CPUState *env) {
	IMAGE_DOS_HEADER *DosHeader = NULL;

	uint8_t page_data[4 * 1024] = { 0 }; //page_size
	uint16_t DOS_HDR = 0x5a4d;

	for (; curr_page > 0x80000000; curr_page -= 4096) {
		if (DECAF_read_mem(env, curr_page, 4096, page_data) < 0)
			//this page is not present in ram, just continue
			continue;

		if (memcmp(&page_data, &DOS_HDR, 2) != 0)
			continue;

		DosHeader = (IMAGE_DOS_HEADER *) &(page_data);
		if ((DosHeader->e_magic == 0x5a4d)
				&&
				 (*((uint32_t *) (&page_data[*((uint32_t *) &page_data[0x3c])]))
										== IMAGE_NT_SIGNATURE))
			return curr_page;
	}

	return 0;
}

uint32_t get_ntoskrnl(CPUState *env) {
	uint32_t ntoskrnl_base = 0;
	ntoskrnl_base = get_ntoskrnl_internal(env->sysenter_eip & 0xfffff000, env);
	if (ntoskrnl_base)
		goto found;

	ntoskrnl_base = get_ntoskrnl_internal(env->eip & 0xfffff000, env);
	if (ntoskrnl_base)
		goto found;
	return 0;

found:
	system_cr3 = env->cr[3];
	return ntoskrnl_base;
}

static void probe_windows(CPUState *env) {

	//struct cr3_info *cr3i = NULL;
	//uint32_t cr3 = env->cr[3];
	uint32_t base;
	insn_counter++;

	if (env->eip > 0x80000000 && env->segs[R_FS].base > 0x80000000) {
		gkpcr = get_kpcr();
		if (gkpcr != 0) {
			//DECAF_unregister_callback(DECAF_INSN_END_CB, insn_handle);
			rtflag = 1;
			cr3_hashtable = g_hash_table_new(0, 0);
			eproc_ht = g_hash_table_new(0, 0);

			get_os_version(env);
			base = get_ntoskrnl(env);
			if (!base) {
				monitor_printf(default_mon,
						"Unable to locate kernel base. Stopping VM...\n");
				//vm_stop(RUN_STATE_DEBUG);
				return;
			}
		}
	}
}

int find_win7sp0(CPUState *env, uintptr_t insn_handle) {
	probe_windows(env);
	if (GuestOS_index == 2 && rtflag == 1)
		return 1;
	else
		return 0;
}
int find_win7sp1(CPUState *env, uintptr_t insn_handle) {
	probe_windows(env);
	if (GuestOS_index == 2 && rtflag == 1)
		return 1;
	else
		return 0;
}
int find_winxpsp2(CPUState *env, uintptr_t insn_handle) {

	probe_windows(env);
	if (GuestOS_index == 0 && rtflag == 1)
		return 1;
	else
		return 0;
}
int find_winxpsp3(CPUState *env, uintptr_t insn_handle) {
	probe_windows(env);
	if (GuestOS_index == 1 && rtflag == 1)
		return 1;
	else
		return 0;
}

uint32_t exit_block_end_eip = 0;
void check_procexit(void *) {
	CPUState *env = cpu_single_env ? cpu_single_env : first_cpu;
	qemu_mod_timer(recon_timer,
			qemu_get_clock_ns(vm_clock) + get_ticks_per_sec() * 30);
	//monitor_printf(default_mon, "Checking for proc exits...\n");

	struct process_entry *proc = NULL, *next = NULL;
	uint32_t end_time[2];
	size_t numofProc;
	dprocess *processes;
	int i = 0;
	processes = find_all_processes_infoV(&numofProc);
	if (processes != NULL) {
		for (i = 0; i < numofProc; i++) {
			dprocess *proc = &processes[i];
			if (proc->parent_pid == 0)
				continue;
			//0x78 for xp, 0x88 for win7
			cpu_memory_rw_debug(env,
					(proc->EPROC_base_addr)
							+ handle_funds[GuestOS_index].offset->PEXIT_TIME,
					(uint8_t *) &end_time[0], 8, 0);
			if (end_time[0] | end_time[1]) {

				removeProcV(proc->pid);
				message_p_d(proc, 0);
				exit_block_end_eip = env->eip;
				//return;
			}
		}
	}
	delete[] processes;
}

void win_vmi_init() {

	DECAF_register_callback(DECAF_TLB_EXEC_CB, tlb_call_back, NULL);
	recon_timer = qemu_new_timer_ns(vm_clock, check_procexit, 0);
	qemu_mod_timer(recon_timer,
			qemu_get_clock_ns(vm_clock) + get_ticks_per_sec() * 30);

}
#endif /* CONFIG_VMI_ENABLE*/

