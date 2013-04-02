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
#include "qemu-common.h"
#include "hw/hw.h"
#include "DECAF_main.h"
#include "DECAF_target.h"
#include "hookapi.h"
#include "read_linux.h"
#include "shared/function_map.h"
#include "shared/procmod.h"
#include "shared/DECAF_main.h"
#include "shared/utils/SimpleCallback.h"


#include <string>
#include <list>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <tr1/unordered_map>
#include <stdlib.h>


static SimpleCallback_t procmod_callbacks[PROCMOD_LAST_CB];

DECAF_Handle procmod_register_callback(
                procmod_callback_type_t cb_type,
                procmod_callback_func_t cb_func,
                int *cb_cond
                )
{
  if ((cb_type > PROCMOD_LAST_CB) || (cb_type < 0))
  {
    return (DECAF_NULL_HANDLE);
  }

  return (SimpleCallback_register(&procmod_callbacks[cb_type], (SimpleCallback_func_t)cb_func, cb_cond));
}

int procmod_unregister_callback(procmod_callback_type_t cb_type, DECAF_Handle handle)
{
  if ((cb_type > PROCMOD_LAST_CB) || (cb_type < 0))
  {
    return (DECAF_NULL_HANDLE);
  }

  return (SimpleCallback_unregister(&procmod_callbacks[cb_type], handle));
}

using namespace std;
using namespace std::tr1;

typedef struct {
    string name;
    uint32_t base;
    uint32_t size;
} module_info_t;

typedef struct {
    uint32_t cr3;
    uint32_t pid;
    uint32_t parent_pid;
    string name;
    list < module_info_t * >module_list;	//we make sure the list is sorted
} process_info_t;

//map cr3 to process_info_t
static unordered_map < uint32_t, process_info_t * >process_map;
//map pid to process_info_t
static unordered_map < uint32_t, process_info_t * >process_pid_map;

void handle_guest_message(const char *message)
{
        switch (message[0]) {
        case 'P':
                parse_process(message);
                break;
        case 'M':
                parse_module(message);
                break;
        case 'F':
                parse_function(message);
                break;
        }
}

// MIN: process tracking...
loadmainmodule_notify_t loadmainmodule_notify = NULL;

int insert_module_info(list < module_info_t * >&module_list,
		       const char *name, uint32_t base, uint32_t size)
{
    module_info_t *mod = new module_info_t();
    module_info_t *mod2;
    if (mod == NULL)
	return -1;

    mod->name = name;
    mod->base = base;
    mod->size = size;

    list < module_info_t * >::iterator iter;
    for (iter = module_list.begin(); iter != module_list.end(); iter++) {
	mod2 = *iter;
	if (mod2->base > base)
	    break;

	if (mod2->base + mod2->size > base) {
	    //there is overlapped region
	    iter = module_list.erase(iter);
	    iter--;
	    delete mod2;
	}
    }
    module_list.insert(iter, mod);
    return 0;
}

//Aravind - added to get the number of loaded modules for the process. This is needed to create the memory required by get_proc_modules
int get_loaded_modules_count(uint32_t pid)
{

    unordered_map < uint32_t, process_info_t * >::iterator iter =
	process_pid_map.find(pid);
    if (iter == process_pid_map.end())	//pid not found
    	return 0;

    list < module_info_t * >::iterator iter2;
    process_info_t *proc = iter->second;
    int counter = 0;
    for (iter2 = proc->module_list.begin();
	 iter2 != proc->module_list.end(); iter2++) {
    	counter++;
    }
	return counter;
}
//end - Aravind

int remove_module_info(list < module_info_t * >&module_list, uint32_t base)
{
    module_info_t *mod;
    list < module_info_t * >::iterator iter;
    for (iter = module_list.begin(); iter != module_list.end(); iter++) {
	mod = *iter;
	if (mod->base == base) {
	    module_list.erase(iter);
	    delete mod;
	    break;
	}
    }
    return 0;
}

int procmod_insert_modinfo(uint32_t pid, uint32_t cr3, const char *name,
			   uint32_t base, uint32_t size)
{
  procmod_Callback_Params params;
  unordered_map < uint32_t, process_info_t * >::iterator iter =
      process_pid_map.find(pid);
  process_info_t *proc;

  if (iter == process_pid_map.end())	//pid not found
      return -1;

  proc = iter->second;
  if (proc->name.length() == 0) {
      //first loaded module is the main executable
      proc->cr3 = cr3;
      proc->name = name;
      process_map[cr3] = proc;

      params.lmm.pid = pid;
      params.lmm.cr3 = cr3;
      params.lmm.name = name;

      SimpleCallback_dispatch(&procmod_callbacks[PROCMOD_LOADMAINMODULE_CB], &params);

      // MIN: process tracking...
      // the main moduled is being loaded.
//      if (loadmainmodule_notify != NULL)
//          loadmainmodule_notify(pid, (char *) name);
  }

  insert_module_info(proc->module_list, name, base, size);
  return 0;
}

int procmod_remove_modinfo(uint32_t pid, uint32_t base)
{
    unordered_map < uint32_t, process_info_t * >::iterator iter =
	process_pid_map.find(pid);
    process_info_t *proc;

    if (iter == process_map.end())	//pid not found
	return -1;

    proc = iter->second;
    remove_module_info(proc->module_list, base);
    return 0;
}


int procmod_createproc(uint32_t pid, uint32_t parent_pid,
		       uint32_t cr3, const char *name)
{
  procmod_Callback_Params params;

  unordered_map < uint32_t, process_info_t * >::iterator iter;
  process_info_t *proc = new process_info_t();
  if (proc == NULL)
      return -1;

  proc->pid = pid;
  proc->parent_pid = parent_pid;
  proc->cr3 = cr3;
  proc->name = name;

  process_pid_map[pid] = proc;
  if (cr3 != -1u)
      process_map[cr3] = proc;


  params.cp.pid = pid;
  params.cp.cr3 = cr3;

  SimpleCallback_dispatch(&procmod_callbacks[PROCMOD_CREATEPROC_CB], &params);

  //LOK: Replaced it with dispatch
  //if (createproc_notify)
//	createproc_notify(pid, cr3);

  return 0;
}

int procmod_removeproc(uint32_t pid)
{
  procmod_Callback_Params params;

  params.rp.pid = pid;

  SimpleCallback_dispatch(&procmod_callbacks[PROCMOD_REMOVEPROC_CB], &params);

  //  if (removeproc_notify)
//	removeproc_notify(pid);

    unordered_map < uint32_t, process_info_t * >::iterator iter =
	process_pid_map.find(pid);
    if (iter == process_pid_map.end())	//pid not found
	return -1;

    process_info_t *proc = iter->second;
    module_info_t *mod;

    while (!proc->module_list.empty()) {
	mod = proc->module_list.front();
	proc->module_list.pop_front();
	delete mod;
    }

    process_pid_map.erase(iter);
    process_map.erase(proc->cr3);
    delete proc;
    return 0;
}


static int procmod_remove_all()
{
    unordered_map < uint32_t, process_info_t * >::iterator iter;
    process_info_t *proc;
    module_info_t *mod;

    process_pid_map.clear();

    while (!process_map.empty()) {
	iter = process_map.begin();
	proc = iter->second;
	while (!proc->module_list.empty()) {
	    mod = proc->module_list.front();
	    proc->module_list.pop_front();
	    delete mod;
	}

	process_map.erase(iter);
	delete proc;
    }
    return 0;
}


void update_proc(void *opaque)
{
//    long taskaddr = 0xC033C300; 
    int pid;
    uint32_t cr3, pgd, mmap;
    uint32_t nextaddr = 0;

    char comm[512];

    procmod_remove_all();

    nextaddr = taskaddr;
    do {
	pid = get_pid(nextaddr);
	pgd = get_pgd(nextaddr);
	cr3 = pgd - 0xc0000000;	//subtract a page offset 
	get_name(nextaddr, comm, 512);
	procmod_createproc(pid, -1, cr3, comm);	//XXX: parent pid is not supported

	mmap = get_first_mmap(nextaddr);
	while (0 != mmap) {
	    get_mod_name(mmap, comm, 512);
	    //term_printf("0x%08lX -- 0x%08lX %s\n", get_vmstart(env, mmap),
	    //            get_vmend(env, mmap), comm); 
	    int base = get_vmstart(mmap);
	    int size = get_vmend(mmap) - get_vmstart(mmap);
	    procmod_insert_modinfo(pid, pgd, comm, base, size);

	    char message[612];
	    snprintf(message, sizeof(message), "M %d %x \"%s\" %x %d", pid,
		     pgd, comm, base, size);
	    handle_guest_message(message);

	    char funcfile[128];
	    snprintf(funcfile, 128, "/tmp/%s.func", comm);
	    FILE *fp = fopen(funcfile, "r");
	    if (fp) {
		while (!feof(fp)) {
		    int offset;
		    char fname[128];
		    if (fscanf(fp, "%x %128s", &offset, fname) == 2) {
			snprintf(message, 128, "F %s %s %x ", comm,
				 fname, offset);
			handle_guest_message(message);
		    }
		}
		fclose(fp);
	    }

	    mmap = get_next_mmap(mmap);
	}

	nextaddr = next_task_struct(nextaddr);

    } while (nextaddr != taskaddr);

}


void procmod_cleanup()
{
  //LOK: cleanup the callbacks
  int i = 0;
  for (i = 0; i < PROCMOD_LAST_CB; i++)
  {
    SimpleCallback_clear(&procmod_callbacks[i]);
  }

  procmod_remove_all();
  // AWH - deregister_savevm(), NULL first parm
  unregister_savevm(NULL, "procmod", 0);
}



static tmodinfo_t *find_module_byeip(uint32_t eip,
				     list < module_info_t * >&module_list)
{
    static tmodinfo_t mi;

    list < module_info_t * >::iterator iter;
    for (iter = module_list.begin(); iter != module_list.end(); iter++) {
	module_info_t *mod = *iter;
	if (mod->base <= eip && mod->size + mod->base > eip) {
	    strncpy(mi.name, mod->name.c_str(), sizeof(mi.name) - 1);
	    mi.base = mod->base;
	    mi.size = mod->size;
	    return &mi;
	}

	if (mod->base > eip)
	    break;
    }

    return NULL;
}


static tmodinfo_t *find_module_byname(const char *name,
				      list < module_info_t * >&module_list)
{
    static tmodinfo_t mi;

    list < module_info_t * >::iterator iter;
    for (iter = module_list.begin(); iter != module_list.end(); iter++) {
	module_info_t *mod = *iter;
	if (strcasecmp(mod->name.c_str(), name) == 0) {
	    strncpy(mi.name, mod->name.c_str(), sizeof(mi.name) - 1);
	    mi.base = mod->base;
	    mi.size = mod->size;
	    return &mi;
	}
    }

    return NULL;
}



tmodinfo_t *locate_module(uint32_t eip, uint32_t cr3, char *proc_name)
{
    //FIXME: here we hardcode the boundary of kernel memory space.
    //we need better solution.
    unordered_map < uint32_t, process_info_t * >::iterator iter =
	process_map.find(eip > 0x80000000 ? 0 : cr3);
    if (iter == process_map.end()) {
	strcpy(proc_name, "<UNKNOWN>");
	return NULL;
    }

    process_info_t *proc = iter->second;
    strcpy(proc_name, proc->name.c_str());
    return find_module_byeip(eip, proc->module_list);
}

tmodinfo_t *locate_module_byname(const char *name, uint32_t pid)
{
    unordered_map < uint32_t, process_info_t * >::iterator iter =
	process_pid_map.find(pid);
    if (iter == process_pid_map.end())	//pid not found
	return NULL;

    process_info_t *proc = iter->second;
    return find_module_byname(name, proc->module_list);
}

uint32_t find_pid(uint32_t cr3)
{
    unordered_map < uint32_t, process_info_t * >::iterator iter =
	process_map.find(cr3);
    if (iter == process_map.end())
	return -1;

    process_info_t *proc = iter->second;
    return proc->pid;
}

uint32_t find_pid_by_name(const char *proc_name)
{
    unordered_map < uint32_t, process_info_t * >::iterator iter;
    for (iter = process_map.begin(); iter != process_map.end(); iter++) {
	process_info_t *proc = iter->second;
	if (strcmp(proc_name, proc->name.c_str()) == 0) {
	    return proc->pid;
	}
    }
    return -1;
}



int find_process(uint32_t cr3, char proc_name[], size_t len, uint32_t * pid)
{
    process_info_t *proc;
    unordered_map < uint32_t, process_info_t * >::iterator iter =
	process_map.find(cr3);
    if (iter != process_map.end()) {
	proc = iter->second;
	strncpy(proc_name, proc->name.c_str(), len);
	*pid = proc->pid;
	return proc->module_list.size();
    }

    strncpy(proc_name, "<UNKNOWN>", len);
    *pid = -1;
    return 0;
}

int find_process_by_pid(uint32_t pid, char proc_name[], size_t len, uint32_t * cr3)
{
    process_info_t *proc;
    unordered_map < uint32_t, process_info_t * >::iterator iter =
	process_pid_map.find(pid);

    if (iter != process_pid_map.end()) {
	proc = iter->second;
	strncpy(proc_name, proc->name.c_str(), len);
	*cr3 = proc->cr3;
	return proc->module_list.size();
    }

    strncpy(proc_name, "<UNKNOWN>", len);
    *cr3 = -1;
    return 0;
}


procinfo_t *find_all_processes_info(size_t * num_proc)
{
    process_info_t *proc;
    unordered_map < uint32_t, process_info_t * >::iterator iter;
    unsigned int idx = 0;
    size_t nproc;

    nproc = process_map.size();

    procinfo_t *arr = (procinfo_t *) malloc(nproc * sizeof(procinfo_t));

    if (arr) {
	for (iter = process_map.begin(); iter != process_map.end(); iter++) {
	    proc = iter->second;
	    arr[idx].pid = proc->pid;
	    arr[idx].cr3 = proc->cr3;
	    arr[idx].n_mods = proc->module_list.size();
	    strncpy(arr[idx].name, proc->name.c_str(), 511);
	    arr[idx].name[511] = '\0';
	    idx++;
	}
	*num_proc = nproc;
    } else {
	*num_proc = 0;
    }

    return arr;
}



void list_procs(Monitor *mon) // AWH void)
{
    process_info_t *proc;
    unordered_map < uint32_t, process_info_t * >::iterator iter;

    for (iter = process_map.begin(); iter != process_map.end(); iter++) {
	proc = iter->second;
	// AWH
	monitor_printf(mon, "%d\tcr3=0x%08x\t%s\n", proc->pid, proc->cr3,
		    proc->name.c_str());
    }
}


void linux_ps(Monitor *mon, int mmap_flag)
{
    int pid;
    uint32_t pgd, mmap;
    uint32_t nextaddr = 0;

    char comm[512];
monitor_printf(mon, "void linux_ps(%d) called\n", mmap_flag); // AWH
    if (0 == taskaddr) {
	if (init_kernel_offsets() == -1) {
	    monitor_printf
		(mon, "No supported linux kernel has been identified!\n");
	    return;
	}
	hookapi_hook_function(1, hookingpoint, 0, update_proc, NULL, 0);
    }
monitor_printf(mon, "linux_ps() -> After kernel check\n"); // AWH
    update_proc(0);
monitor_printf(mon, "linux_ps() -> After update_proc(0)\n"); // AWH
    nextaddr = taskaddr;
    do {
	pid = get_pid(nextaddr);
	pgd = get_pgd(nextaddr);
	get_name(nextaddr, comm, 512);

	monitor_printf(mon, "%10d  CR3=0x%08X  %s\n", pid, pgd - 0xC0000000,
		    comm);
	if (mmap_flag) {
	    mmap = get_first_mmap(nextaddr);
	    while (0 != mmap) {
		get_mod_name(mmap, comm, 512);
		monitor_printf(mon, "              0x%08X -- 0x%08X %s\n",
			    get_vmstart(mmap), get_vmend(mmap), comm);
		mmap = get_next_mmap(mmap);
	    }
	}
	nextaddr = next_task_struct(nextaddr);

    } while (nextaddr != taskaddr);
}


uint32_t find_cr3(uint32_t pid)
{
    unordered_map < uint32_t, process_info_t * >::iterator iter =
	process_pid_map.find(pid);
    return (iter == process_pid_map.end())? 0 : iter->second->cr3;
}


void get_proc_modules(uint32_t pid, old_modinfo_t mi_array[], int size)
{
    module_info_t *mod;
    unordered_map < uint32_t, process_info_t * >::iterator iter =
	process_pid_map.find(pid);
    if (iter == process_pid_map.end())	//pid not found
	return;

    list < module_info_t * >::iterator iter2;
    process_info_t *proc = iter->second;
    int counter = 0;
    for (iter2 = proc->module_list.begin();
	 iter2 != proc->module_list.end(); iter2++, counter++) {
	mod = *iter2;
	strncpy(mi_array[counter].name, mod->name.c_str(),
		sizeof(mi_array[0].name) - 1);
	mi_array[counter].base = mod->base;
	mi_array[counter].size = mod->size;
    }
}


void list_guest_modules(Monitor *mon, uint32_t pid)
{
    unordered_map < uint32_t, process_info_t * >::iterator iter =
	process_pid_map.find(pid);
    if (iter == process_pid_map.end())
	return;

    process_info_t *proc = iter->second;
    module_info_t *mod;
    list < module_info_t * >::iterator iter2;
    for (iter2 = proc->module_list.begin();
	 iter2 != proc->module_list.end(); iter2++) {
	mod = *iter2;
	monitor_printf(mon, "%20s\t0x%08x\t0x%08x\n", mod->name.c_str(), mod->base,
		    mod->size);
    }
}

#if 0
/* return 1 if the process needs to be dumped */
int checkcr3(uint32_t cr3, uint32_t eip, uint32_t tracepid, char *name,
	     int len, uint32_t * offset)
{
    process_info_t *proc;
    list < process_info_t * >::iterator iter;
    module_info_t *mod;
    list < module_info_t * >::iterator iter2;

    for (iter = process_list.begin(); iter != process_list.end(); iter++) {
	proc = *iter;
	if (proc->cr3 == cr3 && proc->pid == (uint32_t) tracepid) {
	    for (iter2 = proc->module_list.begin();
		 iter2 != proc->module_list.end(); iter2++) {
		mod = *iter2;
		if (mod->base <= eip && mod->size + mod->base > eip) {
		    strncpy(name, mod->name.c_str(), len);
		    *offset = eip - mod->base;
		    return 1;
		}
	    }
	}
    }

    //not found
    strcpy(name, "");
    *offset = 0;
    return 0;
}
#endif


uint32_t get_current_tid(CPUState* env)
{
    uint32_t val;
    uint32_t tid;

    //This may only work with Windows XP

    if (!is_guest_windows())
	return -1;

    if (!DECAF_is_in_kernel()) {	// user module
	if (DECAF_read_mem(env, DECAF_cpu_segs[R_FS].base + 0x18, 4, &val) != -1
	    && DECAF_read_mem(env, val + 0x24, 4, &tid) != -1)
	    return tid;
    } else if (DECAF_read_mem(env, DECAF_cpu_segs[R_FS].base + 0x124, 4, &val) !=
	       -1 && DECAF_read_mem(env, val + 0x1F0, 4, &tid) != -1)
	return tid;

    return -1;
}



static void procmod_save(QEMUFile * f, void *opaque)
{
    uint32_t len;
    process_info_t *proc;
    module_info_t *mod;
    unordered_map < uint32_t, process_info_t * >::iterator iter;
    list < module_info_t * >::iterator iter2;

    //save process information
    qemu_put_be32(f, process_map.size());
    for (iter = process_map.begin(); iter != process_map.end(); iter++) {
	proc = iter->second;
	qemu_put_be32(f, proc->pid);
	qemu_put_be32(f, proc->parent_pid);
	qemu_put_be32(f, proc->cr3);
	len = proc->name.length() + 1;
	qemu_put_be32(f, len);
	qemu_put_buffer(f, (uint8_t *) proc->name.c_str(), len);

	//save module information
	qemu_put_be32(f, proc->module_list.size());
	for (iter2 = proc->module_list.begin();
	     iter2 != proc->module_list.end(); iter2++) {
	    mod = *iter2;
	    len = mod->name.length() + 1;
	    qemu_put_be32(f, len);
	    qemu_put_buffer(f, (uint8_t *) mod->name.c_str(), len);
	    qemu_put_be32(f, mod->base);
	    qemu_put_be32(f, mod->size);
	}
    }

    qemu_put_be32(f, -1);	//terminator
}


static int procmod_load(QEMUFile * f, void *opaque, int version_id)
{
    uint32_t i, j, nproc, nmod, len;
    uint32_t base, size;
    char name[GUEST_MESSAGE_LEN];
    process_info_t *proc;

    //load process and module information
    procmod_remove_all();

    nproc = qemu_get_be32(f);
    for (i = 0; i < nproc; i++) {
	proc = new process_info_t();
	if (proc == NULL)
	    return -1;

	uint32_t pid = qemu_get_be32(f);
	uint32_t parent_pid = qemu_get_be32(f);
	uint32_t cr3 = qemu_get_be32(f);
	len = qemu_get_be32(f);
	assert(len <= GUEST_MESSAGE_LEN);
	qemu_get_buffer(f, (uint8_t *) name, len);
	if (name[len - 1] != 0)
	    return -EINVAL;	//last character must be zero
	procmod_createproc(pid, parent_pid, cr3, name);

	nmod = qemu_get_be32(f);
	for (j = 0; j < nmod; j++) {
	    len = qemu_get_be32(f);
	    assert(len <= GUEST_MESSAGE_LEN);
	    qemu_get_buffer(f, (uint8_t *) name, len);
	    if (name[len - 1] != 0)
		return -EINVAL;
	    base = qemu_get_be32(f);
	    size = qemu_get_be32(f);
	    procmod_insert_modinfo(pid, cr3, name, base, size);
	}
    }


    uint32_t terminator = qemu_get_be32(f);
    if (terminator != -1u)
	return -EINVAL;

    return 0;
}


int procmod_init()
{
  //LOK: Initialize the callback list
  int i = 0;
  for (i = 0; i < PROCMOD_LAST_CB; i++)
  {
    SimpleCallback_init(&procmod_callbacks[i]);
  }

	procmod_createproc(0, -1, 0, "<kernel>");	//create a virtual process for the kernel

	FILE *guestlog = fopen("guest.log", "r");
	char syslogline[GUEST_MESSAGE_LEN];
	int pos = 0;
	if (guestlog) {
		int ch;
		while ((ch = fgetc(guestlog)) != EOF) {
			syslogline[pos++] = (char) ch;
			if (pos > GUEST_MESSAGE_LEN - 2)
				pos = GUEST_MESSAGE_LEN - 2;
			if (ch == 0xa) {
				syslogline[pos] = 0;
				handle_guest_message(syslogline);
				pos = 0;
			}
		}
		fclose(guestlog);
	}

    //TODO: save and load thread information

    if (init_kernel_offsets() >= 0)
    	hookapi_hook_function(1, hookingpoint, 0, update_proc, NULL, 0);

    // AWH - Added NULL parm for DeviceState* (change in API)
    register_savevm(NULL, "procmod", 0, 1, procmod_save, procmod_load, NULL);
    return 0;
}

#define BOUNDED_STR(len) "%" #len "s"
#define BOUNDED_QUOTED(len) "%" #len "[^\"]"
#define BOUNDED_STR_x(len) BOUNDED_STR(len)
#define BOUNDED_QUOTED_x(len) BOUNDED_QUOTED(len)
#define BSTR BOUNDED_STR_x(GUEST_MESSAGE_LEN_MINUS_ONE)
#define BQUOT BOUNDED_QUOTED_x(GUEST_MESSAGE_LEN_MINUS_ONE)

void parse_process(const char *log)
{
	char c;
	uint32_t pid;
	uint32_t parent_pid = -1;

	if (sscanf(log, "P %c %d %d", &c, &pid, &parent_pid) < 2) {
		return;
	}
	switch (c) {
	case '-':
		procmod_removeproc(pid);
		break;
	case '+':
		procmod_createproc(pid, parent_pid, -1, "");
		break;
	}
}


void parse_module(const char *log)
{
  procmod_Callback_Params params;
  uint32_t pid, cr3, base, size;
  char mod[GUEST_MESSAGE_LEN];
  char full_mod[GUEST_MESSAGE_LEN]="";
  char c = '+';
  //We try to parse a long name with quotations first. If failed, we parse in the old way,
  //for backward compatibility. -Heng

  if (sscanf(log, "M %d %x \"" BQUOT "\" %x %x \"" BQUOT "\" %c", &pid, &cr3, mod, &base,
                                  &size, full_mod, &c) < 5 &&
      sscanf(log, "M %d %x \"" BSTR "\" %x %x \"" BQUOT "\" %c", &pid, &cr3, mod, &base,
                   &size, full_mod, &c) <5 )
    //no valid format is found
    return;

  switch (c) {
  case '-':
          procmod_remove_modinfo(pid, base);
          break;
  case '+':
          procmod_insert_modinfo(pid, cr3, mod, base, size);
          break;
  }

  //This is time to resolved the hooks that are registered by name.
  check_unresolved_hooks();

  params.lm.pid = pid;
  params.lm.cr3 = cr3;
  params.lm.name = mod;
  params.lm.base = base;
  params.lm.size = size;
  params.lm.full_name = full_mod;

  SimpleCallback_dispatch(&procmod_callbacks[PROCMOD_LOADMODULE_CB], &params);
}


int is_guest_windows()
{
    //FIXME: we use a very simple hack here. Windows uses FS segment register to store 
    // the current process context, while Linux does not. We may need better heuristics 
    // when we need to support more guest systems.
    return (DECAF_cpu_segs[R_FS].selector != 0);
}


