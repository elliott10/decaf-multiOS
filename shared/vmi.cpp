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

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
#include "cpu.h"
#include "config.h"
#include "hw/hw.h" // AWH
#include "DECAF_main_x86.h"

#ifdef __cplusplus
};
#endif /* __cplusplus */
#include "windows_vmi.h"
#include "hookapi.h"
#include "read_linux.h"
#include "shared/vmi.h"
#include "shared/DECAF_main.h"
#include "shared/function_map.h"
#include "shared/utils/SimpleCallback.h"
#include "helper.h"

//#include"peheaders.h"
using namespace std;
using namespace std::tr1;

//map cr3 to process_info_t
static unordered_map < uint32_t, process * >process_map;
//map pid to process_info_t
static unordered_map < uint32_t, process * >process_pid_map;
static unordered_map < string, module * >module_name;
static queue<process*> processes;
static unordered_set <uint32_t> cr3s;
static unordered_map <uint32_t,cr3_info_c *> cr3infos;
//uint32_t gkpcr;
uint32_t GuestOS_index_c=11;
uintptr_t insn_handle_c = 0;
//uintptr_t insn_handle_c = 0;
//uintptr_t block_handle = 0;
//uint32_t system_cr3 = 0;
//uint32_t file_sz;
//BYTE *recon_file_data_raw = 0;
//unsigned long long insn_counter = 0;
 //process *system_proc = NULL;
//static QEMUTimer *recon_timer = NULL;

static os_handle_c handle_funds_c[] = { { WINXP_SP2_C, &find_winxpsp2, &init, },
		{ WINXP_SP3_C,

		&find_winxpsp3, &init,

		}, { WIN7_SP0_C, &find_win7sp0, &init,

		}, { WIN7_SP1_C, &find_win7sp1, &init,

		},

};
int addProcV(process *proc)
{
    if(proc==NULL)
    	return -1;
    unordered_map < uint32_t, process * >::iterator iter =
    	process_pid_map.find(proc->pid);
        if (iter != process_pid_map.end())
        {
        	delete proc;
        	return -1;
        }
    if(proc->pid!=-1UL)
    process_pid_map[proc->pid] = proc;
      if (proc->cr3 != -1UL)
          process_map[proc->cr3] = proc;

      return 0;

}

/*int insert_module_infoV(list < module * >&module_list,
		module *mod)
{

	    module *mod2;
	    if (mod == NULL)
		return -1;

	    list < module * >::iterator iter;
	    for (iter = module_list.begin(); (iter != module_list.end())&&(module_list.size()>0); iter++) {

		mod2 = *iter;
		if (mod2->base > mod->base)
		    break;

		if (mod2->base + mod2->size > mod->base) {
		    //there is overlapped region
		    iter = module_list.erase(iter);
		    iter--;
		    delete mod2;
		}
	    }
	    module_list.insert(iter, mod);
	    return 0;
}*/
/*int remove_module_infoV(list < module * >&module_list, uint32_t base)
{
    module *mod;
    list < module * >::iterator iter;
    for (iter = module_list.begin(); iter != module_list.end(); iter++) {
	mod = *iter;
	if (mod->base == base) {
	    module_list.erase(iter);
	    delete mod;
	    break;
	}
    }
    return 0;
}*/
//Aravind - added to get the number of loaded modules for the process. This is needed to create the memory required by get_proc_modules
int get_loaded_modules_countV(uint32_t pid)
{

    unordered_map < uint32_t, process * >::iterator iter =
	process_pid_map.find(pid);
    if (iter == process_pid_map.end())	//pid not found
    	return 0;

    unordered_map < uint32_t,module * >::iterator iter2;
    process *proc = iter->second;
    int counter = 0;
    for (iter2 = proc->module_list.begin();
	 iter2 != proc->module_list.end(); iter2++) {
    	counter++;
    }
	return counter;
}
//end - Aravind

static void extract_export_table_from(IMAGE_NT_HEADERS *nth, uint32_t cr3, uint32_t base, module *mod)
{
	DWORD edt_va, edt_raw_offset, *export_table, *ptr_to_table, func_raw_offset, name_raw_offset, *names, edt_size;
	DWORD *func_addrs, *name_addrs;
	char name[256] = {0};
	char msg[1024] = {0};
	int i;
	IMAGE_EXPORT_DIRECTORY *pedt;
	CPUState *env = cpu_single_env ? cpu_single_env : first_cpu;
	func_addrs = name_addrs = NULL;
	pedt = NULL;
	edt_va = nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	edt_size = nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

	pedt = (IMAGE_EXPORT_DIRECTORY *) malloc (sizeof(*pedt));
	memset(pedt, 0, sizeof(*pedt));

	if(DECAF_memory_rw_with_cr3 (env, cr3, base + edt_va, (void *)pedt, sizeof(*pedt), 0) < 0) {
		monitor_printf(default_mon, "Unable to read exp dir from image. \n");
		goto done;
	}

	func_addrs = (DWORD *) malloc (sizeof(DWORD *) * pedt->NumberOfFunctions);
	memset(func_addrs, 0, sizeof(DWORD *) * pedt->NumberOfFunctions);
	if(DECAF_memory_rw_with_cr3 (env, cr3, base + pedt->AddressOfFunctions, (void *)func_addrs, sizeof(DWORD *) * pedt->NumberOfFunctions, 0) < 0) {
		monitor_printf(default_mon, "Unable to read func_addrs from image. \n");
		goto done;
	}

	name_addrs = (DWORD *) malloc (sizeof(DWORD *) * pedt->NumberOfNames);
	memset(name_addrs, 0, sizeof(DWORD *) * pedt->NumberOfNames);
	if(DECAF_memory_rw_with_cr3 (env, cr3, base + pedt->AddressOfNames, (void *)name_addrs, sizeof(DWORD *) * pedt->NumberOfNames, 0) < 0) {
		monitor_printf(default_mon, "Unable to read name_addrs from image. \n");
		goto done;
	}

	for(i = 0; i < pedt->NumberOfFunctions && i < pedt->NumberOfNames; i++){
		DECAF_memory_rw_with_cr3(env, cr3, base + name_addrs[i], (void *) &name[0], 255, 0);
		sprintf(msg, "F %s %s %08x\n", mod->name, name, func_addrs[i]);
		parse_function(msg);
		monitor_printf(default_mon, "%d : %s\n", func_addrs[i], name);
	}
	monitor_printf(default_mon, "Total exports = %d, %d\n", pedt->NumberOfFunctions, pedt->NumberOfNames);
done:
	if(func_addrs)
		free(func_addrs);

	if(name_addrs)
		free(name_addrs);

	if(pedt)
		free(pedt);
	func_addrs = name_addrs = NULL;
	pedt = NULL;
}

static void extract_PE_symtab(process *proc, uint32_t base, module *mod)
{
	uint32_t pid = proc->pid;
	uint32_t cr3 = proc->cr3;
	char *name = mod->name;
	uint32_t size = mod->size;
	char *fullname = mod->fullname;

	char temp[1024] = {'\0'};
	uint8_t data[4096] = {0};
	int i;
	IMAGE_DOS_HEADER * DosHeader = NULL;
	IMAGE_NT_HEADERS *nth = NULL;
	uint8_t *file_data = NULL;
	CPUState *env = cpu_single_env ? cpu_single_env : first_cpu;

	DECAF_memory_rw_with_cr3(env, cr3, base, (void *)&data[0], sizeof(IMAGE_DOS_HEADER), 0);
	DosHeader = (IMAGE_DOS_HEADER *) data;
	if (DosHeader->e_magic != (0x5a4d)) {
		monitor_printf(default_mon, "Error -- Not a valid PE file!\n");
		return;
	}
//	monitor_printf(default_mon, "File loaded: %s, base: 0x%08x, size: %d, e_lfanew: %d\n", fullname, base, size, DosHeader->e_lfanew);
//		vm_stop(0);

	if(DECAF_memory_rw_with_cr3(env, cr3, base + DosHeader->e_lfanew, (void *)&data[0], sizeof(IMAGE_NT_HEADERS), 0) < 0) {
//		monitor_printf(default_mon, "Reading NTHeader failed. :'(\n");
//		monitor_printf(default_mon, "%s, 0x%08x, %d\n", fullname, base, DosHeader->e_lfanew);
		return;
	}

	nth = (IMAGE_NT_HEADERS *) data;
//	monitor_printf(default_mon, "Loaded: %s, size: %d\n", fullname, nth->OptionalHeader.SizeOfImage);
	file_data = (uint8_t *) malloc (nth->OptionalHeader.SizeOfImage);
	if(file_data == NULL) {
		monitor_printf(default_mon, "malloc failed in wl_load_module_notify. :'(\n");
//		vm_stop(0);
	}

	extract_export_table_from(nth, cr3, base, mod);

	if(file_data)
		free(file_data);

	file_data = NULL;
}

int procmod_insert_modinfoV(uint32_t pid, uint32_t base,module *mod)
{

  unordered_map < uint32_t, process * >::iterator iter =
      process_pid_map.find(pid);
  process *proc;

  if (iter == process_pid_map.end())	//pid not found
      return -1;

  proc = iter->second;
  proc->module_list[base]=mod;

  //Check if symbols have already been extracted
  if(findModule(mod->fullname) != NULL)
	  goto done;

  if(GuestOS_index_c <= 3) { //This is windows therefore a PE file
	  extract_PE_symtab(proc, base, mod);
  } else {
	  //TODO: extract elf symtab
  }

  //insert_module_infoV(proc->module_list, mod);
done:
  return 0;
}

int procmod_remove_modinfoV(uint32_t pid, uint32_t base)
{
    unordered_map < uint32_t, process * >::iterator iter =
	process_pid_map.find(pid);
    process *proc;

    if (iter == process_map.end())	//pid not found
	return -1;

    proc = iter->second;
    proc->module_list.erase(base);
    return 0;
}



int removeProcV(uint32_t pid)
{

  //  if (removeproc_notify)
//	removeproc_notify(pid);

    unordered_map < uint32_t, process * >::iterator iter =
	process_pid_map.find(pid);
    if (iter == process_pid_map.end())	//pid not found
	return -1;

    process *proc = iter->second;
    process_pid_map.erase(iter);
    process_map.erase(proc->cr3);
    delete proc;
    return 0;
}


int procmod_remove_allV()
{
    unordered_map < uint32_t, process * >::iterator iter;
    process *proc;

    process_pid_map.clear();

    while (!process_map.empty()) {
	iter = process_map.begin();
	proc = iter->second;
	process_map.erase(iter);
	delete proc;
    }
    return 0;
}


int update_procV(process *proc)
{
	if(proc==NULL)
	    	return -1;
	unordered_map < uint32_t, process * >::iterator iter =
		process_pid_map.find(proc->pid);
	    if (iter == process_pid_map.end())	//pid not found
	    {
	    	return addProcV(proc);

	    }
	    else
	    {
	    	removeProcV(proc->pid);
	    	addProcV(proc);
	    }
	    return 0;

}

int addFuncV(module *mod,string name,uint32_t offset)
{

	unordered_map < string, uint32_t >::iterator iter =(mod->function_map_name).find(name);
	unordered_map < uint32_t, string >::iterator iter1 =(mod->function_map_offset).find(offset);
    if(iter!=(mod->function_map_name).end() || iter1!=(mod->function_map_offset).end())
    	return -1;
    mod->function_map_name[name]=offset;
    mod->function_map_offset[offset]=name;
    return 0;

}

int removeFuncV(module *mod,uint32_t offset)
{
	unordered_map < uint32_t, string >::iterator iter1 =
				(mod->function_map_offset).find(offset);
	if(iter1==(mod->function_map_offset).end())
	    	return -1;
	string name = iter1->second;
	(mod->function_map_offset).erase(iter1);
	removeFuncNameV(mod,name);
	return 0;
}
int removeFuncNameV(module *mod,string name)
{
	unordered_map < string, uint32_t >::iterator iter1 =
					(mod->function_map_name).find(name);
		if(iter1==(mod->function_map_name).end())
		    	return -1;
		uint32_t offset = iter1->second;
		//(mod->function_map_name).erase(*iter1);
		removeFuncV(mod,offset);
		return 0;

}
dmodule *find_module_byeipV(uint32_t eip,
				     unordered_map< uint32_t,module * >&module_list)
{


	unordered_map< uint32_t,module * >::iterator iter;
    for (iter = module_list.begin(); iter != module_list.end(); iter++) {
	module *mod = iter->second;
	if (iter->first <= eip && mod->size + iter->first > eip) {
		dmodule *tmod=new dmodule();
		        	tmod->base=iter->first;
		        	strcpy(tmod->fullname,mod->fullname);
		        	strcpy(tmod->name,mod->name);
		        	tmod->size=mod->size;
	    return tmod;
	}

	if (iter->first > eip)
	    break;
    }

    return NULL;
}

dmodule *find_module_bynameV(string name,
				      unordered_map < uint32_t,module * >&module_list)
{


	unordered_map < uint32_t,module * >::iterator iter;
    for (iter = module_list.begin(); iter != module_list.end(); iter++) {
	module *mod = iter->second;
	if (strcasecmp((const char *)mod->fullname,name.c_str()) == 0) {
		dmodule *tmod=new dmodule();
				        	tmod->base=iter->first;
				        	strcpy(tmod->fullname,mod->fullname);
				        	strcpy(tmod->name,mod->name);
				        	tmod->size=mod->size;
			    return tmod;
	}
    }

    return NULL;
}

dmodule *locate_moduleV(uint32_t eip, uint32_t cr3)
{
    //FIXME: here we hardcode the boundary of kernel memory space.
    //we need better solution.
    unordered_map < uint32_t, process * >::iterator iter =
	process_map.find(eip > 0x80000000 ? 0 : cr3);
    if (iter == process_map.end()) {
	return NULL;
    }

    process *proc = iter->second;
    dmodule *mod=find_module_byeipV(eip, proc->module_list);
    if(mod!=NULL)
    {

        	return mod;
    }
    return NULL;
}

dmodule *locate_module_bynameV(char *name, uint32_t pid)
{
    unordered_map < uint32_t, process * >::iterator iter =
	process_pid_map.find(pid);
    if (iter == process_pid_map.end())	//pid not found
	return NULL;

    process *proc = iter->second;
    dmodule *tmod=find_module_bynameV(name, proc->module_list);
      if(tmod!=NULL)
    	return tmod;
      else
    	  return NULL;
}

dprocess* findProcessBYCR3V(uint32_t cr3)
{
    unordered_map < uint32_t, process * >::iterator iter =
	process_map.find(cr3);
    if (iter == process_map.end())
	return NULL;

    process *proc = iter->second;
    dprocess *temp=new dprocess();
    	    temp->cr3=proc->cr3;
    	    strcpy(temp->name,proc->name);
    	    temp->parent_pid=proc->parent_pid;
    	    temp->pid=proc->pid;
    		return temp;

}

dprocess* findProcessByNameV(char *name)
{
    unordered_map < uint32_t, process * >::iterator iter;
    for (iter = process_map.begin(); iter != process_map.end(); iter++) {
	process * proc = iter->second;
	if (strcmp((const char *)name,proc->name) == 0) {
	    dprocess *temp=new dprocess();
	    temp->cr3=proc->cr3;
	    strcpy(temp->name,proc->name);
	    temp->parent_pid=proc->parent_pid;
	    temp->pid=proc->pid;
		return temp;

	}
    }
    return 0;
}

dprocess* findProcessByPidV(uint32_t pid)
{
    process *proc;
    unordered_map < uint32_t, process * >::iterator iter =
	process_pid_map.find(pid);

    if (iter != process_pid_map.end()) {
	proc = iter->second;
	dprocess *temp=new dprocess();
		    temp->cr3=proc->cr3;
		    strcpy(temp->name,proc->name);
		    temp->parent_pid=proc->parent_pid;
		    temp->pid=proc->pid;
			return temp;
    }

    return 0;
}

int findProcessByPidH(uint32_t pid)
{
	unordered_map < uint32_t, process * >::iterator iter =
		process_pid_map.find(pid);

	    if (iter == process_pid_map.end()) {
		return 0;
	    }

	    return 1;
}

void get_proc_modulesV(uint32_t pid, dmodule mi_array[], int size)
{
    module *mod;
    unordered_map < uint32_t, process * >::iterator iter =
	process_pid_map.find(pid);
    if (iter == process_pid_map.end())	//pid not found
	return;

    unordered_map < uint32_t,module * >::iterator iter2;
    process *proc = iter->second;
    int counter = 0;
    for (iter2 = proc->module_list.begin();
	 iter2 != proc->module_list.end()&&counter<size; iter2++) {
	mod = iter2->second;
	dmodule *tmod=new dmodule();
	tmod->base=iter2->first;
	strcpy(tmod->fullname,mod->fullname);
	    	strcpy(tmod->name,mod->name);
	tmod->size=mod->size;
	mi_array[counter++] = *tmod;

    }
}





dprocess *find_all_processes_infoV(size_t * num_proc)
{
    process *proc;
    unordered_map < uint32_t, process * >::iterator iter;
    unsigned int idx = 0;
    size_t nproc;

    nproc = process_map.size();

    dprocess *arr = new dprocess[nproc];

    if (arr) {
	for (iter = process_map.begin(); iter != process_map.end(); iter++) {
	    proc = iter->second;
	    dprocess *temp=new dprocess();
	    	    temp->cr3=proc->cr3;
	    	    temp->EPROC_base_addr=proc->EPROC_base_addr;
	    	    strcpy(temp->name,proc->name);
	    	    temp->parent_pid=proc->parent_pid;
	    	    temp->pid=proc->pid;

	    arr[idx] = *(temp);
	    idx++;
	}
	*num_proc = nproc;
    } else {
	*num_proc = 0;
    }

    return arr;
}

/*
uint32_t get_kpcr() {
	uint32_t kpcr, selfpcr;
	CPUState *env;

	for (env = first_cpu; env != NULL; env = env->next_cpu) {
		if (env->cpu_index == 0) {
			break;
		}
	}

	kpcr = 0;
	cpu_memory_rw_debug(env, env->segs[R_FS].base + 0x1c, (uint8_t *) &selfpcr, 4, 0);

	if (selfpcr == env->segs[R_FS].base) {
		kpcr = selfpcr;
	}
	monitor_printf(default_mon, "KPCR at: 0x%08x\n", kpcr);

	return kpcr;
}

int readustr_with_cr3(uint32_t addr, uint32_t cr3, void *buf, CPUState *env)
{

	uint32_t unicode_data[2];
	int i, j, unicode_len = 0;
	uint8_t unicode_str[MAX_UNICODE_LENGTH] = { '\0' };
	char *store = (char *) buf;

	if(cr3 != 0) {
		if (DECAF_memory_rw_with_cr3 (env,cr3, addr, (void *)&unicode_data, sizeof(unicode_data), 0) < 0) {
			//monitor_printf(default_mon,"TEMU_mem_rw_with_cr3(0x%08x, cr3=0x%08x, %d) returned non-zero.\n", addr, cr3, sizeof(unicode_data));
			store[0] = '\0';
			goto done;
		}
	} else {
		if (DECAF_memory_rw (env,addr, (void *)&unicode_data, sizeof(unicode_data), 0) < 0) {
			//monitor_printf(default_mon,"TEMU_mem_rw(0x%08x, %d) returned non-zero.\n", addr, sizeof(unicode_data));
			store[0] = '\0';
			goto done;
		}
	}

	unicode_len = (int) (unicode_data[0] & 0xFFFF);
	if (unicode_len > MAX_UNICODE_LENGTH)
			unicode_len = MAX_UNICODE_LENGTH;

	if(cr3 != 0) {
		if (DECAF_memory_rw_with_cr3 (env,cr3, unicode_data[1], (void *) unicode_str, unicode_len, 0) < 0) {
			store[0] = '\0';
			goto done;
		}
	} else {
		if (DECAF_memory_rw (env,unicode_data[1], (void *) unicode_str, unicode_len, 0) < 0) {
			store[0] = '\0';
			goto done;
		}
	}

	for (i = 0, j = 0; i < unicode_len; i += 2, j++) {
		if(unicode_str[i] < 0x20 || unicode_str[i] > 0x7e) //Non_printable character
			break;

		store[j] = unicode_str[i];
	}
	store[j] = '\0';

	done:
		return strlen(store);
}
void message_m(uint32_t pid, uint32_t cr3, module* pe){
	char proc_mod_msg[2048]= {'\0'};
	char api_msg[2048] = {'\0'};
	struct api_entry *api = NULL, *next = NULL;
	monitor_printf(default_mon,"in message_m");
	if(strlen(pe->name) == 0)
		return;

	monitor_printf(default_mon,"M %d %08x \"%s\" %08x %08x \"%s\"\n", pid, cr3, pe->name, pe->base, pe->size,pe->fullname);
	sprintf(proc_mod_msg, "M %d %08x \"%s\" %08x %08x \"%s\"\n", pid, cr3, pe->name, pe->base, pe->size,pe->fullname);
	update_api_with_pe(cr3, pe, ((pid == 0 || pid == 4)? 0 : 1));
	if(!QLIST_EMPTY(&pe->apilist_head)){
		QLIST_FOREACH_SAFE(api, &pe->apilist_head, loadedlist_entry, next){
			sprintf(api_msg, "F %s %s %08x\n", pe->name, api->name, api->base);
			handle_guest_message(api_msg);
			QLIST_REMOVE(api, loadedlist_entry);
			free(api);
		}
	}
	handle_guest_message(proc_mod_msg);
}

int update_loaded_user_mods_with_peb(uint32_t cr3,uint32_t peb, target_ulong vaddr,uint32_t pid)
{
	uint32_t ldr, memlist, first_dll, curr_dll;
	module *curr_entry = NULL;

	CPUState *env = cpu_single_env ? cpu_single_env : first_cpu;
	int ret = 0, flag = 0;
	monitor_printf(default_mon,"in updatemods peb:%x",peb);
	if(peb == 0x00)
		goto done;

	DECAF_memory_rw_with_cr3 (env,cr3, peb+0xc, (void *)&ldr, 4, 0);
	memlist = ldr + 0xc;
	DECAF_memory_rw_with_cr3 (env,cr3, memlist, (void *) &first_dll, 4, 0);

	if(first_dll == 0)
		goto done;

	curr_dll = first_dll;

	do {
		curr_entry = (module *) malloc (sizeof(module));
		memset(curr_entry, 0, sizeof(*curr_entry));

		DECAF_memory_rw_with_cr3 (env,cr3, curr_dll+ 0x18, (void *) &(curr_entry->base), 4, 0);
		if(curr_entry->base == 0x0 && flag == 0){
			flag = 1;
			DECAF_memory_rw_with_cr3 (env,cr3, curr_dll, (void *) &curr_dll, 4, 0);
			continue;
		}
		DECAF_memory_rw_with_cr3 (env,cr3, curr_dll+ 0x20, (void *) &(curr_entry->size), 4, 0);
		readustr_with_cr3(curr_dll + 0x24, cr3, curr_entry->fullname, env);
		readustr_with_cr3(curr_dll + 0x2c, cr3, curr_entry->name, env);
		uint32_t modules = curr_entry->base;

		if(modules >0x00300000){
			if((locate_moduleV(modules,cr3)!=NULL))
			{   procmod_insert_modinfoV(pid,curr_entry);
				message_m(pid, cr3, curr_entry);
			}
			}
		free(curr_entry);
		ret++;
		DECAF_memory_rw_with_cr3 (env,cr3, curr_dll, (void *) &curr_dll, 4, 0);
	} while (curr_dll != 0 && curr_dll != first_dll);

done:
	return ret;
}



uint32_t get_cr3_from_proc_base(uint32_t base)
{
	CPUState* env;
	uint32_t cr3;

		for (env = first_cpu; env != NULL; env = env->next_cpu) {
			if (env->cpu_index == 0) {
				break;
			}
		}
	cpu_memory_rw_debug(env, base+0x18, (uint8_t *) &cr3, 4, 0);
	//vm_stop(0);

	return cr3;
}
int clear_list()
{

  while(!processes.empty())
  {

	  process *temp=NULL;
	  temp=processes.front();
	  processes.pop();
	  removeProcV(temp->pid);
	  //delete temp;
  }
}
static void update_active_processlist() {


	 Update the process data structures in procmod

//	procmod_remove_all();
//	QLIST_FOREACH(pe, &processlist, loadedlist_entry) {
//		procmod_createproc(pe->process_id, pe->ppid,
//			       get_cr3_from_proc_base(pe->EPROC_base_addr), pe->name);
//	}

	uint32_t kdvb, psAPH, curr_proc, next_proc, handle_table;
		CPUState *env;
		process *pe;

		if (gkpcr == 0)
			return;

		for (env = first_cpu; env != NULL; env = env->next_cpu) {
			if (env->cpu_index == 0) {
				break;
			}
		}
		clear_list();
		cpu_memory_rw_debug(env, gkpcr + KDVB_OFFSET, (uint8_t *) &kdvb, 4, 0);
		cpu_memory_rw_debug(env, kdvb + PSAPH_OFFSET, (uint8_t *) &psAPH, 4, 0);
		cpu_memory_rw_debug(env, psAPH, (uint8_t *) &curr_proc, 4, 0);
        int i=0;
		while (curr_proc != 0 && curr_proc != psAPH) {
			pe = new process();
			//memset(pe, 0, sizeof(process));

			pe->EPROC_base_addr = curr_proc - handle_funds[GuestOS_index].offset->PSAPL_OFFSET;
			pe->cr3 = get_cr3_from_proc_base(pe->EPROC_base_addr);
			uint32_t curr_proc_base = pe->EPROC_base_addr;

			cpu_memory_rw_debug(env, curr_proc_base + handle_funds[GuestOS_index].offset->PSAPNAME_OFFSET, (uint8_t *) &(pe->name), NAMESIZE, 0);
			cpu_memory_rw_debug(env, curr_proc_base + handle_funds[GuestOS_index].offset->PSAPID_OFFSET, (uint8_t *) &(pe->pid), 4, 0);
			cpu_memory_rw_debug(env, curr_proc_base + handle_funds[GuestOS_index].offset->PSAPPID_OFFSET, (uint8_t *) &(pe->parent_pid), 4, 0);
			//cpu_memory_rw_debug(env, curr_proc_base + handle_funds[GuestOS_index].offset->PSAPTHREADS_OFFSET, (uint8_t *) &(pe->number_of_threads), 4, 0);
			cpu_memory_rw_debug(env, curr_proc_base + handle_funds[GuestOS_index].offset->PSAPHANDLES_OFFSET, (uint8_t *) &(handle_table), 4, 0);
			//cpu_memory_rw_debug(env, handle_table, (uint8_t *) &(pe->table_code), 4, 0);
			//cpu_memory_rw_debug(env, handle_table + handle_funds[GuestOS_index].offset->HANDLE_COUNT_OFFSET, (uint8_t *) &(pe->number_of_handles), 4, 0);

			//QLIST_INSERT_HEAD(&processlist, pe, loadedlist_entry);
            processes.push(pe);
            addProcV(pe);
			cpu_memory_rw_debug(env, curr_proc, (uint8_t *) &next_proc, 4, 0);
			//monitor_printf(default_mon,"cP - %x,,np - %x ,,,ps-%x\n", curr_proc,next_proc,psAPH);

			if(curr_proc==next_proc)
			 {
				break;
			 }
				curr_proc = next_proc;
		}
}
 process *get_system_process()
{
        process *pe = NULL;
        //handle_funds[GuestOS_index].update_processlist();

        //QLIST_FOREACH(pe, &processlist, loadedlist_entry)
        //{
          //      if(strcmp(pe->name.c_str(), "System") == 0)
            //            break;
       // }
       // return pe;
}
void get_os_version() {
	CPUState* env;
	for (env = first_cpu; env != NULL; env = env->next_cpu) {
		if (env->cpu_index == 0) {
			break;
		}
	}
	uint32_t kdvb, CmNtCSDVersion, num_package;

	if (gkpcr == 0xffdff000) {
		cpu_memory_rw_debug(env, gkpcr + 0x34, (uint8_t *) &kdvb, 4, 0);
		cpu_memory_rw_debug(env, kdvb + 0x290, (uint8_t *) &CmNtCSDVersion, 4, 0); //CmNt version info
		cpu_memory_rw_debug(env, CmNtCSDVersion, (uint8_t *) &num_package, 4, 0);
		uint32_t num = num_package >> 8;
		monitor_printf(default_mon, "its windows xp...%x\t%x\n",num,gkpcr);
		if (num == 0x02) {
			GuestOS_index = 0; //winxpsp2
			monitor_printf(default_mon, "its windows xp...\n");
		} else if (num == 0x03) {
			GuestOS_index = 1; //winxpsp3
			monitor_printf(default_mon, "its windows xp...\n");
		}
	} else {
		GuestOS_index = 2; //win7
		monitor_printf(default_mon, "its windows 7...\n");
	}

}
void message_p(process* proc, int operation){
	char proc_mod_msg[1024]= {'\0'};
	if(operation){
		monitor_printf(default_mon,"P + %d %d %08x %s\n", proc->pid, proc->parent_pid, proc->cr3, proc->name);
		sprintf(proc_mod_msg, "P + %d %d %08x %s\n", proc->pid, proc->parent_pid, proc->cr3, proc->name);
	}else{
		monitor_printf(default_mon,"P - %d %d %08x %s\n", proc->pid, proc->parent_pid, proc->cr3, proc->name);
		sprintf(proc_mod_msg, "P - %d %d %08x %s\n", proc->pid, proc->parent_pid, proc->cr3, proc->name);
	}
	//handle_guest_message(proc_mod_msg);
}


static uint32_t get_ntoskrnl_internal(uint32_t curr_page, CPUState *env)
{
	IMAGE_DOS_HEADER *DosHeader = NULL;

	uint8_t page_data[4*1024] = {0}; //page_size
	uint16_t DOS_HDR = 0x5a4d;

	while(curr_page > 0x80000000) {
		if(cpu_memory_rw_debug(env, curr_page, (uint8_t *) page_data, 4*1024, 0) >= 0) { //This is paged out. Just continue
				if(memcmp(&page_data, &DOS_HDR, 2) == 0) {
					DosHeader = (IMAGE_DOS_HEADER *)&(page_data);
					if (DosHeader->e_magic != 0x5a4d)
						goto dec_continue;

					monitor_printf(default_mon, "DOS header matched at: 0x%08x\n", curr_page);

					if(*((uint32_t *)(&page_data[*((uint32_t *)&page_data[0x3c])])) != IMAGE_NT_SIGNATURE)
						goto dec_continue;

					return curr_page;
				}
		}
dec_continue:
		curr_page -= 1024*4;
	}
	return 0;
}

uint32_t  get_ntoskrnl(CPUState *env)
{
	uint32_t ntoskrnl_base = 0, exit_page = 0, cr3 = 0;
	struct cr3_info *cr3i = NULL;
	struct process_entry* procptr = NULL;
	monitor_printf(default_mon, "Trying by scanning back from sysenter_eip...\n");
	ntoskrnl_base = get_ntoskrnl_internal(env->sysenter_eip & 0xfffff000, env);
	if(ntoskrnl_base)
		goto found;
	monitor_printf(default_mon, "Trying by scanning back from eip that sets kpcr...\n");
	ntoskrnl_base = get_ntoskrnl_internal(env->eip & 0xfffff000, env);
	if(ntoskrnl_base)
		goto found;
	return 0;

found:
	cr3 = system_cr3 = env->cr[3];

	monitor_printf(default_mon, "OS base found at: 0x%08x\n", ntoskrnl_base);

	return ntoskrnl_base;
}
process* get_new_process() {
	process *pe = NULL;
	handle_funds[GuestOS_index].update_processlist();
	monitor_printf(default_mon, "%d\tnew process...\n", GuestOS_index);
	//queue<process *> temp=processes;
	//while(!temp.empty())
		//{
			//pe=temp.front();
			//temp.pop();
		//monitor_printf(default_mon, "%d\t%s\t%d\n",
			//		 pe->parent_pid, pe->name, pe->pid
				//	);
		//}
	if(!processes.empty())
	{pe = processes.back();

	return pe;

	}

		return NULL;
}

target_ulong get_new_modules(CPUState* env, uint32_t cr3, target_ulong vaddr){

	uint32_t base = 0, self =0, pid = 0;
	if(cr3 == system_cr3) {
		//Need to load system module here.
		pid = 4; //TODO: Fix this.
		update_kernel_modules(cr3, vaddr, pid, cr3i);
	} else {

		base =  env->segs[R_FS].base;
		cpu_memory_rw_debug(env, base + 0x18,(uint8_t *)&self, 4, 0);
		//monitor_printf(default_mon,"in get new modules base:%x  self:%x\n",base,self);
		if(base !=0 &&base == self){
			uint32_t pid_addr = base+0x20;
			cpu_memory_rw_debug(env,pid_addr,(uint8_t *)&pid,4,0);
			uint32_t peb_addr = base+0x30;
			uint32_t peb,ldr;
			cpu_memory_rw_debug(env,peb_addr,(uint8_t *)&peb, 4, 0);
			update_loaded_user_mods_with_peb(cr3, peb, vaddr, pid);
		}
	//}
	return 0;
}



uint32_t present_in_vtable = 0;
uint32_t adding_to_vtable = 0;
uint32_t getting_new_mods = 0;
void tlb_call_back(DECAF_Callback_Params* temp)
{
	CPUState *env = cpu_single_env ? cpu_single_env : first_cpu;
			struct cr3_info *cr3i = NULL;
			uint32_t cr3 = env->cr[3];
         process* procptr = NULL;
        int flag = 0;
        int new1 = 0;
        char proc_mod_msg[1024] = {'\0'};
        target_ulong modules;
        uint32_t exit_page = 0;
        unordered_set<uint32_t>::const_iterator got = cr3s.find (cr3);
        if(got==cr3s.end())
        {
        	cr3s.insert(cr3);
        	//monitor_printf(default_mon, "found new cr3: 0x%08x\n", cr3);
        	if(system_proc == NULL) { //get the system proc first. This should be automatic.

        								procptr = get_system_process();
        								if(!procptr) {
        										monitor_printf(default_mon, "System proc is null. shouldn't be. Stopping vm...\n");
        										vm_stop(RUN_STATE_DEBUG);
        								}

        						}

        	procptr = get_new_process();
        	if(procptr!=NULL)
        	message_p(procptr,1); // 1 for addition, 0 for remove

        }
		cr3i = g_hash_table_lookup(cr3_hashtable, cr3);
		if(!TEMU_is_in_kernel()) {
				if(!cr3i){ // new cr3'
					new1 = 1;
					if(system_proc == NULL) { //get the system proc first. This should be automatic.
							cr3i = (struct cr3_info *) malloc (sizeof(*cr3i));
							cr3i->value = system_cr3;
							cr3i->vaddr_tbl = g_hash_table_new(0,0);
							cr3i->modules_tbl = g_hash_table_new(0,0);
							g_hash_table_insert(cr3_hashtable, (gpointer)cr3, (gpointer) cr3i);
							procptr = get_system_process();
							if(!procptr) {
									monitor_printf(default_mon, "System proc is null. shouldn't be. Stopping vm...\n");
									vm_stop(0);
							}
							system_proc = procptr;
							message_p(procptr,1); // 1 for addition, 0 for remove
							update_kernel_modules(system_cr3, vaddr, procptr->process_id, cr3i);
							exit_page = (((procptr->EPROC_base_addr)+0x78) >> 3) << 3;
							g_hash_table_insert(eproc_ht, (gpointer)(exit_page), (gpointer)1);
							QLIST_INIT(&procptr->modlist_head);
					}

					cr3i  = (struct cr3_info*)malloc(sizeof(*cr3i));
					cr3i->value = cr3;
					cr3i->vaddr_tbl = g_hash_table_new(0, 0);
					cr3i->modules_tbl = g_hash_table_new(0, 0);
					g_hash_table_insert(cr3i->vaddr_tbl, (gpointer)vaddr, (gpointer)1);
					g_hash_table_insert(cr3_hashtable, (gpointer)cr3, (gpointer) cr3i);

					procptr = get_new_process();
					message_p(procptr,1); // 1 for addition, 0 for remove

					exit_page = (((procptr->EPROC_base_addr)+0x78) >> 3) << 3;
					g_hash_table_insert(eproc_ht, (gpointer)(exit_page), (gpointer)1);
					QLIST_INIT(&procptr->modlist_head);

					if(g_hash_table_size(cr3_hashtable) == 2)
							startup_registrations();
				}
		} else if(!cr3i) {
			goto done;
		}

        if(!new1) { // not a new cr3
				if(g_hash_table_lookup(cr3i->vaddr_tbl, (gpointer)vaddr)) {
						present_in_vtable++;
						goto done;
				}
				g_hash_table_insert(cr3i->vaddr_tbl, (gpointer) vaddr, (gpointer)1);
				adding_to_vtable++;
		}

        getting_new_mods++;
        get_new_modules(env, cr3, vaddr, cr3i);

        //get_new_modules(env, cr3, temp->mw.virt_addr);
        done:
                return;
}




void insn_end_cb(DECAF_Callback_Params* temp)
{
	//monitor_printf(default_mon, "Unable to locate kernel base. Stopping VM...\n");
	//DECAF_unregister_callback(DECAF_INSN_END_CB, insn_handle_c);
	CPUState *env = cpu_single_env ? cpu_single_env : first_cpu;
		struct cr3_info *cr3i = NULL;
		uint32_t cr3 = env->cr[3];
		uint32_t base;
		insn_counter++;

		if(env->eip > 0x80000000 && env->segs[R_FS].base > 0x80000000) {
				gkpcr = get_kpcr();
				if(gkpcr != 0){
					DECAF_unregister_callback(DECAF_INSN_END_CB, insn_handle_c);

					//QLIST_INIT (&loadedlist);
					//QLIST_INIT (&processlist);
					//QLIST_INIT (&threadlist);
					//QLIST_INIT (&filelist);
					//cr3_hashtable = g_hash_table_new(0,0);
					//eproc_ht = g_hash_table_new(0,0);

					get_os_version();
					base = get_ntoskrnl(env);
					if(!base) {
						monitor_printf(default_mon, "Unable to locate kernel base. Stopping VM...\n");
						//vm_stop(0);
						return;
					}

					//block_handle = DECAF_register_callback(DECAF_BLOCK_BEGIN_CB, block_begin_cb, NULL);
					qemu_mod_timer(recon_timer, qemu_get_clock_ns(vm_clock) + get_ticks_per_sec() * 30);
					DECAF_register_callback(DECAF_MEM_WRITE_CB, tlb_call_back, NULL);
				}
		}
}
uint32_t exit_block_end_eip = 0;
void check_procexit(void *)
{
	CPUState *env = cpu_single_env ? cpu_single_env : first_cpu;
//	if(!TEMU_is_in_kernel())
//		return;
//
//	if(exit_block_end_eip && env->eip != exit_block_end_eip)
//		return;

	qemu_mod_timer(recon_timer, qemu_get_clock_ns(vm_clock) + get_ticks_per_sec() * 30);

	monitor_printf(default_mon, "Checking for proc exits...\n");

	process *proc = NULL, *next = NULL;
	uint32_t end_time[2];
	queue<process *> temp;
	if(!processes.empty())
	{
       while(!processes.empty())
       {

    	   proc=processes.front();
    	   processes.pop();
    	   if(proc->parent_pid == 0)
    	   {
    		   temp.push(proc);
    	   }
    	   else
    	   {

    		   cpu_memory_rw_debug(env, (proc->EPROC_base_addr)+handle_funds[GuestOS_index].offset->PEXIT_TIME, (uint8_t *)&end_time[0], 8, 0);
    		   			if(end_time[0] | end_time[1]) {

    		   				message_p(proc, 0);
    		   				delete proc;
    		   				exit_block_end_eip = env->eip;
    		   				//return;
    		   			}
    		   			else
    		   			{
    		   				temp.push(proc);
    		   			}
    	   }

       }
       processes=temp;

	}

}
*/

void insn_end_cb(DECAF_Callback_Params* temp)
{
	//monitor_printf(default_mon, "Unable to locate kernel base. Stopping VM...\n");
	//DECAF_unregister_callback(DECAF_INSN_END_CB, insn_handle_c);
	//CPUState *env = cpu_single_env ? cpu_single_env : first_cpu;
    int i=0;
    int cflag=0;
	for(i=0;i<4;i++)
	{
		if(handle_funds_c[i].find(temp->ie.env,insn_handle_c)==1)
		{
			GuestOS_index_c=i;
			cflag=1;
		}
	}
	if(GuestOS_index_c==0||GuestOS_index_c==1)
		monitor_printf(default_mon, "its win xp \n");
	else if(GuestOS_index_c==2||GuestOS_index_c==3)
		monitor_printf(default_mon, "its win 7 \n");
	if(cflag)
	{DECAF_unregister_callback(DECAF_INSN_END_CB, insn_handle_c);
	handle_funds_c[GuestOS_index_c].init();
	}
}


extern "C" void vmi_init()
{
	monitor_printf(default_mon, "inside vmi init \n");
	insn_handle_c = DECAF_register_callback(DECAF_INSN_END_CB, insn_end_cb, NULL);
	//recon_timer = qemu_new_timer_ns(vm_clock, check_procexit, 0);
}

process* findProcessByNameH(char *name)
{
	unordered_map < uint32_t, process * >::iterator iter;
	    for (iter = process_map.begin(); iter != process_map.end(); iter++) {
		process * proc = iter->second;
		if (strcmp((const char *)name,proc->name) == 0) {

			return proc;

		}
	    }
	    return 0;

}


int findCr3(uint32_t cr3)
{
	 unordered_set<uint32_t>::const_iterator got = cr3s.find (cr3);
	        if(got==cr3s.end())
	        {
	        	return 0;
	        }
	        return 1;
}
void insertCr3(uint32_t cr3)
{
	cr3s.insert(cr3);
}

int addCr3info(cr3_info_c *cr3info)
{
	 if(cr3info==NULL)
	    	return -1;

	    cr3infos[cr3info->value] = cr3info;
	    return 1;
}

int findvaddrincr3(uint32_t cr3,target_ulong vaddr)
{
	unordered_map < uint32_t,cr3_info_c * >::iterator iter =
		cr3infos.find(cr3);
	    if (iter != cr3infos.end())
	    {
	    	unordered_set<target_ulong>::const_iterator got = iter->second->vaddr_tbl->find(vaddr);
	    	if(got!=iter->second->vaddr_tbl->end())
	    	{
	    		return 1;
	    	}

	    }
	    return 0;
}

void insertvaddrincr3(uint32_t cr3,target_ulong vaddr)
{
	unordered_map < uint32_t, cr3_info_c * >::iterator iter =
			cr3infos.find(cr3);
		    if (iter != cr3infos.end())
		    {
		    	iter->second->vaddr_tbl->insert(vaddr);

		    }

}

int addModules(module *mod)
{
	if(mod==NULL)
	    	return -1;
	string temp(mod->fullname);
	    unordered_map < string, module * >::iterator iter =
	    	module_name.find(temp);
	        if (iter != module_name.end())
	        {
	        	delete mod;
	        	return -1;
	        }
	    module_name[temp]=mod;
	     return 1;


}
module* findModule(char *name)
{
	if(name==NULL)
		    	return NULL;
		string temp(name);
		    unordered_map < string, module * >::iterator iter =
		    	module_name.find(temp);
		        if (iter != module_name.end())
		        {
		        	return iter->second;
		        }

		     return NULL;


}

