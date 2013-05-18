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
#include <iostream>
#include <fstream>
#include <sstream>
#include "sqlite3/sqlite3.h"
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
#include "cpu.h"
#include "config.h"
#include "hw/hw.h" // AWH
#include "DECAF_target.h"


#ifdef __cplusplus
};
#endif /* __cplusplus */
#include "windows_vmi.h"
// AWH #include "linux_vmi.h"
#include "hookapi.h"
#include "read_linux.h"
#include "shared/vmi.h"
#include "shared/DECAF_main.h"
#include "shared/procmod.h"
#include "shared/function_map.h" /* AWH "shared/hooks/function_map.h" */
#include "shared/utils/SimpleCallback.h"
//#include "helper.h"

using namespace std;
using namespace std::tr1;

#ifdef CONFIG_VMI_ENABLE
//map cr3 to process_info_t
static unordered_map < uint32_t, process * >process_map;
//map pid to process_info_t
static unordered_map < uint32_t, process * >process_pid_map;
// module list
static unordered_map < string, module * >module_name;
// process list
static queue< process* > processes;
// cr3 set
static unordered_set <uint32_t> cr3s;
// map cr3 to cr3_info
static unordered_map <uint32_t,cr3_info_c *> cr3infos;

uint32_t GuestOS_index_c=11;
uintptr_t insn_handle_c = 0;

static os_handle_c handle_funds_c[] = {
		{ WINXP_SP2_C, &find_winxpsp2, &win_vmi_init, },
		{ WINXP_SP3_C, &find_winxpsp3, &win_vmi_init, },
		{ WIN7_SP0_C, &find_win7sp0, &win_vmi_init, },
		{ WIN7_SP1_C, &find_win7sp1, &win_vmi_init, },
		//{ LINUX_2_6_C, &find_linux, &linux_vmi_init,},
};

void listProcs(Monitor *mon) {
	process *proc;
	unordered_map<uint32_t, process *>::iterator iter;

	for (iter = process_map.begin(); iter != process_map.end(); iter++) {
		proc = iter->second;
		monitor_printf(mon, "%d\tcr3=0x%08x\t%s\n", proc->pid, proc->cr3,
				proc->name);
	}
}

void listModuleByPid(Monitor *mon, uint32_t pid) {
	unordered_map<uint32_t, process *>::iterator iter = process_pid_map.find(
			pid);
	if (iter == process_pid_map.end())	//pid not found
		return;

	unordered_map<uint32_t, module *>::iterator iter2;
	process *proc = iter->second;
	//int counter = 0;
	for (iter2 = proc->module_list.begin(); iter2 != proc->module_list.end();
			iter2++) {
		module* mod = iter2->second;
		uint32_t base = iter2->first;
		monitor_printf(mon, "%20s\t0x%08x\t0x%08x\n", mod->name, base,
				mod->size);
	}
}

int addProcV(process *proc){
    if(proc==NULL)
    	return -1;
    unordered_map < uint32_t, process * >::iterator iter =
    	process_pid_map.find(proc->pid);
    if (iter != process_pid_map.end()){
        delete proc;
        return -1;
    }
    if(proc->pid != -1UL)
    	process_pid_map[proc->pid] = proc;
    if (proc->cr3 != -1UL)
      	process_map[proc->cr3] = proc;

    return 0;
}


//Aravind - added to get the number of loaded modules for the process. This is needed to create the memory required by get_proc_modules
int get_loaded_modules_countV(uint32_t pid) {
	unordered_map<uint32_t, process *>::iterator iter = process_pid_map.find(
			pid);
	if (iter == process_pid_map.end())	//pid not found
		return 0;

	unordered_map<uint32_t, module *>::iterator iter2;
	process *proc = iter->second;
	int counter = 0;
	for (iter2 = proc->module_list.begin(); iter2 != proc->module_list.end();
			iter2++) {
		counter++;
	}
	return counter;
}
//end - Aravind

static void extract_dll_info(IMAGE_NT_HEADERS *nth, uint32_t cr3, uint32_t base, module *mod){

	//CPUState *env = cpu_single_env ? cpu_single_env : first_cpu;
	DWORD checksum = nth->OptionalHeader.CheckSum;
	DWORD codesize = nth->OptionalHeader.SizeOfCode;
	WORD major = nth->OptionalHeader.MajorImageVersion;
	WORD minor = nth->OptionalHeader.MinorImageVersion;
	mod->checksum = checksum;
	mod->codesize = codesize;
	mod->major = major;
	mod->minor = minor;
}
// not used, can't extract dll at runtime
//static void extract_export_table_from(IMAGE_NT_HEADERS *nth, uint32_t cr3, uint32_t base, module *mod)
//{
//	DWORD edt_va,edt_size;
//	DWORD *func_addrs, *name_addrs;
//	char name[128] = {0};
//	char msg[512] = {0};
//	int i;
//	IMAGE_EXPORT_DIRECTORY *pedt;
//	CPUState *env = cpu_single_env ? cpu_single_env : first_cpu;
//	func_addrs = name_addrs = NULL;
//	pedt = NULL;
//	DWORD ver = nth->OptionalHeader.CheckSum;
//	edt_va = nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
//	edt_size = nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
//
//	pedt = (IMAGE_EXPORT_DIRECTORY *) malloc (sizeof(*pedt));
//	memset(pedt, 0, sizeof(*pedt));
//	//monitor_printf(default_mon, "checksum: 0x%08x \n", ver);
//	//monitor_printf(default_mon, "base:x%08x, offset:0x%08x \n",base, base + edt_va);
//
//	if( DECAF_memory_rw_with_cr3 (env, cr3, base + edt_va, (void *)pedt, sizeof(*pedt), 0) < 0) {
//		monitor_printf(default_mon, "Unable to read exp dir from image. \n");
//		goto done;
//	}
//
//	func_addrs = (DWORD *) malloc (sizeof(DWORD *) * pedt->NumberOfFunctions);
//	memset(func_addrs, 0, sizeof(DWORD *) * pedt->NumberOfFunctions);
//	if(DECAF_memory_rw_with_cr3 (env, cr3, base + pedt->AddressOfFunctions, (void *)func_addrs, sizeof(DWORD *) * pedt->NumberOfFunctions, 0) < 0) {
//		monitor_printf(default_mon, "Unable to read func_addrs from image. \n");
//		goto done;
//	}
//
//	name_addrs = (DWORD *) malloc (sizeof(DWORD *) * pedt->NumberOfNames);
//	memset(name_addrs, 0, sizeof(DWORD *) * pedt->NumberOfNames);
//	if(DECAF_memory_rw_with_cr3 (env, cr3, base + pedt->AddressOfNames, (void *)name_addrs, sizeof(DWORD *) * pedt->NumberOfNames, 0) < 0) {
//		monitor_printf(default_mon, "Unable to read name_addrs from image. \n");
//		goto done;
//	}
//
//	for(i = 0; i < pedt->NumberOfFunctions && i < pedt->NumberOfNames; i++){
//		DECAF_memory_rw_with_cr3(env, cr3, base + name_addrs[i], (void *) &name[0], 128, 0);
//		sprintf(msg, "F %s %s %08x\n", mod->name, name, func_addrs[i]);
//		parse_function(msg);
//		monitor_printf(default_mon, "F %08x : %s\n", func_addrs[i], name);
//	}
//	monitor_printf(default_mon, "Total exports = %d, %d\n", pedt->NumberOfFunctions, pedt->NumberOfNames);
//done:
//	if(func_addrs)
//		free(func_addrs);
//
//	if(name_addrs)
//		free(name_addrs);
//
//	if(pedt)
//		free(pedt);
//	func_addrs = name_addrs = NULL;
//	pedt = NULL;
//}

// extract dll verison, size info
static void extract_PE_info(process *proc, uint32_t base, module *mod){
	uint32_t cr3;
	CPUState *env = cpu_single_env ? cpu_single_env : first_cpu;
	DECAF_read_mem(env, proc->EPROC_base_addr+ 0x18, 4, (uint8_t *) &cr3);
	//monitor_printf(default_mon, "cr3 0x%08x, base 0x%08x\n",cr3, base);
	char *fullname = mod->fullname;
	uint8_t data[64] = {0};
	uint8_t data1[512] = {0};
	IMAGE_DOS_HEADER * DosHeader = NULL;
	IMAGE_NT_HEADERS *nth = NULL;
	uint8_t *file_data = NULL;
	DECAF_memory_rw_with_cr3(env, cr3, base, (void *)&data[0], sizeof(IMAGE_DOS_HEADER), 0);

	DosHeader = (IMAGE_DOS_HEADER *) data;
	if (DosHeader->e_magic != (0x5a4d)) {
		monitor_printf(default_mon, "Error -- Not a valid PE file!\n");
		return;
	}

	if(DECAF_memory_rw_with_cr3(env, cr3, base + DosHeader->e_lfanew, (void *)&data1[0], sizeof(IMAGE_NT_HEADERS), 0) < 0) {
		monitor_printf(default_mon, "Reading NTHeader failed. :'(\n");
		monitor_printf(default_mon, "%s, 0x%08x, %d\n", fullname, base, DosHeader->e_lfanew);
		return;
	}

	nth = (IMAGE_NT_HEADERS *) data1;
	file_data = (uint8_t *) malloc (nth->OptionalHeader.SizeOfImage);
	if(file_data == NULL) {
		monitor_printf(default_mon, "malloc failed in wl_load_module_notify. :'(\n");
//		vm_stop(0);
	}
	extract_dll_info(nth, cr3, base, mod); // extract info in IMAGE_NT_HEADERS
	if(file_data)
		free(file_data);
	file_data = NULL;
}
// not used
//static void extract_PE_symtab(process *proc, uint32_t base, module *mod)
//{
//	uint32_t cr3;
//	CPUState *env = cpu_single_env ? cpu_single_env : first_cpu;
//	DECAF_read_mem(env, proc->EPROC_base_addr+ 0x18, 4, (uint8_t *) &cr3);
//	monitor_printf(default_mon, "cr3 0x%08x, base 0x%08x\n",cr3, base);
//	char *fullname = mod->fullname;
//	uint8_t data[128] = {0};
//	int i;
//	IMAGE_DOS_HEADER * DosHeader = NULL;
//	IMAGE_NT_HEADERS *nth = NULL;
//	uint8_t *file_data = NULL;
//
//	DECAF_memory_rw_with_cr3(env, cr3, base, (void *)&data[0], sizeof(IMAGE_DOS_HEADER), 0);
//
//	DosHeader = (IMAGE_DOS_HEADER *) data;
//	if (DosHeader->e_magic != (0x5a4d)) {
//		monitor_printf(default_mon, "Error -- Not a valid PE file!\n");
//		return;
//	}
//
//	if(DECAF_memory_rw_with_cr3(env, cr3, base + DosHeader->e_lfanew, (void *)&data[0], sizeof(IMAGE_NT_HEADERS), 0) < 0) {
//		monitor_printf(default_mon, "Reading NTHeader failed. :'(\n");
//		monitor_printf(default_mon, "%s, 0x%08x, %d\n", fullname, base, DosHeader->e_lfanew);
//		return;
//	}
//
//	nth = (IMAGE_NT_HEADERS *) data;
////	monitor_printf(default_mon, "Loaded: %s, size: %d\n", fullname, nth->OptionalHeader.SizeOfImage);
//	file_data = (uint8_t *) malloc (nth->OptionalHeader.SizeOfImage);
//	if(file_data == NULL) {
//		monitor_printf(default_mon, "malloc failed in wl_load_module_notify. :'(\n");
////		vm_stop(0);
//	}
//	extract_export_table_from(nth, cr3, base, mod);
//	if(file_data)
//		free(file_data);
//	file_data = NULL;
//}


static int db_callback(void *NotUsed, int argc, char **argv, char **szColName){
	ifstream file;
	char msg[256];
	stringstream ss;
	uint32_t offset;
	ss << std::hex <<argv[1]; // argv[1] is offset, argv[0] is funcname
	ss >> offset;
	char* name = strrchr(argv[2],'/') + 1;
	sprintf(msg, "F %s %s %08x\n", name, argv[0], offset);
	//monitor_printf(default_mon,"%s", msg);
	handle_guest_message(msg);
	return 0;
}

// query symbols from database in /i386_soft_mmu directory
void extract_funcs(process *proc, uint32_t base, module *mod){

	string line, function;
	char lower_name[33];
	std::stringstream ss;

	for(unsigned int i =0; i < sizeof(mod->name) + 1; ++i){
		if(mod->name[i] == ' '){
			return;
		}
		lower_name[i] = tolower(mod->name[i]);
	}
	sqlite3 *db; // sqlite3 db struct
	char *zErrMsg = 0;
	char select[512];
	sprintf(select, "SELECT funcname, offset, mname FROM symbols WHERE mname IN ( SELECT modulename FROM modules WHERE modname='%s' AND codesize=%u AND checksum=%u )",
				lower_name, mod->codesize, mod->checksum);
	// Open the test.db file
	if( sqlite3_open("Symbols.db", &db) != SQLITE_OK){
		//monitor_printf(default_mon,"can't open: %s\n", sqlite3_errmsg(db));
	}else{
		if(sqlite3_exec(db, select, db_callback, 0, &zErrMsg) != SQLITE_OK){
		  //std::cout << "SQL Error: " << zErrMsg << std::endl;
		  sqlite3_free(zErrMsg);
		}
	}
	sqlite3_close(db);
}

int procmod_insert_modinfoV(uint32_t pid, uint32_t base, module *mod) {

	unordered_map<uint32_t, process *>::iterator iter = process_pid_map.find(
			pid);
	process *proc;

	if (iter == process_pid_map.end()) //pid not found
		return -1;

	proc = iter->second;

	//Now the pages within the module's memory region are all resolved
	//We also need to removed the previous modules if they happen to sit on the same region
	for (uint32_t vaddr = base; vaddr < base + mod->size; vaddr += 4096) {
		proc->resolved_pages.insert(vaddr >> 12);
		proc->module_list.erase(vaddr);
	}

	//Now we insert the new module in module_list
	proc->module_list[base] = mod;

	//Check if symbols have already been extracted
	if (findModule(mod->fullname) == NULL) {

		if (GuestOS_index_c <= 3) { //This is windows therefore a PE file
			//extract_PE_symtab(proc, base, mod);
			extract_PE_info(proc, base, mod);
			extract_funcs(proc, base, mod);
		} else {
			//TODO: extract elf symtab
		}
	}

	return 0;
}

int procmod_remove_modinfoV(uint32_t pid, uint32_t base){
    unordered_map < uint32_t, process * >::iterator iter =
	process_pid_map.find(pid);
    process *proc;

    if (iter == process_map.end())	//pid not found
	return -1;

    proc = iter->second;
    proc->module_list.erase(base);
    return 0;
}


int removeProcV(uint32_t pid){
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


int procmod_remove_allV(){
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
	if (iter == process_pid_map.end()){	//pid not found
	    return addProcV(proc);
	}else{
	    removeProcV(proc->pid);
	    addProcV(proc);
	}
	return 0;
}

int addFuncV(module *mod,string name,uint32_t offset){
	unordered_map < string, uint32_t >::iterator iter =(mod->function_map_name).find(name);
	unordered_map < uint32_t, string >::iterator iter1 =(mod->function_map_offset).find(offset);
    if(iter!=(mod->function_map_name).end() || iter1!=(mod->function_map_offset).end())
    	return -1;
    mod->function_map_name[name]=offset;
    mod->function_map_offset[offset]=name;
    return 0;
}

int removeFuncV(module *mod,uint32_t offset){
	unordered_map < uint32_t, string >::iterator iter1 =
				(mod->function_map_offset).find(offset);
	if(iter1==(mod->function_map_offset).end())
	    	return -1;
	string name = iter1->second;
	(mod->function_map_offset).erase(iter1);
	removeFuncNameV(mod,name);
	return 0;
}

int removeFuncNameV(module *mod,string name){
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
				     unordered_map< uint32_t,module * >&module_list){
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
				      unordered_map < uint32_t,module * >&module_list){
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
    if (iter == process_map.end()){
    	return NULL;
    }
    process *proc = iter->second;
    dmodule *mod=find_module_byeipV(eip, proc->module_list);
    if(mod!=NULL){
    	return mod;
    }
    return NULL;
}

dmodule *locate_module_bynameV(char *name, uint32_t pid){
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

dprocess* findProcessBYCR3V(uint32_t cr3) {
	unordered_map<uint32_t, process *>::iterator iter = process_map.find(cr3);
	if (iter == process_map.end())
		return NULL;

	process *proc = iter->second;
	dprocess *temp = new dprocess();
	temp->cr3 = proc->cr3;
	strcpy(temp->name, proc->name);
	temp->parent_pid = proc->parent_pid;
	temp->pid = proc->pid;
	return temp;
}

dprocess* findProcessByNameV(char *name){
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

dprocess* findProcessByPidV(uint32_t pid){
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

int findProcessByPidH(uint32_t pid){
	unordered_map < uint32_t, process * >::iterator iter =
		process_pid_map.find(pid);

	if (iter == process_pid_map.end()) {
		return 0;
	}

	return 1;
}

void get_proc_modulesV(uint32_t pid, dmodule mi_array[], int size){
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

static void block_end_cb(DECAF_Callback_Params* temp)
{
    int i=0;
    int cflag=0;
	for(i=0; i<sizeof(handle_funds_c)/sizeof(handle_funds_c[0]); i++)
	{
		if(handle_funds_c[i].find(temp->ie.env,insn_handle_c)==1)
		{
			GuestOS_index_c=i;
			cflag=1;
		}
	}
	if(GuestOS_index_c == 0||GuestOS_index_c == 1)
		monitor_printf(default_mon, "its win xp \n");
	else if(GuestOS_index_c == 2||GuestOS_index_c == 3)
		monitor_printf(default_mon, "its win 7 \n");
	//else if(GuestOS_index_c == 4)
	//	monitor_printf(default_mon, "its linux \n");

	if(cflag)
	{
		DECAF_unregister_callback(DECAF_BLOCK_END_CB, insn_handle_c);
		handle_funds_c[GuestOS_index_c].init();
	}
}


void vmi_init()
{
	monitor_printf(default_mon, "inside vmi init \n");
	insn_handle_c = DECAF_register_callback(DECAF_BLOCK_END_CB, block_end_cb, NULL);
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

process * findProcessByCR3(uint32_t cr3)
{
    unordered_map < uint32_t, process * >::iterator iter =
	process_map.find(cr3);

    if (iter != process_map.end())
		return iter->second;

	return NULL;
}


int findCr3(uint32_t cr3){
	unordered_set<uint32_t>::const_iterator got = cr3s.find (cr3);
	if(got==cr3s.end()){
		return 0;
	}
	return 1;
}

void insertCr3(uint32_t cr3){
	cr3s.insert(cr3);
}

int addCr3info(cr3_info_c *cr3info){
	if(cr3info==NULL)
	    return -1;

	cr3infos[cr3info->value] = cr3info;
	return 1;
}

int findvaddrincr3(uint32_t cr3,target_ulong vaddr){
	unordered_map < uint32_t,cr3_info_c * >::iterator iter =
		cr3infos.find(cr3);
	if (iter != cr3infos.end()){
		unordered_set<target_ulong>::const_iterator got = iter->second->vaddr_tbl->find(vaddr);
		if(got!=iter->second->vaddr_tbl->end()){
			return 1;
		}
	}
	return 0;
}

void insertvaddrincr3(uint32_t cr3,target_ulong vaddr){
	unordered_map < uint32_t, cr3_info_c * >::iterator iter =
			cr3infos.find(cr3);
	if (iter != cr3infos.end()){
		iter->second->vaddr_tbl->insert(vaddr);
	}
}

int addModule(module *mod){
	if(mod==NULL)
		return -1;
	string temp(mod->fullname);
	unordered_map < string, module * >::iterator iter = module_name.find(temp);
	if (iter != module_name.end()){
		return -1;
	}
	module_name[temp]=mod;
	return 1;
}

module* findModule(char *name){
	if(name==NULL)
		return NULL;
	string temp(name);
	unordered_map < string, module * >::iterator iter =
		module_name.find(temp);
	if (iter != module_name.end()){
		return iter->second;
	}
	return NULL;
}
#endif

