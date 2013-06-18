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
//#include "sqlite3/sqlite3.h"
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
#include "linux_vmi.h"

#include "hookapi.h"
#include "read_linux.h"
#include "shared/vmi.h"
#include "shared/DECAF_main.h"
#include "shared/procmod.h"
#include "shared/function_map.h"
#include "shared/utils/SimpleCallback.h"


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
//static unordered_map <uint32_t,cr3_info_c *> cr3infos;

uint32_t GuestOS_index_c=11;
uintptr_t insn_handle_c = 0;

static os_handle_c handle_funds_c[] = {
#ifdef TARGET_I386
		{ WINXP_SP2_C, &find_winxpsp2, &win_vmi_init, },
		{ WINXP_SP3_C, &find_winxpsp3, &win_vmi_init, },
		{ WIN7_SP0_C, &find_win7sp0, &win_vmi_init, },
		{ WIN7_SP1_C, &find_win7sp1, &win_vmi_init, },
#endif
		//{ LINUX_2_6_C, &find_linux, &linux_vmi_init,},
};


#if 0
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
#endif

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



#if 0
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
#endif

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

#if 0
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
#endif

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

/*
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
} */

int addModule(module *mod, char *key){
	if(mod==NULL)
		return -1;
	string temp(key);
	unordered_map < string, module * >::iterator iter = module_name.find(temp);
	if (iter != module_name.end()){
		return -1;
	}
	module_name[temp]=mod;
	return 1;
}

module* findModule(char *key)
{
	string temp(key);
	unordered_map < string, module * >::iterator iter =
		module_name.find(temp);
	if (iter != module_name.end()){
		return iter->second;
	}
	return NULL;
}


void vmi_init()
{
	monitor_printf(default_mon, "inside vmi init \n");
	insn_handle_c = DECAF_register_callback(DECAF_BLOCK_END_CB, block_end_cb, NULL);
}

#endif

