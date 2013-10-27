/*
 * vmi.h
 *
 *  Created on: Jan 22, 2013
 *      Author: haoru
 */



#ifndef VMI_H_
#define VMI_H_

#include <iostream>
#include <list>
#include <tr1/unordered_map>
#include "vmi_include.h"
#include "monitor.h"

//#ifdef CONFIG_VMI_ENABLE
using namespace std;
using namespace std::tr1;

#ifdef __cplusplus
extern "C" {
#endif
#include "qemu-timer.h"
#define NAMESIZEC 16
#define MAX_NAME_LENGTHC 64

typedef enum {
	WINXP_SP2_C = 0, WINXP_SP3_C, WIN7_SP0_C, WIN7_SP1_C, LINUX_GENERIC_C,
} GUEST_OS_C;


class module{
public:
	char name[32];
	char fullname[256];
	//string fullname;
	uint32_t size;
	uint32_t codesize; // use these to identify dll
	uint32_t checksum;
	uint16_t major;
	uint16_t minor;
	bool	symbols_extracted;
	unordered_map < uint32_t, string> function_map_offset;
	unordered_map < string, uint32_t> function_map_name;
};

class process{
public:
    uint32_t cr3;
    uint32_t pid;
    uint32_t parent_pid;
    uint32_t EPROC_base_addr;
    char name[16];
    //map base address to module pointer
    unordered_map < uint32_t,module * >module_list;
    //a set of virtual pages that have been resolved with module information
    unordered_set< uint32_t > resolved_pages;
    unordered_set< uint32_t > pending_pages;
};
/*
typedef struct _cr3_info_c{
	uint32_t value;
	unordered_set<uint32_t> *vaddr_tbl;
}cr3_info_c; */

typedef struct os_handle_c{
	GUEST_OS_C os_info;
	int (*find)(CPUState *env,uintptr_t insn_handle);
	void (*init)();
} os_handle_c;

// add process info to process list
int addProcV(process *proc);

int findProcessByPidH(uint32_t pid);
process *findProcessByPid(uint32_t pid);

process * findProcessByCR3(uint32_t cr3);
// remove process from list
int removeProcV(uint32_t pid);

// add one module
int addModule(module *mod, char *key);
// find module by key
module* findModule(char *key);


// insert module info to a process
int procmod_insert_modinfoV(uint32_t pid,uint32_t base, module *mod);
// remove module info from a process
int procmod_remove_modinfoV(uint32_t pid, uint32_t base);

#if 0 //these APIs are now deprecated. use APIs in procmod.h instead

// list process which may be used by command ps
void listProcs(Monitor *mon);
// list all modules of specified pid process
void listModuleByPid(Monitor *mon, uint32_t pid);
//int insert_module_infoV(list < module * >&module_list,module *mod);
//int remove_module_infoV(list < module * >&module_list, uint32_t base);



int procmod_remove_allV();
int update_procV(process *proc);
int addFuncV(module *mod,string name,uint32_t offset);
int removeFuncV(module *mod,uint32_t offset);
int removeFuncNameV(module *mod,string name);
process* findProcessByNameH(char *name);

int findCr3(uint32_t cr3);
void insertCr3(uint32_t cr3);

int addCr3info(cr3_info_c *cr3info);
int findvaddrincr3(uint32_t cr3,target_ulong vaddr);
void insertvaddrincr3(uint32_t cr3,target_ulong vaddr);
#endif
// query symbols from db
//static void extract_funcs(process *proc, uint32_t base, module *mod);
#ifdef __cplusplus
};
#endif

#endif /* VMI_H_ */

//#endif /*CONFIG_VMI_ENABLE*/
