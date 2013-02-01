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
#ifndef _VMI_INCLUDED
#define _VMI_INCLUDED
#include <tr1/unordered_map>
#include <list>
#include <iostream>
//#include "vmi_include.h"
using namespace std;
using namespace std::tr1;
#ifdef __cplusplus
extern "C" {
#endif
#include "qemu-timer.h"
//#define KPCR_OFFSET 0x1c // base on rc3 at 0xffdff000
//#define KDVB_OFFSET 0x34 // base on KPCR
//#define PSLM_OFFSET 0x70
//#define PSAPH_OFFSET 0x78 // base on KDVB
#define NAMESIZEC 16
#define MAX_NAME_LENGTHC 64
//#define MAX_UNICODE_LENGTH 2*MAX_NAME_LENGTH
typedef enum {
	WINXP_SP2_C = 0, WINXP_SP3_C, WIN7_SP0_C, WIN7_SP1_C
} GUEST_OS_C;


/*typedef struct _module{
char name[512];
char fullname[1024];
uint32_t base;
uint32_t size;
unordered_map < uint32_t, string> function_map_offset;
unordered_map < string,uint32_t> function_map_name;
} module;

typedef struct {
    uint32_t cr3;
    uint32_t pid;
    uint32_t parent_pid;
    uint32_t EPROC_base_addr;
    char name[NAMESIZEC];
    list < module * >module_list;	//we make sure the list is sorted
} process;*/


class module{
public:
char name[64];
char fullname[128];
//uint32_t base;
uint32_t size;
unordered_map < uint32_t, string> function_map_offset;
unordered_map < string,uint32_t> function_map_name;
};

class process{
public:
    uint32_t cr3;
    uint32_t pid;
    uint32_t parent_pid;
    uint32_t EPROC_base_addr;
    char name[16];
    unordered_map < uint32_t,module * >module_list;	//we make sure the list is sorted

} ;

typedef struct _cr3_info_c{
	uint32_t value;
	unordered_set<uint32_t> *vaddr_tbl;

}cr3_info_c;
typedef struct os_handle_c {
	GUEST_OS_C os_info;
	int (*find)(CPUState *env,uintptr_t insn_handle);
	void (*init)();
} os_handle_c;




int addProcV(process *proc);
//int insert_module_infoV(list < module * >&module_list,module *mod);
//int remove_module_infoV(list < module * >&module_list, uint32_t base);
int procmod_insert_modinfoV(uint32_t pid,uint32_t base, module *mod);
int procmod_remove_modinfoV(uint32_t pid, uint32_t base);
int removeProcV(uint32_t pid);
int addModules(module *mod);
module* findModule(char *name);
int procmod_remove_allV();
int update_procV(process *proc);
int addFuncV(module *mod,string name,uint32_t offset);
int removeFuncV(module *mod,uint32_t offset);
int removeFuncNameV(module *mod,string name);
process* findProcessByNameH(char *name);
int findCr3(uint32_t cr3);
void insertCr3(uint32_t cr3);
int findProcessByPidH(uint32_t pid);
int addCr3info(cr3_info_c *cr3info);
int findvaddrincr3(uint32_t cr3,target_ulong vaddr);
void insertvaddrincr3(uint32_t cr3,target_ulong vaddr);
#ifdef __cplusplus
};
#endif

#endif
