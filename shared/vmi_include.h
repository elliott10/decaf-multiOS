/*
 * vmi_include.h
 *
 *  Created on: Jan 30, 2013
 *      Author: haoru
 */


#ifndef VMI_INCLUDE_H_
#define VMI_INCLUDE_H_

#include <stdio.h>

#include <string.h>

#include "monitor.h"
#include "shared/DECAF_types.h"


#ifdef __cplusplus
extern "C" {
#endif
//unordered_map < uint32_t, process_info_t * >process_map;
typedef struct _dmodule{
char name[32];
char fullname[128];
uint32_t base;
uint32_t size;
} dmodule;

typedef struct {
    uint32_t cr3;
    uint32_t pid;
    uint32_t parent_pid;
    uint32_t EPROC_base_addr;
    char name[16];
} dprocess;



extern dprocess* findProcessByNameV(char *name);
extern dprocess* findProcessByPidV(uint32_t pid);
extern dprocess* findProcessBYCR3V(uint32_t cr3);
extern dprocess *find_all_processes_infoV(size_t * num_proc);
extern int get_loaded_modules_countV(uint32_t pid);
extern void get_proc_modulesV(uint32_t pid, dmodule *buf, int size);
extern dmodule *locate_moduleV(uint32_t eip, uint32_t cr3);
extern dmodule *locate_module_bynameV(char *name, uint32_t pid);
void vmi_init();
#ifdef __cplusplus
};
#endif


#endif /* VMI_INCLUDE_H_ */

