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
 * ucore_procinfo.cpp
 *  
 *  Created on: September, 2013
 *      Author: Kevin Wang, Lok Yan
 */

#include <inttypes.h>
#include <string>
#include <list>
#include <vector>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <tr1/unordered_map>
#include <tr1/unordered_set>

#include <boost/foreach.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/ini_parser.hpp>
#include <boost/lexical_cast.hpp>

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
#include "DECAF_main.h"
#include "DECAF_target.h"
#ifdef __cplusplus
};
#endif /* __cplusplus */

#include "ucore_procinfo.h"
#include "hookapi.h"
#include "function_map.h"
#include "shared/vmi.h"
#include "DECAF_main.h"
#include "shared/utils/SimpleCallback.h"

#include "general_procinfo.h"


#if defined(TARGET_I386) 
  //this is the default value - but keep in mind that a custom built
  // kernel can change this
  #define UCORE_TARGET_PAGE_OFFSET 0xC0000000

  //defined this extra constant here so that the code
  // for isKernelAddress can be standardized
  #define UCORE_TARGET_KERNEL_IMAGE_START UCORE_TARGET_PAGE_OFFSET
  #define UCORE_TARGET_MIN_STACK_START 0xA0000000 //trial and error?
  #define UCORE_TARGET_KERNEL_IMAGE_SIZE (0)
#endif //target_i386
#define UCORE_TARGET_PGD_MASK TARGET_PAGE_MASK

//here is a simple function that I wrote for
// use in this kernel module, but you get the idea
// the problem is that not all addresses above
// 0xC0000000 are valid, some are not 
// depending on whether the virtual address range is used
// we can figure this out by searching through the page tables
static inline
int ucore_isKernelAddress(gva_t addr)
{
  return ( addr >=0xC0000000);
}

static inline int ucore_isKernelAddressOrNULL(gva_t addr)
{
  return ( (addr == (gva_t)0) || (ucore_isKernelAddress(addr)) ); 
}

inline int ucore_isStructKernelAddress(gva_t addr, target_ulong structSize)
{
  return ( ucore_isKernelAddress(addr) && ucore_isKernelAddress(addr + structSize) );
}

target_ulong ucore_getESP(CPUState *env)
{
  return DECAF_getESP(env);
}

gpa_t ucore_getPGD(CPUState *env)
{
  return (DECAF_getPGD(env) & UCORE_TARGET_PGD_MASK);
}

//We will have to replace this function with another one - such as
// read_mem in DECAF
static inline target_ulong ucore_get_target_ulong_at(CPUState *env, gva_t addr)
{
  target_ulong val;
  if (DECAF_read_mem(env, addr, sizeof(target_ulong), &val) < 0)
    return (INV_ADDR);
  return val;
}

static inline target_uint ucore_get_uint32_at(CPUState *env, gva_t addr)
{
  target_uint val;
  if (DECAF_read_mem(env, addr, sizeof(uint32_t), &val) < 0)
    return (INV_UINT);
  return val;
}

//Dangerous memcpy
static inline int ucore_get_mem_at(CPUState *env, gva_t addr, void* buf, size_t count)
{
  return DECAF_read_mem(env, addr, count, buf) < 0 ? 0 : count;
}


gpa_t ucore_findPGDFromMMStruct(CPUState * env, gva_t mm, UcoreProcInfo* pPI, int bDoubleCheck)
{

  return (INV_ADDR);
}

gva_t ucore_findMMStructFromTaskStruct(CPUState * env, gva_t ts, UcoreProcInfo* pPI, int bDoubleCheck)
{  

  return (INV_ADDR);
}

//the characteristic of task struct list is that next is followed by previous
//both of which are pointers
// furthermore, next->previous should be equal to self
// same with previous->next
//lh is the list_head (or supposedly list head)
int ucore_isListHead(CPUState * env, gva_t lh)
{

  return (0);
}
 
//TODO: DoubleCheck
//In this case, because there are so many different list_head
// definitions, we are going to use the first
// list head when searching backwards from the mm struct
//The signature that we use to find the task struct is the following (checked against
// version 3.9.5 and 2.6.32)
// depending on whether SMP is configured or not (in 3.9.5) we should see the following
// list_head (tasks) //8 bytes
// int PRIO (if SMP in 3.9.5) //4 bytes
// list_head (plist_node->plist_head->list_head in 2.6.32, and if SMP in 3.9.5) // 8 bytes
// list_head (same // 8 bytes
// spinlock* (optional in 2.6.32 if CONFIG_DEBUG_PI_LIST is set)
//So the idea is that we will see if we have a listhead followed by an int followed by 
// 2 list heads followed by mm struct (basically we search backwards from mmstruct
// if this pattern is found, then we should have the task struct offset
gva_t ucore_findTaskStructListFromTaskStruct(CPUState * env, gva_t ts, UcoreProcInfo* pPI, int bDoubleCheck)
{
  return (INV_ADDR);
}

//basically uses the threadinfo test to see if the current is a task struct
//We also use the task_list as an additional precaution since
// the offset of the threadinfo (i.e., stack) is 4 and the offset of 
// the task_struct in threadinfo is 0 which just happens to correspond
// to previous and next if this ts was the address of a list_head
// instead
//TODO: Find another invariance instead of the tasks list?
int ucore_isTaskStruct(CPUState * env, gva_t ts, UcoreProcInfo* pPI)
{

  return (0);
}

//the signature for real_parent is that this is the
// first item where two task_struct pointers are together
// real_parent is the first one (this should most likely
// be the same as parent, although not necessarily true)
//NOTE: We can also use the follow on items which are
// two list_heads for "children" and "sibling" as well 
// as the final one which is a task_struct for "group_leader"
gva_t ucore_findRealParentGroupLeaderFromTaskStruct(CPUState * env, gva_t ts, UcoreProcInfo* pPI)
{
  return (INV_ADDR);
}

//The characteristics of the init_task that we use are
//The mm struct pointer is NULL - since it shouldn't be scheduled?
//The parent and real_parent is itself
int ucore_isInitTask(CPUState * env, gva_t ts, UcoreProcInfo* pPI, int bDoubleCheck)
{
   return (0);
}

//pid and tgid are pretty much right on top of
// the real_parent, except for the case when a stack
// canary might be around. We will try to see
// if the canary is there - because canaries are supposed
// to be random - which is different from tgid and pid
// both of which are small numbers - so we try it this
// way
gva_t ucore_findPIDFromTaskStruct(CPUState * env, gva_t ts, UcoreProcInfo* pPI)
{
    return (INV_ADDR);
}

//we should be able to populate all of the mm struct field at once
// since we are mostly interested in the vma, and the start stack, brk and etc
// areas
//So basically what we are going to rely on is the fact that
// we have 11 unsigned longs:
// startcode, endcode, startdata, enddata (4)
// startbrk, brk, startstack (3)
// argstart, argend, envstart, envend (4)
//Meaning we have a lot of fields with relative 
// addresses in the same order as defined - except for brk
int ucore_isStartCodeInMM(CPUState * env, target_ulong* temp, target_ulong expectedStackStart)
{
    return (0);
}

#define MM_TEMP_BUF_SIZE 100
int ucore_populate_mm_struct_offsets(CPUState * env, gva_t mm, UcoreProcInfo* pPI)
{
  return (0);
}

//determines whether the address belongs to an RB Node
// RB as in Red Black Tree - it should work for any tree really
// maybe?
int ucore_isRBNode(CPUState * env, gva_t vma)
{
   return (0);
}

//This signature is different for 2.6 and for 3 
// The basic idea is that in 2.6 we have the mm_struct* vm_mm first
// followed by vm_start and vm_end (both ulongs)
// In 3 we have vm_start and vm_end first and vm_mm will come much later
//Now since vm_start is supposed to be the starting address of 
// the vm area - it must be a userspace virtual address. This is a perfect
// test to see which version of the kernel we are dealing with since
// the mm_struct* would be a kernel address
int ucore_populate_vm_area_struct_offsets(CPUState * env, gva_t vma, UcoreProcInfo* pPI)
{
  return (0);
}

//dentry is simple enough its just a pointer away
// first is the union of list_head and rcu_head
// list head is 2 pointers and rcu_head is 2 pointers
// one for rcu_head and another for the function pointer
//then struct path is itself two pointers thus
// its a constant - 3 pointers away
int ucore_getDentryFromFile(CPUState * env, gva_t file, UcoreProcInfo* pPI)
{
  return (0);
}




//runs through the guest's memory and populates the offsets within the
// ProcInfo data structure. Returns the number of elements/offsets found
// or -1 if error
int ucore_populate_kernel_offsets(CPUState *env, gva_t threadinfo, UcoreProcInfo* pPI)
{
  return (0);
}


int ucore_printProcInfo(UcoreProcInfo* pPI)
{
  if (pPI == NULL)
  {
    return (-1);
  }

  monitor_printf(default_mon,
      "    {  \"%s\", /* entry name */\n", pPI->strName
  );
  

  return (0);
}

void ucore_get_executable_directory(string &sPath)
{
  int rval;
  char szPath[1024];
  sPath = "";
  rval = readlink("/proc/self/exe", szPath, sizeof(szPath)-1);
  if(-1 == rval)
  {
    monitor_printf(default_mon, "can't get path of main executable.\n");
    return;
  }
  szPath[rval-1] = '\0';
  sPath = szPath;
  sPath = sPath.substr(0, sPath.find_last_of('/'));
  sPath += "/";
  return;
}

void ucore_get_procinfo_directory(string &sPath)
{
  ucore_get_executable_directory(sPath);
  sPath += "../shared/kernelinfo/procinfo_ucore/";
  return;
}

// given the section number, load the offset values
#define FILL_TARGET_ULONG_FIELD(field) pi.field = pt.get<target_ulong>(sSectionNum + #field)
void ucore_load_one_section(const boost::property_tree::ptree &pt, int iSectionNum, UcoreProcInfo &pi)
{
    string sSectionNum;

    sSectionNum = boost::lexical_cast<string>(iSectionNum);
    sSectionNum += ".";

    // fill strName field
    string sName;
    const int SIZE_OF_STR_NAME = 32;
    sName = pt.get<string>(sSectionNum + "strName");
    strncpy(pi.strName, sName.c_str(), SIZE_OF_STR_NAME);
    pi.strName[SIZE_OF_STR_NAME-1] = '\0';

    // fill other fields
    FILL_TARGET_ULONG_FIELD(initproc);
    FILL_TARGET_ULONG_FIELD(idleproc);
#if 0
    FILL_TARGET_ULONG_FIELD(init_task_size  );
    FILL_TARGET_ULONG_FIELD(ts_tasks        );
    FILL_TARGET_ULONG_FIELD(ts_pid          );
    FILL_TARGET_ULONG_FIELD(ts_tgid         );
    FILL_TARGET_ULONG_FIELD(ts_group_leader );
    FILL_TARGET_ULONG_FIELD(ts_thread_group );
    FILL_TARGET_ULONG_FIELD(ts_real_parent  );
    FILL_TARGET_ULONG_FIELD(ts_mm           );
    FILL_TARGET_ULONG_FIELD(ts_stack        );
    FILL_TARGET_ULONG_FIELD(ts_real_cred    );
    FILL_TARGET_ULONG_FIELD(ts_cred         );
    FILL_TARGET_ULONG_FIELD(ts_comm         );
    FILL_TARGET_ULONG_FIELD(cred_uid        );
    FILL_TARGET_ULONG_FIELD(cred_gid        );
    FILL_TARGET_ULONG_FIELD(cred_euid       );
    FILL_TARGET_ULONG_FIELD(cred_egid       );
    FILL_TARGET_ULONG_FIELD(mm_mmap         );
    FILL_TARGET_ULONG_FIELD(mm_pgd          );
    FILL_TARGET_ULONG_FIELD(mm_arg_start    );
    FILL_TARGET_ULONG_FIELD(mm_start_brk    );
    FILL_TARGET_ULONG_FIELD(mm_brk          );
    FILL_TARGET_ULONG_FIELD(mm_start_stack  );
    FILL_TARGET_ULONG_FIELD(vma_vm_start    );
    FILL_TARGET_ULONG_FIELD(vma_vm_end      );
    FILL_TARGET_ULONG_FIELD(vma_vm_next     );
    FILL_TARGET_ULONG_FIELD(vma_vm_file     );
    FILL_TARGET_ULONG_FIELD(vma_vm_flags    );
    FILL_TARGET_ULONG_FIELD(vma_vm_pgoff    );
    FILL_TARGET_ULONG_FIELD(file_dentry     );
    FILL_TARGET_ULONG_FIELD(dentry_d_name   );
    FILL_TARGET_ULONG_FIELD(dentry_d_iname  );
    FILL_TARGET_ULONG_FIELD(dentry_d_parent );
    FILL_TARGET_ULONG_FIELD(ti_task         );
#endif
}

// infer init_task_addr, use the init_task_addr to search for the corresponding
// section in procinfo.ini. If found, fill the fields in ProcInfo struct.
int ucore_load_proc_info(CPUState * env, UcoreProcInfo &pi)
{
  static bool bProcinfoMisconfigured = false;
  const int CANNOT_FIND_INIT_TASK_STRUCT = -1;
  const int CANNOT_OPEN_PROCINFO = -2;
  const int CANNOT_MATCH_PROCINFO_SECTION = -3;
  target_ulong tulInitTaskAddr;

  if(bProcinfoMisconfigured)
  {
   return CANNOT_MATCH_PROCINFO_SECTION;
  }

  string sProcInfoPath;
  boost::property_tree::ptree pt;
  ucore_get_procinfo_directory(sProcInfoPath);
  sProcInfoPath += "procinfo.ini";
  //monitor_printf(default_mon, "Procinfo path: %s\n",sProcInfoPath.c_str());
  // read procinfo.ini
  if (0 != access(sProcInfoPath.c_str(), 0))
  {
      monitor_printf(default_mon, "can't open %s\n", sProcInfoPath.c_str());
      return CANNOT_OPEN_PROCINFO;
  }
  boost::property_tree::ini_parser::read_ini(sProcInfoPath, pt);

  int cntSection = pt.get("info.total", 0);
  //monitor_printf(default_mon, "Total Sections: %d\n", cntSection);
  target_ulong ucore_name_addr = pt.get<target_ulong>("1.ucore_name");
  char ucore_name[11];
  int count=ucore_get_mem_at(env,ucore_name_addr,ucore_name,sizeof(ucore_name));
  if (count!=sizeof(ucore_name)){
      //monitor_printf(default_mon, "get GUEST ucore_name error %d, %s\n",count,ucore_name);
      return -1;
  }

  char ucore_id[11]="uCore lab8";
  if (strncmp(ucore_name,ucore_id,sizeof(ucore_id))!=0)
  {
    monitor_printf(default_mon,"ucore_name_addr %lu, ucore_name is %s || ucore_id is %s\n",ucore_name_addr,ucore_name,ucore_id);
    monitor_printf(default_mon, "VMI won't work.\nPlease configure procinfo.ini and restart DECAF.\n");
    bProcinfoMisconfigured = true;
    return CANNOT_MATCH_PROCINFO_SECTION;
  }

  ucore_load_one_section(pt, 1, pi);
  monitor_printf(default_mon, "Match %s\n", pi.strName);
  return 0;
}
