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
 * DECAF_callback.c
 *
 *  Created on: Apr 10, 2012
 *      Author: heyin@syr.edu
 */
#include <sys/queue.h>
#include <stdio.h>
#include <inttypes.h>
#include "qemu-common.h"
#include "cpu-all.h"
#include "shared/DECAF_main.h"
#include "shared/DECAF_callback.h"
#include "shared/DECAF_callback_to_QEMU.h"
#include "shared/utils/HashtableWrapper.h"
#ifdef CONFIG_TCG_TAINT
#include "shared/tainting/analysis_log.h"
#endif /* CONFIG_TCG_TAINT */
#if 0 // AWH
#define PUSH_ALL() __asm__ __volatile__ ("push %rax"); \
__asm__ __volatile__ ("push %rbx"); \
__asm__ __volatile__ ("push %rcx"); \
__asm__ __volatile__ ("push %rdx"); \
__asm__ __volatile__ ("push %rbp"); \
__asm__ __volatile__ ("push %rdi"); \
__asm__ __volatile__ ("push %rsi"); \
__asm__ __volatile__ ("push %r8"); \
__asm__ __volatile__ ("push %r9"); \
__asm__ __volatile__ ("push %r10"); \
__asm__ __volatile__ ("push %r11"); \
__asm__ __volatile__ ("push %r12"); \
__asm__ __volatile__ ("push %r13"); \
__asm__ __volatile__ ("push %r14"); \
__asm__ __volatile__ ("push %r15");

#define POP_ALL() __asm__ __volatile__ ("pop %r15"); \
__asm__ __volatile__ ("push %r14"); \
__asm__ __volatile__ ("push %r13"); \
__asm__ __volatile__ ("push %r12"); \
__asm__ __volatile__ ("push %r11"); \
__asm__ __volatile__ ("push %r10"); \
__asm__ __volatile__ ("push %r9"); \
__asm__ __volatile__ ("push %r8"); \
__asm__ __volatile__ ("push %rsi"); \
__asm__ __volatile__ ("push %rdi"); \
__asm__ __volatile__ ("push %rbp"); \
__asm__ __volatile__ ("push %rdx"); \
__asm__ __volatile__ ("push %rcx"); \
__asm__ __volatile__ ("push %rbx"); \
__asm__ __volatile__ ("push %rax");
#endif // AWH

#if defined(TARGET_I386) && (HOST_LONG_BITS == 64)
//#warning 64-bit macro
#define PUSH_ALL() __asm__ __volatile__ ("push %rax\npush %rcx\npush %rdx");
#define POP_ALL() __asm__ __volatile__ ("pop %rdx\npop %rcx\npop %rax");
#elif defined(TARGET_I386) && (HOST_LONG_BITS == 32)
//#warning 32-bit macro
#define PUSH_ALL() __asm__ __volatile__ ("push %eax\npush %ecx\npush %edx");
#define POP_ALL() __asm__ __volatile__ ("pop %edx\npop %ecx\npop %eax");
#else
//#warning Dummy PUSH_ALL() and POP_ALL() macros
#define PUSH_ALL() ;
#define POP_ALL() ;
#endif // AWH

//LOK: The callback logic is separated into two parts
//  1. the interface between QEMU and callback
//    this is invoked during translation time
//  2. the interface between the callback and the plugins
//    this is invoked during execution time
//The basic idea is to provide a rich interface for users
//  while abstracting and hiding all of the details

//Currently we support callbacks for instruction begin/end and
// basic block begin and end. Basic block level callbacks can
// also be optimized. There are two types of optimized callbacks
// constant (OCB_CONST) and page (OCB_PAGE). The idea begin
// the constant optimized callback type is that
// function level hooking only needs to know when the function
// starts and returns, both of which are hard target addresses.
//The idea behind the page level callback is for API level
// instrumentation where modules are normally separated at the
// page level. Block end callbacks are a little bit special
// since the callback can be set for both the from and to
// addresses. In this way, you can specify callbacks only for
// the transitions between a target module and the libc library
// for example. For simplicity sake we only provide page-level optimized
// callback support for block ends. Supporting it at the individual
// address level seemed like overkill - n^2 possible combinations.
//Todo: Future implementations should include support for the NOT
// condition for the optimized callbacks. This capability can be used
// for specifying all transitions from outside of a module into a module.
// for example it would be specified as block end callbacks where from
// is NOT module_page and to is module_page.


//We begin by declaring the necessary data structures
// for determining whether a callback is necessary
//These are declared if all block begins and ends
// are needed.
static int bEnableAllBlockBeginCallbacks = 0;
//We keep a count of the number of registered callbacks that
// need all of the block begins and ends so that we can turn
// on or off the optimized callback interface. The complete
// translation cache is flushed when the count goes from 0 to 1
// and from 1 downto 0
static int enableAllBlockBeginCallbacksCount = 0;
static int bEnableAllBlockEndCallbacks = 0;
static int enableAllBlockEndCallbacksCount = 0;


//We use hashtables to keep track of individual basic blocks
// that is associated with a callback - we ignore
// the conditional that is registered with the callback 
// right now - that is the conditional has been changed
// into a simple "enable" bit. The reasoning is that the condition is controlled
// by the user, and so there is no way for us to update
// the hashtables accordingly.
//Specifically, we use a counting hashtable (essentially a hashmap)
// where the value is the number of callbacks that have registered for
// this particular condition. The affected translation block
// is flushed at the 0 to 1 or 1 to 0 transitions.
static CountingHashtable* pOBBTable;

//A second page table at the page level
//There are two different hashtables so that determining
// whether a callback is needed at translation time (stage 1)
// can be done in the order of - allBlockBegins, Page level and then
// individual address or constant level.
static CountingHashtable* pOBBPageTable;

//Similarly we declare hashtables for block end
// the unique aspect of these hashtables is that they are
// only defined at the page level AND they are defined
// for the block end source (i.e. the location of the current
// basic block), the block end target (i.e. where is the next
// basic block), and then a map that contains both.

//This first table is for block ends callbacks that only specify the
// from address - i.e. where the block currently is
static CountingHashtable* pOBEFromPageTable;

//This second table is for callbacks that only specify the to address
// that is where the next block is
static CountingHashtable* pOBEToPageTable;

//This third table is for callbacks that specify both the from and to
// addresses. The hashmap maps the "from" page to a hashtable of "to" pages
static CountingHashmap* pOBEPageMap;


//data structures for storing the userspace callbacks (stage 2)
typedef struct callback_struct{
	int *enabled;
	//the following are used by the optimized callbacks
	//BlockBegin only uses from - to is ignored
	//blockend uses both from and to
	gva_t from;
	gva_t to;
	OCB_t ocb_type;

	DECAF_callback_func_t callback;
	LIST_ENTRY(callback_struct) link;
}callback_struct_t;

//Each type of callback has its own callback_list
// The callback list is used to maintain the list of registered callbacks
// as well as their conditions. In essense, this data structure
// is used for interfacing with the user (stage 2)
static LIST_HEAD(callback_list_head, callback_struct) callback_list_heads[DECAF_LAST_CB];


//LOK: I turned this into a dumb function
// and so we can have the more specialized helper functions
// for the block begin and block end callbacks 
int DECAF_is_callback_needed(DECAF_callback_type_t cb_type)
{
  return !LIST_EMPTY(&callback_list_heads[cb_type]);
}

//here we search from the broadest to the narrowest
// to determine whether the callback is needed
int DECAF_is_BlockBeginCallback_needed(gva_t pc)
{
  //go through the page list first
  if (bEnableAllBlockBeginCallbacks)
  {
    return (1);
  }

  if (CountingHashtable_exist(pOBBPageTable, pc & TARGET_PAGE_MASK))
  {
    return (1);
  }

  if (CountingHashtable_exist(pOBBTable, pc))
  {
    return (1);
  }

  return 0;
}

int DECAF_is_BlockEndCallback_needed(gva_t from, gva_t to)
{
  if (bEnableAllBlockEndCallbacks)
  {
    return (1);
  }

  from &= TARGET_PAGE_MASK;
  //go through the page list first
  if (CountingHashtable_exist(pOBEFromPageTable, from))
  {
    return (1);
  }
  if (to == INV_ADDR) //this is a special case where the target is not known at translation time
  {
    return (0);
  }

  to &= TARGET_PAGE_MASK;
  if (CountingHashtable_exist(pOBEToPageTable, to))
  {
    return (1);
  }

  return (CountingHashmap_exist(pOBEPageMap, from, to));
}


DECAF_Handle DECAF_registerOptimizedBlockBeginCallback(
    DECAF_callback_func_t cb_func,
    int *cb_cond,
    gva_t addr,
    OCB_t type)
{

  callback_struct_t * cb_struct = (callback_struct_t *)malloc(sizeof(callback_struct_t));
  if (cb_struct == NULL)
  {
    return (DECAF_NULL_HANDLE);
  }

  //pre-populate the info
  cb_struct->callback = cb_func;
  cb_struct->enabled = cb_cond;
  cb_struct->from = addr;
  cb_struct->to = INV_ADDR;
  cb_struct->ocb_type = type;

  switch (type)
  {
    default:
    case (OCB_ALL):
    {
      //call the original
      bEnableAllBlockBeginCallbacks = 1;
      enableAllBlockBeginCallbacksCount++;

      //we need to flush if it just transitioned from 0 to 1
      if (enableAllBlockBeginCallbacksCount == 1)
      {
        //Perhaps we should flush ALL blocks instead of
        // just the ones associated with this env?
        DECAF_flushTranslationCache();
      }

      break;
    }
    case (OCB_CONST):
    {
      if (pOBBTable == NULL)
      {
        free(cb_struct);
        return (DECAF_NULL_HANDLE);
      }
      //This is not necessarily thread-safe
      if (CountingHashtable_add(pOBBTable, addr) == 1)
      {
        DECAF_flushTranslationBlock(addr);
      }
      break;
    }
    case (OCB_CONST_NOT):
    {
      break;
    }
    case (OCB_PAGE_NOT):
    {
      break;
    }
    case (OCB_PAGE):
    {
      addr &= TARGET_PAGE_MASK;
      if (pOBBPageTable == NULL)
      {
        free(cb_struct);
        return (DECAF_NULL_HANDLE);
      }

      //This is not necessarily thread-safe
      if (CountingHashtable_add(pOBBPageTable, addr) == 1)
      {
        DECAF_flushTranslationPage(addr);
      }
      break;
    }
  }

  //insert it into the list
  LIST_INSERT_HEAD(&callback_list_heads[DECAF_BLOCK_BEGIN_CB], cb_struct, link);

  return ((DECAF_Handle)cb_struct);
}

DECAF_Handle DECAF_registerOptimizedBlockEndCallback(
    DECAF_callback_func_t cb_func,
    int *cb_cond,
    gva_t from,
    gva_t to)
{

  callback_struct_t * cb_struct = (callback_struct_t *)malloc(sizeof(callback_struct_t));
  if (cb_struct == NULL)
  {
    return (DECAF_NULL_HANDLE);
  }

  //pre-populate the info
  cb_struct->callback = cb_func;
  cb_struct->enabled = cb_cond;
  cb_struct->from = from;
  cb_struct->to = to;
  cb_struct->ocb_type = OCB_ALL;

  if ( (from == INV_ADDR) && (to == INV_ADDR) )
  {
    enableAllBlockEndCallbacksCount++;
    bEnableAllBlockEndCallbacks = 1;
    if (enableAllBlockEndCallbacksCount == 1)
    {
      DECAF_flushTranslationCache();
    }
  }
  else if (to == INV_ADDR) //this means only looking at the FROM list
  {
    if (pOBEFromPageTable == NULL)
    {
      free(cb_struct);
      return(DECAF_NULL_HANDLE);
    }

    if (CountingHashtable_add(pOBEFromPageTable, from & TARGET_PAGE_MASK) == 1)
    {
      DECAF_flushTranslationPage(from);
    }
  }
  else if (from == INV_ADDR)
    //this is tricky, because it involves flushing the WHOLE cache
  {
    if (pOBEToPageTable == NULL)
    {
      free(cb_struct);
      return(DECAF_NULL_HANDLE);
    }

    if (CountingHashtable_add(pOBEToPageTable, to & TARGET_PAGE_MASK) == 1)
    {
      DECAF_flushTranslationCache();
    }
  }
  else
  {
    if (pOBEPageMap == NULL)
    {
      free(cb_struct);
      return(DECAF_NULL_HANDLE);
    }

    //if we are here then that means we need the hashmap
    if (CountingHashmap_add(pOBEPageMap, from & TARGET_PAGE_MASK, to & TARGET_PAGE_MASK) == 1)
    {
      DECAF_flushTranslationPage(from);
    }
  }

  //insert into the list
  LIST_INSERT_HEAD(&callback_list_heads[DECAF_BLOCK_END_CB], cb_struct, link);
  return ((DECAF_Handle)cb_struct);
}

//this is for backwards compatibility -
// for block begin and end - we make a call to the optimized versions
// for insn begin and end we just use the old logic
// for mem read and write ,use the old logic
DECAF_Handle DECAF_register_callback(
		DECAF_callback_type_t cb_type,
		DECAF_callback_func_t cb_func,
		int *cb_cond)
{
  if (cb_type == DECAF_BLOCK_BEGIN_CB)
  {
    return(DECAF_registerOptimizedBlockBeginCallback(cb_func, cb_cond, INV_ADDR, OCB_ALL));
  }

  if (cb_type == DECAF_BLOCK_END_CB)
  {
    return(DECAF_registerOptimizedBlockEndCallback(cb_func, cb_cond, INV_ADDR, INV_ADDR));
  }

  //if we are here then that means its either insn begin or end - this is the old logic no changes

  callback_struct_t * cb_struct =
      (callback_struct_t *)malloc(sizeof(callback_struct_t));

  if(cb_struct == NULL)
    return (DECAF_NULL_HANDLE);

  cb_struct->callback = cb_func;
  cb_struct->enabled = cb_cond;

//#ifdef COMPONENT_VMI
  if(cb_type == DECAF_TLB_EXEC_CB)
	  goto done; //Should not flush for tlb callbacks since they don't go into tb.
//#endif

  if(LIST_EMPTY(&callback_list_heads[cb_type]))
    DECAF_flushTranslationCache();

  LIST_INSERT_HEAD(&callback_list_heads[cb_type], cb_struct, link);

//#ifdef COMPONENT_VMI
done:
//#endif
  return (DECAF_Handle)cb_struct;
}


DECAF_errno_t DECAF_unregisterOptimizedBlockBeginCallback(DECAF_Handle handle)
{
  callback_struct_t *cb_struct;

  //to unregister the callback, we have to first find the
  // callback and its conditions and then remove it from the
  // corresonding hashtable

  LIST_FOREACH(cb_struct, &callback_list_heads[DECAF_BLOCK_BEGIN_CB], link) {
    if((DECAF_Handle)cb_struct != handle)
      continue;

    //now that we have found it - check out its conditions
    switch(cb_struct->ocb_type)
    {
      default: //same as ALL to match the register function
      case (OCB_ALL):
      {
        enableAllBlockBeginCallbacksCount--;
        if (enableAllBlockBeginCallbacksCount == 0)
        {
          bEnableAllBlockBeginCallbacks = 0;
          //if its now zero flush the cache
          DECAF_flushTranslationCache();
        }
        else if (enableAllBlockBeginCallbacksCount < 0)
        {
          //if it underflowed then reset to 0
          //this is really an error
          //notice I don't reset enableallblockbegincallbacks to 0
          // just in case
          enableAllBlockBeginCallbacksCount = 0;
        }
        break;
      }
      case (OCB_CONST):
      {
        if (pOBBTable == NULL)
        {
          return (NULL_POINTER_ERROR);
        }
        if (CountingHashtable_remove(pOBBTable, cb_struct->from) == 0)
        {
          DECAF_flushTranslationBlock(cb_struct->from);
        }
        break;
      }
      case (OCB_PAGE):
      {
        if (pOBBPageTable == NULL)
        {
          return (NULL_POINTER_ERROR);
        }
        if (CountingHashtable_remove(pOBBPageTable, cb_struct->from) == 0)
        {
          DECAF_flushTranslationPage(cb_struct->from);
        }
        break;
      }
    }

    //now that we cleaned up the hashtables - we should remove the callback entry
    LIST_REMOVE(cb_struct, link);
    //and free the struct
    free(cb_struct);

    return 0;
  }

  return -1;
}


int DECAF_unregisterOptimizedBlockEndCallback(DECAF_Handle handle)
{
  callback_struct_t *cb_struct;

  //to unregister the callback, we have to first find the
  // callback and its conditions and then remove it from the
  // corresonding hashtable

  LIST_FOREACH(cb_struct, &callback_list_heads[DECAF_BLOCK_END_CB], link) {
    if((DECAF_Handle)cb_struct != handle)
      continue;

    if ( (cb_struct->from == INV_ADDR) && (cb_struct->to == INV_ADDR) )
    {
      enableAllBlockEndCallbacksCount--;
      if (enableAllBlockEndCallbacksCount == 0)
      {
        DECAF_flushTranslationCache();
        bEnableAllBlockEndCallbacks = 0;
      }
      else if (enableAllBlockEndCallbacksCount < 0)
      {
        //this is really an error
        enableAllBlockEndCallbacksCount = 0;
      }
    }
    else if (cb_struct->to == INV_ADDR)
    {
      gva_t from = cb_struct->from & TARGET_PAGE_MASK;
      if (CountingHashtable_remove(pOBEFromPageTable, from) == 0)
      {
        DECAF_flushTranslationPage(from);
      }
    }
    else if (cb_struct->from == INV_ADDR)
    {
      gva_t to = cb_struct->to & TARGET_PAGE_MASK;
      if (CountingHashtable_remove(pOBEToPageTable, to) == 0)
      {
        DECAF_flushTranslationCache();
      }
    }
    else if (CountingHashmap_remove(pOBEPageMap, cb_struct->from & TARGET_PAGE_MASK, cb_struct->to & TARGET_PAGE_MASK) == 0)
    {
      DECAF_flushTranslationPage(cb_struct->from & TARGET_PAGE_MASK);
    }

    //we can now remove the entry
    LIST_REMOVE(cb_struct, link);
    //and free the struct
    free(cb_struct);

    return 0;
  }

  return (-1);
}

int DECAF_unregister_callback(DECAF_callback_type_t cb_type, DECAF_Handle handle)
{
  if (cb_type == DECAF_BLOCK_BEGIN_CB)
  {
    return (DECAF_unregisterOptimizedBlockBeginCallback(handle));
  }
  else if (cb_type == DECAF_BLOCK_END_CB)
  {
    return (DECAF_unregisterOptimizedBlockEndCallback(handle));
  }

  callback_struct_t *cb_struct;
  //FIXME: not thread safe
  LIST_FOREACH(cb_struct, &callback_list_heads[cb_type], link) {
    if((DECAF_Handle)cb_struct != handle)
      continue;

    LIST_REMOVE(cb_struct, link);
    free(cb_struct);

//#ifdef COMPONENT_VMI
    if(cb_type == DECAF_TLB_EXEC_CB)
    	goto done;
//#endif

    //Aravind - If going from non-empty to empty. Flush needed
    if(LIST_EMPTY(&callback_list_heads[cb_type]))
    {
      DECAF_flushTranslationCache();
    }

//#ifdef COMPONENT_VMI
done:
//#endif
    return 0;
  }

  return -1;
}

//#ifdef COMPONENT_VMI
void DECAF_invoke_tlb_exec_callback(CPUState *env, gva_t vaddr)
{
	  callback_struct_t *cb_struct;
	  DECAF_Callback_Params params;

	  if ((env == NULL) || (vaddr == 0)) {
	    return;
	  }
	  params.tx.env = env;
	  params.tx.vaddr = vaddr;
	  LIST_FOREACH(cb_struct, &callback_list_heads[DECAF_TLB_EXEC_CB], link) {
		  if(!cb_struct->enabled || *cb_struct->enabled) {
			  cb_struct->callback(&params);
		  }
	  }
}
//#endif

void helper_DECAF_invoke_block_begin_callback(CPUState* env, TranslationBlock* tb)
{
  callback_struct_t *cb_struct;
  DECAF_Callback_Params params;

  if ((env == NULL) || (tb == NULL))
  {
    return;
  }

PUSH_ALL()

  params.bb.env = env;
  params.bb.tb = tb;

  //FIXME: not thread safe
  LIST_FOREACH(cb_struct, &callback_list_heads[DECAF_BLOCK_BEGIN_CB], link) {
    // If it is a global callback or it is within the execution context,
    // invoke this callback
    if(!cb_struct->enabled || *cb_struct->enabled)
    {
      switch (cb_struct->ocb_type)
      {
        default:
        case (OCB_ALL):
        {
          cb_struct->callback(&params);
          break;
        }
        case (OCB_CONST):
        {
          if (cb_struct->from == tb->pc)
          {
            cb_struct->callback(&params);
          }
          break;
        }
        case (OCB_PAGE):
        {
          if ((cb_struct->from & TARGET_PAGE_MASK) == (tb->pc & TARGET_PAGE_MASK))
          {
            cb_struct->callback(&params);
          }
          break;
        }
      }
    }
  }
POP_ALL()
}

void helper_DECAF_invoke_block_end_callback(CPUState* env, TranslationBlock* tb, gva_t from)
{
  callback_struct_t *cb_struct;
  DECAF_Callback_Params params;

  if (env == NULL) return;

PUSH_ALL()

  params.be.env = env;
  params.be.tb = tb;
  params.be.cur_pc = from;

#ifdef TARGET_I386
  params.be.next_pc = env->eip + env->segs[R_CS].base;
#else
  fix this error
#endif

  //FIXME: not thread safe
  LIST_FOREACH(cb_struct, &callback_list_heads[DECAF_BLOCK_END_CB], link) {
    // If it is a global callback or it is within the execution context,
    // invoke this callback
    if(!cb_struct->enabled || *cb_struct->enabled)
    {
      if (cb_struct->to == INV_ADDR)
      {
        cb_struct->callback(&params);
      }
      else if ( (cb_struct->to & TARGET_PAGE_MASK) == (params.be.next_pc & TARGET_PAGE_MASK) )
      {
        if (cb_struct->from == INV_ADDR)
        {
          cb_struct->callback(&params);
        }
        else if ( (cb_struct->from & TARGET_PAGE_MASK) == (params.be.cur_pc & TARGET_PAGE_MASK) )
        {
          cb_struct->callback(&params);
        }
      }
    }
  }

POP_ALL()

}

void helper_DECAF_invoke_insn_begin_callback(CPUState* env)
{
	callback_struct_t *cb_struct;
	DECAF_Callback_Params params;

	if (env == 0) return;

PUSH_ALL()

	params.ib.env = env;

	//FIXME: not thread safe
	LIST_FOREACH(cb_struct, &callback_list_heads[DECAF_INSN_BEGIN_CB], link) {
		// If it is a global callback or it is within the execution context,
		// invoke this callback
		if(!cb_struct->enabled || *cb_struct->enabled)
			cb_struct->callback(&params);
	}
POP_ALL()
}

void helper_DECAF_invoke_insn_end_callback(CPUState* env)
{
	callback_struct_t *cb_struct;
        DECAF_Callback_Params params;

	if (env == 0) return;
PUSH_ALL()
	params.ie.env = env;

	//FIXME: not thread safe
	LIST_FOREACH(cb_struct, &callback_list_heads[DECAF_INSN_END_CB], link) {
		// If it is a global callback or it is within the execution context,
		// invoke this callback
		if(!cb_struct->enabled || *cb_struct->enabled)
			cb_struct->callback(&params);
	}
POP_ALL()
}

void helper_DECAF_invoke_mem_read_callback(gva_t virt_addr,gpa_t phy_addr,DATA_TYPE data_type)
{

	callback_struct_t *cb_struct;
	DECAF_Callback_Params params;
	params.mr.dt=data_type;
	params.mr.phy_addr=phy_addr;
	params.mr.virt_addr=virt_addr;

	//if (cpu_single_env == 0) return;

	//FIXME: not thread safe
	LIST_FOREACH(cb_struct, &callback_list_heads[DECAF_MEM_READ_CB], link)
	{
		// If it is a global callback or it is within the execution context,
		// invoke this callback
		if (!cb_struct->enabled || *cb_struct->enabled) {
			cb_struct->callback(&params);
		}
	}
}
void helper_DECAF_invoke_eip_check_callback(gva_t eip)
{
	callback_struct_t *cb_struct;
	DECAF_Callback_Params params;
	params.ec.eip = eip;
	//if (cpu_single_env == 0) return;

	//FIXME: not thread safe
	LIST_FOREACH(cb_struct, &callback_list_heads[DECAF_EIP_CHECK_CB], link)
	{
		// If it is a global callback or it is within the execution context,
		// invoke this callback
		if (!cb_struct->enabled || *cb_struct->enabled) {
			cb_struct->callback(&params);
		}
	}

}

void helper_DECAF_invoke_keystroke_callback(int keycode,uint32_t *taint_mark)
{
	callback_struct_t *cb_struct;
	DECAF_Callback_Params params;
	params.ks.keycode=keycode;
	params.ks.taint_mark=taint_mark;
	//if (cpu_single_env == 0) return;

	//FIXME: not thread safe
	LIST_FOREACH(cb_struct, &callback_list_heads[DECAF_KEYSTROKE_CB], link)
	{
		// If it is a global callback or it is within the execution context,
		// invoke this callback
		if (!cb_struct->enabled || *cb_struct->enabled) {
			cb_struct->callback(&params);
		}
	}

}

void helper_DECAF_invoke_mem_write_callback(gva_t virt_addr,gpa_t phy_addr,DATA_TYPE data_type)
{

	callback_struct_t *cb_struct;
	DECAF_Callback_Params params;
	params.mw.dt=data_type;
	params.mw.phy_addr=phy_addr;
	params.mw.virt_addr=virt_addr;

	//if (cpu_single_env == 0) return;

	//FIXME: not thread safe
	LIST_FOREACH(cb_struct, &callback_list_heads[DECAF_MEM_WRITE_CB], link)
	{
		// If it is a global callback or it is within the execution context,
		// invoke this callback
		if (!cb_struct->enabled || *cb_struct->enabled)
			cb_struct->callback(&params);
	}
}

void helper_DECAF_invoke_nic_rec_callback(uint8_t * buf,int size,int cur_pos,int start,int stop)
{
	callback_struct_t *cb_struct;
	DECAF_Callback_Params params;
	params.nr.buf=buf;
	params.nr.size=size;
	params.nr.cur_pos=cur_pos;
	params.nr.start=start;
	params.nr.stop=stop;

	//FIXME: not thread safe
	LIST_FOREACH(cb_struct, &callback_list_heads[DECAF_NIC_REC_CB], link)
	{
		// If it is a global callback or it is within the execution context,
		// invoke this callback
		if (!cb_struct->enabled || *cb_struct->enabled)
			cb_struct->callback(&params);
	}
}

void helper_DECAF_invoke_nic_send_callback(uint32_t addr,int size,uint8_t *buf)
{
	callback_struct_t *cb_struct;
	DECAF_Callback_Params params;
	params.ns.addr=addr;
	params.ns.size=size;
	params.ns.buf=buf;

	//FIXME: not thread safe
	LIST_FOREACH(cb_struct, &callback_list_heads[DECAF_NIC_SEND_CB], link)
	{
		// If it is a global callback or it is within the execution context,
		// invoke this callback
		if (!cb_struct->enabled || *cb_struct->enabled)
			cb_struct->callback(&params);
	}
}

void DECAF_callback_init(void)
{
  int i;

  for(i=0; i<DECAF_LAST_CB; i++)
    LIST_INIT(&callback_list_heads[i]);

  pOBBTable = CountingHashtable_new();
  pOBBPageTable = CountingHashtable_new();

  pOBEFromPageTable = CountingHashtable_new();
  pOBEToPageTable = CountingHashtable_new();
  pOBEPageMap = CountingHashmap_new();

  bEnableAllBlockBeginCallbacks = 0;
  enableAllBlockBeginCallbacksCount = 0;
  bEnableAllBlockEndCallbacks = 0;
  enableAllBlockEndCallbacksCount = 0;
}
