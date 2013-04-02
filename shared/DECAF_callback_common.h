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
/**
 * @author Lok Yan
 * @date 12 OCT 2012
 */

#ifndef DECAF_CALLBACK_COMMON_H
#define DECAF_CALLBACK_COMMON_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "cpu.h"
#include "shared/DECAF_types.h"

//#include "test_tlb_cb.h"

typedef enum {
        DECAF_BLOCK_BEGIN_CB = 0,
        DECAF_BLOCK_END_CB,
        DECAF_INSN_BEGIN_CB,
        DECAF_INSN_END_CB,
        DECAF_MEM_READ_CB,
        DECAF_MEM_WRITE_CB,
        DECAF_EIP_CHECK_CB,
        DECAF_KEYSTROKE_CB,//keystroke event
        DECAF_NIC_REC_CB,
        DECAF_NIC_SEND_CB,
//#ifdef COMPONENT_VMI
        DECAF_TLB_EXEC_CB,
//#endif

        DECAF_LAST_CB, //place holder for the last position, no other uses.
} DECAF_callback_type_t;


//Optimized Callback type
typedef enum _OCB_t {
  /**
   * Optimized Callback Condition - Const - The value associated with this flag needs an exact match
   */
  OCB_CONST = 2,
  /**
   * Optimized callback Condition - Page - A match is found as long as the page numbers match
   */
  OCB_PAGE = 4,
  /**
   * Not used yet
   */
  OCB_CONST_NOT = 3,
  /**
   * Not used yet
   */
  OCB_PAGE_NOT = 5,
  /**
   * Optimized Callback Condition - Everything!
   */
  OCB_ALL = -1
} OCB_t;
// HU- for memory read/write callback.Memory be read/written at different grains
//(byte,word,long,quad)
typedef enum{
	DECAF_BYTE=1,
	DECAF_WORD=2,
	DECAF_LONG=4,
	DECAF_QUAD=8,
} DATA_TYPE;

typedef struct _DECAF_Block_Begin_Params
{
  CPUState* env;
  TranslationBlock* tb;
}DECAF_Block_Begin_Params;

//#ifdef COMPONENT_VMI
typedef struct _DECAF_Tlb_Exec_Params
{
	CPUState *env;
	gva_t vaddr;  //Address loaded to tlb exec cache
} DECAF_Tlb_Exec_Params;
//#endif

typedef struct _DECAF_Block_End_Params
{
  CPUState* env;
  TranslationBlock* tb;
  //THIS IS A PC value - NOT EIP!!!!
  gva_t cur_pc;
  gva_t next_pc;
} DECAF_Block_End_Params;

typedef struct _DECAF_Insn_Begin_Params
{
  CPUState* env;
} DECAF_Insn_Begin_Params;

typedef struct _DECAF_Insn_End_Params
{
  CPUState* env;
} DECAF_Insn_End_Params;
typedef struct _DECAF_Mem_Read_Params
{
	gva_t virt_addr;
	gpa_t phy_addr;
	DATA_TYPE dt;

}DECAF_Mem_Read_Params;
typedef struct _DECAF_Mem_Write_Params
{
	gva_t virt_addr;
	gpa_t phy_addr;
	DATA_TYPE dt;
}DECAF_Mem_Write_Params;
typedef struct _DECAF_EIP_Check_Params
{
	gva_t eip;
}DECAF_EIP_Check_Params;
typedef struct _DECAF_Keystroke_Params
{
	int32_t keycode;
	uint32_t *taint_mark;//mark if this keystroke should be monitored

}DECAF_Keystroke_Params;

typedef struct _DECAF_Nic_Rec_Params
{
	uint8_t *buf;
	int32_t size;
	int32_t cur_pos;
	int32_t start;
	int32_t stop;
}DECAF_Nic_Rec_Params;

typedef struct _DECAF_Nic_Send_Params
{
	uint32_t addr;
	int size;
	uint8_t *buf;
}DECAF_Nic_Send_Params;

//LOK: A dummy type
typedef union _DECAF_Callback_Params
{
  DECAF_Block_Begin_Params bb;
  DECAF_Block_End_Params be;
  DECAF_Insn_Begin_Params ib;
  DECAF_Insn_End_Params ie;
  DECAF_Mem_Read_Params mr;
  DECAF_Mem_Write_Params mw;
  DECAF_EIP_Check_Params ec;
  DECAF_Keystroke_Params ks;
  DECAF_Nic_Rec_Params nr;
  DECAF_Nic_Send_Params ns;
//#ifdef COMPONENT_VMI
  DECAF_Tlb_Exec_Params tx;
//#endif
} DECAF_Callback_Params;

typedef void (*DECAF_callback_func_t)(DECAF_Callback_Params*);


#ifdef __cplusplus
}
#endif

#endif//DECAF_CALLBACK_COMMON_H
