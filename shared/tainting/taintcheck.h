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
/// @file taintcheck.h
/// @author: Heng Yin <hyin@ece.cmu.edu>
/// \defgroup taintcheck taintcheck: Dynamic Taint Analysis Engine

//This file needs to be removed --Heng
//uncomment
#ifndef _TAINTCHECK_H_INCLUDED_
#define _TAINTCHECK_H_INCLUDED_

#include "shared/tainting/tainting.h"
//#include "cpu.h" // AWH
//#include "taintcheck_types.h"

//////////////////////////////////////////////////
// DEFINES 
//////////////////////////////////////////////////


/*!
 An internal data structure for holding 64-byte taint information in memory
 */

#ifdef TARGET_X86_64
#define CPU_NUM_REGS 16
#else
#define CPU_NUM_REGS 8
#endif //TARGET_X86_64


#ifdef IMPACT_ANALYSIS
extern int impact_propagate;
#endif

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus


// AWH extern int insn_tainted; // already defined in taintcheck_opt.h

/////////////////////////////////////////////////////////
// PROTOTYPES
/////////////////////////////////////////////////////////

/// Obtain taint information of a memory region by its physical address
///
/// @param addr physical address
/// @param size size of memory region
/// @param records the output buffer for storing taint records
/// @retval bitmap that indicates which bytes are tainted
///
/// @ingroup taintcheck
uint64_t taintcheck_memory_check(uint32_t addr, int size,
                                 uint8_t * records);

/// Obtain taint information of a register
///
/// @param reg index of a full register, such as R_EAX, R_EBX
/// @param offset offset within a full register, e.g., AH has offset 1
/// @param size register size, e.g., the size of AX is 2
/// @param records output buffer for storing taint records
/// @retval bitmap that indicates which bytes are tainted
///
/// @ingroup taintcheck
uint64_t taintcheck_register_check(int reg, int offset, int size,
                                   uint8_t * records);

/// Set taint information of a register
///
/// @param reg index of a full register, such as R_EAX, R_EBX
/// @param offset offset within a full register, e.g., AH has offset 1
/// @param size register size, e.g., the size of AX is 2
/// @param taint bitmap that indicates which bytes are tainted
/// @param records user-specified buffer for storing taint records
/// @retval always 0
///
/// @ingroup taintcheck
int taintcheck_taint_register(int reg, int offset, int size,
                              uint8_t taint, uint8_t * records);

/// Set taint information of a register
///
/// @param reg index of a full register, such as R_EAX, R_EBX
/// @param offset offset within a full register, e.g., AH has offset 1
/// @param size register size, e.g., the size of AX is 2
///
/// @ingroup taintcheck
void taintcheck_reg_clean(int reg, int offset, int size);

/// Set taint information of a memory region by its physical address
///
/// @param addr physical address of memory region
/// @param size size of memory region
/// @param taint bitmap that indicates which bytes are tainted
/// @param records user-specified buffer for storing taint records
/// @retval always 0
///
/// @ingroup taintcheck
int taintcheck_taint_memory(uint32_t addr, int size, uint64_t taint, uint8_t * records);

/// Clean taint information of a memory region by its physical address
///
/// @param addr physical address of memory region
/// @param size size of memory region
///
/// @ingroup taintcheck
void taintcheck_clean_memory(uint32_t addr, int size);

/// Clean taint information for entire memory and registers
/// @ingroup taintcheck
void taintcheck_clean_memreg(void);


/// Set taint information of a memory region by its virtual address
///
/// @param vaddr virtual address of memory region
/// @param size size of memory region
/// @param taint bitmap that indicates which bytes are tainted
/// @param records user-specified buffer for storing taint records
///
/// @ingroup taintcheck
void taintcheck_taint_virtmem(CPUState* env, uint32_t vaddr, uint32_t size, uint64_t taint, void *records);

/// Obtain taint information of a memory region by its virtual address
///
/// @param vaddr virtual address of memory region
/// @param size size of memory region
/// @param records the output buffer for storing taint records
/// @retval bitmap that indicates which bytes are tainted
///
/// @ingroup taintcheck
uint64_t taintcheck_check_virtmem(CPUState* env, uint32_t vaddr, uint32_t size, void *records);


/// This is the default taint_propagate implementation.
/// For a Temu plugin, if it does not need to handle it specially, 
/// it can specify this function in its callback function definitions
///
/// @param nr_src Number of source operands
/// @param src_oprnds source operand array
/// @param dst_oprnd destination operand
/// @param mode propagation mode
///
/// @ingroup taintcheck
void default_taint_propagate(int nr_src,
                            taint_operand_t * src_oprnds,
                            taint_operand_t * dst_oprnd,
                            int mode);

/// Get number of tainted bytes in the physcal memory
/// @retval number of tainted bytes
///
/// @ingroup taintcheck
int taintcheck_get_sizeof_taintmem(void);



int taintcheck_init(void);
int taintcheck_create(void);
void taintcheck_cleanup(void);

#if 1 // AWH TAINT_FLAGS
void taintcheck_update_eflags(uint32_t mask, int which) __attribute__((fastcall));

#ifndef CPU_I386_H //copy from cpu.h
#define CC_C   	0x0001
#define CC_P 	0x0004
#define CC_A	0x0010
#define CC_Z	0x0040
#define CC_S    0x0080
#define CC_O    0x0800
#endif

static inline void taintcheck_update_all_eflags(int which) 
{
  taintcheck_update_eflags( CC_C|CC_P|CC_A|CC_Z|CC_S|CC_O, which);
}

void taintcheck_reg2flag(int regidx, int size, uint32_t mask) 
	__attribute__((fastcall));

void taintcheck_flag2reg(uint32_t mask, int regidx, int size)
	__attribute__ ((fastcall));

#else
#define taintcheck_flag2reg(mask, reg, size) \
	clean_register_slow(reg, size, 0)

#endif


void do_info_taintmem(void);
int taintcheck_taint_disk(uint64_t index, uint64_t taint, int offset,
                          int size, uint8_t * record, void *bs);
uint64_t taintcheck_disk_check(uint64_t index, int offset, int size, uint8_t * record, void *bs);
int taintcheck_jnz_T0_label( void /*uint32_t t0 */ );
int taintcheck_check_eip(uint32_t reg);
#ifdef DEFINE_EIP_TAINTED
int taintcheck_check_eip(uint32_t reg);
#endif

int taintcheck_nic_writebuf(uint32_t addr, int size, uint64_t bitmap, uint8_t * records);       //size<=64
uint64_t taintcheck_nic_readbuf(uint32_t addr, int size, uint8_t * records);    //size<=64

#ifdef __cplusplus
}
#endif // __cplusplus

#endif
