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
//Removed --Heng
//uncomment this
#ifndef TAINTCHECK_OPT_H_INCLUDED
#define TAINTCHECK_OPT_H_INCLUDED

#include "shared/DECAF_main.h" // AWH
#include "DECAF_main_x86.h"
#include "cpu.h" // AWH

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/*!
 An internal data structure for holding 64-byte taint information in memory
 */

typedef struct _tpage_entry {
  uint8_t bitmap[16];              /*!<one bit for each byte. */
  uint8_t records[0];           /*!<stores taint records defined by plugin. */
} tpage_entry_t;

#define PROP_MODE_MOVE 	0
/// This flag tells if emulation mode is enabled
// AWH extern int TEMU_emulation_started;
extern int plugin_taint_record_size;
//#define MAX_REGS (CPU_NUM_REGS + 8) //we assume up to 8 temporary registers
extern uint8_t regs_bitmap[];

extern uint8_t *regs_records; //!<taint records for registers

extern tpage_entry_t **tpage_table; //!<memory page table

extern uint64_t nic_bitmap[]; //!<bitmap for nic
extern uint8_t *nic_records; //!<taint records for nic

#if 1 // AWH TAINT_FLAGS
extern uint32_t eflags_bitmap; //!<bitmap for eflags
extern uint8_t * eflags_records; //!<taint records for eflags
#endif

extern int taintcheck_keyorigin;
extern int insn_tainted; //!<flag that indicates if the current instruction propagates taint
// AWH - use qemu_safe_ram_ptr(0) now - extern uint8_t * phys_ram_base;
// AWH extern ram_addr_t ram_size; // AWH - was an int

#define size_to_mask(size) ((1u << (size)) - 1u) //size<=4

#define REG_OFFSET(reg, ot) (((ot) == 0 && (reg) > 3)?  1 : 0)
#define REG_IND(reg, ot) (((ot)==0 && (reg) > 3)? ((reg) - 4): (reg))


int propagate_taint_info(int nr_src, void *src_oprnds, void *dst_oprnd, int mode);
uint8_t clear_zero(uint32_t value, int size, uint8_t taint);

#ifdef REG_CHECK
void reg_read_wrapper(uint32_t reg, int offset, int size);
void reg_write_wrapper(uint32_t reg, int offset, int size);
#endif

uint8_t __attribute__((fastcall)) taint_mem_check_slower(uint32_t addr, int size, int offset);
void __attribute__((fastcall)) taint_memory_slower(uint32_t addr, int size,
		int offset, uint8_t taint);
void __attribute__((fastcall)) clean_memory_slower(uint32_t addr, int size, int offset);


/* Taint propagation handlers */
void __attribute__ ((fastcall)) memld_fast_propagate_taint (uint32_t addr, int size, int reg, uint8_t mem_taint, uint8_t index_taint);
void __attribute__ ((fastcall)) memld_slow_propagate_taint (uint32_t addr, int size, int reg, int offset, uint8_t mem_taint, uint8_t index_taint);
void __attribute__ ((fastcall)) memst_fast_propagate_taint (uint32_t addr, int size, int reg, uint8_t taint);
void __attribute__ ((fastcall)) memst_slow_propagate_taint (uint32_t addr, int size, int reg, int offset, uint8_t taint);
void __attribute__ ((fastcall)) reg2reg_fast_propagate_taint (int sreg, int dreg, uint8_t taint);
void __attribute__ ((fastcall)) reg2reg_slow_propagate_taint (int sreg, int dreg, int soffset, int doffset, int size, uint8_t taint);
void __attribute__((fastcall)) fn3regs_propagate_taint(
		int sreg1, int sreg2, int sreg3, int dreg, int size, uint8_t taint1, uint8_t taint2, uint8_t taint3);
void __attribute__((fastcall)) fn2regs_propagate_taint(int sreg1, int sreg2, int dreg, int size, uint8_t taint1, uint8_t taint2);
void __attribute__((fastcall)) fn1reg_propagate_taint(int reg, int size);        //size<=4
void __attribute__((fastcall)) reg2TN_taint_propagate(int reg, int t, int size, uint8_t taint);
void __attribute__((fastcall)) regh2TN_taint_propagate(int reg, int t, uint8_t taint);

#if 0 // AWH - in TEMU_main.h
extern void asm_insn_begin(void);
extern void asm_insn_end(void);
extern int asm_block_begin(void);
extern void asm_block_end(void);
extern void asm_mem_read(uint32_t, uint32_t, int);
extern void asm_mem_write(uint32_t, uint32_t, int);
#endif // AWH

int taintcheck_nic_in(uint32_t addr, int size);
int taintcheck_nic_out(uint32_t addr, int size);
int taintcheck_chk_hdread(uint32_t paddr, int size, int64_t sect_num, void *s);
int taintcheck_chk_hdwrite(uint32_t paddr, int size, int64_t sect_num, void *s);
int taintcheck_chk_hdin(int size, int64_t sect_num, uint32_t offset, void *s);
int taintcheck_chk_hdout(int size, int64_t sect_num, uint32_t offset, void *s);
void* opt_qemu_mallocz(size_t size);

void taintcheck_bswap(int reg, int size) __attribute__((fastcall));
void taintcheck_clear_ones(int reg, int size, uint32_t val);
void taintcheck_clear_zeros(int reg, int size, uint32_t val);
void __attribute__((fastcall)) taintcheck_logic_T0_T1(void);
int taintcheck_patch(CPUState* env);
void taintcheck_update_cr3(void);
void taintcheck_code2TN(uint32_t vaddr, uint32_t regid, int size);
void taintcheck_r2r_slow(int s, int d, int ot);


static inline uint8_t taint_reg_check_fast(int reg) //Assume size is 4 bytes
{
  return regs_bitmap[reg];
}

static inline uint8_t taint_reg_check_slow(int regid, int offset, int size)
{
  return (regs_bitmap[regid]>>offset) & size_to_mask(size);
}

static inline void clean_register_fast(int reg)
{
  regs_bitmap[reg] = 0;
}

static inline void clean_register_slow(int reg, int size, int offset)
{
  regs_bitmap[reg] &= ~(size_to_mask(size) << offset);
}

static inline void taint_register_fast(int reg, uint8_t taint)
{
  regs_bitmap[reg] = taint;
}

static inline void taint_register_slow(int reg, int size, int offset, uint8_t taint)
{
  clean_register_slow(reg, size, offset);
  regs_bitmap[reg] |= (taint << offset);
}


///fast version memory taint check. Check 4 bytes without boundary check.
static inline uint8_t taint_mem_check_fast(uint32_t addr)
{
  tpage_entry_t * entry = tpage_table[addr>>6];
  return entry? (entry->bitmap[((addr & 63) >> 2)]): 0;
}


//This is the main function for checking memory taint with boundary check
//size <= 4
static inline uint8_t taint_mem_check(uint32_t addr, int size)
{
  uint8_t offset = addr & 3;

  if(offset == 0 && size == 4) //4-byte aligned and 4-byte access
    return taint_mem_check_fast(addr);

  return taint_mem_check_slower(addr, size, offset);
} 


////s
//fast version: 4-byte aligned and 4-byte access
static inline void taint_memory_fast(uint32_t addr, uint8_t taint)
{
  tpage_entry_t * entry = tpage_table[addr>>6];
  if(taint) {
	  if(!entry)
		  entry = tpage_table[addr>>6] =
  			  (tpage_entry_t *) opt_qemu_mallocz(sizeof(tpage_entry_t) + plugin_taint_record_size * 64);

	  entry->bitmap[(addr & 63) >> 2] = taint;
  }
}



//size <= 4
//This is the main function for setting memory taint
static inline void taint_memory(uint32_t addr, int size, uint8_t taint)
{
  uint8_t offset = addr & 3;
  if(offset == 0 && size == 4) //4-byte aligned and 4-byte access
    return taint_memory_fast(addr, taint);

  taint_memory_slower(addr, size, offset, taint);
}


//Assumption: Addr is 4 byte aligned. Sets taint info for 4 bytes at the address to 0.
static inline void clean_memory_fast(uint32_t addr)
{
  tpage_entry_t *entry;
  uint32_t index = addr >> 6;
  if((entry = tpage_table[index])) {
    entry->bitmap[(addr&63) >> 2] = 0; //Freeing if empty happens as a part of garbage collection
  }
}



static inline void clean_memory(uint32_t addr, int size)
{
	uint8_t offset = addr & 3;
	if(offset == 0 && size == 4) //4-byte aligned and 4-byte access
		return clean_memory_fast(addr);

	clean_memory_slower(addr, size, offset);
}

static inline void taintcheck_mem_clean(void *ptr, int size)
{
	uint32_t addr = (uint8_t *) ptr - /*AWH phys_ram_base*/ (uint8_t *)qemu_safe_ram_ptr(0);
	if(__builtin_expect(addr >= (unsigned int)ram_size, 0))
		return;
	clean_memory(addr, size);
}

static inline void taintcheck_mem_ld_fast(void *ptr, int size, int reg)
{
  uint32_t addr = (uint8_t *) ptr - /* AWH phys_ram_base*/ (uint8_t *)qemu_safe_ram_ptr(0);
  if(__builtin_expect(addr >= (unsigned int)ram_size, 0)) return;

#ifdef MEM_CHECK
  asm_mem_read(cpu_single_env->regs[R_A0], addr, size);
#endif

#ifndef NO_PROPAGATE
  uint8_t mem_taint = taint_mem_check(addr, size);
  uint8_t index_taint = taint_reg_check_fast(R_A0);
  uint8_t taint = index_taint? size_to_mask(size) : mem_taint;
  if(taint) {
	  taint_register_fast(reg, taint);
	  insn_tainted = 1;
	  memld_fast_propagate_taint(addr, size, reg, mem_taint, index_taint);
  } else
	  clean_register_fast(reg);
#endif
}

static inline void taintcheck_mem_ld_slow(void *ptr, int size, int reg, int offset)
{
  uint32_t addr = (uint8_t *) ptr - /* AWH phys_ram_base*/ (uint8_t *)qemu_safe_ram_ptr(0);
  if(__builtin_expect(addr >= (unsigned int)ram_size, 0)) return;

#ifdef MEM_CHECK
  asm_mem_read(cpu_single_env->regs[R_A0], addr, size);
#endif

#ifndef NO_PROPAGATE
  uint8_t mem_taint = taint_mem_check(addr, size);
  uint8_t index_taint = taint_reg_check_fast(R_A0);
  uint8_t taint = index_taint? size_to_mask(size) : mem_taint;
  if(!taint) {
	  clean_register_slow(reg, size, offset);
  } else {
	  taint_register_slow(reg, size, offset, taint);
	  insn_tainted = 1;
	  memld_slow_propagate_taint(addr, size, reg, offset, mem_taint, index_taint);
  }
#endif
}

static inline void taintcheck_mem_st_fast(int reg, int size, void *ptr) //size <= 4
{
	uint32_t addr = (uint8_t *) ptr - /* AWH phys_ram_base*/ (uint8_t *)qemu_safe_ram_ptr(0);
	if(__builtin_expect(addr >= (unsigned int)ram_size, 0)) return;

#ifndef NO_PROPAGATE
  uint8_t taint = taint_reg_check_fast(reg);
  taint &= size_to_mask(size);

#ifdef TAINTCHECK_CLEAR_ZERO
  taint = clear_zero(cpu_single_env->regs[reg], size, taint);
#endif

  (taint != 0)? taint_memory(addr, size, taint): clean_memory(addr, size);

  if(taint) {
	  insn_tainted = 1;
	  memst_fast_propagate_taint(addr, size, reg, taint);
  }
#endif
#ifdef MEM_CHECK
  asm_mem_write(cpu_single_env->regs[R_A0], addr, size);
#endif
}

static inline void taintcheck_mem_st_slow(int reg, int offset, int size, void *ptr)
{
	uint32_t addr = (uint8_t *) ptr - /* AWH phys_ram_base*/ (uint8_t *)qemu_safe_ram_ptr(0);
	if(__builtin_expect(addr >= (unsigned int)ram_size, 0)) return;

#ifndef NO_PROPAGATE
	uint8_t taint = taint_reg_check_slow(reg, offset, size);
	taint &= size_to_mask(size);
	(taint != 0)? taint_memory(addr, size, taint) : clean_memory(addr, size);

	if(taint) {
		insn_tainted = 1;
		memst_slow_propagate_taint(addr, size, reg, offset, taint);
	}
#endif
#ifdef MEM_CHECK
	asm_mem_write(cpu_single_env->regs[R_A0], addr, size);
#endif
}

//Size assumed 4 bytes
static inline void reg2reg_internal_fast(int sreg, int dreg)
{
  uint8_t taint;

//  if((regs_bitmap[sreg] | regs_bitmap[dreg]) == 0)
//	return;

  taint = taint_reg_check_fast(sreg);
  taint_register_fast(dreg, taint);

  if(taint) {
	  insn_tainted = 1;
	  reg2reg_fast_propagate_taint(sreg, dreg, taint);
  }
}

static inline void reg2reg_internal_slow(int sreg, int dreg, int soffset, int doffset, int size)
{
  uint8_t taint;

  if((regs_bitmap[sreg] | regs_bitmap[dreg]) == 0)
	return;

  taint = taint_reg_check_slow(sreg, soffset, size);
  taint_register_slow(dreg, size, doffset, taint);

  if(taint) {
	  insn_tainted = 1;
	  reg2reg_slow_propagate_taint(sreg, dreg, soffset, doffset, size, taint);
  }
}

static inline void taintcheck_fn3regs(int sreg1, int sreg2, int sreg3, int dreg, int size)     //size<=4
{
#ifdef REG_CHECK
  reg_read_wrapper(sreg1, 0, size);
  reg_read_wrapper(sreg2, 0, size);
  reg_read_wrapper(sreg3, 0, size);
#endif

#ifndef NO_PROPAGATE
  uint8_t taint1, taint2, taint3;
  if(size == 4) {
	  taint1 = taint_reg_check_fast(sreg1);
	  taint2 = taint_reg_check_fast(sreg2);
	  taint3 = taint_reg_check_fast(sreg3);
	  if (__builtin_expect(!taint1 && !taint2 && !taint3, 1)) {
		  clean_register_fast(dreg);
		  return;
	  }
	  taint_register_fast(dreg, size_to_mask(size));

  } else {
	  taint1 = taint_reg_check_slow(sreg1, 0, size);
	  taint2 = taint_reg_check_slow(sreg2, 0, size);
	  taint3 = taint_reg_check_slow(sreg3, 0, size);;
	  if (__builtin_expect(!taint1 && !taint2 && !taint3, 1)) {
		  clean_register_slow(dreg, size, 0);
		  return;
	  }
	  taint_register_slow(dreg, size, 0, size_to_mask(size));
  }
  insn_tainted = 1;
  fn3regs_propagate_taint(sreg1, sreg2, sreg3, dreg, size, taint1, taint2, taint3);
#endif

#ifdef REG_CHECK
  reg_write_wrapper(dreg, 0, size);
#endif
}

static inline void taintcheck_fn2regs(int sreg1, int sreg2, int dreg, int size)        //size<=4
{
#ifdef REG_CHECK
  reg_read_wrapper(sreg1, 0, size);
  reg_read_wrapper(sreg2, 0, size);
#endif

#ifndef NO_PROPAGATE
  uint8_t taint1, taint2;

  if(size == 4) {
	  taint1 = taint_reg_check_fast(sreg1);
	  taint2 = taint_reg_check_fast(sreg2);
	  if (__builtin_expect(taint1 == 0 &&  taint2== 0, 1)) {
		clean_register_fast(dreg);
		return;
	  }
	  taint_register_fast(dreg, size_to_mask(size));
  } else {
	  taint1 = taint_reg_check_slow(sreg1, 0, size);
	  taint2 = taint_reg_check_slow(sreg2, 0, size);
	  if (__builtin_expect(taint1 == 0 &&  taint2== 0, 1)) {
		  clean_register_slow(dreg, size, 0);
		  return;
	  }
	  taint_register_slow(dreg, size, 0, size_to_mask(size));
  }
  insn_tainted = 1;
  fn2regs_propagate_taint(sreg1, sreg2, dreg, size, taint1, taint2);
#endif

#ifdef REG_CHECK
  reg_write_wrapper(dreg, 0, size);
#endif
}

static inline void taintcheck_fn1reg(int reg, int size)        //size<=4
{
#ifdef REG_CHECK
  reg_read_wrapper(reg, 0, size);
#endif

#ifndef NO_PROPAGATE
  uint8_t taint;
  if(size == 4) {
	  taint = taint_reg_check_fast(reg);
	  if (__builtin_expect(!taint, 1))
		  return;

	  taint_register_fast(reg, size_to_mask(size));
  } else {
	  taint = taint_reg_check_fast(reg) & size_to_mask(size);
	  if (__builtin_expect(!taint, 1))
		  return;

	  taint_register_slow(reg, size, 0, size_to_mask(size));
  }
  insn_tainted = 1;
  fn1reg_propagate_taint(reg, size);
#endif

#ifdef REG_CHECK
  reg_write_wrapper(reg, 0, size);
#endif
}


static inline void taintcheck_reg2reg_fast(int sreg, int dreg)
{
#ifdef REG_CHECK
  reg_read_wrapper(sreg, 0, 4);
#endif

#ifndef NO_PROPAGATE
  reg2reg_internal_fast(sreg, dreg);
#endif

#ifdef REG_CHECK
  reg_write_wrapper(dreg, 0, 4);
#endif
}



static inline void taintcheck_reg2reg_slow(int sreg, int dreg, int soffset, int doffset, int size)
{
#ifdef REG_CHECK
   reg_read_wrapper(sreg, soffset, size);
#endif

#ifndef NO_PROPAGATE
  reg2reg_internal_slow(sreg, dreg, soffset, doffset, size);
#endif

#ifdef REG_CHECK
  reg_write_wrapper(dreg, doffset, size);
#endif
}



static inline void taintcheck_reg2TN(int reg, int t, int size)
{
#if REG_CHECK
   reg_read_wrapper(reg, 0, size);
#endif
#ifndef NO_PROPAGATE
  uint8_t taint = taint_reg_check_slow(reg, 0, size);
  taint_register_fast(t, taint);
  if(taint) {
	    insn_tainted = 1;
	    reg2TN_taint_propagate(reg, t, size, taint);
  }
#endif
}

static inline void taintcheck_regh2TN(int reg, int t)
{
#if REG_CHECK
   reg_read_wrapper(reg, 1, 1);
#endif
#ifndef NO_PROPAGATE
	uint8_t taint = taint_reg_check_slow(reg, 1, 1);
	taint_register_fast(t, taint);
    if(taint) {
    	insn_tainted = 1;
    	regh2TN_taint_propagate(reg, t, taint);
    }
#endif
}


static inline void taintcheck_i2r(int reg, int size, int offset)
{
#ifndef NO_PROPAGATE
    clean_register_slow(reg, size, offset);
#endif
#if REG_CHECK
   reg_write_wrapper(reg, offset, size);
#endif

}

// AWH - From osdep.h in TEMU
extern void qemu_free(void *ptr);
extern void *qemu_malloc(size_t size);
extern void *qemu_mallocz(size_t size);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif //TAINTCHECK_OPT_H_INCLUDED
