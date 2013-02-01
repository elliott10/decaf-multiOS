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
/********************************************************************
 * @brief This file contains the major functionality of maintaining taint 
 * information in registers and memory and devices (like NIC and HD).
 */
#if 0 //removed --Heng

#include "config.h"
#include <dlfcn.h>
#include <assert.h>
#include <sys/queue.h>
#include "hw/hw.h"
#include "qemu-common.h"
#include "sysemu.h"
#include "hw/hw.h" /* {de,}register_savevm */
#include "shared/DECAF_main.h"
#include "shared/tainting/tainting.h"
#include "shared/tainting/taintcheck_opt.h"
#include "shared/tainting/taintcheck.h"

#ifndef min
#define min(X,Y) ((X) < (Y) ? (X) : (Y))
#endif

#if 1 // AWH TAINT_ENABLED

#define TAINTCHECK_DEBUG 0

#ifdef IMPACT_ANALYSIS
int impact_propagate = 1;
#endif

#if 1 // AWH TAINT_FLAGS
uint32_t eflags_bitmap = 0; //!<bitmap for eflags
uint8_t * eflags_records = NULL; //!<taint records for eflags
#endif


uint64_t taintcheck_register_check(int reg, int offset, int size,
                                   uint8_t * records)
{
  uint64_t taint;
  taint = taint_reg_check_slow(reg, offset, size);
  if (taint && records)
    memcpy(records,
           regs_records + (reg * 4 +
                           offset) * taint_config->taint_record_size,
           size * taint_config->taint_record_size);
  return taint;
}

int taintcheck_taint_register(int reg, int offset, int size,
                              uint8_t taint, uint8_t * records)
{
  taint_register_slow(reg, size, offset, taint);
  if (taint) {
    memcpy(regs_records +
           (reg * 4 + offset) * taint_config->taint_record_size, records,
           size * taint_config->taint_record_size);
  }
  return 0;
}

void taintcheck_reg_clean(int reg, int offset, int size)
{
	clean_register_slow(reg, offset, size);
}


static inline int no_ones(uint8_t num)
{
	return ((num & 1)!=0) + ((num & 2)!=0) + ((num & 4)!=0) + ((num & 8)!=0);
}

int taintcheck_get_sizeof_taintmem(void)
{
	if(!taint_config || !tpage_table)
		return 0;

  int i, j, size = 0;

  for (i = 0; i < ram_size / 64; i++) {
    if (!tpage_table[i]) continue;

    for (j = 0; j < 16; j++) {
    	if(tpage_table[i]->bitmap[j] == 0)
    		continue;
    	size += no_ones(tpage_table[i]->bitmap[j]);
    }
  }
  return size;
}

void  taintcheck_mem2reg_nolookup(uint32_t paddr, uint32_t vaddr, int size, int reg);

int taintcheck_patch(CPUState* env)          //patch for keystroke propagation on Windows XP sp2 and sp3
{
#ifndef NO_PROPAGATE
  if (cpu_single_env->eip != 0xbf8a4bde &&
      cpu_single_env->eip != 0xbf84a74f && 
      cpu_single_env->eip != 0xbf848d65 &&  //for sp3
      cpu_single_env->eip != 0xbf848d1c ) // updated sp3
    return 0;
  
  uint32_t phys_addr, addr, addr2, phys_addr2;
  addr = cpu_single_env->regs[R_EBP] + 8;
  phys_addr = DECAF_get_phys_addr(env, addr);
  if (phys_addr == -1)
    return 0;

  if (!taint_mem_check(phys_addr, 1))
    return 0;

  addr2 = cpu_single_env->regs[R_EBP] + 0x14;
  if (DECAF_read_mem(env, addr2, 4,  &addr2) >= 0 &&
      (phys_addr2 = DECAF_get_phys_addr(env, addr2)) != -1) {
    taintcheck_mem2reg_nolookup(phys_addr, addr, 1, R_T0);
    taintcheck_mem_st_fast(R_T0, 1, /* AWH phys_ram_base*/ qemu_safe_ram_ptr(0) + phys_addr2);
  }
#endif
  return 0;
}


uint64_t taintcheck_memory_check(uint32_t addr, int size,
                                 uint8_t * records)
{
  uint64_t taint;
  int len, len2;
  uint32_t offset = addr & 63;
  tpage_entry_t *entry;

//  if (addr >= ram_size)
//   return 0;
  if (!(taint = taint_mem_check(addr, size)))
    return 0;

  if (!records)
    return taint;

  len = min(64 - offset, size);
  if ((entry = tpage_table[addr >> 6]))
    memcpy(records,
           entry->records + offset * taint_config->taint_record_size,
           len * taint_config->taint_record_size);
  len2 = size - len, entry = tpage_table[(addr >> 6) + 1];
  if (len2 && entry)
    memcpy(records + len * taint_config->taint_record_size,
           entry->records, len2 * taint_config->taint_record_size);
  return taint;
}

/** 
 * Taint a physical memory region:
 * addr: physical address
 * size:  size of memory to taint (size <= 4)
 * taint: bitmap of taint
 * records: an array of taint records
 */
int taintcheck_taint_memory(uint32_t addr, int size, uint64_t taint, uint8_t * records) 
{
  tpage_entry_t *entry;
  int len, len2, offset = addr & 63;

//  if (!TEMU_emulation_started || addr > ram_size)
//   return 0;
  if (!taint)
    clean_memory(addr, size);
  else {
      taint_memory(addr, size, taint);
      len = min(64 - offset, size);
      if ((entry = tpage_table[addr >> 6])) {
        memcpy(entry->records + offset * taint_config->taint_record_size,
             records, len * taint_config->taint_record_size);
      }
      len2 = size - len, entry = tpage_table[(addr >> 6) + 1];
      if (len2 && entry) {
        memcpy(entry->records,
             records + len * taint_config->taint_record_size,
             len2 * taint_config->taint_record_size);
      }
  }
  return 0;
}


//size could be anything
static void clean_range(uint32_t addr, int size)
{
	uint32_t temp = addr;
	uint32_t offset = addr & 3;
	uint32_t size1 = min(size, 4 - offset);
	if (offset) {
		clean_memory(addr, size1);
		temp = addr + size1;
	}

	for(; temp + 4 <= addr + size; temp += 4) {
		clean_memory_fast(temp);
	}

	size1 = addr + size - temp;
    if(size1)
    	clean_memory(temp, size1);
}

void taintcheck_clean_memory(uint32_t phys_addr, int size)
{
//  if (!TEMU_emulation_started) return;
  if (__builtin_expect(phys_addr + size >= ram_size, 0)) return;

  clean_range(phys_addr, size);
}


void taintcheck_clean_memreg(void)
{
  int i;
  memset(regs_bitmap, 0, MAX_REGS);
  for (i = 0; i < ram_size / 64; i++)
    if (tpage_table[i]) {
      qemu_free(tpage_table[i]);
      tpage_table[i] = 0;
    }
}


void taintcheck_taint_virtmem(CPUState* env, uint32_t vaddr, uint32_t size, uint64_t taint, void *records)
{
  uint32_t paddr =0, offset;
  uint32_t size1, size2;
  uint64_t taint1, taint2;
  
  paddr = DECAF_get_phys_addr(env, vaddr);
  if(paddr == -1) return;

  offset = vaddr & ~TARGET_PAGE_MASK;
  if(offset+size > TARGET_PAGE_SIZE) {
	size1 = TARGET_PAGE_SIZE - offset;
	size2 = size - size1;
	taint1 = size_to_mask(size1) & taint;
	taint2 = taint>>size1;
  } else 
	size1 = size, size2 = 0, taint1 = taint, taint2=0;
  taintcheck_taint_memory(paddr, size1, taint1, records);
  if(size2) {
	paddr = DECAF_get_phys_addr(env, (vaddr&TARGET_PAGE_MASK)+TARGET_PAGE_SIZE);
	if(paddr != -1)
	  taintcheck_taint_memory(paddr, size2, taint2, 
	  		records? records + size1*taint_config->taint_record_size : NULL);
  }
}

uint64_t taintcheck_check_virtmem(CPUState* env, uint32_t vaddr, uint32_t size, void *records)
{
  uint64_t ret	= 0;
  uint32_t paddr = 0, offset;
  uint32_t size1, size2;
  
  paddr = DECAF_get_phys_addr(env, vaddr);
  if(paddr == -1) return 0;

  offset = vaddr& ~TARGET_PAGE_MASK;
  if(offset+size > TARGET_PAGE_SIZE) {
	size1 = TARGET_PAGE_SIZE-offset;
	size2 = size -size1;
  } else 
	size1 = size, size2 = 0;

  ret = taintcheck_memory_check(paddr, size1, records);
  if(size2) {
	paddr = DECAF_get_phys_addr(env, (vaddr&TARGET_PAGE_MASK)+TARGET_PAGE_SIZE);
	if(paddr != -1)
	  ret |= taintcheck_memory_check(paddr,size2, 
	  		(uint8_t *)records+size1*taint_config->taint_record_size)<<size1;
  }

  return ret;
}



int taintcheck_jnz_T0_label(void)
{
  int res = 0;
  if (!should_monitor)
    return 0;

  if (taint_reg_check_fast(R_T0) && decaf_plugin && decaf_plugin->cjmp) {
	insn_tainted = 1; //set it to indicate cjmp propagating taint
    res = decaf_plugin->cjmp(cpu_single_env->regs[R_T0]);
    /* res = 1 or 2 */
    //if(jcc_inv) res ^= 3;
  }
  return res;
}

int taintcheck_check_eip(uint32_t reg)
{
#ifdef DEFINE_EIP_TAINTED
  uint8_t taint;
  if (!should_monitor
      || !(taint = taint_reg_check_fast(R_T0))
      || !taint_config->eip_tainted)
    return 0;

  int i;
  for (i = 0; i < 4; i++)
    if (taint & (1 << i)) {
      taint_config->eip_tainted(regs_records +
                               (R_T0 * 4 +
                                i) * taint_config->taint_record_size);
      break;
    }
#endif
#ifdef DEFINE_MEMREG_EIP_CHANGE
  uint8_t taint;
  if (!should_monitor)
    return 0;

  decaf_plugin->memreg_eip_change();

#endif
 
  return 0;
}

void do_info_taintmem(void)
{
  monitor_printf(default_mon, "Tainted memory: %d \n", taintcheck_get_sizeof_taintmem());
}


#endif

#endif
