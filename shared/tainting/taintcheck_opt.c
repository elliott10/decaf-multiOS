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
#if 0 //removed --Heng

#include "config.h"
#include <dlfcn.h>
#include <assert.h>
#include <sys/queue.h>
#include "hw/hw.h"
#include "qemu-common.h"
#include "sysemu.h"
#include "hw/hw.h" /* {de,}register_savevm */
#include "cpu.h"
//#include "DECAF_main.h"
#include "shared/tainting/tainting.h"
#include "shared/tainting/taintcheck_opt.h"
#include "shared/tainting/taintcheck.h"
#include "shared/DECAF_vm_compress.h"

#if 1 // AWH TAINT_ENABLED

void taintcheck_mem2reg_nolookup(uint32_t paddr, uint32_t vaddr, int size, int reg);
void garbage_collect(void);

uint8_t regs_bitmap[MAX_REGS] __attribute__ ((aligned (4)));
uint8_t *regs_records = NULL; //!<taint records for registers
tpage_entry_t **tpage_table = NULL; //!<memory page table

uint64_t nic_bitmap[1024 * 32 / 64]; //!<bitmap for nic
uint8_t *nic_records = NULL; //!<taint records for nic
#ifndef min
#define min(X,Y) ((X) < (Y) ? (X) : (Y))
#endif

typedef struct disk_record{
  void *bs;
  uint64_t index;
  uint64_t bitmap;
  LIST_ENTRY(disk_record) entry;
  uint8_t records[0];
} disk_record_t;

#define DISK_HTAB_SIZE (1024)
static LIST_HEAD(disk_record_list_head, disk_record)
	disk_record_heads[DISK_HTAB_SIZE];

//Slower version and no boundary check
static inline uint8_t taint_mem_check_slow(uint32_t addr, int size)
{
  uint8_t taint, offset;
  tpage_entry_t * entry = tpage_table[addr>>6];
  if(!entry) return 0;

  offset = addr & 3;
  taint = entry->bitmap[((addr&63)>>2)];
  return (taint >> offset) & size_to_mask(size);
}


uint8_t __attribute__((fastcall)) taint_mem_check_slower(uint32_t addr, int size, int offset)
{
	if(offset + size <= 4) //within a 4-byte region
	    return taint_mem_check_slow(addr, size);

	uint8_t taint1 = taint_mem_check_slow(addr, 4-offset);
	uint8_t taint2 = taint_mem_check_slow(addr+4-offset, size-4+offset);
	return (taint2<<(4-offset))|taint1;
}

/* Slow version of taint memory: no boundary check */
static inline void taint_memory_slow(uint32_t addr, int size, uint8_t taint)
{
  uint8_t curr_taint = taint_mem_check_fast(addr);
  uint32_t offset = addr & 3;
  curr_taint &= ~(size_to_mask(size) << offset);
  curr_taint |= (taint << offset);
  taint_memory_fast(addr, curr_taint);
}


void __attribute__((fastcall)) taint_memory_slower(uint32_t addr, int size,
		int offset, uint8_t taint)
{
	if(offset + size <= 4) //within a 4-byte region
	    return taint_memory_slow(addr, size, taint);

	taint_memory_slow(addr, 4-offset, taint & size_to_mask(4-offset));
	taint_memory_slow(addr + 4 - offset, size - 4 + offset, taint >> (4-offset));
}

////s
/* Slow version of clean memory: no boundary check */
static inline void clean_memory_slow(uint32_t addr, int size)
{
  uint8_t curr_taint = taint_mem_check_fast(addr);
  if(!curr_taint)
	return;
  uint8_t offset = addr & 3;
  curr_taint &= ~(size_to_mask(size) << offset);
  if(!curr_taint)
    clean_memory_fast(addr);
  else
    taint_memory_fast(addr, curr_taint);
}


void __attribute__((fastcall)) clean_memory_slower(uint32_t addr, int size, int offset)
{
	if(offset + size <= 4) {//within a 4-byte region
	    clean_memory_slow(addr, size);
	} else {
		clean_memory_slow(addr, 4-offset);
		clean_memory_slow(addr + 4 - offset, size - 4 + offset);
	}
}

int taintcheck_taint_disk(uint64_t index, uint64_t taint, int offset,
                          int size, uint8_t * record, void *bs)
{
  if(!DECAF_emulation_started) return 0;

#ifndef NO_PROPAGATE
  struct disk_record_list_head *head =
      &disk_record_heads[index & (DISK_HTAB_SIZE - 1)];
  disk_record_t *drec,  *new_drec;
  int found = 0;
  int size2 = 0;
  uint64_t taint2 = 0;

  if (offset + size > 64) {
    size = 64 - offset, taint &= size_to_mask(size);
    size2 = offset + size - 64;
    taint2 = taint >> offset;
  }

  LIST_FOREACH(drec, head, entry) {
    if (drec->index == index && drec->bs == bs) {
      found = 1;
      break;
    }
    if (drec->index > index)
      break;
  }
  if (!found) {
    if (!taint)
      return 0;

    if (!(new_drec = qemu_mallocz(sizeof(disk_record_t) +
                              64 * taint_config->taint_record_size)))
      return 0;

    new_drec->index = index;
    new_drec->bs = bs;
    new_drec->bitmap = taint << offset;
    memcpy(new_drec->records + offset * taint_config->taint_record_size,
           record, size * taint_config->taint_record_size);
    LIST_INSERT_HEAD(head, new_drec, entry);
  }
  else {
    drec->bitmap &= ~(size_to_mask(size) << offset);
    if (taint) {
      drec->bitmap |= taint << offset;
      memcpy(drec->records + offset * taint_config->taint_record_size,
             record, size * taint_config->taint_record_size);
    }
    else if (!drec->bitmap) {
      LIST_REMOVE(drec, entry);
      qemu_free(drec);
    }
  }

  if (size2)
    taintcheck_taint_disk(index + 1, taint2, 0, size2,
                          record + size * taint_config->taint_record_size,
                          bs);
#endif
  return 0;
}

uint64_t taintcheck_disk_check(uint64_t index, int offset, int size,
                               uint8_t * record, void *bs)
{
  if(!DECAF_emulation_started) return 0;

#ifndef NO_PROPAGATE
  struct disk_record_list_head *head =
      &disk_record_heads[index & (DISK_HTAB_SIZE - 1)];
  disk_record_t *drec;
  int found = 0;
  uint64_t taint;

  if (offset + size > 64)
    size = 64 - offset, taint &= size_to_mask(size);   //fixme:ignore the unalignment

  LIST_FOREACH(drec, head, entry) {
    if (drec->index == index && drec->bs == bs) {
      found = 1;
      break;
    }
    if (drec->index > index)
      break;
  }

  if (!found)
    return 0;

  taint = (drec->bitmap >> offset) & size_to_mask(size);
  if (taint)
    memcpy(record, drec->records + offset * taint_config->taint_record_size,
           size * taint_config->taint_record_size);
  return taint;
#else
  return 0;
#endif
}

#ifdef MEM_CHECK
void mem_read_wrapper(uint32_t virt_addr, uint32_t phys_addr, int size)
{
	decaf_plugin->mem_read(virt_addr, phys_addr, size);
}
#endif

#ifdef REG_CHECK
void reg_read_wrapper(uint32_t reg, int offset, int size)
{
	//TODO: change to direct call
	if (decaf_plugin)
		decaf_plugin->reg_read(reg, offset, size);
}

void reg_write_wrapper(uint32_t reg, int offset, int size)
{
	//TODO: change to direct call
	if (decaf_plugin)
		decaf_plugin->reg_write(reg, offset, size);
}
#endif


void __attribute__((fastcall)) taintcheck_bswap(int reg, int size)
{
  if(__builtin_expect(!DECAF_emulation_started, 0)) return;

#ifndef NO_PROPAGATE
  uint8_t taint, taint2 = 0;
  int i;
  char *record2 = NULL;

  if (!(taint = taint_reg_check_slow(reg, 0, size)))
    return ;
  if (!(record2 = qemu_mallocz(taint_config->taint_record_size * size)))
    return;

  insn_tainted = 1;
  for (i = 0; i < size; i++) {
    if (taint & (1 << i)) {
      taint2 |= 1 << (size - i - 1);
      memcpy(record2 + (size - i - 1) * taint_config->taint_record_size,
             regs_records + (reg*4 + i) * taint_config->taint_record_size,
             taint_config->taint_record_size);
    }
  }
  memcpy(regs_records + reg *4 * taint_config->taint_record_size, record2,
         size * taint_config->taint_record_size);

  taint_register_slow(reg, size, 0, taint2);
  //may call taint_propagate here

  qemu_free(record2);
#endif //NO_PROPAGATE
}

void taintcheck_clear_ones(int reg, int size, uint32_t val)     //size<=4
{
#ifndef NO_PROPAGATE
  if(__builtin_expect(!DECAF_emulation_started, 0)) return;

  int i;
  uint8_t taint = taint_reg_check_slow(reg, 0, size);
  if (!taint)
    return;

  for (i = 0; i < size; i++) {
    if (((val >> i) & 0xff) == 0xff)
      taint &= ~(1 << i);
  }
  (size == 4)?
		  taint_register_fast(reg, taint) : taint_register_slow(reg, size, 0, taint);
#endif
}

void taintcheck_clear_zeros(int reg, int size, uint32_t val)    //size<=4
{
#ifndef NO_PROPAGATE
  if (__builtin_expect(!DECAF_emulation_started, 0)) return;

  uint8_t taint = taint_reg_check_slow(reg, 0, size);
  if (__builtin_expect(!taint, 1))
    return;
  taint = clear_zero(val, size, taint);
  (size == 4)?
  		  taint_register_fast(reg, taint) : taint_register_slow(reg, size, 0, taint);
#endif
}


#if 1 // AWH TAINT_FLAGS
//which=1 means cc_src, which=2 means cc_dst, which=3 means both
void __attribute__((fastcall))
taintcheck_update_eflags(uint32_t mask, int which)
{
#ifndef NO_PROPAGATE
  if(__builtin_expect(!DECAF_emulation_started, 0))
	return;

  uint8_t taint1 = 0, taint2 = 0;

  if(which & 1) taint1 = taint_reg_check_fast(R_CC_SRC);
  if(which & 2) taint2 = taint_reg_check_fast(R_CC_DST);
  if (taint1 == 0 && taint2== 0) {
	eflags_bitmap &= ~mask;
	return;
  }

  eflags_bitmap |= mask;
  insn_tainted = 1;

  int i;
  uint8_t *dst_rec, *src_rec=NULL;

  if(taint1) {
   for (i = 0; i < 4; i++)
    if(taint1 & (1 << i)) {
      src_rec = regs_records + (R_CC_SRC*4 + i) * taint_config->taint_record_size;
      break;
    }
  }
  if(src_rec == NULL) {
   for (i = 0; i < 4; i++)
    if(taint2 & (1 << i)) {
      src_rec = regs_records + (R_CC_DST*4 + i) * taint_config->taint_record_size;
      break;
    }
  }

  assert(src_rec);

  for (i = 0; i < 12; i++) { //the highest bit is 12 for cc_eflags
    if(mask & (1<<i)) {
      dst_rec = eflags_records + i*taint_config->taint_record_size;
      memcpy(dst_rec, src_rec, taint_config->taint_record_size);
    }
  }

#endif
}

void  __attribute__((fastcall))
taintcheck_flag2reg(uint32_t mask, int reg, int size)
{
#ifndef NO_PROPAGATE
  if(__builtin_expect(!DECAF_emulation_started, 0))
	return;

  uint32_t taint = mask & eflags_bitmap;
  if (!taint) {
    clean_register_slow(reg, size, 0);
    return;
  }

  taint_register_slow(reg, size, 0, (1<<size)-1);
  insn_tainted = 1;

  int i;
  uint8_t *dst_rec, *src_rec=NULL;
  for (i = 0; i < 13; i++)
    if(taint & (1 << i)) { //the highest bit is 12 for cc_eflags
      src_rec = eflags_records + i * taint_config->taint_record_size;
      break;
    }

  assert(src_rec);
  for (i = 0; i < size; i++) {
    dst_rec = regs_records + (reg*4+i)*taint_config->taint_record_size;
    memcpy(dst_rec, src_rec, taint_config->taint_record_size);
  }

#endif //NO_PROPAGATE
}

void __attribute__((fastcall))
taintcheck_reg2flag(int reg, int size, uint32_t mask)
{
#ifndef NO_PROPAGATE
  if(__builtin_expect(!DECAF_emulation_started, 0))
	return;

  uint32_t taint = taint_reg_check_slow(reg, 0, size);
  if (!taint) {
    eflags_bitmap &= ~mask;
    return;
  }

  eflags_bitmap |= mask;
  insn_tainted = 1;

  int i;
  uint8_t *dst_rec, *src_rec=NULL;
  for (i = 0; i < size; i++)
    if(taint & (1 << i)) {
      src_rec = regs_records + i * taint_config->taint_record_size;
      break;
    }

  assert(src_rec);
  for (i = 0; i < size*8; i++) {
    if(mask & (1<<i)) {
      dst_rec = eflags_records + i*taint_config->taint_record_size;
      memcpy(dst_rec, src_rec, taint_config->taint_record_size);
    }
  }

#endif //NO_PROPAGATE
}
#endif

//reg = R_T0 OR R_T1
void  taintcheck_mem2reg_nolookup(uint32_t paddr, uint32_t vaddr, int size, int reg)
{
  if(!DECAF_emulation_started) return;
  if(__builtin_expect(paddr >= ram_size, 0)) return;

#ifdef MEM_CHECK
  decaf_plugin->mem_read(vaddr, paddr, size);
#endif

#ifndef NO_PROPAGATE
  uint8_t taint = 0;
  uint32_t offset = paddr & 63;

  if (offset + size <= 64) {
    taint = taint_mem_check(paddr, size);
    taint_register_slow(reg, size, 0, taint);
    if (taint) {
      insn_tainted = 1;
      taint_operand_t src, dst;
      src.type = 1;              //memory
      dst.type = 0;              //register
      src.size = dst.size = size;
      src.taint = dst.taint = taint;
      src.addr = paddr, dst.addr = reg;
      src.records = tpage_table[paddr >> 6]->records +
      			offset * taint_config->taint_record_size;
      dst.records = regs_records + taint_config->taint_record_size * reg * 4;
      taint_config->taint_propagate(1, &src, &dst, PROP_MODE_MOVE);
    }
  }
  else {
    int size1 = 64 - offset;
    int size2 = size - size1;
    taint = taint_mem_check(paddr, size1);
    if (taint) {
      insn_tainted = 1;
      taint_register_slow(reg, size1, 0, taint);
      taint_operand_t src, dst;
      src.type = 1;              //memory
      dst.type = 0;                 //register
      src.size = dst.size = size1;
      src.taint = dst.taint = taint;
      src.addr = paddr, dst.addr = reg;
      src.records = tpage_table[paddr >> 6]->records +
      			offset * taint_config->taint_record_size;
      dst.records = regs_records + taint_config->taint_record_size * reg * 4;
      taint_config->taint_propagate(1, &src, &dst, PROP_MODE_MOVE);
    }

    taint = taint_mem_check(paddr+size1, size2);
    if (taint) {
      insn_tainted = 1;
      taint_register_slow(reg, size2, size1, taint);
      taint_operand_t src, dst;
      src.type = 1;              //memory
      dst.type = 0;                 //register
      src.size = dst.size = size2;
      src.taint = dst.taint = taint;
      src.addr = paddr+size1, dst.addr = reg+size1;
      src.records = tpage_table[(paddr>>6) + 1]->records;
      dst.records = regs_records + taint_config->taint_record_size * (reg * 4 + size1);
      taint_config->taint_propagate(1, &src, &dst, PROP_MODE_MOVE);
    }
  }
#endif //NO_PROPAGATE
}

void __attribute__((fastcall)) taintcheck_logic_T0_T1(void)
{
  if(__builtin_expect(!DECAF_emulation_started, 0)) return;

#ifndef NO_PROPAGATE
  uint8_t taint1, taint2, taint;
  taint1 = taint_reg_check_fast(R_T0);
  taint2 = taint_reg_check_fast(R_T1);
  taint = taint1 | taint2;
  if(__builtin_expect(0 == taint, 1)) return;

  taint_register_fast(R_T0, taint);
  insn_tainted = 1;
  taint_operand_t src[2], dst;
  int i;
  src[0].type = src[1].type = dst.type = 0; //register
  src[0].size = src[1].size = dst.size = 1; //we do it byte by byte
  for (i=0; i<4; i++) {
    if(!(taint & (1<<i))) continue;

    src[0].taint = (taint1 >> i) & 1;
    src[1].taint = (taint2 >> i) & 1;
    dst.addr = src[0].addr = R_T0;
    dst.offset = src[0].offset = src[1].offset = i;
    src[1].addr = R_T1;
    src[0].records = regs_records + taint_config->taint_record_size * (R_T0 * 4 + i);
    src[1].records = regs_records + taint_config->taint_record_size * (R_T1 * 4 + i);
    dst.records = src[0].records;
    taint_config->taint_propagate(2, src, &dst, PROP_MODE_XFORM);
  }

#endif
}

void __attribute__((fastcall)) reg2TN_taint_propagate(int reg, int t, int size, uint8_t taint)
{
	taint_operand_t src, dst;
	src.type = dst.type = 0;
	src.size = dst.size = size;
	src.taint = dst.taint = taint;
	src.addr = reg, dst.addr = t;
	src.offset = dst.offset = 0;
	src.records = regs_records + reg * 4 * plugin_taint_record_size;
	dst.records = regs_records + t * 4 * plugin_taint_record_size;
	taint_config->taint_propagate(1, &src, &dst, PROP_MODE_MOVE);
}

void __attribute__((fastcall)) regh2TN_taint_propagate(int reg, int t, uint8_t taint)
{
   	taint_operand_t src, dst;
   	src.type = dst.type = 0;
   	src.size = 1;
   	dst.size = 1;
   	src.taint = dst.taint = taint;
   	src.offset = 1;
   	dst.offset = 0;
   	src.addr = reg;
   	dst.addr = t;
   	src.records = regs_records + (reg * 4 + 1)* plugin_taint_record_size;
   	dst.records = regs_records + t * 4 * plugin_taint_record_size;
   	taint_config->taint_propagate(1, &src, &dst, PROP_MODE_MOVE);
 }


void taintcheck_code2TN(uint32_t vaddr, uint32_t reg, int size)
{
  //in the execution context, there should be no page fault
  uint32_t phys_addr = DECAF_get_phys_addr(NULL, vaddr);
  taintcheck_mem2reg_nolookup(phys_addr, vaddr, size, reg);
}


int taintcheck_init(void)
{
  int i;
  for (i = 0; i < DISK_HTAB_SIZE; i++)
    LIST_INIT(&disk_record_heads[i]);

  assert(tpage_table == NULL); //make sure it is not double created
  tpage_table = (tpage_entry_t **) qemu_malloc((ram_size/64) * sizeof(void*));

  return 0;
}

static int taintcheck_load(QEMUFile * f, void *opaque, int version_id)
{
  uint32_t val;
  uint8_t separator;
  DECAF_CompressState_t state;
  if(DECAF_decompress_open(&state, f) < 0)
    return -EINVAL;

  taintcheck_clean_memreg();

  DECAF_decompress_buf(&state, (uint8_t *)&val, 4);
  if (val != taint_config->taint_record_size)
    return -EINVAL;

  DECAF_decompress_buf(&state, (uint8_t *)&regs_bitmap, 8);
  DECAF_decompress_buf(&state, regs_records, 64 * val);

  int i;
  for (DECAF_decompress_buf(&state, (uint8_t *)&i, 4);
       i != -1;
       DECAF_decompress_buf(&state, (uint8_t *)&i, 4)
       )
  {
    tpage_entry_t *entry =
        (tpage_entry_t *) qemu_mallocz(sizeof(tpage_entry_t) + 64 * val);
    if (!entry)
      return -EINVAL;

    DECAF_decompress_buf(&state, (uint8_t *)&entry->bitmap, 8);
    DECAF_decompress_buf(&state, entry->records, 64 * val);
    DECAF_decompress_buf(&state, &separator, 1);
    if(separator != 0) {
      fprintf(stderr, "Invalid taintcheck vm state\n");
      return -EINVAL;
    }
    tpage_table[i] = entry;
  }

  return 0;
}

static void taintcheck_save(QEMUFile * f, void *opaque)
{
  DECAF_CompressState_t state;
  uint32_t ending = -1;
  uint8_t separator = 0;

  if(DECAF_compress_open(&state, f) < 0)
    return;

  DECAF_compress_buf(&state, (uint8_t *)&taint_config->taint_record_size, 4);
  /*save registers' taint info */
  DECAF_compress_buf(&state, (uint8_t *)&regs_bitmap, 8);
  DECAF_compress_buf(&state, regs_records, 64 * taint_config->taint_record_size);

  /*save memory taint info */
  int i;
  for (i = 0; i < ram_size / 64; i++) {
    if (!tpage_table[i])
      continue;

	DECAF_compress_buf(&state, (uint8_t *)&i, 4);
	DECAF_compress_buf(&state, (uint8_t *)&tpage_table[i]->bitmap, 8);
    DECAF_compress_buf(&state, tpage_table[i]->records,
                    64 * taint_config->taint_record_size);
	DECAF_compress_buf(&state, &separator, 1); //separator
  }
  DECAF_compress_buf(&state, (uint8_t *)&ending, 4); //ending
  /*TODO: save disk and nic info */

  DECAF_compress_close(&state);
}

int taintcheck_create(void)
{
  int nic_records_len, reg_records_len; //, i;

  nic_records_len = 32 * 1024 * taint_config->taint_record_size;
  nic_records = qemu_malloc(nic_records_len);
  reg_records_len = 64 * taint_config->taint_record_size;
  regs_records = qemu_mallocz(reg_records_len);

#if 1 // AWH TAINT_FLAGS
  eflags_records = qemu_mallocz(32 * taint_config->taint_record_size);
#endif

  if (!nic_records || !regs_records
#if 1 // AWH TAINT_FLAGS
	|| !eflags_records
#endif
    ) {
    fprintf(stderr, "out of memory\n");
    exit(-1);
  }

//  bzero(tpage_table, (ram_size/64) * sizeof(void*));
  bzero(nic_records, nic_records_len);
/* Changed by Aravind */
  //regs_bitmap = 0;
  memset(regs_bitmap, 0, MAX_REGS);
/*	END	*/
  bzero(nic_bitmap, sizeof(nic_bitmap));
#if 1 // AWH TAINT_FLAGS
  eflags_bitmap = 0;
  bzero(eflags_records, 32 * taint_config->taint_record_size);
#endif
  // AWH - Added NULL as first parm (interface change)
  register_savevm(NULL, "taintcheck", 0, 1, taintcheck_save, taintcheck_load,
                  NULL);
  return 0;
}

void taintcheck_cleanup(void)
{
  int i;

  //clean nic buffer
  bzero(nic_bitmap, sizeof(nic_bitmap));
  qemu_free(nic_records);
  nic_records = NULL;

  //clean registers
  memset(regs_bitmap, 0, MAX_REGS);
  qemu_free(regs_records);
  regs_records = NULL;

#if 1 // AWH TAINT_FLAGS
  eflags_bitmap = 0;
  qemu_free(eflags_records);
  eflags_records = NULL;
#endif

  //clean memory
  for (i = 0; i < ram_size / 64; i++)
    // AWH - Add in additional check for a valid tpage_table, since it
    // may not have been created yet.
    if (tpage_table && tpage_table[i]) {
      qemu_free(tpage_table[i]);
      tpage_table[i] = 0;
    }

  //clean disk
  struct disk_record_list_head *head;
  disk_record_t *rec;
  for (i = 0; i < DISK_HTAB_SIZE; i++) {
    head = &disk_record_heads[i];
    while (!LIST_EMPTY(head)) {
      rec = LIST_FIRST(head);
      LIST_REMOVE(rec, entry);
      qemu_free(rec);
    }
  }
  // AWH - deregister_savevm(), first parm NULL
  unregister_savevm(NULL, "taintcheck", 0);
}

void __attribute__ ((fastcall)) memld_fast_propagate_taint (uint32_t addr, int size,
		int reg, uint8_t mem_taint, uint8_t index_taint)
{
	  uint32_t offset = addr & 63;
	  taint_operand_t src[2], dst;
	  uint8_t taint = index_taint? size_to_mask(size) : mem_taint;

	  if(offset + size <= 64) {
	    //within the 64-byte boundary - common case
	      //Taint propagation
	      src[0].type = 1; //memory
	      dst.type = 0;                 //register
	      src[0].size = dst.size = size;
	      src[0].taint = mem_taint;
	      src[0].offset = dst.offset = 0;
	      dst.taint = taint;
	      src[0].addr = addr, dst.addr = reg;
	      src[0].records = mem_taint? tpage_table[addr>>6]->records +
	                                offset * plugin_taint_record_size
	                                : NULL;
	      dst.records = regs_records + plugin_taint_record_size*reg*4;
	      if(index_taint) {
	              src[1].type = 0;
	              src[1].size = 4;
	              src[1].taint = index_taint;
	              src[1].offset = 0;
	              src[1].records = regs_records + plugin_taint_record_size * R_A0 * 4;
	              src[1].addr = R_A0;
	      }
	      taint_config->taint_propagate(index_taint? 2:1, src, &dst, PROP_MODE_MOVE);
	    }
	  else {
		    int size1 = 64 - offset;
		    int size2 = size - size1;
		    uint8_t taint1, taint2, dst_taint1, dst_taint2;

	        taint1 = mem_taint & size_to_mask(size1);
	        taint2 = mem_taint >> size1;

		    if(index_taint) {
		      dst_taint1 = size_to_mask(size1);
		      dst_taint2 = size_to_mask(size2);
		      src[1].type = 0;
		      src[1].size = 4;
		      src[1].offset = 0;
		      src[1].taint = index_taint;
		      src[1].records = regs_records + plugin_taint_record_size * R_A0 * 4;
		      src[1].addr = R_A0;
		    } else {
		    	dst_taint1 = taint1;
		    	dst_taint2 = taint2;
		    }
		    //Taint Propagation
		    taint_operand_t src[2], dst;
		    if (taint1) {
		    	src[0].type = 1; //memory
		    	dst.type = 0;                 //register
		    	src[0].size = dst.size = size1;
		    	src[0].taint = taint1;
		    	src[0].offset = dst.offset = 0;
		    	dst.taint = dst_taint1;
		    	src[0].addr = addr, dst.addr = reg;
		    	src[0].records = tpage_table[addr>>6]->records +
		    	                                offset*plugin_taint_record_size;
		    	dst.records = regs_records + plugin_taint_record_size * reg * 4;
		    	taint_config->taint_propagate(index_taint? 2:1, src, &dst, PROP_MODE_MOVE);
		    }
		    if (taint2) {
		    	src[0].type = 1; //memory
		    	dst.type = 0;                 //register
		    	src[0].size = dst.size = size2;
		    	src[0].taint = taint2;
		    	dst.taint = dst_taint2;
		    	src[0].addr = addr+size1, dst.addr = reg;
		    	src[0].offset = 0, dst.offset = size1;
		    	src[0].records = tpage_table[(addr>>6)+1]->records;
		    	dst.records = regs_records + plugin_taint_record_size*(reg*4+size1);
		    	taint_config->taint_propagate(index_taint? 2:1, src, &dst, PROP_MODE_MOVE);
		    }
		  }
}

void __attribute__ ((fastcall)) memld_slow_propagate_taint (uint32_t addr, int size, int reg,
		int offset, uint8_t mem_taint, uint8_t index_taint)
{
	  uint32_t offset_mem = addr & 63;
	  taint_operand_t src[2], dst;

	  if(offset_mem + size <= 64) {
	    //within the 64-byte boundary
	    src[0].type = 1; //memory
	    dst.type = 0;                 //register
	    src[0].size = dst.size = size;
	    src[0].offset = 0;
	    dst.offset = offset;
	    src[0].taint = mem_taint;
	    dst.taint = index_taint? size_to_mask(size) : mem_taint;
	    src[0].addr = addr, dst.addr = reg;
	    src[0].records = tpage_table[addr>>6]->records +
	                                offset_mem*plugin_taint_record_size;
	    dst.records = regs_records + plugin_taint_record_size* (reg*4 + offset);
	    if(index_taint) {
	      src[1].type = 0;
	      src[1].size = 4;
	      src[1].taint = index_taint;
	      src[1].offset = 0;
	      src[1].records = regs_records + plugin_taint_record_size * R_A0 * 4;
	      src[1].addr = R_A0;
	    }
	    taint_config->taint_propagate(index_taint? 2:1, src, &dst, PROP_MODE_MOVE);
	  }
	  else {
	    int size1 = 64 - offset_mem;
	    int size2 = size - size1;
	    taint_operand_t src[2], dst;
	    uint8_t taint1, taint2, dst_taint1, dst_taint2;
    	taint1 = mem_taint & size_to_mask(size1);
    	taint2 = mem_taint >> size1;

	    if(index_taint) {
	      dst_taint1 = size_to_mask(size1);
	      dst_taint2 = size_to_mask(size2);
	      src[1].type = 0;
	      src[1].size = 4;
	      src[1].taint = index_taint;
	      src[1].offset = 0;
	      src[1].records = regs_records + plugin_taint_record_size * R_A0 * 4;
	      src[1].addr = R_A0;
	    } else {
	    	dst_taint1 = taint1, dst_taint2 = taint2;
	    }
	    if (taint1) {
	    	src[0].type = 1; //memory
	    	dst.type = 0;                 //register
	    	src[0].size = dst.size = size1;
	    	src[0].taint = taint1;
	    	src[0].offset = 0;

	    	dst.taint = dst_taint1;
	    	dst.offset = offset;
	    	src[0].addr = addr, dst.addr = reg;
	    	src[0].records = tpage_table[addr>>6]->records +
	    	    	                                offset_mem*plugin_taint_record_size;
	    	dst.records = regs_records + plugin_taint_record_size*(reg*4 + offset);
	    	taint_config->taint_propagate(index_taint? 2:1, src, &dst, PROP_MODE_MOVE);
	    }

	    if (taint2) {
	    	src[0].type = 1; //memory
	    	dst.type = 0;                 //register
	    	src[0].size = dst.size = size2;
	    	src[0].taint = taint2;
	    	src[0].offset = 0;
	    	dst.offset = offset+size1;
	    	dst.taint = dst_taint2;
	    	src[0].addr = addr+size1, dst.addr = reg;
	    	src[0].records = tpage_table[(addr>>6)+1]->records;
	    	dst.records = regs_records + plugin_taint_record_size*(reg*4+size1);
	    	taint_config->taint_propagate(index_taint? 2:1, src, &dst, PROP_MODE_MOVE);
	    }
	  }
}


void __attribute__ ((fastcall)) memst_fast_propagate_taint (uint32_t addr, int size, int reg, uint8_t taint)
{
  uint32_t offset = addr & 63;

  if (offset + size <= 64) { //All within one entry
	  taint_operand_t src, dst;
	  src.type = 0; dst.type = 1;
	  src.offset = dst.offset = 0;
	  src.size = dst.size = size;
	  dst.taint = src.taint = taint;
	  src.addr = reg, dst.addr = addr;
	  src.records = regs_records + reg * plugin_taint_record_size * 4;
	  dst.records = tpage_table[addr >> 6]->records + offset * plugin_taint_record_size;
	  taint_config->taint_propagate(1, &src, &dst, PROP_MODE_MOVE);
  } else { //Spans over two entries
    int size1 = 64-offset, size2 = size - size1;

    if(taint & size_to_mask(size1)) {

	  taint_operand_t src, dst;
	  src.type = 0; dst.type = 1;
	  src.size = dst.size = size1;
	  dst.taint = src.taint = (taint & size_to_mask(size1));
	  src.addr = reg, dst.addr = addr;
	  src.offset = dst.offset = 0;
	  src.records =
			regs_records + reg * plugin_taint_record_size * 4;
	  dst.records =
			tpage_table[addr >> 6]->records + offset * plugin_taint_record_size;
	  taint_config->taint_propagate(1, &src, &dst, PROP_MODE_MOVE);
	}

    taint >>= size1;

    if(taint) {
		taint_operand_t src, dst;
          src.type = 0; dst.type = 1;
          src.size = dst.size = size2;
          src.offset = size1;
          dst.offset = 0;
          dst.taint = src.taint = taint;
          src.addr = reg, dst.addr = addr + size1;
          src.records = regs_records + (reg * 4 + size1)*plugin_taint_record_size;
          dst.records = tpage_table[(addr>>6)+1]->records;
          taint_config->taint_propagate(1, &src, &dst, PROP_MODE_MOVE);
      }
  }
}

void __attribute__ ((fastcall)) memst_slow_propagate_taint (uint32_t addr, int size, int reg, int offset, uint8_t taint)
{
	uint32_t offset_mem = addr & 63;

	if (offset + size <= 64) { //All within one entry
    	  taint_operand_t src, dst;
		  src.type = 0; dst.type = 1;
		  src.size = dst.size = size;
		  dst.taint = src.taint = taint;
		  src.addr = reg, dst.addr = addr;
		  src.offset = offset;
		  dst.offset = 0;
		  src.records = regs_records + (reg * 4 + offset) * plugin_taint_record_size;
		  dst.records = tpage_table[addr >> 6]->records + offset_mem * plugin_taint_record_size;
		  taint_config->taint_propagate(1, &src, &dst, PROP_MODE_MOVE);
	} else { //Spans over two entries
		int size1 = 64-offset_mem, size2 = size - size1;

		if(taint & size_to_mask(size1)) {

		  taint_operand_t src, dst;
		  src.type = 0; dst.type = 1;
		  src.size = dst.size = size1;
		  src.offset = offset;
		  dst.offset = 0;
		  dst.taint = src.taint = (taint & size_to_mask(size1));
		  src.addr = reg, dst.addr = addr;
		  src.records =
			regs_records + (reg * 4 + offset) * plugin_taint_record_size;
		  dst.records =
			tpage_table[addr >> 6]->records + offset_mem * plugin_taint_record_size;
		  taint_config->taint_propagate(1, &src, &dst, PROP_MODE_MOVE);
		}
		taint = taint >> size1;
		if(taint) {
			  taint_operand_t src, dst;
				src.type = 0; dst.type = 1;
				src.size = dst.size = size2;
				dst.taint = src.taint = taint;
				src.addr = reg, dst.addr = addr + size1;
				src.offset = offset + size1;
				dst.offset = 0;
				src.records = regs_records + (reg * 4 + offset + size1) * plugin_taint_record_size;
				dst.records = tpage_table[(addr>>6)+1]->records;
				taint_config->taint_propagate(1, &src, &dst, PROP_MODE_MOVE);
		}
	}
	#ifdef MEM_CHECK
			asm_mem_write(cpu_single_env->regs[R_A0], addr, size);
	#endif
}


void __attribute__ ((fastcall)) reg2reg_fast_propagate_taint(int sreg, int dreg, uint8_t taint)
{
  taint_operand_t src, dst;
  src.type = dst.type = 0;
  src.size = dst.size = 4;
  src.offset = dst.offset = 0;

  src.taint = dst.taint = taint;
  src.addr = sreg, dst.addr = dreg;
  src.records =
      regs_records + sreg * 4 * plugin_taint_record_size;
  dst.records =
      regs_records + dreg * 4 * plugin_taint_record_size;
  taint_config->taint_propagate(1, &src, &dst, PROP_MODE_MOVE);
}

void __attribute__ ((fastcall)) reg2reg_slow_propagate_taint(int sreg, int dreg, int soffset, int doffset, int size, uint8_t taint)
{
  taint_operand_t src, dst;
  src.type = dst.type = 0;
  src.size = dst.size = size;
  src.offset = soffset;
  dst.offset = doffset;
  src.taint = dst.taint = taint;
  src.addr = sreg, dst.addr = dreg;
  src.records =
      regs_records + (sreg * 4 + soffset) * plugin_taint_record_size;
  dst.records =
      regs_records + (dreg * 4 + doffset) * plugin_taint_record_size;
  taint_config->taint_propagate(1, &src, &dst, PROP_MODE_MOVE);
}

void __attribute__((fastcall)) fn3regs_propagate_taint(
		int sreg1, int sreg2, int sreg3, int dreg, int size,
		uint8_t taint1, uint8_t taint2, uint8_t taint3)
{
	taint_operand_t src[3], dst;
	src[0].type = src[1].type = src[2].type = dst.type = 0;
	src[0].size = src[1].size = src[2].size = dst.size = size;
	src[0].offset = src[1].offset = src[2].offset = dst.offset = 0;
	src[0].taint = taint1, src[1].taint = taint2, src[2].taint = taint3;
	dst.taint = size_to_mask(size);
	src[0].addr = sreg1, src[1].addr = sreg2, src[2].addr =	sreg3, dst.addr = dreg;
	src[0].records =
		regs_records + taint_config->taint_record_size * sreg1 * 4;
	src[1].records =
		regs_records + taint_config->taint_record_size * sreg2 * 4;
	src[2].records =
		regs_records + taint_config->taint_record_size * sreg3 * 4;
	dst.records = regs_records + taint_config->taint_record_size * dreg * 4;

	taint_config->taint_propagate(3, src, &dst, PROP_MODE_XFORM);
}

void __attribute__((fastcall)) fn2regs_propagate_taint(
		int sreg1, int sreg2, int dreg, int size, uint8_t taint1, uint8_t taint2)
{
	taint_operand_t src[2], dst;
	src[0].type = src[1].type = dst.type = 0;
	src[0].size = src[1].size = dst.size = size;
	src[0].taint = taint1, src[1].taint = taint2;
	dst.taint = size_to_mask(size);
	src[0].offset = src[1].offset = src[2].offset = dst.offset = 0;
	src[0].addr = sreg1, src[1].addr = sreg2, dst.addr = dreg;
	src[0].records =
		regs_records + taint_config->taint_record_size * sreg1 * 4;
	src[1].records =
		regs_records + taint_config->taint_record_size * sreg2 * 4;
	dst.records = regs_records + taint_config->taint_record_size * dreg * 4;
	taint_config->taint_propagate(2, src, &dst, PROP_MODE_XFORM);
}

void __attribute__((fastcall)) fn1reg_propagate_taint(int reg, int size)
{
	  taint_operand_t oprnd;
	  oprnd.type = 0;
	  oprnd.size = size;
	  oprnd.taint = size_to_mask(size);
	  oprnd.addr = reg;
	  oprnd.offset = 0;
	  oprnd.records =
		  regs_records + taint_config->taint_record_size * reg * 4;

	  taint_config->taint_propagate(1, &oprnd, &oprnd, PROP_MODE_XFORM);
}

void garbage_collect(void) 
{
	uint32_t i, j;
	for(i = 0; i < ram_size/64; i++) {
		tpage_entry_t *e = tpage_table[i];
		if(e == NULL) continue;

		for(j = 0; j < 16; j++) {
			if(e->bitmap[j] != 0) {
				break;
			}
		}
		if (j<16) continue;

		qemu_free(tpage_table[i]);
		tpage_table[i] = NULL;
	}
}

uint8_t clear_zero(uint32_t value, int size, uint8_t taint)       //size<=4
{
  int i;
  uint32_t v = 0xff;
  uint8_t taint2 = taint;

  for (i = 0; i < size; i++, v <<= 8) {
    if ((value & v) == 0)
      taint2 &= ~(1 << i);
  }
  return taint2;
}

/*
 * This is the wrapper for taint propagation. It just calls the plugin's taint_propagate
 */
int propagate_taint_info(int nr_src, void *src_oprnds,
		void *dst_oprnd, int mode)
{
	taint_config->taint_propagate(nr_src, (taint_operand_t *)src_oprnds, (taint_operand_t *)dst_oprnd, mode);
	return 0;
}

/*
 * This is the default taint_propagate implementation.
 * For a Temu plugin, if it does not need to handle it specially,
 * it can specify this function in its callback function definitions
 */
void default_taint_propagate(int nr_src,
                            taint_operand_t * src_oprnds,
                            taint_operand_t * dst_oprnd,
                            int mode)
{
  int i, j;
  uint8_t *dst_rec, *src_rec=NULL;

  if (mode == PROP_MODE_MOVE && nr_src == 1) {
    //assert(src_oprnds[0].taint);
    memmove(dst_oprnd->records, src_oprnds[0].records,
                 taint_config->taint_record_size * src_oprnds[0].size);
    return;
  }

  /* deal with multiple sources and tainted index*/
  for (i = 0; i < nr_src; i++) {
    if (src_oprnds[i].taint == 0)
      continue;

    for (j = 0; j < src_oprnds[i].size; j++)
      if (src_oprnds[i].taint & (1 << j)) {
        src_rec = src_oprnds[i].records + j*taint_config->taint_record_size;
   	    goto copy_taint_record;
      }

  }

  if (!src_rec) return;

copy_taint_record:

  for (i = 0; i < dst_oprnd->size; i++) {
    dst_rec = dst_oprnd->records + i*taint_config->taint_record_size;
    memmove(dst_rec, src_rec, taint_config->taint_record_size);
  }
}


int taintcheck_chk_hdout(int size, int64_t sect_num, uint32_t offset,
                         void *s)
{
#ifndef NO_PROPAGATE
  uint8_t taint;
  int i, reg = cpu_single_env->tempidx;

  if (!DECAF_emulation_started)
    return 0;

  taint = taint_reg_check_slow(reg, 0, size);
  taintcheck_taint_disk(sect_num * 8 + offset / 64, taint, offset & 63,
                        size,
                        regs_records +
                        reg * taint_config->taint_record_size, s);
  if(taint_config->taint_disk) {
    for (i = 0; i < size; i++) {
      if (taint & (1 << i))
        taint_config->taint_disk(sect_num * 512 + offset + i, regs_records +
                              (reg +
                               i) * taint_config->taint_record_size,
                              (BlockDriverState *) s);
	}
  }
#endif
  return 0;
}

int taintcheck_chk_hdin(int size, int64_t sect_num, uint32_t offset,
                        void *s)
{
#ifndef NO_PROPAGATE
  uint64_t taint = 0;
  uint8_t *records;
  int reg = cpu_single_env->tempidx;

  if (!DECAF_emulation_started)
    return 0;

  records = qemu_malloc(taint_config->taint_record_size * 4);
  if (!records)
    return 0;

  taint =
      taintcheck_disk_check(sect_num * 8 + offset / 64, offset & 63, size,
                            records, s);
  if (taint) {
	if(taint_config->read_disk_taint) {
      int i;
      for (i = 0; i < size; i++) {
        if (taint & (1 << i))
          taint_config->read_disk_taint(sect_num * 512 + offset + i,
                                       records +
                                       taint_config->taint_record_size * i,
                                       s);
      }
    }

	(size == 4)?
			  taint_register_fast(reg, taint) : taint_register_slow(reg, size, 0, taint);

    memcpy(regs_records + reg * taint_config->taint_record_size * 4,
           records, size * taint_config->taint_record_size);
  }
  qemu_free(records);
#endif
  return 0;
}


int taintcheck_chk_hdwrite(uint32_t paddr, int size, int64_t sect_num,
                           void *s)
{
#ifndef NO_PROPAGATE
  uint32_t i, j, k;
  tpage_entry_t *entry;

  if (!DECAF_emulation_started || (paddr & 63))
    return 0;
  for (i = paddr; i < paddr + size; i += 64) {
    entry = tpage_table[i >> 6];
    taintcheck_taint_disk(sect_num * 8 + (i - paddr) / 64,
                          (entry) ? entry->bitmap[((paddr & 63) >> 2)] : 0, 0, size,
                          (entry) ? entry->records : NULL, s);
    if (!entry || !taint_config->taint_disk)
      continue;

    for (j = 0; j < 16; j++) {
	for(k = 0; k < 4; k++) {
      if (entry->bitmap[j] & (1ULL << k))
        taint_config->taint_disk(sect_num * 512 + i + j - paddr,
                                entry->records +
                                j * taint_config->taint_record_size,
                                (BlockDriverState *) s);
    	}
     }
  }
#endif
  return 0;
}

int taintcheck_chk_hdread(uint32_t paddr, int size, int64_t sect_num,
                          void *s)
{
#ifndef NO_PROPAGATE
  uint32_t i, j;
  uint64_t taint;
  uint8_t *records;

  if (!DECAF_emulation_started)
    return 0;

  records = qemu_malloc(64 * taint_config->taint_record_size);
  if (!records)
    return 0;

  for (i = paddr; i < paddr + size; i += 64) {
    taint =
        taintcheck_disk_check(sect_num * 8 + (i - paddr) / 64, 0, 64,
                              records, s);
    if (!taint)
      continue;
    taint_memory(i, 64, taint);
    memcpy(tpage_table[i >> 6]->records, records,
           64 * taint_config->taint_record_size);

    if (!taint_config->read_disk_taint)
      continue;

    for (j = 0; j < 64; j++) {
      if (taint & (1ULL << j))
        taint_config->read_disk_taint(sect_num * 512 + (i - paddr) + j,
                                     records +
                                     taint_config->taint_record_size * j,
                                     s);
    }
  }
  qemu_free(records);
#endif
  return 0;
}



int taintcheck_nic_writebuf(uint32_t addr, int size, uint64_t bitmap, uint8_t * records)        //size<=64
{
  int size1 = size, size2 = 0, index, offset;

  if (!DECAF_emulation_started || addr >= 32 * 1024)
    return 0;

  index = addr >> 6, offset = addr & 63;
  if (offset + size > 64) {
    size2 = offset + size - 64;
    size1 = 64 - offset;
  }
  nic_bitmap[index] &= ~(((1ULL << size1) - 1) << offset);
  nic_bitmap[index] |= (bitmap & size_to_mask(size1)) << offset;
  if (size2) {
    nic_bitmap[index + 1] &= ~size_to_mask(size2);
    nic_bitmap[index + 1] |= bitmap >> size1;
  }

  if (bitmap)
    memcpy(nic_records + addr * taint_config->taint_record_size,
           records, size * taint_config->taint_record_size);
  return 0;
}

uint64_t taintcheck_nic_readbuf(uint32_t addr, int size, uint8_t * records)     //size<=64
{
  int size1 = size, size2 = 0, index, offset;
  uint64_t taint;

  if (!DECAF_emulation_started || addr >= 32 * 1024)
    return 0;

  index = addr >> 6, offset = addr & 63;
  if (offset + size > 64) {
    size2 = offset + size - 64;
    size1 = 64 - offset;
  }
  taint = (nic_bitmap[index] >> offset) & size_to_mask(size1);
  if (size2) {
    taint |= (nic_bitmap[index + 1] & size_to_mask(size2)) << offset;
  }

  if (taint)
    memcpy(records, nic_records + addr * taint_config->taint_record_size,
           size * taint_config->taint_record_size);
  return taint;
}


int taintcheck_nic_out(uint32_t addr, int size)
{
  uint64_t taint;

  taint = taint_reg_check_slow(cpu_single_env->tempidx, 0, size);
  taintcheck_nic_writebuf(addr, size, taint, regs_records +
                          cpu_single_env->tempidx *
                          taint_config->taint_record_size);
  return 0;
}


int taintcheck_nic_in(uint32_t addr, int size)
{
  uint8_t * records = qemu_malloc(taint_config->taint_record_size * size);
  if(records) {
	uint64_t taint = taintcheck_nic_readbuf(addr, size, records);
	taintcheck_taint_register(cpu_single_env->tempidx, 0, size, taint, records);
	qemu_free(records);
  }
  return 0;
}

void *opt_qemu_mallocz(size_t size)
{
    void *ptr;
    ptr = qemu_malloc(size);
    if (!ptr)
        return NULL;
    memset(ptr, 0, size);
    return ptr;
}

void taintcheck_r2r_slow(int s, int d, int ot)
{
  int sreg = REG_IND(s, ot);
  int dreg = REG_IND(d, ot);
  int size = (1<<ot);
  int soffset = REG_OFFSET(s, ot);
  int doffset = REG_OFFSET(d, ot);
  taintcheck_reg2reg_slow(sreg, dreg, soffset, doffset, size);
}

// AWH - From osdep.c in TEMU
void *qemu_mallocz(size_t size)
{
    void *ptr;
    ptr = qemu_malloc(size);
    if (!ptr)
        return NULL;
    memset(ptr, 0, size);
    return ptr;
}

void qemu_free(void *ptr)
{
    free(ptr);
}

void *qemu_malloc(size_t size)
{
    return malloc(size);
}

#endif 


#endif
