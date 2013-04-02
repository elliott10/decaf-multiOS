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

#include "config.h"
#include <dlfcn.h>
#include <assert.h>
#include <sys/queue.h>
#include "hw/hw.h"
#include "qemu-common.h"
#include "sysemu.h"
#include "hw/hw.h" /* {de,}register_savevm */
#include "cpu.h"
#include "DECAF_main.h"
#include "DECAF_main_internal.h"
#include "shared/tainting/tainting.h"
#include "shared/tainting/taintcheck_opt.h"
//#include "shared/tainting/taintcheck.h"
#include "shared/DECAF_vm_compress.h"
#include "shared/tainting/taint_memory.h"
#include "tcg.h" // tcg_abort()

/*uint64_t*/uint8_t nic_bitmap[1024 * 32 /*/ 64*/]; //!<bitmap for nic

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

int taintcheck_taint_disk(const uint64_t index, const uint32_t taint, 
                          const int offset, const int size, const void *bs)
{
  struct disk_record_list_head *head =
      &disk_record_heads[index & (DISK_HTAB_SIZE - 1)];
  disk_record_t *drec,  *new_drec;
  int found = 0;
  // AWH int size2 = 0;
  uint64_t taint2 = 0;

  if (taint & 0x000000FF) taint2 |= 1;
  if (taint & 0x0000FF00) taint2 |= 2;
  if (taint & 0x00FF0000) taint2 |= 4;
  if (taint & 0xFF000000) taint2 |= 8;

  //if (taint)
  //  fprintf(stderr, "taintcheck_taint_disk() taint -> 0x%08x\n", taint);

#if 0 // AWH
  if (offset + size > 64) {
    size = 64 - offset, taint &= size_to_mask(size);
    size2 = offset + size - 64;
    taint2 = taint >> offset;
  }
#endif // AWH
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

//fprintf(stderr, "taintcheck_taint_disk() -> Not found w/ taint\n");
    if (!(new_drec = g_malloc0((size_t)sizeof(disk_record_t) /*+
                              64 * temu_plugin->taint_record_size*/)))
      return 0;

    new_drec->index = index;
    new_drec->bs = bs;
    new_drec->bitmap = taint2 << offset;
    LIST_INSERT_HEAD(head, new_drec, entry);
//fprintf(stderr, "taintcheck_taint_disk() -> Adding new taint record\n");
  }
  else {
//fprintf(stderr, "taintcheck_taint_disk() -> Changing taint record\n");
    drec->bitmap &= ~(size_to_mask(size) << offset);
    if (taint) {
      drec->bitmap |= taint2 << offset;
      /*memcpy(drec->records + offset * temu_plugin->taint_record_size,
             record, size * temu_plugin->taint_record_size);*/
    }
    else if (!drec->bitmap) {
      LIST_REMOVE(drec, entry);
      g_free(drec);
    }
  }
#if 0 // AWH
  if (size2)
    taintcheck_taint_disk(index + 1, taint2, 0, size2,
                          /*record + size * temu_plugin->taint_record_size,*/
                          bs);
#endif // AWH
  return 0;
}

uint32_t taintcheck_disk_check(const uint64_t index, const int offset, 
                               const int size, const void *bs)
{
  //if(!TEMU_emulation_started) return 0;

  struct disk_record_list_head *head =
      &disk_record_heads[index & (DISK_HTAB_SIZE - 1)];
  disk_record_t *drec;
  int found = 0;
  uint64_t taint;
  uint32_t retval = 0;
  uint32_t ourSize = size;
  if (offset + size > 64)
    ourSize = 64 - offset, taint &= size_to_mask(size);   //fixme:ignore the unalignment

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

  taint = (drec->bitmap >> offset) & size_to_mask(ourSize);
  if (taint & 1) retval |= 0x000000FF;
  if (taint & 2) retval |= 0x0000FF00;
  if (taint & 4) retval |= 0x00FF0000;
  if (taint & 8) retval |= 0xFF000000;
  //fprintf(stderr, "taintcheck_disk_check() -> taint 0x%08x\n", retval);
    //memcpy(record, drec->records + offset * temu_plugin->taint_record_size,
    //       size * temu_plugin->taint_record_size);
  return retval;
}

int taintcheck_init(void)
{
  int i;
  for (i = 0; i < DISK_HTAB_SIZE; i++)
    LIST_INIT(&disk_record_heads[i]);

  // AWH assert(tpage_table == NULL); //make sure it is not double created
  // AWH tpage_table = (tpage_entry_t **) qemu_malloc((ram_size/64) * sizeof(void*));

  return 0;
}

void taintcheck_cleanup(void)
{
  int i;

  //clean nic buffer
  bzero(nic_bitmap, sizeof(nic_bitmap));
  //clean disk
  //TODO:
  // AWH - deregister_savevm(), first parm NULL
  unregister_savevm(NULL, "taintcheck", 0);
}

int taintcheck_chk_hdout(const int size, const int64_t sect_num,
  const uint32_t offset, const void *s)
{
#ifdef CONFIG_TCG_TAINT
  //uint8_t taint_rec;
  int taint = cpu_single_env->tempidx;
  if (size > 4) tcg_abort();

  //taint_rec = taint_reg_check_slow(reg, 0, size);
  taintcheck_taint_disk(sect_num * 8 + offset / 64, taint, offset & 63,
                        size,
                        /*regs_records +
                        reg * temu_plugin->taint_record_size,*/ s);
#endif /* CONFIG_TCG_TAINT */
  return 0;
}

int taintcheck_chk_hdin(const int size, const int64_t sect_num,
  const uint32_t offset, const void *s)
{
  /*taint_rec*/ cpu_single_env->tempidx =
      taintcheck_disk_check(sect_num * 8 + offset / 64, offset & 63, size,
                            /*records,*/ s);
  return 0;
}

int taintcheck_chk_hdwrite(const uint32_t paddr, const int size,
  const int64_t sect_num, const void *s)
{
#ifdef CONFIG_TCG_TAINT
  uint32_t i/*, j, k*/;
  //tpage_entry_t *entry;
  //uint32_t taint;

  if (/* AWH !TEMU_emulation_started ||*/ (paddr & 63))
    return 0;
  for (i = paddr; i < paddr + size; i += 4) {
    //entry = tpage_table[i >> 6];
    __taint_ldl_raw(i);
    //if (cpu_single_env->tempidx) fprintf(stderr, "taintcheck_chk_hdwrite() -> Writing taint 0x%08x to disk\n", cpu_single_env->tempidx);
    taintcheck_taint_disk(sect_num * 8 + (i - paddr) / 64,
                          /*(entry) ? entry->bitmap[((paddr & 63) >> 2)] : 0*/cpu_single_env->tempidx, 0, 4/*size*/,
                          /*(entry) ? entry->records : NULL,*/ s);
  } // end for
#endif /* CONFIG_TCG_TAINT */
  return 0;
}

int taintcheck_chk_hdread(const uint32_t paddr, const int size,
  const int64_t sect_num, const void *s)
{
#ifdef CONFIG_TCG_TAINT
  uint32_t i/*, j*/;
  //uint32_t taint;
  //uint8_t *records;
#if 0 // AWH
  if (!TEMU_emulation_started)
    return 0;

  records = qemu_malloc(64 * temu_plugin->taint_record_size);
  if (!records)
    return 0;
#endif // AWH
  for (i = paddr; i < paddr + size; i += 4) {
    cpu_single_env->tempidx =
        taintcheck_disk_check(sect_num * 8 + (i - paddr) / 64, 0, 4,
                              /*records,*/ s);
    // AWH if (!taint)
      // AWH continue;
    //if (cpu_single_env->tempidx) fprintf(stderr, "taintcheck_chk_hdread() -> Reading taint 0x%08x from disk\n", cpu_single_env->tempidx);
#if 0 // AWH
    taint_memory(i, 64, taint);
    memcpy(tpage_table[i >> 6]->records, records,
           64 * temu_plugin->taint_record_size);
#endif // AWH
    __taint_stl_raw(i);
#if 0 // AWH
    if (!temu_plugin->read_disk_taint)
      continue;

    for (j = 0; j < 64; j++) {
      if (taint & (1ULL << j))
        temu_plugin->read_disk_taint(sect_num * 512 + (i - paddr) + j,
                                     records +
                                     temu_plugin->taint_record_size * j,
                                     s);
    }
#endif // AWH
  }
  // AWH qemu_free(records);
#endif /* CONFIG_TCG_TAINT */
  return 0;
}
#ifdef CONFIG_TCG_TAINT
static uint64_t taint_memory_check(uint32_t middle_node_index,uint32_t leaf_node_index,uint32_t addr,int size)
{
	tbitpage_leaf_t *leaf_node = NULL;
	uint64_t taint=0;
	int i=0;
	if (taint_memory_page_table[middle_node_index])
	leaf_node = taint_memory_page_table[middle_node_index]->leaf[leaf_node_index];
	else
	return 0;

	if (leaf_node) {
		for(i=0;i<size;i++)
		{
			if((*(uint8_t *)(leaf_node->bitmap + (addr & LEAF_ADDRESS_MASK)+i))!=0)
			{
				taint|=1<<i;
			}
		}
	}
	else return 0;

	return taint;
}

uint64_t taintcheck_memory_check(uint32_t addr, int size)
{

	unsigned int middle_node_index,middle_node_index_temp;
	unsigned int leaf_node_index,leaf_node_index_temp;
	unsigned int size1=0;
	tbitpage_leaf_t *leaf_node = NULL;
	uint64_t taint=0;
	uint64_t taint1=0;
	uint64_t taint2=0;

	middle_node_index = addr >> (BITPAGE_LEAF_BITS + BITPAGE_MIDDLE_BITS);
	leaf_node_index = (addr >> BITPAGE_LEAF_BITS) & MIDDLE_ADDRESS_MASK;
	middle_node_index_temp = (addr+size-1) >> (BITPAGE_LEAF_BITS + BITPAGE_MIDDLE_BITS);
	leaf_node_index_temp = ((addr+size-1) >> BITPAGE_LEAF_BITS) & MIDDLE_ADDRESS_MASK;
	if(middle_node_index==middle_node_index_temp && leaf_node_index==leaf_node_index_temp)
	{
		goto Done;
	} else if(middle_node_index!=middle_node_index_temp)
	{
		size1=1<<(BITPAGE_LEAF_BITS + BITPAGE_MIDDLE_BITS)-addr&(1<<(BITPAGE_LEAF_BITS + BITPAGE_MIDDLE_BITS)-1);
	} else if(leaf_node_index!=leaf_node_index_temp)
	{
		size1=(1<<BITPAGE_LEAF_BITS) & MIDDLE_ADDRESS_MASK-addr&(((1<<BITPAGE_LEAF_BITS) & MIDDLE_ADDRESS_MASK)-1);
	}
	Done:
	if(size1)
	{
		taint1=taint_memory_check(middle_node_index,leaf_node_index,addr,size1);
	}
	taint2=taint_memory_check(middle_node_index_temp,leaf_node_index_temp,addr,size-size1);
	taint=taint1|(taint2<<size1);
	return taint;
}




uint64_t taintcheck_check_virtmem(uint32_t vaddr, uint32_t size)
{
  uint64_t ret  = 0;
  uint32_t paddr = 0, offset;
  uint32_t size1, size2;
  CPUState *env;
  env = cpu_single_env ? cpu_single_env : first_cpu;

  paddr = DECAF_get_phys_addr(env,vaddr);
  if(paddr == -1) return 0;
  offset = vaddr& ~TARGET_PAGE_MASK;
  if(offset+size > TARGET_PAGE_SIZE) {
        size1 = TARGET_PAGE_SIZE-offset;
        size2 = size -size1;
  } else
        size1 = size, size2 = 0;

  ret = taintcheck_memory_check(paddr, size1);
  if(size2) {
        paddr = DECAF_get_phys_addr(env,(vaddr&TARGET_PAGE_MASK)+TARGET_PAGE_SIZE);
        if(paddr != -1)
          ret |= taintcheck_memory_check(paddr,size2)<<size1;
  }

  return ret;
}


void taintcheck_nic_writebuf(const uint32_t addr, const int size, const uint8_t * taint)
{
	memcpy(&nic_bitmap[addr], taint, size);
}

void taintcheck_nic_readbuf(const uint32_t addr, const int size, uint8_t *taint)
{
  memcpy(taint, &nic_bitmap[addr], size);
}

void taintcheck_nic_cleanbuf(const uint32_t addr, const int size)
{
	memset(&nic_bitmap[addr], 0, size);
}

#if 0
void taintcheck_nic_out(const uint32_t addr, const int size)
{
  taintcheck_nic_writebuf(addr, size, (uint8_t *)&cpu_single_env->tempidx);
  return 0;
}

int taintcheck_nic_in(const uint32_t addr, const int size)
{
	taintcheck_nic_readbuf(addr, size, (uint8_t *)&cpu_single_env->tempidx);
  return 0;
}
#endif
#endif //CONFIG_TCG_TAINT
