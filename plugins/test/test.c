/*
Copyright (C) <2012> <Syracuse System Security (Sycure) Lab>
This is a plugin of DECAF. You can redistribute and modify it
under the terms of BSD license but it is made available
WITHOUT ANY WARRANTY. See the top-level COPYING file for more details.

For more information about DECAF and other softwares, see our
web site at:
http://sycurelab.ecs.syr.edu/

If you have any questions about DECAF,please post it on
http://code.google.com/p/decaf-platform/
*/
/**
 * @author Lok Yan
 * @date Oct 18 2012
 */

#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>

#include "DECAF_types.h"
#include "DECAF_main.h"
#include "DECAF_callback.h"
#include "vmi_callback.h"
#include "utils/Output.h"
#include "vmi_c_wrapper.h"

#include "DECAF_target.h"
//basic stub for plugins
static plugin_interface_t test_interface;
static int bVerboseTest = 0;

typedef struct _callbacktest_t
{
  char name[64];
  DECAF_callback_type_t cbtype;
  OCB_t ocbtype;
  gva_t from;
  gva_t to;
  DECAF_Handle handle;
  struct timeval tick;
  struct timeval tock;
  int count;
  double elapsedtime;
}callbacktest_t;

#define test_TEST_COUNT 7

static callbacktest_t test[test_TEST_COUNT] = {
    {"Block Begin Single", DECAF_BLOCK_BEGIN_CB, OCB_CONST, 0x7C90d9b0, 0, DECAF_NULL_HANDLE, {0, 0}, {0, 0}, 0, 0.0}, //0x7C90d580 is NtOpenFile 0x7C90d9b0 is NtReadFile
    {"Block Begin Page", DECAF_BLOCK_BEGIN_CB, OCB_PAGE, 0x7C90d9b0, 0, DECAF_NULL_HANDLE, {0, 0}, {0, 0}, 0, 0.0}, //0x7C90d090 is NtCreateFile
    {"Block Begin All", DECAF_BLOCK_BEGIN_CB, OCB_ALL, 0, 0, DECAF_NULL_HANDLE, {0, 0}, {0, 0}, 0, 0.0},
    {"Block End From Page", DECAF_BLOCK_END_CB, OCB_PAGE, 0x7C90d9b0, INV_ADDR, DECAF_NULL_HANDLE, {0, 0}, {0, 0}, 0, 0.0},
    {"Block End To Page", DECAF_BLOCK_END_CB, OCB_PAGE, INV_ADDR, 0x7C90d9b0, DECAF_NULL_HANDLE, {0, 0}, {0, 0}, 0, 0.0},
    {"Insn Begin", DECAF_INSN_BEGIN_CB, OCB_ALL, 0, 0, DECAF_NULL_HANDLE, {0, 0}, {0, 0}, 0, 0.0},
    {"Insn End", DECAF_INSN_END_CB, OCB_ALL, 0, 0, DECAF_NULL_HANDLE, {0, 0}, {0, 0}, 0, 0.0},
};





static char vmi_callback[10][30] = {"NULL","VMI_CREATEPROC_CB","VMI_REMOVEPROC_CB","VMI_LOADMODULE_CB","VMI_REMOVEMODULE_CB","VMI_LOADMAINMODULE_CB","VMI_PROCESSBEGIN_CB"};
static char decaf_callback[20][30] = {"NULL","DECAF_BLOCK_BEGIN_CB","DECAF_BLOCK_END_CB","DECAF_INSN_BEGIN_CB","DECAF_INSN_END_CB","DECAF_MEM_READ_CB","DECAF_MEM_WRITE_CB","DECAF_EIP_CHECK_CB","DECAF_KEYSTROKE_CB","DECAF_NIC_REC_CB","DECAF_NIC_SEND_CB","DECAF_OPCODE_RANGE_CB","DECAF_TLB_EXEC_CB","DECAF_READ_TAINTMEM_CB","DECAF_WRITE_TAINTMEM_CB","DECAF_BLOCK_TRANS_CB"};

static int curTest = 0;


static int taint_key_enabled=0;

static int vmiTest01 = 0;
static int vmiTest02 = 0;
static int vmiTest03 = 0;
static int vmiTest04 = 0;
static int vmiTest05 = 0;
static int vmiTest06 = 0;

static int decafTest01 = 0;
static int decafTest02 = 0;
static int decafTest03 = 0;
static int decafTest04 = 0;
static int decafTest05 = 0;
static int decafTest06 = 0;
static int decafTest07 = 0;
static int decafTest08 = 0;
static int decafTest09 = 0;
static int decafTest10 = 0;
static int decafTest11 = 0;
static int decafTest12 = 0;
static int decafTest13 = 0;
static int decafTest14 = 0;
static int decafTest15 = 0;

static int decafTest16 = 0;
static int decafTest17 = 0;

DECAF_Handle vmi_handle01 = DECAF_NULL_HANDLE; 
DECAF_Handle vmi_handle02 = DECAF_NULL_HANDLE; 
DECAF_Handle vmi_handle03 = DECAF_NULL_HANDLE; 
DECAF_Handle vmi_handle04 = DECAF_NULL_HANDLE; 
DECAF_Handle vmi_handle05 = DECAF_NULL_HANDLE; 
DECAF_Handle vmi_handle06 = DECAF_NULL_HANDLE; 

DECAF_Handle decaf_handle01 = DECAF_NULL_HANDLE;
DECAF_Handle decaf_handle02 = DECAF_NULL_HANDLE;
DECAF_Handle decaf_handle03 = DECAF_NULL_HANDLE;
DECAF_Handle decaf_handle04 = DECAF_NULL_HANDLE;
DECAF_Handle decaf_handle05 = DECAF_NULL_HANDLE;
DECAF_Handle decaf_handle06 = DECAF_NULL_HANDLE;
DECAF_Handle decaf_handle07 = DECAF_NULL_HANDLE;
DECAF_Handle decaf_handle08 = DECAF_NULL_HANDLE;
DECAF_Handle decaf_handle09 = DECAF_NULL_HANDLE;
DECAF_Handle decaf_handle10 = DECAF_NULL_HANDLE;
DECAF_Handle decaf_handle11 = DECAF_NULL_HANDLE;
DECAF_Handle decaf_handle12 = DECAF_NULL_HANDLE;
DECAF_Handle decaf_handle13 = DECAF_NULL_HANDLE;
DECAF_Handle decaf_handle14 = DECAF_NULL_HANDLE;
DECAF_Handle decaf_handle15 = DECAF_NULL_HANDLE;

DECAF_Handle optimizedBlockBeginH = DECAF_NULL_HANDLE;
DECAF_Handle optimizedBlockEndH = DECAF_NULL_HANDLE;


static DECAF_Handle processbegin_handle = DECAF_NULL_HANDLE;
static DECAF_Handle removeproc_handle = DECAF_NULL_HANDLE;

static char targetname[512];
static uint32_t targetpid;
static uint32_t targetcr3;

static void runTests(void);

static void test_printSummary(void);
static void test_resetTests(void);

static int decaf_test_init(void);
static int vmi_test_init(void);
static void test_cleanup(void);

static void test_printSummary(void)
{
  int i = 0;
  DECAF_printf("******* SUMMARY *******\n");
  DECAF_printf("%+30s\t%12s\t%10s\n", "Test", "Count", "Time");
  for (i = 0; i < test_TEST_COUNT; i++)
  {
    DECAF_printf("%-30s\t%12u\t%.5f\n", test[i].name, test[i].count, test[i].elapsedtime);
  }
}

static void test_resetTests(void)
{
  int i = 0;
  for (i = 0; i < test_TEST_COUNT; i++)
  {
    test[i].tick.tv_sec = 0;
    test[i].tick.tv_usec = 0;
    test[i].tock.tv_sec = 0;
    test[i].tock.tv_usec = 0;
    test[i].handle = 0;
    test[i].count = 0;
    test[i].elapsedtime = 0.0;
  }
}

static void test_loadmainmodule_callback(VMI_Callback_Params* params)
{
  char procname[64];
  uint32_t pid;

  if (params == NULL)
  {
    return;
  }

  //DECAF_printf("Process with pid = %d and cr3 = %u was just created\n", params->lmm.pid, params->lmm.cr3);

  VMI_find_process_by_cr3_c(params->cp.cr3, procname, 64, &pid);
  //in find_process pid is set to 1 if the process is not found
  // otherwise the number of elements in the module list is returned
  if (pid == (uint32_t)(-1))
  {
    return;
  }

  if (strcmp(targetname, procname) == 0)
  {
    targetpid = pid;
    targetcr3 = params->cp.cr3;
    runTests();
  }
}

static void test_removeproc_callback(VMI_Callback_Params* params)
{
  double elapsedtime;

  if (params == NULL)
  {
    return;
  }

  if (targetpid == params->rp.pid)
  {
    if (curTest >= test_TEST_COUNT)
    {
      return;
    }

    if (test[curTest].handle == DECAF_NULL_HANDLE)
    {
      return;
    }

    //unregister the callback FIRST before getting the time of day - so
    // we don't get any unnecessary callbacks (although we shouldn't
    // since the guest should be paused.... right?)
    DECAF_unregister_callback(test[curTest].cbtype, test[curTest].handle);
    test[curTest].handle = DECAF_NULL_HANDLE;
    DECAF_printf("Callback Count = %u\n", test[curTest].count);

    gettimeofday(&test[curTest].tock, NULL);

    elapsedtime = (double)test[curTest].tock.tv_sec + ((double)test[curTest].tock.tv_usec / 1000000.0);
    elapsedtime -= ((double)test[curTest].tick.tv_sec + ((double)test[curTest].tick.tv_usec / 1000000.0));
    DECAF_printf("Process [%s] with pid [%d] ended at %u:%u\n", targetname, targetpid, test[curTest].tock.tv_sec, test[curTest].tock.tv_usec);
    DECAF_printf("  Elapsed time = %0.6f seconds\n", elapsedtime);

    test[curTest].elapsedtime = elapsedtime;

    //increment for the next test
    curTest++;
    if (curTest < test_TEST_COUNT)
    {
      DECAF_printf("%d of %d tests completed\n", curTest, test_TEST_COUNT);
      DECAF_printf("Please execute %s again to start next test\n", targetname);
    }
    else
    {
      DECAF_printf("All tests have completed\n");
      test_printSummary();
    }
    targetpid = (uint32_t)(-1);
    targetcr3 = 0;
  }
}

static void test_genericcallback(DECAF_Callback_Params* param)
{
  if (curTest >= test_TEST_COUNT)
  {
    return;
  }

  //LOK: Setup to do a more comprehensive test that does something with the parameters
  //if (1 || bVerboseTest)
  if (0)
  {
    switch(test[curTest].cbtype)
    {
      case (DECAF_BLOCK_BEGIN_CB):
      {
        DECAF_printf("BB @ [%x]\n", param->bb.tb->pc);
        break;
      }
      case (DECAF_BLOCK_END_CB):
      {
        DECAF_printf("BE @ [%x] [%x] -> [%x]\n", param->be.tb->pc, param->be.cur_pc, param->be.next_pc);
        break;
      }
      default:
      case (DECAF_INSN_BEGIN_CB):
      case (DECAF_INSN_END_CB):
      {
        //do nothing yet?
      }
    }
  }

  //TODO: Add support for ONLY tracking target process and not ALL processes
  test[curTest].count++;
}

static void runTests(void)
{
  if (curTest >= test_TEST_COUNT)
  {
    DECAF_printf("All tests have completed\n");
    return;
  }

  if (test[curTest].handle != DECAF_NULL_HANDLE)
  {
    DECAF_printf("%s test is currently running\n", test[curTest].name);
    return;
  }

  DECAF_printf("\n");
  DECAF_printf("**********************************************\n");
  DECAF_printf("Running the %s test\n", test[curTest].name);
  DECAF_printf("\n");
  gettimeofday(&test[curTest].tick, NULL);
  DECAF_printf("Process [%s] with pid [%d] started at %u:%u\n", targetname, targetpid, test[curTest].tick.tv_sec, test[curTest].tick.tv_usec);
  DECAF_printf("Registering for callback\n");

  switch(test[curTest].cbtype)
  {
    case (DECAF_BLOCK_BEGIN_CB):
    {
      test[curTest].handle = DECAF_registerOptimizedBlockBeginCallback(&test_genericcallback, NULL, test[curTest].from, test[curTest].ocbtype);
      break;
    }
    case (DECAF_BLOCK_END_CB):
    {
      test[curTest].handle = DECAF_registerOptimizedBlockEndCallback(&test_genericcallback, NULL, test[curTest].from, test[curTest].to);
      break;
    }
    default:
    case (DECAF_INSN_BEGIN_CB):
    case (DECAF_INSN_END_CB):
    {
      test[curTest].handle = DECAF_register_callback(test[curTest].cbtype, &test_genericcallback, NULL);
    }
  }

  if (test[curTest].handle == DECAF_NULL_HANDLE)
  {
    DECAF_printf("Could not register the event\n");
    return;
  }

  test[curTest].count = 0;
  DECAF_printf("Callback Registered\n");
}

void do_test(Monitor* mon, const QDict* qdict)
{

  if ((qdict != NULL) && (qdict_haskey(qdict, "procname")))
  {
    strncpy(targetname, qdict_get_str(qdict, "procname"), 512);
  }
  else
  {
    DECAF_printf("A program name was not specified, so we will use sort.exe\n");
    strncpy(targetname, "sort.exe", 512);
  }
  targetname[511] = '\0';

  curTest = 0;
  test_resetTests();
  DECAF_printf("Tests will be completed using: %s (case sensitive).\n", targetname);
  DECAF_printf("  Run the program to start the first test\n");
}


static void vmi_cb_func01(VMI_Callback_Params* params)
{
	//char procname[64];
	char *procname = NULL;
	uint32_t pid, cr3, ebp;

	if (params == NULL)
	{
		return;
	}

	vmiTest01++;
	DECAF_printf("[%s] callback test.",vmi_callback[1]);

	pid = params->cp.pid;
	cr3 = params->cp.cr3;
	ebp = DECAF_getEBP(cpu_single_env);
	procname = params->cp.name;
	//VMI_find_process_by_ebp

	DECAF_printf("Process found: name [%s], pid [%d], cr3 [%08x], ebp [%08x]\n",procname, pid, cr3, ebp);

	/*
	   vmiTest01++;
	   if(vmiTest01 > 3)
	   {
	   return 0;
	   }
	 */
}
static void vmi_cb_func02(VMI_Callback_Params* params)
{
	uint32_t pid;
	if (params == NULL)
	{
		return;
	}
	vmiTest02++;
	/*
	   if(vmiTest02 > 3)
	   {
	   return 0;
	   }
	 */
	DECAF_printf("[%s] callback test.",vmi_callback[2]);
	pid = params->rp.pid;
	DECAF_printf("Process remove: pid [%d]\n",pid);

	if(vmiTest02 == 1)
	{
		VMI_unregister_callback(VMI_CREATEPROC_CB, vmi_handle01); 
		VMI_unregister_callback(VMI_REMOVEPROC_CB, vmi_handle02); 
		VMI_unregister_callback(VMI_LOADMODULE_CB, vmi_handle03); 
		VMI_unregister_callback(VMI_REMOVEMODULE_CB, vmi_handle04); 
		VMI_unregister_callback(VMI_LOADMAINMODULE_CB, vmi_handle05); 
		VMI_unregister_callback(VMI_PROCESSBEGIN_CB, vmi_handle06); 

		decaf_test_init();
	}
}

static void vmi_cb_func03(VMI_Callback_Params* params)
{
	uint32_t pid, base, size;
	//char name[64], full_name[128];
	char *name = NULL;
	char *full_name = NULL;

	if(params == NULL)
	{   
		return;
	}  

	vmiTest03++;
	DECAF_printf("[%s] callback test.",vmi_callback[3]);

	pid=params->lm.pid;
	base=params->lm.base;
	size=params->lm.size;
	name=params->lm.name;
	full_name=params->lm.full_name;
	/*
	   if(vmiTest03 > 3) {
	   return 0;
	   }
	 */

	DECAF_printf("Module found: fullname [%s], pid [%d], base [%08x], size [%08x], name [%s]\n", full_name, pid, base, size, name);
}
static void vmi_cb_func04(VMI_Callback_Params* params)
{
	uint32_t pid, base;

	if (params == NULL)
	{
		return;
	}

	vmiTest04++;
	DECAF_printf("[%s] callback test.",vmi_callback[4]);

	pid=params->rm.pid;
	base=params->rm.base;

	DECAF_printf("Module remove: pid [%d], base [%08x]\n",pid, base);

	/*
	   if(vmiTest04 > 3)
	   {
	   return 0;
	   }
	 */
}
static void vmi_cb_func05(VMI_Callback_Params* params)
{
  vmiTest05++;
  if(vmiTest05 > 3)
  {
	  return 0;
  }
  DECAF_printf("[%s] callback test.\n",vmi_callback[5]);
}
static void vmi_cb_func06(VMI_Callback_Params* params)
{
  vmiTest06++;
  if(vmiTest06 > 3)
  {
	  return 0;
  }
  DECAF_printf("[%s] callback test.\n",vmi_callback[6]);
}


static void decaf_cb_func01(DECAF_Callback_Params* params)
{
	uint32_t eip = -1, cr3 = -1, ebp = -1;

	decafTest01++;
	if(decafTest01 > 3)
	{
		return 0;
	}
	DECAF_printf("[%s] callback test.\n", decaf_callback[1]);

	/*
	DECAF_read_register(eip_reg, &eip);
	if(eip == -1)
		DECAF_printf("DECAF_read_register() error*****\n");

	DECAF_read_register(cr3_reg,&cr3);
	if(cr3 == -1)
		DECAF_printf("DECAF_read_register() error*****\n");

	DECAF_read_register(ebp_reg,&ebp);
	if(ebp == -1)
		DECAF_printf("DECAF_read_register() error*****\n");
		*/
}

static void decaf_cb_func02(DECAF_Callback_Params* params)
{
  decafTest02++;
  if(decafTest02 > 3)
  {
	  return 0;
  }
  DECAF_printf("[%s] callback test.", decaf_callback[2]);
  DECAF_printf("Block_End: cur_pc [%08x], next_pc [%08x]\n", params->be.cur_pc, params->be.next_pc);
}

static void decaf_cb_func03(DECAF_Callback_Params* params)
{
  decafTest03++;
  if(decafTest03 > 3)
  {
	  return 0;
  }
  DECAF_printf("[%s] callback test.\n", decaf_callback[3]);
}
static void decaf_cb_func04(DECAF_Callback_Params* params)
{
  decafTest04++;
  if(decafTest04 > 3)
  {
	  return 0;
  }
  DECAF_printf("[%s] callback test.\n", decaf_callback[4]);
}
static void decaf_cb_func05(DECAF_Callback_Params* params)
{
	uint32_t virt_addr, phys_addr;
	int size;
	decafTest05++;
	if(decafTest05 > 3)
	{
		return 0;
	}
	DECAF_printf("[%s] callback test.", decaf_callback[5]);
	virt_addr=params->mw.vaddr;
	phys_addr=params->mw.paddr;
	size=params->mw.dt;
	DECAF_printf("Mem_Read: virt_addr [%08x], phys_addr [%08x], size [%d]\n", virt_addr, phys_addr, size);
}
static void decaf_cb_func06(DECAF_Callback_Params* params)
{
	uint32_t virt_addr, phys_addr;
	int size;
	decafTest06++;
	if(decafTest06 > 3)
	{
		return 0;
	}
	DECAF_printf("[%s] callback test.", decaf_callback[6]);
	virt_addr=params->mw.vaddr;
	phys_addr=params->mw.paddr;
	size=params->mw.dt;
	DECAF_printf("Mem_Write: virt_addr [%08x], phys_addr [%08x], size [%d]\n", virt_addr, phys_addr, size);
}
static void decaf_cb_func07(DECAF_Callback_Params* params)
{
  decafTest07++;
  if(decafTest07 > 3)
  {
	  return 0;
  }

  DECAF_printf("[%s] callback test.", decaf_callback[7]);

  DECAF_printf("CHECK_EIP : SOURCE: 0x%08x TARGET: 0x%08x  TAINT_VALUE: 0x%08x \n",
		params->ec.source_eip, params->ec.target_eip, params->ec.target_eip_taint);

}
static void decaf_cb_func08(DECAF_Callback_Params* params)
{
	decafTest08++;
	if(decafTest08 > 3)
	{
		return 0;
	}
	DECAF_printf("[%s] callback test.\n", decaf_callback[8]);

	if(!taint_key_enabled)
		return;

	int keycode=params->ks.keycode;
	uint32_t *taint_mark=params->ks.taint_mark;
	*taint_mark=taint_key_enabled;
	taint_key_enabled=0;
	printf("Taint keystroke %d \n ",keycode);
}
static void decaf_cb_func09(DECAF_Callback_Params* params)
{
  decafTest09++;
  if(decafTest09 > 3)
  {
	  return 0;
  }
  DECAF_printf("[%s] callback test.\n", decaf_callback[9]);
}
static void decaf_cb_func10(DECAF_Callback_Params* params)
{
  decafTest10++;
  if(decafTest10 > 3)
  {
	  return 0;
  }
  DECAF_printf("[%s] callback test.\n", decaf_callback[10]);
}
static void decaf_cb_func11(DECAF_Callback_Params* params)
{
  decafTest11++;
  if(decafTest11 > 3)
  {
	  return 0;
  }
  DECAF_printf("[%s] callback test.", decaf_callback[11]);
  DECAF_printf("Opcode_Range: eip [%08x], next_eip [%08x], op [%d]\n", params->op.eip, params->op.next_eip, params->op.op);
}
static void decaf_cb_func12(DECAF_Callback_Params* params)
{
	CPUState *env = params->tx.env;
	uint32_t vaddr = params->tx.vaddr;
	uint32_t pgd = -1, ebp = -1;

	decafTest12++;
	if(decafTest12 > 3)
	{
		return 0;
	}
	DECAF_printf("[%s] callback test.\n", decaf_callback[12]);

	pgd = DECAF_getPGD(env);
	if(pgd == -1)
		DECAF_printf("DECAF_getPGD() error*****\n");

	ebp = DECAF_getEBP(env);
	if(ebp == -1)
		DECAF_printf("DECAF_getEBP() error*****\n");

	DECAF_printf("TLB_call_back: vaddr [%08x], pgd [%08x], ebp [%08x]\n", vaddr, pgd, ebp);
}
static void decaf_cb_func13(DECAF_Callback_Params* params)
{
	uint32_t eip= DECAF_getPC(cpu_single_env);
	uint32_t cr3= DECAF_getPGD(cpu_single_env);
	uint32_t ebp= DECAF_getEBP(cpu_single_env);

	decafTest13++;
	if(decafTest13 > 3)
	{

		if(decaf_handle13)
		{
			DECAF_unregister_callback(DECAF_READ_TAINTMEM_CB, decaf_handle13);
			decaf_handle13 = DECAF_NULL_HANDLE;
		}

		if(decaf_handle08)
		{
			DECAF_unregister_callback(DECAF_KEYSTROKE_CB, decaf_handle08);//invoked when system read a keystroke from ps2 driver
			decaf_handle08 = DECAF_NULL_HANDLE;
		}

		//	DECAF_unregister_callback(DECAF_WRITE_TAINTMEM_CB, decaf_handle14);
		return 0;
	}

	DECAF_printf("[%s] callback test.", decaf_callback[13]);
	DECAF_printf("Read_Taint_Mem: vaddr [%08x], paddr [%08x], size [%d], taint_info [%08x], eip [%08x], cr3 [%08x], ebp [%08x]\n", params->rt.vaddr, params->rt.paddr, params->rt.size,*((uint32_t *)params->rt.taint_info), eip, cr3, ebp);
}
static void decaf_cb_func14(DECAF_Callback_Params* params)
{
	uint32_t eip=-1, cr3=-1, ebp=-1;

	decafTest14++;
	if(decafTest14 > 3)
	{
		//	DECAF_unregister_callback(DECAF_READ_TAINTMEM_CB, decaf_handle13);
		if(decaf_handle14)
		{
			DECAF_unregister_callback(DECAF_WRITE_TAINTMEM_CB, decaf_handle14);
			decaf_handle14 = DECAF_NULL_HANDLE;
		}
		return 0;
	}

	eip = DECAF_getPC(cpu_single_env);
	if(eip == -1)
	DECAF_printf("DECAF_getPC() error*****\n");

	cr3 = DECAF_getPGD(cpu_single_env);
	if(cr3 == -1)
	DECAF_printf("DECAF_getPGD() error*****\n");

	ebp = DECAF_getEBP(cpu_single_env);
	if(ebp == -1)
	DECAF_printf("DECAF_getEBP() error*****\n");

	DECAF_printf("[%s] callback test.", decaf_callback[14]);
	DECAF_printf("Write_Taint_Mem: vaddr [%08x], paddr [%08x], size [%d], taint_info [%08x], eip [%08x], cr3 [%08x], ebp [%08x]\n", params->rt.vaddr, params->rt.paddr, params->rt.size,*((uint32_t *)params->rt.taint_info), eip, cr3, ebp);
}
static void decaf_cb_func15(DECAF_Callback_Params* params)
{
  decafTest15++;
  if(decafTest15 > 3)
  {
	  return 0;
  }
  DECAF_printf("[%s] callback test.\n", decaf_callback[15]);
}

static void oBlockBegin_cb(DECAF_Callback_Params* params)
{
	uint32_t pc = -1, pgd = -1, ebp = -1;
	decafTest16++;
	if(decafTest16 > 3)
	{
		return 0;
	}

	if(cpu_single_env == NULL) return;

	pc = DECAF_getPC(cpu_single_env);
	if(pc == -1)
	DECAF_printf("DECAF_getPC() error*****\n");

	pgd = DECAF_getPGD(cpu_single_env);
	if(pgd == -1)
	DECAF_printf("DECAF_getPGD() error*****\n");

	ebp = DECAF_getEBP(cpu_single_env);
	if(ebp == -1)
	DECAF_printf("DECAF_getEBP() error*****\n");

	DECAF_printf("[OptimizedBlockBeginCallback] callback test.");
	DECAF_printf("BlockBegin: record->eip ?= pc. pc [%08x], pgd [%08x], ebp [%08x]\n");
}

static void oBlockEnd_cb(DECAF_Callback_Params* params)
{
	unsigned char insn_buf[2];
	int is_call = 0, is_ret = 0;
	int b;

	decafTest17++;
	if(decafTest17 > 3)
	{
		return 0;
	}
	DECAF_printf("[OptimizedBlockEndCallback] callback test.\n");

	if(DECAF_read_mem(params->be.env,params->be.cur_pc,sizeof(char)*2,insn_buf) < 0)
		DECAF_printf("DECAF_read_mem() error*****\n");

	switch(insn_buf[0]) {
		case 0x9a:
		case 0xe8:
			is_call = 1;
			break;
		case 0xff:
			b = (insn_buf[1]>>3) & 7;
			if(b==2 || b==3)
				is_call = 1;
			break;

		case 0xc2:
		case 0xc3:
		case 0xca:
		case 0xcb:
			is_ret = 1;
			break;
		default: break;
	}

	if (is_call)
		DECAF_printf("BlockEnd: It is Call.\n");
	else if (is_ret)
		DECAF_printf("BlockEnd: It is Ret.\n");
}



static int api_hook(void)
{


hookapi_hook_function();
hookapi_hook_return();
hookapi_remove_hook();
hookapi_hook_function_byname();


}

static int decaf_test_init(void)
{
	//DECAF_output_init(NULL);
	DECAF_printf("\n*****02.DECAF callback interfaces test*****\n");

	uint32_t begin_eip = -1;
	char *key = "t"; 

	/*
	//VMI
	vmi_handle01 = VMI_register_callback(VMI_CREATEPROC_CB, &vmi_cb_func01, NULL); 
	vmi_handle02 = VMI_register_callback(VMI_REMOVEPROC_CB, &vmi_cb_func02, NULL);
	vmi_handle03 = VMI_register_callback(VMI_LOADMODULE_CB, &vmi_cb_func03, NULL);
	vmi_handle04 = VMI_register_callback(VMI_REMOVEMODULE_CB, &vmi_cb_func04, NULL);
	vmi_handle05 = VMI_register_callback(VMI_LOADMAINMODULE_CB, &vmi_cb_func05, NULL); //when process starts to run
	vmi_handle06 = VMI_register_callback(VMI_PROCESSBEGIN_CB, &vmi_cb_func06, NULL); //when process starts to run
	*/

	//DECAF
	decaf_handle01 = DECAF_register_callback(DECAF_BLOCK_BEGIN_CB, decaf_cb_func01, NULL);//Instruction
	decaf_handle02 = DECAF_register_callback(DECAF_BLOCK_END_CB, decaf_cb_func02, NULL);//Instruction
	decaf_handle03 = DECAF_register_callback(DECAF_INSN_BEGIN_CB, decaf_cb_func03, NULL);//invoked before this instruction is executed
	decaf_handle04 = DECAF_register_callback(DECAF_INSN_END_CB, decaf_cb_func04, NULL);//invoked after this instruction is executed

	decaf_handle05 = DECAF_register_callback(DECAF_MEM_READ_CB, decaf_cb_func05, NULL);//Mem read/write
	decaf_handle06 = DECAF_register_callback(DECAF_MEM_WRITE_CB, decaf_cb_func06, NULL);//Mem read/write

	decaf_handle07 = DECAF_register_callback(DECAF_EIP_CHECK_CB, decaf_cb_func07, NULL);//for every function call, it will invoked this callback before it jump to target function specified by EIP.


	decaf_handle13 = DECAF_register_callback(DECAF_READ_TAINTMEM_CB, decaf_cb_func13, NULL);
	decaf_handle14 = DECAF_register_callback(DECAF_WRITE_TAINTMEM_CB, decaf_cb_func14, NULL);

	//tain_key
	{
		taint_key_enabled=1;
		decaf_handle08 = DECAF_register_callback(DECAF_KEYSTROKE_CB, decaf_cb_func08, &taint_key_enabled);//invoked when system read a keystroke from ps2 driver
		// Send the key
		do_send_key(key);
	}

	decaf_handle09 = DECAF_register_callback(DECAF_NIC_REC_CB, decaf_cb_func09, NULL);//network “-device ne2k_pci,netdev=mynet”
	decaf_handle10 = DECAF_register_callback(DECAF_NIC_SEND_CB, decaf_cb_func10, NULL);//network “-device ne2k_pci,netdev=mynet”

	decaf_handle11 = DECAF_register_callback(DECAF_OPCODE_RANGE_CB, decaf_cb_func11, NULL);
	decaf_handle12 = DECAF_register_callback(DECAF_TLB_EXEC_CB, decaf_cb_func12, NULL);

	//CONFIG_TCG_LLVM
	//decaf_handle15 = DECAF_register_callback(DECAF_BLOCK_TRANS_CB, decaf_cb_func15, NULL);

	//block begin/end callback, for a high performance
	optimizedBlockBeginH = DECAF_registerOptimizedBlockBeginCallback(&oBlockBegin_cb, NULL, begin_eip, OCB_CONST);
	optimizedBlockEndH = DECAF_registerOptimizedBlockEndCallback(&oBlockEnd_cb, NULL, INV_ADDR, INV_ADDR);

	/*
	if (vmi_handle01 == DECAF_NULL_HANDLE)
	{
		DECAF_printf("Could not register for the event: [%s]\n", vmi_callback[1]);
	}
	if (vmi_handle02 == DECAF_NULL_HANDLE)
	{
		DECAF_printf("Could not register for the event: [%s]\n", vmi_callback[2]);
	}
	if (vmi_handle03 == DECAF_NULL_HANDLE)
	{
		DECAF_printf("Could not register for the event: [%s]\n", vmi_callback[3]);
	}
	if (vmi_handle04 == DECAF_NULL_HANDLE)
	{
		DECAF_printf("Could not register for the event: [%s]\n", vmi_callback[4]);
	}
	if (vmi_handle05 == DECAF_NULL_HANDLE)
	{
		DECAF_printf("Could not register for the event: [%s]\n", vmi_callback[5]);
	}
	if (vmi_handle06 == DECAF_NULL_HANDLE)
	{
		DECAF_printf("Could not register for the event: [%s]\n", vmi_callback[6]);
	}
	*/

	if (decaf_handle01 == DECAF_NULL_HANDLE)
	{
		DECAF_printf("Could not register for the event: [%s]\n", decaf_callback[1]);
	}
	if (decaf_handle02 == DECAF_NULL_HANDLE)
	{
		DECAF_printf("Could not register for the event: [%s]\n", decaf_callback[2]);
	}
	if (decaf_handle03 == DECAF_NULL_HANDLE)
	{
		DECAF_printf("Could not register for the event: [%s]\n", decaf_callback[3]);
	}
	if (decaf_handle04 == DECAF_NULL_HANDLE)
	{
		DECAF_printf("Could not register for the event: [%s]\n", decaf_callback[4]);
	}
	if (decaf_handle05 == DECAF_NULL_HANDLE)
	{
		DECAF_printf("Could not register for the event: [%s]\n", decaf_callback[5]);
	}
	if (decaf_handle06 == DECAF_NULL_HANDLE)
	{
		DECAF_printf("Could not register for the event: [%s]\n", decaf_callback[6]);
	}
	if (decaf_handle07 == DECAF_NULL_HANDLE)
	{
		DECAF_printf("Could not register for the event: [%s]\n", decaf_callback[7]);
	}
	if (decaf_handle08 == DECAF_NULL_HANDLE)
	{
		DECAF_printf("Could not register for the event: [%s]\n", decaf_callback[8]);
	}
	if (decaf_handle09 == DECAF_NULL_HANDLE)
	{
		DECAF_printf("Could not register for the event: [%s]\n", decaf_callback[9]);
	}
	if (decaf_handle10 == DECAF_NULL_HANDLE)
	{
		DECAF_printf("Could not register for the event: [%s]\n", decaf_callback[10]);
	}
	if (decaf_handle11 == DECAF_NULL_HANDLE)
	{
		DECAF_printf("Could not register for the event: [%s]\n", decaf_callback[11]);
	}
	if (decaf_handle12 == DECAF_NULL_HANDLE)
	{
		DECAF_printf("Could not register for the event: [%s]\n", decaf_callback[12]);
	}
	if (decaf_handle13 == DECAF_NULL_HANDLE)
	{
		DECAF_printf("Could not register for the event: [%s]\n", decaf_callback[13]);
	}
	if (decaf_handle14 == DECAF_NULL_HANDLE)
	{
		DECAF_printf("Could not register for the event: [%s]\n", decaf_callback[14]);
	}
	if (decaf_handle15 == DECAF_NULL_HANDLE)
	{
		DECAF_printf("Could not register for the event: [%s]\n", decaf_callback[15]);
	}

	if (optimizedBlockBeginH == DECAF_NULL_HANDLE)
	{
		DECAF_printf("Could not register for the event: [OptimizedBlockBeginCallback]\n");
	}
	if (optimizedBlockEndH == DECAF_NULL_HANDLE)
	{
		DECAF_printf("Could not register for the event: [OptimizedBlockEndCallback]\n");
	}

	targetname[0] = '\0';
	targetcr3 = 0;
	targetpid = (uint32_t)(-1);

	//do_test(NULL, NULL);

	return (0);
}

static int vmi_test_init(void)
{
	DECAF_output_init(NULL);
	DECAF_printf("\n*****Test Case Start*****\n");
	DECAF_printf("\n*****01.VMI callback interfaces test*****\n");
	DECAF_printf("Please create a process in Guest OS.\n");

	//VMI
	vmi_handle01 = VMI_register_callback(VMI_CREATEPROC_CB, &vmi_cb_func01, NULL); 
	vmi_handle02 = VMI_register_callback(VMI_REMOVEPROC_CB, &vmi_cb_func02, NULL);
	vmi_handle03 = VMI_register_callback(VMI_LOADMODULE_CB, &vmi_cb_func03, NULL);
	vmi_handle04 = VMI_register_callback(VMI_REMOVEMODULE_CB, &vmi_cb_func04, NULL);
	vmi_handle05 = VMI_register_callback(VMI_LOADMAINMODULE_CB, &vmi_cb_func05, NULL); //when process starts to run
	vmi_handle06 = VMI_register_callback(VMI_PROCESSBEGIN_CB, &vmi_cb_func06, NULL); //when process starts to run

	if (vmi_handle01 == DECAF_NULL_HANDLE)
	{
		DECAF_printf("Could not register for the event: [%s]\n", vmi_callback[1]);
	}
	if (vmi_handle02 == DECAF_NULL_HANDLE)
	{
		DECAF_printf("Could not register for the event: [%s]\n", vmi_callback[2]);
	}
	if (vmi_handle03 == DECAF_NULL_HANDLE)
	{
		DECAF_printf("Could not register for the event: [%s]\n", vmi_callback[3]);
	}
	if (vmi_handle04 == DECAF_NULL_HANDLE)
	{
		DECAF_printf("Could not register for the event: [%s]\n", vmi_callback[4]);
	}
	if (vmi_handle05 == DECAF_NULL_HANDLE)
	{
		DECAF_printf("Could not register for the event: [%s]\n", vmi_callback[5]);
	}
	if (vmi_handle06 == DECAF_NULL_HANDLE)
	{
		DECAF_printf("Could not register for the event: [%s]\n", vmi_callback[6]);
	}

	return (0);
}

static void test_cleanup(void)
{
	VMI_unregister_callback(VMI_CREATEPROC_CB, vmi_handle01); 
	VMI_unregister_callback(VMI_REMOVEPROC_CB, vmi_handle02); 
	VMI_unregister_callback(VMI_LOADMODULE_CB, vmi_handle03); 
	VMI_unregister_callback(VMI_REMOVEMODULE_CB, vmi_handle04); 
	VMI_unregister_callback(VMI_LOADMAINMODULE_CB, vmi_handle05); 
	VMI_unregister_callback(VMI_PROCESSBEGIN_CB, vmi_handle06); 

	DECAF_unregister_callback(DECAF_BLOCK_BEGIN_CB, decaf_handle01);//Instruction
	DECAF_unregister_callback(DECAF_BLOCK_END_CB, decaf_handle02);//Instruction
	DECAF_unregister_callback(DECAF_INSN_BEGIN_CB, decaf_handle03);//invoked before this instruction is executed
	DECAF_unregister_callback(DECAF_INSN_END_CB, decaf_handle04);//invoked after this instruction is executed
	DECAF_unregister_callback(DECAF_MEM_READ_CB, decaf_handle05);//Mem read/write
	DECAF_unregister_callback(DECAF_MEM_WRITE_CB, decaf_handle06);//Mem read/write

	DECAF_unregister_callback(DECAF_EIP_CHECK_CB, decaf_handle07);//for every function call, it will invoked this callback before it jump to target function specified by EIP.

	DECAF_unregister_callback(DECAF_KEYSTROKE_CB, decaf_handle08);//invoked when system read a keystroke from ps2 driver
	DECAF_unregister_callback(DECAF_NIC_REC_CB, decaf_handle09);//network “-device ne2k_pci,netdev=mynet”
	DECAF_unregister_callback(DECAF_NIC_SEND_CB, decaf_handle10);//network “-device ne2k_pci,netdev=mynet”
	DECAF_unregister_callback(DECAF_OPCODE_RANGE_CB, decaf_handle11);
	DECAF_unregister_callback(DECAF_TLB_EXEC_CB, decaf_handle12);
	DECAF_unregister_callback(DECAF_READ_TAINTMEM_CB, decaf_handle13);
	DECAF_unregister_callback(DECAF_WRITE_TAINTMEM_CB, decaf_handle14);

	//DECAF_unregister_callback(DECAF_BLOCK_TRANS_CB, decaf_handle15);

	DECAF_unregisterOptimizedBlockBeginCallback(optimizedBlockBeginH);
	DECAF_unregisterOptimizedBlockEndCallback(optimizedBlockEndH);

	curTest = 0;
	DECAF_printf("Bye world\n");
}

static mon_cmd_t test_term_cmds[] = {
  #include "plugin_cmds.h"
  {NULL, NULL, },
};

plugin_interface_t* init_plugin(void)
{
  test_interface.mon_cmds = test_term_cmds;
  test_interface.plugin_cleanup = &test_cleanup;
  
  //initialize the plugin
//  test_init();
  return (&test_interface);
}

