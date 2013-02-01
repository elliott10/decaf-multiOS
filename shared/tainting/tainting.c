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
#include "shared/tainting/tainting.h"

//tainting_struct_t taint_config_internal;
//tainting_struct_t* taint_config = NULL;

void tainting_init(void)
{
/*
  taint_config_internal.taint_record_size = 0;
  taint_config_internal.taint_propagate = NULL;
  taint_config_internal.taint_disk = NULL;
  taint_config_internal.read_disk_taint = NULL;
  taint_config_internal.eip_tainted = NULL;
  taint_config = &taint_config_internal; */

#if 0 //LOK: Copied this over to tainting.c // AWH TAINT_ENABLED
    taintcheck_init();
    //EK
    //taintInit_err = taintInit(ram_size);
    if(taintInit_err){
        printf("%s\n", strerror(taintInit_err));
        exit(taintInit_err);
    }
    //xed2_init();
#endif
}

void tainting_cleanup(void)
{
  //nothing to do
}

