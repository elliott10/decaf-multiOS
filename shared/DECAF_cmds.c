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
#include "DECAF_cmds.h"
#include "procmod.h"

void do_linux_ps(Monitor *mon, const QDict* qdict)
{
  if (qdict_haskey(qdict, "mmap_flag"))
    linux_ps(mon, qdict_get_int(qdict, "mmap_flag"));
  else
    linux_ps(mon, 1);
}

void do_guest_ps(Monitor *mon)
{
  list_procs(mon);
}

void do_guest_modules(Monitor *mon, const QDict *qdict)
{
  int pid = -1;

  //LOK: This check should be unnecessary since the
  // monitor should have taken care of it. However we leave it here
  if (qdict_haskey(qdict, "pid"))
  {
    pid = qdict_get_int(qdict, "pid");
  }    
 
  if (pid == -1)
  {
    monitor_printf(mon, "need a pid\n");
  }
  list_guest_modules(mon, pid);
}
