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
{
.name       = "load_plugin",
.args_type  = "filename:F",
.params     = "filename",
.help       = "Load a DECAF plugin",
.mhandler.cmd_new = do_load_plugin,
},


{
.name       = "unload_plugin",
.args_type  = "",
.params     = "",
.help       = "Unload the current DECAF plugin",
.mhandler.cmd_new = do_unload_plugin,
},


/* operating system information */
{
	.name		= "guest_ps|ps",
	.args_type	= "",
	.mhandler.info	= do_guest_ps,
	.params		= "", 
	.help		= "list the processes on guest system"
},
{
	.name		= "guest_modules", 
	.args_type	= "pid:i", 
	.mhandler.cmd	= do_guest_modules,
	.params		= "pid",
	.help		= "list the modules of the process with <pid>"
},
{
	.name		= "linux_ps",
	.args_type	= "mmap_flag:i?", 
	.mhandler.cmd	= do_linux_ps,
	.params		= "[mmap_flag]", 
	.help		= "list the processes on linux guest system (default: mmap_flag = 1)"
},
