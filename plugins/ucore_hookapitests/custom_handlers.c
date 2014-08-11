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
/*
 * custom_handlers.c
 *
 *
 *      Author: Xunchao Hu
 */

#include <stdio.h>
#include <stdlib.h>

#include "custom_handlers.h"

void hello_ret_handler(void *opaque)
{
	monitor_printf(default_mon, "hello_ret_handler-- hello::print_me ret\n");

}
