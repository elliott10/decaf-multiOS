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
/*
 * DECAF_callback.h
 *
 *  Created on: Apr 10, 2012
 *      Author: heyin@syr.edu
 */

#ifndef DECAF_CALLBACK_H_
#define DECAF_CALLBACK_H_

//LOK: for CPUState
// #include "cpu.h" //Not needed - included in DECAF_callback_common.h
// #include "shared/DECAF_types.h" // not needed either
#include "shared/DECAF_callback_common.h"

#ifdef __cplusplus
extern "C"
{
#endif

/// \brief Register a callback function
///
/// @param cb_type the event type
/// @param cb_func the callback function
/// @param cb_cond the boolean condition provided by the caller. Only
/// if this condition is true, the callback can be activated. This condition
/// can be NULL, so that callback is always activated.
/// @return handle, which is needed to unregister this callback later.
extern DECAF_Handle DECAF_register_callback(
		DECAF_callback_type_t cb_type,
		DECAF_callback_func_t cb_func,
		int *cb_cond
                );

extern int DECAF_unregister_callback(DECAF_callback_type_t cb_type, DECAF_Handle handle);

DECAF_Handle DECAF_registerOptimizedBlockBeginCallback(
    DECAF_callback_func_t cb_func,
    int *cb_cond,
    gva_t addr,
    OCB_t type);

DECAF_Handle DECAF_registerOptimizedBlockEndCallback(
    DECAF_callback_func_t cb_func,
    int *cb_cond,
    gva_t from,
    gva_t to);

int DECAF_unregisterOptimizedBlockBeginCallback(DECAF_Handle handle);

int DECAF_unregisterOptimizedBlockEndCallback(DECAF_Handle handle);

#ifdef __cplusplus
}
#endif // __cplusplus


#endif /* DECAF_CALLBACK_H_ */
