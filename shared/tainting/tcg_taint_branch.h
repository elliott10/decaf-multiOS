#ifndef __DECAF_TCG_TAINT_BRANCH_H__
#define __DECAF_TCG_TAINT_BRANCH_H__

/* Comment these in to enable local branching logic */

//#define BRANCH_DEPOSIT_I32 1
//#define LOG_DEPOSIT_I32 1

//#define BRANCH_SETCOND2_I32 1
//#define LOG_SETCOND2_I32 1

// OK
//#define BRANCH_MOVI_I32 1
//#define LOG_MOVI_I32 1

// Freeze, OK with global check
//#define BRANCH_MOV_I32 1
//#define LOG_MOV_I32 1

// Abort
//#define BRANCH_ADD_I32 1
//#define LOG_ADD_I32 1

// Invalid digital signature
//#define BRANCH_SUB_I32 1
//#define LOG_SUB_I32 1

// Freeze
//#define BRANCH_AND_I32 1
//#define LOG_AND_I32 1

// Abort
//#define BRANCH_OR_I32 1
//#define LOG_OR_I32 1

//#define LOG_DEPOSIT_I32 1
//#define LOG_SHL_I32 1
//#define LOG_SHR_I32 1
//#define LOG_SAR_I32 1
//#define LOG_ROTL_I32 1
//#define LOG_ROTR_I32 1
//#define LOG_MUL_I32 1

#endif /* __DECAF_TCG_TAINT_BRANCH_H__ */

