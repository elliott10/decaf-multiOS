
#ifndef UCORE_PROCINFO_H_
#define UCORE_PROCINFO_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef target_ulong target_ptr;

/** Data structure that helps keep things organized. **/
typedef struct _UcoreProcInfo
{
	char strName[32];
#include "ucore_kernel_procinfo.h"
} UcoreProcInfo;

int ucore_printProcInfo(UcoreProcInfo* pPI);
int ucore_load_proc_info(CPUState * env, UcoreProcInfo &pi);
void ucore_load_library_info(const char *strName);

#ifdef __cplusplus
};
#endif
#endif /* UCORE_PROCINFO_H_ */

