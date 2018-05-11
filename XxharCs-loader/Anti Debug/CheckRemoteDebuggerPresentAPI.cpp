#include "CheckRemoteDebuggerPresentAPI.h"

BOOL CheckRemoteDebuggerPresentAPI ()
{
	BOOL bIsDbgPresent = FALSE;
	CheckRemoteDebuggerPresent(GetCurrentProcess(), &bIsDbgPresent);
	return bIsDbgPresent;
}
