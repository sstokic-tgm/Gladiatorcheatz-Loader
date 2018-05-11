#include "PEB_BeingDebugged.h"

BOOL IsDebuggerPresentPEB()
{
#if defined (ENV64BIT)
	PPEB pPeb = (PPEB)__readgsqword(0x60);

#elif defined(ENV32BIT)
	PPEB pPeb = (PPEB)__readfsdword(0x30);

#endif

	if (pPeb->BeingDebugged == 1)
		return TRUE;
	else
		return FALSE;
}

