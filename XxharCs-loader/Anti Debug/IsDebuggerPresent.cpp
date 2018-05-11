#include "IsDebuggerPresent.h"

BOOL IsDebuggerPresentAPI ()
{
	if(IsDebuggerPresent())
		return TRUE;
	else
		return FALSE;
}