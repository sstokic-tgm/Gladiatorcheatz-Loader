#include "OutputDebugStringAPI.h"

BOOL OutputDebugStringAPI()
{

	BOOL IsDbgPresent = FALSE;
	DWORD Val = 0x29A;

	// This is working only in Windows XP/2000
	if (IsWindowsXPOr2k())
	{
		SetLastError(Val);
		OutputDebugString(_xor_(_T("random")).c_str());

		if (GetLastError() == Val)
			IsDbgPresent = TRUE;
	}
		
	return IsDbgPresent;
}

