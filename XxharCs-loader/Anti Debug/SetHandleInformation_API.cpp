#include "SetHandleInformation_API.h"
#include "..\XorStr.h"

BOOL SetHandleInformatiom_ProtectedHandle()
{
	HANDLE hMutex;

	hMutex = CreateMutex(NULL, FALSE, _xor_(_T("Random name")).c_str());

	SetHandleInformation(hMutex, HANDLE_FLAG_PROTECT_FROM_CLOSE, HANDLE_FLAG_PROTECT_FROM_CLOSE);

	__try {
		CloseHandle(hMutex);
	}

	__except (HANDLE_FLAG_PROTECT_FROM_CLOSE) {
		return TRUE;
	}

	return FALSE;
}