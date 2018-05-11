#include "NtQueryInformationProcess_ProcessDebugPort.h"

BOOL NtQueryInformationProcess_ProcessDebugPort ()
{
	typedef NTSTATUS (WINAPI *pNtQueryInformationProcess)(IN  HANDLE, IN  UINT, OUT PVOID, IN ULONG, OUT PULONG);

	pNtQueryInformationProcess NtQueryInfoProcess = NULL;
 
	const int ProcessDbgPort = 7;
 
	NTSTATUS Status;
	
#if defined (ENV64BIT)
	DWORD dProcessInformationLength = sizeof(ULONG) * 2;
	DWORD64 IsRemotePresent = 0;

#elif defined(ENV32BIT)
	DWORD dProcessInformationLength = sizeof(ULONG);
	DWORD32 IsRemotePresent = 0;
#endif

	HMODULE hNtdll = LoadLibrary(_xor_(_T("ntdll.dll")).c_str());
	if (hNtdll == NULL)
	{
	}
 
	NtQueryInfoProcess = (pNtQueryInformationProcess)GetProcAddress(hNtdll, _xor_("NtQueryInformationProcess").c_str());

	if (NtQueryInfoProcess == NULL)
		return 0;
 
	Status = NtQueryInfoProcess(GetCurrentProcess(), ProcessDbgPort, &IsRemotePresent, dProcessInformationLength, NULL);
	if(Status == 0x00000000 && IsRemotePresent != 0)
		return TRUE;
	else 
		return FALSE;
}

