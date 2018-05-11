#include "NtQueryInformationProcess_ProcessDebugObject.h"

BOOL NtQueryInformationProcess_ProcessDebugObject()
{
	typedef NTSTATUS (WINAPI *pNtQueryInformationProcess)(IN  HANDLE, IN  UINT, OUT PVOID, IN ULONG, OUT PULONG);

	const int ProcessDebugObjectHandle =  0x1e;

	pNtQueryInformationProcess NtQueryInfoProcess = NULL;

	NTSTATUS Status;
	HANDLE hDebugObject = NULL; 

#if defined (ENV64BIT)
	DWORD dProcessInformationLength = sizeof(ULONG) * 2;
	DWORD64 IsRemotePresent = 0;

#elif defined(ENV32BIT)
	DWORD dProcessInformationLength = sizeof(ULONG);
	DWORD32 IsRemotePresent = 0;
#endif

	HMODULE hNtDll = LoadLibrary(_xor_(_T("ntdll.dll")).c_str());
	if(hNtDll == NULL)
	{
	}
 
    NtQueryInfoProcess = (pNtQueryInformationProcess)GetProcAddress(hNtDll, _xor_("NtQueryInformationProcess").c_str());
	
	if(NtQueryInfoProcess == NULL)
	{
	}

	Status = NtQueryInfoProcess(GetCurrentProcess(), ProcessDebugObjectHandle, &hDebugObject, dProcessInformationLength, NULL);
    
	if (Status == 0x00000000 && hDebugObject)
        return TRUE;
    else
        return FALSE;
}