#include "NtQueryInformationProcess_ProcessDebugFlags.h"

BOOL NtQueryInformationProcess_ProcessDebugFlags()
{
	typedef NTSTATUS (WINAPI *pNtQueryInformationProcess)(IN  HANDLE, IN  UINT, OUT PVOID, IN ULONG, OUT PULONG);
 
	const int ProcessDebugFlags =  0x1f;

	pNtQueryInformationProcess NtQueryInfoProcess = NULL;

	NTSTATUS Status;
	DWORD NoDebugInherit = 0; 

	HMODULE hNtDll = LoadLibrary(_T("ntdll.dll"));
	if(hNtDll == NULL)
	{
	}
 
    NtQueryInfoProcess = (pNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");
	if(NtQueryInfoProcess == NULL)
	{
	}
	
	Status = NtQueryInfoProcess(GetCurrentProcess(), ProcessDebugFlags, &NoDebugInherit, sizeof(DWORD), NULL);
	if (Status == 0x00000000 && NoDebugInherit == 0)
		return TRUE;
	else        
		return FALSE;
}