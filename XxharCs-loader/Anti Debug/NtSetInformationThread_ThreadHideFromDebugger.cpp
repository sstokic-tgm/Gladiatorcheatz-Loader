#include "NtSetInformationThread_ThreadHideFromDebugger.h"
#include "..\XorStr.h"

BOOL NtSetInformationThread_ThreadHideFromDebugger()
{
	typedef NTSTATUS (WINAPI *pNtSetInformationThread)(HANDLE, UINT, PVOID, ULONG);

	const int ThreadHideFromDebugger =  0x11;

	pNtSetInformationThread NtSetInformationThread = NULL;

	NTSTATUS Status;
	BOOL IsBeingDebug = FALSE;

	HMODULE hNtDll = LoadLibrary(_xor_(_T("ntdll.dll")).c_str());
	if(hNtDll == NULL)
	{
	}
 
    NtSetInformationThread = (pNtSetInformationThread)GetProcAddress(hNtDll, _xor_("NtSetInformationThread").c_str());
	
	if(NtSetInformationThread == NULL)
	{
	}

	Status = NtSetInformationThread(GetCurrentThread(), ThreadHideFromDebugger, NULL, 0);
    
	if(Status)
		IsBeingDebug = TRUE;

	return IsBeingDebug;
}