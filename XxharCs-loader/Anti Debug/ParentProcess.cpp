#include "ParentProcess.h"

typedef struct _PROCESS_BASIC_INFORMATION {
	PVOID Reserved1;
	void* PebBaseAddress;
	PVOID Reserved2[2];
	ULONG_PTR UniqueProcessId;
	ULONG_PTR ParentProcessId;
} PROCESS_BASIC_INFORMATION;

DWORD GetExplorerPIDbyShellWindow()
{
	DWORD dwProcessId = 0;

	GetWindowThreadProcessId(GetShellWindow(), &dwProcessId);

	return dwProcessId;
}

DWORD GetParentProcessId()
{
	typedef NTSTATUS(WINAPI *pNtQueryInformationProcess)(HANDLE, UINT, PVOID, ULONG, PULONG);

	pNtQueryInformationProcess NtQueryInfoProcess = NULL;

	NTSTATUS Status = 0;
	PROCESS_BASIC_INFORMATION pbi;
	SecureZeroMemory(&pbi, sizeof(PROCESS_BASIC_INFORMATION));

	NtQueryInfoProcess = (pNtQueryInformationProcess)GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "NtQueryInformationProcess");

	if (NtQueryInfoProcess == 0)
		return 0;

	Status = NtQueryInfoProcess(GetCurrentProcess(), 0, (PVOID)&pbi, sizeof(PROCESS_BASIC_INFORMATION), 0);

	if (Status != 0x00000000)
		return 0;
	else
		return (DWORD)pbi.ParentProcessId;
}


BOOL IsParentExplorerExe()
{
	DWORD dwExplorerProcessId = GetParentProcessId();
	if (dwExplorerProcessId != GetExplorerPIDbyShellWindow())
		return TRUE;
	else
		return FALSE;
}