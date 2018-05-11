#include "NtYieldExecution.h"

BOOL NtYieldExecutionAPI()
{
	typedef NTSTATUS(WINAPI* pNtYieldExecution)();

	pNtYieldExecution NtYieldExecution = NULL;

	HMODULE hNtdll;
	INT iDebugged = 0;

	hNtdll = LoadLibrary(_T("ntdll.dll"));

	if (hNtdll == NULL)
	{
	}


	NtYieldExecution = (pNtYieldExecution)GetProcAddress(hNtdll, "NtYieldExecution");
	if (NtYieldExecution == NULL)
	{
	}


	for (int i = 0; i < 0x20; i++)
	{
		Sleep(0xf);

		if (NtYieldExecution() != STATUS_NO_YIELD_PERFORMED)
			iDebugged++;
	}

	if (iDebugged <= 3)
		return FALSE;
	else
		return TRUE;
	

}