#include <Windows.h>
#include <tchar.h>

BOOL NtClose_InvalideHandle()
{
	typedef NTSTATUS(WINAPI* pNtClose)(HANDLE);

	pNtClose NtClose_ = NULL;

	HMODULE hNtdll = LoadLibrary(_T("ntdll.dll"));
	if (hNtdll == NULL)
	{
	}

	NtClose_ = (pNtClose)GetProcAddress(hNtdll, "NtClose");
	if (NtClose_ == NULL)
	{
	}

	__try {
		
		NtClose_((HANDLE)0x99999999);
	}

	__except (EXCEPTION_EXECUTE_HANDLER) {
		return TRUE;
	}

	return FALSE;

}

BOOL CloseHandle_InvalideHandle()
{
	__try {
		CloseHandle((HANDLE)0x99999999);
	}

	__except (EXCEPTION_EXECUTE_HANDLER) {
		return TRUE;
	}

	if (NtClose_InvalideHandle())
		return TRUE;
	else
		return FALSE;
}

