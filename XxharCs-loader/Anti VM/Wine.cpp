#include "Wine.h"

BOOL wine_exports()
{
	HMODULE hKernel32;

	hKernel32 = GetModuleHandle(_T("kernel32.dll"));
	if (hKernel32 == NULL) {
		print_last_error(_T("GetModuleHandle"));
		return FALSE;
	}

	if (GetProcAddress(hKernel32, "wine_get_unix_file_name") == NULL)
		return FALSE;
	else
		return TRUE;
}

bool wine_reg_keys()
{
	TCHAR* szKeys[] = {
		_T("SOFTWARE\\Wine")
	};

	WORD dwlength = sizeof(szKeys) / sizeof(szKeys[0]);

	for (int i = 0; i < dwlength; i++)
	{
		if (Is_RegKeyExists(HKEY_CURRENT_USER, szKeys[i]))
			return true;
	}
	return false;
}