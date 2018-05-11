#include "Parallels.h"

bool parallels_process()
{
	TCHAR *szProcesses[] = {
		_T("prl_cc.exe"),
		_T("prl_tools.exe"),
	};

	WORD iLength = sizeof(szProcesses) / sizeof(szProcesses[0]);
	for (int i = 0; i < iLength; i++)
	{
		if (GetProcessIdFromName(szProcesses[i]))
			return true;
	}
	return false;
}
