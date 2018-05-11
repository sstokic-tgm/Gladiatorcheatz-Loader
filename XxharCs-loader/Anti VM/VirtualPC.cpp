#include "VirtualPC.h"

bool virtual_pc_process()
{
	TCHAR *szProcesses[] = {
		_T("VMSrvc.exe"),
		_T("VMUSrvc.exe"),
	};

	WORD iLength = sizeof(szProcesses) / sizeof(szProcesses[0]);
	for (int i = 0; i < iLength; i++)
	{
		if (GetProcessIdFromName(szProcesses[i]))
			return true;
	}
	return false;
}
