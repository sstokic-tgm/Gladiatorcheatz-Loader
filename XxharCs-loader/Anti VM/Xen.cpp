#include "Xen.h"

bool xen_process()
{
	TCHAR *szProcesses[] = {
		_T("xenservice.exe"),
	};

	WORD iLength = sizeof(szProcesses) / sizeof(szProcesses[0]);
	for (int i = 0; i < iLength; i++)
	{
		if (GetProcessIdFromName(szProcesses[i]))
			return true;
	}
	return false;
}
