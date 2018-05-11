#include "VMWare.h"

bool vmware_reg_key_value()
{
	TCHAR *szEntries[][3] = {
		{ _T("HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0"), _T("Identifier"), _T("VMWARE") },
		{ _T("HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 1\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0"), _T("Identifier"), _T("VMWARE") },
		{ _T("HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 2\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0"), _T("Identifier"), _T("VMWARE") },
	};

	WORD dwLength = sizeof(szEntries) / sizeof(szEntries[0]);

	for (int i = 0; i < dwLength; i++)
	{
		if (Is_RegKeyValueExists(HKEY_LOCAL_MACHINE, szEntries[i][0], szEntries[i][1], szEntries[i][2]))
			return true;
	}
	return false;
}

bool vmware_reg_keys()
{
	TCHAR* szKeys[] = {
		_T("SOFTWARE\\VMware, Inc.\\VMware Tools"),
	};

	WORD dwlength = sizeof(szKeys) / sizeof(szKeys[0]);

	for (int i = 0; i < dwlength; i++)
	{
		if (Is_RegKeyExists(HKEY_LOCAL_MACHINE, szKeys[i]))
			return true;
	}
	return false;
}

bool vmware_files()
{
	TCHAR* szPaths[] = {
		_T("system32\\drivers\\vmmouse.sys"),
		_T("system32\\drivers\\vmhgfs.sys"),
	};

	WORD dwlength = sizeof(szPaths) / sizeof(szPaths[0]);
	TCHAR szWinDir[MAX_PATH] = _T("");
	TCHAR szPath[MAX_PATH] = _T("");
	GetWindowsDirectory(szWinDir, MAX_PATH);

	for (int i = 0; i < dwlength; i++)
	{
		PathCombine(szPath, szWinDir, szPaths[i]);
		if (is_FileExists(szPath))
			return true;
	}
	return false;
}

BOOL vmware_dir()
{
	TCHAR szProgramFile[MAX_PATH];
	TCHAR szPath[MAX_PATH] = _T("");
	TCHAR szTarget[MAX_PATH] = _T("VMWare\\");

	if (IsWoW64())
		ExpandEnvironmentStrings(_T("%ProgramW6432%"), szProgramFile, ARRAYSIZE(szProgramFile));
	else
		SHGetSpecialFolderPath(NULL, szProgramFile, CSIDL_PROGRAM_FILES, FALSE);

	PathCombine(szPath, szProgramFile, szTarget);
	return is_DirectoryExists(szPath);
}

bool vmware_mac()
{
	TCHAR *szMac[][2] = {
		{ _T("\x00\x05\x69"), _T("00:05:69") },
		{ _T("\x00\x0C\x29"), _T("00:0c:29") },
		{ _T("\x00\x1C\x14"), _T("00:1C:14") },
		//{ _T("\x00\x50\x56"), _T("00:50:56") },
	};

	WORD dwLength = sizeof(szMac) / sizeof(szMac[0]);

	for (int i = 0; i < dwLength; i++)
	{
		if (check_mac_addr(szMac[i][0]))
			return true;
	}
	return false;
}

BOOL vmware_adapter_name()
{
	TCHAR* szAdapterName = _T("VMWare");
	if (check_adapter_name(szAdapterName))
		return TRUE;
	else
		return FALSE;
}

bool vmware_devices()
{
	TCHAR *devices[] = {
		_T("\\\\.\\HGFS"),
		//_T("\\\\.\\vmci"),
	};

	WORD iLength = sizeof(devices) / sizeof(devices[0]);
	for (int i = 0; i < iLength; i++)
	{
		HANDLE hFile = CreateFile(devices[i], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		
		if (hFile != INVALID_HANDLE_VALUE)
			return true;
	}
	return false;
}

bool vmware_processes()
{
	TCHAR *szProcesses[] = {
		_T("vmtoolsd.exe"),
		_T("vmwaretray.exe"),
		_T("vmwareuser.exe"),
	};

	WORD iLength = sizeof(szProcesses) / sizeof(szProcesses[0]);
	for (int i = 0; i < iLength; i++)
	{
		if (GetProcessIdFromName(szProcesses[i]))
			return true;
	}
	return false;
}
