#include "VirtualBox.h"

bool vbox_reg_key_value()
{
	TCHAR *szEntries[][3] = {
		{ _T("HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0"), _T("Identifier"), _T("VBOX") },
		{ _T("HARDWARE\\Description\\System"), _T("SystemBiosVersion"), _T("VBOX") },
		{ _T("HARDWARE\\Description\\System"), _T("VideoBiosVersion"), _T("VIRTUALBOX") },
		{ _T("HARDWARE\\Description\\System"), _T("SystemBiosDate"), _T("06/23/99") },
	};

	WORD dwLength = sizeof(szEntries) / sizeof(szEntries[0]);

	for (int i = 0; i < dwLength; i++)
	{
		if (Is_RegKeyValueExists(HKEY_LOCAL_MACHINE, szEntries[i][0], szEntries[i][1], szEntries[i][2]))
			return true;
	}
	return false;
}

bool vbox_reg_keys()
{
	TCHAR* szKeys[] = {
		_T("HARDWARE\\ACPI\\DSDT\\VBOX__"),
		_T("HARDWARE\\ACPI\\FADT\\VBOX__"),
		_T("HARDWARE\\ACPI\\RSDT\\VBOX__"),
		_T("SOFTWARE\\Oracle\\VirtualBox Guest Additions"),
		_T("SYSTEM\\ControlSet001\\Services\\VBoxGuest"),
		_T("SYSTEM\\ControlSet001\\Services\\VBoxMouse"),
		_T("SYSTEM\\ControlSet001\\Services\\VBoxService"),
		_T("SYSTEM\\ControlSet001\\Services\\VBoxSF"),
		_T("SYSTEM\\ControlSet001\\Services\\VBoxVideo")
	};

	WORD dwlength = sizeof(szKeys) / sizeof(szKeys[0]);

	for (int i = 0; i < dwlength; i++)
	{
		if (Is_RegKeyExists(HKEY_LOCAL_MACHINE, szKeys[i]))
			return true;
	}
	return false;
}

bool vbox_files()
{
	TCHAR* szPaths[] = {
		_T("system32\\drivers\\VBoxMouse.sys"),
		_T("system32\\drivers\\VBoxGuest.sys"),
		_T("system32\\drivers\\VBoxSF.sys"),
		_T("system32\\drivers\\VBoxVideo.sys"),
		_T("system32\\vboxdisp.dll"),
		_T("system32\\vboxhook.dll"),
		_T("system32\\vboxmrxnp.dll"),
		_T("system32\\vboxogl.dll"),
		_T("system32\\vboxoglarrayspu.dll"),
		_T("system32\\vboxoglcrutil.dll"),
		_T("system32\\vboxoglerrorspu.dll"),
		_T("system32\\vboxoglfeedbackspu.dll"),
		_T("system32\\vboxoglpackspu.dll"),
		_T("system32\\vboxoglpassthroughspu.dll"),
		_T("system32\\vboxservice.exe"),
		_T("system32\\vboxtray.exe"),
		_T("system32\\VBoxControl.exe"),
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

BOOL vbox_dir()
{
	TCHAR szProgramFile[MAX_PATH];
	TCHAR szPath[MAX_PATH] = _T("");
	TCHAR szTarget[MAX_PATH] = _T("oracle\\virtualbox guest additions\\");

	if (IsWoW64())
		ExpandEnvironmentStrings(_T("%ProgramW6432%"), szProgramFile, ARRAYSIZE(szProgramFile));
	else
		SHGetSpecialFolderPath(NULL, szProgramFile, CSIDL_PROGRAM_FILES, FALSE);

	PathCombine(szPath, szProgramFile, szTarget);
	return is_DirectoryExists(szPath);
}

BOOL vbox_check_mac()
{
	return check_mac_addr(_T("\x08\x00\x27"));
}

bool vbox_devices()
{
	TCHAR *devices[] = {
		_T("\\\\.\\VBoxMiniRdrDN"),
		_T("\\\\.\\VBoxGuest"),
		_T("\\\\.\\pipe\\VBoxMiniRdDN"),
		_T("\\\\.\\VBoxTrayIPC"),
		_T("\\\\.\\pipe\\VBoxTrayIPC")
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

BOOL vbox_window_class()
{
	HWND hClass = FindWindow(_T("VBoxTrayToolWndClass"), NULL);
	HWND hWindow = FindWindow(NULL, _T("VBoxTrayToolWnd"));

	if (hClass || hWindow)
		return TRUE;
	else
		return FALSE;
}

BOOL vbox_network_share()
{
	TCHAR szProviderName[MAX_PATH] = _T("");
	DWORD lpBufferSize = MAX_PATH;

	if (WNetGetProviderName(WNNC_NET_RDR2SAMPLE, szProviderName, &lpBufferSize) == NO_ERROR)
	{
		if (StrCmpI(szProviderName, _T("VirtualBox Shared Folders")) == 0)
			return TRUE;
		else
			return FALSE;
	}
	return FALSE;
}

bool vbox_processes()
{
	TCHAR *szProcesses[] = {
		_T("vboxservice.exe"),
		_T("vboxtray.exe")
	};

	WORD iLength = sizeof(szProcesses) / sizeof(szProcesses[0]);
	for (int i = 0; i < iLength; i++)
	{
		if (GetProcessIdFromName(szProcesses[i]))
			return true;
	}
	return false;
}

BOOL vbox_devices_wmi()
{
	IWbemServices *pSvc = NULL;
	IWbemLocator *pLoc = NULL;
	IEnumWbemClassObject* pEnumerator = NULL;
	BOOL bStatus = FALSE;
	HRESULT hRes;
	BOOL bFound = FALSE;

	bStatus = InitWMI(&pSvc, &pLoc);
	
	if (bStatus)
	{
		bStatus = ExecWMIQuery(&pSvc, &pLoc, &pEnumerator, _T("SELECT * FROM Win32_PnPEntity"));
		if (bStatus)
		{
			IWbemClassObject *pclsObj = NULL;
			ULONG uReturn = 0;
			VARIANT vtProp;

			while (pEnumerator)
			{
				hRes = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
				if (0 == uReturn)
					break;

				hRes = pclsObj->Get(_T("DeviceId"), 0, &vtProp, 0, 0);
				
				if (_tcsstr(vtProp.bstrVal, _T("PCI\\VEN_80EE&DEV_CAFE")) != 0)
				{
					bFound = TRUE;
					break;
				}

				VariantClear(&vtProp);
				pclsObj->Release();
			}

			pSvc->Release();
			pLoc->Release();
			pEnumerator->Release();
			CoUninitialize();
		}
	}

	return bFound;
}

BOOL vbox_mac_wmi()
{
	IWbemServices *pSvc = NULL;
	IWbemLocator *pLoc = NULL;
	IEnumWbemClassObject* pEnumerator = NULL;
	BOOL bStatus = FALSE;
	HRESULT hRes;
	BOOL bFound = FALSE;

	bStatus = InitWMI(&pSvc, &pLoc);
	if (bStatus)
	{
		bStatus = ExecWMIQuery(&pSvc, &pLoc, &pEnumerator, _T("SELECT * FROM Win32_NetworkAdapterConfiguration"));
		if (bStatus)
		{
			IWbemClassObject *pclsObj = NULL;
			ULONG uReturn = 0;
			VARIANT vtProp;

			while (pEnumerator)
			{
				hRes = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
				if (0 == uReturn)
					break;

				hRes = pclsObj->Get(_T("MACAddress"), 0, &vtProp, 0, 0);
				if (V_VT(&vtProp) != VT_NULL) {

					if (_tcsstr(vtProp.bstrVal, _T("08:00:27")) != 0){
						bFound = TRUE; break;
					}

					VariantClear(&vtProp);
					pclsObj->Release();
				}
			}

			pEnumerator->Release();
			pSvc->Release();
			pLoc->Release();
			CoUninitialize();
		}
	}

	return bFound;
}

BOOL vbox_eventlogfile_wmi()
{
	IWbemServices *pSvc = NULL;
	IWbemLocator *pLoc = NULL;
	IEnumWbemClassObject* pEnumerator = NULL;
	BOOL bStatus = FALSE;
	HRESULT hRes;
	BOOL bFound = FALSE;

	bStatus = InitWMI(&pSvc, &pLoc);
	if (bStatus)
	{
		bStatus = ExecWMIQuery(&pSvc, &pLoc, &pEnumerator, _T("SELECT * FROM Win32_NTEventlogFile"));
		if (bStatus)
		{
			IWbemClassObject *pclsObj = NULL;
			ULONG uReturn = 0;
			VARIANT vtProp;

			while (pEnumerator && !bFound)
			{
				hRes = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
				if (0 == uReturn)
					break;

				hRes = pclsObj->Get(_T("FileName"), 0, &vtProp, 0, 0);
				if (V_VT(&vtProp) != VT_NULL) {

					if (StrCmpI(vtProp.bstrVal, _T("System")) == 0) {

						VariantClear(&vtProp);
						hRes = pclsObj->Get(_T("Sources"), 0, &vtProp, 0, 0);

						SAFEARRAY* saSources = vtProp.parray;
						LONG* pVals;
						HRESULT hr = SafeArrayAccessData(saSources, (VOID**)&pVals);
						if (SUCCEEDED(hr)) {
							LONG lowerBound, upperBound;
							SafeArrayGetLBound(saSources, 1, &lowerBound);
							SafeArrayGetUBound(saSources, 1, &upperBound);
							LONG iLength = upperBound - lowerBound + 1;

							TCHAR* bstrItem;
							for (LONG ix = 0; ix < iLength; ix++) {
								SafeArrayGetElement(saSources, &ix, (void *)&bstrItem);
								if (_tcsicmp(bstrItem, _T("vboxvideo")) == 0) {
									bFound = TRUE;
									break;
								}
							}
						}	
					}

					VariantClear(&vtProp);
					pclsObj->Release();
				}
			}

			pEnumerator->Release();
			pSvc->Release();
			pLoc->Release();
			CoUninitialize();

		}
	}

	return bFound;
}
