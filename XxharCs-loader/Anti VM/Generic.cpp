#include "Generic.h"

bool loaded_dlls()
{
	HMODULE hDll;

	std::wstring szDlls[] = {
		_xor_(_T("sbiedll.dll")),
		_xor_(_T("dbghelp.dll")),
		_xor_(_T("api_log.dll")),
		_xor_(_T("dir_watch.dll")),
		_xor_(_T("pstorec.dll")),
		_xor_(_T("vmcheck.dll")),
		_xor_(_T("wpespy.dll")),

	};

	WORD dwlength = sizeof(szDlls) / sizeof(szDlls[0]);
	for (int i = 0; i < dwlength; i++)
	{
		hDll = GetModuleHandle(szDlls[i].c_str());
		if (hDll != NULL)
			return true;
	}
	return false;
}

BOOL NumberOfProcessors()
{
#if defined (ENV64BIT)
	PULONG ulNumberProcessors = (PULONG)(__readgsqword(0x30) + 0xB8);

#elif defined(ENV32BIT)
	PULONG ulNumberProcessors = (PULONG)(__readfsdword(0x30) + 0x64) ;

#endif

	if (*ulNumberProcessors < 2)
		return TRUE;
	else
		return FALSE;
}

BOOL idt_trick()
{
	UINT idt_base = get_idt_base();
	if ((idt_base >> 24) == 0xff) 
		return TRUE;

	else
		return FALSE;
}

BOOL ldt_trick()
{
	UINT ldt_base = get_ldt_base();

	if (ldt_base == 0xdead0000) 
		return FALSE;
	else 
		return TRUE;
}

BOOL gdt_trick()
{
	UINT gdt_base = get_gdt_base();

	if ((gdt_base >> 24) == 0xff)
		return TRUE;

	else
		return FALSE;
}

BOOL str_trick()
{
	UCHAR *mem = get_str_base();

	if ((mem[0] == 0x00) && (mem[1] == 0x40))
		return TRUE;
	else
		return FALSE;
}

BOOL number_cores_wmi()
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
		bStatus = ExecWMIQuery(&pSvc, &pLoc, &pEnumerator, _xor_(_T("SELECT * FROM Win32_Processor")).c_str());
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

				hRes = pclsObj->Get(_xor_(_T("NumberOfCores")).c_str(), 0, &vtProp, 0, 0);
				if (V_VT(&vtProp) != VT_NULL) {

					if (vtProp.uintVal < 2) {
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

BOOL disk_size_wmi()
{
	IWbemServices *pSvc = NULL;
	IWbemLocator *pLoc = NULL;
	IEnumWbemClassObject* pEnumerator = NULL;
	BOOL bStatus = FALSE;
	HRESULT hRes;
	BOOL bFound = FALSE;
	INT64 minHardDiskSize = (80LL * (1024LL * (1024LL * (1024LL))));

	bStatus = InitWMI(&pSvc, &pLoc);
	if (bStatus)
	{
		bStatus = ExecWMIQuery(&pSvc, &pLoc, &pEnumerator, _xor_(_T("SELECT * FROM Win32_LogicalDisk")).c_str());
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

				hRes = pclsObj->Get(_xor_(_T("Size")).c_str(), 0, &vtProp, 0, 0);
				if (V_VT(&vtProp) != VT_NULL) {

					if (vtProp.llVal < minHardDiskSize) {
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

BOOL dizk_size_deviceiocontrol()
{
	HANDLE hDevice = INVALID_HANDLE_VALUE;
	BOOL bResult = FALSE;
	GET_LENGTH_INFORMATION size = { 0 };
	DWORD lpBytesReturned = 0;
	LONGLONG minHardDiskSize = (80LL * (1024LL * (1024LL * (1024LL))));

	if (!IsElevated() && IsWindowsVistaOrGreater())
		return FALSE;
	
	hDevice = CreateFile(_xor_(_T("\\\\.\\PhysicalDrive0")).c_str(),
		GENERIC_READ,              
		FILE_SHARE_READ, 			
		NULL,						
		OPEN_EXISTING,				
		0,							
		NULL);						

	if (hDevice == INVALID_HANDLE_VALUE) {
		CloseHandle(hDevice);
		return FALSE;
	}

	bResult = DeviceIoControl(
		hDevice,					
		IOCTL_DISK_GET_LENGTH_INFO, 
		NULL, 0,					
		&size, sizeof(GET_LENGTH_INFORMATION),
		&lpBytesReturned,			
		(LPOVERLAPPED) NULL);  

	if (bResult != NULL) {
		if (size.Length.QuadPart < minHardDiskSize)
			bResult = TRUE;
		else
			bResult = FALSE;
	}

	CloseHandle(hDevice);
	return bResult;
}


BOOL setupdi_diskdrive()
{
	HDEVINFO hDevInfo;
	SP_DEVINFO_DATA DeviceInfoData;
	DWORD i;
	BOOL bFound = FALSE;

	hDevInfo = SetupDiGetClassDevs((LPGUID)&GUID_DEVCLASS_DISKDRIVE,
		0, 
		0,
		DIGCF_PRESENT);

	if (hDevInfo == INVALID_HANDLE_VALUE)
		return FALSE;

	DeviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);

	DWORD dwPropertyRegDataType;
	LPTSTR buffer = NULL;
	DWORD dwSize = 0;

	for (i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &DeviceInfoData); i++)
	{
		while (!SetupDiGetDeviceRegistryProperty(hDevInfo, &DeviceInfoData, SPDRP_HARDWAREID,
			&dwPropertyRegDataType, (PBYTE)buffer, dwSize, &dwSize))
		{
			if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
			
				if (buffer)LocalFree(buffer);

				buffer = (LPTSTR)LocalAlloc(LPTR, dwSize * 2);
			}
			else
				break;

		}

		if ((StrStrI(buffer, _xor_(_T("vbox")).c_str()) != NULL) ||
			(StrStrI(buffer, _xor_(_T("vmware")).c_str()) != NULL) || 
			(StrStrI(buffer, _xor_(_T("qemu")).c_str()) != NULL) ||
			(StrStrI(buffer, _xor_(_T("virtual")).c_str()) != NULL))
		{
			bFound =  TRUE;
			break;
		}
	}

	if (buffer)
		LocalFree(buffer);

	if (GetLastError() != NO_ERROR && GetLastError() != ERROR_NO_MORE_ITEMS)
		return FALSE;

	SetupDiDestroyDeviceInfoList(hDevInfo);

	if (bFound)
		return TRUE;

	else
		return FALSE;
}

BOOL mouse_movement() {

	POINT positionA = {};
	POINT positionB = {};

	GetCursorPos(&positionA);

	Sleep(2000);

	GetCursorPos(&positionB);

	if ((positionA.x == positionB.x) && (positionA.y == positionB.y))
		return TRUE;

	else 
		return FALSE;
}

BOOL memory_space()
{
	DWORDLONG ullMinRam = (1024LL * (1024LL * (1024LL * 1LL))); // 1GB
	MEMORYSTATUSEX statex = {0};

	statex.dwLength = sizeof(statex);
	GlobalMemoryStatusEx(&statex);

	return (statex.ullTotalPhys < ullMinRam) ? TRUE : FALSE;
}

BOOL disk_size_getdiskfreespace()
{
	ULONGLONG minHardDiskSize = (80ULL * (1024ULL * (1024ULL * (1024ULL))));
	LPCWSTR pszDrive = NULL;
	BOOL bStatus = FALSE;

	ULARGE_INTEGER totalNumberOfBytes;

	bStatus = GetDiskFreeSpaceEx(pszDrive, NULL, &totalNumberOfBytes, NULL);
	if (bStatus) {
		if (totalNumberOfBytes.QuadPart < minHardDiskSize)  // 80GB
			return TRUE;
	}

	return FALSE;;
}

BOOL accelerated_sleep()
{
	DWORD dwStart = 0, dwEnd = 0, dwDiff = 0;
	DWORD dwMillisecondsToSleep = 60*1000;

	dwStart = GetTickCount();

	Sleep(dwMillisecondsToSleep);

	dwEnd = GetTickCount();

	dwDiff = dwEnd - dwStart;
	if (dwDiff > dwMillisecondsToSleep - 1000)
		return FALSE;
	else 
		return TRUE;
}

BOOL cpuid_is_hypervisor()
{
	INT CPUInfo[4] = { -1 };

	__cpuid(CPUInfo, 1);
	if ((CPUInfo[2] >> 31) & 1) 
		return TRUE;
	else
		return FALSE;
}

BOOL cpuid_hypervisor_vendor()
{
	INT CPUInfo[4] = {-1};
	CHAR szHypervisorVendor[0x40];
	std::wstring szBlacklistedHypervisors[] = {
		_xor_(_T("KVMKVMKVM\0\0\0")),	
		_xor_(_T("Microsoft Hv")),
		_xor_(_T("VMwareVMware")),
		_xor_(_T("XenVMMXenVMM")),
		_xor_(_T("prl hyperv  ")),
		_xor_(_T("VBoxVBoxVBox")),
	};
	WORD dwlength = sizeof(szBlacklistedHypervisors) / sizeof(szBlacklistedHypervisors[0]);

	__cpuid(CPUInfo, 0x40000000);
	memset(szHypervisorVendor, 0, sizeof(szHypervisorVendor));
	memcpy(szHypervisorVendor, CPUInfo + 1, 12);

	for (int i = 0; i < dwlength; i++)
	{
		if (_tcscmp(ascii_to_wide_str(szHypervisorVendor), szBlacklistedHypervisors[i].c_str()) == 0)
			return TRUE;
	}

	return FALSE;
}