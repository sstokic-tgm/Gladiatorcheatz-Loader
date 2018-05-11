#include "process.h"

bool analysis_tools_process()
{
	 std::wstring szProcesses[] = {
		_xor_(_T("ollydbg.exe")),			// OllyDebug debugger
		_xor_(_T("ProcessHacker.exe")),	// Process Hacker
		_xor_(_T("tcpview.exe")),			// Part of Sysinternals Suite
		_xor_(_T("autoruns.exe")),			// Part of Sysinternals Suite
		_xor_(_T("autorunsc.exe")),		// Part of Sysinternals Suite
		_xor_(_T("filemon.exe")),			// Part of Sysinternals Suite
		_xor_(_T("procmon.exe")),			// Part of Sysinternals Suite
		_xor_(_T("regmon.exe")),			// Part of Sysinternals Suite
		_xor_(_T("procexp.exe")),			// Part of Sysinternals Suite
		_xor_(_T("idaq.exe")),				// IDA Pro Interactive Disassembler
		_xor_(_T("idaq64.exe")),			// IDA Pro Interactive Disassembler
		_xor_(_T("ImmunityDebugger.exe")), // ImmunityDebugger
		_xor_(_T("Wireshark.exe")),		// Wireshark packet sniffer
		_xor_(_T("dumpcap.exe")),			// Network traffic dump tool
		_xor_(_T("HookExplorer.exe")),		// Find various types of runtime hooks
		_xor_(_T("ImportREC.exe")),		// Import Reconstructor
		_xor_(_T("PETools.exe")),			// PE Tool
		_xor_(_T("LordPE.exe")),			// LordPE
		_xor_(_T("dumpcap.exe")),			// Network traffic dump tool
		_xor_(_T("SysInspector.exe")),		// ESET SysInspector
		_xor_(_T("proc_analyzer.exe")),	// Part of SysAnalyzer iDefense
		_xor_(_T("sysAnalyzer.exe")),		// Part of SysAnalyzer iDefense
		_xor_(_T("sniff_hit.exe")),		// Part of SysAnalyzer iDefense
		_xor_(_T("windbg.exe")),			// Microsoft WinDbg
		_xor_(_T("joeboxcontrol.exe")),	// Part of Joe Sandbox
		_xor_(_T("joeboxserver.exe")),		// Part of Joe Sandbox
		_xor_(_T("fiddler.exe")),
		_xor_(_T("TeamViewer_Service.exe")),
		_xor_(_T("TeamViewer.exe")),
		_xor_(_T("tv_w32.exe")),
		_xor_(_T("tv_x64.exe")),
	};

	WORD iLength = sizeof(szProcesses) / sizeof(szProcesses[0]);
	for (int i = 0; i < iLength; i++)
	{
		if (GetProcessIdFromName(szProcesses[i].c_str()))
			return true;
	}
	return false;
}

bool IsRemoteSession()
{
	const int session_metrics = GetSystemMetrics(SM_REMOTESESSION);
	return session_metrics != 0;
}

bool check_network_drivers()
{
	LPVOID drivers[1024];
	DWORD cbNeeded;
	int cDrivers, i;

	if (K32EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers))
	{
		TCHAR szDriver[1024];
		cDrivers = cbNeeded / sizeof(drivers[0]);

		for (i = 0; i < cDrivers; i++)
		{
			if (K32GetDeviceDriverBaseNameW(drivers[i], szDriver, sizeof(szDriver) / sizeof(szDriver[0])))
			{
				if (wcscmp(szDriver, _xor_(_T("npf.sys")).c_str()) == 0)
					return true;
			}
		}
	}
	return false;
}