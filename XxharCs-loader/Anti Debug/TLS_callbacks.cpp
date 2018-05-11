#include "TLS_callbacks.h"
#include "../Shared/Main.h"

DWORD WINAPI Thread(LPVOID lpReserverd)
{
	while (true)
	{
		if (IsDebuggerPresentAPI() || IsDebuggerPresentPEB() || CheckRemoteDebuggerPresentAPI() ||
			NtGlobalFlag() || HeapFlags() || HeapForceFlags() || NtQueryInformationProcess_ProcessDebugPort() || NtQueryInformationProcess_ProcessDebugFlags() ||
			NtQueryInformationProcess_ProcessDebugObject() || NtSetInformationThread_ThreadHideFromDebugger() || CloseHandle_InvalideHandle() ||
			UnhandledExcepFilterTest() || OutputDebugStringAPI() || HardwareBreakpoints() || SoftwareBreakpoints() || Interrupt_0x2d() || Interrupt_3() ||
			MemoryBreakpoints_PageGuard() || IsParentExplorerExe() || CanOpenCsrss() || NtQueryObject_ObjectTypeInformation() || SetHandleInformatiom_ProtectedHandle() ||
			analysis_tools_process() || IsRemoteSession() || check_network_drivers() ||
			loaded_dlls() || NumberOfProcessors() || idt_trick() || ldt_trick() || gdt_trick() || str_trick() || dizk_size_deviceiocontrol() ||
			setupdi_diskdrive() || memory_space() || disk_size_getdiskfreespace() || cpuid_is_hypervisor() || cpuid_hypervisor_vendor() /*|| vbox_reg_key_value() || 
			vbox_dir() || vbox_files() || vbox_reg_keys() || vbox_check_mac() || vbox_devices() || vbox_window_class() || vbox_processes() || vmware_reg_key_value() || 
			vmware_reg_keys() || vmware_files() || vmware_mac() || vmware_devices() || vmware_dir() || wine_exports() || wine_reg_keys() ||
			number_cores_wmi() ||  mouse_movement() || accelerated_sleep() || vbox_network_share() ||
			vbox_devices_wmi() || vbox_mac_wmi() || vbox_eventlogfile_wmi() || vmware_adapter_name() || */
			)
		{
			ErasePEHeaderFromMemory();
			//SizeOfImage();

			Sleep(100);

			HANDLE handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_TERMINATE, 0, GetCurrentProcessId());
			TerminateProcess(handle, 0);
		}

		Sleep(20);
	}
}

VOID WINAPI tls_callback(PVOID hModule, DWORD dwReason, PVOID pContext)
{
	if (dwReason == DLL_THREAD_ATTACH)
	{
	}

	if (dwReason == DLL_PROCESS_ATTACH)
	{
		SizeOfImage();
		CreateThread(0, 0, &Thread, 0, 0, 0);
	}
}

#ifdef _WIN64
	#pragma comment (linker, "/INCLUDE:_tls_used")
	#pragma comment (linker, "/INCLUDE:tls_callback_func")
#else
	#pragma comment (linker, "/INCLUDE:__tls_used")
	#pragma comment (linker, "/INCLUDE:_tls_callback_func")
#endif


#ifdef _WIN64
	#pragma const_seg(".CRT$XLF")
	EXTERN_C const
#else
	#pragma data_seg(".CRT$XLF")
	EXTERN_C
#endif

PIMAGE_TLS_CALLBACK tls_callback_func = tls_callback;

#ifdef _WIN64
	#pragma const_seg()
#else
	#pragma data_seg()
#endif
