#include <windows.h>
#include <tchar.h>
#include <Winternl.h>
#include <devguid.h>
#include <winioctl.h>
#include <intrin.h>


#include <SetupAPI.h>
#pragma comment(lib, "setupapi.lib")

#include "../Shared/Utils.h"
#include "../Shared/VersionHelpers.h"

bool loaded_dlls();
BOOL NumberOfProcessors();
BOOL idt_trick();
BOOL ldt_trick();
BOOL gdt_trick();
BOOL str_trick();
BOOL number_cores_wmi();
BOOL disk_size_wmi();
BOOL setupdi_diskdrive();
BOOL mouse_movement();
BOOL memory_space();
BOOL dizk_size_deviceiocontrol();
BOOL disk_size_getdiskfreespace();
BOOL accelerated_sleep();
BOOL cpuid_is_hypervisor();
BOOL cpuid_hypervisor_vendor();