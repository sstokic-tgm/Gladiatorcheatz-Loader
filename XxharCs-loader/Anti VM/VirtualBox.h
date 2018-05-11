#include <Windows.h>
#include <tchar.h>
#include <ShlObj.h>
#include <strsafe.h>
#include <Shlwapi.h>
#include <Wbemidl.h>

# pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Mpr.lib")

#include "../Shared/Common.h"
#include "../Shared/Utils.h"




bool vbox_reg_key_value();
bool vbox_reg_keys();
bool vbox_files();
BOOL vbox_dir();

BOOL vbox_check_mac();
bool vbox_devices();
BOOL vbox_window_class();
BOOL vbox_network_share();
bool vbox_processes();
BOOL vbox_devices_wmi();
BOOL vbox_mac_wmi();
BOOL vbox_eventlogfile_wmi();
