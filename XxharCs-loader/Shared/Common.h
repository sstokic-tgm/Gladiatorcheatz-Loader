#include <Windows.h>
#include <stdio.h>
#include <tchar.h>
#include <strsafe.h>

VOID print_detected(TCHAR *szMsg);
VOID print_last_error(LPTSTR lpszFunction);
TCHAR* ascii_to_wide_str(CHAR* lpMultiByteStr);
CHAR* wide_str_to_multibyte(TCHAR* lpWideStr);