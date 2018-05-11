#include "NtQueryObject_ObjectInformation.h"
#include "..\XorStr.h"

BOOL NtQueryObject_ObjectTypeInformation()
{
	typedef NTSTATUS (WINAPI *pNtQueryObject)(IN HANDLE, IN UINT, OUT PVOID, IN ULONG, OUT PULONG);
	typedef NTSTATUS(WINAPI *pNtCreateDebugObject)(OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES, IN ULONG);

	pNtQueryObject NtQueryObject = NULL;
	pNtCreateDebugObject NtCreateDebugObject = NULL;

	HANDLE DebugObjectHandle;
	OBJECT_ATTRIBUTES ObjectAttributes;
	InitializeObjectAttributes(&ObjectAttributes, 0, 0, 0, 0);
	BYTE memory[0x1000] = { 0 };
	POBJECT_TYPE_INFORMATION ObjectInformation = (POBJECT_TYPE_INFORMATION)memory;
	NTSTATUS Status;
	

	HMODULE hNtdll = LoadLibrary(_xor_(_T("ntdll.dll")).c_str());
	if (hNtdll == NULL)
	{
	}

	NtCreateDebugObject = (pNtCreateDebugObject)GetProcAddress(hNtdll, _xor_("NtCreateDebugObject").c_str());
	if (NtCreateDebugObject == NULL)
	{
	}

	NtCreateDebugObject(&DebugObjectHandle, DEBUG_ALL_ACCESS, &ObjectAttributes, FALSE);
	if (NtCreateDebugObject) {

		HMODULE hNtdll = LoadLibrary(_xor_(_T("ntdll.dll")).c_str());
		if (hNtdll == NULL)
		{
		}

		NtQueryObject = (pNtQueryObject)GetProcAddress(hNtdll, _xor_("NtQueryObject").c_str());
		if (NtCreateDebugObject == NULL)
		{
		}

		Status = NtQueryObject(DebugObjectHandle, ObjectTypeInformation, ObjectInformation, sizeof(memory), 0);
		
		CloseHandle(DebugObjectHandle);
		

		if (Status >= 0)
		{
			if (ObjectInformation->TotalNumberOfObjects == 0)
				return TRUE;
			else
				return FALSE;
		}
		else
		{
			return FALSE;
		}
	}
	else
		return FALSE;

}