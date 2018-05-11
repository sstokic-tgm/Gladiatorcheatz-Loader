#include "NtQueryObject_ObjectInformation.h"

BOOL NtQueryObject_ObjectAllTypesInformation()
{
	typedef NTSTATUS(WINAPI *pNtQueryObject)(IN HANDLE, IN UINT, OUT PVOID, IN ULONG, OUT PULONG);
	typedef NTSTATUS(WINAPI *pNtCreateDebugObject)(OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES, IN ULONG);

	pNtQueryObject NtQueryObject = NULL;
	pNtCreateDebugObject NtCreateDebugObject = NULL;

	ULONG size;
	PVOID pMemory = NULL;
	POBJECT_ALL_INFORMATION pObjectAllInfo = NULL;
	NTSTATUS Status;


	HMODULE hNtdll = LoadLibrary(_T("ntdll.dll"));
	if (hNtdll == NULL)
	{
	}

	NtQueryObject = (pNtQueryObject)GetProcAddress(hNtdll, "NtQueryObject");
	if (NtQueryObject == NULL)
	{
	}

	Status = NtQueryObject(NULL, 3, &size, sizeof(ULONG), &size);

	pMemory = VirtualAlloc(NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (pMemory == NULL)
		return FALSE;

	Status = NtQueryObject((HANDLE)-1, 3, pMemory, size, NULL);

	if (Status != 0x00000000)
	{
		VirtualFree(pMemory, 0, MEM_RELEASE);
		return FALSE;
	}

	pObjectAllInfo = (POBJECT_ALL_INFORMATION)pMemory;
	UCHAR *pObjInfoLocation = (UCHAR*)pObjectAllInfo->ObjectTypeInformation;
	ULONG NumObjects = pObjectAllInfo->NumberOfObjects;

	for (UINT i = 0; i < NumObjects; i++)
	{

		POBJECT_TYPE_INFORMATION pObjectTypeInfo = (POBJECT_TYPE_INFORMATION)pObjInfoLocation;

		if (StrCmp(_T("DebugObject"), pObjectTypeInfo->TypeName.Buffer) == 0)
		{
			if (pObjectTypeInfo->TotalNumberOfObjects > 0)
			{
				VirtualFree(pMemory, 0, MEM_RELEASE);
				return TRUE;
			}
			else
			{
				VirtualFree(pMemory, 0, MEM_RELEASE);
				return FALSE;
			}
		}

		pObjInfoLocation = (unsigned char*)pObjectTypeInfo->TypeName.Buffer;

		pObjInfoLocation += pObjectTypeInfo->TypeName.MaximumLength;

		ULONG_PTR tmp = ((ULONG_PTR)pObjInfoLocation) & -(int)sizeof(void*);

		if ((ULONG_PTR)tmp != (ULONG_PTR)pObjInfoLocation)
			tmp += sizeof(void*);
		pObjInfoLocation = ((unsigned char*)tmp);
	}

	VirtualFree(pMemory, 0, MEM_RELEASE);
	return FALSE;
}