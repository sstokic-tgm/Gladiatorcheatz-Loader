#include "SoftwareBreakpoints.h"

VOID My_Critical_Function()
{
	int a = 1;
	int b = 2;
	int c = a + b;
}


VOID Myfunction_Adresss_Next()
{
	My_Critical_Function();
};

BOOL SoftwareBreakpoints()
{
	size_t sSizeToCheck = (size_t)(Myfunction_Adresss_Next)-(size_t)(My_Critical_Function);
	PUCHAR Critical_Function = (PUCHAR)My_Critical_Function;

	for (size_t i = 0; i < sSizeToCheck; i++) {
		if (Critical_Function[i] == 0xCC)
			return TRUE;
	}
	return FALSE;
}