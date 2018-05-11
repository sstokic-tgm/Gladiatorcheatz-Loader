#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <fstream>
#include <conio.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <tlhelp32.h>
#include <thread>
#include <chrono>
#include <future>
#include "Rijndael.h"
#include "XorStr.h"
#include "WMICHwid.h"
#include "Shared\Main.h"

#pragma comment (lib, "Ws2_32.lib")

#define NT_SUCCESS(x) ((x) >= 0)

typedef struct _CLIENT_ID
{
	PVOID UniqueProcess;
	PVOID UniqueThread;
} CLIENT_ID, *PCLIENT_ID;


#define InitializeObjectAttributes(p, n, a, r, s) \
{ \
	(p)->Length = sizeof(OBJECT_ATTRIBUTES); \
	(p)->RootDirectory = r; \
	(p)->Attributes = a; \
	(p)->ObjectName = n; \
	(p)->SecurityDescriptor = s; \
	(p)->SecurityQualityOfService = NULL; \
}

typedef HMODULE(WINAPI *pLoadLibraryA)(LPCSTR);
typedef FARPROC(WINAPI *pGetProcAddress)(HMODULE, LPCSTR);

typedef BOOL(WINAPI *PDLL_MAIN)(HMODULE, DWORD, PVOID);

typedef struct _MANUAL_INJECT
{
	PVOID ImageBase;
	PIMAGE_NT_HEADERS NtHeaders;
	PIMAGE_BASE_RELOCATION BaseRelocation;
	PIMAGE_IMPORT_DESCRIPTOR ImportDirectory;
	pLoadLibraryA fnLoadLibraryA;
	pGetProcAddress fnGetProcAddress;
}MANUAL_INJECT, *PMANUAL_INJECT;

static const int BLOCK_SIZE = 16;

SOCKET connectSocket;
int m_iResult;
std::string hwid;
std::thread thr;
bool bSentinel;

void SetStdinEcho(bool enable = true);
BOOL IsAdministrator(VOID);
void DecodeBuffer(char *buffer, char *output, unsigned int size);
int sendall(SOCKET s, char *buf, int *len);

BOOL ProcessExists(std::wstring process);
DWORD GetProcID(std::wstring ProcName);
PVOID GetLibraryProcAddress(PSTR LibraryName, PSTR ProcName);
DWORD WINAPI LoadDll(PVOID p);
DWORD WINAPI LoadDllEnd();

typedef NTSTATUS(NTAPI *_RtlCreateUserThread)(HANDLE ProcessHandle, PSECURITY_DESCRIPTOR SecurityDescriptor, BOOLEAN CreateSuspended, ULONG StackZeroBits, PULONG StackReserved, PULONG StackCommit, PVOID StartAddress, PVOID StartParameter, PHANDLE ThreadHandle, PCLIENT_ID ClientID);
typedef NTSTATUS(NTAPI *_RtlAdjustPrivilege)(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN Enabled);
typedef NTSTATUS(NTAPI *_NtOpenProcess)(PHANDLE ProcessHandle, ACCESS_MASK AccessMask, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientID);
typedef NTSTATUS(NTAPI *_NtWriteVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten);
typedef NTSTATUS(NTAPI *_NtClose)(HANDLE ObjectHandle);

static void ReadAllBytes(char const *filename, std::vector<char> &result)
{
	std::ifstream ifs(filename, std::ios::binary | std::ios::ate);
	std::ifstream::pos_type pos = ifs.tellg();

	std::vector<char> tmp(pos);

	ifs.seekg(0, std::ios::beg);
	ifs.read(&tmp[0], pos);

	result = tmp;
}

int sendall(SOCKET s, char *buf, int *len)
{
	int total = 0;
	int bytesleft = *len;
	int n;

	while (total < *len)
	{
		n = send(s, buf + total, bytesleft, 0);
		if (n == -1) { break; }
		total += n;
		bytesleft -= n;
	}

	*len = total;

	return n == -1 ? -1 : 0;
}

void KeepAliveThread();

int main(int argc, char **argv)
{
	SetConsoleTitleA(_xor_("Gladiatorcheatz").c_str());
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 11);

	if (IsAdministrator() == FALSE)
	{
		std::cerr << _xor_("Error: Please start it as admin !") << std::endl;

		std::getchar();
		std::exit(EXIT_FAILURE);
	}

	std::cout << _xor_("############################") << std::endl;
	std::cout << _xor_("# Gladiatorcheatz - Loader #") << std::endl;
	std::cout << _xor_("############################") << std::endl << std::endl;

	WMICHwid wmiHWID;

	if (!wmiHWID.query())
	{
		std::cerr << _xor_("An error has occured, please try again!") << std::endl;

		std::getchar();
		std::exit(EXIT_FAILURE);
	}

	hwid += wmiHWID.getCPU() + wmiHWID.getComputerName() + wmiHWID.getPhysicalHddSerial();
	hwid.erase(std::remove_if(hwid.begin(), hwid.end(), std::isspace), hwid.end());

	PIMAGE_DOS_HEADER pIDH;
	PIMAGE_NT_HEADERS pINH;
	PIMAGE_SECTION_HEADER pISH;

	NTSTATUS status;
	OBJECT_ATTRIBUTES objAttr;
	CLIENT_ID cID;
	DWORD procID = 0;
	BOOLEAN enabled;
	DWORD numBytesWritten;
	HANDLE hThread = INVALID_HANDLE_VALUE;
	HANDLE hProcess = INVALID_HANDLE_VALUE;
	HANDLE hFile = INVALID_HANDLE_VALUE;

	PVOID image, mem;
	DWORD ExitCode;

	MANUAL_INJECT ManualInject;

	_RtlCreateUserThread RtlCreateUserThread = (_RtlCreateUserThread)GetLibraryProcAddress(_xor_("ntdll.dll").c_str(), _xor_("RtlCreateUserThread").c_str());
	_RtlAdjustPrivilege RtlAdjustPrivilege = (_RtlAdjustPrivilege)GetLibraryProcAddress(_xor_("ntdll.dll").c_str(), _xor_("RtlAdjustPrivilege").c_str());
	_NtOpenProcess NtOpenProcess = (_NtOpenProcess)GetLibraryProcAddress(_xor_("ntdll.dll").c_str(), _xor_("NtOpenProcess").c_str());
	_NtWriteVirtualMemory NtWriteVirtualMemory = (_NtWriteVirtualMemory)GetLibraryProcAddress(_xor_("ntdll.dll").c_str(), _xor_("NtWriteVirtualMemory").c_str());
	_NtClose NtClose = (_NtClose)GetLibraryProcAddress(_xor_("ntdll.dll").c_str(), _xor_("NtClose").c_str());

	auto ProcessName = L"csgo.exe";

	WSADATA wsaData;

	connectSocket = INVALID_SOCKET;

	struct addrinfo *result = NULL;
	struct addrinfo *ptr = NULL;
	struct addrinfo hints = { 0 };

	m_iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (m_iResult != 0)
	{
		std::cout << _xor_("WSAStartup() failed with error: ") << m_iResult << std::endl;
		std::exit(EXIT_FAILURE);
	}

	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	m_iResult = getaddrinfo(_xor_("url_to_site.com").c_str(), _xor_("3724").c_str(), &hints, &result);
	if (m_iResult != 0)
	{
		std::exit(EXIT_FAILURE);
	}

	for (ptr = result; ptr != NULL; ptr = ptr->ai_next)
	{
		connectSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);

		if (connectSocket == INVALID_SOCKET)
		{
			WSACleanup();
			std::exit(EXIT_FAILURE);
		}

		m_iResult = connect(connectSocket, ptr->ai_addr, ptr->ai_addrlen);
		if (m_iResult == SOCKET_ERROR)
		{
			closesocket(connectSocket);
			connectSocket = INVALID_SOCKET;
			std::cout << _xor_("The server is currently down!") << std::endl;
			std::getchar();
		}
	}

	freeaddrinfo(result);

	if (connectSocket == INVALID_SOCKET)
	{
		std::cout << _xor_("Unable to connect to server!") << std::endl;
		WSACleanup();
		connectSocket = NULL;
		std::exit(EXIT_FAILURE);
	}

	u_long m_iMode = 0;

	m_iResult = ioctlsocket(connectSocket, FIONBIO, &m_iMode);
	if (m_iResult == SOCKET_ERROR)
	{
		closesocket(connectSocket);
		WSACleanup();
		connectSocket = NULL;
		std::exit(EXIT_FAILURE);
	}

	char value = 1;
	setsockopt(connectSocket, IPPROTO_TCP, TCP_NODELAY, &value, sizeof(value));

	bSentinel = false;

	std::vector<char> chararr;
	std::string fpath(_xor_("C:\\Windows\\System32\\drivers\\etc\\hosts").c_str());
	ReadAllBytes(fpath.c_str(), chararr);

	size_t len = 0;
	
	int file_size = chararr.size();
	char* pFileData = new char[file_size];
	memcpy(pFileData, chararr.data(), file_size);

	char* filePacket = new char[file_size + 6 + fpath.length() + 1];
	memset(filePacket, 0, file_size + 6 + fpath.length() + 1);

	*(int*)filePacket = fpath.length() + 1 + file_size;
	*(WORD*)(filePacket + 5) = 0x01;
	strcpy((char*)(filePacket + 6), fpath.c_str());
	memcpy((char*)(filePacket + 6 + fpath.length() + 1), pFileData, file_size);

	int r = file_size + 6 + fpath.length() + 1;
	if (sendall(connectSocket, filePacket, &r) == -1)
	{
		closesocket(connectSocket);
		WSACleanup();
		connectSocket = NULL;
		delete[] pFileData;
		delete[] filePacket;
		std::exit(EXIT_FAILURE);
	}
	delete[] pFileData;
	delete[] filePacket;

	char eAuthData[BUFSIZ] = { 0 };
	m_iResult = recv(connectSocket, eAuthData, BUFSIZ, 0);
	eAuthData[m_iResult] = '\0';

	BYTE resCode = *(BYTE*)(eAuthData + 2);
	if (resCode == 3)
	{
		closesocket(connectSocket);
		WSACleanup();
		connectSocket = NULL;
		ZeroMemory(eAuthData, BUFSIZ);
		std::exit(EXIT_FAILURE);
	}
	ZeroMemory(eAuthData, BUFSIZ);

	//std::async(std::launch::async, []() {thr = std::thread(KeepAliveThread); });

	char eNetworkData[BUFSIZ] = { 0 };
	char* pLoginData = new char[400];

	bSentinel = true;

	do
	{
		std::string username;
		std::string password;
		std::cout << _xor_("Username: ");
		std::cin >> username;
		SetStdinEcho(false);
		std::cout << _xor_("Password: ");
		std::cin >> password;
		SetStdinEcho(true);

		int usernameLength = username.length();
		int passwordLength = password.length();
		int hwidLength = hwid.length();

		char* packet = pLoginData;
		
		*(int*)pLoginData = (usernameLength + 1 + passwordLength + 1 + hwidLength + 1);

		pLoginData += 5;
		*(WORD*)pLoginData = 0x02;
		pLoginData += 1;

		strcpy((char*)(pLoginData), username.c_str());
		pLoginData += usernameLength;
		strcpy((char*)(pLoginData), ";");
		pLoginData += 1;
		
		strcpy((char*)(pLoginData), password.c_str());
		pLoginData += passwordLength;
		strcpy((char*)(pLoginData), ";");
		pLoginData += 1;

		strcpy((char*)(pLoginData), hwid.c_str());
		pLoginData += hwidLength;
		strcpy((char*)(pLoginData), ";");
		pLoginData += 1;

		m_iResult = send(connectSocket, packet, *(WORD*)(packet) + 6, 0);

		m_iResult = recv(connectSocket, eNetworkData, BUFSIZ, 0);
		eNetworkData[m_iResult] = '\0';

		BYTE resCode = *(BYTE*)(eNetworkData + 2);
		ZeroMemory(eNetworkData, BUFSIZ);

		if (resCode == 5)
			std::cout << _xor_("\nInvalid username/password. Please try again.\n") << std::endl;
		if (resCode == 3 || resCode == 6)
			std::cout << _xor_("\nAn unknown error occured. Please try again.\n") << std::endl;
		if (resCode == 7)
			std::cout << _xor_("\nYou are not a Gladiator! Please buy VIP access.\n") << std::endl;
		if (resCode == 8)
			std::cout << _xor_("\nThis account is already linked to another computer.\n") << std::endl;
		if (resCode == 9)
			break;

		if (m_iResult == 0)
		{
			closesocket(connectSocket);
			WSACleanup();
			connectSocket = NULL;
			std::exit(EXIT_FAILURE);
		}
	} while (m_iResult > 0);

	ZeroMemory(eNetworkData, BUFSIZ);

	std::cout << _xor_("\nSuccessfull logged in!") << std::endl;

	std::cout << _xor_("\nWaiting for csgo...\n");
	while (!ProcessExists(ProcessName)) {}

	std::cout << _xor_("Process detected !\n");
	std::cout << _xor_("\nPreparing hack...") << std::endl;

	char* buf = new char[BUFSIZ];
	ZeroMemory(buf, BUFSIZ);
	len = recv(connectSocket, buf, BUFSIZ, 0);
	if (len < 4)
	{
		closesocket(connectSocket);
		WSACleanup();
		connectSocket = NULL;
		delete[] buf;
		std::exit(EXIT_FAILURE);
	}

	int fileSize = *(int*)buf;

	BYTE *dllData = new BYTE[fileSize];
	memset(dllData, 0, fileSize);
	int offset = 0;

	memcpy(dllData, buf + 4, len - 4);
	offset += len - 4;

	while (len > 0)
	{
		ZeroMemory(buf, BUFSIZ);
		len = recv(connectSocket, buf, BUFSIZ, 0);

		if (len == 0)
			break;
		else if (len < 0)
		{
			closesocket(connectSocket);
			WSACleanup();
			connectSocket = NULL;
			std::exit(EXIT_FAILURE);
		}
		
		memcpy(dllData + offset, buf, len);
		offset += len;
	}
	delete[] buf;

	bSentinel = false;
	closesocket(connectSocket);
	WSACleanup();
	connectSocket = NULL;

	char *enDllData = new char[offset];
	
	char filestr[999999] = { 0 };
	int spacetoblock = 0;

	enDllData[0] = dllData[0];

	spacetoblock = (offset - 1) % BLOCK_SIZE;
	int tmpSize = (offset - 1) + (BLOCK_SIZE - spacetoblock);
	char *data = new char[tmpSize + 1];
	ZeroMemory(data, tmpSize);
	memcpy(data, dllData + 1, tmpSize);

	DecodeBuffer(data, filestr, tmpSize);

	delete[] data;
	data = new char[offset - 1 + 1];
	ZeroMemory(data, offset - 1);
	for (int i = 0; i < offset - 1; i++)
		data[i] = filestr[i];

	memcpy(enDllData + 1, data, offset - 1);

	delete[] data;
	delete[] buf;

	RtlAdjustPrivilege(20, TRUE, FALSE, &enabled);
	InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

	procID = GetProcID(ProcessName);
	cID.UniqueProcess = (PVOID)procID;
	cID.UniqueThread = 0;

	pIDH = (PIMAGE_DOS_HEADER)enDllData;
	if (pIDH->e_magic != IMAGE_DOS_SIGNATURE)
	{
		delete[] enDllData;
		delete[] dllData;
		return EXIT_FAILURE;
	}

	pINH = (PIMAGE_NT_HEADERS)((LPBYTE)enDllData + pIDH->e_lfanew);
	if (pINH->Signature != IMAGE_NT_SIGNATURE)
	{
		delete[] enDllData;
		delete[] dllData;
		return EXIT_FAILURE;
	}

	if (!(pINH->FileHeader.Characteristics & IMAGE_FILE_DLL))
	{
		delete[] enDllData;
		delete[] dllData;
		return EXIT_FAILURE;
	}

	if (!NT_SUCCESS(status = NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objAttr, &cID)))
	{
		std::cerr << _xor_("Unable to open target process ") << GetLastError() << std::endl;
		system("pause");
		delete[] enDllData;
		delete[] dllData;
		return EXIT_FAILURE;
	}

	image = VirtualAllocEx(hProcess, NULL, pINH->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!image)
	{
		std::cerr << _xor_("Unable to allocate memory ") << GetLastError() << std::endl;
		delete[] enDllData;
		delete[] dllData;
		NtClose(hProcess);
		return EXIT_FAILURE;
	}

	if (!NT_SUCCESS(status = NtWriteVirtualMemory(hProcess, image, enDllData, pINH->OptionalHeader.SizeOfHeaders, &numBytesWritten)))
	{
		VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);
		delete[] enDllData;
		delete[] dllData;
		NtClose(hProcess);
		return EXIT_FAILURE;
	}

	pISH = (PIMAGE_SECTION_HEADER)(pINH + 1);
	for (int i = 0; i < pINH->FileHeader.NumberOfSections; i++)
		NtWriteVirtualMemory(hProcess, (PVOID)((LPBYTE)image + pISH[i].VirtualAddress), (PVOID)((LPBYTE)enDllData + pISH[i].PointerToRawData), pISH[i].SizeOfRawData, &numBytesWritten);

	mem = VirtualAllocEx(hProcess, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!mem)
	{
		std::cerr << _xor_("Unable to allocate memory for the loader code ") << GetLastError() << std::endl;
		VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);
		delete[] enDllData;
		delete[] dllData;
		NtClose(hProcess);
		return EXIT_FAILURE;
	}

	memset(&ManualInject, 0, sizeof(MANUAL_INJECT));
	ManualInject.ImageBase = image;
	ManualInject.NtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)image + pIDH->e_lfanew);
	ManualInject.BaseRelocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)image + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	ManualInject.ImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)image + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	ManualInject.fnLoadLibraryA = LoadLibraryA;
	ManualInject.fnGetProcAddress = GetProcAddress;

	NtWriteVirtualMemory(hProcess, mem, &ManualInject, sizeof(MANUAL_INJECT), &numBytesWritten);
	NtWriteVirtualMemory(hProcess, (PVOID)((PMANUAL_INJECT)mem + 1), LoadDll, (DWORD)LoadDllEnd - (DWORD)LoadDll, &numBytesWritten);

	hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((PMANUAL_INJECT)mem + 1), mem, 0, NULL);
	if (!hThread)
	{
		std::cerr << _xor_("Unable to allocate memory for the loader code ") << GetLastError() << std::endl;
		VirtualFreeEx(hProcess, mem, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);
		delete[] enDllData;
		delete[] dllData;
		NtClose(hProcess);
		return EXIT_FAILURE;
	}
	std::cout << _xor_("Loading...") << std::endl;
	WaitForSingleObject(hThread, INFINITE);
	GetExitCodeThread(hThread, &ExitCode);
	if (!ExitCode)
	{
		VirtualFreeEx(hProcess, mem, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);
		delete[] enDllData;
		delete[] dllData;
		NtClose(hProcess);
		NtClose(hThread);
		return EXIT_FAILURE;
	}

	if (pINH->OptionalHeader.AddressOfEntryPoint)
		std::cout << _xor_("Have Fun!") << std::endl;

	NtClose(hThread);
	VirtualFreeEx(hProcess, mem, 0, MEM_RELEASE);
	NtClose(hProcess);

	delete[] enDllData;
	delete[] dllData;

	ErasePEHeaderFromMemory();

	_getch();

	return EXIT_SUCCESS;
}

void DecodeBuffer(char *buffer, char *output, unsigned int size)
{
	CRijndael rijndael;
	static std::string k = _xor_("TIMOTEI_ZION");
	rijndael.MakeKey(k.c_str(), CRijndael::sm_chain0, 16, BLOCK_SIZE);
	rijndael.Decrypt((char*)buffer, (char*)output, size);
	rijndael.ResetChain();
}

BOOL IsAdministrator(VOID)
{
	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	PSID AdministratorsGroup;

	if (!AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdministratorsGroup))
	{
		return FALSE;
	}

	BOOL IsInAdminGroup = FALSE;

	if (!CheckTokenMembership(NULL, AdministratorsGroup, &IsInAdminGroup))
	{
		IsInAdminGroup = FALSE;
	}

	FreeSid(AdministratorsGroup);
	return IsInAdminGroup;
}

void SetStdinEcho(bool enable)
{
	HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
	DWORD mode;
	GetConsoleMode(hStdin, &mode);

	if (!enable)
		mode &= ~ENABLE_ECHO_INPUT;
	else
		mode |= ENABLE_ECHO_INPUT;

	SetConsoleMode(hStdin, mode);
}

BOOL ProcessExists(std::wstring process)
{
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	pe32.dwSize = sizeof(PROCESSENTRY32);
	do {
		if (wcscmp(pe32.szExeFile, process.c_str()) == 0)
		{
			CloseHandle(hProcessSnap);
			return true;
		}
	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	return false;
}

DWORD GetProcID(std::wstring ProcName)
{
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	pe32.dwSize = sizeof(PROCESSENTRY32);
	do {
		if (wcscmp(pe32.szExeFile, ProcName.c_str()) == 0)
		{
			DWORD ProcId = pe32.th32ProcessID;
			CloseHandle(hProcessSnap);
			return ProcId;
		}
	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	return 0;
}

PVOID GetLibraryProcAddress(PSTR LibraryName, PSTR ProcName)
{
	return GetProcAddress(GetModuleHandleA(LibraryName), ProcName);
}

BOOL executeTls(PMANUAL_INJECT manualInject)
{
	BYTE *codeBase = (BYTE*)manualInject->ImageBase;

	PIMAGE_TLS_DIRECTORY tls;
	PIMAGE_TLS_CALLBACK* callback;

	PIMAGE_DATA_DIRECTORY directory = &(manualInject)->NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
	if (directory->VirtualAddress == 0)
		return TRUE;

	tls = (PIMAGE_TLS_DIRECTORY)(codeBase + directory->VirtualAddress);
	callback = (PIMAGE_TLS_CALLBACK *)tls->AddressOfCallBacks;
	if (callback)
	{
		while (*callback)
		{
			(*callback)((LPVOID)codeBase, DLL_PROCESS_ATTACH, NULL);
			callback++;
		}
	}
	return TRUE;
}

DWORD WINAPI LoadDll(PVOID p)
{
	PMANUAL_INJECT ManualInject;

	HMODULE hModule;
	DWORD i, Function, count, delta;

	PDWORD ptr;
	PWORD list;

	PIMAGE_BASE_RELOCATION pIBR;
	PIMAGE_IMPORT_DESCRIPTOR pIID;
	PIMAGE_IMPORT_BY_NAME pIBN;
	PIMAGE_THUNK_DATA FirstThunk, OrigFirstThunk;

	PDLL_MAIN EntryPoint;

	ManualInject = (PMANUAL_INJECT)p;

	pIBR = ManualInject->BaseRelocation;
	delta = (DWORD)((LPBYTE)ManualInject->ImageBase - ManualInject->NtHeaders->OptionalHeader.ImageBase); // Calculate the delta

	// Relocate the image
	while (pIBR->VirtualAddress)
	{
		if (pIBR->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
		{
			count = (pIBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			list = (PWORD)(pIBR + 1);

			for (i = 0; i<count; i++)
			{
				if (list[i])
				{
					ptr = (PDWORD)((LPBYTE)ManualInject->ImageBase + (pIBR->VirtualAddress + (list[i] & 0xFFF)));
					*ptr += delta;
				}
			}
		}

		pIBR = (PIMAGE_BASE_RELOCATION)((LPBYTE)pIBR + pIBR->SizeOfBlock);
	}

	pIID = ManualInject->ImportDirectory;

	// Resolve DLL imports
	while (pIID->Characteristics)
	{
		OrigFirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)ManualInject->ImageBase + pIID->OriginalFirstThunk);
		FirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)ManualInject->ImageBase + pIID->FirstThunk);

		hModule = ManualInject->fnLoadLibraryA((LPCSTR)ManualInject->ImageBase + pIID->Name);

		if (!hModule)
		{
			return FALSE;
		}

		while (OrigFirstThunk->u1.AddressOfData)
		{
			if (OrigFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				// Import by ordinal

				Function = (DWORD)ManualInject->fnGetProcAddress(hModule, (LPCSTR)(OrigFirstThunk->u1.Ordinal & 0xFFFF));

				if (!Function)
				{
					return FALSE;
				}

				FirstThunk->u1.Function = Function;
			}

			else
			{
				// Import by name

				pIBN = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)ManualInject->ImageBase + OrigFirstThunk->u1.AddressOfData);
				Function = (DWORD)ManualInject->fnGetProcAddress(hModule, (LPCSTR)pIBN->Name);

				if (!Function)
				{
					return FALSE;
				}

				FirstThunk->u1.Function = Function;
			}

			OrigFirstThunk++;
			FirstThunk++;
		}

		pIID++;
	}

	if (!executeTls(ManualInject))
		MessageBoxA(0, _xor_("TLS execution failed!").c_str(), 0, MB_ICONERROR | MB_OK);

	if (ManualInject->NtHeaders->OptionalHeader.AddressOfEntryPoint)
	{
		EntryPoint = (PDLL_MAIN)((LPBYTE)ManualInject->ImageBase + ManualInject->NtHeaders->OptionalHeader.AddressOfEntryPoint);
		return EntryPoint((HMODULE)ManualInject->ImageBase, DLL_PROCESS_ATTACH, NULL); // Call the entry point
	}

	return TRUE;
}

DWORD WINAPI LoadDllEnd()
{
	return 0;
}

void KeepAliveThread()
{
	size_t len = 0;
	while (connectSocket != NULL)
	{
		if (bSentinel)
			continue;

		std::this_thread::sleep_for(std::chrono::milliseconds(500)); // lets do it every 500ms

		char* pKeepAliveData = new char[100];
		char* packet = pKeepAliveData;

		int hwidLength = hwid.length();

		*(int*)pKeepAliveData = (hwidLength + 1);

		pKeepAliveData += 5;
		*(WORD*)pKeepAliveData = 0x04;
		pKeepAliveData += 1;

		strcpy((char*)(pKeepAliveData), hwid.c_str());
		pKeepAliveData += hwidLength;
		strcpy((char*)(pKeepAliveData), ";");
		pKeepAliveData += 1;

		len = send(connectSocket, packet, *(WORD*)(packet) + 6, 0);
		delete[] pKeepAliveData;

		char eAuthData[BUFSIZ] = { 0 };
		len = recv(connectSocket, eAuthData, BUFSIZ, 0);
		eAuthData[len] = '\0';

		BYTE resCode = *(BYTE*)(eAuthData + 2);

		if (resCode != 9)
		{
			closesocket(connectSocket);
			WSACleanup();
			ZeroMemory(eAuthData, BUFSIZ);
			HANDLE handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_TERMINATE, 0, GetCurrentProcessId());
			TerminateProcess(handle, 0);
		}
		ZeroMemory(eAuthData, BUFSIZ);
	}
}