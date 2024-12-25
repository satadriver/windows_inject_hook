
#include <stdio.h>
#include <Windows.h>
#include "hook.h"
#include "log.h"


typedef HANDLE (__stdcall*ptrCreateFileA)(
LPCSTR                lpFileName,
DWORD                 dwDesiredAccess,
DWORD                 dwShareMode,
LPSECURITY_ATTRIBUTES lpSecurityAttributes,
DWORD                 dwCreationDisposition,
DWORD                 dwFlagsAndAttributes,
HANDLE                hTemplateFile
);

ptrCreateFileA lpCreateFileA = 0;

HANDLE __stdcall newCreateFileA(LPCSTR  lpFileName, DWORD  dwDesiredAccess, DWORD  dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) 
{
	

	HANDLE hf= lpCreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition,
		dwFlagsAndAttributes, hTemplateFile);

	printf("newCreateFileA\r\n");
	//MessageBoxA(0, "hello", "hello", MB_OK);

	return hf;
}

void hookMain() {
	//MessageBoxA(0, "2", "2", MB_OK);

	(ptrCreateFileA)hook(L"Kernel32.dll",L"CreateFileA",(BYTE*) newCreateFileA,(PROC*)&lpCreateFileA);

	
}



BOOL WINAPI DllMain(
	HINSTANCE hinstDLL,  // handle to DLL module
	DWORD fdwReason,     // reason for calling function
	LPVOID lpvReserved) 
{
	
	if (fdwReason == DLL_PROCESS_ATTACH) {
		//MessageBoxA(0, "1", "1", MB_OK);
		hookMain();
	}

	return TRUE;
}