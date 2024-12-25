#include <windows.h>


int __stdcall MainThread(void* pParamAddr);

//int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
int main_old()
{

	HMODULE pLoadLibraryA;
	HMODULE pGetProcAddress;
	HMODULE pGetModuleHandleA;
	HMODULE pDllKernel32;
	void* pRemoteThreadAddr;
	void* pRemoteParamAddr;
	DWORD hProcessId;				//DWORD =unsigned long

	const char* szDllKernel32 = "kernel32.dll";
	const char* szLoadLibraryA = "LoadLibraryA";
	const char* szGetProcAddress = "GetProcAddress";			// is GetProcAddressA? NO
	const char* szGetModuleHandleA = "GetModuleHandleA";

	LARGE_INTEGER GdtLimit;

	__asm
	{


		sgdt fword ptr GdtLimit;
		pushad
			push MB_OKCANCEL
			push 0
			push szLoadLibraryA
			push 0
			mov esi, 0x77e5425f
			call esi

			// 		push offset EipAddress
			// 		__emit 0xe9
			// 		__emit 0x5f
			// 		__emit 0x42
			// 		__emit 0xe5
			// 		__emit 0x77
		EipAddress:
		popad
			//GdtLen:
			__emit 0x90;
		__emit 0x90;
		__emit 0x90;
		__emit 0x90;
		__emit 0x90;
		__emit 0x90;
		__emit 0x90;
		__emit 0x90;
	}

	pDllKernel32 = (HINSTANCE)GetModuleHandleA(szDllKernel32);
	if (pDllKernel32 == 0)
	{
		MessageBoxA(0, "NOT Find Window!\n", 0, MB_OK);
		return 0;
	}

	pLoadLibraryA = (HINSTANCE)GetProcAddress(pDllKernel32, szLoadLibraryA);
	if (pLoadLibraryA == 0)
	{
		MessageBoxA(0, "NOT Find Window!\n", 0, MB_OK);
		return 0;
	}
	pGetProcAddress = (HINSTANCE)GetProcAddress(pDllKernel32, szGetProcAddress);
	if (pGetProcAddress == 0)
	{
		MessageBoxA(0, "NOT Find Window!\n", 0, MB_OK);
		return 0;
	}
	pGetModuleHandleA = (HINSTANCE)GetProcAddress(pDllKernel32, szGetModuleHandleA);
	if (pGetModuleHandleA == 0)
	{
		MessageBoxA(0, "NOT Find Window!\n", 0, MB_OK);
		return 0;
	}




	HWND hDeskTop = FindWindowA("Progman", "Program Manager");
	if (hDeskTop)
	{
		//MessageBoxA(0,"Find Window!\n",0,MB_OK);
	}
	else
	{
		MessageBoxA(0, "NOT Find Window!\n", 0, MB_OK);
		return 0;
	}

	DWORD hMainThreadId = GetWindowThreadProcessId(hDeskTop, &hProcessId);
	if (hProcessId)
	{
		//MessageBoxA(0,"Get Window ID!\n",0,MB_OK);
	}
	else
	{
		MessageBoxA(0, "NOT Get Window ID!\n", 0, MB_OK);
		return 0;
	}
	SYSTEM_INFO stSysInfo;
	GetSystemInfo(&stSysInfo);
	HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, hProcessId);
	if (hProcess)
	{
		//MessageBoxA(0,"Get Process Handle!\n",0,MB_OK);
	}
	else
	{
		MessageBoxA(0, "NOT Get Process Handle!\n", 0, MB_OK);
		return 0;
	}



	pRemoteThreadAddr = VirtualAllocEx(hProcess, 0, 0x40000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (pRemoteThreadAddr)
	{
		//MessageBoxA(0,"Get pRemoteThreadAddr!\n",0,MB_OK);
	}
	else
	{
		MessageBoxA(0, "NOT Get pRemoteThreadAddr!\n", 0, MB_OK);
		return 0;
	}
	pRemoteParamAddr = VirtualAllocEx(hProcess, 0, stSysInfo.dwPageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (pRemoteParamAddr)
	{
		//MessageBoxA(0,"Get pRemoteParamAddr!\n",0,MB_OK);
	}
	else
	{
		MessageBoxA(0, "NOT Get pRemoteParamAddr!\n", 0, MB_OK);
		return 0;
	}



	SIZE_T Counter;
	Counter = WriteProcessMemory(hProcess, pRemoteThreadAddr, (LPVOID)MainThread, 0x10000, &Counter);
	if (Counter)
	{
		//MessageBoxA(0,"Write pRemoteThreadAddr!\n",0,MB_OK);
	}
	else
	{
		MessageBoxA(0, "NOT Write pRemoteThreadAddr!\n", 0, MB_OK);
		return 0;
	}
	Counter = WriteProcessMemory(hProcess, pRemoteParamAddr, &pLoadLibraryA, 12, &Counter);
	if (Counter)
	{
		//MessageBoxA(0,"Write pRemoteParamAddr!\n",0,MB_OK);
	}
	else
	{
		MessageBoxA(0, "NOT Write pRemoteParamAddr!\n", 0, MB_OK);
		return 0;
	}



	HANDLE hRemoteThread = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)pRemoteThreadAddr, &pLoadLibraryA, 0, 0);
	if (hRemoteThread)
	{
		MessageBoxA(0, "Create Remote Thread!\n", 0, MB_OK);
	}
	else
	{
		MessageBoxA(0, "NOT Create Remote Thread!\n", 0, MB_OK);
		return 0;
	}
	CloseHandle(hRemoteThread);
	CloseHandle(hProcess);

	Sleep(1000);
	//ExitProcess(true);
	return true;
}


int __stdcall MainThread(void* pParamAddr)
{
	const char* szDllUser32 = "user32.dll";
	const char* szMessageBoxA = "MessageBoxA";
	HANDLE pDllUser32;
	HANDLE pMessageBoxA;
	unsigned long DeltaOffset;

	HMODULE pLoadLibraryA;
	HMODULE pGetProcAddress;
	HMODULE pGetModuleHandleA;
	HMODULE pDllKernel32;
	void* pRemoteThreadAddr;
	void* pRemoteParamAddr;
	DWORD hProcessId;				//DWORD =unsigned long	
	__asm
	{

		call Coordinate
		Coordinate :
		pop ebx
			sub ebx, offset Coordinate
			mov DeltaOffset, ebx

			mov esi, szDllUser32
			push esi
			mov edi, pParamAddr
			mov edi, [edi]
			call edi
			mov pDllUser32, eax

			mov esi, szMessageBoxA
			push esi
			mov eax, pDllUser32
			push eax
			mov edi, pParamAddr
			mov edi, [edi + 4]
			call edi
			mov pMessageBoxA, eax

			push MB_OK
			push 0
			push szMessageBoxA
			push 0
			call pMessageBoxA
			ret

	}

	return true;
}
