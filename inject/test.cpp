#include <windows.h>
#include <iostream>
#include <TlHelp32.h>
#include <tchar.h>

// 传入进程名称返回该进程PID
DWORD FindProcessID(LPCSTR szProcessName)
{
    DWORD dwPID = 0xFFFFFFFF;
    HANDLE hSnapShot = INVALID_HANDLE_VALUE;
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
    Process32First(hSnapShot, &pe);
    wchar_t procname[1024];
    MultiByteToWideChar(CP_ACP, 0, szProcessName, -1, procname, sizeof(procname)/sizeof(wchar_t));
    do
    {
        if (lstrcmpiW(procname, (LPCTSTR)pe.szExeFile)==0)
        {
            dwPID = pe.th32ProcessID;
            break;
        }
    } while (Process32Next(hSnapShot, &pe));
    CloseHandle(hSnapShot);
    return dwPID;
}

// 远程线程注入
BOOL CreateRemoteThreadInjectDll(DWORD Pid, char* DllName)
{
    HANDLE hProcess = NULL;
    SIZE_T dwSize = 0;
    LPVOID pDllAddr = NULL;
    FARPROC pFuncProcAddr = NULL;

    // 打开注入进程
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Pid);
    if (NULL == hProcess)
    {
        return FALSE;
    }

    // 得到注入文件的完整路径
    dwSize = sizeof(char) + lstrlenA(DllName);

    // 在对端申请一块内存
    pDllAddr = VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT, PAGE_READWRITE);
    if (NULL == pDllAddr)
    {
        return FALSE;
    }

    // 将注入文件名写入到内存中
    if (FALSE == WriteProcessMemory(hProcess, pDllAddr, DllName, dwSize, NULL))
    {
        return FALSE;
    }

    // 得到LoadLibraryA()函数的地址
    pFuncProcAddr = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    if (NULL == pFuncProcAddr)
    {
        return FALSE;
    }

    // 启动线程注入
    HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pFuncProcAddr, pDllAddr, 0, NULL);
    if (NULL == hRemoteThread)
    {
        return FALSE;
    }

    WaitForSingleObject(hRemoteThread,-1);
    // 关闭句柄
    CloseHandle(hProcess);
    return TRUE;
}

int main(int argc, LPCSTR argv[])
{
    if (argc < 2) {
        printf("usage:%s -n ProcessName\r\n",argv[0]);
        printf("usage:%s -p Pid\r\n", argv[0]);
        return 0;
    }

    char dllpath[MAX_PATH];
    GetModuleFileNameA(0, dllpath, MAX_PATH);
    for (int i = lstrlenA(dllpath); i >= 0; i--) {
        if (dllpath[i] == '\\') {
            dllpath[i + 1] = 0;
            lstrcatA(dllpath, "hook.dll");
            break;
        }
    }
    if (lstrcmpiA(argv[1], ("-n")) == 0) {
        DWORD pid = FindProcessID(argv[2]);
        bool flag = CreateRemoteThreadInjectDll(pid, (char*)dllpath);
    }
    else if (lstrcmpiA(argv[1], ("-p")) == 0) {
        DWORD pid = atoi(argv[2]);
        bool flag = CreateRemoteThreadInjectDll(pid, (char*)dllpath);
    }
    else {

    }

    return 0;
}
