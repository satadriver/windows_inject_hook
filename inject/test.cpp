#include <windows.h>
#include <iostream>
#include <TlHelp32.h>
#include <tchar.h>

// ����������Ʒ��ظý���PID
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

// Զ���߳�ע��
BOOL CreateRemoteThreadInjectDll(DWORD Pid, char* DllName)
{
    HANDLE hProcess = NULL;
    SIZE_T dwSize = 0;
    LPVOID pDllAddr = NULL;
    FARPROC pFuncProcAddr = NULL;

    // ��ע�����
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Pid);
    if (NULL == hProcess)
    {
        return FALSE;
    }

    // �õ�ע���ļ�������·��
    dwSize = sizeof(char) + lstrlenA(DllName);

    // �ڶԶ�����һ���ڴ�
    pDllAddr = VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT, PAGE_READWRITE);
    if (NULL == pDllAddr)
    {
        return FALSE;
    }

    // ��ע���ļ���д�뵽�ڴ���
    if (FALSE == WriteProcessMemory(hProcess, pDllAddr, DllName, dwSize, NULL))
    {
        return FALSE;
    }

    // �õ�LoadLibraryA()�����ĵ�ַ
    pFuncProcAddr = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    if (NULL == pFuncProcAddr)
    {
        return FALSE;
    }

    // �����߳�ע��
    HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pFuncProcAddr, pDllAddr, 0, NULL);
    if (NULL == hRemoteThread)
    {
        return FALSE;
    }

    WaitForSingleObject(hRemoteThread,-1);
    // �رվ��
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
