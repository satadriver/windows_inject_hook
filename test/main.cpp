

#include <Windows.h>
#include <stdio.h>


int main(int argc,char ** argv){
	
	int num = 0;
	while (1) {
		Sleep(3000);
		HANDLE hf = CreateFileA("mytest.txt", GENERIC_READ, 0, 0, OPEN_ALWAYS, 0, 0);
		if (hf == INVALID_HANDLE_VALUE || hf == 0) {
			break;
		}

		char buf[1024];
		DWORD cnt = 0;
		int len = wsprintfA(buf, "time:%d\r\n", num++);
		
		printf("%s\r\n",buf);
		WriteFile(hf, buf, len, &cnt, 0);
		CloseHandle(hf);
	}

	return 0;
}