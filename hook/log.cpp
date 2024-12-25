
#include "log.h"
#include <stdio.h>


#define LOG_TAG_A "[ljg]"
#define LOG_TAG_W _T(LOG_TAG_A)

int __cdecl __log(const WCHAR* format, ...) {

	WCHAR szbuf[2048];

	va_list   pArgList;

	va_start(pArgList, format);

	int prefixLen = lstrlenW(LOG_TAG_W);

	lstrcpyW(szbuf, LOG_TAG_W);

	int nByteWrite = vswprintf_s(szbuf + prefixLen, sizeof(szbuf) / sizeof(WCHAR)- prefixLen, format, pArgList);

	va_end(pArgList);

	OutputDebugStringW(szbuf);

	//wprintf(L"%S\r\n",(char*)szbuf);

	return nByteWrite;
}



int __cdecl __log(const CHAR* format, ...) {

	CHAR szbuf[2048];

	va_list   pArgList;

	va_start(pArgList, format);

	int prefixLen = lstrlenA(LOG_TAG_A) ;

	lstrcpyA(szbuf, LOG_TAG_A);

	int nByteWrite = vsprintf_s(szbuf+ prefixLen, sizeof(szbuf) / sizeof(CHAR) - prefixLen, format, pArgList);

	va_end(pArgList);

	OutputDebugStringA(szbuf);

	printf("%s\r\n", szbuf);

	return nByteWrite;
}




int hex2str(char* codeptr,int codelen, wchar_t* szout) {
	WCHAR* loginfo = szout;
	int len = 0;
	for (int i = 0; i < codelen; i++)
	{
		len = wsprintfW(loginfo, L" %02X ", *(codeptr + i));
		loginfo = loginfo + len;
	}
	*loginfo = 0;
	return loginfo - szout;
}