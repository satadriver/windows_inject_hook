

#include "hook.h"
#include "log.h"


HOOK_TRAMPLINE g_trampline = { 0 };



HOOK_TRAMPLINE* findTrampline(const WCHAR* funcname) {

	HOOK_TRAMPLINE* ptr = g_trampline.next;
	while(ptr )
	{
		if (lstrcmpiW(funcname, ptr->apiName) == 0)
		{
			return ptr;
		}
		ptr = ptr->next;
	}

	return 0;
}


HOOK_TRAMPLINE* insertTrampline( HOOK_TRAMPLINE* node) {
	HOOK_TRAMPLINE* ptr = &g_trampline;
	if (ptr->next == 0) {
		ptr->next = node;
		return ptr->next;
	}

	while (ptr->next)
	{
		ptr = ptr->next;
	}
	ptr->next = node;

	return node;
}


int deleteTrampline(const WCHAR* funcname) {

	HOOK_TRAMPLINE* prev = &g_trampline;

	HOOK_TRAMPLINE* ptr = g_trampline.next;
	while (ptr )
	{
		if (lstrcmpiW(funcname, ptr->apiName) == 0)
		{
			HOOK_TRAMPLINE* next = ptr->next;

			prev->next = next;
			VirtualFree(ptr, sizeof(HOOK_TRAMPLINE), MEM_DECOMMIT);
			VirtualFree( ptr, 0,MEM_RELEASE);
			return TRUE;
		}	
		prev = ptr;
		ptr = ptr->next;
	}

	return 0;
}


HOOK_TRAMPLINE* createTrampline(const WCHAR* funcname) {
	HOOK_TRAMPLINE* ptr = findTrampline(funcname);
	if (ptr == 0) {
		ptr = (HOOK_TRAMPLINE * )VirtualAlloc(0,sizeof( HOOK_TRAMPLINE), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (ptr) {
			lstrcpyW(ptr->apiName, funcname);

			insertTrampline(ptr);
			return ptr;
		}
	}
	return 0;
}


#ifdef _WIN64
#include "hde/hde64.h"

int inlinehook64(BYTE* newfun, BYTE* hookaddr, PROC* keepaddr, const WCHAR* funcname) {
	int result = 0;

	if (hookaddr == newfun || newfun == 0 || keepaddr == 0 || funcname == 0 || hookaddr == 0)
	{
		log(L"%ws hook %ws parameter error\r\n", __FUNCTIONW__, funcname);
		return FALSE;
	}

	HOOK_TRAMPLINE* trampline = createTrampline(funcname);
	if (trampline <= 0)
	{
		log(L"%ws hook %ws createTrampline error\r\n", __FUNCTIONW__, funcname);
		return FALSE;
	}

	//DebugBreak();

	ULONGLONG offset = 0;

	int codelen = 0;

	BYTE* codeptr = hookaddr;

	while (codelen < AMD64_INLINE_HOOK_STUB_SIZE)
	{
		hde64s asm64 = { 0 };
		int instructionlen = hde64_disasm(codeptr+codelen, &asm64);
		if (instructionlen <= 0)
		{
			log(L"%ws function:%ws hde64_disasm address:%p error\r\n", __FUNCTIONW__, funcname, codeptr);
			deleteTrampline(funcname);
			return FALSE;
		}

		/*
		if ((*codeptr == 0xff && *(codeptr + 1) == 0x25) || (*codeptr == 0xff && *(codeptr + 1) == 0x15))
		{
			offset = *(DWORD*)(codeptr + 2);
			offset = ((offset + 6 + (ULONGLONG)codeptr) & ADDRESS64_LOW_MASK) + ((ULONGLONG)codeptr & ADDRESS64_HIGI_MASK);
			offset = *(ULONGLONG*)offset;
			codeptr = (BYTE*)(offset);

			codelen = 0;

			continue;
		}
		else if ((*codeptr == 0x48 && *(codeptr + 1) == 0xff && *(codeptr + 2) == 0x25) ||
			(*codeptr == 0x48 && *(codeptr + 1) == 0xff && *(codeptr + 2) == 0x15))
		{
			offset = *(DWORD*)(codeptr + 3);
			offset = ((offset + 7 + (ULONGLONG)codeptr) & ADDRESS64_LOW_MASK) + ((ULONGLONG)codeptr & ADDRESS64_HIGI_MASK);
			offset = *(ULONGLONG*)offset;
			codeptr = (BYTE*)(offset);
			codelen = 0;
			continue;
		}
		else if (*codeptr == 0xeb)
		{
			offset = *(codeptr + 1);
			codeptr = (BYTE*)((offset + 2 + (ULONGLONG)codeptr) & ADDRESS64_LOW_MASK) + ((ULONGLONG)codeptr & ADDRESS64_HIGI_MASK);

			codelen = 0;
			continue;
		}
		else if (*codeptr == 0xe9 || *codeptr == 0xe8)		
		{
			offset = *(DWORD*)(codeptr + 1);
			codeptr = (BYTE*)(((ULONGLONG)codeptr + 5 + offset) & ADDRESS64_LOW_MASK) + ((ULONGLONG)oldfun & ADDRESS64_HIGI_MASK);

			codelen = 0;
			continue;
		}

		else if (*codeptr == 0x83 && *(codeptr + 1) == 0x3d)
			//0000000180026130 83 3D 35 C8 08 00 05                    cmp     cs:?g_systemCallFilterId@@3KA, 5
			//0000000180026137 74 0C                                   jz      short loc_180026145
		{
			memcpy(trump->code + codelen, codeptr, instructionlen);

			offset = *(DWORD*)(codeptr + 2);

			ULONGLONG offsetlow = ((offset + 7 + (ULONGLONG)codeptr) & ADDRESS64_LOW_MASK);
			ULONGLONG offsethigh = ((ULONGLONG)codeptr & ADDRESS64_HIGI_MASK);

			ULONGLONG delta = (offsetlow - ((ULONGLONG)trump->code + codelen + instructionlen)) & ADDRESS64_LOW_MASK;
			*(DWORD*)(trump->code + codelen + 2) = (DWORD)delta;
		}
		else {
			memcpy(trump->code + codelen, codeptr, instructionlen);
		}
		*/
	
		codelen += instructionlen;
	}

	DWORD codeprotect = 0;
	result = VirtualProtect(codeptr, codelen, PAGE_EXECUTE_READWRITE, &codeprotect);
	if (result == 0)
	{
		log(L"%ws VirtualProtect function:%ws address:%p error\r\n", __FUNCTIONW__,funcname, codeptr);
		deleteTrampline(funcname);
		return FALSE;
	}

	memcpy(trampline->code, codeptr, codelen);

	codeptr[0] = 0xff;
	codeptr[1] = 0x25;
	*(DWORD*)(codeptr + 2) = 0;
	*(ULONGLONG*)(codeptr + 6) = (ULONGLONG)newfun;

	trampline->code[codelen] = 0xff;
	trampline->code[codelen + 1] = 0x25;
	*(DWORD*)(trampline->code + codelen + 2) = 0;
	*(ULONGLONG*)(trampline->code + codelen + 6) = (ULONGLONG)(codeptr + codelen);

	*keepaddr = (FARPROC) & (trampline->code);

	DWORD trampProtect = 0;
	result = VirtualProtect(trampline->code, codelen+ AMD64_INLINE_HOOK_STUB_SIZE, PAGE_EXECUTE_READWRITE, &trampProtect);

	result = VirtualProtect(codeptr, codelen, codeprotect, &codeprotect);
	
	trampline->replace.oldaddr = codeptr;
	trampline->replace.len = codelen;

	log(L"%ws %ws hook size:%d ,trampline address:%p, function address:%p,new function address:%p,keep address:%p",
		__FUNCTIONW__,funcname, codelen, trampline->code, codeptr, newfun, *keepaddr);

	WCHAR szout[1024];
	hex2str((char*)codeptr, codelen, szout);
	log(szout);

	hex2str((char*)trampline->code, codelen + AMD64_INLINE_HOOK_STUB_SIZE , szout);
	log(szout);

	return result;
}
#else
#include "hde/hde32.h"

int inlinehook32(BYTE* newfun, BYTE* hookaddr, PROC* keepaddr, const WCHAR* funcname) {
	int result = 0;

	if (hookaddr == newfun || newfun == 0 || keepaddr == 0 || funcname==0 || hookaddr == 0)
	{
		log(L"%ws hook %ws parameter error\r\n", __FUNCTIONW__, funcname);
		return FALSE;
	}

	HOOK_TRAMPLINE* trampline = createTrampline(funcname);
	if (trampline <= 0)
	{
		log(L"%ws hook %ws createTrampline error\r\n", __FUNCTIONW__, funcname);
		return FALSE;
	}
	
	BYTE* codeptr = hookaddr;

	int codelen = 0;
	
	while (codelen < IA32_INLINE_HOOK_STUB_SIZE)
	{
		hde32s asm32 = { 0 };
		int instructionlen = hde32_disasm(codeptr + codelen, &asm32);
		if (instructionlen <= 0)
		{
			log(L"%ws hook %ws hde32_disasm address:%p error\r\n", __FUNCTIONW__, funcname, codeptr);
			deleteTrampline(funcname);
			return FALSE;
		}

		/*
		if ((*codeptr == 0xff && *(codeptr + 1) == 0x25) || (*codeptr == 0xff && *(codeptr + 1) == 0x15))
		{
			//FF 25 D4 0F B1 76
			//76b10fd4:76 1e a4 70
			//70a41e76:CreateFileA
			DWORD offset = *(DWORD*)(codeptr + 2);
			offset = *(DWORD*)offset;
			codeptr = (BYTE*)offset;

			codelen = 0;
			continue;
		}	
		else if (*codeptr == 0xe9 || *codeptr == 0xe8 )
		{
			DWORD offset = *(DWORD*)(codeptr + 1);
			codeptr += offset + 5;

			codelen = 0;
			continue;
		}
		//0xeb 
		//0xea
		//0x70-0x7f
		//0x0f
		else if (*oldfun == 0xeb)
		{
			DWORD offset = *(oldfun + 1);
			oldfun += offset + 2;

			oldcode = oldfun;
			codelen = 0;
			continue;
		}
		else if (*oldfun >= 0x70 && *oldfun <= 0x7f)		//jump with flag range in 128 bytes
		{

		}
		else if (*oldfun == 0x0f && (*(oldfun + 1) >= 0x80 && *(oldfun + 1) <= 0x8f))	
		{

		}
		else if (*oldfun == 0xea) {

		}
		//ffe4 jmp esp
		else {
				
		}
		*/

		codelen += instructionlen;
	}

	DWORD codeprotect = 0;
	result = VirtualProtect(codeptr, codelen, PAGE_EXECUTE_READWRITE, &codeprotect);
	if (result == 0)
	{
		log(L"%ws VirtualProtect function:%ws address:%p error\r\n", __FUNCTIONW__, funcname, codeptr);
		deleteTrampline(funcname);
		return FALSE;
	}

	memcpy(trampline->code, codeptr, codelen);

	codeptr[0] = 0xe9;
	*(DWORD*)(codeptr + 1) = newfun - (codeptr + 5);		//why is 5?

	trampline->code[codelen] = 0xe9;
	*(DWORD*)(trampline->code + codelen + 1) = codeptr + codelen - (trampline->code + codelen + 5);

	*keepaddr = (FARPROC) & (trampline->code);

	DWORD dummyprotect = 0;
	result = VirtualProtect(trampline->code, codelen + 5, PAGE_EXECUTE_READWRITE, &dummyprotect);
	
	result = VirtualProtect(codeptr, codelen, codeprotect, &dummyprotect);

	trampline->replace.oldaddr = codeptr;
	trampline->replace.len = codelen;

	log(L"%ws %ws trampline size:%d,trampline address:%p,function addr:%p,new function addr:%p,keep address:%p",
		__FUNCTIONW__, funcname, codelen, trampline->code, codeptr, newfun, keepaddr);

	WCHAR szout[1024];
	hex2str((char*)codeptr, codelen, szout);
	log(szout);

	hex2str((char*)trampline->code, codelen + IA32_INLINE_HOOK_STUB_SIZE, szout);
	log(szout);

	return result;
}

#endif

int hook(CONST WCHAR* modulename, const WCHAR* wstrfuncname, BYTE* newfuncaddr, PROC* keepaddr) {
	int result = 0;
	HMODULE h = GetModuleHandleW(modulename);
	if (h)
	{
		CHAR funcname[MAX_PATH];
		result = WideCharToMultiByte(CP_ACP, 0, wstrfuncname, -1, funcname, MAX_PATH, 0, 0);
		if (result)
		{
			LPBYTE  oldfunc = (LPBYTE)GetProcAddress(h, funcname);
			if (oldfunc)
			{
#ifdef _WIN64
				result = inlinehook64(newfuncaddr, oldfunc, keepaddr, wstrfuncname);
#else
				result = inlinehook32(newfuncaddr, oldfunc, (FARPROC*)keepaddr, wstrfuncname);
#endif	
				if (result)
				{
					log(L"hook %ws %ws ok\r\n", modulename, wstrfuncname);
				}
				return result;
			}
			else {
				log(L"%ws %ws %ws not found", __FUNCTIONW__,wstrfuncname, modulename);
			}
		}
		else {
			log(L"%ws WideCharToMultiByte %ws error", __FUNCTIONW__, wstrfuncname);
		}
	}
	else {
		log(L"%ws module %ws not found", __FUNCTIONW__,modulename);
	}
	return FALSE;
}


int unhook(CONST WCHAR* modulename, const WCHAR* wstrfuncname) {
	int result = 0;

	HOOK_TRAMPLINE* ptr = g_trampline.next;
	while (ptr)
	{
		if (lstrcmpiW(wstrfuncname, ptr->apiName) == 0)
		{
			unsigned char* oldcode = ptr->replace.oldaddr;
			int oldcodelen = ptr->replace.len;
			DWORD oldprotect = 0;
			result = VirtualProtect(oldcode, oldcodelen, PAGE_EXECUTE_READWRITE, &oldprotect);
			memcpy(oldcode, ptr->code, oldcodelen);
			DWORD dummyprotect = 0;
			result = VirtualProtect(oldcode, oldcodelen, oldprotect, &dummyprotect);

			log(L"%ws unhook function:%ws ok", __FUNCTIONW__,wstrfuncname);
			return TRUE;
		}
		ptr = ptr->next;
	}

	return FALSE;
}


int  unhookall() {
	int result = 0;

	HOOK_TRAMPLINE* ptr = g_trampline.next;
	while (ptr)
	{
		unsigned char* oldcode = ptr->replace.oldaddr;

		int oldcodelen = ptr->replace.len;
		result = IsBadReadPtr(oldcode, oldcodelen);
		if (result == 0)
		{
			DWORD oldprotect = 0;
			result = VirtualProtect(oldcode, oldcodelen, PAGE_EXECUTE_READWRITE, &oldprotect);

			memcpy(oldcode, ptr->code, oldcodelen);
			DWORD dummyprotect = 0;
			result = VirtualProtect(oldcode, oldcodelen, oldprotect, &dummyprotect);
			log(L"%ws unhook function:%ws ok", __FUNCTIONW__,ptr->apiName);
		}
		else {
			log(L"funciton:%ws address:%p can not be write,maybe the dll has been unload?", ptr->apiName, oldcode);
		}

		ptr = ptr->next;
	}

	return TRUE;
}




PUCHAR allocTrampAddress(PUCHAR  module) {
	IMAGE_NT_HEADERS64* hdr = (IMAGE_NT_HEADERS64*)module;
	PUCHAR* address = (PUCHAR*)hdr->OptionalHeader.ImageBase + hdr->OptionalHeader.SizeOfImage;

	PUCHAR* alloc = (PUCHAR*)VirtualAlloc(address, 0x4000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (alloc)
	{
	}
	return 0;
}

