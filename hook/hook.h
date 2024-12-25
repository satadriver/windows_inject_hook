#pragma once



#include <windows.h>

#ifdef _WIN64

#define ADDRESS64_HIGI_MASK				0xffffffff00000000L

#define ADDRESS64_LOW_MASK				0xffffffffL

#define AMD64_INLINE_HOOK_STUB_SIZE		14
#else

#define IA32_INLINE_HOOK_STUB_SIZE		5
#endif




#define TRAMPLINE_SIZE					64


#pragma pack(1)

typedef struct
{
	unsigned char* oldaddr;
	char len;
}REPLACE_CODE;

typedef struct  _HOOK_TRAMPS
{
	_HOOK_TRAMPS* next;

	WCHAR apiName[64];

	BYTE code[TRAMPLINE_SIZE];

	REPLACE_CODE replace;

}HOOK_TRAMPLINE;

#pragma pack()

HOOK_TRAMPLINE* insertTrampline(HOOK_TRAMPLINE* node);

HOOK_TRAMPLINE* findTrampline(const WCHAR* funcname);

int deleteTrampline(const WCHAR* funcname);

HOOK_TRAMPLINE* createTrampline(const WCHAR* funcname);



extern "C" __declspec(dllexport) int hook(const WCHAR * modulename, const WCHAR * funcname, BYTE * newfuncaddr, PROC * keepaddr);

extern "C" __declspec(dllexport) int inlinehook64(BYTE * newfun, BYTE * oldfun, PROC * keepaddr, const WCHAR * funcname);

extern "C" __declspec(dllexport) int inlinehook32(BYTE * newfun, BYTE * oldfun, PROC * keepaddr, const WCHAR * funcname);

int unhook(CONST WCHAR* modulename, const WCHAR* wstrfuncname);

int  unhookall();


/*
EB  cb    JMP rel8        7+m             Jump short
E9  cd    JMP rel32       7+m             Jump near, displacement relative to next instruction
EA  cp    JMP ptr16:32    12+m,pm=27+m    Jump intersegment, 6-byte immediate address
FF  15/25


je��jz         //  �����������������74��84��
jne��jnz       //  �������������������75��85��
jmp            //  ������������������EB��

JC| 72| C=1| �н�λ
JNC| 73| C=0| �޽�λ
JZ/JE| 74| Z=1| ��/����
JNZ/JNE| 75| Z=0| ��Ϊ��/������
JS| 78| S=1| ����
JNS| 79| S=0| ����
JO| 70| O=1| �����
JNO| 71| O=0| �����
JP/JPE| 7A| P=1| ��żλΪż
JNP/IPO| 7B| P=0| ��żλΪ��
JA/JNBE(�Ƚ��޷�����)| 77| C��Z=0 > | ����/�����ڻ����
JAE/JNB(�Ƚ��޷�����)| 73| C=0 >= | ���ڻ����/������
JB/JNAE(�Ƚ��޷�����)| 72| C=1 < | ����/�����ڻ����
JBE/JNA(�Ƚ��޷�����)| 76| C��Z=1 <= | ���ڻ����/������
JG/JNLE(�Ƚϴ�������)| 7F| (S���O����Z=0 > | ����/��С�ڻ����
JGE/JNL(�Ƚϴ�������)| 7D| S���O=0 >= | ���ڻ����/��С��
JL/JNGE(�Ƚϴ�������)| 7C| S���O=1 < | С��/�����ڻ����
JLE/JNG(�Ƚϴ�������)| 7E| (S���O)��Z=1 <= | С�ڻ����/������


EB cb | JMP rel8 | ��Զ���ת��8λ, ʹrel8���Ĵ���λ��һ��ָ��
E9 cw | JMP rel16 | �����ת��16λ, ʹrel16���Ĵ���λ��һ��ָ��
FF /4 | JMP r/m16 | ������ת��16λ, ��һָ���ַ��r/m16�и��� FF /4 | JMP r/m32 | ������ת��32λ, ��һָ���ַ��r/m32�и��� EA cb | JMP ptr16:16 | Զ���������ת, ��һָ���ַ�ڲ�������
EA cb | JMP ptr16:32 | Զ���������ת, ��һָ���ַ�ڲ�������
FF /5 | JMP m16:16 | Զ���������ת, ��һָ���ַ���ڴ�m16:16��
FF /5 | JMP m16:32 | Զ���������ת, ��һָ���ַ���ڴ�m16:32��


0F 87 cw/cd | JA rel16/32 | ���� | near | (CF=0 and ZF=0) 0F 83 cw/cd | JAE rel16/32 | ���ڵ��� | near | (CF=0)
0F 82 cw/cd | JB rel16/32 | С�� | near | (CF=1)
0F 86 cw/cd | JBE rel16/32 | С�ڵ��� | near | (CF=1 or ZF=1)
0F 82 cw/cd | JC rel16/32 | ��λ | near | (CF=1)
0F 84 cw/cd | JE rel16/32 | ���� | near | (ZF=1)
0F 84 cw/cd | JZ rel16/32 | Ϊ0 | near | (ZF=1)
0F 8F cw/cd | JG rel16/32 | ���� | near | (ZF=0 and SF=OF)
0F 8D cw/cd | JGE rel16/32 | ���ڵ��� | near | (SF=OF) 0F 8C cw/cd | JL rel16/32 | С�� | near | (SF<>OF) 0F 8E cw/cd | JLE rel16/32 | С�ڵ��� | near | (ZF=1 or SF<>OF)
0F 86 cw/cd | JNA rel16/32 | ������ | near | (CF=1 or ZF=1)
0F 82 cw/cd | JNAE rel16/32 | �����ڵ��� | near | (CF=1)
0F 83 cw/cd | JNB rel16/32 | ��С�� | near | (CF=0) 0F 87 cw/cd | JNBE rel16/32 | ��С�ڵ��� | near | (CF=0 and ZF=0) 0F 83 cw/cd | JNC rel16/32 | ����λ | near | (CF=0)
0F 85 cw/cd | JNE rel16/32 | ������ | near | (ZF=0) 0F 8E cw/cd | JNG rel16/32 | ������ | near | (ZF=1 or SF<>OF)
0F 8C cw/cd | JNGE rel16/32 | �����ڵ��� | near | (SF<>OF)
0F 8D cw/cd | JNL rel16/32 | ��С�� | near | (SF=OF)
0F 8F cw/cd | JNLE rel16/32 | ��С�ڵ��� | near | (ZF=0 and SF=OF)
0F 81 cw/cd | JNO rel16/32 | δ��� | near | (OF=0)
0F 8B cw/cd | JNP rel16/32 | ����ż�� | near | (PF=0) 0F 89 cw/cd | JNS rel16/32 | �Ǹ��� | near | (SF=0)
0F 85 cw/cd | JNZ rel16/32 | ���㣨�����ڣ�| near | (ZF=0)
0F 80 cw/cd | JO rel16/32 | ��� | near | (OF=1)
0F 8A cw/cd | JP rel16/32 | ż�� | near | (PF=1)
0F 8A cw/cd | JPE rel16/32 | ż�� | near | (PF=1) 0F 8B cw/cd | JPO rel16/32 | ���� | near | (PF=0)
0F 88 cw/cd | JS rel16/32 | ���� | near | (SF=1)
0F 84 cw/cd | JZ rel16/32 | Ϊ�㣨���ڣ� | near | (ZF=1)


*/