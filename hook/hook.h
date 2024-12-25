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


je或jz         //  相等则跳（机器码是74或84）
jne或jnz       //  不相等则跳（机器码是75或85）
jmp            //  无条件跳（机器码是EB）

JC| 72| C=1| 有进位
JNC| 73| C=0| 无进位
JZ/JE| 74| Z=1| 零/等于
JNZ/JNE| 75| Z=0| 不为零/不等于
JS| 78| S=1| 负号
JNS| 79| S=0| 正号
JO| 70| O=1| 有溢出
JNO| 71| O=0| 无溢出
JP/JPE| 7A| P=1| 奇偶位为偶
JNP/IPO| 7B| P=0| 奇偶位为奇
JA/JNBE(比较无符号数)| 77| C或Z=0 > | 高于/不低于或等于
JAE/JNB(比较无符号数)| 73| C=0 >= | 高于或等于/不低于
JB/JNAE(比较无符号数)| 72| C=1 < | 低于/不高于或等于
JBE/JNA(比较无符号数)| 76| C或Z=1 <= | 低于或等于/不高于
JG/JNLE(比较带符号数)| 7F| (S异或O）或Z=0 > | 大于/不小于或等于
JGE/JNL(比较带符号数)| 7D| S异或O=0 >= | 大于或等于/不小于
JL/JNGE(比较带符号数)| 7C| S异或O=1 < | 小于/不大于或等于
JLE/JNG(比较带符号数)| 7E| (S异或O)或Z=1 <= | 小于或等于/不大于


EB cb | JMP rel8 | 相对短跳转（8位, 使rel8处的代码位下一条指令
E9 cw | JMP rel16 | 相对跳转（16位, 使rel16处的代码位下一条指令
FF /4 | JMP r/m16 | 绝对跳转（16位, 下一指令地址在r/m16中给出 FF /4 | JMP r/m32 | 绝对跳转（32位, 下一指令地址在r/m32中给出 EA cb | JMP ptr16:16 | 远距离绝对跳转, 下一指令地址在操作数中
EA cb | JMP ptr16:32 | 远距离绝对跳转, 下一指令地址在操作数中
FF /5 | JMP m16:16 | 远距离绝对跳转, 下一指令地址在内存m16:16中
FF /5 | JMP m16:32 | 远距离绝对跳转, 下一指令地址在内存m16:32中


0F 87 cw/cd | JA rel16/32 | 大于 | near | (CF=0 and ZF=0) 0F 83 cw/cd | JAE rel16/32 | 大于等于 | near | (CF=0)
0F 82 cw/cd | JB rel16/32 | 小于 | near | (CF=1)
0F 86 cw/cd | JBE rel16/32 | 小于等于 | near | (CF=1 or ZF=1)
0F 82 cw/cd | JC rel16/32 | 进位 | near | (CF=1)
0F 84 cw/cd | JE rel16/32 | 等于 | near | (ZF=1)
0F 84 cw/cd | JZ rel16/32 | 为0 | near | (ZF=1)
0F 8F cw/cd | JG rel16/32 | 大于 | near | (ZF=0 and SF=OF)
0F 8D cw/cd | JGE rel16/32 | 大于等于 | near | (SF=OF) 0F 8C cw/cd | JL rel16/32 | 小于 | near | (SF<>OF) 0F 8E cw/cd | JLE rel16/32 | 小于等于 | near | (ZF=1 or SF<>OF)
0F 86 cw/cd | JNA rel16/32 | 不大于 | near | (CF=1 or ZF=1)
0F 82 cw/cd | JNAE rel16/32 | 不大于等于 | near | (CF=1)
0F 83 cw/cd | JNB rel16/32 | 不小于 | near | (CF=0) 0F 87 cw/cd | JNBE rel16/32 | 不小于等于 | near | (CF=0 and ZF=0) 0F 83 cw/cd | JNC rel16/32 | 不进位 | near | (CF=0)
0F 85 cw/cd | JNE rel16/32 | 不等于 | near | (ZF=0) 0F 8E cw/cd | JNG rel16/32 | 不大于 | near | (ZF=1 or SF<>OF)
0F 8C cw/cd | JNGE rel16/32 | 不大于等于 | near | (SF<>OF)
0F 8D cw/cd | JNL rel16/32 | 不小于 | near | (SF=OF)
0F 8F cw/cd | JNLE rel16/32 | 不小于等于 | near | (ZF=0 and SF=OF)
0F 81 cw/cd | JNO rel16/32 | 未溢出 | near | (OF=0)
0F 8B cw/cd | JNP rel16/32 | 不是偶数 | near | (PF=0) 0F 89 cw/cd | JNS rel16/32 | 非负数 | near | (SF=0)
0F 85 cw/cd | JNZ rel16/32 | 非零（不等于）| near | (ZF=0)
0F 80 cw/cd | JO rel16/32 | 溢出 | near | (OF=1)
0F 8A cw/cd | JP rel16/32 | 偶数 | near | (PF=1)
0F 8A cw/cd | JPE rel16/32 | 偶数 | near | (PF=1) 0F 8B cw/cd | JPO rel16/32 | 奇数 | near | (PF=0)
0F 88 cw/cd | JS rel16/32 | 负数 | near | (SF=1)
0F 84 cw/cd | JZ rel16/32 | 为零（等于） | near | (ZF=1)


*/