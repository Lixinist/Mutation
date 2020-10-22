#pragma once
#include <vector>
#include <capstone/capstone.h>
#include "PE.h"
#include "define.h"
using namespace std;
using namespace asmjit;

typedef struct _imm {
	DWORD		address;
	DWORD		imm_value;
	uint8_t		imm_offset;
	uint8_t		imm_size;

}x86_imm, *P_x86_imm;
typedef struct _mem {
	DWORD		address;
	uint8_t		disp_offset;
	uint8_t		disp_size;
	x86_reg		base;
	x86_reg		index;
	int			scale;
	int64_t		disp;
	uint8_t		mem_size;

}x86_mem, *P_x86_mem;
typedef struct _jcc {
	DWORD		address;
	DWORD		Target_JumpAddr;
	uint8_t		imm_offset;
	uint8_t		imm_size;

}x86_jcc, *P_x86_jcc;
typedef struct _jcc_FixOffset
{
	DWORD		address;
	DWORD		Target_JumpAddr;
	uint8_t		imm_offset;

} FixOffset, *P_FixOffset;
//static vector<FixOffset> Fix_Offset;



class Mutation;
class x86Insn_Mutation;
class Mutation
{
public:
	Mutation();
	~Mutation();
	//初始化变量
	void InitValue();

public:
	//标志中不要有\x00
#define Mutation_Start		"\xEB\x0C\x4C\x58\x5F\x4D\x75\x74\x5F\x53\x74\x61\x72\x74"
#define Mutation_End		"\xEB\x0A\x4C\x58\x5F\x4D\x75\x74\x5F\x45\x6E\x64"
	typedef struct _Mark
	{
		LPBYTE Jmp_Start;
		LPBYTE Protected_Start;
		LPBYTE Protected_End;
		LPBYTE Jmp_End;
	} Mark, *PMark;
	vector<Mark>	Mut_Mark;
	CPE	objPE;


public:
	//最开始的地方
	void	Start(CString filepath);
	//寻找Mutation标志
	UINT	Find_MutationMark(LPBYTE pFinalBuf, DWORD size, OUT vector<Mark> *Mark);
	//开始变异
	void	Start_Mutation(x86Insn_Mutation& code);
	//jmp连接首尾
	void	link_jmp(int flag, x86Insn_Mutation& code, CPE& objPE, LPBYTE Addr);
	//清除原代码
	void	ClearCode(LPBYTE Start_Addr, LPBYTE End_Addr);



	//保存最终加壳后的文件
	BOOL SaveFinalFile(LPBYTE pFinalBuf, DWORD pFinalBufSize, CString strFilePath);
};

class x86Insn_Mutation : public Mutation
{
public:
	x86Insn_Mutation();
	~x86Insn_Mutation();
	//初始化变量
	void InitValue();

public:
	csh			handle;
	cs_insn		insn;
	vector<Mark>Mut_Mark_again;
	//BOOL again_flag;


	//用于变异代码重定位的基地址
	//void* BaseAddress;

	//单条指令的变异代码
	CodeHolder	Mut_Code;
	//单条指令的变异代码的大小
	//size_t Mut_CodeSize;

	//所有变异代码所在的内存
	void*		Final_MutMemory;
	//所有变异代码所在内存的大小
	size_t		FinalMem_Size;
	//所有变异代码所在内存的剩余大小
	size_t		FinalRemainMem_Size;

	//所有变异代码的总大小
	size_t Final_CodeSize;


	typedef struct _Single_MutCode
	{
		//原指令地址
		DWORD		Raw_CodeAddr;
		//变异代码块起始地址
		DWORD		Mut_CodeStartAddr;
		//变异代码块大小
		size_t		Mut_CodeSize;
		//变异代码块尾部（下一个变异代码块的起始处）
		DWORD		Mut_CodeEndAddr;
		//重定位基地址
		DWORD		BaseAddr;
	} Single_MutCode, *PSingle_MutCode;
	Single_MutCode SingMut_Sec;
	vector<Single_MutCode> SingMut;
	vector<FixOffset> Fix_Offset;

	//继承成员数据
	x86Insn_Mutation& operator=(const Mutation& Mut) {
		objPE = Mut.objPE;
		Mut_Mark = Mut.Mut_Mark;
		return *this;
	}
public:
	//针对每段代码进行反汇编
	BOOL	Disassemble(LPBYTE Protected_Start, LPBYTE Protected_End, LPBYTE Jmp_Start, LPBYTE Jmp_End);
	//针对单行指令开始变异
	UINT	Mutation_SingleCode();
	//判断指令类型
	UINT	Analyze_InsnType();
	//处理未知的指令
	UINT	Resolve_UnknownInsn();
	//将单行指令的变异代码写到Final空间
	UINT	Copy_MutCodes_to_FinalMem();


	//重定位imm和mem(disp)
	BOOL	RelocData_imm_mem(DWORD DataAddr, IN OUT x86::Gp base_reg, IN OUT UINT* offset);
	//修复jmp的offset
	UINT	Fix_JmpOffset();
	//更新内存容量
	UINT	Update_Mem();
	//重定位处理
	virtual BOOL	DealWithReloc(DWORD DataAddr, DWORD NeedtoReloActuAddr);
	//转换jcc目标跳转地址为实际地址
	virtual UINT	Jcc_ActuAddr(DWORD Target_JumpAddr);
	
	UINT	reloc();

	x86_MutationRule
	x86Insn_Class;
};

class x86Insn_Mutation_again : public x86Insn_Mutation
{
public:
	//重写方法
	UINT	Jcc_ActuAddr(DWORD Target_JumpAddr);
	BOOL	DealWithReloc(DWORD DataAddr, DWORD NeedtoReloActuAddr);
public:
	void* old_Final_MutMemory;
	//继承成员数据
	x86Insn_Mutation_again& operator=(const x86Insn_Mutation& code) {
		//FinalMem_Size = code.FinalMem_Size;
		//FinalRemainMem_Size = code.FinalRemainMem_Size;
		//Final_CodeSize = code.Final_CodeSize;
		//SingMut = code.SingMut;
		old_Final_MutMemory = code.Final_MutMemory;
		objPE = code.objPE;
		Fix_Offset = code.Fix_Offset;
		Mut_Mark = code.Mut_Mark_again;
		return *this;
	}
};

#define memory_size 0x100000	//1MB
#define Unknown_Address 0xFFFFFFFF

