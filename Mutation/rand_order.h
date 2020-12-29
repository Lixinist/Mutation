#pragma once
#include "Mutation_Protecting.h"


typedef struct _Order_FixJcc
{
	//此struct用于修复jns/jnp unknown_address和call unknown_address
	//乱序代码尾部的jns/jnp/call的地址
	DWORD		address;
	uint8_t		imm_offset;
} Order_FixJcc, * POrder_FixJcc;
typedef struct _OrderedInsns
{
	//此struct表示每次乱序切割的指令段
	cs_insn*	order_insn;
	size_t		index;
	size_t		nums;
}OrderedInsns, * POrderedInsns;

class rand_order : public x86Insn_Mutation_again
{
public:
	BOOL	Disassemble(LPBYTE Protected_Start, LPBYTE Protected_End, LPBYTE Jmp_Start, LPBYTE Jmp_End);
	UINT	Update_Mem();
	UINT	_jnp(x86_jcc* jcc0);
	UINT	_jns(x86_jcc* jcc0);
	UINT	_jmp_imm(x86_jcc* jcc0);
	UINT	_call_imm(x86_jcc* jcc0);
	UINT	_add();
	UINT	_call();
	UINT	_jcc_jmp();
	
	UINT	Order_ManyCode();
	size_t	MakeOrderHead(DWORD CodeStartAddr);
	size_t	MakeOrderBody(DWORD CodeStartAddr);
	size_t	MakeOrderTail(DWORD	CodeStartAddr);

	//UINT	Copy_OrdCodes_to_FinalMem(BOOL copy_flag, DWORD codesize);
	//UINT	Update_Mem();
	//void	link_jmp(int flag, x86Insn_Mutation& code, CPE& objPE, LPBYTE Addr);
	void*	GetTargetAddress(DWORD dwsize);

public:
	BOOL		firstcode_flag;
	BOOL		endcode_flag;
	//放在首or尾
	int			place_flag;
	//双指针指向mem首尾
	void*		phead_mem;
	void*		ptail_mem;
	Order_FixJcc Order_FixOffset;
	OrderedInsns Ordered_Insns;
	//void*		plink_jmp;

	//继承成员数据
	rand_order& operator=(const x86Insn_Mutation_again& code) {
		old_Final_MutMemory = code.Final_MutMemory;
		old_Fix_Offset = code.CA_Fix_Offset;
		objPE = code.objPE;
		Mut_Mark = code.Mut_Mark_again;
		return *this;
	}
	rand_order& operator=(const x86Insn_Mutation& code) {
		old_Final_MutMemory = code.Final_MutMemory;
		old_Fix_Offset = code.CA_Fix_Offset;
		objPE = code.objPE;
		Mut_Mark = code.Mut_Mark_again;
		return *this;
	}
};