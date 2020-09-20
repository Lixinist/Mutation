#pragma once
#include <capstone/capstone.h>
#include "PE.h"

LPBYTE Find_MemoryString(LPBYTE pFinalBuf, DWORD size, const LPBYTE String);
x86::Gp to_asmjit_reg(x86_reg capstone_reg);
x86::SReg to_asmjit_sreg(x86_reg capstone_reg);
x86::Gp Low_reg(x86_reg capstone_reg, UINT Low_reg);
x86_reg Low_reg_2(x86_reg capstone_reg, UINT Low_reg);
x86_reg Low_reg_Check(x86_reg capstone_reg);
bool Check_Reg(x86_reg capstone_reg);
bool Check_SReg(x86_reg capstone_reg);

typedef enum {
	ax,
	ah,
	al
}low_reg;