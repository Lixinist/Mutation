#include "pch.h"
#include "Mutation_Protecting.h"
#include "auxiliary_function.h"
#ifdef _DEBUG
#pragma comment(lib, "asmjit_debug.lib")
#else
#pragma comment(lib, "asmjit.lib")
#endif 

Mutation::Mutation()
{
	InitValue();
}
Mutation::~Mutation(){}
void Mutation::InitValue()
{
	
}
x86Insn_Mutation::x86Insn_Mutation()
{
	InitValue();
}
x86Insn_Mutation::~x86Insn_Mutation() {}
void x86Insn_Mutation::InitValue()
{
	Final_MutMemory = NULL;
	FinalMem_Size = 0;
	FinalRemainMem_Size = 0;
	Final_CodeSize = 0;
	again_flag = false;
}




void Mutation::Start(CString filepath)
{
	//CPE	objPE;
	x86Insn_Mutation code;
	vector<Mark> Mark;
	
	if (filepath.IsEmpty()) {
		MessageBox(NULL, _T("未输入文件路径！"), NULL, NULL);
		return;
	}
	if (objPE.InitPE(filepath) == false) {
		MessageBox(NULL, _T("InitPE失败！"), NULL, NULL);
		return;
	}
	//此时文件已读入内存且已内存对齐
	//1.寻找Mutation保护标志
	if (Find_MutationMark(objPE.m_pFileBuf, objPE.m_dwImageSize, &Mark) == 0) {
		MessageBox(NULL, _T("未找到Mutation保护标志！"), NULL, NULL);
		VirtualFree(objPE.m_pFileBuf, 0, MEM_DECOMMIT);
		//delete[] objPE.m_pFileBuf;
		return;
	}
	
	//2.开始进行变异
	code.objPE = this->objPE;								//objPE的初始化不适合放在构造函数，所以直接赋值过去
	code.Mut_Mark = this->Mut_Mark;
	Start_Mutation(code);									//不能写objMut.Start_Mutation()

	//3.合并PE文件和变异代码到新的缓冲区
	LPBYTE pFinalBuf = NULL;
	DWORD dwFinalBufSize = 0;
	objPE.MergeBuf(objPE.m_pFileBuf, objPE.m_dwImageSize,
		(LPBYTE)code.Final_MutMemory, code.Final_CodeSize,
		pFinalBuf, dwFinalBufSize);
	//4.保存文件（处理完成的缓冲区）
	SaveFinalFile(pFinalBuf, dwFinalBufSize, filepath);
	//5.释放资源
	VirtualFree(objPE.m_pFileBuf, 0, MEM_DECOMMIT);
	VirtualFree(pFinalBuf, 0, MEM_DECOMMIT);
	VirtualFree(code.Final_MutMemory, 0, MEM_DECOMMIT);
	//delete[] objPE.m_pFileBuf;
	//delete[] pFinalBuf;
	//free(code.Final_MutMemory);
}
//针对所有段的代码进行变异
void Mutation::Start_Mutation(x86Insn_Mutation& code)
{
	//先置一波随机数种子
	srand((unsigned)time(NULL));


	//初始化重定位基址
	//code.CS_Struct.Mut_CodeStartAddr = (objPE.m_dwImageBase + objPE.m_dwImageSize);
	//开Final空间
	if (code.Final_MutMemory == NULL)
	{
		code.Final_MutMemory = VirtualAlloc(NULL, memory_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		code.FinalMem_Size = memory_size;
		code.FinalRemainMem_Size = memory_size;
		if (code.Final_MutMemory == NULL)
			MessageBox(NULL, _T("Final_MutMemory申请空间失败"), NULL, NULL);
	}
	//针对每一段代码进行变异
	for (auto iter = Mut_Mark.begin(); iter != Mut_Mark.end(); iter++) {
		//start_link
		link_jmp(1, code, objPE, iter->Start);
		//反汇编&&变异
		code.Disassemble(iter->Start + strlen((char*)Mutation_Start), iter->End);
		//end_link
		link_jmp(0, code, objPE, iter->End + strlen((char*)Mutation_End));
		//清除该段的原代码
		ClearCode(iter->Start + 5, iter->End + strlen((char*)Mutation_End));
	}
}
static csh handle;
//针对每段代码
BOOL x86Insn_Mutation ::Disassemble(LPBYTE Start_Addr, LPBYTE End_Addr)
{
	uint64_t address = (uint64_t)Start_Addr;		//起始地址
	cs_insn *insn;									//反汇编出的指令信息
	BOOL result = true;
	size_t count;
	cs_err err = cs_open(CS_ARCH_X86, CS_MODE_32, &handle);
	if (err) {
		MessageBox(NULL, _T("Failed on cs_open()"), NULL, NULL);
		printf("Failed on cs_open() with error returned: %u\n", err);
		abort();
	}

	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

	//cs_disasm倒数第二个参数：需要解析的指令数量，0为全部
	count = cs_disasm(handle, Start_Addr, End_Addr-Start_Addr, address, 0, &insn);
	if (count) {
		size_t j;
		
		for (j = 0; j < count; j++) {
			//x86Insn_Mutation code;
			this->handle = handle;
			this->insn = insn[j];
			this->Mutation_SingleCode();
		}

		// free memory allocated by cs_disasm()
		cs_free(insn, count);
	}
	else {
		printf("ERROR: Failed to disasm given code!\n");
		abort();
		result = false;
	}

	cs_close(&handle);
	return result;
}
//针对单行指令
UINT x86Insn_Mutation::Mutation_SingleCode()
{
	UINT result = -1;
	Mut_Code.init(CodeInfo(ArchInfo::kIdHost));
	//1.变异前先判断 该代码地址是否为jmp的目标跳转地址
	Fix_JmpOffset();
	//1.分析指令类型，生成变异代码
	result = Analyze_InsnType();

	//遇上不能变异的指令，直接copy过去
	if (result == -1)
	{
		Resolve_UnknownInsn();
		return result;
	}
	//2.将单行指令的变异代码重定位后写到Final空间，并填写CodeSection结构体
	Copy_MutCodes_to_FinalMem();
	
	//3.清除这次存入CodeHolder的代码
	Mut_Code.reset();

	return result;
}
//判断指令类型
UINT x86Insn_Mutation::Analyze_InsnType()
{
	cs_x86 *x86;
	if (insn.detail == NULL)
		return -1;
	x86 = &(insn.detail->x86);
	//1.先判断reg和mem中有没有esp或sp寄存器，对这种特殊情况不做变异，直接留给Resolve_UnknownInsn()处理
	for (int i = 0; i < x86->op_count; i++) {
		//当前op_type为reg
		if (x86->operands[i].type == X86_OP_REG ) {
			if (x86->operands[i].reg == X86_REG_ESP || x86->operands[i].reg == X86_REG_SP)
				return -1;
		}
		//当前op_type为mem
		if (x86->operands[i].type == X86_OP_MEM) {
			if (x86->operands[i].mem.base == X86_REG_ESP || x86->operands[i].mem.base == X86_REG_SP)
				return -1;
			if (x86->operands[i].mem.index == X86_REG_ESP || x86->operands[i].mem.index == X86_REG_SP)
				return -1;
		}
	}

	//2.
	//判断是不是mov指令
	if (strcmp(insn.mnemonic, "mov") == 0)
		return(_mov());
	//判断是不是add指令
	if (strcmp(insn.mnemonic, "add") == 0)
		return(_add());
	//判断是不是sub指令
	if (strcmp(insn.mnemonic, "sub") == 0)
		return(_sub());
	//判断是不是xor指令
	if (strcmp(insn.mnemonic, "xor") == 0)
		return(_xor());
	//判断是不是and指令
	if (strcmp(insn.mnemonic, "and") == 0)
		return(_and());
	//判断是不是or指令
	if (strcmp(insn.mnemonic, "or") == 0)
		return(_or());
	//判断是不是rcl指令
	if (strcmp(insn.mnemonic, "rcl") == 0)
		return(_rcl());
	//判断是不是rcr指令
	if (strcmp(insn.mnemonic, "rcr") == 0)
		return(_rcr());
	//判断是不是lea指令
	if (strcmp(insn.mnemonic, "lea") == 0)
		return(_lea());
	//判断是不是cmp指令
	if (strcmp(insn.mnemonic, "cmp") == 0)
		return(_cmp());
	//判断是不是test指令
	if (strcmp(insn.mnemonic, "test") == 0)
		return(_test());
	//判断是不是push指令
	if (strcmp(insn.mnemonic, "push") == 0)
		return(_push());
	//判断是不是pop指令
	if (strcmp(insn.mnemonic, "pop") == 0)
		return(_pop());
	//判断是不是jcc和jmp指令
	if (cs_insn_group(handle, &insn, CS_GRP_JUMP) == true)
		return(_jcc_jmp());
	if (cs_insn_group(handle, &insn, CS_GRP_CALL) == true)
		return(_call());


	return -1;
}

//处理未知的指令
UINT x86Insn_Mutation::Resolve_UnknownInsn()
{
	UINT result = -1;
	cs_x86 *x86;
	if (insn.detail == NULL)
		return result;
	x86 = &(insn.detail->x86);
	x86_mem mem = { 0 };
	x86_imm imm = { 0 };
	mem.disp_offset = x86->encoding.disp_offset;
	mem.disp_size = x86->encoding.disp_size;
	imm.imm_offset = x86->encoding.imm_offset;
	imm.imm_size = x86->encoding.imm_size;

	//1.把未知指令copy过去
	memcpy_s((void*)((size_t)Final_MutMemory + Final_CodeSize), insn.size, (void*)insn.address, insn.size);
	//2.加入CodeSection的vector
	CodeSection CS_Struct = { 0 };
	CS_Struct.Raw_CodeAddr = (DWORD)insn.address;
	CS_Struct.Mut_CodeStartAddr = (DWORD)Final_MutMemory + Final_CodeSize;
	CS_Struct.BaseAddr = objPE.m_dwImageBase + objPE.m_dwImageSize + Final_CodeSize;
	CS_Struct.Mut_CodeEndAddr = CS_Struct.Mut_CodeStartAddr + insn.size;
	CS_Struct.Mut_CodeSize = insn.size;
	code_section.push_back(CS_Struct);
	Final_CodeSize += insn.size;	
	//3.重定位处理：
	//如果该指令的mem的disp_size为4，可能有重定位
	///*
	if (mem.disp_size == 4) {
		DealWithReloc((DWORD)insn.address + mem.disp_offset, CS_Struct.BaseAddr + mem.disp_offset);
	}
	//如果imm的size为4，可能有重定位
	if (imm.imm_size == 4) {
		DealWithReloc((DWORD)insn.address + imm.imm_offset, CS_Struct.BaseAddr + imm.imm_offset);
	}
	//*/
	return true;
}

//将单行指令的变异代码重定位后写到Final空间，并填写CodeSection结构体
UINT x86Insn_Mutation::Copy_MutCodes_to_FinalMem()
{
	Mut_Code.flatten();
	Mut_Code.resolveUnresolvedLinks();
	CodeSection CS_Struct = { 0 };
	//1.填写原指令地址
	CS_Struct.Raw_CodeAddr = (DWORD)insn.address;
	//1.1填写变异代码起始地址
	CS_Struct.Mut_CodeStartAddr = (DWORD)Final_MutMemory + Final_CodeSize;
	//1.2填写重定位基地址（原区段基地址+已生成的总变异代码大小）
	CS_Struct.BaseAddr = objPE.m_dwImageBase + objPE.m_dwImageSize + Final_CodeSize;
	//1.3进行重定位
	Mut_Code.relocateToBase((uint64_t)CS_Struct.BaseAddr);
	//1.4填写变异代码块大小（重定位后再取CodeSize，CodeSize可能在重定位后变化）
	CS_Struct.Mut_CodeSize = Mut_Code.codeSize();					
	//1.5填写变异代码块尾部（下一个变异代码块的起始处）
	CS_Struct.Mut_CodeEndAddr = CS_Struct.Mut_CodeStartAddr + CS_Struct.Mut_CodeSize;
	//1.6将结构体写进vector
	code_section.push_back(CS_Struct);


	//2.分析Final空间够不够装下这个变异指令
	FinalRemainMem_Size -= CS_Struct.Mut_CodeSize;
	if (FinalRemainMem_Size < 0)
	{
		//创建2倍大小的空间并将原空间代码copy过来
		void* temp = Final_MutMemory;
		size_t temp_size = FinalMem_Size;
		FinalMem_Size *= 2;
		Final_MutMemory = VirtualAlloc(NULL, FinalMem_Size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (Final_MutMemory == NULL)
			MessageBox(NULL, _T("Final_MutMemory申请空间失败"), NULL, NULL);
		memcpy_s(Final_MutMemory, FinalMem_Size, temp, temp_size);
		VirtualFree(temp, 0, MEM_DECOMMIT);
	}
	//3.将变异代码写到Final空间
	Mut_Code.copyFlattenedData((void*)CS_Struct.Mut_CodeStartAddr, CS_Struct.Mut_CodeSize, CodeHolder::kCopyWithPadding);
	//3.1更新Final_CodeSize
	Final_CodeSize += CS_Struct.Mut_CodeSize;
	
	return true;
}







//寻找Mutation保护标志
UINT Mutation::Find_MutationMark(LPBYTE pFinalBuf, DWORD size, OUT vector<Mark> *_Out_Mark)
{
	Mark Mark_Struct = {0};
	UINT Mark_Sum = 0;
	LPBYTE Start_Addr = 0, End_Addr = 0;
	if (pFinalBuf == NULL) {
		MessageBox(NULL, _T("pFinalBuf缓冲区异常！"), NULL, NULL);
		return 0;
	}
	for (DWORD Offset = 0; size - Offset > 0 ; Offset = End_Addr - pFinalBuf + 1)
	{
		Start_Addr = Find_MemoryString(pFinalBuf + Offset, size - Offset, (LPBYTE)Mutation_Start);
		End_Addr = Find_MemoryString(pFinalBuf + Offset, size - Offset, (LPBYTE)Mutation_End);
		if (Start_Addr == NULL || End_Addr == NULL) {
			return Mark_Sum;
		}
		if (Start_Addr > End_Addr) {
			MessageBox(NULL, _T("发现错误的SDK！请检查SDK标志"), NULL, NULL);
			return Mark_Sum;
		}
		Mark_Struct.Start = Start_Addr;
		Mark_Struct.End = End_Addr;
		_Out_Mark->push_back(Mark_Struct);
		Mut_Mark.push_back(Mark_Struct);
		Mark_Sum++;
	}
	return Mark_Sum;
}
//jmp连接首尾。 1 = Start, 0 = End
void Mutation::link_jmp(int flag, x86Insn_Mutation& code, CPE& objPE, LPBYTE Addr)
{	//只要知道其中一个地址和偏移即可
	//	start_link，往下跳
	if (flag == 1)
	{
		//偏移 =   整块镜像内存 - Addr + CodeSize - 5
		DWORD data = (DWORD)objPE.m_pFileBuf + objPE.m_dwImageSize - (DWORD)Addr + code.Final_CodeSize - 5;
		memcpy_s(Addr, 1, "\xE9", 1);
		memcpy_s(Addr + 1, 4, &data, 4);
	}
	else
	//	end_link，往上跳。由于添加了代码，还要修改一些成员变量
	{
		//偏移 = -(整块镜像内存 - Addr + CodeSize) - 5
		DWORD data = (DWORD)Addr - (DWORD)objPE.m_pFileBuf - objPE.m_dwImageSize - code.Final_CodeSize - 5;
		memcpy_s((void*)((size_t)code.Final_MutMemory + code.Final_CodeSize), 1, "\xE9", 1);
		memcpy_s((void*)((size_t)code.Final_MutMemory + code.Final_CodeSize + 1), 4, &data, 4);
		code.FinalRemainMem_Size -= 5;
		code.Final_CodeSize += 5;
	}
}
//清除原代码
void Mutation::ClearCode(LPBYTE Start_Addr, LPBYTE End_Addr)
{
	size_t size = End_Addr - Start_Addr;
	memset(Start_Addr,0,size);
}
//保存至文件
BOOL Mutation::SaveFinalFile(LPBYTE pFinalBuf, DWORD pFinalBufSize, CString strFilePath)
{
	//修正区段信息中 文件对齐大小（文件对齐大小同内存对齐大小）
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFinalBuf;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(pFinalBuf + pDosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
	for (DWORD i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++, pSectionHeader++)
	{
		pSectionHeader->PointerToRawData = pSectionHeader->VirtualAddress;
	}


	//获取保存路径
	TCHAR strOutputPath[MAX_PATH] = { 0 };
	LPWSTR strSuffix = PathFindExtension(strFilePath);
	wcsncpy_s(strOutputPath, MAX_PATH, strFilePath, wcslen(strFilePath));
	PathRemoveExtension(strOutputPath);
	wcscat_s(strOutputPath, MAX_PATH, L"_Mut");
	wcscat_s(strOutputPath, MAX_PATH, strSuffix);

	//保存文件
	HANDLE hNewFile = CreateFile(
		strOutputPath,
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hNewFile == INVALID_HANDLE_VALUE)
	{
		MessageBox(NULL, _T("保存文件失败！"), _T("提示"), MB_OK);
		return FALSE;
	}
	DWORD WriteSize = 0;
	BOOL bRes = WriteFile(hNewFile, pFinalBuf, pFinalBufSize, &WriteSize, NULL);
	if (bRes)
	{
		CloseHandle(hNewFile);
		return TRUE;
	}
	else
	{
		CloseHandle(hNewFile);
		MessageBox(NULL, _T("保存文件失败！"), _T("提示"), MB_OK);
		return FALSE;
	}
}


UINT x86Insn_Mutation::reloc()
{
	if (cs_insn_group(handle, &insn, CS_GRP_CALL) == true)
	{

	}
	if (cs_insn_group(handle, &insn, CS_GRP_JUMP) == true)
	{

	}
	return 0;
}

