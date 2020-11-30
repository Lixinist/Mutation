#include "pch.h"
#include "PE.h"



CPE::CPE()
{
	InitValue();
}


CPE::~CPE()
{
}

//************************************************************
// 函数名称:	InitValue
// 函数说明:	初始化变量
// 作	者:	cyxvc
// 时	间:	2015/12/25
// 返 回	值:	void
//************************************************************
void CPE::InitValue()
{
	m_hFile				= NULL;
	m_pFileBuf			= NULL;
	m_pDosHeader		= NULL;
	m_pNtHeader			= NULL;
	m_pSecHeader		= NULL;
	m_dwFileSize		= 0;
	m_dwImageSize		= 0;
	m_dwImageBase		= 0;
	m_dwCodeBase		= 0;
	m_dwCodeSize		= 0;
	m_dwPEOEP			= 0;
	m_dwShellOEP		= 0;
	m_dwSizeOfHeader	= 0;
	m_dwSectionNum		= 0;
	m_dwFileAlign		= 0;
	m_dwMemAlign		= 0;
	m_PERelocDir		= { 0 };
	m_PEImportDir		= { 0 };
	m_IATSectionBase	= 0;
	m_IATSectionSize	= 0;

	//Raw_RelocDirsize	= 0;
}

//************************************************************
// 函数名称:	InitPE
// 函数说明:	初始化PE，读取PE文件，保存PE信息
// 作	者:	cyxvc
// 时	间:	2015/12/25
// 参	数:	CString strFilePath
// 返 回	值:	BOOL
//************************************************************
BOOL CPE::InitPE(CString strFilePath)
{
	//打开文件
	if (OpenPEFile(strFilePath) == FALSE)
		return FALSE;

	//将PE以文件分布格式读取到内存
	m_dwFileSize = GetFileSize(m_hFile, NULL);

	m_pFileBuf = (LPBYTE)VirtualAlloc(NULL, m_dwFileSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	//m_pFileBuf = new BYTE[m_dwFileSize];
	DWORD ReadSize = 0;
	if (ReadFile(m_hFile, m_pFileBuf, m_dwFileSize, &ReadSize, NULL) == FALSE)
		return FALSE;
	CloseHandle(m_hFile);
	m_hFile = NULL;

	//判断是否为PE文件
	if (IsPE() == FALSE)
		return FALSE;

	//将PE以内存分布格式读取到内存
	//修正镜像大小没有对齐的情况
	m_dwImageSize = m_pNtHeader->OptionalHeader.SizeOfImage;
	m_dwMemAlign = m_pNtHeader->OptionalHeader.SectionAlignment;
	m_dwSizeOfHeader = m_pNtHeader->OptionalHeader.SizeOfHeaders;
	m_dwSectionNum = m_pNtHeader->FileHeader.NumberOfSections;

	if (m_dwImageSize % m_dwMemAlign)
		m_dwImageSize = (m_dwImageSize / m_dwMemAlign + 1) * m_dwMemAlign;
	//这里申请2倍内存是为了方便增加重定位区段大小
	LPBYTE pFileBuf_New = (LPBYTE)VirtualAlloc(NULL, m_dwImageSize * 2, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memset(pFileBuf_New, 0, m_dwImageSize * 2);
	//拷贝文件头
	memcpy_s(pFileBuf_New, m_dwSizeOfHeader, m_pFileBuf, m_dwSizeOfHeader);
	//拷贝区段
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(m_pNtHeader);
	for (DWORD i = 0; i < m_dwSectionNum; i++, pSectionHeader++)
	{
		memcpy_s(pFileBuf_New + pSectionHeader->VirtualAddress,
			pSectionHeader->SizeOfRawData,
			m_pFileBuf+pSectionHeader->PointerToRawData,
			pSectionHeader->SizeOfRawData);
	}
	VirtualFree(m_pFileBuf, 0, MEM_RELEASE);
	//delete[] m_pFileBuf;
	m_pFileBuf = pFileBuf_New;
	pFileBuf_New = NULL;
	
	//事先增加重定位区段大小
	AddSize_RelocSection();
	//获取PE信息
	GetPEInfo();
	
	return TRUE;
}

//************************************************************
// 函数名称:	OpenPEFile
// 函数说明:	打开文件
// 作	者:	cyxvc
// 时	间:	2015/12/25
// 参	数:	CString strFilePath
// 返 回	值:	BOOL
//************************************************************
BOOL CPE::OpenPEFile(CString strFilePath)
{
	m_hFile = CreateFile(strFilePath,
		GENERIC_READ | GENERIC_WRITE, 0, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (m_hFile == INVALID_HANDLE_VALUE)
	{
		MessageBox(NULL, _T("加载文件失败！"), _T("提示"), MB_OK);
		m_hFile = NULL;
		return FALSE;
	}
	return TRUE;
}

//************************************************************
// 函数名称:	IsPE
// 函数说明:	判断是否为PE文件
// 作	者:	cyxvc
// 时	间:	2015/12/25
// 返 回	值:	BOOL
//************************************************************
BOOL CPE::IsPE()
{
	//判断是否为PE文件
	m_pDosHeader = (PIMAGE_DOS_HEADER)m_pFileBuf;
	if (m_pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		//不是PE
		MessageBox(NULL, _T("不是有效的PE文件！"), _T("提示"), MB_OK);
		VirtualFree(m_pFileBuf, 0, MEM_RELEASE);
		//delete[] m_pFileBuf;
		InitValue();
		return FALSE;
	}
	m_pNtHeader = (PIMAGE_NT_HEADERS)(m_pFileBuf + m_pDosHeader->e_lfanew);
	if (m_pNtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		//不是PE文件
		MessageBox(NULL, _T("不是有效的PE文件！"), _T("提示"), MB_OK);
		VirtualFree(m_pFileBuf, 0, MEM_RELEASE);
		//delete[] m_pFileBuf;
		InitValue();
		return FALSE;
	}
	return TRUE;
}

//************************************************************
// 函数名称:	GetPEInfo
// 函数说明:	获取PE信息
// 作	者:	cyxvc
// 时	间:	2015/12/25
// 返 回	值:	void
//************************************************************
void CPE::GetPEInfo()
{
	m_pDosHeader	= (PIMAGE_DOS_HEADER)m_pFileBuf;
	m_pNtHeader		= (PIMAGE_NT_HEADERS)(m_pFileBuf + m_pDosHeader->e_lfanew);

	m_dwFileAlign	= m_pNtHeader->OptionalHeader.FileAlignment;
	m_dwMemAlign	= m_pNtHeader->OptionalHeader.SectionAlignment;
	m_dwImageBase	= m_pNtHeader->OptionalHeader.ImageBase;
	m_dwPEOEP		= m_pNtHeader->OptionalHeader.AddressOfEntryPoint;
	m_dwCodeBase	= m_pNtHeader->OptionalHeader.BaseOfCode;
	m_dwCodeSize	= m_pNtHeader->OptionalHeader.SizeOfCode;
	m_dwSizeOfHeader= m_pNtHeader->OptionalHeader.SizeOfHeaders;
	m_dwSectionNum	= m_pNtHeader->FileHeader.NumberOfSections;
	m_pSecHeader	= IMAGE_FIRST_SECTION(m_pNtHeader);
	m_dwImageSize = m_pNtHeader->OptionalHeader.SizeOfImage;
	if (m_dwImageSize % m_dwMemAlign)
		m_dwImageSize = (m_dwImageSize / m_dwMemAlign + 1) * m_dwMemAlign;
	m_pNtHeader->OptionalHeader.SizeOfImage = m_dwImageSize;

	//保存重定位目录信息
	m_PERelocDir = 
		IMAGE_DATA_DIRECTORY(m_pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);
	//搜集需要reloc的数据的内存地址及其数据本身的偏移值
	if(m_PERelocDir.VirtualAddress)
		Find_reloc();


	//保存IAT信息目录信息
	m_PEImportDir =
		IMAGE_DATA_DIRECTORY(m_pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);

	//获取IAT所在的区段的起始位置和大小（PS:PE里不是有IAT表偏移及其大小吗？）
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(m_pNtHeader);
	for (DWORD i = 0; i < m_dwSectionNum; i++, pSectionHeader++)
	{
		if (m_PEImportDir.VirtualAddress >= pSectionHeader->VirtualAddress&&
			m_PEImportDir.VirtualAddress <= pSectionHeader[1].VirtualAddress)
		{
			//保存该区段的起始地址和大小
			m_IATSectionBase = pSectionHeader->VirtualAddress;
			m_IATSectionSize = pSectionHeader[1].VirtualAddress - pSectionHeader->VirtualAddress;
			break;
		}
	}
}


//************************************************************
// 函数名称:	MergeBuf
// 函数说明:	合并PE文件和Shell
// 作	者:	cyxvc
// 时	间:	2015/12/25
// 参	数:	LPBYTE pFileBuf
// 参	数:	DWORD pFileBufSize
// 参	数:	LPBYTE pShellBuf
// 参	数:	DWORD pShellBufSize
// 参	数:	LPBYTE & pFinalBuf
// 返 回	值:	void
//************************************************************
void CPE::MergeBuf(LPBYTE pFileBuf, DWORD pFileBufSize,
	LPBYTE pShellBuf, DWORD pShellBufSize, 
	LPBYTE& pFinalBuf, DWORD& pFinalBufSize)
{
	//获取最后一个区段的信息
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuf;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(pFileBuf + pDosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
	PIMAGE_SECTION_HEADER pLastSection =
		&pSectionHeader[pNtHeader->FileHeader.NumberOfSections - 1];

	//1.修改区段数量
	pNtHeader->FileHeader.NumberOfSections += 1;

	//2.编辑区段表头结构体信息
	PIMAGE_SECTION_HEADER AddSectionHeader =
		&pSectionHeader[pNtHeader->FileHeader.NumberOfSections - 1];
	memcpy_s(AddSectionHeader->Name, 8, ".Mut", 5);

	//VOffset(1000对齐)
	DWORD dwTemp = 0;
	dwTemp = (pLastSection->Misc.VirtualSize / m_dwMemAlign) * m_dwMemAlign;
	if (pLastSection->Misc.VirtualSize % m_dwMemAlign)
	{
		dwTemp += 0x1000;
	}
	AddSectionHeader->VirtualAddress = pLastSection->VirtualAddress + dwTemp;

	//Vsize（实际添加的大小）
	AddSectionHeader->Misc.VirtualSize = pShellBufSize;

	//ROffset（旧文件的末尾）
	AddSectionHeader->PointerToRawData = pFileBufSize;

	//RSize(200对齐)
	dwTemp = (pShellBufSize / m_dwFileAlign) * m_dwFileAlign;
	if (pShellBufSize % m_dwFileAlign)
	{
		dwTemp += m_dwFileAlign;
	}
	AddSectionHeader->SizeOfRawData = dwTemp;

	//标志
	AddSectionHeader->Characteristics = 0XE0000040;

	//3.修改PE头文件大小属性，增加文件大小
	dwTemp = (pShellBufSize / m_dwMemAlign) * m_dwMemAlign;
	if (pShellBufSize % m_dwMemAlign)
	{
		dwTemp += m_dwMemAlign;
	}
	pNtHeader->OptionalHeader.SizeOfImage += dwTemp;


	//4.申请合并所需要的空间
	pFinalBuf = (LPBYTE)VirtualAlloc(NULL, pFileBufSize + dwTemp, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	//pFinalBuf = new BYTE[pFileBufSize + dwTemp];
	pFinalBufSize = pFileBufSize + dwTemp;
	memset(pFinalBuf, 0, pFileBufSize + dwTemp);
	memcpy_s(pFinalBuf, pFileBufSize, pFileBuf, pFileBufSize);
	memcpy_s(pFinalBuf + pFileBufSize, dwTemp, pShellBuf, dwTemp);
}


//搜集需要reloc的数据的内存地址及其数据本身的偏移值
void CPE::Find_reloc()
{
	//1.获取重定位表结构体指针
	PIMAGE_BASE_RELOCATION	pPEReloc =
		(PIMAGE_BASE_RELOCATION)(m_pFileBuf + m_PERelocDir.VirtualAddress);

	//2.开始重定位
	while (pPEReloc->VirtualAddress)
	{
		//
		PTYPEOFFSET pTypeOffset = (PTYPEOFFSET)(pPEReloc + 1);
		DWORD dwNumber = (pPEReloc->SizeOfBlock - 8) / 2;
		for (DWORD i = 0; i < dwNumber; i++)
		{
			if (*(PWORD)(&pTypeOffset[i]) == NULL)
				continue;
			//被重定位数据的偏移地址（相对基地址
			DWORD dwRVA = pTypeOffset[i].offset + pPEReloc->VirtualAddress;
			//被重定位数据的内存地址
			DWORD Addr = (DWORD)m_pFileBuf + dwRVA;
			//被重定位数据
			DWORD DataOfNeedReloc = *(PDWORD)((DWORD)m_pFileBuf + dwRVA);
			//DataOfNeedReloc = DataOfNeedReloc - m_dwImageBase + (DWORD)m_pFileBuf;
			//被重定位数据的偏移值
			DWORD OffsetData = DataOfNeedReloc - m_dwImageBase;
			
			
			//写入成员
			RelocData RelocData_Struct = { 0 };
			RelocData_Struct.RelocAddr = Addr;
			RelocData_Struct.Offset = OffsetData;
			m_RelocData.push_back(RelocData_Struct);
		}
		//2.4下一个区段
		pPEReloc = (PIMAGE_BASE_RELOCATION)((DWORD)pPEReloc + pPEReloc->SizeOfBlock);
	}
}


BOOL CPE::Add_DataToRelocDir(WORD added_offset, DWORD added_VA)
{
	//这个函数写的还有些问题：
	//1.重定位的添加写的很粗暴，导致aslr会失效。2.在极端情况下reloc可能溢出覆盖后面的区段，存在不稳定情况
	bool flag = 1;
	//判断是否有重定位表
	if (m_PERelocDir.VirtualAddress)
	{
		//1.获取重定位表结构体指针
		PIMAGE_BASE_RELOCATION	pPEReloc =
			(PIMAGE_BASE_RELOCATION)(m_pFileBuf + m_PERelocDir.VirtualAddress);

		//2.修改重定位表的Size成员
		m_pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size += 1 * sizeof(WORD) + 8;
		m_PERelocDir.Size += 1 * sizeof(WORD) + 8;
		/*
		//2.1判断要不要扩大重定位区段的空间（virtual size）
		PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(m_pNtHeader);
		for (DWORD i = 0; i < m_pNtHeader->FileHeader.NumberOfSections; i++, pSectionHeader++)
		{	//如果当前区段是重定位区段
			if (pSectionHeader->VirtualAddress == m_PERelocDir.VirtualAddress) {
				//求出VirtualSize的内存对齐大小
				DWORD dwTemp = 0;
				dwTemp = (pSectionHeader->Misc.VirtualSize / m_dwMemAlign) * m_dwMemAlign;
				if (pSectionHeader->Misc.VirtualSize % m_dwMemAlign)
				{
					//dwTemp += 0x1000;
					dwTemp += m_dwMemAlign;
				}
				//重定位表.size已经超过了重定位区段空间.virtual size的对齐大小
				if (m_PERelocDir.Size > dwTemp)
				{
					pSectionHeader->Misc.VirtualSize += m_dwMemAlign;
					pSectionHeader->SizeOfRawData += m_dwMemAlign;
					m_pNtHeader->OptionalHeader.SizeOfImage += m_dwMemAlign;
					m_dwImageSize += m_dwMemAlign;
				}
			}
		}
		*/
		//3.获取每个重定位块，让pPEReloc走到终点
		while (pPEReloc->VirtualAddress)
			//3.1下一个区段
			pPEReloc = (PIMAGE_BASE_RELOCATION)((DWORD)pPEReloc + pPEReloc->SizeOfBlock);
		//3.2创建新重定位块
		pPEReloc->VirtualAddress = added_VA;
		pPEReloc->SizeOfBlock = 1 * sizeof(WORD) + 8;
		//3.3写入block
		PTYPEOFFSET pTypeOffset = (PTYPEOFFSET)(pPEReloc + 1);
		*(PWORD)(&pTypeOffset[0]) = 0x3000 + added_offset;
	}
	else
		flag = 0;
	
	return flag;
}


void CPE::AddSize_RelocSection()
{
	m_pDosHeader = (PIMAGE_DOS_HEADER)m_pFileBuf;
	m_pNtHeader = (PIMAGE_NT_HEADERS)(m_pFileBuf + m_pDosHeader->e_lfanew);
	m_PERelocDir =
		IMAGE_DATA_DIRECTORY(m_pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(m_pNtHeader);
	

	m_pNtHeader->OptionalHeader.SizeOfImage = 0x1000;
	for (DWORD i = 0; i < m_dwSectionNum; i++, pSectionHeader++)
	{	//如果当前是重定位区段，且是最后一个区段。
		if (pSectionHeader->VirtualAddress == m_PERelocDir.VirtualAddress && i == (m_dwSectionNum - 1)) 
		{	//增加区段大小，
			pSectionHeader->Misc.VirtualSize += m_PERelocDir.Size * 0x10;
			//改Raw Size
			DWORD dwTemp = 0;
			dwTemp = (pSectionHeader->Misc.VirtualSize / m_dwMemAlign) * m_dwMemAlign;
			if (pSectionHeader->Misc.VirtualSize % m_dwMemAlign)
			{
				//dwTemp += 0x1000;
				dwTemp += m_dwMemAlign;
			}
			//pSectionHeader->SizeOfRawData = dwTemp;
		}
		//改SizeOfImage
		DWORD dwTemp = 0;
		dwTemp = (pSectionHeader->Misc.VirtualSize / m_dwMemAlign) * m_dwMemAlign;
		if (pSectionHeader->Misc.VirtualSize % m_dwMemAlign)
		{
			//dwTemp += 0x1000;
			dwTemp += m_dwMemAlign;
		}
		m_pNtHeader->OptionalHeader.SizeOfImage += dwTemp;
		//本来还要改m_dwImageSize，但是后面调用的GetPEInfo()已经对其更新了。
	}
}
