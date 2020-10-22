#pragma once
#include <vector>
using namespace std;

class CPE
{
public:
	CPE();
	~CPE();
public:
	HANDLE					m_hFile;			//PE文件句柄
	LPBYTE					m_pFileBuf;			//PE文件缓冲区
	DWORD					m_dwFileSize;		//文件大小
	DWORD					m_dwImageSize;		//镜像大小
	PIMAGE_DOS_HEADER		m_pDosHeader;		//Dos头
	PIMAGE_NT_HEADERS		m_pNtHeader;		//NT头
	PIMAGE_SECTION_HEADER	m_pSecHeader;		//第一个SECTION结构体指针
	DWORD					m_dwImageBase;		//镜像基址
	DWORD					m_dwCodeBase;		//代码基址
	DWORD					m_dwCodeSize;		//代码大小
	DWORD					m_dwPEOEP;			//OEP地址
	DWORD					m_dwShellOEP;		//新OEP地址
	DWORD					m_dwSizeOfHeader;	//文件头大小
	DWORD					m_dwSectionNum;		//区段数量

	DWORD					m_dwFileAlign;		//文件对齐
	DWORD					m_dwMemAlign;		//内存对齐

	DWORD					m_IATSectionBase;	//IAT所在段基址
	DWORD					m_IATSectionSize;	//IAT所在段大小

	IMAGE_DATA_DIRECTORY	m_PERelocDir;		//重定位表信息
	IMAGE_DATA_DIRECTORY	m_PEImportDir;		//导入表信息

	typedef struct _TYPEOFFSET
	{
		WORD offset : 12;						//偏移值
		WORD Type : 4;							//重定位属性(方式)
	}TYPEOFFSET, *PTYPEOFFSET;
	typedef struct _RelocData
	{
		DWORD RelocAddr;						//被重定位数据在内存中的地址
		DWORD Offset;							//被重定位数据的偏移值	（注意是数据的偏移值）
	} RelocData, *PRelocData;
	vector<RelocData> m_RelocData;


public:
	BOOL InitPE(CString strFilePath);			//初始化PE，读取PE文件，保存PE信息
	void InitValue();							//初始化变量
	BOOL OpenPEFile(CString strFilePath);		//打开文件
	BOOL IsPE();								//判断是否为PE文件
	void GetPEInfo();							//获取PE信息
	

	void MergeBuf(LPBYTE pFileBuf, DWORD pFileBufSize, 
		LPBYTE pShellBuf, DWORD pShellBufSize, 
		LPBYTE& pFinalBuf, DWORD& pFinalBufSize);
												//合并PE文件和Shell

	void AddSize_RelocSection();

	void Find_reloc();							//搜集需要reloc的数据的内存地址及其数据本身的偏移值

	//DWORD Raw_RelocDirsize;						//初始值为原始的重定位表大小
	BOOL Add_DataToRelocDir(WORD added_offset, DWORD added_VA);
};

