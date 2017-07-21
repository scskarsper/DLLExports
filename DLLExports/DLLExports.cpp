// DLL2Headers.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#pragma comment(lib,"imagehlp")
#include <stdio.h>
#include <windows.h>
#include <DbgHelp.h>
#include <map>
#include <string>
using namespace std;
typedef map<string,FILE*> fmap;

bool GetDLLFileExports(TCHAR *szFileName, UINT *nNoOfExports, char **&pszFunctions, DWORD*& Addr)
{
    HANDLE hFile;
    HANDLE hFileMapping;
    LPVOID lpFileBase;
    PIMAGE_DOS_HEADER pImg_DOS_Header;
    PIMAGE_NT_HEADERS pImg_NT_Header;
    PIMAGE_EXPORT_DIRECTORY pImg_Export_Dir;

    hFile = CreateFile(szFileName, GENERIC_READ, FILE_SHARE_READ,
            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if(hFile == INVALID_HANDLE_VALUE)
        return false;

    hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if(hFileMapping == 0)
    {
        CloseHandle(hFile);
        return false;
    }

    lpFileBase = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
    if(lpFileBase == 0)
    {
        CloseHandle(hFileMapping);
        CloseHandle(hFile);
        return false;
    }

    pImg_DOS_Header = (PIMAGE_DOS_HEADER)lpFileBase;
    pImg_NT_Header = (PIMAGE_NT_HEADERS)(
            (LONG)pImg_DOS_Header + (LONG)pImg_DOS_Header->e_lfanew);

    if(IsBadReadPtr(pImg_NT_Header, sizeof(IMAGE_NT_HEADERS))
            || pImg_NT_Header->Signature != IMAGE_NT_SIGNATURE)
    {
    UnmapViewOfFile(lpFileBase);
    CloseHandle(hFileMapping);
    CloseHandle(hFile);
    return false;
    }

    pImg_Export_Dir = (PIMAGE_EXPORT_DIRECTORY)pImg_NT_Header->OptionalHeader
            .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if(!pImg_Export_Dir)
    {
    UnmapViewOfFile(lpFileBase);
    CloseHandle(hFileMapping);
    CloseHandle(hFile);
    return false;
    }
    pImg_Export_Dir= (PIMAGE_EXPORT_DIRECTORY)ImageRvaToVa(pImg_NT_Header,
            pImg_DOS_Header, (DWORD)pImg_Export_Dir, 0);

    DWORD **ppdwNames = (DWORD **)pImg_Export_Dir->AddressOfNames;
    PDWORD pFun = (PDWORD)ImageRvaToVa(pImg_NT_Header, pImg_DOS_Header,pImg_Export_Dir->AddressOfFunctions, 0);
	PWORD pOrdFun = (PWORD)ImageRvaToVa(pImg_NT_Header, pImg_DOS_Header,pImg_Export_Dir->AddressOfNameOrdinals, 0);

    ppdwNames = (PDWORD*)ImageRvaToVa(pImg_NT_Header,
            pImg_DOS_Header, (DWORD)ppdwNames, 0);
    if(!ppdwNames)
    {
        UnmapViewOfFile(lpFileBase);
        CloseHandle(hFileMapping);
        CloseHandle(hFile);
        return false;
    }

    *nNoOfExports = pImg_Export_Dir->NumberOfFunctions;
    pszFunctions = new char*[*nNoOfExports];
	DWORD* Addrs=(DWORD*)malloc(sizeof(DWORD)**nNoOfExports);
	Addr=Addrs;
    for(UINT i=0; i < *nNoOfExports; i++)
    {
		DWORD pFunPoint = *(pFun + i);
		Addrs[i]=pFunPoint;
        char *szFunc=(PSTR)ImageRvaToVa(pImg_NT_Header, pImg_DOS_Header, (DWORD)*ppdwNames, 0);

        pszFunctions[i] = new char[strlen(szFunc)+1];
        strcpy_s(pszFunctions[i],strlen(szFunc)+1,szFunc);

        ppdwNames++;
    }
    UnmapViewOfFile(lpFileBase);
    CloseHandle(hFileMapping);
    CloseHandle(hFile);
    return true;
}

char* DecodeSymbolName(char* code)
{
	char dsn[1024];
	if (0==UnDecorateSymbolName(code,dsn,1024,UNDNAME_COMPLETE)) {
		return code;
    } else {
		char* tmpc=(char*)malloc(1+sizeof(char)*strlen(dsn));
		strcpy_s(tmpc,1+sizeof(char)*strlen(dsn),dsn);
		return tmpc;
    }
}

void Usage()
{
	TCHAR chBuf[0x8000]={0};  
   // 将当前路径\dll路径添加到本进程的路径中  
   if(!GetModuleFileName(NULL,chBuf,MAX_PATH))  
       return;  
   TCHAR* EFile=_tcsrchr(chBuf,'\\');
   if(EFile==NULL)return;
   EFile++;
   printf("Balthasar Toolboxes Version 1.0.0.0\n");
   printf("Copyright (C) RCAWorks Studio(Balthasar). All rights reserved.\n\n");
   printf("Usage: %S [DLLFile]\n",EFile);
   printf("\tDLLFile\tThe Dll file for decode into lib.\n");
   printf("The output file is dll's name with \".export.lib\" , \".export.def\" , \".export.h\" , \".export.csv\"\n");
}
BOOL contentKey(fmap Map,string Key)
{
	fmap::iterator l_it;
	l_it=Map.find(Key);
	if(l_it==Map.end()) return FALSE;
	return TRUE;
}
int _tmain(int argc, _TCHAR* argv[])
{
	
	TCHAR CurrentPath[0x8000]={0};  
   // 将当前路径\dll路径添加到本进程的路径中  
   if(!GetModuleFileName(NULL,CurrentPath,MAX_PATH))  
       return 0;  
   *_tcsrchr(CurrentPath,'\\')=0;

	TCHAR LibPath[0x8000]={0};
	_tcscpy_s(LibPath,0x8000,CurrentPath);
	_tcscat_s(LibPath,0x8000,L"\\lib.exe");
	
	if(_taccess_s(LibPath,0)!=0)
	{
		printf("Cannot find the library linker:Lib.exe , please copy and leave it in the same directory of this file.\n");
		return 0;
	}
	if(argc==1)
	{
		Usage();
		return 0;
	}
	TCHAR* DllPath=argv[1];
	if(DllPath[1]!=':' || _waccess(DllPath,0)!=0 || _waccess(DllPath,6)!=0)
	{
		TCHAR CurrentUrl[0x8000]={0}; 
		_tcscpy_s(CurrentUrl,0x8000,CurrentPath);
		_tcscat_s(CurrentUrl,0x8000,L"\\");
		_tcscat_s(CurrentUrl,0x8000,argv[1]);
		DllPath=CurrentUrl;
	}
	TCHAR* DllName=NULL;
	TCHAR DllHead[MAX_PATH];
	TCHAR DllDir[MAX_PATH]=L"";
	TCHAR ClassHTemp[MAX_PATH]=L"";
	TCHAR HeaderFile[MAX_PATH]=L"";
	TCHAR LibFile[MAX_PATH]=L"";
	TCHAR CSVFile[MAX_PATH]=L"";
	TCHAR DefFile[MAX_PATH]=L"";
	TCHAR CFile[MAX_PATH]=L"";
	fmap ClassHeaders;
	if(_waccess(DllPath,0)!=0 || _waccess(DllPath,6)!=0)
	{
		printf("Cannot open the file %S.\n",DllPath);
		return 0;
	}
	_tcscpy_s(DllHead,MAX_PATH,DllPath);
   *_tcsrchr(DllHead,'.')=0;
   DllName=_tcsrchr(DllHead,'\\');
   if(DllName==NULL)DllName=DllPath;else DllName++;
    _tcscat_s(DllDir,MAX_PATH,DllHead);
    _tcscat_s(DllDir,MAX_PATH,L".exports");
   _tmkdir(DllDir);
    _tcscat_s(HeaderFile,MAX_PATH,DllHead);
    _tcscat_s(HeaderFile,MAX_PATH,L".exports\\");
	_tcscat_s(HeaderFile,MAX_PATH,DllName);
    _tcscat_s(HeaderFile,MAX_PATH,L".h");
    _tcscat_s(LibFile,MAX_PATH,DllHead);
    _tcscat_s(LibFile,MAX_PATH,L".exports\\");
	_tcscat_s(LibFile,MAX_PATH,DllName);
    _tcscat_s(LibFile,MAX_PATH,L".lib");
    _tcscat_s(CSVFile,MAX_PATH,DllHead);
    _tcscat_s(CSVFile,MAX_PATH,L".exports\\");
	_tcscat_s(CSVFile,MAX_PATH,DllName);
    _tcscat_s(CSVFile,MAX_PATH,L".csv");
    _tcscat_s(DefFile,MAX_PATH,DllHead);
    _tcscat_s(DefFile,MAX_PATH,L".exports\\");
	_tcscat_s(DefFile,MAX_PATH,DllName);
    _tcscat_s(DefFile,MAX_PATH,L".def");
    _tcscat_s(CFile,MAX_PATH,DllHead);
    _tcscat_s(CFile,MAX_PATH,L".exports\\");
	_tcscat_s(CFile,MAX_PATH,DllName);
    _tcscat_s(CFile,MAX_PATH,L".c");

    printf("Balthasar Toolboxes Version 1.0.0.0\n");
    printf("Copyright (C) RCAWorks Studio(Balthasar). All rights reserved.\n\n");
	printf("Input:\n");
	printf("\tDllFile: %S\n",DllPath);
	printf("Output:\n");
	printf("\tHeader:  %S\n",HeaderFile);
	printf("\tCFile:   %S\n",CFile);
	printf("\tLibFile: %S\n",LibFile);
	printf("\tCSVMap:  %S\n",CSVFile);
	printf("\tDefine:  %S\n",DefFile);
    UINT unNoOfExports;
    char **lppBuffer;
    DWORD *lppAddr=NULL;

	FILE* hFile;
	FILE* csvFile;
	FILE* defFile;
	FILE* cFile;
	_wfopen_s(&hFile,HeaderFile,L"w");
	_wfopen_s(&cFile,CFile,L"w");
	_wfopen_s(&csvFile,CSVFile,L"w");
	_wfopen_s(&defFile,DefFile,L"w");
    GetDLLFileExports(DllPath, &unNoOfExports, lppBuffer,lppAddr);
	
	fprintf_s(csvFile,"\"%s\",\"%s\",\"%s\",\"%s\"\n","HINT","RVAddress","FunctionDeclare","FunExportSymbol");
    fprintf_s(defFile,"LIBRARY %S \nEXPORTS\n",DllName);
	BOOL haveNoClass=FALSE;
    for(UINT i=0; i<unNoOfExports; i++)
	{
		char* Symbol=lppBuffer[i];
		if(Symbol[0]!='?')
		{
			haveNoClass=TRUE;
		}
	}
	fprintf_s(cFile,"#include \"%S.exports.h\"\n",DllName);
	if(haveNoClass)
	{
			printf("\nAnalysis:  Find Cdecl Exports,Creating Dynamic Mapper in HeaderFile:%S.h\n",DllName);
			printf("Analysis:  Find Cdecl Exports,Creating Dynamic Code in CppFile:%S.c\n",DllName);
			fprintf_s(hFile,"class %S\n{\nprivate:\n\tHMODULE handle;\npublic:\n\t%S(void);\n\t~%S(void);\n",DllName,DllName,DllName);
			fprintf_s(cFile,"%S::~%S(void)\n{\n\tif(handle!=NULL)FreeLibrary(handle);\n}\n\n",DllName,DllName);
			fprintf_s(cFile,"%S::%S(void)\n{\n\thandle=LoadLibrary(_T(\"%S.dll\"));\n",DllName,DllName,DllName);
	}
    for(UINT i=0; i<unNoOfExports; i++)
	{
		char* Symbol=lppBuffer[i];
		char* DeSymbol=DecodeSymbolName(Symbol);
		UINT hint=i;
		DWORD FAddr=lppAddr[i];
		fprintf_s(csvFile,"\"%X\",\"%08X\",\"%s\",\"%s\"\n",hint,FAddr,DeSymbol,Symbol);
		if(Symbol[0]=='?')
		{
			//isClass
			char Tmp[0x8000]="";
			strcpy_s(Tmp,0x8000,DeSymbol);
			char* kh=strchr(Tmp,'(');
			if(kh!=NULL)*kh=0;
			char* TmpRev=_strrev(Tmp);
			char* classptr=strstr(TmpRev,"::");
			char* classname;
			if(classptr==NULL)
			{
				classname="default";
			}else
			{
				char* RRev2=classptr+2;
				RRev2=_strrev(RRev2);
				classname=strrchr(Tmp,' ');
				if(classname==NULL)
				{
					classname="default";
				}else
				{
					classname++;
				}
			}
			char* classptr2=strstr(classname,"::");
			if(classptr2!=NULL)*classptr2=0;
			string classKey=classname;
			if(!contentKey(ClassHeaders,classKey))
			{
				printf("Analysis:  Find Class Exports,Creating HeaderFile: ClassHeaders\\%S.%s.h\n",DllName,classKey.c_str());
				FILE* TFile;
				wsprintf(ClassHTemp,L"%s\\ClassHeaders",DllDir);
				_tmkdir(ClassHTemp);
				wsprintf(ClassHTemp,L"%s\\ClassHeaders\\%s.%S.h",DllDir,DllName,classname);
				_wfopen_s(&TFile,ClassHTemp,L"w");
				ClassHeaders.insert(pair<string,FILE*>(classKey,TFile));
			}
			FILE* TFile=ClassHeaders[classKey];
			fprintf_s(TFile,"%s\n",DeSymbol);
		}else
		{
			fprintf_s(hFile,"\tPVOID %s;\n",Symbol);
			fprintf_s(cFile,"\t%s=GetProcAddress(handle, \"%s\");\n",Symbol,Symbol);
		}
	    fprintf_s(defFile,"\t%s @%d\n",Symbol,hint+1);
	}
	if(haveNoClass)
	{
		fprintf_s(hFile,"};\n");
		fprintf_s(cFile,"}\n");
	}
	fclose(hFile);
	char buf[0x8000];
	_wfopen_s(&hFile,HeaderFile,L"r");
	fseek(hFile,0,SEEK_END);
	long size=ftell(hFile);
	char* btmp=(char*)malloc(sizeof(char)*size);
	memset(btmp,0,sizeof(char)*size);
	fseek(hFile,0,SEEK_SET);
	//fread_s(btmp,sizeof(char)*size,sizeof(char),size,hFile);
	while(fgets(buf,0x8000,hFile))
	{
		strcat_s(btmp,sizeof(char)*size,buf);
	};
	fclose(hFile);
	_wfopen_s(&hFile,HeaderFile,L"w");
	fseek(hFile,0,SEEK_SET);
	fprintf_s(hFile,"#pragma once\n#include <windows.h>\n");
	fmap::iterator iter;
	if(!ClassHeaders.empty())
	{
		fprintf_s(hFile,"#pragma comment(lib,\"%S.exports.lib\")\n",DllName);
	}
	for (iter=ClassHeaders.begin();iter!=ClassHeaders.end();++iter)
	{
		fprintf_s(hFile,"#include \"ClassHeaders\\%S.%s.h\"\n",DllName,iter->first.c_str());
		fclose(iter->second);
	}
	
	if(size>0)fprintf_s(hFile,"%s",btmp);
	free(btmp);
	fclose(hFile);
	fclose(csvFile);
	fclose(defFile);
	TCHAR CMD[MAX_PATH*3];
	wsprintf(CMD,L"/def:\"%s\" /machine:%s /out:\"%s\"",DefFile,L"i386",LibFile);
	ShellExecute(0,L"open",LibPath,CMD,CurrentPath,0);
	return 0;
}
