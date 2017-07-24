// DLL2Headers.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#pragma comment(lib,"imagehlp")
#include <stdio.h>
#include <windows.h>
#include <DbgHelp.h>
#include <map>
#include <list>
#include <string>

using namespace std;
typedef map<string,FILE*> fmap;
typedef list<string> flines;
typedef map<string,flines> fhrebs;

BOOL ShowDebug=FALSE;
BOOL DoClassFormat=TRUE;
BOOL UseOrdinal=FALSE;

void ClassHeaderFormater(const char* className,TCHAR* ClassTPath);
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
   printf("Usage: %S [DLLFile] [OPTIONS]\n",EFile);
   printf("\tDLLFile\tThe Dll file for decode into lib.\n");
   printf("OPTIONS:\n");
   printf("\t-d\tShow Debug Messages.\n");
   printf("\t-C\tBuild Lib File By Function Ordinals(Default is NameSymbol).\n");
   printf("\t-O\tDo not format class header to normal header.\n");
   printf("The output file is dll's name with \".export.lib\" , \".export.def\" , \".export.h\" , \".export.csv\"\n");
}
BOOL contentKey(fmap Map,string Key)
{
	fmap::iterator l_it;
	l_it=Map.find(Key);
	if(l_it==Map.end()) return FALSE;
	return TRUE;
}
BOOL IsHrebsKey(fhrebs Map,string Key)
{
	fhrebs::iterator l_it;
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

	for(int i=2;i<argc;i++)
	{
		TCHAR* OAC=argv[i];
		wstring OA=OAC;
		if(OA==L"-d")
		{
			ShowDebug=TRUE;
		}
		if(OA==L"-O")
		{
			DoClassFormat=FALSE;
		}
		if(OA==L"-C")
		{
			UseOrdinal=TRUE;
		}
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
	if(lppBuffer==NULL)
	{
		printf("Cannot Open File!\n");
		return 0;
	}
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
			
			char* kh=strchr(Tmp,'{');
			if(kh!=NULL)*kh=0;
			
			kh=strchr(Tmp,'(');
			if(kh!=NULL)*kh=0;
			
			char* k2=strrchr(Tmp,' ');
			if(k2!=NULL)k2++;
			
			while(strstr(k2,"::")==NULL && strstr(Tmp,"::")!=NULL)
			{
				if(k2!=NULL)k2--;
				*k2=0;
				k2=strrchr(Tmp,' ');
				if(k2!=NULL)k2++;
			}

			char* TmpRev=_strrev(k2);
			char* classptr=strstr(TmpRev,"::");
			char* classname;
			if(classptr==NULL)
			{
				classname="default";
			}else
			{
				char* RRev2=classptr+2;
				RRev2=_strrev(RRev2);
				classname=RRev2;
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
	    if(UseOrdinal)
		{
			fprintf_s(defFile,"\t%s @%d\n",Symbol,hint+1);
		}else
		{
			fprintf_s(defFile,"\t%s\n",Symbol);
		}
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
	//格式化Class
	fmap::iterator iter;
	if(!ClassHeaders.empty())
	{
		fprintf_s(hFile,"#pragma comment(lib,\"%S.lib\")\n",DllName);
	}
	if(DoClassFormat)
	{
		for (iter=ClassHeaders.begin();iter!=ClassHeaders.end();++iter)
		{
			fprintf_s(hFile,"#include \"ClassHeaders\\%S.%s.h\"\n",DllName,iter->first.c_str());
			fclose(iter->second);
		
			wsprintf(ClassHTemp,L"%s\\ClassHeaders\\%s.%S.h",DllDir,DllName,iter->first.c_str());
			ClassHeaderFormater(iter->first.c_str(),ClassHTemp);
		}
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


BOOL contentLine(flines lines,string Key)
{
	flines::iterator liter;
	for (liter=lines.begin();liter!=lines.end();++liter)
	{
		if(*liter==Key)
		{
			return TRUE;
		}
	}
	return FALSE;
}
void ReplaceClass(flines &addonsHeader,string &line,string Header,string Org,string Dst)
{
	int wx=line.find(Org);
	if(wx==-1)return;
	while(wx!=-1)
	{
		int wa=Org.length();
		line=line.substr(0,wx)+Dst+line.substr(wx+wa);
		wx=line.find(Org);
	}
	if(Header=="")return;
	string ok="#include <"+Header+">";
	if(!contentLine(addonsHeader,ok))
	{
		addonsHeader.push_back(ok);
	}
}
void FindClass(flines &addonsHeader,string &line,string Header,string Org)
{
	if(Header=="")return;
	int wx=line.find(Org);
	if(wx==-1)return;
	string ok="#include <"+Header+">";
	if(!contentLine(addonsHeader,ok))
	{
		addonsHeader.push_back(ok);
	}
}
void ConvertGlass(flines &addonsHeader,string &line)
{                                                         
	ReplaceClass(addonsHeader,line,"atlstr.h","class ATL::CStringT<wchar_t,class StrTraitMFC_DLL<wchar_t,class ATL::ChTraitsCRT<wchar_t> > >","CAtlStringW");
	ReplaceClass(addonsHeader,line,"atlstr.h","class ATL::CStringT<wchar_t,class StrTraitMFC_DLL<wchar_t> >","CAtlStringW");
	ReplaceClass(addonsHeader,line,"atlstr.h","class ATL::CStringT<char,class StrTraitMFC_DLL<char,class ATL::ChTraitsCRT<char> > >","CAtlStringA");
	ReplaceClass(addonsHeader,line,"atlstr.h","class ATL::CStringT<char,class StrTraitMFC_DLL<char> >","CAtlStringA");
	FindClass(addonsHeader,line,"afxtempl.h","class class CList");
	FindClass(addonsHeader,line,"vector","class std::vector");
	FindClass(addonsHeader,line,"allocators","class std::allocator");
	FindClass(addonsHeader,line,"deque","class std::deque");
	FindClass(addonsHeader,line,"list","class std::list");
	FindClass(addonsHeader,line,"map","class std::map");
	FindClass(addonsHeader,line,"sort","class std::sort");
	FindClass(addonsHeader,line,"hash_map","class std::hash_map");
	FindClass(addonsHeader,line,"hash_set","class std::hash_set");
}

void ClassHeaderFormater(const char* className,TCHAR* ClassTPath)
{
	BOOL isDefStruct=FALSE;
	if(strcmp(className,"default")==0)
	{
		isDefStruct=TRUE;
	}
	TCHAR NewPath[MAX_PATH]=_T("");
	if(_waccess_s(ClassTPath,6)==0)
	{
		wcscpy_s(NewPath,MAX_PATH,ClassTPath);
		TCHAR* dot=wcsrchr(NewPath,'.');
		if(dot!=NULL)*dot=0;
		wcscat_s(NewPath,MAX_PATH,_T(".hdef"));
		CopyFile(ClassTPath,NewPath,FALSE);
		printf("Format:  Class HeaderFile: %S\n",ClassTPath);
	}else
	{
		printf("Error:  Format Class HeaderFile: %S\n",ClassTPath);
		return;
	}
	if(_waccess_s(NewPath,6)!=0)
	{
		printf("Error:  Load Class DefHeaderFile: %S\n",NewPath);
		return;
	}
	FILE* hDef;
	_wfopen_s(&hDef,NewPath,L"r");
	if(hDef==NULL)
	{
		printf("Error:  Open Class DefHeaderFile: %S\n",NewPath);
		return;
	}
	FILE* hFile;
	_wfopen_s(&hFile,ClassTPath,L"w");
	if(hFile==NULL)
	{
		printf("Error:  Create Class HeaderFile: %S\n",ClassTPath);
		return;
	}
	flines lines;
	flines addonsHeader;
	fhrebs lhrebs;
	char linebuf[0x8000];
	while(fgets(linebuf,0x8000,hDef))
	{
		string s=linebuf;
		lines.push_back(s);
	}
	fclose(hDef);
	//lines.sort();
	
	if(isDefStruct)
	{
		fprintf_s(hFile,"#pragma once\n");
		flines::iterator liter;
		for (liter=lines.begin();liter!=lines.end();++liter)
		{
			if(ShowDebug)printf("Work for data:%s\n",(*liter).c_str());
			string line=*liter;
			char lchar=line.c_str()[line.length()-1];
			if(lchar=='\n')
			{
				line=line.substr(0,line.length()-1)+";\n";
			}
			fprintf_s(hFile,"%s",line.c_str());
		}
	}
	else
	{
		flines::iterator liter;
		for (liter=lines.begin();liter!=lines.end();++liter)
		{
			if(ShowDebug)printf("Work for data:%s\n",(*liter).c_str());
			string line=*liter;
			int x=line.find(':');
			string inhrebs=line.substr(0,x);
			if(inhrebs=="protected" || inhrebs=="public" || inhrebs=="private")
			{
				line=line.substr(inhrebs.length()+1);
				if(line.substr(0,1)==" ")
				{
					line=line.substr(1);
				}
			}else
			{
				inhrebs="default";
			}
			//删除thiscall
			int w=line.find("__thiscall ");//len=11
			if(w>-1)
			{
				line=line.substr(0,w)+line.substr(w+11);
			}
			//删除类名
			string oc=className;
			oc=oc+"::";
			w=line.find(oc);
			if(w>-1)
			{
				line=line.substr(0,w)+line.substr(w+oc.length());
			}
			//删除无效修饰
			if(line.find("const `vftable'")!=-1)continue;
			if(line.find("default constructor closure")!=-1)continue;
			char tap[0x8000]="";
			sprintf_s(tap,0x8000,"operator=(class %s const",className);
			if(line.find(tap)!=-1)continue;
			//添加结束符
			char lchar=line.c_str()[line.length()-1];
			if(lchar=='\n')
			{
				line=line.substr(0,line.length()-1)+";\n";
			}
			ConvertGlass(addonsHeader,line);

			if(!IsHrebsKey(lhrebs,inhrebs))
			{
				flines tlines;
				lhrebs.insert(pair<string,flines>(inhrebs,tlines));
			}
			lhrebs[inhrebs].push_back(line);
		}
	
		fprintf_s(hFile,"#pragma once\n");
		for (liter=addonsHeader.begin();liter!=addonsHeader.end();++liter)
		{
			fprintf_s(hFile,"%s\n",(*liter).c_str());
		}
		fprintf_s(hFile,"class __declspec(dllimport) %s\n{\n",className);
		if(IsHrebsKey(lhrebs,"default"))
		{
			for (liter=lhrebs["default"].begin();liter!=lhrebs["default"].end();++liter)
			{
				fprintf_s(hFile,"\t%s",(*liter).c_str());
			}
		}
		fhrebs::iterator hiter;
		for (hiter=lhrebs.begin();hiter!=lhrebs.end();++hiter)
		{
			if(hiter->first=="default")continue;
			fprintf_s(hFile,"%s:\n",hiter->first.c_str());
			for (liter=hiter->second.begin();liter!=hiter->second.end();++liter)
			{
				if(ShowDebug)printf("Write for data:%s\n",(*liter).c_str());
				fprintf_s(hFile,"\t%s",(*liter).c_str());
			}
		}
		fprintf_s(hFile,"};\n",className);
	}
	fclose(hFile);
}