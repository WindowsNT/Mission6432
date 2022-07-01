#include <windows.h>
#include <vector>
extern "C"
{
	void myf1(void*,DWORD);
}
#include "MemoryModuleModified.h"
#include "..\\xml3all.h"


#pragma comment(lib,"dbghelp.lib")
#include <dbghelp.h>


const wchar_t* xResult = L"xresult.xml";

void PatchIAT(HINSTANCE h)
{
    PCHAR codeBase = (PCHAR)h;
    XML3::XML x(xResult);
    PIMAGE_NT_HEADERS32           ntheaders = (PIMAGE_NT_HEADERS32)(PCHAR(h) + PIMAGE_DOS_HEADER(h)->e_lfanew);
    PIMAGE_SECTION_HEADER       pSech = IMAGE_FIRST_SECTION(ntheaders);//Pointer to first section header
    DWORD ulsize = 0;
    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(h, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &ulsize);
    if (!importDesc)
        return;

    for (; importDesc && importDesc->Name; importDesc++) {

        PSTR pszModName = (PSTR)((PBYTE)h + importDesc->Name);
        if (!pszModName)
            break;

        XML3::XMLElement* module = 0;
        for (auto& mo : x.GetRootElement())
        {
            if (mo.vv("f").GetValue() == pszModName)
            {
                module = &mo; break;
            }
        }
        if (!module)
            continue;

        DWORD* thunkRef;
        DWORD* funcRef = 0;

        if (importDesc->OriginalFirstThunk) {
            thunkRef = (DWORD*)(codeBase + importDesc->OriginalFirstThunk);
            funcRef = (DWORD*)(codeBase + importDesc->FirstThunk);
        }
        else {
            // no hint table
            thunkRef = (DWORD*)(codeBase + importDesc->FirstThunk);
            funcRef = (DWORD *)(codeBase + importDesc->FirstThunk);
        }

        DWORD V = 0;
        for (; *thunkRef; thunkRef++, funcRef++) {

            DWORD* wr = (DWORD*)funcRef;

            if (IMAGE_SNAP_BY_ORDINAL(*thunkRef)) {
//                *funcRef = module->getProcAddress(handle, (LPCSTR)IMAGE_ORDINAL(*thunkRef), module->userdata);

                const char* fe = (LPCSTR)IMAGE_ORDINAL(*thunkRef);
                for (auto& fu : *module)
                {
                    if (fu.vv("n").GetValue() == fe)
                    {
                        V = fu.vv("p").GetValueUInt();
                    }
                }

            }
            else {
                PIMAGE_IMPORT_BY_NAME thunkData = (PIMAGE_IMPORT_BY_NAME)(codeBase + (*thunkRef));
//                *wr = module->getProcAddress(handle, (LPCSTR)&thunkData->Name, module->userdata);
                for (auto& fu : *module)
                {
                    if (fu.vv("n").GetValue() == (LPCSTR)&thunkData->Name)
                    {
                        V = fu.vv("p").GetValueUInt();
                        break;
                    }
                }
            }

            // Patch it now...
            DWORD dwOldProtect = 0;
            if (VirtualProtect((LPVOID)wr, 4, PAGE_READWRITE, &dwOldProtect))
            {
                memcpy((void*)wr, &V, 4);
                VirtualProtect((LPVOID)wr, 4, dwOldProtect, &dwOldProtect);
            }
            VirtualProtect((LPVOID)V, 4, PAGE_EXECUTE_READWRITE, &dwOldProtect);
        }

    }




}

void LookupIAT(HINSTANCE h)
{
    DeleteFile(xResult);
    XML3::XML x(xResult);

    PIMAGE_NT_HEADERS32           ntheaders = (PIMAGE_NT_HEADERS32)(PCHAR(h) + PIMAGE_DOS_HEADER(h)->e_lfanew);
    PIMAGE_SECTION_HEADER       pSech = IMAGE_FIRST_SECTION(ntheaders);//Pointer to first section header


    // Find the IAT size
    DWORD ulsize = 0;
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(h, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &ulsize);
    if (!pImportDesc)
        return;

    // Loop names
    for (; pImportDesc->Name; pImportDesc++)
    {
        PSTR pszModName = (PSTR)((PBYTE)h + pImportDesc->Name);
        if (!pszModName)
            break;


        XML3::XMLElement* module = 0;
        auto& module2 = x.GetRootElement().AddElement("module");
        module = &module2;
        module2.vv("f").SetValue(pszModName);

        PIMAGE_THUNK_DATA32 pThunk = (PIMAGE_THUNK_DATA32)((PBYTE)h + pImportDesc->OriginalFirstThunk);
        while (pThunk->u1.Function)
        {
            DWORD pfnNew = 0;
            DWORD rva = 0;
            if (pThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
            {
                // Ordinal
                DWORD ord = IMAGE_ORDINAL32(pThunk->u1.Ordinal);
                PROC* ppfn = (PROC*)&pThunk->u1.Function;
                if (!ppfn)
                {
                    // ... (error)
                }
                rva = (DWORD)pThunk;

                char fe[100] = { 0 };
                sprintf_s(fe, 100, "#%zi", ord);
                auto& foo = module->AddElement("function");
                foo.vv("n").SetValue(fe);
            }
            else
            {
                // Get the address of the function address
                PROC* ppfn = (PROC*)&pThunk->u1.Function;
                if (!ppfn)
                {
                    // ... (error)
                }
                rva = (DWORD)pThunk;
                PSTR fName = (PSTR)h;
                fName += pThunk->u1.Function;
                fName += 2;
                if (!fName)
                    break;
                auto& foo = module->AddElement("function");
                foo.vv("n").SetValue((LPCSTR)fName);
            }

            pThunk++;
        }
    }
   x.Save();
}


DWORD Run(const wchar_t* y, bool W, DWORD flg)
{
    PROCESS_INFORMATION pInfo = { 0 };
    STARTUPINFO sInfo = { 0 };

    sInfo.cb = sizeof(sInfo);
    wchar_t yy[1000];
    swprintf_s(yy, 1000, L"%s", y);
    CreateProcess(0, yy, 0, 0, 0, flg, 0, 0, &sInfo, &pInfo);
    SetPriorityClass(pInfo.hProcess, IDLE_PRIORITY_CLASS);
    SetThreadPriority(pInfo.hThread, THREAD_PRIORITY_IDLE);
    if (W)
        WaitForSingleObject(pInfo.hProcess, INFINITE);
    DWORD ec = 0;
    GetExitCodeProcess(pInfo.hProcess, &ec);
    CloseHandle(pInfo.hProcess);
    CloseHandle(pInfo.hThread);
    return ec;
}



int main()
{
	const wchar_t* tf = L"..\\debug\\Library.dll";
//	const wchar_t* tf = L"..\\fasmdll\\fasmdll.dll";
	HANDLE hX = CreateFile(tf, GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0);
	LARGE_INTEGER sz = {};
	GetFileSizeEx(hX, &sz);
	std::vector<char> d(sz.QuadPart);
	DWORD a = 0;
	ReadFile(hX, d.data(), (DWORD)sz.LowPart, &a, 0);
	CloseHandle(hX);
	auto hDLL = MemoryLoadLibrary(d.data(), sz.QuadPart);
	if (!hDLL)
		return 0;

    PMEMORYMODULE mm = (PMEMORYMODULE)hDLL;
    // Build the IAT
    LookupIAT((HINSTANCE)mm->codeBase);
#ifndef _DEBUG
    Run(L"..\\Release\\Get32Imports.exe xresult.xml", true, CREATE_NO_WINDOW);
#else
    Run(L"..\\Debug\\Get32Imports.exe xresult.xml", true, CREATE_NO_WINDOW);
#endif
    PatchIAT((HINSTANCE)mm->codeBase);



	auto exp1 = MemoryGetProcAddress(hDLL, "exp1");
//	DebugBreak();
	myf1(exp1,(DWORD)0);
	MessageBox(0, L"Test Succeeded.", 0, 0);
}
