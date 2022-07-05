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

DWORD GetExport(HINSTANCE h, const char* n)
{
    DWORD ulsize = 0;
    IMAGE_EXPORT_DIRECTORY* pExportDir = (IMAGE_EXPORT_DIRECTORY*)ImageDirectoryEntryToData(h, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &ulsize);
    if (!pExportDir)
        return 0;
    auto MAP = [&](DWORD off) -> DWORD
    {
        return DWORD((char*)h + off);
    };

    UINT32* export_addr_table = (UINT32*)MAP(pExportDir->AddressOfFunctions);
    UINT32* export_nameptr_table = (UINT32*)MAP(pExportDir->AddressOfNames);
    UINT16* export_ordinal_table = (UINT16*)MAP(pExportDir->AddressOfNameOrdinals);

    for (SIZE_T i = 0; i < pExportDir->NumberOfFunctions; i++)
    {
        UINT32 ordinal = pExportDir->Base + i;


/*        if (is_forwarder_rva(export_rva))
        {
            // TODO: special care must be taken here - we cannot resolve directly to a VA unless target module is memory mapped
        }
        else*/
        {
            BOOL found_symname = FALSE;
            char symname[100];

            // Loop through all exported names
            for (SIZE_T j = 0; j < pExportDir->NumberOfNames; j++)
            {
                if (export_ordinal_table[j] == i)
                {
                    UINT32 export_symname_rva = export_nameptr_table[j];
                    const char* export_symname = (const char*)MAP(export_symname_rva);
                    found_symname = TRUE;

                    if (_stricmp(n, export_symname) == 0)
                    {
                        UINT32 export_rva = export_addr_table[i];
                        return MAP(export_rva);
                    }

                    // Copy export_symname into symname (i.e. using strncat or similar)
                }
            }
            if (!found_symname)
            {
                snprintf(symname, 100, "#%i", ordinal);
            }
            // Print symname, ordinal, address
        }
    }
    return 0;
}

struct FANDP
{
    const char* f  = 0;
    void* p = 0;
};

void PatchIAT(HINSTANCE h,std::vector<FANDP>* CustomLoading = 0)
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

                        if (CustomLoading)
                        {
                            for (auto& cc : *CustomLoading)
                            {
                                if (_stricmp(pszModName, cc.f) == 0)
                                {
                                    auto v2 = GetExport((HINSTANCE)cc.p, (LPCSTR)&thunkData->Name);
                                    if (v2)
                                        V = v2;
                                }
                            }
                        }
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

std::vector<char> loadf(const wchar_t* f)
{
    HANDLE hX = CreateFile(f, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
    LARGE_INTEGER sz = {};
    GetFileSizeEx(hX, &sz);
    std::vector<char> d(sz.QuadPart);
    DWORD a = 0;
    ReadFile(hX, d.data(), (DWORD)sz.LowPart, &a, 0);
    CloseHandle(hX);
    return d;
}

HMEMORYMODULE LoadAndPatch(const wchar_t* tf, std::vector<FANDP>* CustomLoading = 0)
{
    auto d = loadf(tf);
    auto hDLL = MemoryLoadLibrary(d.data(), d.size());
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
    PatchIAT((HINSTANCE)mm->codeBase, CustomLoading);
    return hDLL;
}

int main()
{
    std::vector<FANDP> CustomPatching;
    auto h2 = LoadAndPatch(L"..\\debug\\Library.dll" , &CustomPatching);
    if (!h2)
        return 0;
    PMEMORYMODULE ph2 = ((PMEMORYMODULE)h2);
    FANDP fa = { "library.dll", (void*)(ph2->codeBase)};
    CustomPatching.push_back(fa);

    if (0)
    {
        auto h21 = LoadAndPatch(L"c:\\windows\\syswow64\\kernel32.dll", &CustomPatching);
        if (!h21)
            return 0;
        PMEMORYMODULE ph2 = ((PMEMORYMODULE)h21);
        FANDP fa = { "kernel32.dll", (void*)(ph2->codeBase) };
        CustomPatching.push_back(fa);
    }

    auto h1 = LoadAndPatch(L"..\\fasmdll\\fasmdll.dll", &CustomPatching);
    if (!h1)
        return 0;

	auto exp1 = MemoryGetProcAddress(h2, "exp1");
    auto exp2 = MemoryGetProcAddress(h1, "exp2");

    if (exp1)
    	myf1(exp1,(DWORD)0);
//    DebugBreak();
    if (exp2)
        myf1(exp2, (DWORD)0);
    MessageBox(0, L"Test Succeeded.", 0, 0);
}
