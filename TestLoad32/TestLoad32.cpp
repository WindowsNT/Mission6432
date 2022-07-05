// TestLoad32.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <vector>
#include "MemoryModule.h"
typedef void(__stdcall* x)(DWORD);

int main()
{
//	const wchar_t* tf = L"..\\debug\\Library.dll";
	const wchar_t* tf = L"..\\fasmdll\\fasmdll.dll";

//#define CALL_2

#ifdef CALL_2
	auto h3 = LoadLibrary(tf);
	x X = (x)GetProcAddress(h3, "exp1");
	X((DWORD)h3);

#else
	HANDLE hX = CreateFile(tf, GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0);
	LARGE_INTEGER sz = {};
	GetFileSizeEx(hX, &sz);
	std::vector<char> d(sz.QuadPart);
	DWORD a = 0;
	ReadFile(hX, d.data(), (DWORD)sz.LowPart, &a, 0);
	CloseHandle(hX);
	auto hDLL = MemoryLoadLibrary(d.data(), sz.QuadPart);
	auto exp1 = MemoryGetProcAddress(hDLL, "exp2");
	PMEMORYMODULE mm = (PMEMORYMODULE)hDLL;
	x X = (x)exp1;
	X((DWORD)mm->codeBase);
#endif
	
}
