// Get32Imports.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>
#include "..\\xml3all.h"
int wmain(int argc,wchar_t** argv)
{
	if (argc != 2)
		return 0;

	XML3::XML x(argv[1]);
	for (auto& module : x.GetRootElement())
	{
		HINSTANCE hL = LoadLibrary(module.vv("f").GetWideValue().c_str());
		if (!hL)
			continue;
		for (auto& function : module)
		{
			auto proc = GetProcAddress(hL, function.vv("n").GetValue().c_str());
			function.vv("p").SetValueUInt((DWORD)proc);
		}
	}
	x.Save();
	return 0;
}

