#pragma once

#include <Windows.h>
#include <memory>
#include <map>
#include <algorithm>
#include <TlHelp32.h>
#include "Memory.h"
#include "Utils.h"

class Process
{
public:
	std::map<std::string, DWORD> mappedModules;
	std::map<std::string, DWORD> processModules;

	HANDLE _proc = 0;
	DWORD _pid = 0;
public:
	bool Attach()
	{
		_proc = OpenProcess(PROCESS_CREATE_THREAD|PROCESS_VM_OPERATION|PROCESS_VM_READ|PROCESS_VM_WRITE, false, _pid);
		if (!_proc)
		{
			TRACE("OpenProcess failed");
			return false;
		}
		else
			return true;
	}

	void SetPid(DWORD pid)
	{
		_pid = pid;
	}

	bool IsAttached()
	{
		return _proc != 0;
	}

	void Detach()
	{
		CloseHandle(_proc);
	}

	Memory Alloc(size_t size)
	{
		auto mem = VirtualAllocEx(_proc, 0, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!mem)
		{
			TRACE("VirtualAllocEx failed");
			return Memory(0, 0);
		}
		else
		{
			Memory block(mem, _proc);
			block.bValid = true;
			return block;
		}
	}

	DWORD GetExport(DWORD base, std::string fnName)
	{
		IMAGE_DOS_HEADER dos;
		IMAGE_NT_HEADERS32 nt;

		//TRACE("Read dos 2");
		MemRead((void*)base, &dos, sizeof(dos));
		//TRACE("Read nt 2");
		MemRead((void*)(base + dos.e_lfanew), &nt, sizeof(nt));

		auto expBase = (DWORD)base + nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

		BYTE* expTable = new BYTE[nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size];
		MemRead((void*)expBase, expTable, nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size);

		PIMAGE_EXPORT_DIRECTORY exportTable = (PIMAGE_EXPORT_DIRECTORY)expTable;

		auto offset = (DWORD)exportTable - nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

		auto funcNames = (DWORD*)(exportTable->AddressOfNames + (DWORD)offset);
		auto functions = (DWORD*)(exportTable->AddressOfFunctions + (DWORD)offset);
		auto ordinals = (WORD*)(exportTable->AddressOfNameOrdinals + (DWORD)offset);

		for (int i = 0; i < exportTable->NumberOfNames; ++i)
		{
			std::string function((char*)(funcNames[i] + (DWORD)offset));
			auto ordinal = ordinals[i];

			if (!_stricmp(fnName.c_str(), function.c_str()))
			{
				auto funcAddress = functions[ordinal] + base;

				if (funcAddress >= expBase &&
					funcAddress <= expBase + nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)
				{
					//Forwarded Export
					char forwardStr[255] = { 0 };
					MemRead((void*)funcAddress, forwardStr, 255);
					std::string forwardedFunc((char*)forwardStr);
					std::string forwardDll = forwardedFunc.substr(0, forwardedFunc.find(".")) + ".dll";
					std::string forwardName = forwardedFunc.substr(forwardedFunc.find(".") + 1, std::string::npos);

					auto forwardBase = GetModuleBase(forwardDll);
					if (!forwardBase)
						TRACE("forwardBase = 0");
					else
					{
						if (forwardName.find("#") != std::string::npos)
						{
							TRACE("forwardImport by Ordinal");
						}
						else
						{
							delete[] expTable;
							return GetExport(forwardBase, forwardName);
						}
					}
				}
				else
				{
					delete[] expTable;
					return funcAddress;
				}
			}
		}

		delete[] expTable;
		return 0;
	}

	bool MemRead(void* source, void* dest, size_t size)
	{
		DWORD n;
		if (!ReadProcessMemory(_proc, source, dest, size, &n) || n != size)
		{
			TRACE("ReadProcessMemory failed");
			TRACE("Last Error: %d", GetLastError());
			return false;
		}
		else
			return true;
	}

	DWORD GetModuleBase(std::string name)
	{
		std::transform(name.begin(), name.end(), name.begin(), tolower);

		auto a = processModules.find(name);
		auto b = mappedModules.find(name);

		if (a != processModules.end())
			return a->second;

		if (b != mappedModules.end())
			return b->second;

		return 0;
	}

	bool FindModules()
	{
		processModules.clear();
		auto handle = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, _pid);
		if (handle == INVALID_HANDLE_VALUE)
		{
			TRACE("CreateToolhelp32Snapshot failed");
			return false;
		}

		MODULEENTRY32 me;
		me.dwSize = sizeof(MODULEENTRY32);

		if (!Module32First(handle, &me))
		{
			TRACE("Module32First failed");
			CloseHandle(handle);
			return false;
		}

		std::string szModule(UnicodeToAscii(std::wstring(me.szModule)));
		std::transform(szModule.begin(), szModule.end(), szModule.begin(), tolower);
		processModules.emplace(szModule, (DWORD)me.hModule);

		while (Module32Next(handle, &me))
		{
			std::string szModule(UnicodeToAscii(std::wstring(me.szModule)));
			std::transform(szModule.begin(), szModule.end(), szModule.begin(), tolower);
			processModules.emplace(szModule, (DWORD)me.hModule);
		}

		CloseHandle(handle);
		return true;
	}

	std::string UnicodeToAscii(std::wstring unicode)
	{
		std::string ascii;
		auto len = WideCharToMultiByte(CP_OEMCP, WC_COMPOSITECHECK, unicode.c_str(), unicode.length(), NULL, 0, NULL, NULL);
		ascii.resize(len);
		WideCharToMultiByte(CP_OEMCP, WC_COMPOSITECHECK, unicode.c_str(), unicode.length(), (char*)ascii.c_str(), ascii.length(), NULL, NULL);

		return ascii;
	}
};