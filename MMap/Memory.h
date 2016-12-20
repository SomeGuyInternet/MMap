#pragma once

#include <Windows.h>
#include <cstdint>
#include "Utils.h"

class Memory
{
public:
	bool bValid = false;
	void* _base;
	HANDLE _proc;
public:
	Memory() : _base(0), _proc(0) {}
	Memory(void* base, HANDLE proc) : _base(base), _proc(proc) {}

	bool Write(void* source, void* dest, size_t size)
	{
		DWORD n;
		if (!WriteProcessMemory(_proc, (void*)((DWORD)_base + (DWORD)dest), source, size, &n) || n != size)
		{
			TRACE("WriteProcessMemory failed");
			return false;
		}
		else
			return true;
	}

	bool Write(void* dest, ULONG val)
	{
		DWORD n;
		if (!WriteProcessMemory(_proc, (void*)((DWORD)_base + (DWORD)dest), &val, 4, &n) || n != 4)
		{
			TRACE("WriteProcessMemory failed");
			return false;
		}
		else
			return true;
	}

	void Free()
	{
		bValid = false;
		VirtualFreeEx(_proc, _base, 0, MEM_RELEASE);
	}

	bool isValid()
	{
		return bValid;
	}
};