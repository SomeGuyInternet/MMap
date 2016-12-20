#pragma once

#include <Windows.h>
#include <TlHelp32.h>
#include <map>
#include <iostream>
#include <cstdarg>

//#define LOG

#ifdef LOG
#define TRACE(fmt, ...) Utils::print(fmt, ##__VA_ARGS__)
#else
#define TRACE(...)
#endif

class Utils
{
public:
	static void print(char* fmt, ...)
	{
		va_list l;
		va_start(l, fmt);
		vprintf(fmt, l);
		printf("\n");
		va_end(l);
	}

	static std::string GetFileNameWithExtensionFromPath(std::string path)
	{
		auto k = path.rfind("\\");
		return path.substr(k+1, std::string::npos);
	}

	static std::string LookupDependancy(std::string module)
	{
		char directory[MAX_PATH] = {0};

		//lookup in exe folder
		if (GetModuleHandle(NULL))
		{
			if (GetModuleFileNameA(GetModuleHandle(NULL), directory, MAX_PATH))
			{
				WIN32_FIND_DATAA file;
				HANDLE hFirstFile;

				std::string local = std::string(directory).substr(0, std::string(directory).rfind("\\")) + "\\*";

				hFirstFile = FindFirstFileA(local.c_str(), &file);
				if (hFirstFile != INVALID_HANDLE_VALUE)
				{
					do
					{
						if (!(file.dwFileAttributes &FILE_ATTRIBUTE_DIRECTORY))
						{
							if (!_stricmp(module.c_str(), file.cFileName))
							{
								return local.substr(0, local.length() - 1) + std::string(module);
							}
						}
					} while (FindNextFileA(hFirstFile, &file));

					FindClose(hFirstFile);
				}
			}
		}

		
		if (GetSystemDirectoryA(directory, MAX_PATH))
		{
			std::string system32 = std::string(directory) + "\\*";

			WIN32_FIND_DATAA file;
			HANDLE hFirstFile;

			hFirstFile = FindFirstFileA(system32.c_str(), &file);
			if (hFirstFile != INVALID_HANDLE_VALUE)
			{
				do
				{
					if (!(file.dwFileAttributes &FILE_ATTRIBUTE_DIRECTORY))
					{
						if (!_stricmp(module.c_str(), file.cFileName))
						{
							return system32.substr(0, system32.length() - 1) + std::string(module);
						}
					}
				} while (FindNextFileA(hFirstFile, &file));

				FindClose(hFirstFile);
			}
		}

		return std::string("");
	}

	static DWORD FindProcessByName(std::wstring name)
	{
		auto handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (handle == INVALID_HANDLE_VALUE)
		{
			TRACE("CreateToolhelp32Snapshot failed");
			return 0;
		}

		PROCESSENTRY32 pe;
		pe.dwSize = sizeof(PROCESSENTRY32);

		if (!Process32First(handle, &pe))
		{
			TRACE("Process32First failed");
			CloseHandle(handle);
			return 0;
		}

		if (!wcscmp(pe.szExeFile, name.c_str()))
		{
			TRACE("Process %s found", name.c_str());
			CloseHandle(handle);
			return pe.th32ProcessID;
		}

		while (Process32Next(handle, &pe))
			if (!wcscmp(pe.szExeFile, name.c_str()))
			{
				TRACE("Process %s found", name.c_str());
				CloseHandle(handle);
				return pe.th32ProcessID;
			}

		CloseHandle(handle);
		return 0;
	}
};