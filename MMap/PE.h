#pragma once

#include <Windows.h>
#include <string>
#include <vector>
#include <unordered_map>

class PE
{
public:
	struct RelocData
	{
		ULONG PageRVA;
		ULONG BlockSize;

		struct
		{
			WORD Offset : 12;
			WORD Type : 4;
		}Item[1];
	};

	struct ImportData
	{
		std::string name;
		WORD ordinal;
		bool byOrdinal;
		DWORD rva;
	};
public:
	HANDLE hMapping = INVALID_HANDLE_VALUE;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	void* pFileBase = 0;
	DWORD headerSize, imageSize, epRVA, imgBase;
	IMAGE_DOS_HEADER dos;
	IMAGE_NT_HEADERS32 nt;

	std::vector<IMAGE_SECTION_HEADER> sections;
	std::unordered_map<std::string, std::vector<ImportData>> imports;
public:
	bool Load(std::string path)
	{
		hFile = CreateFileA(path.c_str(), FILE_GENERIC_READ,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			NULL, OPEN_EXISTING, 0, NULL);

		if (hFile != INVALID_HANDLE_VALUE)
		{
			hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);

			if (hMapping != INVALID_HANDLE_VALUE)
				pFileBase = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
			else
				return false;
		}
		else
			return false;

		if (!pFileBase)
			return false;

		return true;
	}

	bool Load(void* buffer)
	{
		pFileBase = buffer;
		return true;
	}

	bool Parse()
	{
		dos = *(IMAGE_DOS_HEADER*)pFileBase;
		nt = *(IMAGE_NT_HEADERS32*)((DWORD)pFileBase + ((IMAGE_DOS_HEADER*)pFileBase)->e_lfanew);

		if (dos.e_magic != IMAGE_DOS_SIGNATURE || nt.Signature != IMAGE_NT_SIGNATURE)
			return false;

		epRVA = nt.OptionalHeader.AddressOfEntryPoint;
		imageSize = nt.OptionalHeader.SizeOfImage;
		headerSize = nt.OptionalHeader.SizeOfHeaders;
		imgBase = nt.OptionalHeader.ImageBase;

		auto section = (IMAGE_SECTION_HEADER*)((DWORD)pFileBase + dos.e_lfanew + sizeof(IMAGE_NT_HEADERS32));
		for (int i = 0; i < nt.FileHeader.NumberOfSections; ++i, ++section)
			sections.push_back(*section);
		
		GetImports();

		return true;
	}

	void GetImports()
	{
		auto importTable = (IMAGE_IMPORT_DESCRIPTOR*)GetDirectoryAddress(IMAGE_DIRECTORY_ENTRY_IMPORT);
		
		while (importTable->Name)
		{
			std::string dllName((char*)RVA2VA(importTable->Name));

			int IAT = 0;
			auto thunk = (IMAGE_THUNK_DATA32*)RVA2VA(importTable->OriginalFirstThunk);
			if (!importTable->OriginalFirstThunk)
				TRACE("OriginalFirstThunk = 0");

			while (thunk->u1.AddressOfData)
			{
				ImportData impData;
				auto function = (IMAGE_IMPORT_BY_NAME*)RVA2VA(thunk->u1.AddressOfData);

				if (thunk->u1.AddressOfData < IMAGE_ORDINAL_FLAG && function->Name[0])
				{
					impData.byOrdinal = false;
					impData.name = std::string(function->Name);
					impData.ordinal = 0;
				}
				else
				{
					TRACE("PE: Import by ordinal");
					impData.byOrdinal = true;
					impData.name = "";
					impData.ordinal = (WORD)(thunk->u1.AddressOfData & 0xFFFF);
				}

				if (importTable->FirstThunk)
					impData.rva = importTable->FirstThunk + IAT;
				else
				{
					impData.rva = thunk->u1.AddressOfData - (DWORD)pFileBase;
					TRACE("Could not locate IAT");
				}

				imports[dllName].emplace_back(impData);

				IAT += 4;
				thunk++;
			}

			importTable++;
		}
	}
	
	DWORD RVA2VA(DWORD rva)
	{
		for (auto& section : sections)
		{
			if (rva >= section.VirtualAddress && rva <= section.VirtualAddress + section.Misc.VirtualSize)
				return (DWORD)pFileBase + rva + (section.PointerToRawData - section.VirtualAddress);
		}

		return 0;
	}

	DWORD GetDirectoryAddress(int index)
	{
		if (nt.OptionalHeader.DataDirectory[index].Size == 0 ||
			nt.OptionalHeader.DataDirectory[index].VirtualAddress == 0)
		{
			TRACE("GetDirectoryAddress = 0");
			return 0;
		}
		else
			return RVA2VA(nt.OptionalHeader.DataDirectory[index].VirtualAddress);
	}

	DWORD GetDirectorySize(int index)
	{
		if (nt.OptionalHeader.DataDirectory[index].Size == 0 ||
			nt.OptionalHeader.DataDirectory[index].VirtualAddress == 0)
		{
			TRACE("GetDirectorySize = 0");
			return 0;
		}
		else
			return nt.OptionalHeader.DataDirectory[index].Size;
	}
};