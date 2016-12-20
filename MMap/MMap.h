#pragma once

#include "Process.h"
#include "PE.h"
#include "Utils.h"
#include "asmjit\x86\x86assembler.h"
#include <vector>

class MMap
{
public:
	Process _pe;
	Memory workerCode;

	std::vector<std::pair<DWORD, PE>> images;
public:
	MMap(Process& pe) : _pe(pe) {}

	void CreateRPCEnvironment()
	{
		workerCode = _pe.Alloc(100);
	}

	bool MapModule(std::string path)
	{
		if (!MapModuleInternal(path))
		{
			std::cout << "MapModuleInternal fail" << std::endl;
			return false;
		}
		else
			std::cout << path.c_str() << " mapped correctly " << std::endl;

			//TRACE();

		for (auto mod : images)
			WipePEHeader(mod.first, mod.second.headerSize);

		//TRACE("Wiped PE Headers");
		std::cout << "Wiped PE Headers"<< std::endl;

		workerCode.Free();
		_pe.Detach();

		return true;
	}

	bool MapModule(void* buffer)
	{
		if (!MapModuleInternal(buffer))
		{
			std::cout << "MapModuleInternal fail" << std::endl;
			return false;
		}
		else
			std::cout << "File mapped correctly" << std::endl;
			//TRACE("File mapped correctly");

		for (auto mod : images)
			WipePEHeader(mod.first, mod.second.headerSize);

		//TRACE("Wiped PE Headers");
		std::cout << "Wiped PE Headers" << std::endl;

		workerCode.Free();
		_pe.Detach();

		return true;
	}

	void WipePEHeader(DWORD base, DWORD headerSize)
	{
		DWORD n;
		BYTE* zeroBuff = new BYTE[headerSize];
		memset(zeroBuff, 0, headerSize);
		WriteProcessMemory(_pe._proc, (void*)base, zeroBuff, headerSize, &n);
		delete[] zeroBuff;
	}

	bool MapModuleInternal(void* buffer)
	{
		if (_pe.IsAttached())
		{
			PE file;
			if (file.Load(buffer))
			{
				TRACE("Loading file");
				if (file.Parse())
				{
					TRACE("Parsing PE file");
					Memory block = _pe.Alloc(file.imageSize);
					if (block.isValid())
					{
						//PE Header
						block.Write(file.pFileBase, 0, file.headerSize);
						//Sections
						CopySections(block, file);
						//Fix Relocs
						FixRelocs(block, file);
						//Fix Imports
						FixImports(block, file);
						//Run module initalizer
						RunModuleInitializer(block, file);

						images.push_back(std::make_pair((DWORD)block._base, file));

						TRACE("PE file loaded at: 0x%X", (DWORD)block._base);

						return true;
					}
				}
			}
		}

		return false;
	}

	bool MapModuleInternal(std::string path)
	{
		if (_pe.IsAttached())
		{
			std::cout << "Mapping file " << path.c_str() << std::endl;
		//	TRACE("Mapping file %s", path.c_str());
			//module is already in the process
			if (_pe.GetModuleBase(Utils::GetFileNameWithExtensionFromPath(path)) != 0)
				return true;

			PE file;
			if (file.Load(path))
			{
				std::cout << " Loading file " << path.c_str() << std::endl;
				//TRACE("Loading file %s", path.c_str());
				if (file.Parse())
				{
					std::cout << "Parsing PE file" << std::endl;
					//TRACE("Parsing PE file");
					Memory block = _pe.Alloc(file.imageSize);
					std::cout << "Allocated space" << std::endl;
					//TRACE("Allocated space");
					if (block.isValid())
					{
						//TRACE("block is valid");
						std::cout << "block is valid" << std::endl;
						//PE Header
						block.Write(file.pFileBase, 0, file.headerSize);
						//TRACE("write pe header");
						std::cout << "write pe header" << std::endl;
						//Sections
						CopySections(block, file);
						//TRACE("copy sections");
						std::cout << "copy sections" << std::endl;
						//Fix Relocs
						FixRelocs(block, file);
						//TRACE("fix relocs");
						std::cout << "fix relocs" << std::endl;

						AddManualModule((DWORD)block._base, path);

						//Fix Imports
						FixImports(block, file);
						//TRACE("imports fixed of %s", path.c_str());
						std::cout << "imports fixed of" << path.c_str() << std::endl;
						//Run module initalizer
						RunModuleInitializer(block, file);

						images.push_back(std::make_pair((DWORD)block._base, file));

						//TRACE("PE file loaded at: 0x%X", (DWORD)block._base);
						std::cout << "PE file loaded at: " << std::endl;

						return true;
					}
				}
			}
		}

		return false;
	}

	void AddManualModule(DWORD base, std::string path)
	{
		std::string mapped = Utils::GetFileNameWithExtensionFromPath(path);
		std::transform(mapped.begin(), mapped.end(), mapped.begin(), tolower);
		_pe.mappedModules.emplace(mapped, (DWORD)base);
	}

	void RemoveManualModule(std::string path)
	{
		std::string mapped = Utils::GetFileNameWithExtensionFromPath(path);
		std::transform(mapped.begin(), mapped.end(), mapped.begin(), tolower);

		auto it = _pe.mappedModules.find(mapped);
		if (it != _pe.mappedModules.end())
		{
			_pe.mappedModules.erase(it);
		}
	}
	/* this is the function that actually makes the game crash and the DLL not being able to load! */
	void RunModuleInitializer(Memory& mem, PE file)
	{
		asmjit::JitRuntime jitruntime;
		asmjit::X86Assembler a(&jitruntime);

		std::cout << "jitruntime" << std::endl;

		//Prolog
		a.push(asmjit::x86::ebp);
		a.mov(asmjit::x86::ebp, asmjit::x86::esp);

		std::cout << "Push?" << std::endl;
		// There is an entry point in the dll. Maybe it cannot find it? i do not know.
		//call Entrypoint
		a.push(0);
		a.push(DLL_PROCESS_ATTACH);
		a.push((unsigned int)mem._base);
		a.mov(asmjit::x86::eax, (unsigned int)(file.epRVA + (DWORD)mem._base));
		a.call(asmjit::x86::eax);

		std::cout << "Execute Code?" << std::endl;
		
		//Epilog
		a.mov(asmjit::x86::esp, asmjit::x86::ebp);
		a.pop(asmjit::x86::ebp);

		std::cout << "EpiLog?" << std::endl;

		a.ret();

		void* code = a.make();
		auto size = a.getCodeSize();

		workerCode.Write(code, 0, size);
		auto thread = CreateRemoteThread(_pe._proc, 0, 0, (LPTHREAD_START_ROUTINE)workerCode._base, 0, 0, 0);
		if (!thread)
			std::cout << "CreateRemoteThread failed " << std::endl;
			//TRACE("CreateRemoteThread failed");

		std::cout << "ThreadIssue??" << std::endl;
		WaitForSingleObject(thread, INFINITE);
		std::cout << "No?" << std::endl;
	}

	DWORD MapDependancy(std::string szDllName)
	{
		auto path = Utils::LookupDependancy(szDllName);
		if (path.empty()) //Error: Could not find dependancy
		{
			//TRACE("Could not locate dependancy: %s", szDllName.c_str());
			std::cout << "Could not locate dependancy: " << szDllName.c_str() << std::endl;
			return 0;
		}
		else
		{
			if (!MapModuleInternal(path)) //Error: Didnt succeed mapping dependancy
			{
				//TRACE("Could not manual map: %s", szDllName.c_str());
				std::cout << "Could not manual map : " << szDllName.c_str() << std::endl;
				return 0;
			}
			else
			{
				//it needs to exist now since we just mapped it
			//	TRACE("Dependancy %s mapped correctly", szDllName.c_str());
				std::cout << "Dependancy " << szDllName.c_str() << "mapped correctly" << std::endl;
				return _pe.GetModuleBase(szDllName);
			}
		}
	}

	void FixImports(Memory& target, PE& file)
	{
		auto imports = file.imports;

		for (auto keyVal : imports)
		{
			auto dllName = keyVal.first;
			auto hMod = _pe.GetModuleBase(dllName);
			//TRACE("Import Dll: %s, 0x%X", dllName.c_str(), hMod);
			std::cout << "Import Dll: " << dllName.c_str() << std::endl;
			if (hMod == 0) //manual map this dependancy
			{
				//TRACE("Mapping depedendancy: %s", dllName);
				std::cout << "Mapping depedendancy: " << dllName.c_str() << std::endl;
				hMod = MapDependancy(dllName);
				if (hMod == 0) //Error: Didnt succeed mapping dependancy
				{
					return;
				}
			}

			for (auto impData : keyVal.second)
			{
				if (impData.byOrdinal)
				{
					//Import by Ordinal
					//TRACE("Import by Oridnal not handled");
					std::cout << "Import by Oridnal not handled" << std::endl;
				}
				else
				{
					auto functionAddr = _pe.GetExport(hMod, impData.name);
					if (!functionAddr)
						std::cout << "Bad function address received" << std::endl;
						//TRACE("Bad function address received");
					

					//TRACE("Fixxing import table 0x%X", impData.rva);
					target.Write((void*)impData.rva, functionAddr);
				}
			}
		}
	}

	void FixRelocs(Memory& target, PE& file)
	{
		auto Delta = (DWORD)target._base - (DWORD)file.imgBase;

		auto start = file.GetDirectoryAddress(IMAGE_DIRECTORY_ENTRY_BASERELOC);
		auto end = start + file.GetDirectorySize(IMAGE_DIRECTORY_ENTRY_BASERELOC);

		auto relocData = (PE::RelocData*)start;
		while ((DWORD)relocData < end && relocData->BlockSize)
		{
			auto numRelocs = (relocData->BlockSize - 8) / 2;
			for (int i = 0; i < numRelocs; ++i)
			{
				auto offset = relocData->Item[i].Offset % 4096;
				auto type = relocData->Item[i].Type;

				if (type == IMAGE_REL_BASED_ABSOLUTE)
					continue;

				if (type == IMAGE_REL_BASED_HIGHLOW)
				{
					auto rva = relocData->PageRVA + offset;
					auto val = *(DWORD*)file.RVA2VA(rva) + Delta;
					target.Write((void*)rva, val);
				}
				else
					std::cout << "Abnormal relocation type" << std::endl;
					//TRACE("Abnormal relocation type");
			}
			relocData = (PE::RelocData*)((DWORD)relocData + relocData->BlockSize);
		}
	}

	void CopySections(Memory& mem, PE& file)
	{
		for (int i = 0; i < file.sections.size(); ++i)
		{
			if (!(file.sections[i].Characteristics & IMAGE_SCN_MEM_DISCARDABLE) && file.sections[i].SizeOfRawData != 0)
			{
				auto pSource = file.RVA2VA(file.sections[i].VirtualAddress);
				mem.Write((void*)pSource, (void*)file.sections[i].VirtualAddress, file.sections[i].SizeOfRawData);
			}
		}
	}
};
