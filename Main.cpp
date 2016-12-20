#include <Windows.h>
#include "MMap\MMap.h"

int main()
{
	/*auto dllpath = "H:\\Projects\\testdll\\Release\\test.dll"; // i stream it from the server in to memory so my friends do not need to redownload the injector every time 
	// i change something. 
	std::string file(dllpath);
	auto pos = file.find_first_of("#+#~");
	std::string fileLen = file.substr(0, pos);

	BYTE* DLLHack = new BYTE[std::stoi(fileLen)];
	memset(DLLHack, 0, std::stoi(fileLen));
	memcpy(DLLHack, dllpath + fileLen.length() + 4, std::stoi(fileLen));
	*/

	std::string dllpath = "H:\\Projects\\testdll\\Release\\test.dll";
	DWORD pid;
	while (!(pid = Utils::FindProcessByName(L"csgo.exe")))
	{
		Sleep(200);
	}

	Process proc;
	proc.SetPid(pid);

	MMap mmap(proc);
	mmap.CreateRPCEnvironment();
	if (!mmap.MapModule(dllpath))
		MessageBox(NULL, L"Unknown error.\n Please try again.", L"Error", MB_OK | MB_ICONEXCLAMATION);
	else
	{
		MessageBox(NULL, L"Worked!", L"Error", MB_OK | MB_ICONEXCLAMATION);
	}

	system("pause");
}