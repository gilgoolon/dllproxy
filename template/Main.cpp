#include <Windows.h>

BOOL WINAPI DllMain([[maybe_unused]] HINSTANCE instance,
                    [[maybe_unused]] const DWORD reason,
                    [[maybe_unused]] DWORD reserved)
{
	if (reason == DLL_PROCESS_ATTACH)
	{
		MessageBoxW(nullptr, L"SimpleDll loaded", L"SimpleDll", 0);
	}
	if (reason == DLL_PROCESS_DETACH)
	{
		MessageBoxW(nullptr, L"SimpleDll unloaded", L"SimpleDll", 0);
	}
	return TRUE;
}
