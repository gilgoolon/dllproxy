#include "Library.hpp"

#include <memory>
#include <Windows.h>

static constexpr auto WORKER_PATH = L"%WORKER_PATH%";
static std::unique_ptr<Library> g_worker = nullptr;

BOOL WINAPI DllMain([[maybe_unused]] HINSTANCE instance,
                    [[maybe_unused]] const DWORD reason,
                    [[maybe_unused]] DWORD reserved)
{
	try
	{
		if (reason == DLL_PROCESS_ATTACH)
		{
			g_worker = std::make_unique<Library>(WORKER_PATH);
		}
		if (reason == DLL_PROCESS_DETACH)
		{
			g_worker.reset();
		}
		return TRUE;
	}
	catch (...)
	{
	}
	return FALSE;
}
