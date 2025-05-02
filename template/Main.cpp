#include "Framework/Library.hpp"
#include "Protections/ProgramProtector.hpp"

#include <optional>
#include <Windows.h>

static std::optional<Protections::ProgramProtector> g_protector = std::nullopt;

static constexpr auto WORKER_PATH = L"%WORKER_PATH%";
static std::optional<Library> g_worker = std::nullopt;

BOOL WINAPI DllMain([[maybe_unused]] HINSTANCE instance,
                    [[maybe_unused]] const DWORD reason,
                    [[maybe_unused]] DWORD reserved)
{
	try
	{
		if (reason == DLL_PROCESS_ATTACH)
		{
			g_protector.emplace();
			g_worker.emplace(WORKER_PATH);
		}
		if (reason == DLL_PROCESS_DETACH)
		{
			g_worker.reset();
			g_worker.reset();
		}
		return TRUE;
	}
	catch (...)
	{
	}
	return FALSE;
}

%EXPORT_STUBS%
