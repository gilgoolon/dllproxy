#include "Thread.hpp"
#include "Worker.hpp"
#include "Protections/ProgramProtector.hpp"

#include <optional>
#include <Windows.h>

static std::optional<Protections::ProgramProtector> g_protector = std::nullopt;
static std::shared_ptr<Event> g_quit_event = nullptr;
static std::optional<Thread> g_worker = std::nullopt;

BOOL WINAPI DllMain([[maybe_unused]] HINSTANCE instance,
                    [[maybe_unused]] const DWORD reason,
                    [[maybe_unused]] DWORD reserved)
{
	try
	{
		if (reason == DLL_PROCESS_ATTACH)
		{
			g_protector.emplace();
			g_quit_event = std::make_shared<Event>(Event::Type::MANUAL_RESET);
			g_worker.emplace(std::make_unique<Worker>(g_quit_event));
		}
		if (reason == DLL_PROCESS_DETACH)
		{
			g_quit_event->set();
			g_quit_event.reset();
			g_worker.reset();
			g_protector.reset();
		}
		return TRUE;
	}
	catch (...)
	{
	}
	return FALSE;
}

%EXPORT_STUBS%
