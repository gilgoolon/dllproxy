#include "Worker.hpp"

#include "Config.hpp"
#include "Library.hpp"
#include "SingleRuntimeGuard.hpp"

Worker::Worker(std::shared_ptr<Event> quit_event):
	m_quit_event(std::move(quit_event))
{
}

void Worker::run()
{
	static constexpr std::chrono::seconds ITERATION_COOLDOWN{10};
	do
	{
		try
		{
			SingleRuntimeGuard runtime(Config::MUTEX_GUID);

			Library worker_library(Config::WORKER_PATH);

			static constexpr uint16_t MAIN_FUNCTION_ORDINAL = 1;
			worker_library.call<void>(MAIN_FUNCTION_ORDINAL);
		}
		catch (...)
		{
		}
	}
	while (m_quit_event->checked_wait(ITERATION_COOLDOWN) == WaitStatus::TIMEOUT);
}
