#include "Thread.hpp"

#include "Exception.hpp"
#include "Protections/EntryPointProtector.hpp"

Thread::Thread(IRunner::Ptr runner) :
	m_handle(create_thread(std::move(runner)))
{
}

DWORD Thread::thread_main(const LPVOID argument)
{
	try
	{
		Protections::EntryPointProtector protections;
		const IRunner::Ptr runner(static_cast<IRunner*>(argument));
		runner->run();
		return EXIT_SUCCESS;
	}
	catch (...)
	{
	}
	return EXIT_FAILURE;
}

HANDLE Thread::create_thread(IRunner::Ptr runner)
{
	static constexpr LPSECURITY_ATTRIBUTES DEFAULT_SECURITY = nullptr;
	static constexpr DWORD DEFAULT_STACK_SIZE = 0;
	static constexpr DWORD RUN_ON_CREATION = 0;
	static constexpr LPDWORD DONT_OUT_TID = nullptr;
	const HANDLE result = CreateThread(
		DEFAULT_SECURITY,
		DEFAULT_STACK_SIZE,
		thread_main,
		runner.get(),
		RUN_ON_CREATION,
		DONT_OUT_TID
	);
	if (result == nullptr)
	{
		throw WinApiException(ErrorCode::FAILED_THREAD_CREATE);
	}
	std::ignore = runner.release();
	return result;
}
