#pragma once
#include "IRunner.hpp"
#include "ScopedHandle.hpp"

class Thread final
{
public:
	explicit Thread(IRunner::Ptr runner);
	~Thread() = default;
	Thread(const Thread&) = delete;
	Thread& operator=(const Thread&) = delete;
	Thread(Thread&&) = delete;
	Thread& operator=(Thread&&) = delete;

private:
	[[nodiscard]] static DWORD WINAPI thread_main(LPVOID argument);

	[[nodiscard]] static HANDLE create_thread(IRunner::Ptr runner);

	ScopedHandle m_handle;
};
