#include "SingleRuntimeGuard.hpp"

#include "Exception.hpp"

SingleRuntimeGuard::SingleRuntimeGuard(const std::wstring& guid):
	m_mutex(guid)
{
	switch (m_mutex.wait(std::chrono::milliseconds::zero()))
	{
	case WaitStatus::FINISHED:
	{
		return;
	}

	case WaitStatus::TIMEOUT:
	{
		throw WinApiException(ErrorCode::MUTEX_ALREADY_TAKEN);
	}

	case WaitStatus::FAILED:
		[[fallthrough]];
	case WaitStatus::OBJECT_CLOSED:
		[[fallthrough]];
	default:
	{
		throw WinApiException(ErrorCode::FAILED_MUTEX_ACQUIRE);
	}
	}
}
