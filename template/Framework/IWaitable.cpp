#include "IWaitable.hpp"

#include "Exception.hpp"

static WaitStatus to_wait_status(const DWORD result)
{
	switch (result)
	{
	case WAIT_OBJECT_0:
		return WaitStatus::FINISHED;

	case WAIT_ABANDONED:
		return WaitStatus::OBJECT_CLOSED;

	case WAIT_TIMEOUT:
		return WaitStatus::TIMEOUT;

	case WAIT_FAILED:
		[[fallthrough]];
	default:
		return WaitStatus::FAILED;
	}
}

WaitStatus IWaitable::wait(const std::chrono::milliseconds timeout) const
{
	const DWORD result = WaitForSingleObject(handle(), static_cast<DWORD>(timeout.count()));
	return to_wait_status(result);
}

WaitStatus IWaitable::checked_wait(const std::chrono::milliseconds timeout) const
{
	switch (const WaitStatus result = wait(timeout))
	{
	case WaitStatus::FINISHED:
		[[fallthrough]];
	case WaitStatus::TIMEOUT:
	{
		return result;
	}

	case WaitStatus::OBJECT_CLOSED:
		[[fallthrough]];
	case WaitStatus::FAILED:
		[[fallthrough]];
	default:
	{
		throw WinApiException(ErrorCode::FAILED_WAIT);
	}
	}
}

void IWaitable::sleep(const std::chrono::milliseconds duration)
{
	Sleep(static_cast<DWORD>(duration.count()));
}

WaitResult IWaitable::wait_for_any(const std::vector<std::shared_ptr<IWaitable>>& objects,
                                   const std::chrono::milliseconds timeout)
{
	static constexpr bool WAIT_FOR_ANY = false;
	return wait_for_multiple(objects, timeout, WAIT_FOR_ANY);
}

WaitResult IWaitable::wait_for_all(const std::vector<std::shared_ptr<IWaitable>>& objects,
                                   const std::chrono::milliseconds timeout)
{
	static constexpr bool WAIT_FOR_ALL = true;
	return wait_for_multiple(objects, timeout, WAIT_FOR_ALL);
}

WaitResult IWaitable::wait_for_multiple(const std::vector<std::shared_ptr<IWaitable>>& objects,
                                        const std::chrono::milliseconds timeout,
                                        const bool wait_all)
{
	std::vector<HANDLE> handles;
	handles.reserve(objects.size());
	for (const std::shared_ptr<IWaitable>& object : objects)
	{
		handles.push_back(object->handle());
	}
	const BOOL wait_all_win = wait_all ? TRUE : FALSE;

	const DWORD result = WaitForMultipleObjects(
		static_cast<DWORD>(handles.size()),
		handles.data(),
		wait_all_win,
		static_cast<DWORD>(timeout.count())
	);

	if (result == WAIT_TIMEOUT)
	{
		return {.status = WaitStatus::TIMEOUT, .triggered_object = std::nullopt};
	}

	if (result >= WAIT_OBJECT_0 && result <= WAIT_OBJECT_0 + handles.size())
	{
		if (wait_all)
		{
			return {.status = WaitStatus::FINISHED, .triggered_object = std::nullopt};
		}
		return {.status = WaitStatus::FINISHED, .triggered_object = result - WAIT_OBJECT_0};
	}

	if (result >= WAIT_ABANDONED_0 && result <= WAIT_ABANDONED_0 + handles.size())
	{
		return {.status = WaitStatus::OBJECT_CLOSED, .triggered_object = result - WAIT_ABANDONED_0};
	}

	return {.status = WaitStatus::FAILED, .triggered_object = std::nullopt};
}
