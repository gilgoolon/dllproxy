#include "Event.hpp"

#include "Exception.hpp"

#include <string>

Event::Event(const std::wstring& name) :
	m_handle(open_event(name))
{
}

Event::Event(const std::wstring& name, const Type type) :
	m_handle(create_event(name, type))
{
}

Event::Event(const Type type) :
	Event(L"", type)
{
}

HANDLE Event::handle() const
{
	return m_handle.get();
}

void Event::set()
{
	if (SetEvent(m_handle.get()) == FALSE)
	{
		throw WinApiException(ErrorCode::FAILED_EVENT_SET);
	}
}

void Event::unset()
{
	if (ResetEvent(m_handle.get()) == FALSE)
	{
		throw WinApiException(ErrorCode::FAILED_EVENT_UNSET);
	}
}

HANDLE Event::open_event(const std::wstring& name)
{
	static constexpr BOOL DONT_INHERIT = FALSE;
	const HANDLE result = OpenEventW(SYNCHRONIZE | EVENT_MODIFY_STATE, DONT_INHERIT, name.c_str());
	if (result == nullptr)
	{
		throw WinApiException(ErrorCode::FAILED_EVENT_OPEN);
	}
	return result;
}

HANDLE Event::create_event(const std::wstring& name, Type type)
{
	static constexpr LPSECURITY_ATTRIBUTES DEFAULT_SECURITY = nullptr;
	static constexpr BOOL INITIALLY_UNSET = FALSE;
	const HANDLE result = CreateEventW(DEFAULT_SECURITY, static_cast<BOOL>(type), INITIALLY_UNSET, name.c_str());
	if (result == nullptr)
	{
		throw WinApiException(ErrorCode::FAILED_EVENT_CREATE);
	}
	return result;
}
