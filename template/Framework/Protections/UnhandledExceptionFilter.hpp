#pragma once
#include <Windows.h>

namespace Protections
{
class UnhandledExceptionFilter final
{
public:
	explicit UnhandledExceptionFilter();
	~UnhandledExceptionFilter();
	UnhandledExceptionFilter(const UnhandledExceptionFilter&) = delete;
	UnhandledExceptionFilter& operator=(const UnhandledExceptionFilter&) = delete;
	UnhandledExceptionFilter(UnhandledExceptionFilter&&) = delete;
	UnhandledExceptionFilter& operator=(UnhandledExceptionFilter&&) = delete;

private:
	LPTOP_LEVEL_EXCEPTION_FILTER m_previous_filter;

	static LONG WINAPI filter(EXCEPTION_POINTERS* exception);
};
}
