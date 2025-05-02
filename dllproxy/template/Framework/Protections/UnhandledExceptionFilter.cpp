#include "Protections/UnhandledExceptionFilter.hpp"

Protections::UnhandledExceptionFilter::UnhandledExceptionFilter():
	m_previous_filter(SetUnhandledExceptionFilter(filter))
{
}

Protections::UnhandledExceptionFilter::~UnhandledExceptionFilter()
{
	try
	{
		SetUnhandledExceptionFilter(m_previous_filter);
	}
	catch (...)
	{
	}
}

LONG Protections::UnhandledExceptionFilter::filter([[maybe_unused]] EXCEPTION_POINTERS* const exception)
{
	return EXCEPTION_EXECUTE_HANDLER;
}
