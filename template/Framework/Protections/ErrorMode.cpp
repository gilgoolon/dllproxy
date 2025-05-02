#include "ErrorMode.hpp"

#include "Exception.hpp"

#include <cstdlib>

Protections::ErrorMode::ErrorMode():
	m_previous_mode(_set_error_mode(_OUT_TO_STDERR))
{
	static constexpr int SET_MODE_ERROR = -1;
	if (m_previous_mode == SET_MODE_ERROR)
	{
		throw CriticalException();
	}
}

Protections::ErrorMode::~ErrorMode()
{
	try
	{
		_set_error_mode(m_previous_mode);
	}
	catch (...)
	{
	}
}
