#include "Protections/InvalidParameter.hpp"

#include "Exception.hpp"

Protections::InvalidParameter::InvalidParameter():
	m_prev_handler(_set_invalid_parameter_handler(handler))
{
}

Protections::InvalidParameter::~InvalidParameter()
{
	try
	{
		_set_invalid_parameter_handler(m_prev_handler);
	}
	catch (...)
	{
	}
}

void Protections::InvalidParameter::handler([[maybe_unused]] const wchar_t* const expression,
                                            [[maybe_unused]] const wchar_t* const function,
                                            [[maybe_unused]] const wchar_t* const file,
                                            [[maybe_unused]] const unsigned int line,
                                            [[maybe_unused]] const uintptr_t reserved)
{
	throw CriticalException();
}
