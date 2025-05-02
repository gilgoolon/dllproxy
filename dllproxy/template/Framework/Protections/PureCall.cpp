#include "Protections/PureCall.hpp"

#include "Exception.hpp"

Protections::PureCall::PureCall():
	m_previous_handler(_set_purecall_handler(handler))
{
}

Protections::PureCall::~PureCall()
{
	try
	{
		_set_purecall_handler(m_previous_handler);
	}
	catch (...)
	{
	}
}

void Protections::PureCall::handler()
{
	throw CriticalException();
}
