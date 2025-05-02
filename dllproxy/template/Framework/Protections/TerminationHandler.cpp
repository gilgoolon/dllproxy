#include "Protections/TerminationHandler.hpp"

#include "Exception.hpp"

TerminationHandler::TerminationHandler():
	m_previous_handler(set_terminate(handler))
{
}

TerminationHandler::~TerminationHandler()
{
	try
	{
		set_terminate(m_previous_handler);
	}
	catch (...)
	{
	}
}

void TerminationHandler::handler()
{
	throw CriticalException();
}
