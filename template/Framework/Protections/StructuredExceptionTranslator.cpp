#include "Protections/StructuredExceptionTranslator.hpp"

#include "Exception.hpp"

#include <eh.h>

Protections::StructuredExceptionTranslator::StructuredExceptionTranslator():
	m_previous_translator(_set_se_translator(translator))
{
}

Protections::StructuredExceptionTranslator::~StructuredExceptionTranslator()
{
	try
	{
		_set_se_translator(m_previous_translator);
	}
	catch (...)
	{
	}
}

void Protections::StructuredExceptionTranslator::translator([[maybe_unused]] const unsigned int code,
                                                            [[maybe_unused]] _EXCEPTION_POINTERS* const ep)
{
	throw CriticalException();
}
