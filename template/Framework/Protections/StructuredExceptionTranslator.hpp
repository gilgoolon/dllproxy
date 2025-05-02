#pragma once
#include <eh.h>
#include <Windows.h>

namespace Protections
{
class StructuredExceptionTranslator final
{
public:
	explicit StructuredExceptionTranslator();
	~StructuredExceptionTranslator();
	StructuredExceptionTranslator(const StructuredExceptionTranslator&) = delete;
	StructuredExceptionTranslator& operator=(const StructuredExceptionTranslator&) = delete;
	StructuredExceptionTranslator(StructuredExceptionTranslator&&) = delete;
	StructuredExceptionTranslator& operator=(StructuredExceptionTranslator&&) = delete;

private:
	_se_translator_function m_previous_translator;

	[[noreturn]] static void translator(unsigned int code, _EXCEPTION_POINTERS* ep);
};
}
