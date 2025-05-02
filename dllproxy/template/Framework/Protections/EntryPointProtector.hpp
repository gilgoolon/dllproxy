#pragma once
#include "StructuredExceptionTranslator.hpp"
#include "UnhandledExceptionFilter.hpp"

namespace Protections
{
class EntryPointProtector final
{
public:
	explicit EntryPointProtector() = default;
	~EntryPointProtector() = default;
	EntryPointProtector(const EntryPointProtector&) = delete;
	EntryPointProtector& operator=(const EntryPointProtector&) = delete;
	EntryPointProtector(EntryPointProtector&&) = delete;
	EntryPointProtector& operator=(EntryPointProtector&&) = delete;

private:
	StructuredExceptionTranslator m_translator;
	UnhandledExceptionFilter m_filter;
};
}
