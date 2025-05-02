#pragma once
#include <cstdlib>

namespace Protections
{
class InvalidParameter final
{
public:
	explicit InvalidParameter();
	~InvalidParameter();
	InvalidParameter(const InvalidParameter&) = delete;
	InvalidParameter& operator=(const InvalidParameter&) = delete;
	InvalidParameter(InvalidParameter&&) = delete;
	InvalidParameter& operator=(InvalidParameter&&) = delete;

private:
	_invalid_parameter_handler m_prev_handler;

	[[noreturn]] static void __cdecl handler(const wchar_t* expression,
	                                         const wchar_t* function,
	                                         const wchar_t* file,
	                                         unsigned int line,
	                                         uintptr_t reserved);
};
}
