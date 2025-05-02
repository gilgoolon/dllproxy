#pragma once
#include <cstdlib>

namespace Protections
{
class PureCall final
{
public:
	explicit PureCall();
	~PureCall();
	PureCall(const PureCall&) = delete;
	PureCall& operator=(const PureCall&) = delete;
	PureCall(PureCall&&) = delete;
	PureCall& operator=(PureCall&&) = delete;

private:
	_purecall_handler m_previous_handler;

	[[noreturn]] static void __cdecl handler();
};
}
