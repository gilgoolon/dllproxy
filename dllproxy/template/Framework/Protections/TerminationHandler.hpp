#pragma once
#include <eh.h>

class TerminationHandler final
{
public:
	explicit TerminationHandler();
	~TerminationHandler();
	TerminationHandler(const TerminationHandler&) = delete;
	TerminationHandler& operator=(const TerminationHandler&) = delete;
	TerminationHandler(TerminationHandler&&) = delete;
	TerminationHandler& operator=(TerminationHandler&&) = delete;

private:
	terminate_handler m_previous_handler;

	static void __cdecl handler();
};
