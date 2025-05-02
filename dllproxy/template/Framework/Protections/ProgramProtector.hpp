#pragma once
#include "AbortBehavior.hpp"
#include "LibraryProtector.hpp"
#include "TerminationHandler.hpp"

namespace Protections
{
class ProgramProtector final
{
public:
	explicit ProgramProtector() = default;
	~ProgramProtector() = default;
	ProgramProtector(const ProgramProtector&) = delete;
	ProgramProtector& operator=(const ProgramProtector&) = delete;
	ProgramProtector(ProgramProtector&&) = delete;
	ProgramProtector& operator=(ProgramProtector&&) = delete;

private:
	LibraryProtector m_library_protector;
	AbortBehavior m_abort_behavior;
	TerminationHandler m_terminate_handler;
};
}
