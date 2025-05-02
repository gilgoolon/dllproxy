#pragma once
#include <cstdlib>

namespace Protections
{
class AbortBehavior final
{
public:
	explicit AbortBehavior();
	~AbortBehavior();
	AbortBehavior(const AbortBehavior&) = delete;
	AbortBehavior& operator=(const AbortBehavior&) = delete;
	AbortBehavior(AbortBehavior&&) = delete;
	AbortBehavior& operator=(AbortBehavior&&) = delete;

private:
	unsigned int m_previous_flags;
	static constexpr unsigned int ALL_OPTIONS = _WRITE_ABORT_MSG | _CALL_REPORTFAULT;
};
}
