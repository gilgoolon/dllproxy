#include "AbortBehavior.hpp"

static constexpr unsigned int DISABLE = 0;

Protections::AbortBehavior::AbortBehavior():
	m_previous_flags(_set_abort_behavior(DISABLE, ALL_OPTIONS))
{
}

Protections::AbortBehavior::~AbortBehavior()
{
	try
	{
		_set_abort_behavior(m_previous_flags, ALL_OPTIONS);
	}
	catch (...)
	{
	}
}
