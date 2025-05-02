#pragma once

namespace Protections
{
class ErrorMode final
{
public:
	explicit ErrorMode();
	~ErrorMode();
	ErrorMode(const ErrorMode&) = delete;
	ErrorMode& operator=(const ErrorMode&) = delete;
	ErrorMode(ErrorMode&&) = delete;
	ErrorMode& operator=(ErrorMode&&) = delete;

private:
	int m_previous_mode;
};
}
