#pragma once
#include "EntryPointProtector.hpp"
#include "ErrorMode.hpp"
#include "InvalidParameter.hpp"
#include "PureCall.hpp"

namespace Protections
{
class LibraryProtector final
{
public:
	explicit LibraryProtector() = default;
	~LibraryProtector() = default;
	LibraryProtector(const LibraryProtector&) = delete;
	LibraryProtector& operator=(const LibraryProtector&) = delete;
	LibraryProtector(LibraryProtector&&) = delete;
	LibraryProtector& operator=(LibraryProtector&&) = delete;

private:
	EntryPointProtector m_entry_point_protector;
	InvalidParameter m_invalid_parameter;
	PureCall m_pure_call;
	ErrorMode m_error_mode;
};
}
