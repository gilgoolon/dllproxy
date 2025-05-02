#pragma once
#include "Exception.hpp"

#include <string>
#include <Windows.h>

class Library final
{
public:
	explicit Library(const std::wstring& path);
	~Library();
	Library(const Library&) = delete;
	Library& operator=(const Library&) = delete;
	Library(Library&&) = delete;
	Library& operator=(Library&&) = delete;

	template <typename ReturnType, typename... ParameterTypes>
	ReturnType call(uint16_t ordinal, ParameterTypes... parameters);

private:
	HMODULE m_handle;

	[[nodiscard]] static HMODULE load_library(const std::wstring& path);
};

template <typename ReturnType, typename... ParameterTypes>
ReturnType Library::call(const uint16_t ordinal, ParameterTypes... parameters)
{
	const FARPROC proc = GetProcAddress(m_handle, MAKEINTRESOURCEA(ordinal));

	if (proc == nullptr)
	{
		throw WinApiException(ErrorCode::FAILED_LIBRARY_GET);
	}

	using FunctionPointer = ReturnType(__cdecl*)(ParameterTypes...);

	return reinterpret_cast<FunctionPointer>(proc)(std::forward<ParameterTypes>(parameters)...);
}
