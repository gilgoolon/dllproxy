#pragma once
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

private:
	HMODULE m_handle;

	[[nodiscard]] static HMODULE load_library(const std::wstring& path);
};
