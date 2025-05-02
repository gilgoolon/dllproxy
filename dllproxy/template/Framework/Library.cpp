#include "Library.hpp"

#include "Exception.hpp"

#include <stdexcept>

Library::Library(const std::wstring& path):
	m_handle(load_library(path))
{
}

Library::~Library()
{
	try
	{
		FreeLibrary(m_handle);
	}
	catch (...)
	{
	}
}

HMODULE Library::load_library(const std::wstring& path)
{
	const HMODULE result = LoadLibraryW(path.c_str());
	if (result == nullptr)
	{
		throw WinApiException(ErrorCode::FAILED_LIBRARY_LOAD);
	}
	return result;
}
