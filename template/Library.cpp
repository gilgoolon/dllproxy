#include "Library.hpp"

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
		throw std::runtime_error("failed to load library");
	}
	return result;
}
