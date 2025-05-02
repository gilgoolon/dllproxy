#pragma once

#include <memory>
#include <Windows.h>

struct HandleCloser
{
	void operator()(HANDLE handle) const;
};

using ScopedHandle = std::unique_ptr<std::remove_pointer_t<HANDLE>, HandleCloser>;
