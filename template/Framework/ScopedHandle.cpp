#include "ScopedHandle.hpp"

void HandleCloser::operator()(const HANDLE handle) const
{
	try
	{
		if (CloseHandle(handle) == FALSE)
		{
		}
	}
	catch (...)
	{
	}
}
