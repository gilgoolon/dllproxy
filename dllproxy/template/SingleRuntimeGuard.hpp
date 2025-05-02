#pragma once
#include "Mutex.hpp"

class SingleRuntimeGuard final
{
public:
	explicit SingleRuntimeGuard(const std::wstring& guid);
	~SingleRuntimeGuard() = default;
	SingleRuntimeGuard(const SingleRuntimeGuard&) = delete;
	SingleRuntimeGuard& operator=(const SingleRuntimeGuard&) = delete;
	SingleRuntimeGuard(SingleRuntimeGuard&&) = delete;
	SingleRuntimeGuard& operator=(SingleRuntimeGuard&&) = delete;

private:
	Mutex m_mutex;
};
