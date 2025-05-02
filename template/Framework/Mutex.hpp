#pragma once
#include "IWaitable.hpp"
#include "ScopedHandle.hpp"

#include <string>

class Mutex final : public IWaitable
{
public:
	explicit Mutex(const std::wstring& name);
	~Mutex() override;
	Mutex(const Mutex&) = delete;
	Mutex& operator=(const Mutex&) = delete;
	Mutex(Mutex&&) = delete;
	Mutex& operator=(Mutex&&) = delete;

private:
	ScopedHandle m_handle;

	[[nodiscard]] static HANDLE create_mutex(const std::wstring& name);

	[[nodiscard]] HANDLE handle() const override;
};
