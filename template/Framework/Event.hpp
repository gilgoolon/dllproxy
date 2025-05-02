#pragma once
#include "IWaitable.hpp"
#include "ScopedHandle.hpp"

class Event final : public IWaitable
{
public:
	using Ptr = std::shared_ptr<Event>;

	enum class Type : uint32_t
	{
		MANUAL_RESET = FALSE,
		AUTO_RESET = TRUE,
	};

	static constexpr auto GLOBAL_NAMESPACE = L"Global/";

	explicit Event(const std::wstring& name);
	explicit Event(const std::wstring& name, Type type);
	explicit Event(Type type);
	~Event() override = default;
	Event(const Event&) = delete;
	Event& operator=(const Event&) = delete;
	Event(Event&&) = delete;
	Event& operator=(Event&&) = delete;

	[[nodiscard]] HANDLE handle() const override;

	void set();
	void unset();

private:
	[[nodiscard]] static HANDLE open_event(const std::wstring& name);

	[[nodiscard]] static HANDLE create_event(const std::wstring& name, Type type);

	ScopedHandle m_handle;
};
