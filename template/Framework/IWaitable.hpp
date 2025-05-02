#pragma once
#include <chrono>
#include <cstdint>
#include <optional>
#include <Windows.h>

enum class WaitStatus : uint32_t
{
	FINISHED = 0,
	OBJECT_CLOSED,
	TIMEOUT,
	FAILED,
};

struct WaitResult final
{
	WaitStatus status;
	std::optional<uint32_t> triggered_object;
};

class IWaitable
{
public:
	explicit IWaitable() = default;
	virtual ~IWaitable() = default;
	IWaitable(const IWaitable&) = delete;
	IWaitable& operator=(const IWaitable&) = delete;
	IWaitable(IWaitable&&) = delete;
	IWaitable& operator=(IWaitable&&) = delete;

	[[nodiscard]] virtual HANDLE handle() const = 0;

	[[nodiscard]] WaitStatus wait(std::chrono::milliseconds timeout) const;

	static void sleep(std::chrono::milliseconds duration);

	[[nodiscard]] static WaitResult wait_for_any(const std::vector<std::shared_ptr<IWaitable>>& objects,
	                                             std::chrono::milliseconds timeout);

	[[nodiscard]] static WaitResult wait_for_all(const std::vector<std::shared_ptr<IWaitable>>& objects,
	                                             std::chrono::milliseconds timeout);

private:
	[[nodiscard]] static WaitResult wait_for_multiple(const std::vector<std::shared_ptr<IWaitable>>& objects,
	                                                  std::chrono::milliseconds timeout,
	                                                  bool wait_all);
};
