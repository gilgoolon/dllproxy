#pragma once
#include <memory>

class IRunner
{
public:
	using Ptr = std::unique_ptr<IRunner>;

	explicit IRunner() = default;
	virtual ~IRunner() = default;
	IRunner(const IRunner&) = delete;
	IRunner& operator=(const IRunner&) = delete;
	IRunner(IRunner&&) = delete;
	IRunner& operator=(IRunner&&) = delete;

	virtual void run() = 0;
};
