#pragma once
#include "Event.hpp"
#include "IRunner.hpp"

class Worker final : public IRunner
{
public:
	explicit Worker(std::shared_ptr<Event> quit_event);
	~Worker() override = default;
	Worker(const Worker&) = delete;
	Worker& operator=(const Worker&) = delete;
	Worker(Worker&&) = delete;
	Worker& operator=(Worker&&) = delete;

	void run() override;

private:
	std::shared_ptr<Event> m_quit_event;
};
