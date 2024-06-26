/*
 * Task.h
 *
 *  Created on: May 19, 2024
 *      Author: aoaaceai
 */

#ifndef HITCON_SERVICE_SCHED_TASK_H_
#define HITCON_SERVICE_SCHED_TASK_H_

namespace hitcon {
namespace service {
namespace sched {

typedef void (*task_callback_t)(void *thisptr, void *arg);

class Task {
protected:
	unsigned prio;
	task_callback_t callback;
	void *thisptr, *arg;
public:
	// For prio, see Scheduler.h
	constexpr Task(unsigned prio, task_callback_t callback, void *thisptr) : prio(prio), callback(callback), thisptr(thisptr), arg(nullptr) {
	}

	virtual ~Task();
	bool operator ==(Task &task);
	virtual bool operator <(Task &task);
	void Run();
	void SetArg(void *arg);
};

} /* namespace sched */
} /* namespcae service */
} /* namespace hitcon */

#endif /* HITCON_SERVICE_SCHED_TASK_H_ */
