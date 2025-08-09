/*
 * Scheduler.cpp
 *
 *  Created on: May 19, 2024
 *      Author: aoaaceai
 */

#include "Scheduler.h"

#include <Service/Sched/Checks.h>

#include "SysTimer.h"
#include "main.h"

namespace hitcon {
namespace service {
namespace sched {

Scheduler scheduler;

Scheduler::Scheduler() {}

Scheduler::~Scheduler() {}

bool Scheduler::Queue(Task *task, void *arg) {
  my_assert(task);
  task->SetArg(arg);
  bool result = true;
  __disable_irq();
  if (tasksAddQueue.PushBack(task)) {
    task->EnterQueue();
  }
  else {
    // Overflow, we need to drop this request.
    result = false;
    AssertOverflow();
  }
  __enable_irq();
  return result;
}

bool Scheduler::Queue(DelayedTask *task, void *arg) {
  my_assert(task);
  task->SetArg(arg);
  bool result = true;
  __disable_irq();
  if (delayedTasksAddQueue.PushBack(task)) {
    task->EnterQueue();
  }
  else {
    // Overflow, we need to drop this request.
    result = false;
    AssertOverflow();
  }
  __enable_irq();
  return result;
}

bool Scheduler::Queue(PeriodicTask *task, void *arg) {
  my_assert(task);
  task->SetArg(arg);
  return disabledPeriodicTasks.Add(task);
}

bool Scheduler::EnablePeriodic(PeriodicTask *task) {
  if (!disabledPeriodicTasks.Remove(task)) {
    AssertOverflow();
    return false;
  }
  if (!enabledPeriodicTasks.Add(task)) {
    AssertOverflow();
    return false;
  }
  if (currentTask != task) {
    if (delayedTasks.Add(task))
      task->EnterQueue();
    else {
      // Heap is full, we need to drop this request.
      AssertOverflow();
      return false;
    }
  }
  task->Enable();
  return true;
}

bool Scheduler::DisablePeriodic(PeriodicTask *task) {
  if (!enabledPeriodicTasks.Remove(task)) {
    AssertOverflow();
    return false;
  }
  if (!disabledPeriodicTasks.Add(task)) {
    AssertOverflow();
    return false;
  }
  DelayedHouseKeeping();
  bool removed = tasks.Remove(task) || delayedTasks.Remove(task);
  if (removed)
    task->ExitQueue();
  task->Disable();
  return true;
}

void Scheduler::DelayedHouseKeeping() {
  // Handle all Queue operations.
  while (!tasksAddQueue.IsEmpty()) {
    bool ret = tasks.Add(tasksAddQueue.Front());
    if (!ret) {
      // Heap is full.
      AssertOverflow();
      break;
    }
    tasksAddQueue.PopFront();
  }
  while (!delayedTasksAddQueue.IsEmpty()) {
    bool ret = delayedTasks.Add(delayedTasksAddQueue.Front());
    if (!ret) {
      // Heap is full.
      AssertOverflow();
      break;
    }
    delayedTasksAddQueue.PopFront();
  }
  unsigned now = SysTimer::GetTime();
  while (delayedTasks.size()) {
    DelayedTask &top = delayedTasks.Top();
    unsigned wake = top.WakeTime();
    if (wake > now) break;
    bool ret = delayedTasks.Remove(&top);
    if (!ret) {
      AssertOverflow();
    } else {
      top.ExitQueue();
    }
    ret = tasks.Add(&top);
    if (!ret) {
      AssertOverflow();
    } else {
      top.EnterQueue();
    }
  }
}

void Scheduler::Run() {
  while (1) {
    DelayedHouseKeeping();
    if (!tasks.size()) continue;
    Task &top = tasks.Top();
    bool ret = tasks.Remove(&top);
    if (!ret) {
      AssertOverflow();
    } else {
      top.ExitQueue();
    }
    totalTasks++;
    TaskRecord record;
    record.startTime = SysTimer::GetTime();
    record.task = &top;

    currentTask = &top;
    top.Run();
    currentTask = nullptr;
    record.endTime = SysTimer::GetTime();
    taskRecords[record_index] = record;
    record_index++;
    if (record_index == kRecordSize) record_index = 0;
  }
}

} /* namespace sched */
} /* namespace service */
} /* namespace hitcon */
