#include <Logic/keccak.h>
#include <Service/HashService.h>
#include <Service/Sched/Task.h>

using namespace hitcon::service::sched;
using namespace hitcon::hash::internal;

namespace hitcon {

namespace hash {

HashService g_hash_service;

namespace internal {

HashStatus::HashStatus() { Init(); }

void HashStatus::Init() {
  progress = 0;
  round = 0;
  state = kUpdateState;
}

void HashStatus::NewState(enum state state) {
  this->state = state;
  progress = 0;
  round = 0;
}

ServiceContext::ServiceContext()
    : message(nullptr), len(0), callback(nullptr), callbackArg1(nullptr) {}

void ServiceContext::Init(uint8_t const *message, size_t len,
                          callback_t callback, void *callbackArg1) {
  this->message = message;
  this->len = len;
  this->callback = callback;
  this->callbackArg1 = callbackArg1;
}

}  // namespace internal

void HashService::Init() { scheduler.Queue(&hashTask, nullptr); }

bool HashService::StartHash(uint8_t const *message, size_t len,
                            callback_t callback, void *callbackArg1) {
  if (hashTask.IsEnabled()) return false;
  // TODO: remove this restriction. HashService should support messages of all
  // sizes.
  if (len % 8) return false;
  hashTask.Enable();
  status.Init();
  serviceContext.Init(message, len, callback, callbackArg1);
  sha3_Init(&sha3Context, SHA3_BIT_SIZE);
  return true;
}

void HashService::doHash(void *unused) {
  switch (status.state) {
    case status.kUpdateState:
      doHashUpdate();
      break;
    case status.kFinalizeState:
      doHashFinalize();
      break;
    case status.kDoneState:
      doHashDone();
      break;
  }
}

void HashService::doHashUpdate() {
  // TODO: the performance of UpdateWord can be optimized.
  // sha3_UpdateWord_split often does a "fast return", so we can analyze how
  // much each "fast return" takes, and do multiple of them each round.
  status.round = sha3_UpdateWord_split(
      &sha3Context, serviceContext.message + status.progress, status.round);
  if (status.round == 0) {
    status.progress += 8;
  }

  if (status.progress == serviceContext.len) {
    status.NewState(status.kFinalizeState);
  }
}

void HashService::doHashFinalize() {
  uint8_t *digest = (uint8_t *)sha3_Finalize_split(&sha3Context, status.round);
  if (++status.round == KECCAK_ROUNDS + 2) {
    result.digest = digest;
    result.size = SHA3_BIT_SIZE / 8;
    status.NewState(status.kDoneState);
  }
}

void HashService::doHashDone() {
  serviceContext.callback(serviceContext.callbackArg1, &result);
  hashTask.Disable();
}

HashService::HashService()
    : hashTask(880, (task_callback_t)&HashService::doHash, (void *)this, 0) {}

}  // namespace hash

}  // namespace hitcon