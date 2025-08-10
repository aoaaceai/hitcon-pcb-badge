#include <Service/Sched/Checks.h>
#include <Service/XBoardService.h>

using namespace hitcon::service::sched;
using namespace hitcon::service::xboard;

namespace hitcon {
namespace service {
namespace xboard {

XBoardService g_xboard_service;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpmf-conversions"
XBoardService::XBoardService()
    : _on_rx_callback(nullptr), _on_rx_callback_arg1(nullptr),
      _rx_task(480, (callback_t)&XBoardService::OnRxWrapper, this),
      _routine_task(490, (task_callback_t)&XBoardService::Routine, this, 10) {}
#pragma GCC diagnostic pop

void XBoardService::Init() {
  scheduler.Queue(&_routine_task, nullptr);
  scheduler.EnablePeriodic(&_routine_task);

  TriggerRx();
}

void XBoardService::QueueDataForTx(uint8_t* data, size_t len) {
  for (size_t i = 0; i < len; i++) {
    if ((_tx_buffer_tail + 1) % kTxBufferSize == _tx_buffer_head) {
      // Overflow, we're dropping data.
      AssertOverflow();
      break;
    }
    _tx_buffer[_tx_buffer_tail] = data[i];
    _tx_buffer_tail = (_tx_buffer_tail + 1) % kTxBufferSize;
  }
}

void XBoardService::SetOnByteRx(callback_t callback, void* callback_arg1) {
  _on_rx_callback = callback;
  _on_rx_callback_arg1 = callback_arg1;
}

void XBoardService::NotifyTxFinish() {
  _tx_busy = false;
  if (_tx_buffer_head != _tx_buffer_tail && !_tx_busy) {
    _tx_busy = true;
    HAL_UART_Transmit_IT(_huart, &_tx_buffer[_tx_buffer_head], 1);
    _tx_buffer_head = (_tx_buffer_head + 1) % kTxBufferSize;
  }
}

void XBoardService::NotifyRxFinish() {
  if (_rx_task_busy) {
    // Overflow, we dropped a byte.
  } else {
    if (_on_rx_callback) {
      _rx_task_busy = true;
      OnRxWrapper(reinterpret_cast<void*>(static_cast<size_t>(rx_byte_)));
      /*scheduler.Queue(&_rx_task,
                      reinterpret_cast<void*>(static_cast<size_t>(rx_byte_)));*/
    }
  }
  TriggerRx();
}

// private function
void XBoardService::Routine(void*) {
  if (_tx_buffer_head != _tx_buffer_tail && !_tx_busy) {
    _tx_busy = true;
    HAL_UART_Transmit_IT(_huart, &_tx_buffer[_tx_buffer_head], 1);
    _tx_buffer_head = (_tx_buffer_head + 1) % kTxBufferSize;
  }

  if (_huart->RxState == HAL_UART_STATE_BUSY_RX) {
    // We're receiving properly.
    _rx_stopped_count = 0;
  } else {
    _rx_stopped_count++;
    if (_rx_stopped_count > 10) {
      TriggerRx();
      _rx_stopped_count = 0;
    }
  }
}

void XBoardService::TriggerRx() { HAL_UART_Receive_IT(_huart, &rx_byte_, 1); }

void XBoardService::OnRxWrapper(void* arg2) {
  _rx_task_busy = false;
  if (_on_rx_callback) {
    _on_rx_callback(_on_rx_callback_arg1, arg2);
  }
}

}  // namespace xboard
}  // namespace service
}  // namespace hitcon

void HAL_UART_TxCpltCallback(UART_HandleTypeDef* huart) {
  g_xboard_service.NotifyTxFinish();
}

void HAL_UART_RxCpltCallback(UART_HandleTypeDef* huart) {
  g_xboard_service.NotifyRxFinish();
}

void HAL_UART_ErrorCallback(UART_HandleTypeDef* huart) {
  uint32_t osrv = g_xboard_service._huart->Instance->SR;
  g_xboard_service._huart->Instance->SR = 0x00;
  uint32_t srv = g_xboard_service._huart->Instance->SR;
  uint32_t drv = g_xboard_service._huart->Instance->DR;
  srv = g_xboard_service._huart->Instance->SR;
  g_xboard_service.sr_accu |= osrv & (~srv);
  g_xboard_service.sr_clear++;
}

void HAL_UART_AbortCpltCallback(UART_HandleTypeDef* huart) { my_assert(false); }

void HAL_UART_AbortReceiveCpltCallback(UART_HandleTypeDef* huart) {
  my_assert(false);
}
