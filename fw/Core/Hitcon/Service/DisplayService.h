#ifndef SERVICE_DISPLAY_SERVICE_H_
#define SERVICE_DISPLAY_SERVICE_H_

#include <stddef.h>
#include <stdint.h>
#include <Util/callback.h>
#include <Service/DisplayInfo.h>
#include <Service/Sched/Task.h>

using namespace hitcon::service::sched;

namespace hitcon {
typedef struct CB_Param{
  void* p1;
  void* p2;
} request_cb_param ;
class DisplayService {
  public:
    DisplayService();

    // Init should:
    // - Setup TIM2 to run at 9.5kHz.
    // - Setup TIM2_CH1 to fire DMA trigger.
    // - Setup DMA1 CH5 to write to PB GPIO.
    void Init();

    // This callback will be called whenever DisplayService wants to pull a
    // set of frames from the upper layer.
    // The callback should call PopulateFrames().
    void SetRequestFrameCallback(callback_t callback, void* callback_arg1);

    // After RequestFrame callback is triggered, this should be called by upper
    // layer to send frame to DisplayService. Each call should contain
    // DISPLAY_FRAME_BATCH of frames.
    void PopulateFrames(uint8_t* buffer);

    // 0-10
    void SetBrightness(uint8_t brightness);

    void* request_frame_callback_arg1;
    Task task;
  private:
    callback_t request_frame_callback;
    uint8_t current_buffer_index;
    uint32_t double_buffer[DISPLAY_FRAME_SIZE*DISPLAY_FRAME_BATCH*2];

    void cb(request_cb_param* arg) {
    	request_frame_callback(arg->p1, arg->p2);

        if(current_buffer_index == 0)
          current_buffer_index = 1;
        else
          current_buffer_index = 0;
    }
};

#ifndef SERVICE_DISPLAY_SERVICE_CC_
extern DisplayService g_display_service;
#endif

}  // namespace hitcon

#endif  // #ifndef SERVICE_DISPLAY_SERVICE_H_
