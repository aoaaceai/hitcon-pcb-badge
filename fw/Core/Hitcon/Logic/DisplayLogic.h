#ifndef SERVICE_DISPLAY_LOGIC_H_
#define SERVICE_DISPLAY_LOGIC_H_

#include <stddef.h>
#include <stdint.h>
#include <Util/callback.h>
#include <Service/DisplayService.h>
#include <Service/DisplayInfo.h>
#include <Logic/Display/display.h>

namespace hitcon {

class DisplayLogic {
 public:
  // Don't place too complicated initialization in constructor because this
  // might be a global variable.
  DisplayLogic();

  // This is called to init DisplayLogic().
  void Init();

  // This is called by DisplayService to request for frames.
  void OnRequestFrame(void* unused);
 private:
  uint8_t buffer_[DISPLAY_HEIGHT*DISPLAY_WIDTH*DISPLAY_FRAME_BATCH];

  // How many frames have we pushed to DisplayService?
  int frame_;
};
extern DisplayLogic g_display_logic;
}  // namespace hitcon

#endif  // #ifndef SERVICE_DISPLAY_SERVICE_H_
