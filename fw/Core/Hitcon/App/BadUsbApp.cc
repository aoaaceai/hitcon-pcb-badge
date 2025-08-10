#include <App/BadUsbApp.h>
#include <App/UsbMenuApp.h>
#include <Logic/BadgeController.h>
#include <Logic/UsbLogic.h>

namespace hitcon {
namespace usb {
BadUsbApp bad_usb_app;

BadUsbApp::BadUsbApp() {}

void BadUsbApp::OnEntry() {
  _skip_crc = false;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpmf-conversions"
  g_usb_logic.RunScript((callback_t)&BadUsbApp::OnScriptFinished, this,
                        (callback_t)&BadUsbApp::OnScriptError, this, true);
#pragma GCC diagnostic pop
}

void BadUsbApp::OnExit() { g_usb_logic.StopScript(); }

void BadUsbApp::OnButton(button_t button) {
  switch (button & BUTTON_VALUE_MASK) {
    case BUTTON_BACK:
      badge_controller.BackToMenu(this);
      break;
    case BUTTON_OK:
      if (_skip_crc) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpmf-conversions"
        g_usb_logic.RunScript((callback_t)&BadUsbApp::OnScriptFinished, this,
                              (callback_t)&BadUsbApp::OnScriptError, this,
                              false);
#pragma GCC diagnostic pop
      }
      break;
  }
}

void BadUsbApp::OnScriptFinished(void* unsed) {
  badge_controller.change_app(&usb_menu);
}

void BadUsbApp::OnScriptError(void* msg) {
  _skip_crc = true;
  if (msg != nullptr) {
    display_set_mode_scroll_text(reinterpret_cast<char*>(msg));
  } else {
    display_set_mode_scroll_text("checksum fail");
  }
}

}  // namespace usb
}  // namespace hitcon