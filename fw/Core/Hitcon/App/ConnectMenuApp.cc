#include <App/ConnectMenuApp.h>
#include <App/TamaApp.h>
#include <Logic/BadgeController.h>

namespace hitcon {

ConnectMenuApp connect_menu;
ConnectLegacyMenuApp connect_legacy_menu;
ConnectBasestnMenuApp connect_basestn_menu;

void ConnectBasestnMenuApp::OnEntry() {
  basestn_available_ = false;
  // Note that we do not call MenuApp::OnEntry() because the IR-XB bridge
  // is still working.
}

void ConnectBasestnMenuApp::NotifyIrXbFinished() {
  // Switch over to Tama and run heal.
  hitcon::app::tama::SetBaseStationConnect();
  // TamaHeal() is called by OnEntry() in base station mode.
  hitcon::badge_controller.change_app(&hitcon::app::tama::tama_app);

  // We don't actually use the base station menu.
  //if (!basestn_available_) {
  //  basestn_available_ = true;
  //  MenuApp::OnEntry();
  //}
}

void ConnectBasestnMenuApp::OnButton(button_t button) {
  if (!basestn_available_) return;
  MenuApp::OnButton(button);
}
}  // namespace hitcon
