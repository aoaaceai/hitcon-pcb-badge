#ifndef HITCON_SERVICE_SIGNED_PACKET_SERVICE_H_
#define HITCON_SERVICE_SIGNED_PACKET_SERVICE_H_

#include <Logic/EcLogic.h>
#include <Logic/IrController.h>
#include <Service/Sched/Scheduler.h>
#include <stdint.h>

namespace hitcon {

namespace signed_packet {

constexpr size_t MAX_PACKET_DATA_SIZE = 13;
constexpr size_t PACKET_QUEUE_SIZE = 4;

enum PacketStatus : uint8_t {
  kFree,
  kWaitSignStart,
  kWaitSignDone,
  kWaitTransmit,
  kWaitVerStart,
  kWaitVerDone,
  kWaitReceive
};

struct SignedPacket {
  PacketStatus status;
  packet_type type;
  size_t signatureOffset;
  uint8_t data[MAX_PACKET_DATA_SIZE];
  size_t dataSize;
  uint8_t sig[ECC_SIGNATURE_SIZE];

  SignedPacket();
};

}  // namespace signed_packet

class SignedPacketService {
 public:
  /**
   * Signs the data produced from games and send it out.
   */
  bool SignAndSendData(packet_type packetType, const uint8_t *data,
                       size_t size);
  bool VerifyAndReceivePacket(hitcon::ir::IrPacket *irpacket);

  SignedPacketService();
  void Init();

 private:
  hitcon::service::sched::PeriodicTask sigRoutineTask;
  hitcon::service::sched::PeriodicTask verRoutineTask;
  size_t signingPacketId;
  size_t verifyingPacketId;
  signed_packet::SignedPacket
      sig_packet_queue_[signed_packet::PACKET_QUEUE_SIZE];
  signed_packet::SignedPacket
      ver_packet_queue_[signed_packet::PACKET_QUEUE_SIZE];

  void VerRoutineFunc();
  void SigRoutineFunc();
  void OnPacketVerFinish(void *isValid);
  void ReceivePacket(signed_packet::SignedPacket &packet);
  void OnPacketSignFinish(hitcon::ecc::Signature *signature);
  bool FindPacketOfState(signed_packet::SignedPacket *queue, signed_packet::PacketStatus status, size_t &packetId);
};

extern SignedPacketService g_signed_packet_service;

}  // namespace hitcon

#endif  // HITCON_SERVICE_SIGNED_PACKET_SERVICE_H_