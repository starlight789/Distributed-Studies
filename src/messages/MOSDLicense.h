// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#ifndef CEPH_MOSDLICENSE_H
#define CEPH_MOSDLICENSE_H

#include "messages/PaxosServiceMessage.h"
#include "osd/OSDMap.h"

// tell the mon to update the license status.

class MOSDLicense : public PaxosServiceMessage {
 public:
  epoch_t map_epoch = 0;
  uint32_t state = 0;

private:
  ~MOSDLicense() {}

public:
  MOSDLicense(epoch_t e, unsigned s)
    : PaxosServiceMessage(MSG_OSD_LICENSE, e), map_epoch(e), state(s) { }
  MOSDLicense()
    : PaxosServiceMessage(MSG_OSD_LICENSE, 0) {}

public:
  void encode_payload(uint64_t features) {
    using ceph::encode;
    paxos_encode();
    encode(map_epoch, payload);
    encode(state, payload);
  }
  void decode_payload() {
    bufferlist::iterator p = payload.begin();
    paxos_decode(p);
    decode(map_epoch, p);
    decode(state, p);
  }

  const char *get_type_name() const { return "osd_license"; }
  void print(ostream &out) const {
    set<string> states;
    OSDMap::calc_state_set(state, states);
    out << "osd_license(e" << map_epoch << " " << states << " v" << version << ")";
  }

};

#endif
