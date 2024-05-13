// -*- mode:C++; tab-width:4; c-basic-offset:4; indent-tabs-mode:t -*-
// vim: ts=4 sw=4 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Author: Liu Peng <liupeng37@baidu.com>
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation.  See file COPYING.
 *
 */

#ifndef CEPH_MOSDSLOWDISK_H
#define CEPH_MOSDSLOWDISK_H

#include "messages/PaxosServiceMessage.h"

class MOSDSlowDisk : public PaxosServiceMessage {
 public:
    epoch_t map_epoch = 0;
    uuid_d fsid;
    map<string, string> metadata;

private:
    ~MOSDSlowDisk() {}

public:
    MOSDSlowDisk(epoch_t e, const uuid_d &fsid, const map<string, string>& s) :
        PaxosServiceMessage(MSG_OSD_SLOW_DISK, e), map_epoch(e),  fsid(fsid), metadata(s) { }
    MOSDSlowDisk() :
        PaxosServiceMessage(MSG_OSD_SLOW_DISK, 0) {}

public:
    void encode_payload(uint64_t features) {
        using ceph::encode;
        paxos_encode();
        encode(map_epoch, payload);
        encode(fsid, payload);
        encode(metadata, payload);
    }
    void decode_payload() {
        bufferlist::iterator p = payload.begin();
        paxos_decode(p);
        decode(map_epoch, p);
        decode(fsid, p);
        decode(metadata, p);
    }

    epoch_t get_epoch() const { return map_epoch; }
    const char *get_type_name() const { return "osd_slow_disk"; }
    void print(ostream &out) const {
      out << "osd_slow_disk(e" << map_epoch << " v  " << version
          << " fsid " << fsid << " metadata " << metadata << ")";
    }
};

#endif
