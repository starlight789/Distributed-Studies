#ifndef CEPH_RGW_MIRRORING_H
#define CEPH_RGW_MIRRORING_H

#include <map>
#include <string>
#include <iostream>
#include <include/types.h>

#include "include/str_list.h"
#include "rgw_common.h"
#include "common/ceph_json.h"


class MirroringCustomHeader {
public:
  string name;
  string value;

  MirroringCustomHeader() {}
  virtual ~MirroringCustomHeader() {}

  void decode_json(JSONObj *obj);
  void dump(Formatter *f) const;
  void encode(bufferlist& bl) const {
     ENCODE_START(1, 1, bl);
     encode(name, bl);
     encode(value, bl);
     ENCODE_FINISH(bl);
   }
   void decode(bufferlist::iterator& bl) {
     DECODE_START_LEGACY_COMPAT_LEN(1, 1, 1, bl);
     decode(name, bl);
     decode(value, bl);
     DECODE_FINISH(bl);
   }
};
WRITE_CLASS_ENCODER(MirroringCustomHeader)


class MirroringConfiguration {
public:
  string prefix;
  string source_url;
  bool pass_querystring;
  string mode = "fetch";
  string storage_class; // ?
  list<string> pass_headers;
  list<string> ignore_headers;
  list<MirroringCustomHeader> custom_headers;

  MirroringConfiguration() {}
  virtual ~MirroringConfiguration() {}

  void encode(bufferlist& bl) const {
    ENCODE_START(1, 1, bl);
    encode(prefix, bl);
    encode(source_url, bl);
    encode(pass_querystring, bl);
    encode(mode, bl);
    encode(storage_class, bl);
    encode(pass_headers, bl);
    encode(ignore_headers, bl);
    encode(custom_headers, bl);
    ENCODE_FINISH(bl);
  }
  void decode(bufferlist::iterator& bl) {
    DECODE_START_LEGACY_COMPAT_LEN(1, 1, 1, bl);
    decode(prefix, bl);
    decode(source_url, bl);
    decode(pass_querystring, bl);
    decode(mode, bl);
    decode(storage_class, bl);
    decode(pass_headers, bl);
    decode(ignore_headers, bl);
    decode(custom_headers, bl);
    DECODE_FINISH(bl);
  }
  void dump(Formatter *f) const;
  void decode_json(JSONObj *obj);
};
WRITE_CLASS_ENCODER(MirroringConfiguration)

class RGWMirroringConfiguration
{
private:

  bool is_blacklists_refused(string& endpoint, vector<string>& blacklists);
public:
  list<MirroringConfiguration> configurations;
  static map<string, bool> unallowed_headers;

  RGWMirroringConfiguration() {}
  virtual ~RGWMirroringConfiguration() {}

//  int get_perm(string& id, int perm_mask);
//  int get_group_perm(ACLGroupTypeEnum group, int perm_mask);
  void encode(bufferlist& bl) const {
    ENCODE_START(1, 1, bl);
    encode(configurations, bl);
    ENCODE_FINISH(bl);
  }
  void decode(bufferlist::iterator& bl) {
    DECODE_START_LEGACY_COMPAT_LEN(1, 1, 1, bl);
    decode(configurations, bl);
    DECODE_FINISH(bl);
  }
  void dump(Formatter *f) const;
  void decode_json(JSONObj *obj);

  int is_valid(string url_blacklist);
};
WRITE_CLASS_ENCODER(RGWMirroringConfiguration)

namespace rgw::mirror {

void generate_mirror_headers(req_state* s,
                             MirroringConfiguration& config,
                             map<string, string>& headers);
}  /* namespace rgw::mirror */

#endif /* CEPH_RGW_MIRRORING_H */
