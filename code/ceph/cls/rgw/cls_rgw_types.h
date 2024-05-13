// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#ifndef CEPH_CLS_RGW_TYPES_H
#define CEPH_CLS_RGW_TYPES_H

#include <boost/container/flat_map.hpp>
#include "common/ceph_time.h"
#include "common/Formatter.h"

#include "rgw/rgw_basic_types.h"

#define CEPH_RGW_REMOVE 'r'
#define CEPH_RGW_UPDATE 'u'
#define CEPH_RGW_TAG_TIMEOUT 120
#define CEPH_RGW_DIR_SUGGEST_LOG_OP  0x80
#define CEPH_RGW_DIR_SUGGEST_OP_MASK 0x7f

class JSONObj;

namespace ceph {
  class Formatter;
}
using ceph::operator <<;

using rgw_zone_set = std::set<std::string>;

enum RGWPendingState {
  CLS_RGW_STATE_PENDING_MODIFY = 0,
  CLS_RGW_STATE_COMPLETE       = 1,
  CLS_RGW_STATE_UNKNOWN        = 2,
};

enum RGWModifyOp {
  CLS_RGW_OP_ADD     = 0,
  CLS_RGW_OP_DEL     = 1,
  CLS_RGW_OP_CANCEL  = 2,
  CLS_RGW_OP_UNKNOWN = 3,
  CLS_RGW_OP_LINK_OLH        = 4,
  CLS_RGW_OP_LINK_OLH_DM     = 5, /* creation of delete marker */
  CLS_RGW_OP_UNLINK_INSTANCE = 6,
  CLS_RGW_OP_SYNCSTOP        = 7,
  CLS_RGW_OP_RESYNC          = 8,
};

enum RGWBILogFlags {
  RGW_BILOG_FLAG_VERSIONED_OP = 0x1,
};

enum RGWCheckMTimeType {
  CLS_RGW_CHECK_TIME_MTIME_EQ = 0,
  CLS_RGW_CHECK_TIME_MTIME_LT = 1,
  CLS_RGW_CHECK_TIME_MTIME_LE = 2,
  CLS_RGW_CHECK_TIME_MTIME_GT = 3,
  CLS_RGW_CHECK_TIME_MTIME_GE = 4,
};

enum RGWObjCategory {
  RGW_OBJ_CATEGORY_NONE      = 0,
  RGW_OBJ_CATEGORY_MAIN      = 1,
  RGW_OBJ_CATEGORY_SHADOW    = 2,
  RGW_OBJ_CATEGORY_MULTIMETA = 3,
};

#define ROUND_BLOCK_SIZE 4096

static inline uint64_t cls_rgw_get_rounded_size(uint64_t size)
{
  return (size + ROUND_BLOCK_SIZE - 1) & ~(ROUND_BLOCK_SIZE - 1);
}

/*
 * This takes a std::string that either wholly contains a delimiter or is a
 * path that ends with a delimiter and appends a new character to the
 * end such that when a we request bucket-index entries *after* this,
 * we'll get the next object after the "subdirectory". This works
 * because we append a '\xFF' charater, and no valid UTF-8 character
 * can contain that byte, so no valid entries can be skipped.
 */
inline void cls_rgw_append_max_charater(std::string& path) {
  // assert: ! path.empty()
  path.push_back('\xFF');
}

static const set<string> read_op_list = {
  "get_obj", "get_obj_tags", "list_buckets", "get_usage",
  "stat_account", "list_rgw", "list_bucket", "get_bucket_logging",
  "get_bucket_location", "get_bucket_versioning", "get_bucket_website", "get_bucket_namespace",
  "stat_bucket", "get_acls", "get_lifecycle", "get_cors",
  "get_request_payment", "list_multipart", "list_bucket_multiparts", "get_crossdomain_policy",
  "get_health_check", "get info", "get_obj_layout", "get_bucket_policy",
  "get_bucket_object_lock", "get_obj_retention", "get_obj_legal_hold", "get_bucket_meta_search",
  "get_cluster_stat", "list_user", "get_user_info", "get_quota_info",
  "get_period", "get_realm", "get_usage", "get_zonegroup_map",
  "get_zone_config", "get_metadata_log_status", "get_bucket_index_log_status", "get_data_changes_log_status",
  "get_role", "list_roles", "get_role_policy", "list_role_policies",
  "list_bucket_index_log", "bucket_index_log_info", "list_metadata_log", "get_metadata_log_info",
  "get_metadata_log_shard_info", "list_data_changes_log", "get_data_changes_log_info", "get_data_changes_log_shard_info",
  "opstate_list", "get_bucket_info", "get_policy", "list_metadata",
  "get_metadata", "stat_obj"
};

struct rgw_bucket_pending_info {
  RGWPendingState state;
  ceph::real_time timestamp;
  uint8_t op;

  rgw_bucket_pending_info() : state(CLS_RGW_STATE_PENDING_MODIFY), op(0) {}

  void encode(bufferlist &bl) const {
    ENCODE_START(2, 2, bl);
    uint8_t s = (uint8_t)state;
    encode(s, bl);
    encode(timestamp, bl);
    encode(op, bl);
    ENCODE_FINISH(bl);
  }
  void decode(bufferlist::iterator &bl) {
    DECODE_START_LEGACY_COMPAT_LEN(2, 2, 2, bl);
    uint8_t s;
    decode(s, bl);
    state = (RGWPendingState)s;
    decode(timestamp, bl);
    decode(op, bl);
    DECODE_FINISH(bl);
  }
  void dump(Formatter *f) const;
  void decode_json(JSONObj *obj);
  static void generate_test_instances(list<rgw_bucket_pending_info*>& o);
};
WRITE_CLASS_ENCODER(rgw_bucket_pending_info)

struct rgw_bucket_dir_entry_meta {
  uint8_t category;
  uint64_t size;
  ceph::real_time mtime;
  string etag;
  string owner;
  string owner_display_name;
  string content_type;
  uint64_t accounted_size;
  string user_data;
  string storage_class;
  bool accounted_entry;
  bool appendable;
  bool has_tags{false};
  bufferlist tags_bl;

  rgw_bucket_dir_entry_meta() :
  category(0), size(0), accounted_size(0), accounted_entry(true), appendable(false) { 
    tags_bl.clear();
  }

  void encode(bufferlist &bl) const {
    ENCODE_START(9, 3, bl);
    encode(category, bl);
    encode(size, bl);
    encode(mtime, bl);
    encode(etag, bl);
    encode(owner, bl);
    encode(owner_display_name, bl);
    encode(content_type, bl);
    encode(accounted_size, bl);
    encode(user_data, bl);
    encode(storage_class, bl);
    encode(accounted_entry, bl);
    encode(appendable, bl);
    encode(has_tags, bl);
    if (has_tags) {
      encode(tags_bl, bl);
    }
    ENCODE_FINISH(bl);
  }
  void decode(bufferlist::iterator &bl) {
    DECODE_START_LEGACY_COMPAT_LEN(9, 3, 3, bl);
    decode(category, bl);
    decode(size, bl);
    decode(mtime, bl);
    decode(etag, bl);
    decode(owner, bl);
    decode(owner_display_name, bl);
    if (struct_v >= 2)
      decode(content_type, bl);
    if (struct_v >= 4)
      decode(accounted_size, bl);
    else
      accounted_size = size;
    if (struct_v >= 5)
      decode(user_data, bl);
    if (struct_v >= 6)
      decode(storage_class, bl);
    if (struct_v >= 7) {
      decode(accounted_entry, bl);
    }
    if (struct_v >= 8) {
      decode(appendable, bl);
    }
    if (struct_v >= 9) {
      decode(has_tags, bl);
      if (has_tags) {
        decode(tags_bl, bl);
      }
    }
    DECODE_FINISH(bl);
  }
  void dump(Formatter *f) const;
  void decode_json(JSONObj *obj);
  static void generate_test_instances(list<rgw_bucket_dir_entry_meta*>& o);
};
WRITE_CLASS_ENCODER(rgw_bucket_dir_entry_meta)

template<class T>
void encode_packed_val(T val, bufferlist& bl)
{
  using ceph::encode;
  if ((uint64_t)val < 0x80) {
    encode((uint8_t)val, bl);
  } else {
    unsigned char c = 0x80;

    if ((uint64_t)val < 0x100) {
      c |= 1;
      encode(c, bl);
      encode((uint8_t)val, bl);
    } else if ((uint64_t)val <= 0x10000) {
      c |= 2;
      encode(c, bl);
      encode((uint16_t)val, bl);
    } else if ((uint64_t)val <= 0x1000000) {
      c |= 4;
      encode(c, bl);
      encode((uint32_t)val, bl);
    } else {
      c |= 8;
      encode(c, bl);
      encode((uint64_t)val, bl);
    }
  }
}

template<class T>
void decode_packed_val(T& val, bufferlist::iterator& bl)
{
  using ceph::decode;
  unsigned char c;
  decode(c, bl);
  if (c < 0x80) {
    val = c;
    return;
  }

  c &= ~0x80;

  switch (c) {
    case 1:
      {
        uint8_t v;
        decode(v, bl);
        val = v;
      }
      break;
    case 2:
      {
        uint16_t v;
        decode(v, bl);
        val = v;
      }
      break;
    case 4:
      {
        uint32_t v;
        decode(v, bl);
        val = v;
      }
      break;
    case 8:
      {
        uint64_t v;
        decode(v, bl);
        val = v;
      }
      break;
    default:
      throw buffer::error();
  }
}

struct rgw_bucket_entry_ver {
  int64_t pool;
  uint64_t epoch;

  rgw_bucket_entry_ver() : pool(-1), epoch(0) {}

  void encode(bufferlist &bl) const {
    ENCODE_START(1, 1, bl);
    encode_packed_val(pool, bl);
    encode_packed_val(epoch, bl);
    ENCODE_FINISH(bl);
  }
  void decode(bufferlist::iterator &bl) {
    DECODE_START(1, bl);
    decode_packed_val(pool, bl);
    decode_packed_val(epoch, bl);
    DECODE_FINISH(bl);
  }
  void dump(Formatter *f) const;
  void decode_json(JSONObj *obj);
  static void generate_test_instances(list<rgw_bucket_entry_ver*>& o);
};
WRITE_CLASS_ENCODER(rgw_bucket_entry_ver)

struct cls_rgw_obj_key {
  string name;
  string instance;

  cls_rgw_obj_key() {}
  cls_rgw_obj_key(const string &_name) : name(_name) {}
  cls_rgw_obj_key(const string& n, const string& i) : name(n), instance(i) {}

  void set(const string& _name) {
    name = _name;
  }

  bool operator==(const cls_rgw_obj_key& k) const {
    return (name.compare(k.name) == 0) &&
           (instance.compare(k.instance) == 0);
  }
  bool operator<(const cls_rgw_obj_key& k) const {
    int r = name.compare(k.name);
    if (r == 0) {
      r = instance.compare(k.instance);
    }
    return (r < 0);
  }
  bool operator<=(const cls_rgw_obj_key& k) const {
    return !(k < *this);
  }
  bool empty() {
    return name.empty();
  }
  void encode(bufferlist &bl) const {
    ENCODE_START(1, 1, bl);
    encode(name, bl);
    encode(instance, bl);
    ENCODE_FINISH(bl);
  }
  void decode(bufferlist::iterator &bl) {
    DECODE_START(1, bl);
    decode(name, bl);
    decode(instance, bl);
    DECODE_FINISH(bl);
  }
  void dump(Formatter *f) const {
    f->dump_string("name", name);
    f->dump_string("instance", instance);
  }
  void decode_json(JSONObj *obj);
  static void generate_test_instances(list<cls_rgw_obj_key*>& ls) {
    ls.push_back(new cls_rgw_obj_key);
    ls.push_back(new cls_rgw_obj_key);
    ls.back()->name = "name";
    ls.back()->instance = "instance";
  }
};
WRITE_CLASS_ENCODER(cls_rgw_obj_key)


#define RGW_BUCKET_DIRENT_FLAG_VER           0x1    /* a versioned object instance */
#define RGW_BUCKET_DIRENT_FLAG_CURRENT       0x2    /* the last object instance of a versioned object */
#define RGW_BUCKET_DIRENT_FLAG_DELETE_MARKER 0x4    /* delete marker */
#define RGW_BUCKET_DIRENT_FLAG_VER_MARKER    0x8    /* object is versioned, a placeholder for the plain entry */

struct rgw_bucket_dir_entry {
  cls_rgw_obj_key key;
  rgw_bucket_entry_ver ver;
  std::string locator;
  bool exists;
  struct rgw_bucket_dir_entry_meta meta;
  multimap<string, struct rgw_bucket_pending_info> pending_map;
  uint64_t index_ver;
  string tag;
  uint16_t flags;
  uint64_t versioned_epoch;

  rgw_bucket_dir_entry() :
    exists(false), index_ver(0), flags(0), versioned_epoch(0) {}

  void encode(bufferlist &bl) const {
    ENCODE_START(8, 3, bl);
    encode(key.name, bl);
    encode(ver.epoch, bl);
    encode(exists, bl);
    encode(meta, bl);
    encode(pending_map, bl);
    encode(locator, bl);
    encode(ver, bl);
    encode_packed_val(index_ver, bl);
    encode(tag, bl);
    encode(key.instance, bl);
    encode(flags, bl);
    encode(versioned_epoch, bl);
    ENCODE_FINISH(bl);
  }
  void decode(bufferlist::iterator &bl) {
    DECODE_START_LEGACY_COMPAT_LEN(8, 3, 3, bl);
    decode(key.name, bl);
    decode(ver.epoch, bl);
    decode(exists, bl);
    decode(meta, bl);
    decode(pending_map, bl);
    if (struct_v >= 2) {
      decode(locator, bl);
    }
    if (struct_v >= 4) {
      decode(ver, bl);
    } else {
      ver.pool = -1;
    }
    if (struct_v >= 5) {
      decode_packed_val(index_ver, bl);
      decode(tag, bl);
    }
    if (struct_v >= 6) {
      decode(key.instance, bl);
    }
    if (struct_v >= 7) {
      decode(flags, bl);
    }
    if (struct_v >= 8) {
      decode(versioned_epoch, bl);
    }
    DECODE_FINISH(bl);
  }

  bool is_current() {
    int test_flags = RGW_BUCKET_DIRENT_FLAG_VER | RGW_BUCKET_DIRENT_FLAG_CURRENT;
    return (flags & RGW_BUCKET_DIRENT_FLAG_VER) == 0 ||
           (flags & test_flags) == test_flags;
  }
  bool is_delete_marker() { return (flags & RGW_BUCKET_DIRENT_FLAG_DELETE_MARKER) != 0; }
  bool is_visible() {
    return is_current() && !is_delete_marker();
  }
  bool is_valid() { return (flags & RGW_BUCKET_DIRENT_FLAG_VER_MARKER) == 0; }

  void dump(Formatter *f) const;
  void decode_json(JSONObj *obj);
  static void generate_test_instances(list<rgw_bucket_dir_entry*>& o);
};
WRITE_CLASS_ENCODER(rgw_bucket_dir_entry)


/*
 * magic:
 * bits |<- 2 ->|<- 1 ->|<- 1   ->|<-   1   -> | <-  3  ->|<- 36 ->|<-   20    ->|
 *          |     exist     |       appendable   reserved     |      microsecond
 *         type          pending?                           second
 *
 * type: file 10 dir 01
 */
static const uint64_t CLS_RGW_NAMESPACE_FILE_MASK = 0x8000000000000000;
static const uint64_t CLS_RGW_NAMESPACE_DIR_MASK = 0x4000000000000000;
static const uint64_t CLS_RGW_NAMESPACE_NODE_EXIST = 0x2000000000000000;
static const uint64_t CLS_RGW_NAMESPACE_NODE_PENDING = 0x1000000000000000;
static const uint64_t CLS_RGW_NAMESPACE_NODE_CLEAR_PENDING = 0xefffffffffffffff;
static const uint64_t CLS_RGW_NAMESPACE_NODE_CLEAR_EXIST = 0xdfffffffffffffff;
static const uint64_t CLS_RGW_NAMESPACE_SEC_MASK = 0x00fffffffff00000;
static const uint64_t CLS_RGW_NAMESPACE_USEC_MASK = 0x00000000000fffff;
static const uint64_t CLS_RGW_NAMESPACE_TIME_MASK = 0x00ffffffffffffff;
static const uint64_t CLS_RGW_NAMESPACE_CLEAR_TIME = 0xff00000000000000;
static const uint64_t CLS_RGW_NAMESPACE_APPENDABLE = 0x0800000000000000;
static const uint64_t CLS_RGW_NAMESPACE_CLEAR_APPENDABLE = 0xf7ffffffffffffff;


inline bool namespace_entry_is_dir(uint64_t magic) { return magic & CLS_RGW_NAMESPACE_DIR_MASK; }
inline bool namespace_entry_is_file(uint64_t magic) { return magic & CLS_RGW_NAMESPACE_FILE_MASK; }

class rgw_bucket_namespace_node {
public:
  rgw_bucket_namespace_node(const uint64_t& m) : magic(m) {}

  inline bool exist() { return magic & CLS_RGW_NAMESPACE_NODE_EXIST; }
  inline bool not_exist() { return (magic & CLS_RGW_NAMESPACE_NODE_EXIST) == 0; }
  inline void clear_exist() { magic &= CLS_RGW_NAMESPACE_NODE_CLEAR_EXIST; }
  inline void set_exist() { magic |= CLS_RGW_NAMESPACE_NODE_EXIST; }

  inline void set_mtime(ceph::real_time& ut) { 
    struct timeval tv;
    ceph::real_clock::to_timeval(ut, tv);
    uint64_t usec = uint64_t(tv.tv_sec) << 20;
    usec += (uint64_t(tv.tv_usec) & CLS_RGW_NAMESPACE_USEC_MASK);
    magic = (magic & CLS_RGW_NAMESPACE_CLEAR_TIME) | (CLS_RGW_NAMESPACE_TIME_MASK & usec);
  }

  inline bool is_pending() { return  magic & CLS_RGW_NAMESPACE_NODE_PENDING; }
  inline void set_pending() { magic |= CLS_RGW_NAMESPACE_NODE_PENDING; }
  inline void clear_pending() { magic &= CLS_RGW_NAMESPACE_NODE_CLEAR_PENDING; }

  inline ceph::real_time mtime() {
    uint64_t sec = (magic & CLS_RGW_NAMESPACE_SEC_MASK) >> 20;
    uint64_t usec = magic & CLS_RGW_NAMESPACE_USEC_MASK;
    return ceph::real_time(ceph::time_detail::seconds(sec) + ceph::time_detail::microseconds(usec));
  }

  inline bool is_file() { return magic & CLS_RGW_NAMESPACE_DIR_MASK; }
  inline bool is_dir() { return magic & CLS_RGW_NAMESPACE_FILE_MASK; }

public:
  uint64_t magic;
};

class rgw_bucket_namespace_dir : public rgw_bucket_namespace_node {
public:
  rgw_bucket_namespace_dir(const uint64_t& m) : rgw_bucket_namespace_node(m) {}
  rgw_bucket_namespace_dir() : rgw_bucket_namespace_node(CLS_RGW_NAMESPACE_DIR_MASK) {}

  inline bool is_corrent_type() { return magic & CLS_RGW_NAMESPACE_DIR_MASK; }
  
  void encode(bufferlist &bl) const {
    {
      using ceph::encode;
      encode(magic, bl);
    }
    ENCODE_START(1, 1, bl);
    encode(ver, bl);
    encode(pending_map, bl);
    ENCODE_FINISH(bl);
  }

  void decode(bufferlist::iterator &bl) {
    // must first decode magic in outside
    DECODE_START(1, bl);
    decode(ver, bl);
    decode(pending_map, bl);
    DECODE_FINISH(bl);
  }

public:
  rgw_bucket_entry_ver ver;
  multimap<string, struct rgw_bucket_pending_info> pending_map;
};
WRITE_CLASS_ENCODER(rgw_bucket_namespace_dir)

class rgw_bucket_namespace_file : public rgw_bucket_namespace_node {
public:
  rgw_bucket_namespace_file(uint64_t m) : rgw_bucket_namespace_node(m) {}
  rgw_bucket_namespace_file() : rgw_bucket_namespace_node(CLS_RGW_NAMESPACE_FILE_MASK), size(0) {}

  inline bool is_corrent_type() { return magic & CLS_RGW_NAMESPACE_FILE_MASK; }
  inline void set_appendable(bool appendable) {
    if (appendable) {
      magic |= CLS_RGW_NAMESPACE_APPENDABLE;
    } else {
      magic &= CLS_RGW_NAMESPACE_CLEAR_APPENDABLE;
    }
  }
  inline bool is_appendable() {return magic & CLS_RGW_NAMESPACE_APPENDABLE;}

  void encode(bufferlist &bl) const {
    {
      using ceph::encode;
      encode(magic, bl);
      encode(size, bl);
    }
    ENCODE_START(1, 1, bl);
    encode(obj_name, bl);
    encode(ver, bl);
    encode(pending_map, bl);
    ENCODE_FINISH(bl);
  }

  // in head_obj and list_obj we jues need know size and mtime
  void decode_size(bufferlist::iterator &bl) {
    using ceph::decode;
    decode(size, bl);
    have_decode_size = true;
  }

  void decode(bufferlist::iterator &bl) {
    // must first decode magic and size in outside
    if (!have_decode_size) {
      using ceph::decode;
      decode(size, bl);
    }
    DECODE_START(1, bl);
    decode(obj_name, bl);
    decode(ver, bl);
    decode(pending_map, bl);
    DECODE_FINISH(bl);
  }

public:
  bool have_decode_size = false;
  uint64_t size;
  string obj_name; // s3 object name
  rgw_bucket_entry_ver ver;
  multimap<string, struct rgw_bucket_pending_info> pending_map;
};
WRITE_CLASS_ENCODER(rgw_bucket_namespace_file)

enum BIIndexType {
  InvalidIdx    = 0,
  PlainIdx      = 1,
  InstanceIdx   = 2,
  OLHIdx        = 3,
};

struct rgw_bucket_category_stats;

struct rgw_cls_bi_entry {
  BIIndexType type;
  string idx;
  bufferlist data;

  rgw_cls_bi_entry() : type(InvalidIdx) {}

  void encode(bufferlist& bl) const {
    ENCODE_START(1, 1, bl);
    encode((uint8_t)type, bl);
    encode(idx, bl);
    encode(data, bl);
    ENCODE_FINISH(bl);
  }

  void decode(bufferlist::iterator& bl) {
    DECODE_START(1, bl);
    uint8_t c;
    decode(c, bl);
    type = (BIIndexType)c;
    decode(idx, bl);
    decode(data, bl);
    DECODE_FINISH(bl);
  }

  void dump(Formatter *f) const;
  void decode_json(JSONObj *obj, cls_rgw_obj_key *effective_key = NULL);

  bool get_info(cls_rgw_obj_key *key, uint8_t *category, rgw_bucket_category_stats *accounted_stats);
};
WRITE_CLASS_ENCODER(rgw_cls_bi_entry)

enum OLHLogOp {
  CLS_RGW_OLH_OP_UNKNOWN         = 0,
  CLS_RGW_OLH_OP_LINK_OLH        = 1,
  CLS_RGW_OLH_OP_UNLINK_OLH      = 2, /* object does not exist */
  CLS_RGW_OLH_OP_REMOVE_INSTANCE = 3,
};

struct rgw_bucket_olh_log_entry {
  uint64_t epoch;
  OLHLogOp op;
  string op_tag;
  cls_rgw_obj_key key;
  bool delete_marker;

  rgw_bucket_olh_log_entry() : epoch(0), op(CLS_RGW_OLH_OP_UNKNOWN), delete_marker(false) {}


  void encode(bufferlist &bl) const {
    ENCODE_START(1, 1, bl);
    encode(epoch, bl);
    encode((__u8)op, bl);
    encode(op_tag, bl);
    encode(key, bl);
    encode(delete_marker, bl);
    ENCODE_FINISH(bl);
  }
  void decode(bufferlist::iterator &bl) {
    DECODE_START(1, bl);
    decode(epoch, bl);
    uint8_t c;
    decode(c, bl);
    op = (OLHLogOp)c;
    decode(op_tag, bl);
    decode(key, bl);
    decode(delete_marker, bl);
    DECODE_FINISH(bl);
  }
  static void generate_test_instances(list<rgw_bucket_olh_log_entry*>& o);
  void dump(Formatter *f) const;
  void decode_json(JSONObj *obj);
};
WRITE_CLASS_ENCODER(rgw_bucket_olh_log_entry)

struct rgw_bucket_olh_entry {
  cls_rgw_obj_key key;
  bool delete_marker;
  uint64_t epoch;
  map<uint64_t, vector<struct rgw_bucket_olh_log_entry> > pending_log;
  string tag;
  bool exists;
  bool pending_removal;

  rgw_bucket_olh_entry() : delete_marker(false), epoch(0), exists(false), pending_removal(false) {}

  void encode(bufferlist &bl) const {
    ENCODE_START(1, 1, bl);
    encode(key, bl);
    encode(delete_marker, bl);
    encode(epoch, bl);
    encode(pending_log, bl);
    encode(tag, bl);
    encode(exists, bl);
    encode(pending_removal, bl);
    ENCODE_FINISH(bl);
  }
  void decode(bufferlist::iterator &bl) {
    DECODE_START(1, bl);
    decode(key, bl);
    decode(delete_marker, bl);
    decode(epoch, bl);
    decode(pending_log, bl);
    decode(tag, bl);
    decode(exists, bl);
    decode(pending_removal, bl);
    DECODE_FINISH(bl);
  }
  void dump(Formatter *f) const;
  void decode_json(JSONObj *obj);
};
WRITE_CLASS_ENCODER(rgw_bucket_olh_entry)

struct rgw_bi_log_entry {
  string id;
  string object;
  string instance;
  ceph::real_time timestamp;
  rgw_bucket_entry_ver ver;
  RGWModifyOp op;
  RGWPendingState state;
  uint64_t index_ver;
  string tag;
  uint16_t bilog_flags;
  string owner; /* only being set if it's a delete marker */
  string owner_display_name; /* only being set if it's a delete marker */
  rgw_zone_set zones_trace;

  rgw_bi_log_entry() : op(CLS_RGW_OP_UNKNOWN), state(CLS_RGW_STATE_PENDING_MODIFY), index_ver(0), bilog_flags(0) {}

  void encode(bufferlist &bl) const {
    ENCODE_START(4, 1, bl);
    encode(id, bl);
    encode(object, bl);
    encode(timestamp, bl);
    encode(ver, bl);
    encode(tag, bl);
    uint8_t c = (uint8_t)op;
    encode(c, bl);
    c = (uint8_t)state;
    encode(c, bl);
    encode_packed_val(index_ver, bl);
    encode(instance, bl);
    encode(bilog_flags, bl);
    encode(owner, bl);
    encode(owner_display_name, bl);
    encode(zones_trace, bl);
    ENCODE_FINISH(bl);
  }
  void decode(bufferlist::iterator &bl) {
    DECODE_START(4, bl);
    decode(id, bl);
    decode(object, bl);
    decode(timestamp, bl);
    decode(ver, bl);
    decode(tag, bl);
    uint8_t c;
    decode(c, bl);
    op = (RGWModifyOp)c;
    decode(c, bl);
    state = (RGWPendingState)c;
    decode_packed_val(index_ver, bl);
    if (struct_v >= 2) {
      decode(instance, bl);
      decode(bilog_flags, bl);
    }
    if (struct_v >= 3) {
      decode(owner, bl);
      decode(owner_display_name, bl);
    }
    if (struct_v >= 4) {
      decode(zones_trace, bl);
    }
    DECODE_FINISH(bl);
  }
  void dump(Formatter *f) const;
  void decode_json(JSONObj *obj);
  static void generate_test_instances(list<rgw_bi_log_entry*>& o);

  bool is_versioned() {
    return ((bilog_flags & RGW_BILOG_FLAG_VERSIONED_OP) != 0);
  }
};
WRITE_CLASS_ENCODER(rgw_bi_log_entry)

struct rgw_bucket_category_stats {
  uint64_t total_size;
  uint64_t total_size_rounded;
  uint64_t num_entries;
  uint64_t actual_size{0}; //< account for compression, encryption

  rgw_bucket_category_stats() : total_size(0), total_size_rounded(0), num_entries(0) {}

  void encode(bufferlist &bl) const {
    ENCODE_START(3, 2, bl);
    encode(total_size, bl);
    encode(total_size_rounded, bl);
    encode(num_entries, bl);
    encode(actual_size, bl);
    ENCODE_FINISH(bl);
  }
  void decode(bufferlist::iterator &bl) {
    DECODE_START_LEGACY_COMPAT_LEN(3, 2, 2, bl);
    decode(total_size, bl);
    decode(total_size_rounded, bl);
    decode(num_entries, bl);
    if (struct_v >= 3) {
      decode(actual_size, bl);
    } else {
      actual_size = total_size;
    }
    DECODE_FINISH(bl);
  }
  void dump(Formatter *f) const;
  static void generate_test_instances(list<rgw_bucket_category_stats*>& o);
  void decode_json(JSONObj *obj);
};
WRITE_CLASS_ENCODER(rgw_bucket_category_stats)

enum cls_rgw_reshard_status {
  CLS_RGW_RESHARD_NONE        = 0,
  CLS_RGW_RESHARD_IN_PROGRESS = 1,
  CLS_RGW_RESHARD_DONE        = 2,
};

static inline std::string to_string(const enum cls_rgw_reshard_status status)
{
  switch (status) {
  case CLS_RGW_RESHARD_NONE:
    return "CLS_RGW_RESHARD_NONE";
    break;
  case CLS_RGW_RESHARD_IN_PROGRESS:
    return "CLS_RGW_RESHARD_IN_PROGRESS";
    break;
  case CLS_RGW_RESHARD_DONE:
    return "CLS_RGW_RESHARD_DONE";
    break;
  default:
    break;
  };
  return "Unknown reshard status";
}

struct cls_rgw_bucket_instance_entry {
  cls_rgw_reshard_status reshard_status{CLS_RGW_RESHARD_NONE};
  string new_bucket_instance_id;
  int32_t num_shards{-1};

  void encode(bufferlist& bl) const {
    ENCODE_START(1, 1, bl);
    encode((uint8_t)reshard_status, bl);
    encode(new_bucket_instance_id, bl);
    encode(num_shards, bl);
    ENCODE_FINISH(bl);
  }

  void decode(bufferlist::iterator& bl) {
    DECODE_START(1, bl);
    uint8_t s;
    decode(s, bl);
    reshard_status = (cls_rgw_reshard_status)s;
    decode(new_bucket_instance_id, bl);
    decode(num_shards, bl);
    DECODE_FINISH(bl);
  }

  void dump(Formatter *f) const;
  static void generate_test_instances(list<cls_rgw_bucket_instance_entry*>& o);
  void decode_json(JSONObj *obj);

  void clear() {
    reshard_status = CLS_RGW_RESHARD_NONE;
    new_bucket_instance_id.clear();
  }

  void set_status(const string& new_instance_id, int32_t new_num_shards, cls_rgw_reshard_status s) {
    reshard_status = s;
    new_bucket_instance_id = new_instance_id;
    num_shards = new_num_shards;
  }

  bool resharding() const {
    return reshard_status != CLS_RGW_RESHARD_NONE;
  }
  bool resharding_in_progress() const {
    return reshard_status == CLS_RGW_RESHARD_IN_PROGRESS;
  }
};
WRITE_CLASS_ENCODER(cls_rgw_bucket_instance_entry)

struct rgw_bucket_dir_header {
  map<uint8_t, rgw_bucket_category_stats> stats;
  map<std::string, rgw_bucket_category_stats> storageclass_stats;
  uint64_t tag_timeout;
  uint64_t ver;
  uint64_t master_ver;
  string max_marker;
  cls_rgw_bucket_instance_entry new_instance;
  bool syncstopped;

  rgw_bucket_dir_header() : tag_timeout(0), ver(0), master_ver(0), syncstopped(false) {}

  void encode(bufferlist &bl) const {
    ENCODE_START(8, 2, bl);
    encode(stats, bl);
    encode(tag_timeout, bl);
    encode(ver, bl);
    encode(master_ver, bl);
    encode(max_marker, bl);
    encode(new_instance, bl);
    encode(syncstopped,bl);
    encode(storageclass_stats, bl);
    ENCODE_FINISH(bl);
  }
  void decode(bufferlist::iterator &bl) {
    DECODE_START_LEGACY_COMPAT_LEN(8, 2, 2, bl);
    decode(stats, bl);
    if (struct_v > 2) {
      decode(tag_timeout, bl);
    } else {
      tag_timeout = 0;
    }
    if (struct_v >= 4) {
      decode(ver, bl);
      decode(master_ver, bl);
    } else {
      ver = 0;
    }
    if (struct_v >= 5) {
      decode(max_marker, bl);
    }
    if (struct_v >= 6) {
      decode(new_instance, bl);
    } else {
      new_instance = cls_rgw_bucket_instance_entry();
    }
    if (struct_v >= 7) {
      decode(syncstopped,bl);
    }
    if (struct_v >= 8) {
      decode(storageclass_stats, bl);
    }
    DECODE_FINISH(bl);
  }
  void dump(Formatter *f) const;
  static void generate_test_instances(list<rgw_bucket_dir_header*>& o);

  bool resharding() const {
    return new_instance.resharding();
  }
  bool resharding_in_progress() const {
    return new_instance.resharding_in_progress();
  }
  void decode_json(JSONObj *obj);
};
WRITE_CLASS_ENCODER(rgw_bucket_dir_header)

struct rgw_bucket_dir {
  struct rgw_bucket_dir_header header;
  boost::container::flat_map<string, rgw_bucket_dir_entry> m;

  void encode(bufferlist &bl) const {
    ENCODE_START(2, 2, bl);
    encode(header, bl);
    encode(m, bl);
    ENCODE_FINISH(bl);
  }
  void decode(bufferlist::iterator &bl) {
    DECODE_START_LEGACY_COMPAT_LEN(2, 2, 2, bl);
    decode(header, bl);
    decode(m, bl);
    DECODE_FINISH(bl);
  }
  void dump(Formatter *f) const;
  static void generate_test_instances(list<rgw_bucket_dir*>& o);
};
WRITE_CLASS_ENCODER(rgw_bucket_dir)

struct rgw_usage_data {
  uint64_t bytes_sent;
  uint64_t bytes_received;
  uint64_t ops;
  uint64_t successful_ops;

  rgw_usage_data() : bytes_sent(0), bytes_received(0), ops(0), successful_ops(0) {}
  rgw_usage_data(uint64_t sent, uint64_t received) : bytes_sent(sent), bytes_received(received), ops(0), successful_ops(0) {}

  void encode(bufferlist& bl) const {
    ENCODE_START(1, 1, bl);
    encode(bytes_sent, bl);
    encode(bytes_received, bl);
    encode(ops, bl);
    encode(successful_ops, bl);
    ENCODE_FINISH(bl);
  }

  void decode(bufferlist::iterator& bl) {
    DECODE_START(1, bl);
    decode(bytes_sent, bl);
    decode(bytes_received, bl);
    decode(ops, bl);
    decode(successful_ops, bl);
    DECODE_FINISH(bl);
  }

  void aggregate(const rgw_usage_data& usage) {
    bytes_sent += usage.bytes_sent;
    bytes_received += usage.bytes_received;
    ops += usage.ops;
    successful_ops += usage.successful_ops;
  }
};
WRITE_CLASS_ENCODER(rgw_usage_data)


struct rgw_usage_log_entry {
  rgw_user owner;
  rgw_user payer; /* if empty, same as owner */
  string bucket;
  uint64_t epoch;
  rgw_usage_data total_usage; /* this one is kept for backwards compatibility */
  rgw_usage_data read_ops;
  rgw_usage_data write_ops;
  map<string, rgw_usage_data> usage_map;
  bool update_readop_usage;

  rgw_usage_log_entry() : epoch(0) {}
  rgw_usage_log_entry(string& o, string& b) : owner(o), bucket(b), epoch(0) {}
  rgw_usage_log_entry(string& o, string& p, string& b) : owner(o), payer(p), bucket(b), epoch(0) {}

  void encode(bufferlist& bl) const {
    ENCODE_START(4, 1, bl);
    encode(owner.to_str(), bl);
    encode(bucket, bl);
    encode(epoch, bl);
    encode(total_usage.bytes_sent, bl);
    encode(total_usage.bytes_received, bl);
    encode(total_usage.ops, bl);
    encode(total_usage.successful_ops, bl);
    encode(usage_map, bl);
    encode(payer.to_str(), bl);
    encode(read_ops.bytes_sent, bl);
    encode(read_ops.bytes_received, bl);
    encode(read_ops.ops, bl);
    encode(read_ops.successful_ops, bl);
    encode(write_ops.bytes_sent, bl);
    encode(write_ops.bytes_received, bl);
    encode(write_ops.ops, bl);
    encode(write_ops.successful_ops, bl);
    ENCODE_FINISH(bl);
  }


   void decode(bufferlist::iterator& bl) {
    DECODE_START(4, bl);
    string s;
    decode(s, bl);
    owner.from_str(s);
    decode(bucket, bl);
    decode(epoch, bl);
    decode(total_usage.bytes_sent, bl);
    decode(total_usage.bytes_received, bl);
    decode(total_usage.ops, bl);
    decode(total_usage.successful_ops, bl);
    if (struct_v < 2) {
      usage_map[""] = total_usage;
    } else {
      decode(usage_map, bl);
    }
    if (struct_v >= 3) {
      string p;
      decode(p, bl);
      payer.from_str(p);
    }
    if (struct_v >=4) {
      decode(read_ops.bytes_sent, bl);
      decode(read_ops.bytes_received, bl);
      decode(read_ops.ops, bl);
      decode(read_ops.successful_ops, bl);
      decode(write_ops.bytes_sent, bl);
      decode(write_ops.bytes_received, bl);
      decode(write_ops.ops, bl);
      decode(write_ops.successful_ops, bl);
    }
    DECODE_FINISH(bl);
  }

  void aggregate(const rgw_usage_log_entry& e, map<string, bool> *categories = NULL) {
    if (owner.empty()) {
      owner = e.owner;
      bucket = e.bucket;
      epoch = e.epoch;
      payer = e.payer;
    }

    map<string, rgw_usage_data>::const_iterator iter;
    for (iter = e.usage_map.begin(); iter != e.usage_map.end(); ++iter) {
      if (!categories || !categories->size() || categories->count(iter->first)) {
        add(iter->first, iter->second);
      }
    }
  }

  void aggregate_readop(const rgw_usage_log_entry& e) {
    if (owner.empty()) {
      owner = e.owner;
      epoch = e.epoch;
      payer = e.payer;
    }
    read_ops.bytes_sent += e.read_ops.bytes_sent;
    write_ops.bytes_received += e.write_ops.bytes_received;
    read_ops.ops = e.read_ops.ops;
    read_ops.successful_ops = e.read_ops.successful_ops;
    write_ops.ops = e.write_ops.ops;
    write_ops.successful_ops = e.write_ops.successful_ops;
  }

  void sum(rgw_usage_data& usage, map<string, bool>& categories) const {
    usage = rgw_usage_data();
    for (map<string, rgw_usage_data>::const_iterator iter = usage_map.begin(); iter != usage_map.end(); ++iter) {
      if (!categories.size() || categories.count(iter->first)) {
        usage.aggregate(iter->second);
      }
    }
  }

  void add(const string& category, const rgw_usage_data& data) {
    usage_map[category].aggregate(data);
    total_usage.aggregate(data);
    if (!update_readop_usage)
      read_and_write_ops(category, data);
    update_readop_usage = false;
  }

  void dump(Formatter* f) const;
  static void generate_test_instances(list<rgw_usage_log_entry*>& o);

  void read_and_write_ops(const string& category, const rgw_usage_data& data) {
    read_ops.bytes_sent += data.bytes_sent;
    write_ops.bytes_received += data.bytes_received;
    // check op type
    if (read_op_list.find(category) != read_op_list.end()) {
      read_ops.ops += data.ops;
      read_ops.successful_ops += data.successful_ops;
    } else {
      write_ops.ops += data.ops;
      write_ops.successful_ops += data.successful_ops;
    }
  }
  void set_update_readop_usage() {
    update_readop_usage = true;
  }
};
WRITE_CLASS_ENCODER(rgw_usage_log_entry)

struct rgw_usage_log_info {
  vector<rgw_usage_log_entry> entries;

  void encode(bufferlist& bl) const {
    ENCODE_START(1, 1, bl);
    encode(entries, bl);
    ENCODE_FINISH(bl);
  }

  void decode(bufferlist::iterator& bl) {
    DECODE_START(1, bl);
    decode(entries, bl);
    DECODE_FINISH(bl);
  }

  rgw_usage_log_info() {}
};
WRITE_CLASS_ENCODER(rgw_usage_log_info)

struct rgw_user_bucket {
  string user;
  string bucket;

  rgw_user_bucket() {}
  rgw_user_bucket(const string& u, const string& b) : user(u), bucket(b) {}

  void encode(bufferlist& bl) const {
    ENCODE_START(1, 1, bl);
    encode(user, bl);
    encode(bucket, bl);
    ENCODE_FINISH(bl);
  }

  void decode(bufferlist::iterator& bl) {
    DECODE_START(1, bl);
    decode(user, bl);
    decode(bucket, bl);
    DECODE_FINISH(bl);
  }

  bool operator<(const rgw_user_bucket& ub2) const {
    int comp = user.compare(ub2.user);
    if (comp < 0)
      return true;
    else if (!comp)
      return bucket.compare(ub2.bucket) < 0;

    return false;
  }
};
WRITE_CLASS_ENCODER(rgw_user_bucket)

enum cls_rgw_gc_op {
  CLS_RGW_GC_DEL_OBJ,
  CLS_RGW_GC_DEL_BUCKET,
};

struct cls_rgw_obj {
  string pool;
  cls_rgw_obj_key key;
  string loc;

  cls_rgw_obj() {}
  cls_rgw_obj(string& _p, cls_rgw_obj_key& _k) : pool(_p), key(_k) {}

  void encode(bufferlist& bl) const {
    ENCODE_START(2, 1, bl);
    encode(pool, bl);
    encode(key.name, bl);
    encode(loc, bl);
    encode(key, bl);
    ENCODE_FINISH(bl);
  }

  void decode(bufferlist::iterator& bl) {
    DECODE_START(2, bl);
    decode(pool, bl);
    decode(key.name, bl);
    decode(loc, bl);
    if (struct_v >= 2) {
      decode(key, bl);
    }
    DECODE_FINISH(bl);
  }

  void dump(Formatter *f) const {
    f->dump_string("pool", pool);
    f->dump_string("oid", key.name);
    f->dump_string("key", loc);
    f->dump_string("instance", key.instance);
  }
  static void generate_test_instances(list<cls_rgw_obj*>& ls) {
    ls.push_back(new cls_rgw_obj);
    ls.push_back(new cls_rgw_obj);
    ls.back()->pool = "mypool";
    ls.back()->key.name = "myoid";
    ls.back()->loc = "mykey";
  }
};
WRITE_CLASS_ENCODER(cls_rgw_obj)

enum {
  DELAY_REMOVE_HEAD_UNKNOWN       = 0, // unknown delay remove option when obj add chain
  DELAY_REMOVE_HEAD_ENABLE        = 1, // explicit enable  delay remove head obj
  DELAY_REMOVE_HEAD_DISABLE       = 2, // explicit disable delay remove head obj
};

struct cls_rgw_obj_chain {
  list<cls_rgw_obj> objs;
  bool skip_cache{false};
  uint8_t enable_delay_remove_head_obj{DELAY_REMOVE_HEAD_UNKNOWN};

  cls_rgw_obj_chain() {}

  void push_obj(const string& pool, const cls_rgw_obj_key& key, const string& loc) {
    cls_rgw_obj obj;
    obj.pool = pool;
    obj.key = key;
    obj.loc = loc;
    objs.push_back(obj);
  }

  void encode(bufferlist& bl) const {
    ENCODE_START(2, 1, bl);
    encode(objs, bl);
    encode(skip_cache, bl);
    encode(enable_delay_remove_head_obj, bl);
    ENCODE_FINISH(bl);
  }

  void decode(bufferlist::iterator& bl) {
    DECODE_START(2, bl);
    decode(objs, bl);
    if (struct_v >= 2) {
      decode(skip_cache, bl);
      decode(enable_delay_remove_head_obj, bl);
    }
    DECODE_FINISH(bl);
  }

  void dump(Formatter *f) const {
    f->open_array_section("objs");
    for (list<cls_rgw_obj>::const_iterator p = objs.begin(); p != objs.end(); ++p) {
      f->open_object_section("obj");
      p->dump(f);
      f->close_section();
    }
    f->close_section();
    f->dump_bool("skip_cache", skip_cache);
    f->dump_unsigned("enable_delay_remove_head_obj", enable_delay_remove_head_obj);
  }
  static void generate_test_instances(list<cls_rgw_obj_chain*>& ls) {
    ls.push_back(new cls_rgw_obj_chain);
  }

  bool empty() {
    return objs.empty();
  }
};
WRITE_CLASS_ENCODER(cls_rgw_obj_chain)

struct cls_rgw_gc_obj_info
{
  string tag;
  cls_rgw_obj_chain chain;
  ceph::real_time time;
  int64_t survive_time = 0;

  cls_rgw_gc_obj_info() {}

  void encode(bufferlist& bl) const {
    ENCODE_START(2, 1, bl);
    encode(tag, bl);
    encode(chain, bl);
    encode(time, bl);
    encode(survive_time, bl);
    ENCODE_FINISH(bl);
  }

  void decode(bufferlist::iterator& bl) {
    DECODE_START(2, bl);
    decode(tag, bl);
    decode(chain, bl);
    decode(time, bl);
    if (struct_v >= 2)
      decode(survive_time, bl);
    DECODE_FINISH(bl);
  }

  void dump(Formatter *f) const {
    f->dump_string("tag", tag);
    f->open_object_section("chain");
    chain.dump(f);
    f->close_section();
    f->dump_stream("time") << time;
    f->dump_int("survive_time", survive_time);
  }
  static void generate_test_instances(list<cls_rgw_gc_obj_info*>& ls) {
    ls.push_back(new cls_rgw_gc_obj_info);
    ls.push_back(new cls_rgw_gc_obj_info);
    ls.back()->tag = "footag";
    ceph_timespec ts{21, 32};
    ls.back()->time = ceph::real_clock::from_ceph_timespec(ts);
  }
};
WRITE_CLASS_ENCODER(cls_rgw_gc_obj_info)

struct cls_rgw_lc_obj_head
{
  time_t start_date = 0;
  string marker;

  cls_rgw_lc_obj_head() {}

  void encode(bufferlist& bl) const {
    ENCODE_START(1, 1, bl);
    uint64_t t = start_date;
    encode(t, bl);
    encode(marker, bl);
    ENCODE_FINISH(bl);
  }

  void decode(bufferlist::iterator& bl) {
    DECODE_START(1, bl);
    uint64_t t;
    decode(t, bl);
    start_date = static_cast<time_t>(t);
    decode(marker, bl);
    DECODE_FINISH(bl);
  }

  void dump(Formatter *f) const;
  static void generate_test_instances(list<cls_rgw_lc_obj_head*>& ls);
};
WRITE_CLASS_ENCODER(cls_rgw_lc_obj_head)

struct cls_rgw_lc_entry {
  std::string bucket;
  uint64_t start_time; // if in_progress
  uint32_t status;
  int32_t shard_id;

  cls_rgw_lc_entry()
    : start_time(0), status(0), shard_id(-1) {}

  cls_rgw_lc_entry(const cls_rgw_lc_entry& rhs) = default;

  cls_rgw_lc_entry(const std::string& b, uint64_t t, uint32_t s, int32_t shard)
    : bucket(b), start_time(t), status(s), shard_id(shard) {};

  void encode(bufferlist& bl) const {
    ENCODE_START(1, 1, bl);
    encode(bucket, bl);
    encode(start_time, bl);
    encode(status, bl);
    encode(shard_id, bl);
    ENCODE_FINISH(bl);
  }

  void decode(bufferlist::iterator& bl) {
    DECODE_START(1, bl);
    decode(bucket, bl);
    decode(start_time, bl);
    decode(status, bl);
    decode(shard_id, bl);
    DECODE_FINISH(bl);
  }
};
WRITE_CLASS_ENCODER(cls_rgw_lc_entry);

struct cls_rgw_reshard_entry
{
  ceph::real_time time;
  string tenant;
  string bucket_name;
  string bucket_id;
  string new_instance_id;
  uint32_t old_num_shards{0};
  uint32_t new_num_shards{0};

  cls_rgw_reshard_entry() {}

  void encode(bufferlist& bl) const {
    ENCODE_START(1, 1, bl);
    encode(time, bl);
    encode(tenant, bl);
    encode(bucket_name, bl);
    encode(bucket_id, bl);
    encode(new_instance_id, bl);
    encode(old_num_shards, bl);
    encode(new_num_shards, bl);
    ENCODE_FINISH(bl);
  }

  void decode(bufferlist::iterator& bl) {
    DECODE_START(1, bl);
    decode(time, bl);
    decode(tenant, bl);
    decode(bucket_name, bl);
    decode(bucket_id, bl);
    decode(new_instance_id, bl);
    decode(old_num_shards, bl);
    decode(new_num_shards, bl);
    DECODE_FINISH(bl);
  }

  void dump(Formatter *f) const;
  static void generate_test_instances(list<cls_rgw_reshard_entry*>& o);

  static void generate_key(const string& tenant, const string& bucket_name, string *key);
  void get_key(string *key) const;
};
WRITE_CLASS_ENCODER(cls_rgw_reshard_entry)

#endif
