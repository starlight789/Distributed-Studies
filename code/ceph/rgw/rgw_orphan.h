// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*- 
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2015 Red Hat
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software 
 * Foundation.  See file COPYING.
 * 
 */

#ifndef CEPH_RGW_ORPHAN_H
#define CEPH_RGW_ORPHAN_H

#include "common/config.h"
#include "common/Formatter.h"
#include "common/iso_8601.h"
#include "common/errno.h"

#include "rgw_rados.h"

#define dout_subsys ceph_subsys_rgw

#define RGW_ORPHAN_INDEX_OID "orphan.index"
#define RGW_ORPHAN_INDEX_PREFIX "orphan.scan"


enum RGWOrphanSearchStageId {
  ORPHAN_SEARCH_STAGE_UNKNOWN = 0,
  ORPHAN_SEARCH_STAGE_INIT = 1,
  ORPHAN_SEARCH_STAGE_LSPOOL = 2,
  ORPHAN_SEARCH_STAGE_LSBUCKETS = 3,
  ORPHAN_SEARCH_STAGE_ITERATE_BI = 4,
  ORPHAN_SEARCH_STAGE_COMPARE = 5,
};


struct RGWOrphanSearchStage {
  RGWOrphanSearchStageId stage;
  int shard;
  string marker;

  RGWOrphanSearchStage() : stage(ORPHAN_SEARCH_STAGE_UNKNOWN), shard(0) {}
  explicit RGWOrphanSearchStage(RGWOrphanSearchStageId _stage) : stage(_stage), shard(0) {}
  RGWOrphanSearchStage(RGWOrphanSearchStageId _stage, int _shard, const string& _marker) : stage(_stage), shard(_shard), marker(_marker) {}

  void encode(bufferlist& bl) const {
    ENCODE_START(1, 1, bl);
    encode((int)stage, bl);
    encode(shard, bl);
    encode(marker, bl);
    ENCODE_FINISH(bl);
  }

  void decode(bufferlist::iterator& bl) {
    DECODE_START(1, bl);
    int s;
    decode(s, bl);
    stage = (RGWOrphanSearchStageId)s;
    decode(shard, bl);
    decode(marker, bl);
    DECODE_FINISH(bl);
  }

  void dump(Formatter *f) const;
};
WRITE_CLASS_ENCODER(RGWOrphanSearchStage)
  
struct RGWOrphanSearchInfo {
  string job_name;
  rgw_pool pool;
  uint16_t num_shards;
  utime_t start_time;

  void encode(bufferlist& bl) const {
    ENCODE_START(2, 1, bl);
    encode(job_name, bl);
    encode(pool.to_str(), bl);
    encode(num_shards, bl);
    encode(start_time, bl);
    ENCODE_FINISH(bl);
  }

  void decode(bufferlist::iterator& bl) {
    DECODE_START(2, bl);
    decode(job_name, bl);
    string s;
    decode(s, bl);
    pool.from_str(s);
    decode(num_shards, bl);
    decode(start_time, bl);
    DECODE_FINISH(bl);
  }

  void dump(Formatter *f) const;
};
WRITE_CLASS_ENCODER(RGWOrphanSearchInfo)

struct RGWOrphanSearchState {
  RGWOrphanSearchInfo info;
  RGWOrphanSearchStage stage;

  RGWOrphanSearchState() : stage(ORPHAN_SEARCH_STAGE_UNKNOWN) {}

  void encode(bufferlist& bl) const {
    ENCODE_START(1, 1, bl);
    encode(info, bl);
    encode(stage, bl);
    ENCODE_FINISH(bl);
  }

  void decode(bufferlist::iterator& bl) {
    DECODE_START(1, bl);
    decode(info, bl);
    decode(stage, bl);
    DECODE_FINISH(bl);
  }

  void dump(Formatter *f) const;
};
WRITE_CLASS_ENCODER(RGWOrphanSearchState)

class RGWOrphanStore {
  RGWRados *store;
  librados::IoCtx ioctx;

  string oid;

public:
  explicit RGWOrphanStore(RGWRados *_store) : store(_store), oid(RGW_ORPHAN_INDEX_OID) {}

  librados::IoCtx& get_ioctx() { return ioctx; }

  int init();

  int read_job(const string& job_name, RGWOrphanSearchState& state);
  int write_job(const string& job_name, const RGWOrphanSearchState& state);
  int remove_job(const string& job_name);
  int list_jobs(map<string,RGWOrphanSearchState> &job_list);


  int store_entries(const string& oid, const map<string, bufferlist>& entries);
  int read_entries(const string& oid, const string& marker, map<string, bufferlist> *entries, bool *truncated);
};


class RGWOrphanSearch {
  RGWRados *store;

  RGWOrphanStore orphan_store;

  RGWOrphanSearchInfo search_info;
  RGWOrphanSearchStage search_stage;

  map<int, string> all_objs_index;
  map<int, string> buckets_instance_index;
  map<int, string> linked_objs_index;

  string index_objs_prefix;

  uint16_t max_concurrent_ios;
  uint64_t stale_secs;

  struct log_iter_info {
    string oid;
    list<string>::iterator cur;
    list<string>::iterator end;
  };

  int log_oids(map<int, string>& log_shards, map<int, list<string> >& oids);

#define RGW_ORPHANSEARCH_HASH_PRIME 7877
  int orphan_shard(const string& str) {
    return ceph_str_hash_linux(str.c_str(), str.size()) % RGW_ORPHANSEARCH_HASH_PRIME % search_info.num_shards;
  }

  int handle_stat_result(map<int, list<string> >& oids, RGWRados::Object::Stat::Result& result);
  int pop_and_handle_stat_op(map<int, list<string> >& oids, std::deque<RGWRados::Object::Stat>& ops);


  int remove_index(map<int, string>& index);
public:
  RGWOrphanSearch(RGWRados *_store, int _max_ios, uint64_t _stale_secs) : store(_store), orphan_store(store), max_concurrent_ios(_max_ios), stale_secs(_stale_secs) {}

  int save_state() {
    RGWOrphanSearchState state;
    state.info = search_info;
    state.stage = search_stage;
    return orphan_store.write_job(search_info.job_name, state);
  }

  int init(const string& job_name, RGWOrphanSearchInfo *info);

  int create(const string& job_name, int num_shards);

  int build_all_oids_index();
  int build_buckets_instance_index();
  int build_linked_oids_for_bucket(const string& bucket_instance_id, map<int, list<string> >& oids);
  int build_linked_oids_index();
  int compare_oid_indexes();

  int run();
  int finish();
};

int init_buckets_list(RGWRados *store, std::unordered_map<string, RGWBucketInfo>& buckets_name_index);

class RGWMultipartOrphanSearch {
  RGWRados *store;
  string input_file;
  string useless_part_file_name;
  // include deleted bucket marker and removed object
  string invalid_bucket_file_name;


  // key: bucket marker, value: bucket info
  std::unordered_map<string, RGWBucketInfo> buckets_name_index;

  // key: bucket_marker+object_name  value: vector<raw_obj_name>
  std::unordered_map<string, vector<string>> multipart_obj_parts;


  int init_obj_parts_list(const string& part_list_file);
public:
  RGWMultipartOrphanSearch(RGWRados *_store, string& _input_file) : store(_store), input_file(_input_file) {
    string ts = std::to_string(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    useless_part_file_name = "useless_part_list" + ts;
    invalid_bucket_file_name = "invalid_bucket_list" + ts;
  }

  int run();

};

class RGWGCLeftObjClear {
  RGWRados *store;
  string input_file;
  uint32_t before_day;
  int clear_trully;

  // key: bucket marker, value: bucket info
  std::unordered_map<string, RGWBucketInfo> buckets_name_index;

  std::unordered_set<string> exist_obj;
  std::unordered_set<string> nonexist_obj;

  int head_obj_is_exist(string& object_name,
                        const string& bucket_marker,
                        const rgw_obj& head_obj,
                        RGWBucketInfo& bucket_info,
                        const string& line);
  int remove_raw_obj(const rgw_raw_obj& raw_obj);
  public:
  RGWGCLeftObjClear(RGWRados *_store, const string& _input_file, uint32_t _before_day, int _clear_trully)
    : store(_store), input_file(_input_file), before_day(_before_day), clear_trully(_clear_trully) {}

  int run();

};

#endif
