// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#ifndef CEPH_MERGE_OBJCLASS_H
#define CEPH_MERGE_OBJCLASS_H

#include "include/rados/objclass.h"


class CLSMergedProcess {

protected:
  CephContext* cct;

public:
  CLSMergedProcess(CephContext* c) : cct(c) {}
  virtual ~CLSMergedProcess() {}

  virtual int cls_cxx_map_read_header(cls_method_context_t hctx, bufferlist *outbl) = 0;
  virtual int cls_cxx_map_write_header(cls_method_context_t hctx, bufferlist *inbl) = 0;

  virtual int cls_cxx_map_set_val(cls_method_context_t hctx,
                                  const std::string &key,
                                  ceph::bufferlist *inbl) = 0;
  virtual int cls_cxx_map_get_val(cls_method_context_t hctx,
                                  const std::string &key,
                                  ceph::bufferlist *outbl) = 0;
  virtual int cls_cxx_map_remove_key(cls_method_context_t hctx, const string &key) = 0;
  virtual int cls_cxx_map_remove_keys(cls_method_context_t hctx, const vector<string>& keys) = 0;

  virtual int cls_cxx_map_get_vals(cls_method_context_t hctx,
                                   const string &start_after,
                                   const string &filter_prefix,
                                   uint64_t max_to_get,
                                   std::map<string, bufferlist> *vals,
                                   bool *more) = 0;

  virtual void cls_cxx_map_snap() = 0;
  virtual void cls_cxx_map_apply() = 0;
  virtual void cls_cxx_map_rollback() = 0;
  virtual int cls_cxx_map_flush(cls_method_context_t hctx) = 0;
};

struct OmapCacheStat {
    OmapCacheStat() : deleted(false), dirty(false) {}
    OmapCacheStat(bufferlist &inbl, bool deleted, bool dirty): deleted(deleted), dirty(dirty) {
        value.claim(inbl);
    }
    OmapCacheStat(bufferlist *inbl, bool deleted, bool dirty): deleted(deleted), dirty(dirty) {
        value.clear();
        if (inbl) {
            value.append(*inbl);
        }
    }

    bufferlist value;
    bool deleted;
    bool dirty;
};

// for rgw cls merge
class CLSMergedRGWProcess : public CLSMergedProcess {
public:
  CLSMergedRGWProcess(CephContext *c) : CLSMergedProcess(c),
                                        header(nullptr),
                                        header_temp(nullptr),
                                        on_snap(false) {};

  CLSMergedRGWProcess() = delete;
  CLSMergedRGWProcess(const CLSMergedRGWProcess &) = delete;
  CLSMergedRGWProcess &operator=(const CLSMergedRGWProcess &) = delete;

  int cls_cxx_map_read_header(cls_method_context_t hctx, bufferlist *outbl) override;
  int cls_cxx_map_write_header(cls_method_context_t hctx, bufferlist *inbl) override;

  int cls_cxx_map_set_val(cls_method_context_t hctx,
                          const std::string &key,
                          ceph::bufferlist *inbl) override;
  int cls_cxx_map_get_val(cls_method_context_t hctx,
                          const std::string &key,
                          ceph::bufferlist *outbl) override;
  int cls_cxx_map_remove_key(cls_method_context_t hctx, const string &key) override;
  int cls_cxx_map_remove_keys(cls_method_context_t hctx, const vector<string>& keys) override;

  int cls_cxx_map_get_vals(cls_method_context_t hctx,
                           const string &start_after,
                           const string &filter_prefix,
                           uint64_t max_to_get,
                           std::map<string, bufferlist> *vals,
                           bool *more) override;

  // flush to PGTransaction
  int cls_cxx_map_flush(cls_method_context_t hctx) override;

  // take a snapshot of the current cache, for rollback no error
  void cls_cxx_map_snap() override;
  // apply this change
  void cls_cxx_map_apply() override;
  // an error occurred, rollback
  void cls_cxx_map_rollback() override;

private:
  unique_ptr<OmapCacheStat> header;
  unique_ptr<OmapCacheStat> header_temp;
  bool on_snap;
  std::map<std::string, unique_ptr<OmapCacheStat>> omaps;
  std::map<std::string, unique_ptr<OmapCacheStat>> omaps_temp;
};

CLSMergedProcess* make_merge_cache_processor(int type, CephContext *c);

#endif
