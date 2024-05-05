// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include "common/debug.h"
#include "objclass/merge_cls.h"
#include "osd/ClassHandler.h"

static constexpr int dout_subsys = ceph_subsys_objclass;

CLSMergedProcess* make_merge_cache_processor(int type, CephContext *cct)
{
    CLSMergedProcess *c = nullptr;

    switch(type) {
    case CLS_MERGE_OP_TYPE_RGW:
        c = new CLSMergedRGWProcess(cct);
        break;
    default:
      ldout(cct, 0) << __func__ << "unknown merge type " << type << dendl;
    }
    return c;
}

int CLSMergedRGWProcess::cls_cxx_map_read_header(cls_method_context_t hctx, bufferlist *outbl)
{
    ldout(cct, 10) << __func__ << " start " << dendl;
    if (header) {
        outbl->clear();
        outbl->append(header->value);
        ldout(cct, 20) << __func__ << " hit from header outbl.lenght=" << outbl->length()
                       << " cache value.length=" << header->value.length() << dendl;
        return 0;
    } else if (on_snap && header_temp) {
        outbl->clear();
        outbl->append(header_temp->value);
        ldout(cct, 20) << __func__ << " hit from header_temp outbl.lenght=" << outbl->length()
                       << " cache value.length=" << header_temp->value.length() << dendl;
        return 0;
    }

    int r = ::cls_cxx_map_read_header(hctx, outbl, true);
    if (r < 0) {
        lderr(cct) << __func__ << " failed to read header r=" << r << dendl;
        return r;
    }

    header = make_unique<OmapCacheStat>(outbl, false, false);

    ldout(cct, 20) << __func__ << " outbl.lenght=" << outbl->length()
                   << " cache value.length=" << header->value.length() << dendl;

    return 0;
}

int CLSMergedRGWProcess::cls_cxx_map_write_header(cls_method_context_t hctx, bufferlist *inbl)
{
    if (!header) {
        ldout(cct, 20) << __func__ << " write new header " << dendl;
        header = make_unique<OmapCacheStat>(*inbl, false, true);
    } else {
        header->value.claim(*inbl);
        header->dirty = true;
        ldout(cct, 20) << __func__ << " replace old header length="
                       << header->value.length() << dendl;
    }
    return 0;
}

int CLSMergedRGWProcess::cls_cxx_map_set_val(cls_method_context_t hctx,
                                             const std::string &key,
                                             ceph::bufferlist *inbl)
{
    ldout(cct, 10) << __func__ << " set key " << key << dendl;
    auto iter = omaps.emplace(key, nullptr);
    if (iter.second) {
        ldout(cct, 20) << __func__ << " set new key " << key << dendl;
        iter.first->second = make_unique<OmapCacheStat>(*inbl, false, true);
    } else {
        ldout(cct, 20) << __func__ << " replace old key " << key << dendl;
        OmapCacheStat *om = iter.first->second.get();
        om->value.claim(*inbl);
        om->deleted = false;
        om->dirty = true;
    }
    return 0;
}

int CLSMergedRGWProcess::cls_cxx_map_get_val(cls_method_context_t hctx,
                                             const std::string &key,
                                             ceph::bufferlist *outbl)
{
    ldout(cct, 10) << __func__ << " get key " << key << dendl;
    auto iter = omaps.find(key);
    // find in omaps
    if (iter != omaps.end()) {
        if (iter->second->deleted) {
            ldout(cct, 20) << __func__ << " key " << key << " is deleted" << dendl;
            return -ENOENT;
        }
        ldout(cct, 20) << __func__ << " get key from cache " << key << dendl;
        outbl->clear();
        outbl->append(iter->second->value);
        return 0;
    }
    // find in temp omaps
    if (on_snap) {
        iter = omaps_temp.find(key);
        if (iter != omaps_temp.end()) {
            if (iter->second->deleted) {
                ldout(cct, 20) << __func__ << " snap key " << key << " is deleted" << dendl;
                return -ENOENT;
            }
            ldout(cct, 20) << __func__ << " get key from omaps_temp " << key << dendl;
            outbl->clear();
            outbl->append(iter->second->value);
            return 0;
        }
    }
    // find in rocksdb
    int r = ::cls_cxx_map_get_val(hctx, key, outbl, true);
    if (r < 0) {
        if (r != -ENOENT) {
          lderr(cct) << __func__ << " failed get key " << key
                     << " from KV ret=" << r << dendl;
        }
        return r;
    }
    // insert value to cache
    omaps[key] = make_unique<OmapCacheStat>(outbl, false, false);

    ldout(cct, 20) << __func__ << " outbl.lenght=" << outbl->length()
                   << " cache value.length=" << omaps[key]->value.length() << dendl;

    return 0;
}

int CLSMergedRGWProcess::cls_cxx_map_remove_key(cls_method_context_t hctx, const string &key)
{
    ldout(cct, 10) << __func__ << " remove key " << key << dendl;
    auto iter = omaps.emplace(key, nullptr);
    if (iter.second) {
        ldout(cct, 20) << __func__ << " remove new key " << key << dendl;
        iter.first->second = make_unique<OmapCacheStat>(nullptr, true, true);
    } else {
        ldout(cct, 20) << __func__ << " remove exist key " << key << dendl;
        OmapCacheStat *om = iter.first->second.get();
        om->value.clear();
        om->deleted = true;
        om->dirty = true;
    }
    return 0;
}

int CLSMergedRGWProcess::cls_cxx_map_remove_keys(cls_method_context_t hctx, const vector<string>& keys)
{
  for (auto key : keys) {
    cls_cxx_map_remove_key(hctx, key);
  }
  return 0;
}

// NOTE: this function cannot list the values that have not yet been submitted to rocksdb
int CLSMergedRGWProcess::cls_cxx_map_get_vals(cls_method_context_t hctx,
                                              const string &start_after,
                                              const string &filter_prefix,
                                              uint64_t max_to_get,
                                              std::map<string, bufferlist> *vals,
                                              bool *more)
{
    ldout(cct, 20) << __func__ << " start_after " <<  start_after 
                   << " filter_prefix " << filter_prefix << dendl;
    return ::cls_cxx_map_get_vals(hctx, start_after, filter_prefix, max_to_get, vals, more, true);
}


// take a snapshot of the current cache, for rollback no error
void CLSMergedRGWProcess::cls_cxx_map_snap()
{
    ldout(cct, 10) << __func__ << " set snap " << dendl;
    assert(!on_snap);
    // backup omaps
    omaps_temp.clear();
    omaps_temp.swap(omaps);

    // backup omap header
    if (header_temp) {
        header_temp.reset(nullptr);
    }
    if (header) {
        std::swap(header_temp, header);
    }
    on_snap = true;
}

// apply this change
void CLSMergedRGWProcess::cls_cxx_map_apply()
{
    ldout(cct, 10) << __func__ << " apply snap " << dendl;
    assert(on_snap);

    // apply omaps
    for (auto& iter : omaps) {
        ldout(cct, 20) << __func__ << " merge " << iter.first
                       << " len " << iter.second->value.length() << dendl;
        omaps_temp[iter.first] = std::move(iter.second);
    }
    omaps.clear();
    omaps.swap(omaps_temp);

    // apply header
    if (header) {
        if (header_temp) {
            header_temp.reset(nullptr);
        }
    } else if(header_temp) {
        std::swap(header_temp, header);
    }

    on_snap = false;
}

// an error occurred, rollback
void CLSMergedRGWProcess::cls_cxx_map_rollback()
{
    ldout(cct, 10) << __func__ << " rollback " << dendl;
    assert(on_snap);
    // rollback omaps
    omaps.clear();
    omaps.swap(omaps_temp);

    // rollback header
    header.reset(nullptr);
    if (header_temp) {
        std::swap(header, header_temp);
    }

    on_snap = false;
}

// flush to PGTransaction
int CLSMergedRGWProcess::cls_cxx_map_flush(cls_method_context_t hctx)
{
    ldout(cct, 10) << __func__ << " start " << dendl;
    int r = 0;
    assert(!on_snap);
    if (header != nullptr && header->dirty) {
        ldout(cct, 20) << __func__ << " write omap header" << dendl;
        r = ::cls_cxx_map_write_header(hctx, &(header->value), true);
        if (r < 0) {
            ldout(cct, 0) << __func__ << " failed to write omap header ret=" << r << dendl;
            goto done;
        }
    }

    for (auto& iter : omaps) {
        if (!iter.second->dirty) {
            continue;
        }
        if (iter.second->deleted) {
            ldout(cct, 20) << __func__ << " remove omap key " << iter.first << dendl;
            r = ::cls_cxx_map_remove_key(hctx, iter.first, true);
            if (r < 0) {
                ldout(cct, 0) << __func__ << " failed to remove omap key " << iter.first
                              << " ret=" << r << dendl;
                goto done;
            }
        } else {
            ldout(cct, 20) << __func__ << " set omap key " << iter.first << dendl;
            r = ::cls_cxx_map_set_val(hctx, iter.first, &(iter.second->value), true);
            if (r < 0) {
                ldout(cct, 0) << __func__ << " failed to set omap key " << iter.first
                              << " ret=" << r << dendl;
                goto done;
            }
        }
    }

done:
    // clear cache
    header.reset(nullptr);
    header_temp.reset(nullptr);
    omaps.clear();
    omaps_temp.clear();

    return r;
}
