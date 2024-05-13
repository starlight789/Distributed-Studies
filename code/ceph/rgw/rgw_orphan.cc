// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include <string>
#include <regex>

#include "common/config.h"
#include "common/Formatter.h"
#include "common/errno.h"

#include "rgw_rados.h"
#include "rgw_orphan.h"
#include "rgw_multi.h"

#include "cls/refcount/cls_refcount_client.h"

#define dout_context g_ceph_context
#define dout_subsys ceph_subsys_rgw

#define DEFAULT_NUM_SHARDS 64

static string obj_fingerprint(const string& oid, const char *force_ns = NULL)
{
  ssize_t pos = oid.find('_');
  if (pos < 0) {
    cerr << "ERROR: object does not have a bucket marker: " << oid << std::endl;
  }

  string obj_marker = oid.substr(0, pos);

  rgw_obj_key key;

  rgw_obj_key::parse_raw_oid(oid.substr(pos + 1), &key);

  if (key.ns.empty()) {
    return oid;
  }

  string s = oid;

  if (force_ns) {
    rgw_bucket b;
    rgw_obj new_obj(b, key);
    s = obj_marker + "_" + new_obj.get_oid();
  }

  /* cut out suffix */
  size_t i = s.size() - 1;
  for (; i >= s.size() - 10; --i) {
    char c = s[i];
    if (!isdigit(c) && c != '.' && c != '_') {
      break;
    }
  }

  return s.substr(0, i + 1);
}

int RGWOrphanStore::read_job(const string& job_name, RGWOrphanSearchState & state)
{
  set<string> keys;
  map<string, bufferlist> vals;
  keys.insert(job_name);
  int r = ioctx.omap_get_vals_by_keys(oid, keys, &vals);
  if (r < 0) {
    return r;
  }

  map<string, bufferlist>::iterator iter = vals.find(job_name);
  if (iter == vals.end()) {
    return -ENOENT;
  }

  try {
    bufferlist& bl = iter->second;
    decode(state, bl);
  } catch (buffer::error& err) {
    lderr(store->ctx()) << "ERROR: could not decode buffer" << dendl;
    return -EIO;
  }

  return 0;
}

int RGWOrphanStore::write_job(const string& job_name, const RGWOrphanSearchState& state)
{
  map<string, bufferlist> vals;
  bufferlist bl;
  encode(state, bl);
  vals[job_name] = bl;
  int r = ioctx.omap_set(oid, vals);
  if (r < 0) {
    return r;
  }

  return 0;
}

int RGWOrphanStore::remove_job(const string& job_name)
{
  set<string> keys;
  keys.insert(job_name);

  int r = ioctx.omap_rm_keys(oid, keys);
  if (r < 0) {
    return r;
  }

  return 0;
}

int RGWOrphanStore::list_jobs(map <string,RGWOrphanSearchState>& job_list)
{
  map <string,bufferlist> vals;
  int MAX_READ=1024;
  string marker="";
  int r = 0;

  // loop through all the omap vals from index object, storing them to job_list,
  // read in batches of 1024, we update the marker every iteration and exit the
  // loop when we find that total size read out is less than batch size
  do {
    r = ioctx.omap_get_vals(oid, marker, MAX_READ, &vals);
    if (r < 0) {
      return r;
    }
    r = vals.size();

    for (const auto &it : vals) {
      marker=it.first;
      RGWOrphanSearchState state;
      try {
        bufferlist bl = it.second;
        decode(state, bl);
      } catch (buffer::error& err) {
        lderr(store->ctx()) << "ERROR: could not decode buffer" << dendl;
        return -EIO;
      }
      job_list[it.first] = state;
    }
  } while (r == MAX_READ);

  return 0;
}

int RGWOrphanStore::init()
{
  rgw_pool& log_pool = store->get_zone_params().log_pool;
  int r = rgw_init_ioctx(store->get_rados_handle(), log_pool, ioctx);
  if (r < 0) {
    cerr << "ERROR: failed to open log pool (" << log_pool << " ret=" << r << std::endl;
    return r;
  }

  return 0;
}

int RGWOrphanStore::store_entries(const string& oid, const map<string, bufferlist>& entries)
{
  librados::ObjectWriteOperation op;
  op.omap_set(entries);
  cout << "storing " << entries.size() << " entries at " << oid << std::endl;
  ldout(store->ctx(), 20) << "storing " << entries.size() << " entries at " << oid << ": " << dendl;
  for (map<string, bufferlist>::const_iterator iter = entries.begin(); iter != entries.end(); ++iter) {
    ldout(store->ctx(), 20) << " > " << iter->first << dendl;
  }
  int ret = ioctx.operate(oid, &op);
  if (ret < 0) {
    lderr(store->ctx()) << "ERROR: " << __func__ << "(" << oid << ") returned ret=" << ret << dendl;
  }
  
  return 0;
}

int RGWOrphanStore::read_entries(const string& oid, const string& marker, map<string, bufferlist> *entries, bool *truncated)
{
#define MAX_OMAP_GET 100
  int ret = ioctx.omap_get_vals(oid, marker, MAX_OMAP_GET, entries);
  if (ret < 0 && ret != -ENOENT) {
    cerr << "ERROR: " << __func__ << "(" << oid << ") returned ret=" << cpp_strerror(-ret) << std::endl;
  }

  *truncated = (entries->size() == MAX_OMAP_GET);

  return 0;
}

int RGWOrphanSearch::init(const string& job_name, RGWOrphanSearchInfo *info) {
  int r = orphan_store.init();
  if (r < 0) {
    return r;
  }

  RGWOrphanSearchState state;
  r = orphan_store.read_job(job_name, state);
  if (r < 0 && r != -ENOENT) {
    lderr(store->ctx()) << "ERROR: failed to read state ret=" << r << dendl;
    return r;
  }

  if (r == 0) {
    search_info = state.info;
    search_stage = state.stage;
  } else if (info) { /* r == -ENOENT, initiate a new job if info was provided */ 
    search_info = *info;
    search_info.job_name = job_name;
    search_info.num_shards = (info->num_shards ? info->num_shards : DEFAULT_NUM_SHARDS);
    search_info.start_time = ceph_clock_now();
    search_stage = RGWOrphanSearchStage(ORPHAN_SEARCH_STAGE_INIT);

    r = save_state();
    if (r < 0) {
      lderr(store->ctx()) << "ERROR: failed to write state ret=" << r << dendl;
      return r;
    }
  } else {
      lderr(store->ctx()) << "ERROR: job not found" << dendl;
      return r;
  }

  index_objs_prefix = RGW_ORPHAN_INDEX_PREFIX + string(".");
  index_objs_prefix += job_name;

  for (int i = 0; i < search_info.num_shards; i++) {
    char buf[128];

    snprintf(buf, sizeof(buf), "%s.rados.%d", index_objs_prefix.c_str(), i);
    all_objs_index[i] = buf;

    snprintf(buf, sizeof(buf), "%s.buckets.%d", index_objs_prefix.c_str(), i);
    buckets_instance_index[i] = buf;

    snprintf(buf, sizeof(buf), "%s.linked.%d", index_objs_prefix.c_str(), i);
    linked_objs_index[i] = buf;
  }
  return 0;
}

int RGWOrphanSearch::log_oids(map<int, string>& log_shards, map<int, list<string> >& oids)
{
  map<int, list<string> >::iterator miter = oids.begin();

  list<log_iter_info> liters; /* a list of iterator pairs for begin and end */

  for (; miter != oids.end(); ++miter) {
    log_iter_info info;
    info.oid = log_shards[miter->first];
    info.cur = miter->second.begin();
    info.end = miter->second.end();
    liters.push_back(info);
  }

  list<log_iter_info>::iterator list_iter;
  while (!liters.empty()) {
     list_iter = liters.begin();

     while (list_iter != liters.end()) {
       log_iter_info& cur_info = *list_iter;

       list<string>::iterator& cur = cur_info.cur;
       list<string>::iterator& end = cur_info.end;

       map<string, bufferlist> entries;
#define MAX_OMAP_SET_ENTRIES 100
       for (int j = 0; cur != end && j != MAX_OMAP_SET_ENTRIES; ++cur, ++j) {
         ldout(store->ctx(), 20) << "adding obj: " << *cur << dendl;
         entries[*cur] = bufferlist();
       }

       int ret = orphan_store.store_entries(cur_info.oid, entries);
       if (ret < 0) {
         return ret;
       }
       list<log_iter_info>::iterator tmp = list_iter;
       ++list_iter;
       if (cur == end) {
         liters.erase(tmp);
       }
     }
  }
  return 0;
}

int init_buckets_list(RGWRados *store, std::unordered_map<string, RGWBucketInfo>& buckets_name_index) {
  RGWAccessHandle handle;

  if (store->list_buckets_init(&handle) >= 0) {
    rgw_bucket_dir_entry obj;
    while (store->list_buckets_next(obj, &handle) >= 0) {
      RGWObjectCtx obj_ctx(store);
      RGWBucketInfo bucket_info;

      int ret = store->get_bucket_info(obj_ctx, "", obj.key.name, bucket_info, NULL, NULL);
      if (ret < 0) {
        ldout(store->ctx(), 0) << __func__ << "(): ERROR get_bucket_info for " << obj.key.name
                               << " ret:" << ret
                               << dendl;
        cerr << "ERROR: failed to get bucket info:" << obj.key.name
             << " ret:" << ret
             << std::endl;
        return ret;
      }
      buckets_name_index[bucket_info.bucket.marker] = bucket_info;
    }
  }
  return 0;
}

int RGWMultipartOrphanSearch::init_obj_parts_list(const string& part_list_file) {
  ifstream whole_parts_file(part_list_file);
  string strline;
  while (getline(whole_parts_file, strline)) {
    auto pos = strline.find("__");
    if (pos == string::npos || pos == strline.length() - 2) {
      cerr << "ERROR: invalid part raw obj:"<< strline << std::endl;
      return -EINTR;
    }
    string bucket_marker = strline.substr(0, pos);
    auto end_dot = strline.rfind(".");
    if (end_dot == string::npos) {
      cerr << "ERROR: invalid part raw obj:"<< strline << std::endl;
      return -EINTR;
    }
    string temp = strline.substr(0, end_dot);
    auto obj_end_pos = temp.rfind(".");
    if (obj_end_pos == string::npos) {
      cerr << "ERROR: invalid part raw obj:"<< strline << std::endl;
      return -EINTR;
    }
    string object_name;
    if (strline.compare(pos, strlen("__multipart_"), "__multipart_") == 0) {
      // multipart
      auto obj_beg_pos = pos + strlen("__multipart_");
      if (obj_beg_pos >= obj_end_pos) {
        cerr << "ERROR: invalid part raw obj:"<< strline << std::endl;
        return -EINTR;
      }
      object_name = temp.substr(obj_beg_pos, obj_end_pos - obj_beg_pos);
    } else if (strline[pos+2] == 's') {
      // shadow
      auto obj_beg_pos = pos + strlen("__shadow_");
      if (obj_beg_pos >= obj_end_pos) {
        cerr << "ERROR: invalid part raw obj:"<< strline << std::endl;
        return -EINTR;
      }
      object_name = temp.substr(obj_beg_pos, obj_end_pos - obj_beg_pos);
    } else {
      cerr << "ERROR: invalid part raw obj:"<< strline << std::endl;
      return -EINTR;
    }

    multipart_obj_parts[bucket_marker + "+" + object_name].push_back(strline);
  }
  whole_parts_file.close();
  cout << "NOTICE: iterate whole_parts_file end "<< ceph_clock_now() << std::endl;
  return 0;
}


int RGWMultipartOrphanSearch::run() {
  size_t pos = input_file.find(',');
  if (pos == string::npos) {
    cerr << "invalid file param, need [statis.num2.list],[part.list]" << std::endl;
    /* what is this object, oids should be in the format of <bucket marker>_<obj>,
     * skip this entry
     */
    return -EINVAL;
  }
  ifstream repeated_parts_file(input_file.substr(0, pos));
  string line;
  string part_list_file = input_file.substr(pos + 1);

  ofstream useless_part_file(useless_part_file_name);
  ofstream invalid_bucket_file(invalid_bucket_file_name);

  if(!repeated_parts_file) {
    cerr << "ERROR: failed to read input:" << input_file << std::endl;
    return -EINVAL;
  }

  int ret = init_buckets_list(store, buckets_name_index);
  if (ret < 0) {
    return -EINTR;
  }

  ret = init_obj_parts_list(part_list_file);
  if (ret < 0) {
    return -EINTR;
  }

  uint64_t line_num = 0;

  while(getline(repeated_parts_file, line)) {
    line_num++;
    if (line_num % 10000 == 0) {
      cout << "NOTICE: process lines:" << line_num << std::endl;
    }
    pos = line.find("__multipart_");
    if (pos == string::npos) {
      ldout(store->ctx(), 0) << "ERROR: unidentified oid, skip it:" << line << dendl;
      continue;
    }
    string bucket_marker = line.substr(0, pos);
    auto binfo_iter = buckets_name_index.find(bucket_marker);
    if (binfo_iter == buckets_name_index.end()) {
      ldout(store->ctx(), 10) << "couldn't find bucket info, bucket marker:"
                              << bucket_marker << ", bucket is deleted,"
                              << " its orphan objs can be removed directly"
                              << dendl;
      invalid_bucket_file << bucket_marker << std::endl;
      continue;
    }
    string obj_name = line.substr(pos + strlen("__multipart_"));

    RGWBucketInfo& bucket_info = binfo_iter->second;
    rgw_obj head_obj(bucket_info.bucket, obj_name);

    RGWObjState *astate = nullptr;
    RGWObjectCtx obj_ctx(store);
    int r = store->get_obj_state(&obj_ctx, bucket_info, head_obj, &astate);
    if (r < 0) {
      cerr << "ERROR: get obj state eror:" << head_obj << std::endl;
      return r;
    }

    if (!astate->exists) {
      vector<rgw_bucket_dir_entry> objs;
      string prefix = "";
      string delim = "";
      int max_objs = 1;
      r = list_bucket_multiparts(store, bucket_info, prefix, obj_name, delim,
                                 max_objs, &objs, nullptr, nullptr);
      if (r < 0) {
        cerr << "ERROR: list_bucket_multiparts eror:" << r << std::endl;
        return r;
      }
      bool is_in_multiparting = false;
      for (auto& o : objs) {
        string meta = o.key.name;
        int end_pos = meta.rfind('.'); // search for ".meta"
        if (end_pos < 0) {
          cerr << "ERROR: invalid in_multipart obj name:" << meta << std::endl;
          return -EINTR;
        }
        int mid_pos = meta.rfind('.', end_pos - 1); // <key>.<upload_id>
        if (mid_pos < 0) {
          cerr << "ERROR: invalid in_multipart obj name:" << meta << std::endl;
          return -EINTR;
        }
        string oid = meta.substr(strlen("_multipart_"), mid_pos - strlen("_multipart_"));
        if (oid.compare(obj_name) == 0) {
          ldout(store->ctx(), 20) << "object hasn't been completed multipart, retain it:"
                                  << obj_name << dendl;
          is_in_multiparting = true;
          break;
        }
      }
      if (is_in_multiparting) {
        continue;
      }
      // need check head obj again, avoid complete multipart between get_obj_state&list_bucket_multiparts
      obj_ctx.obj.invalidate(head_obj);

      r = store->get_obj_state(&obj_ctx, bucket_info, head_obj, &astate);
      if (r < 0) {
        cerr << "ERROR: get obj state eror:" << head_obj << std::endl;
        return r;
      }
      if (astate->exists) {
        ldout(store->ctx(), 10) << "object is completed between orphan find, ignore its parts:"
                                << obj_name << dendl;
        continue;
      }
      // find object's left repeated parts, 
      auto iter_parts = multipart_obj_parts.find(bucket_marker + "+" + obj_name);
      if (iter_parts == multipart_obj_parts.end()) {
        continue;
      }
      rgw_placement_rule dest_placement;
      dest_placement.storage_class = bucket_info.storage_class;
      dest_placement.name = bucket_info.head_placement_rule.name;

      // all of its left parts should be removed if it has no refcount attr
      for (auto& s : iter_parts->second) {
        rgw_raw_obj raw_obj;
        store->get_obj_data_pool(dest_placement, head_obj, &raw_obj.pool);
        raw_obj.oid = s;
        map<string, bufferlist> attrs;
        int r = store->raw_obj_stat(raw_obj, NULL, NULL, NULL, &attrs, NULL, nullptr, false);
        if (r < 0) {
          cerr << "ERROR: get raw obj stat err:" << raw_obj
               << ", ret:" << r << std::endl;
          continue;
        }
        auto iter = attrs.find("refcount");
        if (iter != attrs.end()) {
          ldout(store->ctx(), 10) << "this raw object is copyed by other, keep it:" << s << dendl;
          continue;
        }
        useless_part_file << s << std::endl;
      }

      continue; // below codes are work for object existing condition.
    }

    const map<uint64_t, RGWObjManifestRule>& rules = astate->manifest.get_rules();


    for (auto iter = rules.begin(); iter != rules.end(); ++iter) {

      string prefix_str = bucket_info.bucket.marker + "__multipart_" + obj_name;
      string useful_part;
      if (iter->second.override_prefix.empty()) {
        useful_part = astate->manifest.get_prefix() + "." + to_string(iter->second.start_part_num);
      } else {
        useful_part = iter->second.override_prefix + "." + to_string(iter->second.start_part_num);
      }
      bool found_useful = false;
      vector<string> repeated_multipart_objs;

      auto iter_parts = multipart_obj_parts.find(bucket_marker + "+" + obj_name);
      if (iter_parts == multipart_obj_parts.end()) {
        continue;
      }

      for (auto& s : iter_parts->second) {
        ssize_t end_dot = s.rfind('.');
        string temp = s.substr(0, end_dot);
        auto obj_end_pos = temp.rfind('.');
        if (!boost::algorithm::starts_with(temp.substr(0, obj_end_pos), prefix_str)) {
          continue;
        }

        string part = s.substr(end_dot + 1);
        if (part.compare(to_string(iter->second.start_part_num)) != 0) {
          continue;
        }

        if (boost::algorithm::ends_with(s, useful_part)) {
          found_useful = true;
          continue;
        }
        repeated_multipart_objs.push_back(s);
      }

      if (repeated_multipart_objs.size() > 0) {
        if (found_useful) {
          for (auto o : repeated_multipart_objs) {
            rgw_raw_obj raw_obj;
            store->get_obj_data_pool(astate->manifest.get_tail_placement().placement_rule, head_obj, &raw_obj.pool);
            raw_obj.oid = o;
            ceph::real_time mtime;
            map<string, bufferlist> attrs;
            int r = store->raw_obj_stat(raw_obj, NULL, &mtime, NULL, &attrs, NULL, nullptr, false);
            if (r < 0) {
              cerr << "ERROR: get raw obj stat err:" << raw_obj
                   << ", ret:" << r << std::endl;
              continue;
            }
            auto iter = attrs.find("refcount");
            if (iter != attrs.end()) {
              cerr << "ERROR: useless part shouldn't be referenced, raw object"
                   << o << std::endl;
              continue;
            }

            if (mtime > astate->mtime) {
              cerr << "ERROR: useless part is newer than object:" << o
                   << " mtime:" << mtime << " object mtime:" << astate->mtime
                   << std::endl;
              continue;
            }

            useless_part_file << o << std::endl;

            // find all shadow objs


            pos = o.find(head_obj.key.name);
            if (pos == string::npos) {
              cerr << "ERROR: couldn't find obj name in raw_obj:" << o
                   << " obj:" << head_obj
                   << std::endl;
              continue;
            }

            string shadow_key = "__shadow_" + o.substr(pos);
            for (auto& s : iter_parts->second) {
              if (s.find(shadow_key) != std::string::npos) {
                useless_part_file << s << std::endl;
              }
            }

          }
        } else {
          ldout(store->ctx(), 20) << "ERROR: couldn't find useful part:" << head_obj
               << " part num:" << iter->second.start_part_num
               << " override_prefix:" << iter->second.override_prefix
               << dendl;
          return -EIO;
        }
      }
    }

  }
  return 0;
}

int split_tail_obj(string& raw_obj, string& bucket_marker, string& object_name) {
  auto pos = raw_obj.find("__");
  if (pos == string::npos || pos == raw_obj.length() - 2) {
    dout(10) << "not part raw obj, skip it:"<< raw_obj << dendl;
    return -EBADFD;
  }
  bucket_marker = raw_obj.substr(0, pos);
  auto end_dot = raw_obj.rfind(".");
  if (end_dot == string::npos) {
    dout(10) << "not part raw obj, skip it:"<< raw_obj << dendl;
    return -EBADFD;
  }
  string temp = raw_obj.substr(0, end_dot);
  auto obj_end_pos = temp.rfind(".");
  if (obj_end_pos == string::npos) {
    dout(10) << "not part raw obj, skip it:"<< raw_obj << dendl;
    return -EBADFD;
  }
  if (raw_obj.compare(pos, strlen("__multipart_"), "__multipart_") == 0) {
    // multipart
    auto obj_beg_pos = pos + strlen("__multipart_");
    if (obj_beg_pos >= obj_end_pos) {
      cerr << "ERROR: invalid part raw obj:"<< raw_obj << std::endl;
      return -EINVAL;
    }
    object_name = temp.substr(obj_beg_pos, obj_end_pos - obj_beg_pos);
  } else if (raw_obj[pos+2] == 's') {
    // shadow
    auto obj_beg_pos = pos + strlen("__shadow_");
    if (obj_beg_pos >= obj_end_pos) {
      cerr << "ERROR: invalid part raw obj:"<< raw_obj << std::endl;
      return -EINVAL;
    }
    object_name = temp.substr(obj_beg_pos, obj_end_pos - obj_beg_pos);
  } else {
    dout(10) << "not part raw obj, skip it:"<< raw_obj << dendl;
    return -EBADFD;
  }
  return 0;
}

#define ONE_DAY 86400

int RGWGCLeftObjClear::run() {
  ifstream raw_objs_file(input_file);
  if(!raw_objs_file) {
    cerr << "ERROR: failed to read input:" << input_file << std::endl;
    return -EINVAL;
  }

  if (before_day < 1) {
    cerr << "ERROR: only support clear timeout more than one day, invalid before_day param:" << before_day << std::endl;
    return -EINVAL;
  }

  int ret = init_buckets_list(store, buckets_name_index);
  if (ret < 0) {
    return -EINTR;
  }

  string line;
  uint64_t line_num = 0;
  while(getline(raw_objs_file, line)) {
    line_num++;
    if (line_num % 10000 == 0) {
      cout << "NOTICE: process lines:" << line_num << std::endl;
    }
    string bucket_marker = "";
    string object_name = "";

    ret = split_tail_obj(line, bucket_marker, object_name);
    if (ret < 0) {
      if (ret == -EINVAL) {
        return ret;
      }
      // skip invalid part raw_obj
      continue;
    }

    if (bucket_marker.empty() || object_name.empty() ||
        buckets_name_index.find(bucket_marker) == buckets_name_index.end()) {
      cerr << "ERROR: invalid part raw obj:"<< line << std::endl;
      return -EINVAL;
    }

    string s_key = bucket_marker + "+" + object_name;

    if (exist_obj.find(s_key) != exist_obj.end()) {
      ldout(store->ctx(), 10) << "head obj for this raw object is exist:" << line << dendl;
      continue;
    }

    RGWBucketInfo& bucket_info = buckets_name_index[bucket_marker];
    rgw_obj head_obj(bucket_info.bucket, object_name);


    rgw_placement_rule dest_placement;
    dest_placement.storage_class = bucket_info.storage_class;
    dest_placement.name = bucket_info.head_placement_rule.name;


    rgw_raw_obj raw_obj;
    store->get_obj_data_pool(dest_placement, head_obj, &raw_obj.pool);
    raw_obj.oid = line;
    map<string, bufferlist> attrs;
    ceph::real_time mtime;
    ret = store->raw_obj_stat(raw_obj, NULL, &mtime, NULL, &attrs, NULL, nullptr, false);
    if (ret < 0) {
      if (ret != -ENOENT) {
        cerr << "ERROR: get raw obj stat err:" << raw_obj
             << ", ret:" << ret << std::endl;
      }
      continue;
    }

    auto iter = attrs.find("refcount");
    if (iter != attrs.end()) {
      ldout(store->ctx(), 10) << "this raw object is copyed by other, keep it:" << line << dendl;
      continue;
    }
    ceph::real_time deadline = real_clock::now();

    deadline = deadline - make_timespan(before_day*ONE_DAY);

    if (mtime > deadline) {
      ldout(store->ctx(), 10) << "this raw object is newer than deadline:" << line
                              << " mtime:" << mtime
                              << " deadline:" << deadline
                              << dendl;
      continue;
    }


    if (nonexist_obj.find(s_key) != nonexist_obj.end()) {
      if (clear_trully) {
        ret = remove_raw_obj(raw_obj);
        if (ret < 0 && ret != -ENOENT)
          return ret;
        if (ret == -ENOENT) {
         ldout(store->ctx(), 10) << "raw object has already be removed:" << line << dendl;
        }
      } else {
        // just output to log
        ldout(store->ctx(), 10) << "raw object can be removed:" << line
                                << " mtime:" << mtime
                                << " deadline:" << deadline
                                << dendl;
      }
      continue;
    }

    ret = head_obj_is_exist(object_name, bucket_marker, head_obj, bucket_info, line);
    if (ret > 0) {
      if (ret == EEXIST) {
        if (nonexist_obj.find(s_key) != nonexist_obj.end()) {
          cerr << "ERROR: head obj is exist while still in nonexist_obj set:" << s_key << std::endl;
          return -EINTR;
        }
        exist_obj.insert(s_key);
        continue;
      }
    } else if (ret < 0) {
      return ret;
    }

    // ret == 0, head obj is not exist
    if (exist_obj.find(s_key) != exist_obj.end()) {
      cerr << "ERROR: head obj is non exist while still in exist_obj set:" << s_key << std::endl;
      return -EINTR;
    }
    nonexist_obj.insert(s_key);
    if (clear_trully) {
      ret = remove_raw_obj(raw_obj);
      if (ret < 0 && ret != -ENOENT)
        return ret;
      if (ret == -ENOENT) {
        ldout(store->ctx(), 10) << "raw object has already be removed:" << line << dendl;
      }
    } else {
      // just output to log
      ldout(store->ctx(), 10) << "raw object can be removed:" << line
                              << " mtime:" << mtime
                              << " deadline:" << deadline
                              << dendl;
    }
  }
  return 0;
}

int RGWGCLeftObjClear::remove_raw_obj(const rgw_raw_obj& raw_obj) {
   static string no_use_tag = "abcstorage_20221228@baidu";
   rgw_rados_ref ref;
   int ret = store->get_raw_obj_ref(raw_obj, &ref);
   if (ret < 0) {
     ldout(store->ctx(), 0) << "ERROR: get raw object ref err:" << raw_obj << dendl;
     return ret;
   }

   librados::ObjectWriteOperation op;

   cls_refcount_put(op, no_use_tag, true);
   return ref.ioctx.operate(ref.oid, &op);
}

int RGWGCLeftObjClear::head_obj_is_exist(string& object_name,
                                         const string& bucket_marker,
                                         const rgw_obj& head_obj,
                                         RGWBucketInfo& bucket_info,
                                         const string& line) {
  // 2.1 check head obj is exist ?
  RGWObjState *astate = nullptr;
  RGWObjectCtx obj_ctx(store);
  // get obj state, works with cache. Don't need invalidate it from cache.
  int r = store->get_obj_state(&obj_ctx, bucket_info, head_obj, &astate);
  if (r < 0) {
    cerr << "ERROR: get obj state eror:" << head_obj << std::endl;
    return r;
  }

  if (astate->exists) {
    ldout(store->ctx(), 10) << "tail obj is used:" << line << dendl;
    return EEXIST;
  }

  // 2.2 check head obj is in bucket list result
  bool truncated;
  int max_entries = 10;
  int count = 0;

  string prefix = "";
  string delim = "";
  vector<rgw_bucket_dir_entry> result;
  map<string, bool> common_prefixes;
  string ns = "";

  RGWRados::Bucket target(store, bucket_info);
  RGWRados::Bucket::List list_op(&target);

  list_op.params.prefix = object_name;
  list_op.params.delim = delim;
  list_op.params.ns = ns;
  list_op.params.enforce_ns = false;
  list_op.params.list_versions = true;

  do {
    r = list_op.list_objects(max_entries, &result, &common_prefixes, &truncated);
    if (r < 0) {
      cerr << "ERROR: store->list_objects(): " << cpp_strerror(-r) << std::endl;
      return r;
    }

    count += result.size();
    for (vector<rgw_bucket_dir_entry>::iterator iter = result.begin(); iter != result.end(); ++iter) {
      rgw_bucket_dir_entry& entry = *iter;
      if (entry.key.name.compare(object_name) == 0) {
        ldout(store->ctx(), 0) << "ERROR: object not exist while in list result "
                                << object_name << dendl;
        return EEXIST;
      }
    }
  } while (truncated && count < max_entries);

  // 2.3 check head obj is in multipart uploading ?
  vector<rgw_bucket_dir_entry> objs;
  int max_objs = 1;
  r = list_bucket_multiparts(store, bucket_info, prefix, object_name, delim,
                             max_objs, &objs, nullptr, nullptr);
  if (r < 0) {
    cerr << "ERROR: list_bucket_multiparts eror:" << r << std::endl;
    return r;
  }
  bool is_in_multiparting = false;
  for (auto& o : objs) {
    string meta = o.key.name;
    int end_pos = meta.rfind('.'); // search for ".meta"
    if (end_pos < 0) {
      cerr << "ERROR: invalid in_multipart obj name:" << meta << std::endl;
      return -EINTR;
    }
    int mid_pos = meta.rfind('.', end_pos - 1); // <key>.<upload_id>
    if (mid_pos < 0) {
      cerr << "ERROR: invalid in_multipart obj name:" << meta << std::endl;
      return -EINTR;
    }
    string oid = meta.substr(strlen("_multipart_"), mid_pos - strlen("_multipart_"));
    if (oid.compare(object_name) == 0) {
      ldout(store->ctx(), 10) << "object hasn't been completed multipart, retain it:"
                              << object_name << dendl;
      is_in_multiparting = true;
      break;
    }
  }
  if (is_in_multiparting) {
    return EEXIST;
  }

  return 0;
}

int RGWOrphanSearch::build_all_oids_index()
{
  librados::IoCtx ioctx;

  int ret = rgw_init_ioctx(store->get_rados_handle(), search_info.pool, ioctx);
  if (ret < 0) {
    lderr(store->ctx()) << __func__ << ": rgw_init_ioctx() returned ret=" << ret << dendl;
    return ret;
  }

  ioctx.set_namespace(librados::all_nspaces);
  librados::NObjectIterator i = ioctx.nobjects_begin();
  librados::NObjectIterator i_end = ioctx.nobjects_end();

  map<int, list<string> > oids;

  int count = 0;
  uint64_t total = 0;

  cout << "logging all objects in the pool" << std::endl;

  for (; i != i_end; ++i) {
    string nspace = i->get_nspace();
    string oid = i->get_oid();
    string locator = i->get_locator();

    ssize_t pos = oid.find('_');
    if (pos < 0) {
      cout << "unidentified oid: " << oid << ", skipping" << std::endl;
      /* what is this object, oids should be in the format of <bucket marker>_<obj>,
       * skip this entry
       */
      continue;
    }
    string stripped_oid = oid.substr(pos + 1);
    rgw_obj_key key;
    if (!rgw_obj_key::parse_raw_oid(stripped_oid, &key)) {
      cout << "cannot parse oid: " << oid << ", skipping" << std::endl;
      continue;
    }

    if (key.ns.empty()) {
      /* skipping head objects, we don't want to remove these as they are mutable and
       * cleaning them up is racy (can race with object removal and a later recreation)
       */
      cout << "skipping head object: oid=" << oid << std::endl;
      continue;
    }

    string oid_fp = obj_fingerprint(oid);

    ldout(store->ctx(), 20) << "oid_fp=" << oid_fp << dendl;

    int shard = orphan_shard(oid_fp);
    oids[shard].push_back(oid);

#define COUNT_BEFORE_FLUSH 1000
    ++total;
    if (++count >= COUNT_BEFORE_FLUSH) {
      ldout(store->ctx(), 1) << "iterated through " << total << " objects" << dendl;
      ret = log_oids(all_objs_index, oids);
      if (ret < 0) {
        cerr << __func__ << ": ERROR: log_oids() returned ret=" << ret << std::endl;
        return ret;
      }
      count = 0;
      oids.clear();
    }
  }
  ret = log_oids(all_objs_index, oids);
  if (ret < 0) {
    cerr << __func__ << ": ERROR: log_oids() returned ret=" << ret << std::endl;
    return ret;
  }
  
  return 0;
}

int RGWOrphanSearch::build_buckets_instance_index()
{
  void *handle;
  int max = 1000;
  string section = "bucket.instance";
  int ret = store->meta_mgr->list_keys_init(section, &handle);
  if (ret < 0) {
    lderr(store->ctx()) << "ERROR: can't get key: " << cpp_strerror(-ret) << dendl;
    return -ret;
  }

  map<int, list<string> > instances;

  bool truncated;

  RGWObjectCtx obj_ctx(store);

  int count = 0;
  uint64_t total = 0;

  do {
    list<string> keys;
    ret = store->meta_mgr->list_keys_next(handle, max, keys, &truncated);
    if (ret < 0) {
      lderr(store->ctx()) << "ERROR: lists_keys_next(): " << cpp_strerror(-ret) << dendl;
      return -ret;
    }

    for (list<string>::iterator iter = keys.begin(); iter != keys.end(); ++iter) {
      ++total;
      ldout(store->ctx(), 10) << "bucket_instance=" << *iter << " total=" << total << dendl;
      int shard = orphan_shard(*iter);
      instances[shard].push_back(*iter);

      if (++count >= COUNT_BEFORE_FLUSH) {
        ret = log_oids(buckets_instance_index, instances);
        if (ret < 0) {
          lderr(store->ctx()) << __func__ << ": ERROR: log_oids() returned ret=" << ret << dendl;
          return ret;
        }
        count = 0;
        instances.clear();
      }
    }

  } while (truncated);

  ret = log_oids(buckets_instance_index, instances);
  if (ret < 0) {
    lderr(store->ctx()) << __func__ << ": ERROR: log_oids() returned ret=" << ret << dendl;
    return ret;
  }
  store->meta_mgr->list_keys_complete(handle);

  return 0;
}

int RGWOrphanSearch::handle_stat_result(map<int, list<string> >& oids, RGWRados::Object::Stat::Result& result)
{
  set<string> obj_oids;
  rgw_bucket& bucket = result.obj.bucket;
  if (!result.has_manifest) { /* a very very old object, or part of a multipart upload during upload */
    const string loc = bucket.bucket_id + "_" + result.obj.get_oid();
    obj_oids.insert(obj_fingerprint(loc));

    /*
     * multipart parts don't have manifest on them, it's in the meta object. Instead of reading the
     * meta object, just add a "shadow" object to the mix
     */
    obj_oids.insert(obj_fingerprint(loc, "shadow"));
  } else {
    RGWObjManifest& manifest = result.manifest;

    RGWObjManifest::obj_iterator miter;
    for (miter = manifest.obj_begin(); miter != manifest.obj_end(); ++miter) {
      const rgw_raw_obj& loc = miter.get_location().get_raw_obj(store);
      string s = loc.oid;
      obj_oids.insert(obj_fingerprint(s));
    }
  }

  for (set<string>::iterator iter = obj_oids.begin(); iter != obj_oids.end(); ++iter) {
    ldout(store->ctx(), 20) << __func__ << ": oid for obj=" << result.obj << ": " << *iter << dendl;

    int shard = orphan_shard(*iter);
    oids[shard].push_back(*iter);
  }

  return 0;
}

int RGWOrphanSearch::pop_and_handle_stat_op(map<int, list<string> >& oids, std::deque<RGWRados::Object::Stat>& ops)
{
  RGWRados::Object::Stat& front_op = ops.front();

  int ret = front_op.wait();
  if (ret < 0) {
    if (ret != -ENOENT) {
      lderr(store->ctx()) << "ERROR: stat_async() returned error: " << cpp_strerror(-ret) << dendl;
    }
    goto done;
  }
  ret = handle_stat_result(oids, front_op.result);
  if (ret < 0) {
    lderr(store->ctx()) << "ERROR: handle_stat_response() returned error: " << cpp_strerror(-ret) << dendl;
  }
done:
  ops.pop_front();
  return ret;
}

int RGWOrphanSearch::build_linked_oids_for_bucket(const string& bucket_instance_id, map<int, list<string> >& oids)
{
  ldout(store->ctx(), 10) << "building linked oids for bucket instance: " << bucket_instance_id << dendl;
  RGWBucketInfo bucket_info;
  RGWObjectCtx obj_ctx(store);
  int ret = store->get_bucket_instance_info(obj_ctx, bucket_instance_id, bucket_info, NULL, NULL);
  if (ret < 0) {
    if (ret == -ENOENT) {
      /* probably raced with bucket removal */
      return 0;
    }
    lderr(store->ctx()) << __func__ << ": ERROR: RGWRados::get_bucket_instance_info() returned ret=" << ret << dendl;
    return ret;
  }

  RGWRados::Bucket target(store, bucket_info);
  RGWRados::Bucket::List list_op(&target);

  string marker;
  list_op.params.marker = rgw_obj_key(marker);
  list_op.params.list_versions = true;
  list_op.params.enforce_ns = false;

  bool truncated;

  deque<RGWRados::Object::Stat> stat_ops;

  int count = 0;

  do {
    vector<rgw_bucket_dir_entry> result;

#define MAX_LIST_OBJS_ENTRIES 100
    ret = list_op.list_objects(MAX_LIST_OBJS_ENTRIES, &result, NULL, &truncated);
    if (ret < 0) {
      cerr << "ERROR: store->list_objects(): " << cpp_strerror(-ret) << std::endl;
      return -ret;
    }

    for (vector<rgw_bucket_dir_entry>::iterator iter = result.begin(); iter != result.end(); ++iter) {
      rgw_bucket_dir_entry& entry = *iter;
      if (entry.key.instance.empty()) {
        ldout(store->ctx(), 20) << "obj entry: " << entry.key.name << dendl;
      } else {
        ldout(store->ctx(), 20) << "obj entry: " << entry.key.name << " [" << entry.key.instance << "]" << dendl;
      }

      ldout(store->ctx(), 20) << __func__ << ": entry.key.name=" << entry.key.name << " entry.key.instance=" << entry.key.instance << dendl;
      rgw_obj obj(bucket_info.bucket, entry.key);

      RGWRados::Object op_target(store, bucket_info, obj_ctx, obj);

      stat_ops.push_back(RGWRados::Object::Stat(&op_target));
      RGWRados::Object::Stat& op = stat_ops.back();


      ret = op.stat_async();
      if (ret < 0) {
        lderr(store->ctx()) << "ERROR: stat_async() returned error: " << cpp_strerror(-ret) << dendl;
        return ret;
      }
      if (stat_ops.size() >= max_concurrent_ios) {
        ret = pop_and_handle_stat_op(oids, stat_ops);
        if (ret < 0) {
          if (ret != -ENOENT) {
            lderr(store->ctx()) << "ERROR: stat_async() returned error: " << cpp_strerror(-ret) << dendl;
          }
        }
      }
      if (++count >= COUNT_BEFORE_FLUSH) {
        ret = log_oids(linked_objs_index, oids);
        if (ret < 0) {
          cerr << __func__ << ": ERROR: log_oids() returned ret=" << ret << std::endl;
          return ret;
        }
        count = 0;
        oids.clear();
      }
    }
  } while (truncated);

  while (!stat_ops.empty()) {
    ret = pop_and_handle_stat_op(oids, stat_ops);
    if (ret < 0) {
      if (ret != -ENOENT) {
        lderr(store->ctx()) << "ERROR: stat_async() returned error: " << cpp_strerror(-ret) << dendl;
      }
    }
  }

  return 0;
}

int RGWOrphanSearch::build_linked_oids_index()
{
  map<int, list<string> > oids;
  map<int, string>::iterator iter = buckets_instance_index.find(search_stage.shard);
  for (; iter != buckets_instance_index.end(); ++iter) {
    ldout(store->ctx(), 0) << "building linked oids index: " << iter->first << "/" << buckets_instance_index.size() << dendl;
    bool truncated;

    string oid = iter->second;

    do {
      map<string, bufferlist> entries;
      int ret = orphan_store.read_entries(oid, search_stage.marker, &entries, &truncated);
      if (ret == -ENOENT) {
        truncated = false;
        ret = 0;
      }

      if (ret < 0) {
        lderr(store->ctx()) << __func__ << ": ERROR: read_entries() oid=" << oid << " returned ret=" << ret << dendl;
        return ret;
      }

      if (entries.empty()) {
        break;
      }

      for (map<string, bufferlist>::iterator eiter = entries.begin(); eiter != entries.end(); ++eiter) {
        ldout(store->ctx(), 20) << " indexed entry: " << eiter->first << dendl;
        ret = build_linked_oids_for_bucket(eiter->first, oids);
        if (ret < 0) {
          lderr(store->ctx()) << __func__ << ": ERROR: build_linked_oids_for_bucket() indexed entry=" << eiter->first
                              << " returned ret=" << ret << dendl;
          return ret;
        }
      }

      search_stage.shard = iter->first;
      search_stage.marker = entries.rbegin()->first; /* last entry */
    } while (truncated);

    search_stage.marker.clear();
  }

  int ret = log_oids(linked_objs_index, oids);
  if (ret < 0) {
    cerr << __func__ << ": ERROR: log_oids() returned ret=" << ret << std::endl;
    return ret;
  }

  ret = save_state();
  if (ret < 0) {
    cerr << __func__ << ": ERROR: failed to write state ret=" << ret << std::endl;
    return ret;
  }

  return 0;
}

class OMAPReader {
  librados::IoCtx ioctx;
  string oid;

  map<string, bufferlist> entries;
  map<string, bufferlist>::iterator iter;
  string marker;
  bool truncated;

public:
  OMAPReader(librados::IoCtx& _ioctx, const string& _oid) : ioctx(_ioctx), oid(_oid), truncated(true) {
    iter = entries.end();
  }

  int get_next(string *key, bufferlist *pbl, bool *done);
};

int OMAPReader::get_next(string *key, bufferlist *pbl, bool *done)
{
  if (iter != entries.end()) {
    *key = iter->first;
    if (pbl) {
      *pbl = iter->second;
    }
    ++iter;
    *done = false;
    marker = *key;
    return 0;
  }

  if (!truncated) {
    *done = true;
    return 0;
  }

#define MAX_OMAP_GET_ENTRIES 100
  int ret = ioctx.omap_get_vals(oid, marker, MAX_OMAP_GET_ENTRIES, &entries);
  if (ret < 0) {
    if (ret == -ENOENT) {
      *done = true;
      return 0;
    }
    return ret;
  }

  truncated = (entries.size() == MAX_OMAP_GET_ENTRIES);
  iter = entries.begin();
  return get_next(key, pbl, done);
}

int RGWOrphanSearch::compare_oid_indexes()
{
  assert(linked_objs_index.size() == all_objs_index.size());

  librados::IoCtx& ioctx = orphan_store.get_ioctx();

  librados::IoCtx data_ioctx;

  int ret = rgw_init_ioctx(store->get_rados_handle(), search_info.pool, data_ioctx);
  if (ret < 0) {
    lderr(store->ctx()) << __func__ << ": rgw_init_ioctx() returned ret=" << ret << dendl;
    return ret;
  }

  uint64_t time_threshold = search_info.start_time.sec() - stale_secs;

  map<int, string>::iterator liter = linked_objs_index.begin();
  map<int, string>::iterator aiter = all_objs_index.begin();

  for (; liter != linked_objs_index.end(); ++liter, ++aiter) {
    OMAPReader linked_entries(ioctx, liter->second);
    OMAPReader all_entries(ioctx, aiter->second);

    bool done;

    string cur_linked;
    bool linked_done = false;


    do {
      string key;
      int r = all_entries.get_next(&key, NULL, &done);
      if (r < 0) {
        return r;
      }
      if (done) {
        break;
      }

      string key_fp = obj_fingerprint(key);

      while (cur_linked < key_fp && !linked_done) {
        r = linked_entries.get_next(&cur_linked, NULL, &linked_done);
        if (r < 0) {
          return r;
        }
      }

      if (cur_linked == key_fp) {
        ldout(store->ctx(), 20) << "linked: " << key << dendl;
        continue;
      }

      time_t mtime;
      r = data_ioctx.stat(key, NULL, &mtime);
      if (r < 0) {
        if (r != -ENOENT) {
          lderr(store->ctx()) << "ERROR: ioctx.stat(" << key << ") returned ret=" << r << dendl;
        }
        continue;
      }
      if (stale_secs && (uint64_t)mtime >= time_threshold) {
        ldout(store->ctx(), 20) << "skipping: " << key << " (mtime=" << mtime << " threshold=" << time_threshold << ")" << dendl;
        continue;
      }
      ldout(store->ctx(), 20) << "leaked: " << key << dendl;
      cout << "leaked: " << key << std::endl;
    } while (!done);
  }

  return 0;
}

int RGWOrphanSearch::run()
{
  int r;

  switch (search_stage.stage) {
    
    case ORPHAN_SEARCH_STAGE_INIT:
      ldout(store->ctx(), 0) << __func__ << "(): initializing state" << dendl;
      search_stage = RGWOrphanSearchStage(ORPHAN_SEARCH_STAGE_LSPOOL);
      r = save_state();
      if (r < 0) {
        lderr(store->ctx()) << __func__ << ": ERROR: failed to save state, ret=" << r << dendl;
        return r;
      }
      // fall through
    case ORPHAN_SEARCH_STAGE_LSPOOL:
      ldout(store->ctx(), 0) << __func__ << "(): building index of all objects in pool" << dendl;
      r = build_all_oids_index();
      if (r < 0) {
        lderr(store->ctx()) << __func__ << ": ERROR: build_all_objs_index returned ret=" << r << dendl;
        return r;
      }

      search_stage = RGWOrphanSearchStage(ORPHAN_SEARCH_STAGE_LSBUCKETS);
      r = save_state();
      if (r < 0) {
        lderr(store->ctx()) << __func__ << ": ERROR: failed to save state, ret=" << r << dendl;
        return r;
      }
      // fall through

    case ORPHAN_SEARCH_STAGE_LSBUCKETS:
      ldout(store->ctx(), 0) << __func__ << "(): building index of all bucket indexes" << dendl;
      r = build_buckets_instance_index();
      if (r < 0) {
        lderr(store->ctx()) << __func__ << ": ERROR: build_all_objs_index returned ret=" << r << dendl;
        return r;
      }

      search_stage = RGWOrphanSearchStage(ORPHAN_SEARCH_STAGE_ITERATE_BI);
      r = save_state();
      if (r < 0) {
        lderr(store->ctx()) << __func__ << ": ERROR: failed to save state, ret=" << r << dendl;
        return r;
      }
      // fall through


    case ORPHAN_SEARCH_STAGE_ITERATE_BI:
      ldout(store->ctx(), 0) << __func__ << "(): building index of all linked objects" << dendl;
      r = build_linked_oids_index();
      if (r < 0) {
        lderr(store->ctx()) << __func__ << ": ERROR: build_all_objs_index returned ret=" << r << dendl;
        return r;
      }

      search_stage = RGWOrphanSearchStage(ORPHAN_SEARCH_STAGE_COMPARE);
      r = save_state();
      if (r < 0) {
        lderr(store->ctx()) << __func__ << ": ERROR: failed to save state, ret=" << r << dendl;
        return r;
      }
      // fall through

    case ORPHAN_SEARCH_STAGE_COMPARE:
      r = compare_oid_indexes();
      if (r < 0) {
        lderr(store->ctx()) << __func__ << ": ERROR: build_all_objs_index returned ret=" << r << dendl;
        return r;
      }

      break;

    default:
      ceph_abort();
  };

  return 0;
}


int RGWOrphanSearch::remove_index(map<int, string>& index)
{
  librados::IoCtx& ioctx = orphan_store.get_ioctx();

  for (map<int, string>::iterator iter = index.begin(); iter != index.end(); ++iter) {
    int r = ioctx.remove(iter->second);
    if (r < 0) {
      if (r != -ENOENT) {
        ldout(store->ctx(), 0) << "ERROR: couldn't remove " << iter->second << ": ret=" << r << dendl;
      }
    }
  }
  return 0;
}

int RGWOrphanSearch::finish()
{
  int r = remove_index(all_objs_index);
  if (r < 0) {
    ldout(store->ctx(), 0) << "ERROR: remove_index(" << all_objs_index << ") returned ret=" << r << dendl;
  }
  r = remove_index(buckets_instance_index);
  if (r < 0) {
    ldout(store->ctx(), 0) << "ERROR: remove_index(" << buckets_instance_index << ") returned ret=" << r << dendl;
  }
  r = remove_index(linked_objs_index);
  if (r < 0) {
    ldout(store->ctx(), 0) << "ERROR: remove_index(" << linked_objs_index << ") returned ret=" << r << dendl;
  }

  r = orphan_store.remove_job(search_info.job_name);
  if (r < 0) {
    ldout(store->ctx(), 0) << "ERROR: could not remove job name (" << search_info.job_name << ") ret=" << r << dendl;
  }

  return r;
}
