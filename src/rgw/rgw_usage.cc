// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include <string>
#include <map>

#include "rgw_rados.h"
#include "rgw_usage.h"
#include "rgw_formats.h"
#include "rgw_user.h"



static void dump_usage_categories_info(Formatter *formatter, const rgw_usage_log_entry& entry, map<string, bool> *categories)
{
  formatter->open_array_section("categories");
  map<string, rgw_usage_data>::const_iterator uiter;
  for (uiter = entry.usage_map.begin(); uiter != entry.usage_map.end(); ++uiter) {
    if (categories && !categories->empty() && !categories->count(uiter->first))
      continue;
    const rgw_usage_data& usage = uiter->second;
    formatter->open_object_section("entry");
    formatter->dump_string("category", uiter->first);
    formatter->dump_int("bytes_sent", usage.bytes_sent);
    formatter->dump_int("bytes_received", usage.bytes_received);
    formatter->dump_int("ops", usage.ops);
    formatter->dump_int("successful_ops", usage.successful_ops);
    formatter->close_section(); // entry
  }
  formatter->close_section(); // categories
}

bool generate_user_list(const rgw_user& user, set<string>& user_list) {
  string user_str = user.to_str();
  if (!user_str.empty()) {
    if (user_list.find(user_str) != user_list.end()) {
      user_list.clear();
      user_list.insert(user_str);
    } else {
      return false;
    }
  }
  return true;
}

float get_sync_rate(uint64_t dflow) {
  float bandwidth = float(dflow) / 60;
  bandwidth = round(bandwidth * 100) / 100;

  return bandwidth;
}

int RGWUsage::show(RGWRados *store, rgw_user& uid, uint64_t start_epoch,
		   uint64_t end_epoch, bool show_log_entries, bool show_log_sum,
		   map<string, bool> *categories,
		   RGWFormatterFlusher& flusher)
{
  uint32_t max_entries = 1000;

  bool is_truncated = true;

  RGWUsageIter usage_iter;
  Formatter *formatter = flusher.get_formatter();

  map<rgw_user_bucket, rgw_usage_log_entry> usage;

  flusher.start(0);

  formatter->open_object_section("usage");
  if (!show_log_entries && !show_log_sum) { // not show entries and sum means to show total
    string last_owner;
    bool user_section_open = false;
    int ret = 0;
    formatter->open_array_section("entries");
    while (is_truncated) {
      ret = store->read_total_usage(uid, max_entries, &is_truncated, usage_iter, usage);
      if (ret == -ENOENT) {
        ret = 0;
        is_truncated = false;
      }
      if (ret < 0) {
        break;
      }
      map<rgw_user_bucket, rgw_usage_log_entry>::iterator iter;
      for (iter = usage.begin(); iter != usage.end(); ++iter) {
        const rgw_user_bucket& ub = iter->first;
        const rgw_usage_log_entry& entry = iter->second;
        if (!ub.user.empty() && ub.user.compare(last_owner) != 0) {
          if (user_section_open) {
            formatter->close_section();
            formatter->close_section();
          }
          formatter->open_object_section("user");
          formatter->dump_string("user", ub.user);
          formatter->open_array_section("buckets");
          user_section_open = true;
          last_owner = ub.user;
        }
        formatter->open_object_section("bucket");
        formatter->dump_string("bucket", ub.bucket);
        utime_t ut(entry.epoch, 0);
        ut.gmtime(formatter->dump_stream("time"));
        formatter->dump_int("epoch", entry.epoch);
        string owner = entry.owner.to_str();
        string payer = entry.payer.to_str();
        formatter->dump_string("owner", owner);
        if (!payer.empty() && payer != owner) {
          formatter->dump_string("payer", payer);
        }
        dump_usage_categories_info(formatter, entry, categories);
        formatter->close_section(); // bucket
        flusher.flush();
      }
    }
    if (user_section_open) {
      formatter->close_section(); // buckets
      formatter->close_section(); //user
    }
    formatter->close_section(); // entries
    formatter->close_section(); // usage
    flusher.flush();
    return ret;
  }

  if (show_log_entries) {
    formatter->open_array_section("entries");
  }
  string last_owner;
  bool user_section_open = false;
  map<string, rgw_usage_log_entry> summary_map;
  while (is_truncated) {
    int ret = store->read_usage(uid, start_epoch, end_epoch, max_entries,
                                &is_truncated, usage_iter, usage);

    if (ret == -ENOENT) {
      ret = 0;
      is_truncated = false;
    }

    if (ret < 0) {
      return ret;
    }

    map<rgw_user_bucket, rgw_usage_log_entry>::iterator iter;
    for (iter = usage.begin(); iter != usage.end(); ++iter) {
      const rgw_user_bucket& ub = iter->first;
      const rgw_usage_log_entry& entry = iter->second;

      if (show_log_entries) {
        if (ub.user.compare(last_owner) != 0) {
          if (user_section_open) {
            formatter->close_section();
            formatter->close_section();
          }
          formatter->open_object_section("user");
          formatter->dump_string("user", ub.user);
          formatter->open_array_section("buckets");
          user_section_open = true;
          last_owner = ub.user;
        }
        formatter->open_object_section("bucket");
        formatter->dump_string("bucket", ub.bucket);
        utime_t ut(entry.epoch, 0);
        ut.gmtime(formatter->dump_stream("time"));
        formatter->dump_int("epoch", entry.epoch);
        string owner = entry.owner.to_str();
        string payer = entry.payer.to_str();
        formatter->dump_string("owner", owner);
        if (!payer.empty() && payer != owner) {
          formatter->dump_string("payer", payer);
        }
        dump_usage_categories_info(formatter, entry, categories);
        formatter->close_section(); // bucket
        flusher.flush();
      }

      summary_map[ub.user].aggregate(entry, categories);
    }
  }
  if (show_log_entries) {
    if (user_section_open) {
      formatter->close_section(); // buckets
      formatter->close_section(); //user
    }
    formatter->close_section(); // entries
  }

  if (show_log_sum) {
    formatter->open_array_section("summary");
    map<string, rgw_usage_log_entry>::iterator siter;
    for (siter = summary_map.begin(); siter != summary_map.end(); ++siter) {
      const rgw_usage_log_entry& entry = siter->second;
      formatter->open_object_section("user");
      formatter->dump_string("user", siter->first);
      dump_usage_categories_info(formatter, entry, categories);
      rgw_usage_data total_usage;
      entry.sum(total_usage, *categories);
      formatter->open_object_section("total");
      formatter->dump_int("bytes_sent", total_usage.bytes_sent);
      formatter->dump_int("bytes_received", total_usage.bytes_received);
      formatter->dump_int("ops", total_usage.ops);
      formatter->dump_int("successful_ops", total_usage.successful_ops);
      formatter->close_section(); // total

      formatter->close_section(); // user

      flusher.flush();
    }

    formatter->close_section(); // summary
  }

  formatter->close_section(); // usage
  flusher.flush();

  return 0;
}

int RGWUsage::trim(RGWRados *store, rgw_user& uid, uint64_t start_epoch,
		   uint64_t end_epoch, string bucket)
{
  if (bucket.empty()) {
    return store->trim_usage(uid, start_epoch, end_epoch);
  } else {
    return store->trim_total_usage(uid, bucket);
  }
}

int RGWUsage::clear(RGWRados *store)
{
  return store->clear_usage();
}

int RGWReadUsage::show(RGWRados *store, rgw_user& uid, uint64_t start_epoch,
            uint64_t end_epoch, bool show_log_all,
            RGWFormatterFlusher& flusher)
{
  Formatter *formatter = flusher.get_formatter();
  flusher.start(0);
  formatter->open_object_section("usage");

  if (!show_log_all) { // only show entry of ReadOp and WriteOp in last miniute.
    formatter->open_array_section("userChargeDatas");
    map<rgw_user_bucket, rgw_usage_log_entry> usage;
    utime_t ts = ceph_clock_now().round_to_minute();
    uint64_t end_epoch = ts.sec();
    set<string> user_list;
    get_user_list(store, user_list);

    if (generate_user_list(uid, user_list) == false) {
      dout(0) << __func__ << " ERROR, input user is not exist. uid=" << uid.to_str() << dendl;
      return -1;
    }

    int ret = 0;
    ret = store->read_usage_current_readop(user_list, end_epoch, usage);
    if (ret < 0) {
      ldout(store->ctx(), 10) << __func__ << " Error, faile to get current data flow info. uid=" << uid
                                          << ", epoch=" << end_epoch << ", ret=" << ret << dendl;
      return ret;
    }
    map<rgw_user_bucket, rgw_usage_log_entry>::iterator iter;
    for (iter = usage.begin(); iter != usage.end(); ++iter) {
      const rgw_user_bucket& ub = iter->first;
      const rgw_usage_log_entry& entry = iter->second;
      if (!ub.user.empty()) {
        formatter->open_object_section("scope");
        formatter->dump_string("scope", "BCE_BOS");
        formatter->dump_string("userId", ub.user);
        formatter->open_array_section("metricData");
        formatter->open_object_section("timestamp");
        utime_t ut(entry.epoch, 0);
        formatter->dump_int("timestamp", entry.epoch);
        formatter->open_array_section("statisticValues");
        uint64_t sum = entry.read_ops.bytes_sent;
        formatter->open_object_section("sum");
        formatter->dump_unsigned("sum", sum);
        formatter->dump_string("unit", "Bytes");
        formatter->close_section(); // sum
        formatter->close_section(); // statisticValues
        formatter->dump_string("metricName", "ReadBytes");
        formatter->close_section(); // timestamp
        formatter->close_section(); // metricData
        formatter->close_section(); // scope
        flusher.flush();
      }
    }
    formatter->close_section(); // userChargeDatas
    formatter->close_section(); // usage
    flusher.flush();
  } else {
    uint32_t max_entries = 1000;
    bool is_truncated = true;
    map<rgw_user_bucket, vector<rgw_usage_log_entry> > usage;
    RGWUsageIter usage_iter;

    formatter->open_array_section("userChargeDatas");
    int ret = 0;
    while (is_truncated) {
      ret = store->read_usage_readop(uid, start_epoch, end_epoch, max_entries, &is_truncated, usage_iter, usage);
      if (ret == -ENOENT) {
        ret = 0;
        is_truncated = false;
      }
      if (ret < 0) {
        break;
      }
    }
    map<rgw_user_bucket, vector<rgw_usage_log_entry> >::iterator iter;
    for (iter = usage.begin(); iter != usage.end(); ++iter) {
      const rgw_user_bucket& ub = iter->first;
      const vector<rgw_usage_log_entry>& entry_vec = iter->second;
      if (!ub.user.empty()) {
        formatter->open_object_section("scope");
        formatter->dump_string("scope", "BCE_BOS");
        formatter->dump_string("userId", ub.user);
        formatter->open_array_section("metricData");
        vector<rgw_usage_log_entry>::const_iterator entry_iter;
        for (entry_iter = entry_vec.begin(); entry_iter != entry_vec.end(); ++entry_iter) {
          const rgw_usage_log_entry& entry = *entry_iter;
          formatter->open_object_section("timestamp");
          utime_t ut(entry.epoch, 0);
          formatter->dump_int("timestamp", entry.epoch);
          formatter->open_array_section("statisticValues");
          uint64_t sum = entry.read_ops.bytes_sent;
          formatter->open_object_section("sum");
          formatter->dump_unsigned("sum", sum);
          formatter->dump_string("unit", "Bytes");
          formatter->close_section(); // sum
          formatter->close_section(); // statisticValues
          formatter->dump_string("metricName", "ReadBytes");
          formatter->close_section(); // timestamp
        }
        formatter->close_section(); // metricData
        formatter->close_section(); // scope
        flusher.flush();
      }
    }
    formatter->close_section(); // userChargeDatas
    formatter->close_section(); // usage
    flusher.flush();
    return ret;
  }
  return 0;
}

int RGWReadUsage::trim(RGWRados *store, rgw_user& uid, uint64_t start_epoch, uint64_t end_epoch)
{
  return store->trim_readop_usage(uid, start_epoch, end_epoch);
}

int RGWReadUsage::show_multisite_dataflow(RGWRados *store, rgw_user& uid, uint64_t start_epoch,
                                uint64_t end_epoch, bool show_log_all, RGWFormatterFlusher& flusher)
{
  Formatter *formatter = flusher.get_formatter();
  flusher.start(0);

  if (!show_log_all) { // only show entry of ReadOp and WriteOp in last miniute.
    formatter->open_object_section("dataflow");

    uint64_t dflow = 0;
    map<rgw_user_bucket, rgw_usage_log_entry> usage;
    utime_t ts = ceph_clock_now().round_to_minute();
    uint64_t end_epoch = ts.sec();
    set<string> user_list;
    get_user_list(store, user_list);

    if (generate_user_list(uid, user_list) == false) {
      dout(0) << __func__ << " ERROR, input user is not exist. uid=" << uid.to_str() << dendl;
      return -1;
    }

    int ret = 0;
    ret = store->read_usage_current_readop(user_list, end_epoch, usage);
    if (ret < 0) {
      ldout(store->ctx(), 10) << __func__ << " ERROR, faile to get current data flow info. uid=" << uid
                                          << ", epoch=" << end_epoch << ", ret=" << ret << dendl;
      return ret;
    }

    map<rgw_user_bucket, rgw_usage_log_entry>::iterator iter = usage.begin();
    for (; iter != usage.end(); iter++) {
      if (iter->first.user == uid.id) {
        dflow = iter->second.read_ops.bytes_sent;
      }
    }

    double bandwidth = double(dflow) / 60;
    int index = 0;
    const char* u[] = {"B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"};
    while (bandwidth >= 1024 && index < 7) {
      bandwidth /= 1024;
      index++;
    }

    std::stringstream stream;
    stream << std::fixed << std::setprecision(2) << bandwidth;
    string out = stream.str() + " " + u[index] + "/s";

    formatter->dump_string("bandwidth", out);

    formatter->close_section(); // dataflow
    flusher.flush();
  } else {
    uint32_t max_entries = 1000;
    bool is_truncated = true;
    map<rgw_user_bucket, vector<rgw_usage_log_entry> > usage;
    RGWUsageIter usage_iter;

    formatter->open_array_section("sync_speed");
    int ret = 0;
    while (is_truncated) {
      ret = store->read_usage_readop(uid, start_epoch, end_epoch, max_entries, &is_truncated, usage_iter, usage);
      if (ret == -ENOENT) {
        ret = 0;
        is_truncated = false;
      }
      if (ret < 0) {
        dout(0) << __func__ << " ERROR: failed to get current readop usage kv, ret: " << ret << dendl;
        return ret;
      }
    }
    map<rgw_user_bucket, vector<rgw_usage_log_entry> >::iterator iter;
    for (iter = usage.begin(); iter != usage.end(); ++iter) {
      if (iter->first.user == uid.id) {
        const vector<rgw_usage_log_entry>& entry_vec = iter->second;
        vector<rgw_usage_log_entry>::const_iterator entry_iter;
        for (entry_iter = entry_vec.begin(); entry_iter != entry_vec.end(); ++entry_iter) {
          const rgw_usage_log_entry& entry = *entry_iter;
          formatter->open_object_section("timestamp");
          utime_t ut(entry.epoch, 0);
          formatter->dump_int("timestamp", entry.epoch);
          uint64_t dflow = entry.read_ops.bytes_sent;
          float bandwidth = get_sync_rate(dflow);
          formatter->dump_float("bandwidth", bandwidth);
          formatter->close_section(); // timestamp
        }
      }
    }

    formatter->close_section(); // dataflow
    flusher.flush();
  }
  return 0;
}

