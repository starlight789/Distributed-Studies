// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include "rgw_op.h"
#include "rgw_usage.h"
#include "rgw_rest_usage.h"

#include "include/str_list.h"

#define dout_subsys ceph_subsys_rgw

void adjust_timezone(RGWRados *store, uint64_t &utime) {
  time_t timet = static_cast<time_t>(utime);
  struct tm time_bdt;

  if (store->ctx()->_conf->rgw_log_object_name_utc) {
    localtime_r(&timet, &time_bdt);
  } else {
    gmtime_r(&timet, &time_bdt);
  }

  timet = mktime(&time_bdt);

  utime = (uint64_t)timet;
}

class RGWOp_Usage_Get : public RGWRESTOp {

public:
  RGWOp_Usage_Get() {}

  int check_caps(RGWUserCaps& caps) override {
    return caps.check_cap("usage", RGW_CAP_READ);
  }
  void execute() override;

  const string name() override { return "get_usage"; }
};

void RGWOp_Usage_Get::execute() {
  map<std::string, bool> categories;

  string uid_str;
  uint64_t start, end;
  bool show_entries;
  bool show_summary;

  RESTArgs::get_string(s, "uid", uid_str, &uid_str);
  rgw_user uid(uid_str);

  RESTArgs::get_epoch(s, "start", 0, &start);
  RESTArgs::get_epoch(s, "end", (uint64_t)-1, &end);
  RESTArgs::get_bool(s, "show-entries", true, &show_entries);
  RESTArgs::get_bool(s, "show-summary", true, &show_summary);

  string cat_str;
  RESTArgs::get_string(s, "categories", cat_str, &cat_str);

  if (!cat_str.empty()) {
    list<string> cat_list;
    list<string>::iterator iter;
    get_str_list(cat_str, cat_list);
    for (iter = cat_list.begin(); iter != cat_list.end(); ++iter) {
      categories[*iter] = true;
    }
  }

  http_ret = RGWUsage::show(store, uid, start, end, show_entries, show_summary, &categories, flusher);
}

class RGWOp_Usage_Delete : public RGWRESTOp {

public:
  RGWOp_Usage_Delete() {}

  int check_caps(RGWUserCaps& caps) override {
    return caps.check_cap("usage", RGW_CAP_WRITE);
  }
  void execute() override;

  const string name() override { return "trim_usage"; }
};

void RGWOp_Usage_Delete::execute() {
  string uid_str, specified_bucket;
  uint64_t start, end;

  RESTArgs::get_string(s, "uid", uid_str, &uid_str);
  rgw_user uid(uid_str);

  RESTArgs::get_epoch(s, "start", 0, &start);
  RESTArgs::get_epoch(s, "end", (uint64_t)-1, &end);

  // specify the given bucket to delete all usage data of this bucket
  RESTArgs::get_string(s, "bucket", specified_bucket, &specified_bucket);

  if (uid.empty() &&
      !start &&
      end == (uint64_t)-1) {
    bool remove_all;
    RESTArgs::get_bool(s, "remove-all", false, &remove_all);
    if (!remove_all) {
      http_ret = -EINVAL;
      return;
    }
  }

  http_ret = RGWUsage::trim(store, uid, start, end, specified_bucket);
}

class RGWOp_Read_Usage_Get : public RGWRESTOp {
public:
  RGWOp_Read_Usage_Get() {}

  int check_caps(RGWUserCaps& caps) override {
    return caps.check_cap("usage", RGW_CAP_READ);
  }
  void execute() override;

  const string name() override { return "get_read_usage"; }
};

void RGWOp_Read_Usage_Get::execute() {
  string uid_str;
  uint64_t start, end;
  bool show_log_all;

  RESTArgs::get_string(s, "uid", uid_str, &uid_str);
  rgw_user uid(uid_str);

  RESTArgs::get_epoch(s, "start", 0, &start);
  RESTArgs::get_epoch(s, "end", (uint64_t)-1, &end);
  RESTArgs::get_bool(s, "show-log-all", false, &show_log_all);

  adjust_timezone(store, start);
  adjust_timezone(store, end);

  http_ret = RGWReadUsage::show(store, uid, start, end, show_log_all, flusher);
}

class RGWOp_Read_Usage_Delete : public RGWRESTOp {

public:
  RGWOp_Read_Usage_Delete() {}

  int check_caps(RGWUserCaps& caps) override {
    return caps.check_cap("usage", RGW_CAP_WRITE);
  }
  void execute() override;

  const string name() override { return "trim_read_usage"; }
};

void RGWOp_Read_Usage_Delete::execute() {
  string uid_str, specified_bucket;
  uint64_t start, end;

  RESTArgs::get_string(s, "uid", uid_str, &uid_str);
  rgw_user uid(uid_str);

  RESTArgs::get_epoch(s, "start", 0, &start);
  RESTArgs::get_epoch(s, "end", (uint64_t)-1, &end);

  adjust_timezone(store, start);
  adjust_timezone(store, end);

  if (uid.empty() && !start && end == (uint64_t)-1) {
    bool remove_all;
    RESTArgs::get_bool(s, "remove-all", false, &remove_all);
    if (!remove_all) {
      http_ret = -EINVAL;
      return;
    }
  }

  http_ret = RGWReadUsage::trim(store, uid, start, end);
}

class RGWOp_Multisite_Dataflow_Get : public RGWRESTOp {
public:
  RGWOp_Multisite_Dataflow_Get() {}

  int check_caps(RGWUserCaps& caps) override {
    return caps.check_cap("usage", RGW_CAP_READ);
  }
  void execute() override;

  const string name() override { return "get_multisite_dataflow"; }
};

void RGWOp_Multisite_Dataflow_Get::execute() {
  string uid_str =  MULTISITE_SYNC_USER;
  rgw_user uid(uid_str);
  uint64_t start, end;
  bool show_log_all;

  RESTArgs::get_epoch(s, "start", 0, &start);
  RESTArgs::get_epoch(s, "end", (uint64_t)-1, &end);
  RESTArgs::get_bool(s, "show-log-all", false, &show_log_all);

  adjust_timezone(store, start);
  adjust_timezone(store, end);

  http_ret = RGWReadUsage::show_multisite_dataflow(store, uid, start, end, show_log_all, flusher);
}

RGWOp *RGWHandler_Usage::op_get()
{
  if (s->info.args.sub_resource_exists("read-usage")) {
    return new RGWOp_Read_Usage_Get;
  } else if (s->info.args.sub_resource_exists("multisite-dataflow")) {
    return new RGWOp_Multisite_Dataflow_Get;
  }
  return new RGWOp_Usage_Get;
}

RGWOp *RGWHandler_Usage::op_delete()
{
  if (s->info.args.sub_resource_exists("read-usage")) {
    return new RGWOp_Read_Usage_Delete;
  }
  return new RGWOp_Usage_Delete;
}

