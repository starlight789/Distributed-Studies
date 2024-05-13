// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#ifndef CEPH_RGW_NOTIFICATION_H
#define CEPH_RGW_NOTIFICATION_H

#include <limits.h>

#include <map>
#include <list>
#include <string>
#include <string_view>
#include <vector>

#include "include/utime.h"
#include "rgw_basic_types.h"
#include "rgw_string.h"



static const int MAX_NOTIFICATION_NUM = 20;
const std::map<std::string, std::string> event_map = {
  {"put_obj", "PutObject"},
  {"post_obj", "PostObject"},
  {"copy_obj", "CopyObject"},
  {"complete_multipart", "CompleteMultipartUpload"},
  {"delete_obj", "DeleteObject"},
  {"multi_object_delete", "DeleteMultipleObjects"}
};

bool check_notification_object_match(const string& in_obj, string_view conf_obj);

class JSONObj;

struct rgw_notification_app {
  std::string eventurl;
  std::string xvars;
  std::string id;

  void encode(bufferlist& bl) const {
    ENCODE_START(1, 1, bl);
    encode(eventurl, bl);
    encode(xvars, bl);
    encode(id, bl);
    ENCODE_FINISH(bl);
  }

  void decode(bufferlist::iterator& bl) {
    DECODE_START(1, bl);
    decode(eventurl, bl);
    decode(xvars, bl);
    decode(id, bl);
    DECODE_FINISH(bl);
  }

  void decode_json(JSONObj *obj);
};
WRITE_CLASS_ENCODER(rgw_notification_app)

struct rgw_notification_entry {
  std::string appid;
  std::string name;
  std::vector<string> resource;
  std::string id;
  std::vector<string> events;
  std::string status;
  std::vector<rgw_notification_app> apps;

  void encode(bufferlist& bl) const {
    ENCODE_START(1, 1, bl);
    encode(appid, bl);
    encode(name, bl);
    encode(resource, bl);
    encode(id, bl);
    encode(events, bl);
    encode(status, bl);
    encode(apps, bl);
    ENCODE_FINISH(bl);
  }

  void decode(bufferlist::iterator& bl) {
    DECODE_START(1, bl);
    decode(appid, bl);
    decode(name, bl);
    decode(resource, bl);
    decode(id, bl);
    decode(events, bl);
    decode(status, bl);
    decode(apps, bl);
    DECODE_FINISH(bl);
  }

  void decode_json(JSONObj *obj);
};
WRITE_CLASS_ENCODER(rgw_notification_entry)

struct rgw_notification {
  std::vector<rgw_notification_entry> notification;

  rgw_notification() {}

  void encode(bufferlist& bl) const {
    ENCODE_START(1, 1, bl);
    encode(notification, bl);
    ENCODE_FINISH(bl);
  }

  void decode(bufferlist::iterator& bl) {
    DECODE_START(1, bl);
    decode(notification, bl);
    DECODE_FINISH(bl);
  }

  void decode_json(const char *data, int len);
};
WRITE_CLASS_ENCODER(rgw_notification)

class RGWNotification {
  rgw_notification _notification;

public:
  RGWNotification() {}

  int gen_notification_bl(bufferlist& text, bufferlist& bl, const std::string& bucket_name);
  int get_notification(bufferlist& text);

  int validate(const std::string& bucket_name);
  int check_notification(rgw_notification_entry& entry, const std::string& bucket_name);
  int check_id(const std::string& id);
  int check_appid(const std::string& appid);
  int check_status(const std::string& status);
  int check_resource_format(const std::string_view& resource, const std::string& bucket_name);
  int check_resources(std::vector<string> resource, const std::string& bucket_name);
  int check_events(std::vector<string> events);
  int check_app(rgw_notification_app& app);
  int check_apps(std::vector<rgw_notification_app> apps);

  int decode_notification_bl(bufferlist& bl);
  void to_json(ostream& ss);
  rgw_notification* get_rgw_notification() { return &_notification; }


private:
  std::set<std::string> id_set;
  std::set<std::string> appid_set;
  static const std::set<std::string> status_set;
  static const std::set<std::string> event_set;

};

#endif
