// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include "common/ceph_json.h"
#include "rgw/rgw_notification.h"
#include "rgw_common.h"
#include "rgw_formats.h"
#include <boost/algorithm/string/predicate.hpp>

#define dout_context g_ceph_context
#define dout_subsys ceph_subsys_rgw

bool check_notification_object_match(const string& in_obj, string_view conf_obj) {
  if (in_obj.size() < conf_obj.size()) {
    return false;
  }

  size_t pos = conf_obj.find('*');
  if (pos == conf_obj.npos) {
    if (in_obj != conf_obj) {
      return false;
    }
    return true;
  } else {
    vector<string> b_vec;
    boost::split(b_vec, conf_obj, boost::is_any_of("*"));
    if (pos == 0) {
      if (boost::algorithm::ends_with(in_obj, b_vec[1])) {
        return true;
      }
      return false;
    }
    if (pos == conf_obj.size()-1) {
      if (boost::algorithm::starts_with(in_obj, b_vec[0])) {
        return true;
      }
      return false;
    }
    if (boost::algorithm::starts_with(in_obj, b_vec[0]) && boost::algorithm::ends_with(in_obj, b_vec[1])) {
      return true;
    }
    return false;
  }
}

void rgw_notification_app::decode_json(JSONObj *obj)
{
  JSONDecoder::decode_json("eventUrl", eventurl, obj);
  JSONDecoder::decode_json("xVars", xvars, obj);
  JSONDecoder::decode_json("id", id, obj);
}

void rgw_notification_entry::decode_json(JSONObj *obj)
{
  JSONDecoder::decode_json("appId", appid, obj);
  JSONDecoder::decode_json("name", name, obj);
  JSONDecoder::decode_json("resources", resource, obj);
  JSONDecoder::decode_json("id", id, obj);
  JSONDecoder::decode_json("events", events, obj);
  JSONDecoder::decode_json("status", status, obj);
  JSONDecoder::decode_json("apps", apps, obj);
}

void rgw_notification::decode_json(const char *data, int len)
{
  JSONParser parser;
  bool ret = parser.parse(data, len);
  if (!ret)
    return;
  JSONDecoder::decode_json("notifications", notification, &parser);
}

int RGWNotification::gen_notification_bl(bufferlist& text, bufferlist& bl, const std::string& bucket_name)
{
  int ret = get_notification(text);
  if (ret != 0) {
    return ret;
  }
  ret = validate(bucket_name);
  if (ret != 0) {
    return ret;
  }
  encode(_notification, bl);
  return 0;
}

int RGWNotification::get_notification(bufferlist& text)
{
  try {
    _notification.decode_json(text.c_str(), text.length());
  } catch (JSONDecoder::err& e) {
    dout(5) << __func__ << " ERROR: Bad notification configuration: " << e.message << dendl;
    return -ERR_NOTIFICATIONS_FORMAT_ERROR;
  }
  return 0;
}

int RGWNotification::validate(const std::string& bucket_name)
{
  int num = _notification.notification.size();
  if (num > MAX_NOTIFICATION_NUM) {
    return -ERR_NOTIFICATIONS_TOO_MANY;
  }

  int ret = 0;
  for (int i = 0; i < num; i++) {
    ret = check_notification(_notification.notification[i], bucket_name);
    if (ret != 0)
      break;
  }
  return ret;
}

int RGWNotification::check_notification(rgw_notification_entry& entry, const std::string& bucket_name)
{
  int ret = 0;
  ret = check_id(entry.id);
  if (ret != 0) {
    return ret;
  }

  ret = check_appid(entry.appid);
  if (ret != 0) {
    return ret;
  }

  ret = check_status(entry.status);
  if (ret != 0) {
    return ret;
  }

  ret = check_resources(entry.resource, bucket_name);
  if (ret != 0) {
    return ret;
  }

  ret = check_events(entry.events);
  if (ret != 0) {
    return ret;
  }

  ret = check_apps(entry.apps);
  if (ret != 0) {
    return ret;
  }

  return ret;
}

int RGWNotification::check_id(const std::string& id)
{
  if (id.empty()) {
    dout(10) << __func__ << " failde: the input id is empty." << dendl;
    return -ERR_NOTIFICATIONS_FORMAT_ERROR;
  }

  if (id_set.find(id) != id_set.end()) {
    dout(10) << __func__ << " failed: the input id repeat. id=" << id << dendl;
    return -ERR_NOTIFICATIONS_FORMAT_ERROR;
  }
  id_set.insert(id);
  return 0;
}

int RGWNotification::check_appid(const std::string& appid)
{
  if (appid.empty()) {
    dout(10) << __func__ << " failed: the input appid is empty." << dendl;
    return -ERR_NOTIFICATIONS_FORMAT_ERROR;
  }

  if (appid_set.find(appid) != appid_set.end()) {
    dout(10) << __func__ << " failed: the input appid repeat. appid=" << appid << dendl;
    return -ERR_NOTIFICATIONS_FORMAT_ERROR;
  }
  appid_set.insert(appid);
  return 0;
}

int RGWNotification::check_status(const std::string& status)
{
  if (status_set.find(status) == status_set.end()) {
    dout(10) << __func__ << " failed: the input status is error. status=" << status << dendl;
    return -ERR_NOTIFICATIONS_FORMAT_ERROR;
  }
  return 0;
}

int RGWNotification::check_resource_format(const std::string_view& resource, const std::string& bucket_name)
{
  size_t delimiter_pos = resource.find('/');
  size_t wildcard_pos = resource.find('*');
  size_t wildcard_end_pos = resource.rfind('*');

  if (delimiter_pos == std::string::npos) {
    dout(10) << __func__ << " failed: the resource bucket mismatch. resource=" << resource << dendl;
    return -ERR_NOTIFICATIONS_FORMAT_ERROR;
  }

  // if path has bucket, must be match with bucket_name
  if (delimiter_pos > 0) {
    if (resource.substr(0, delimiter_pos) != bucket_name) {
      dout(10) << __func__ << " failed: the resource bucket mismatch. resource=" << resource << dendl;
      return -ERR_NOTIFICATIONS_FORMAT_ERROR;
    }
  }

  // in old process framework, only support only 1 "*" and must be in the begin-
  // or the end to maximum matching only 1 rulue, but may be user want to-
  // trigger more then 1 notification for different end point
  // e.g. /image/* to scan and /image/png/* compress to jpg
  // it' should be match these 2 rules
  if (wildcard_pos != wildcard_end_pos) {
      dout(10) << __func__ << " failed: the resource bucket mismatch. resource=" << resource << dendl;
      return -ERR_NOTIFICATIONS_FORMAT_ERROR;
  }

  return 0;
}

int RGWNotification::check_resources(std::vector<string> resource, const std::string& bucket_name)
{
  if (resource.size() == 0) {
    dout(10) << __func__ << " failed: the input resource is empty." << dendl;
    return -ERR_NOTIFICATIONS_FORMAT_ERROR;
  }

  int ret = 0;
  for (std::string_view r : resource) {
    ret = check_resource_format(r, bucket_name);
    if (ret != 0) {
      break;
    }
  }

  return ret;
}

int RGWNotification::check_events(std::vector<string> events)
{
  if (events.size() == 0) {
    dout(10) << __func__ << " failed: the input events is empty." << dendl;
    return -ERR_NOTIFICATIONS_FORMAT_ERROR;
  }

  int ret = 0;
  for (std::string e : events) {
    if (event_set.find(e) == event_set.end()) {
      dout(10) << __func__ << " failed: the input events is invalid. event=" << e << dendl;
      ret = -ERR_NOTIFICATIONS_FORMAT_ERROR;
      break;
    }
  }
  return ret;
}

// example: "http://10.190.78.29:8765/api/radosgw/notification/"
int RGWNotification::check_app(rgw_notification_app& app)
{
  std::string_view url = app.eventurl;

  // check eventUrl
  if (!url.empty()) {
    if ((url.substr(0, 7) != "http://") && (url.substr(0, 8) != "https://")) {
      dout(10) << __func__ << " failed: the input app url is invalid. url=" << url << dendl;
      return -ERR_NOTIFICATIONS_FORMAT_ERROR;
    }
  }
  return 0;
}

int RGWNotification::check_apps(std::vector<rgw_notification_app> apps)
{
  if (apps.size() == 0) {
    dout(10) << __func__ << " failed: the input apps is empty." << dendl;
    return -ERR_NOTIFICATIONS_FORMAT_ERROR;
  }

  int ret = 0;
  for (unsigned int i = 0; i < apps.size(); i++) {
    ret = check_app(apps[i]);
    if (ret != 0)
      break;
  }

  return ret;
}

int RGWNotification::decode_notification_bl(bufferlist& bl)
{
  try {
    decode(_notification, bl);
  } catch (buffer::error& err) {
    dout(0) << __func__ << " ERROR: could not decode notification, caught buffer::error" << dendl;
    return -EIO;
  }
  return 0;
}

void RGWNotification::to_json(ostream& out)
{
  JSONFormatter f;

  f.open_object_section("rgw_notification");
  f.open_array_section("notifications");
  std::vector<rgw_notification_entry>::iterator iter;
  for (iter = _notification.notification.begin(); iter != _notification.notification.end(); ++iter) {
    const rgw_notification_entry& entry = *iter;
    f.open_object_section("notification");
    f.dump_string("appId", entry.appid);
    f.dump_string("name", entry.name);
    f.open_array_section("resources");
    std::stringstream resource_ss;
    for (const auto& res : entry.resource) {
       resource_ss << "\"" << res << "\", ";
    }
    std::string resource_str = resource_ss.str();
    f.write_raw_data(resource_str.substr(0, resource_str.size()-2).c_str());
    f.close_section(); // end of resources
    f.dump_string("id", entry.id);
    f.open_array_section("events");
    std::stringstream event_ss;
    for (const auto& eve : entry.events) {
      event_ss << "\"" << eve << "\", ";
    }
    std::string event_str = event_ss.str();
    f.write_raw_data(event_str.substr(0, event_str.size()-2).c_str());
    f.close_section(); // end of events
    f.dump_string("status", entry.status);
    f.open_array_section("apps");
    for (const auto& app : entry.apps) {
      f.open_object_section("app");
      f.dump_string("eventUrl", app.eventurl);
      f.dump_string("xVars", app.xvars);
      f.dump_string("id", app.id);
      f.close_section(); // end of app
    }
    f.close_section(); // end of apps
    f.close_section(); // end of notification
  }
  f.close_section(); // end of notifications
  f.close_section(); // end of rgw_notification
  f.flush(out);
}

const std::set<std::string> RGWNotification::status_set = { "disabled", "enabled" };
const std::set<std::string> RGWNotification::event_set = {
        "PutObject", "PostObject" , "CopyObject",
        "CompleteMultipartUpload", "DeleteObject", "DeleteMultipleObjects" };
