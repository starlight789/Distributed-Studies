// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include <errno.h>
#include <array>
#include <string.h>
#include <sstream>

#include "common/ceph_crypto.h"
#include "common/Formatter.h"
#include "common/utf8.h"
#include "common/safe_io.h"
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <boost/utility/string_view.hpp>
#include "rapidjson/stringbuffer.h"
#include "rapidjson/reader.h"
#include "rapidjson/prettywriter.h"
#include "rapidjson/document.h"
#include "rapidjson/error/error.h"
#include "rapidjson/error/en.h"

#include <liboath/oath.h>

#include "rgw_rest.h"
#include "rgw_rest_bos.h"
#include "rgw_auth_s3.h"
#include "rgw_acl.h"
#include "rgw_policy_s3.h"
#include "rgw_user.h"
#include "rgw_cors.h"
#include "rgw_cors_s3.h"
#include "rgw_tag_s3.h"

#include "rgw_client_io.h"

#include "rgw_keystone.h"
#include "rgw_auth_keystone.h"
#include "rgw_auth_registry.h"

#include "rgw_es_query.h"

#include <typeinfo> // for 'typeid'

#include "rgw_ldap.h"
#include "rgw_token.h"
#include "rgw_rest_role.h"
#include "rgw_crypt.h"
#include "rgw_crypt_sanitize.h"
#include "rgw_string.h"

#include "include/assert.h"

#define dout_context g_ceph_context
#define dout_subsys ceph_subsys_rgw

#define RGW_URI_ALL_BOS_USERS "*"
#define RGW_URI_AUTH_BOS_USERS "*"

#define S3_USER_STR "arn:aws:iam:::user/"
#define S3_PERM_STR "s3:"
#define S3_RESOURCE_NAME "arn:aws:s3:::nme"
#define S3_RESOURCE_NULL "arn:aws:s3:::nil"
#define S3_RESOURCE_STR "arn:aws:s3:::"

using namespace rgw;
using namespace ceph::crypto;

using std::get;

using rapidjson::BaseReaderHandler;
using rapidjson::UTF8;
using rapidjson::SizeType;
using rapidjson::StringStream;

void dump_bucket_bos(struct req_state *s, RGWBucketEnt& obj)
{
  s->formatter->open_object_section("bucket");
  s->formatter->dump_string("name", obj.bucket.name);
  s->formatter->dump_string("location", s->cct->_conf->rgw_default_location);
  s->formatter->dump_bool("enableDedicated", obj.enable_dedicated);
  dump_time(s, "creationDate", &obj.creation_time);
  s->formatter->close_section();
}

void RGWListBuckets_ObjStore_BOS::send_response_begin(bool has_buckets)
{
  if (op_ret)
    set_req_state_err(s, op_ret);
  dump_errno(s);
  dump_start(s);
  end_header(s, NULL, CONTENT_TYPE_JSON);

  if (! op_ret) {
    s->formatter->open_object_section("ListAllMyBucketsResult");
    dump_owner(s, s->user->user_id, s->user->display_name);
    s->formatter->open_array_section("buckets");
    sent_data = true;
  }
}

void RGWListBuckets_ObjStore_BOS::send_response_data(RGWUserBuckets& buckets)
{
  if (!sent_data)
    return;

  map<string, RGWBucketEnt>& m = buckets.get_buckets();
  map<string, RGWBucketEnt>::iterator iter;

  for (iter = m.begin(); iter != m.end(); ++iter) {
    RGWBucketEnt obj = iter->second;
    dump_bucket_bos(s, obj);
  }
  rgw_flush_formatter(s, s->formatter);
}

void RGWListBuckets_ObjStore_BOS::send_response_end()
{
  if (sent_data) {
    s->formatter->close_section();
    list_all_buckets_end(s);
    rgw_flush_formatter_and_reset(s, s->formatter);
  }
}

int RGWListBucket_ObjStore_BOS::get_params()
{
  prefix = s->info.args.get("prefix");
#define MAX_NAME_LENGTH 1024
  if (s->info.args.get("marker").length() > MAX_NAME_LENGTH) {
    op_ret = -EINVAL;
    return op_ret;
  }
  marker = s->info.args.get("marker");

  // non-standard
  s->info.args.get_bool("allow-unordered", &allow_unordered, false);

  delimiter = s->info.args.get("delimiter");

  max_keys = s->info.args.get("maxKeys");
  int64_t value = atoll(max_keys.c_str());
  if (value < 0) {
    return -EINVAL;
  }
  op_ret = parse_max_keys();
  if (op_ret < 0) {
    return op_ret;
  }

  encoding_type = s->info.args.get("encoding-type");
  if (s->system_request) {
    s->info.args.get_bool("objs-container", &objs_container, false);
    const char *shard_id_str = s->info.env->get("HTTP_RGWX_SHARD_ID");
    if (shard_id_str) {
      string err;
      shard_id = strict_strtol(shard_id_str, 10, &err);
      if (!err.empty()) {
        ldout(s->cct, 5) <<  __func__ << " bad shard id specified: " << shard_id_str << dendl;
        return -EINVAL;
      }
    } else {
      shard_id = s->bucket_instance_shard_id;
    }
  }

  return 0;
}

void RGWListBucket_ObjStore_BOS::send_response()
{
  if (website_retarget) {
    return;
  }
  if (op_ret < 0)
    set_req_state_err(s, op_ret);
  dump_errno(s);

  end_header(s, this, CONTENT_TYPE_JSON);
  dump_start(s);
  if (op_ret < 0)
    return;

  s->formatter->open_object_section("ListBucketsResult");
  if (!s->bucket_tenant.empty())
    s->formatter->dump_string("tenant", s->bucket_tenant);
  s->formatter->dump_string("name", s->bucket_name);
  s->formatter->dump_string("prefix", prefix);
  s->formatter->dump_string("marker", marker.name);
  if (is_truncated && !next_marker.empty())
    s->formatter->dump_string("nextMarker", next_marker.name);
  s->formatter->dump_int("maxKeys", max);
  if (!delimiter.empty())
    s->formatter->dump_string("delimiter", delimiter);

  s->formatter->dump_bool("isTruncated", (max && is_truncated ? true : false));

  bool encode_key = false;
  if (strcasecmp(encoding_type.c_str(), "url") == 0) {
    s->formatter->dump_string("EncodingType", "url");
    encode_key = true;
  }

  if (op_ret >= 0) {
    vector<rgw_bucket_dir_entry>::iterator iter;
    s->formatter->open_array_section("contents");
    for (iter = objs.begin(); iter != objs.end(); ++iter) {
      s->formatter->open_object_section("key");
      rgw_obj_key key(iter->key);

      string key_name = key.name;
      if (encode_key) {
        url_encode(key.name, key_name);
      }
      s->formatter->dump_string("key", key.name);
      dump_time(s, "lastModified", &iter->meta.mtime);
      s->formatter->dump_format("eTag", "%s", iter->meta.etag.c_str());
      s->formatter->dump_int("size", iter->meta.accounted_size);
      s->formatter->dump_string("storageClass",
      rgw_placement_rule::get_canonical_storage_class(iter->meta.storage_class));
      dump_owner(s, iter->meta.owner, iter->meta.owner_display_name);
      s->formatter->close_section();
    }
    s->formatter->close_section();  // close [contents]
    if (!common_prefixes.empty()) {
      map<string, bool>::iterator pref_iter;
      s->formatter->open_array_section("commonPrefixes");
      for (pref_iter = common_prefixes.begin();
          pref_iter != common_prefixes.end(); ++pref_iter) {
        s->formatter->open_object_section("p");
        s->formatter->dump_string("prefix", pref_iter->first);
        s->formatter->close_section();
      }
      s->formatter->close_section();
    }
  }
  s->formatter->close_section();
  rgw_flush_formatter_and_reset(s, s->formatter);
}

static std::string parse_policy_to_bos(CephContext* cct, std::string&  text, RGWBucketInfo& bucket_info) {
  std::string out_put;
  rapidjson::Document dom;
  if (!dom.Parse(text.c_str()).HasParseError()) {
    rapidjson::StringBuffer buf;
    rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(buf);

    writer.StartObject();
    writer.Key("owner"); writer.StartObject();
    writer.Key("id"); writer.String(bucket_info.owner.id.c_str());
    writer.EndObject();

    if (dom.HasMember("Statement") && dom["Statement"].IsArray()) {
      writer.Key("accessControlList"); writer.StartArray();
      for (SizeType index = 0; index < dom["Statement"].Size(); index++) {
        const rapidjson::Value& s3_control = dom["Statement"][index];
        writer.StartObject();

        if (s3_control.HasMember("HaveEffect") &&
            strcmp(s3_control["HaveEffect"].GetString(), "true") == 0 && s3_control.HasMember("Effect")) {
          writer.Key("effect"); writer.String(s3_control["Effect"].GetString());
        }

        if (s3_control.HasMember("Principal")  && s3_control["Principal"].IsObject() && s3_control["Principal"].HasMember("AWS")) {
          const rapidjson::Value& users = s3_control["Principal"]["AWS"];
          writer.Key("grantee"); writer.StartArray();
          if (users.IsArray()) {
            for (SizeType index = 0; index < users.Size(); index++) {
              writer.StartObject(); writer.Key("id");
              std::string id = users[index].GetString();
              if (id.find(S3_USER_STR) != std::string::npos) {
                id.replace(id.find(S3_USER_STR), strlen(S3_USER_STR), "");
              }
              writer.String(id.c_str());
              writer.EndObject();
            }
          } else {
            std::string id = users.GetString();
            if (id.find(S3_USER_STR) != std::string::npos) {
              id.replace(id.find(S3_USER_STR), strlen(S3_USER_STR), "");
            }
            writer.StartObject(); writer.Key("id");
            writer.String(id.c_str()); writer.EndObject();
          }
          writer.EndArray(); // end of grantee
        } else {
          return out_put;
        }

        if (s3_control.HasMember("Action")) {
          writer.Key("permission"); writer.StartArray();
          if (s3_control["Action"].IsArray()) {
            for (SizeType index = 0; index < s3_control["Action"].Size(); index++) {
              std::string perm = s3_control["Action"][index].GetString();
              if (perm.find(S3_PERM_STR) != std::string::npos) {
                perm.replace(perm.find(S3_PERM_STR), strlen(S3_PERM_STR), "");
              }
              writer.String(perm.c_str());
            }
          } else {
            std::string perm = s3_control["Action"].GetString();
            if (perm.find(S3_PERM_STR) != std::string::npos) {
              perm.replace(perm.find(S3_PERM_STR), strlen(S3_PERM_STR), "");
            }
            writer.String(perm.c_str());
          }
          writer.EndArray(); // end of permission
        } else {
          return out_put;
        }

        if (s3_control.HasMember("Resource") && !s3_control.HasMember("NotResource")) {
          if (s3_control["Resource"].IsArray()) {
            writer.Key("resource"); writer.StartArray();
            for (SizeType index = 0; index < s3_control["Resource"].Size(); index++) {
              std::string resource = s3_control["Resource"][index].GetString();
              if (resource == S3_RESOURCE_NAME) {
                writer.String(bucket_info.bucket.name.c_str());
              } else if (resource.find(S3_RESOURCE_STR) != std::string::npos) {
                resource.replace(resource.find(S3_RESOURCE_STR), strlen(S3_RESOURCE_STR), "");
                writer.String(resource.c_str());
              } else {
                writer.String(resource.c_str());
              }
            }
            writer.EndArray(); // end of resource
          } else {
            std::string resource = s3_control["Resource"].GetString();
            if (resource == S3_RESOURCE_NAME) {
              writer.StartArray(); writer.String(bucket_info.bucket.name.c_str()); writer.EndArray();
            } else if (resource != S3_RESOURCE_NULL && resource.find(S3_RESOURCE_STR) != std::string::npos) {
              resource.replace(resource.find(S3_RESOURCE_STR), strlen(S3_RESOURCE_STR), "");
              writer.StartArray(); writer.String(resource.c_str()); writer.EndArray();
            }
          }
        }

        if (s3_control.HasMember("NotResource")) {
          writer.Key("notResource"); writer.StartArray();
          if (s3_control["NotResource"].IsArray()) {
            for (SizeType index = 0; index < s3_control["NotResource"].Size(); index++) {
              std::string resource = s3_control["NotResource"][index].GetString();
              if (resource == S3_RESOURCE_NAME) {
                writer.String(bucket_info.bucket.name.c_str());
              } else if (resource.find(S3_RESOURCE_STR) != std::string::npos) {
                resource.replace(resource.find(S3_RESOURCE_STR), strlen(S3_RESOURCE_STR), "");
                writer.String(resource.c_str());
              } else {
                writer.String(resource.c_str());
              }
            }
          } else {
            std::string resource = s3_control["NotResource"].GetString();
            if (resource == S3_RESOURCE_NAME) {
              writer.String(bucket_info.bucket.name.c_str());
            } else if (resource.find(S3_RESOURCE_STR) != std::string::npos) {
              resource.replace(resource.find(S3_RESOURCE_STR), strlen(S3_RESOURCE_STR), "");
              writer.String(resource.c_str());
            } else {
              writer.String(resource.c_str());
            }
          }
          writer.EndArray(); // end of notResource
        }

        if (s3_control.HasMember("Condition") && s3_control["Condition"].IsObject()) {
          const rapidjson::Value& condition = s3_control["Condition"];
          writer.Key("condition"); writer.StartObject();
          if (condition.HasMember("StringLike") || condition.HasMember("StringEquals")) {
            std::vector<std::string> string_like;
            std::vector<std::string> string_equals;
            if (condition.HasMember("StringLike") && condition["StringLike"].IsObject()
              && condition["StringLike"].HasMember("aws:Referer")) {
              if (condition["StringLike"]["aws:Referer"].IsArray()) {
                for (SizeType index = 0; index < condition["StringLike"]["aws:Referer"].Size(); index++) {
                  std::string referer = condition["StringLike"]["aws:Referer"][index].GetString();
                  string_like.push_back(referer);
                }
              } else {
                std::string referer = condition["StringLike"]["aws:Referer"].GetString();
                string_like.push_back(referer);
              }
            }
            if (condition.HasMember("StringEquals") && condition["StringEquals"].IsObject()
                && condition["StringEquals"].HasMember("aws:Referer")) {
              if (condition["StringEquals"]["aws:Referer"].IsArray()) {
                for (SizeType index = 0; index < condition["StringEquals"]["aws:Referer"].Size(); index++) {
                  std::string referer = condition["StringEquals"]["aws:Referer"][index].GetString();
                  string_equals.push_back(referer);
                }
              } else {
                std::string referer = condition["StringEquals"]["aws:Referer"].GetString();
                string_equals.push_back(referer);
              }
            }

            writer.Key("referer"); writer.StartObject();
            if (!string_like.empty()) {
              writer.Key("stringLike"); writer.StartArray();
              for (auto referer : string_like) {
                writer.String(referer.c_str());
              }
              writer.EndArray();
            }
            if (!string_equals.empty()) {
             writer.Key("stringEquals"); writer.StartArray();
              for (auto referer : string_equals) {
                writer.String(referer.c_str());
              }
              writer.EndArray();
            }
            writer.EndObject();
          }

          if (condition.HasMember("IpAddress") && condition["IpAddress"].IsObject()
              && condition["IpAddress"].HasMember("aws:SourceIp")) {
            writer.Key("ipAddress"); writer.StartArray();
            if (condition["IpAddress"]["aws:SourceIp"].IsArray()) {
              for (SizeType index = 0; index < condition["IpAddress"]["aws:SourceIp"].Size(); index++) {
                writer.String(condition["IpAddress"]["aws:SourceIp"][index].GetString());
              }
            } else {
              writer.String(condition["IpAddress"]["aws:SourceIp"].GetString());
            }
            writer.EndArray();
          }
          writer.EndObject(); // end of ipAddoress
        }

        writer.EndObject(); // end of condition
      }
      writer.EndArray();

    } else {
      return out_put;
    }
    writer.EndObject(); // end of accessControlList

    out_put = buf.GetString();
  }
  out_put.erase(std::remove(out_put.begin(), out_put.end(), ' '), out_put.end());
  out_put.erase(std::remove(out_put.begin(), out_put.end(), '\n'), out_put.end());
  return out_put;
}

static bool check_bos_condition_ip(string val) {
  string ip;
  if (val.find(".*") == string::npos) {
    auto slash = val.find("/");
    if (slash == val.size() - 1) {
      return false;
    }
    if (slash != string::npos) {
      auto prefix = atoi(val.substr(slash + 1).c_str());
      if (prefix > 32 || prefix % 8 != 0) {
        return false;
      }
      ip.assign(val, 0, slash);
    } else {
      ip = val;
    }
  } else if (val.find(".*") == val.size() - 2) {
    ip.assign(val, 0, val.size() - 2);
    int split_count = count(ip.begin(), ip.end(), '.');
    if (split_count < 3) {
      while (3 - split_count > 0) {
        ip += ".0";
        split_count++;
      }
    }
  } else {
    return false;
  }
  struct in_addr bos_addr;
  if (inet_pton(AF_INET, ip.c_str(), static_cast<void*>(&bos_addr)) != 1) {
    return false;
  }
  return true;
}

static std::string parse_policy_to_s3(CephContext* cct, char* text, RGWBucketInfo& bucket_info) {
  std::string out_put;
  rapidjson::Document dom;
  if (!dom.Parse(text).HasParseError()) {
    rapidjson::StringBuffer buf;
    rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(buf);

    if (dom.HasMember("owner")) {
      if (!dom["owner"].IsObject() || !dom["owner"].HasMember("id") || !dom["owner"]["id"].IsString()
          || strcmp(dom["owner"]["id"].GetString(), bucket_info.owner.id.c_str()) != 0) {
        return out_put;
      }
    }

    if (dom.HasMember("accessControlList") && dom["accessControlList"].IsArray()) {
      writer.StartObject(); writer.Key("Statement");
      writer.StartArray();
      for (SizeType index = 0; index < dom["accessControlList"].Size(); index++) {
        const rapidjson::Value& bos_control = dom["accessControlList"][index];
        writer.StartObject();

        if (bos_control.HasMember("effect")){
          if (bos_control["effect"].IsString()) {
            writer.Key("Effect"); writer.String(bos_control["effect"].GetString());
            writer.Key("HaveEffect"); writer.String("true");
          } else {
            return out_put;
          }
        } else {
          writer.Key("Effect"); writer.String("Allow");
          writer.Key("HaveEffect"); writer.String("false");
        }

        if (bos_control.HasMember("grantee") && bos_control["grantee"].IsArray()) {
          writer.Key("Principal"); writer.StartObject();
          writer.Key("AWS"); writer.StartArray();
          if (bos_control["grantee"].Size() == 0) {
            return out_put;
          }
          for (SizeType index_id = 0; index_id < bos_control["grantee"].Size(); index_id++) {
            if (bos_control["grantee"][index_id].HasMember("id") && bos_control["grantee"][index_id]["id"].IsString()) {
              string bos_id = bos_control["grantee"][index_id]["id"].GetString();
              if (bos_id.find("*") == std::string::npos) {
                bos_id = S3_USER_STR + bos_id;
              }
              writer.String(bos_id.c_str());
            } else {
              return out_put;
            }
          }
          writer.EndArray();
          writer.EndObject(); // end of Principal
        } else {
          return out_put;
        }

        if (bos_control.HasMember("permission") && bos_control["permission"].IsArray()) {
          writer.Key("Action");
          writer.StartArray();
          if (bos_control["permission"].Size() == 0) {
            return out_put;
          }
          for (SizeType index_perm = 0; index_perm < bos_control["permission"].Size(); index_perm++) {
            string perm = bos_control["permission"][index_perm].GetString();
            if (perm != "READ" && perm != "WRITE" && perm != "LIST" && perm != "MODIFY" && perm != "FULL_CONTROL") {
              perm = S3_PERM_STR + perm;
            }
            writer.String(perm.c_str());
          }
          writer.EndArray();
        } else {
          return out_put;
        }

        writer.Key("Resource");
        if (bos_control.HasMember("resource") && bos_control["resource"].IsArray()) {
          writer.StartArray();
          for (SizeType index = 0; index < bos_control["resource"].Size(); index++) {
            string bos_resource_str = bos_control["resource"][index].GetString();
            string resource_str = string(S3_RESOURCE_STR) + bos_resource_str;
            if (bos_resource_str == bucket_info.bucket.name) {
              resource_str = S3_RESOURCE_NAME;
            } else if (bos_resource_str.find(bucket_info.bucket.name + "/") != 0 ||
                (bos_resource_str.find("*") != string::npos && bos_resource_str.find("*") != bos_resource_str.size() - 1) ||
                bos_resource_str == (bucket_info.bucket.name + "/")) {
              return out_put;
            }
            writer.String(resource_str.c_str());
          }
          writer.EndArray();
        } else if (bos_control.HasMember("notResource")) {
          string resource_str = string(S3_RESOURCE_STR) + bucket_info.bucket.name + "/*";
          writer.String(resource_str.c_str());
        } else {
          writer.String(S3_RESOURCE_NULL);
        }

        if (bos_control.HasMember("notResource")) {
          if (!bos_control["notResource"].IsArray() || bos_control.HasMember("resource")) {
            return out_put;
          }
          writer.Key("NotResource"); writer.StartArray();
          for (SizeType index = 0; index < bos_control["notResource"].Size(); index++) {
            string bos_not_resource_str = bos_control["notResource"][index].GetString();
            string not_resource_str = string(S3_RESOURCE_STR)  + bos_not_resource_str;
            if (bos_not_resource_str == bucket_info.bucket.name) {
              not_resource_str = S3_RESOURCE_NAME;
            } else if (bos_not_resource_str.find(bucket_info.bucket.name + "/") != 0 ||
                (bos_not_resource_str.find("*") != string::npos && bos_not_resource_str.find("*") != bos_not_resource_str.size() - 1) ||
                bos_not_resource_str == (bucket_info.bucket.name + "/")) {
              return out_put;
            }
            writer.String(not_resource_str.c_str());
          }
          writer.EndArray();
        }

        if (bos_control.HasMember("condition") && bos_control["condition"].IsObject()) {
          writer.Key("Condition");
          writer.StartObject();
          const rapidjson::Value& condition = bos_control["condition"];
          if (condition.HasMember("referer") && condition["referer"].IsObject()) {
            if (condition["referer"].HasMember("stringEquals") && condition["referer"]["stringEquals"].IsArray()) {
              writer.Key("StringEquals"); writer.StartObject();
              writer.Key("aws:Referer"); writer.StartArray();
              for (SizeType index = 0; index < condition["referer"]["stringEquals"].Size(); index++) {
                writer.String(condition["referer"]["stringEquals"][index].GetString());
              }
              writer.EndArray(); writer.EndObject();
            }
            if (condition["referer"].HasMember("stringLike") && condition["referer"]["stringLike"].IsArray()) {
              writer.Key("StringLike"); writer.StartObject();
              writer.Key("aws:Referer"); writer.StartArray();
              for (SizeType index = 0; index < condition["referer"]["stringLike"].Size(); index++) {
                string referer_str = condition["referer"]["stringLike"][index].GetString();
                if (referer_str.find("*") != string::npos && referer_str.find("*") != referer_str.rfind("*")) {
                  return out_put;
                }
                writer.String(referer_str.c_str());
              }
              writer.EndArray(); writer.EndObject(); // end of referer
            }
          }
          if (condition.HasMember("ipAddress") && condition["ipAddress"].IsArray()) {
            writer.Key("IpAddress");
            writer.StartObject();
            writer.Key("aws:SourceIp");
            writer.StartArray();
            for (SizeType index = 0; index < condition["ipAddress"].Size(); index++) {
              string ip = condition["ipAddress"][index].GetString();
              if (!check_bos_condition_ip(ip)) {
                return out_put;
              }
              writer.String(ip.c_str());
            }
            writer.EndArray();
            writer.EndObject(); // end of ipAddress
          }
          writer.EndObject(); // end of Conidition
        }
        writer.EndObject();
      }
      writer.EndArray();
      writer.EndObject(); // end of Statement
    }
    out_put = buf.GetString();
  }
  out_put.erase(std::remove(out_put.begin(), out_put.end(), ' '), out_put.end());
  out_put.erase(std::remove(out_put.begin(), out_put.end(), '\n'), out_put.end());
  return out_put;
}

static std::string parse_canned_policy(CephContext* cct, const char* canned_acl, RGWBucketInfo& bucket_info) {
  string out_put;
  rapidjson::StringBuffer buf;
  rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(buf);

  writer.StartObject();
  writer.Key("Statement"); writer.StartArray();

  writer.StartObject();
  writer.Key("Effect"); writer.String("Allow");
  writer.Key("Principal"); writer.StartObject();
  writer.Key("AWS"); writer.String(string(S3_USER_STR + bucket_info.owner.id).c_str());
  writer.EndObject();
  writer.Key("Resource"); writer.String(S3_RESOURCE_NULL);
  writer.Key("Action"); writer.String("FULL_CONTROL");
  writer.EndObject();

  if (strcmp(canned_acl, "public-read") == 0 || strcmp(canned_acl, "public-read-write") == 0) {
    writer.StartObject();
    writer.Key("Effect"); writer.String("Allow");
    writer.Key("Principal"); writer.StartObject();
    writer.Key("AWS"); writer.String("*");
    writer.EndObject();
    writer.Key("Resource"); writer.String(S3_RESOURCE_NULL);
    writer.Key("Action"); writer.StartArray();
    if (strcmp(canned_acl, "public-read") == 0) {
      writer.String("READ");
    } else {
      writer.String("READ"); writer.String("WRITE");
    }
    writer.EndArray();
    writer.EndObject();
    writer.EndArray(); writer.EndObject();
    out_put = buf.GetString();
  } else if (strcmp(canned_acl, "private") == 0) {
    writer.EndArray(); writer.EndObject();
    out_put = buf.GetString();
  }

  out_put.erase(std::remove(out_put.begin(), out_put.end(), ' '), out_put.end());
  out_put.erase(std::remove(out_put.begin(), out_put.end(), '\n'), out_put.end());
  return out_put;
}

void RGWGetBucketPolicy_ObjStore_BOS::send_response()
{
  std::string new_policy;
  if (policy.length() == 0) {
    new_policy = parse_canned_policy(s->cct, "private", s->bucket_info);
  } else {
    new_policy = policy.c_str();
    new_policy = new_policy.substr(0, policy.length());
  }

  std::string bos_acl = parse_policy_to_bos(s->cct, new_policy, s->bucket_info);
  if (bos_acl.empty()) {
    op_ret = -EACCES;
  }

  if (op_ret)
    set_req_state_err(s, op_ret);
  dump_errno(s);
  end_header(s, this, CONTENT_TYPE_JSON);

  dump_body(s, bos_acl);
}

int RGWSetBucketWebsite_ObjStore_BOS::get_params()
{
  char *data = nullptr;
  int len = 0;
  const auto max_size = s->cct->_conf->rgw_max_put_param_size;
  int r = rgw_rest_read_all_input(s, &data, &len, max_size, false);
  if (r < 0) {
    return r;
  }

  if (len == 0) {
    return -EINVAL;
  }

  auto data_deleter = std::unique_ptr<char, decltype(free)*> {data, free};

  JSONParser parser;
  in_data = bufferlist::static_from_mem(data, len);
  op_ret = parser.parse(in_data.c_str(), len);
  if (op_ret < 0){ 
    ldout(s->cct, 10) << __func__ << " failed to parse json." << dendl;
    return -ERR_MALFORMED_JSON;
  }

  JSONObj *index_file = parser.find_obj("index");
  JSONObj *error_file = parser.find_obj("notFound");
  if (!index_file && !error_file) {
    op_ret = -ERR_INAPPROPRIATE_JSON;
    ldout(s->cct, 10) << __func__ << " missing parameter." << dendl;
    return op_ret;
  } else if (index_file && index_file->get_data().empty() && error_file && error_file->get_data().empty()) {
    op_ret = -ERR_INAPPROPRIATE_JSON;
    ldout(s->cct, 10) << __func__ << " all parameter is empty." << dendl;
    return op_ret;
  }

  string index_doc, error_doc;
  if (index_file) {
    index_doc = index_file->get_data();
    if (index_doc.size() > 0) {
      std::string suffix = ".html";
      std::size_t index = index_doc.find(suffix, index_doc.length() - suffix.length());
      if (index == std::string::npos) {
        op_ret = -ERR_INVAILD_STATIC_WEBSITE_FORMAT;
        return op_ret;
      }
    }
  }
  if (error_file) {
    error_doc = error_file->get_data();
    if (error_doc.size() > 0  && !check_suffix(error_doc)) {
      op_ret = -ERR_INVAILD_STATIC_WEBSITE_FORMAT;
      return op_ret;
    }
  }

  if (index_doc.compare(error_doc) == 0) {
    op_ret = -ERR_INVAILD_STATIC_WEBSITE_FORMAT;
    return op_ret;
  }

  website_conf.index_doc_suffix = index_doc;
  website_conf.error_doc = error_doc;

  return 0;
}

void RGWSetBucketWebsite_ObjStore_BOS::send_response()
{
  if (op_ret) {
    set_req_state_err(s, op_ret);
  }
  dump_errno(s);
  end_header(s, this, CONTENT_TYPE_JSON);
}

void RGWGetBucketWebsite_ObjStore_BOS::send_response()
{
  if (op_ret)
    set_req_state_err(s, op_ret);
  dump_errno(s);
  end_header(s, this, CONTENT_TYPE_JSON);

  if (op_ret == 0) {
    RGWBucketWebsiteConf& website_conf = s->bucket_info.website_conf;
    dump_start(s);
    s->formatter->open_object_section("WebsiteConfiguration");
    if (!website_conf.index_doc_suffix.empty()) {
      s->formatter->dump_string("index", website_conf.index_doc_suffix);
    }
    if (!website_conf.error_doc.empty()) {
      s->formatter->dump_string("notFound", website_conf.error_doc);
    }
    s->formatter->close_section();
    rgw_flush_formatter_and_reset(s, s->formatter);
  }
}

void RGWDeleteBucketWebsite_ObjStore_BOS::send_response()
{
  int r = op_ret;
  if (!r)
    r = STATUS_NO_CONTENT;

  set_req_state_err(s, r);
  dump_errno(s);
  end_header(s, this, CONTENT_TYPE_JSON);
}

int RGWPutBucketPolicy_ObjStore_BOS::get_params()
{
  const auto max_size = s->cct->_conf->rgw_max_put_param_size;
  op_ret = rgw_rest_read_all_input(s, &data, &len, max_size, false);
#define MAX_BOS_POLICY_BODY 20480
  if (len > MAX_BOS_POLICY_BODY) {
    op_ret = -ERR_MAX_MESSAGE_LENGTH_EXCEEDED;
    return op_ret;
  }
  string parse_str;
  if (len == 0 && !s->canned_acl.empty()) {
    parse_str = parse_canned_policy(s->cct, s->canned_acl.c_str(), s->bucket_info);
  } else if (len != 0 && s->canned_acl.empty()) {
    parse_str = parse_policy_to_s3(s->cct, data, s->bucket_info);
  }
  char* new_data = strdup(parse_str.c_str());
  if (data) {
    free(data);
  }
  data = new_data;
  len = parse_str.size();
  return op_ret;
}

void RGWPutBucketPolicy_ObjStore_BOS::send_response()
{
  if (op_ret) {
    set_req_state_err(s, op_ret);
  }
  dump_errno(s);
  end_header(s);
}

int RGWPutBucketQuota_ObjStore_BOS::verify_permission()
{
  // only the primary user with bucket has permission.
  if (!s->auth.identity->is_owner_of(s->bucket_owner.get_id()) || s->user->subusers.size() != 0) {
    return -EACCES;
  }

  return 0;
}

int RGWPutBucketQuota_ObjStore_BOS::get_params()
{
  char *data = nullptr;
  int len = 0;
  const auto max_size = s->cct->_conf->rgw_max_put_param_size;
  op_ret = rgw_rest_read_all_input(s, &data, &len, max_size, false);
  if (op_ret != 0) {
    ldout(s->cct, 10) << __func__ << " error in request body." << dendl;
    return op_ret;
  }

  JSONParser parser;
  in_data = bufferlist::static_from_mem(data, len);
  op_ret = parser.parse(in_data.c_str(), len);
  if (op_ret < 0){ 
    ldout(s->cct, 10) << __func__ << " failed to parse json." << dendl;
    return op_ret;
  }
  
  JSONObj *maxOCJsonObj = parser.find_obj("maxObjectCount");
  JSONObj *maxCMBJsonObj = parser.find_obj("maxCapacityMegaBytes");
  if (!maxOCJsonObj || !maxCMBJsonObj) {
    op_ret = -EINVAL;
    ldout(s->cct, 10) << __func__ << " missing parameter." << dendl;
    return op_ret;
  }

  try {
      JSONDecoder::decode_json("maxObjectCount", max_objects, &parser);
      JSONDecoder::decode_json("maxCapacityMegaBytes", max_size_mb, &parser);
  } catch (JSONDecoder::err& e) {
    ldout(s->cct, 10) << __func__ << " wrong parameter type." << dendl;
    op_ret = -ERR_INAPPROPRIATE_JSON;
    return op_ret;
  }

  return op_ret;
}

int RGWPutBucketQuota_ObjStore_BOS::check_quota_params(){
  if (max_objects < -1 || max_size_mb < -1){
    ldout(s->cct, 10) << __func__ << " wrong parameter value." << dendl;
    op_ret = -EINVAL;
    return op_ret;
  }

  /* The bos api uses 0 to indicate that an unlimited quota has been set, and -1 to remove the quota limit. In fact, both have the same effect.
     In ceph, 0 means no quota. So we replace the 0 with -2 to indicate that the quota was removed. */
  if(max_size_mb == 0){
    max_size_kb = -2;
  }else if (max_size_mb == -1){
    max_size_kb = -1;
  }else{
    max_size_kb = max_size_mb * 1024 * 1024;
  }
  if (max_objects == 0){
    max_objects = -2;
  }

  return 0;
}

void RGWPutBucketQuota_ObjStore_BOS::send_response()
{
  if (op_ret) {
    set_req_state_err(s, op_ret);
  }
  dump_errno(s);
  end_header(s);
}

int RGWGetBucketQuota_ObjStore_BOS::verify_permission()
{
  // only the primary user with bucket has permission.
  if (!s->auth.identity->is_owner_of(s->bucket_owner.get_id()) || s->user->subusers.size() != 0) {
    return -EACCES;
  }

  return 0;
}

void RGWGetBucketQuota_ObjStore_BOS::send_response()
{
  RGWQuotaInfo *quota = &s->bucket_info.quota;
  if (quota->max_size == -1 && quota->max_objects == -1){
      op_ret = -CODE_NO_SUCH_BUCKET_QUOTA;
  }
  if (op_ret) {
    set_req_state_err(s, op_ret);
  }
  dump_errno(s);
  end_header(s);

  if (op_ret == 0){
    if (quota->max_size == -2){
      quota->max_size = 0;
    }
    if (quota->max_objects == -2){
      quota->max_objects = 0;
    }
    dump_start(s);
    s->formatter->open_object_section("GetBucketQuotaResult");
    s->formatter->dump_int("maxObjectCount", (int)quota->max_objects);
    if (quota->max_size > 0){
      int64_t maxCapacityMegaBytes = quota->max_size / (1024 *1024);
      s->formatter->dump_int("maxCapacityMegaBytes", (int)maxCapacityMegaBytes);
    }else{
      s->formatter->dump_int("maxCapacityMegaBytes", quota->max_size );
    }
    s->formatter->close_section();
    rgw_flush_formatter_and_reset(s, s->formatter);
  }
}

int RGWDeleteBucketQuota_ObjStore_BOS::verify_permission()
{
  // only the primary user with bucket has permission.
  if (!s->auth.identity->is_owner_of(s->bucket_owner.get_id()) || s->user->subusers.size() != 0) {
    return -EACCES;
  }

  return 0;
}

void RGWDeleteBucketQuota_ObjStore_BOS::send_response()
{
  if (op_ret == 0) {
    op_ret = STATUS_NO_CONTENT;
  }

  set_req_state_err(s, op_ret);
  dump_errno(s);
  end_header(s);
}

int RGWPutUserQuota_ObjStore_BOS::verify_permission()
{
  // only the primary user has permission.
  if (s->user->subusers.size() != 0){
    return -EACCES;
  }

  return 0;
}

int RGWPutUserQuota_ObjStore_BOS::get_params()
{
  char *data = nullptr;
  int len = 0;
  const auto max_size = s->cct->_conf->rgw_max_put_param_size;
  op_ret = rgw_rest_read_all_input(s, &data, &len, max_size, false);
  if (op_ret != 0) {
    ldout(s->cct, 10) << __func__ << " error in request body." << dendl;
    return op_ret;
  }

  JSONParser parser;
  bufferlist in_data = bufferlist::static_from_mem(data, len);
  bool ret = parser.parse(in_data.c_str(), len);
  if (!ret){
    ldout(s->cct, 10) << __func__ << " failed to parse json " << dendl;
    return 0;
  }  

  JSONObj *uidJsonObj = parser.find_obj("uid");
  JSONObj *maxOCJsonObj = parser.find_obj("maxObjectCount");
  JSONObj *maxCMBJsonObj = parser.find_obj("maxCapacityMegaBytes");
  JSONObj *maxBCJsonObj = parser.find_obj("maxBucketCount");
  if (!maxOCJsonObj || !maxCMBJsonObj || !maxBCJsonObj) {
    op_ret = -EINVAL;
    ldout(s->cct, 10) << __func__ << " missing parameter. " << dendl;
    return op_ret;
  }

  try {
    if (!uidJsonObj){
      uid_str = s->user->user_id.id;
    }else{
      JSONDecoder::decode_json("uid", uid_str, &parser);
    }
    JSONDecoder::decode_json("maxObjectCount", max_objects, &parser);
    JSONDecoder::decode_json("maxCapacityMegaBytes", max_size_mb, &parser);  
    JSONDecoder::decode_json("maxBucketCount", max_bucket_count, &parser);
  } catch (JSONDecoder::err& e) {
    ldout(s->cct, 10) << __func__ << " wrong parameter type." << dendl;
    op_ret = -ERR_INAPPROPRIATE_JSON;
    return op_ret;
  }

  return op_ret;
}

int RGWPutUserQuota_ObjStore_BOS::check_quota_params()
{
  if (max_size_mb < -1 || max_objects < -1 || max_bucket_count < -1){
    ldout(s->cct, 10) << __func__ << " wrong parameter value." << dendl;
    return -EINVAL;
  }

  /* The bos api uses 0 to indicate that an unlimited quota has been set, and -1 to remove the quota limit. In fact, both have the same effect.
     In ceph, 0 means no quota. So we replace the 0 with -2 to indicate that the quota was removed. */
  if(max_size_mb == 0){
    max_size_kb = -2;
  }else if (max_size_mb == -1){
    max_size_kb = -1;
  }else{
    max_size_kb = max_size_mb * 1024 * 1024;
  }
  if (max_objects == 0){
    max_objects = -2;
  }
  if (max_bucket_count == -1){
    max_bucket_count = s->cct->_conf->rgw_user_max_buckets;
  }

  return 0;
}

void RGWPutUserQuota_ObjStore_BOS::send_response()
{
  if (op_ret) {
    set_req_state_err(s, op_ret);
  }
  dump_errno(s);
  end_header(s);
}

int RGWGetUserQuota_ObjStore_BOS::verify_permission()
{
  // only the primary user has permission.
  if (s->user->subusers.size() != 0){
    return -EACCES;
  }

  return 0;
}

void RGWGetUserQuota_ObjStore_BOS::send_response()
{
  if (user_info.max_buckets == s->cct->_conf->rgw_user_max_buckets 
       && user_info.user_quota.max_size == -1 
         && user_info.user_quota.max_objects == -1){
       op_ret = -CODE_NO_SUCH_USER_QUOTA;
    }
  if (op_ret) {
    set_req_state_err(s, op_ret);
  }
  dump_errno(s);
  end_header(s);

  if (op_ret == 0){
    if (user_info.user_quota.max_size == -2){
      user_info.user_quota.max_size = 0;
    }
    if (user_info.user_quota.max_objects == -2){
      user_info.user_quota.max_objects = 0;
    }
    if (user_info.max_buckets ==  s->cct->_conf->rgw_user_max_buckets){
      user_info.max_buckets = -1;
    }

    dump_start(s);
    s->formatter->open_object_section("GetUserQuotaResult");  
    s->formatter->dump_int("maxBucketCount", (int)user_info.max_buckets);
    s->formatter->dump_int("maxObjectCount", (int)user_info.user_quota.max_objects);
    if ( user_info.user_quota.max_size > 0){
      int64_t maxCapacityMegaBytes = user_info.user_quota.max_size / (1024 * 1024);
      s->formatter->dump_int("maxCapacityMegaBytes", (int)maxCapacityMegaBytes);
    }else{
      s->formatter->dump_int("maxCapacityMegaBytes", user_info.user_quota.max_size);
    }      
    s->formatter->close_section();
    rgw_flush_formatter_and_reset(s, s->formatter);
  }
}

int RGWDeleteUserQuota_ObjStore_BOS::verify_permission()
{
  // only the primary user has permission.
  if (s->user->subusers.size() != 0){
    return -EACCES;
  }

  return 0;
}

void RGWDeleteUserQuota_ObjStore_BOS::send_response()
{
  if (op_ret == 0) {
    op_ret = STATUS_NO_CONTENT;
  }
  set_req_state_err(s, op_ret);
  dump_errno(s);
  end_header(s);
}

void RGWGetBucketStorageClass_BOS::send_response()
{
  if (op_ret)
    set_req_state_err(s, op_ret);
  dump_errno(s);
  end_header(s, this, CONTENT_TYPE_JSON);
  dump_start(s);

  s->formatter->open_object_section("StorageClass");
  if (s->bucket_info.storage_class.empty()) {
    s->formatter->dump_string("storageClass", "STANDARD");
  } else {
    s->formatter->dump_string("storageClass", s->bucket_info.storage_class);
  }
  s->formatter->close_section(); // end of storage class
  rgw_flush_formatter_and_reset(s, s->formatter);
}

int RGWPutBucketStorageClass_BOS::get_params()
{
  char* data = nullptr;
  int len = 0;
  int r = rgw_rest_read_all_input(s, &data, &len, s->cct->_conf->rgw_max_put_param_size, false);
  if (r < 0) {
    return r;
  }

  auto data_deleter = std::unique_ptr<char, decltype(free)*> {data, free};

  JSONParser parser;
  bool ret = parser.parse(data, len);
  if (!ret) {
    ldout(s->cct, 10) << __func__ << "() ERROR: malformed json error, data: " << data << dendl;
    return -ERR_MALFORMED_JSON;
  }

  JSONObj *jsonObj = parser.find_obj("storageClass");
  if (!jsonObj) {
    ldout(s->cct, 10) << __func__ << "() ERROR: parse storage class error, data: " << data << dendl;
    return -EINVAL;
  }
  s->bucket_info.storage_class = jsonObj->get_data();
  if (s->bucket_info.storage_class.empty()) {
    ldout(s->cct, 10) << __func__ << "() ERROR: storage class is empty." << dendl;
    return -EINVAL;
  }
  std::transform(s->bucket_info.storage_class.begin(), s->bucket_info.storage_class.end(),
                 s->bucket_info.storage_class.begin(), [](const int c) { return std::toupper(c); });
  return r;
}

void RGWPutBucketStorageClass_BOS::send_response()
{
  if (op_ret < 0) {
    set_req_state_err(s, op_ret);
  }
  dump_errno(s);
  end_header(s, NULL);
}

void RGWGetBucketTrash_BOS::send_response()
{
  string trash_dir = s->bucket_info.trash_dir;
  if (trash_dir.empty()) {
    op_ret = -ERR_NO_SUCH_TRASH_DIR;
  }

  if (trash_dir.rfind('/') == trash_dir.size() - 1) {
    // return trash dir trim '/'
    trash_dir = trash_dir.substr(0, trash_dir.size() - 1);
  }

  if (op_ret) {
    set_req_state_err(s, op_ret);
  }
  dump_errno(s);
  end_header(s, this, CONTENT_TYPE_JSON);
  if (op_ret == 0) {
    dump_start(s);

    s->formatter->open_object_section("Trash");
    s->formatter->dump_string("trashDir", trash_dir);
    s->formatter->close_section(); // end of trash
    rgw_flush_formatter_and_reset(s, s->formatter);
  }
}

int RGWPutBucketTrash_BOS::get_params()
{
  char* data = nullptr;
  int len = 0;
  int r = rgw_rest_read_all_input(s, &data, &len, s->cct->_conf->rgw_max_put_param_size, false);
  if (r < 0) {
    return r;
  }

  auto data_deleter = std::unique_ptr<char, decltype(free)*> {data, free};

  JSONParser parser;
  bool ret = parser.parse(data, len);
  if (!ret) {
     ldout(s->cct, 10) << __func__ << "() ERROR: malformed json error, data: " << data << dendl;
     return ret;
  }

  JSONObj *obj = parser.find_obj("trashDir");
  if (obj) {
    trash_dir = obj->get_data();
  }
  return r;
}

void RGWPutBucketTrash_BOS::send_response()
{
  if (op_ret < 0) {
    set_req_state_err(s, op_ret);
  }
  dump_errno(s);
  end_header(s, NULL);
}

void RGWDeleteBucketTrash_BOS::send_response()
{
  int r = op_ret;
  if (!r || r == -ENOENT) {
    r = STATUS_NO_CONTENT;
  }

  set_req_state_err(s, r);
  dump_errno(s);
  end_header(s, NULL);
}

void RGWGetACLs_ObjStore_BOS::send_response()
{
  if (op_ret)
    set_req_state_err(s, op_ret);
  dump_errno(s);
  end_header(s, this, CONTENT_TYPE_JSON);
  dump_start(s);
  if (op_ret < 0)
    return;

  s->formatter->open_object_section("AccessControlPolicy");
  s->formatter->open_object_section("owner");
  string owner_id;
  bos_acl->get_owner().get_id().to_str(owner_id);
  if (!owner_id.empty()) {
    s->formatter->dump_string("id", owner_id);
  } else {
    return;
  }
  s->formatter->close_section(); // end of owner
  s->formatter->open_array_section("accessControlList");

  map<string, ACLGrant> id_to_acl;
  multimap<string, ACLGrant>::iterator iter;

  for (iter = bos_acl->get_acl().get_grant_map().begin(); iter != bos_acl->get_acl().get_grant_map().end(); ++iter) {
    ACLGrant& grant = iter->second;
    ACLPermission perm = grant.get_permission();

    // only show s3 compatible permissions
    if (!(perm.get_permissions() & RGW_PERM_ALL_S3))
      continue;
    string id = "";

    switch (grant.get_type().get_type()) {
    case ACL_TYPE_CANON_USER:
      id = grant.get_id().id;
      break;
    case ACL_TYPE_EMAIL_USER:
      id = grant.get_email();
      break;
    case ACL_TYPE_GROUP:
      if (grant.get_group() == ACL_GROUP_ALL_USERS) {
        id = RGW_URI_ALL_BOS_USERS;
      } else if (grant.get_group() == ACL_GROUP_AUTHENTICATED_USERS) {
        id = RGW_URI_AUTH_BOS_USERS;
      } else {
        ldout(s->cct, 0) << __func__ << " ERROR: group_to_uri failed with group=" << (int)grant.get_group() << dendl;
      }
      break;
    default:
      break;
    }

    if (id.empty()) {
      continue;
    }

    if (id_to_acl.find(id) == id_to_acl.end()) {
      id_to_acl[id] = iter->second;
    } else {
      id_to_acl[id].get_permission().set_permissions(
          id_to_acl[id].get_permission().get_permissions() |
          iter->second.get_permission().get_permissions());
    }
  }

  for (iter = id_to_acl.begin(); iter != id_to_acl.end(); ++iter) {
    s->formatter->open_object_section("one_grant");

    s->formatter->open_array_section("grantee");

    s->formatter->open_object_section("acl_user_id");
    s->formatter->dump_string("id", iter->first);
    s->formatter->close_section(); // acl_user_id

    s->formatter->close_section(); // end of grantee

    std::stringstream ss;
    ACLPermission perm = iter->second.get_permission();
    if ((perm.get_permissions() & RGW_PERM_FULL_CONTROL) == RGW_PERM_FULL_CONTROL) {
      ss << "\"FULL_CONTROL\"" << ", ";
    } else {
      if (perm.get_permissions() & RGW_PERM_READ)
        ss << "\"READ\"" << ", ";
      if (perm.get_permissions() & RGW_PERM_WRITE)
        ss << "\"WRITE\"" << ", ";
      if (perm.get_permissions() & RGW_PERM_READ_ACP)
        ss << "\"READ_ACP\"" << ", ";
      if (perm.get_permissions() & RGW_PERM_WRITE_ACP)
        ss << "\"WRITE_ACP\"" << ", ";
    }
    std::string ss_str = ss.str();

    s->formatter->open_array_section("permission");
    if (ss_str.size() >= 2) {
      s->formatter->write_raw_data(ss_str.substr(0, ss_str.size()-2).c_str());
    }
    s->formatter->close_section(); // end of permission
    s->formatter->close_section(); // end of one_grant
  }

  s->formatter->close_section(); // end of accessControlList
  s->formatter->close_section(); // end of AccessControlPolicy
  rgw_flush_formatter_and_reset(s, s->formatter);
}

void RGWDeleteACLs_ObjStore_BOS::send_response()
{
  int r = op_ret;
  if (!r || r == -ENOENT)
    r = STATUS_NO_CONTENT;
  set_req_state_err(s, r);
  dump_errno(s);
  end_header(s, NULL);
}

void RGWListBucketMultiparts_ObjStore_BOS::send_response()
{
  if (op_ret < 0)
    set_req_state_err(s, op_ret);
  dump_errno(s);

  end_header(s, this, CONTENT_TYPE_JSON);
  dump_start(s);
  if (op_ret < 0)
    return;

  s->formatter->open_object_section("ListMultipartUploadsResult");
  s->formatter->dump_string("bucket", s->bucket_name);
  s->formatter->dump_string("prefix", prefix);
  string& key_marker = marker.get_key();
  if (!key_marker.empty()) {
    s->formatter->dump_string("keyMarker", key_marker);
  } else {
    s->formatter->dump_string("keyMarker", "");
  }
  string next_key = next_marker.mp.get_key();
  if (!next_key.empty())
    s->formatter->dump_string("nextKeyMarker", next_key);
  s->formatter->dump_int("maxUploads", max_uploads);
  if (!delimiter.empty())
    s->formatter->dump_string("delimiter", delimiter);
  s->formatter->dump_bool("isTruncated", (is_truncated ? true : false));

  if (op_ret >= 0) {
    s->formatter->open_array_section("uploads");
    vector<RGWMultipartUploadEntry>::iterator iter;
    for (iter = uploads.begin(); iter != uploads.end(); ++iter) {
      RGWMPObj& mp = iter->mp;
      if (mp.get_key() == key_marker) {
        continue;
      }
      s->formatter->open_object_section("Upload");
      s->formatter->dump_string("key", mp.get_key());
      s->formatter->dump_string("uploadId", mp.get_upload_id());

      dump_owner(s, s->bucket_owner.get_id(), s->bucket_owner.get_display_name());

      s->formatter->dump_string("storageClass",
          rgw_placement_rule::get_canonical_storage_class(iter->obj.meta.storage_class));
      dump_time(s, "initiated", &iter->obj.meta.mtime);
      s->formatter->close_section(); // close section "Upload"
    }
    s->formatter->close_section(); // close section "uploads"
    if (!common_prefixes.empty()) {
      s->formatter->open_array_section("commonPrefixes");
      map<string, bool>::iterator pref_iter;
      for (pref_iter = common_prefixes.begin();
          pref_iter != common_prefixes.end(); ++pref_iter) {
        s->formatter->dump_string("prefix", pref_iter->first);
      }
      s->formatter->close_section();
    }
  }
  s->formatter->close_section();
  rgw_flush_formatter_and_reset(s, s->formatter);
}

void RGWCopyObj_ObjStore_BOS::send_response()
{
  if (! sent_header) {
    if (op_ret)
      set_req_state_err(s, op_ret);
    dump_errno(s);
    end_header(s, this, CONTENT_TYPE_JSON);
    dump_start(s);
    sent_header = true;
    rgw_flush_formatter(s, s->formatter);
  }

  if (op_ret == 0) {
    s->formatter->open_object_section("CopyObjectResult");
    dump_time(s, "lastModified", &mtime);
    if (! etag.empty()) {
      s->formatter->dump_string("eTag", std::move(etag));
    }
    s->formatter->close_section();
    rgw_flush_formatter_and_reset(s, s->formatter);
  }
}

void RGWInitMultipart_ObjStore_BOS::send_response()
{
  if (op_ret)
    set_req_state_err(s, op_ret);
  dump_errno(s);
  for (auto &it : crypt_http_responses) {
     dump_header(s, it.first, it.second);
  }
  end_header(s, this, CONTENT_TYPE_JSON);
  if (op_ret == 0) {
    dump_start(s);
    s->formatter->open_object_section("InitiateMultipartUploadResult");
    s->formatter->dump_string("bucket", s->bucket_name);
    s->formatter->dump_string("key", s->object.name);
    s->formatter->dump_string("uploadId", upload_id);
    s->formatter->close_section();
    rgw_flush_formatter_and_reset(s, s->formatter);
  }
}

void RGWListMultipart_ObjStore_BOS::send_response()
{
  if (op_ret)
    set_req_state_err(s, op_ret);
  dump_errno(s);
  end_header(s, this, CONTENT_TYPE_JSON);

  if (op_ret == 0) {
    dump_start(s);
    s->formatter->open_object_section("ListPartsResult");
    map<uint32_t, RGWUploadPartInfo>::iterator iter;
    map<uint32_t, RGWUploadPartInfo>::reverse_iterator test_iter;
    int cur_max = 0;

    iter = parts.begin();
    test_iter = parts.rbegin();
    if (test_iter != parts.rend()) {
      cur_max = test_iter->first;
    }

    s->formatter->dump_string("bucket", s->bucket_name);
    s->formatter->dump_string("key", s->object.name);
    s->formatter->dump_string("uploadId", upload_id);
    s->formatter->dump_string("storageClass",
        rgw_placement_rule::get_canonical_storage_class(storage_class));
    s->formatter->dump_int("partNumberMarker", marker);
    s->formatter->dump_int("nextPartNumberMarker", cur_max);
    s->formatter->dump_int("maxParts", max_parts);
    s->formatter->dump_bool("isTruncated", (truncated ? true : false));
    s->formatter->dump_string("initiated", "");

    ACLOwner& owner = policy.get_owner();
    dump_owner(s, owner.get_id(), owner.get_display_name());

    s->formatter->open_array_section("parts");
    for (; iter != parts.end(); ++iter) {
      RGWUploadPartInfo& info = iter->second;

      s->formatter->open_object_section("part");

      dump_time(s, "lastModified", &info.modified);

      s->formatter->dump_unsigned("partNumber", info.num);
      s->formatter->dump_format("eTag", "%s", info.etag.c_str());
      s->formatter->dump_unsigned("size", info.accounted_size);
      s->formatter->close_section();
    }
    s->formatter->close_section();
    s->formatter->close_section();
    rgw_flush_formatter_and_reset(s, s->formatter);
  }
}

void RGWCompleteMultipart_ObjStore_BOS::send_response()
{
  if (op_ret)
    set_req_state_err(s, op_ret);
  dump_errno(s);
  end_header(s, this, CONTENT_TYPE_JSON);
  if (op_ret == 0) {
    dump_start(s);
    s->formatter->open_object_section("CompleteMultipartUploadResult");
    std::string base_uri = compute_domain_uri(s);
    if (!s->bucket_tenant.empty()) {
      s->formatter->dump_format("location", "%s/%s:%s/%s",
        base_uri.c_str(),
        s->bucket_tenant.c_str(),
        s->bucket_name.c_str(),
        s->object.name.c_str()
      );
    } else {
      s->formatter->dump_format("location", "%s/%s/%s",
        base_uri.c_str(),
        s->bucket_name.c_str(),
        s->object.name.c_str()
      );
    }
    s->formatter->dump_string("bucket", s->bucket_name);
    s->formatter->dump_string("key", s->object.name);
    s->formatter->dump_string("eTag", etag);
    s->formatter->close_section();
    rgw_flush_formatter_and_reset(s, s->formatter);
  }
}

int RGWInitBucketObjectLock_ObjStore_BOS::get_params()
{
  char* data = nullptr;
  int len = 0;
  int r = rgw_rest_read_all_input(s, &data, &len, s->cct->_conf->rgw_max_put_param_size, false);
  if (r < 0) {
    return r;
  }

  auto data_deleter = std::unique_ptr<char, decltype(free)*> {data, free};

  JSONParser parser;
  bool ret = parser.parse(data, len);
  if (!ret) {
    ldout(s->cct, 10) << __func__ << "() ERROR: malformed json error, data: " << data << dendl;
    return -ERR_MALFORMED_JSON;
  }

  JSONObj *jsonObj = parser.find_obj("retentionDays");
  if (!jsonObj) {
    ldout(s->cct, 10) << __func__ << "() ERROR: parse retentionDays error, data: " << data << dendl;
    return -EINVAL;
  }
  std::string retention_days_str = jsonObj->get_data();
  if (retention_days_str.empty()) {
    ldout(s->cct, 10) << __func__ << "() ERROR: retentionDays is empty." << dendl;
    return -EINVAL;
  }

  std::string err;
  retention_days = strict_strtoll(retention_days_str.c_str(), 10, &err);
  if (!err.empty()) {
    ldout(s->cct, 10) << __func__ << "() ERROR: retentionDays is not int." << dendl;
    return -EINVAL;
  }

  return r;
}

void RGWInitBucketObjectLock_ObjStore_BOS::send_response()
{
  if (op_ret < 0) {
    set_req_state_err(s, op_ret);
  }
  dump_errno(s);
  end_header(s, NULL);
}

void RGWGetBucketObjectLock_ObjStore_BOS::send_response()
{
  if (op_ret)
    set_req_state_err(s, op_ret);
  dump_errno(s);
  end_header(s, this, CONTENT_TYPE_JSON);
  if (op_ret == 0) {
    dump_start(s);

    time_t expiration_date = create_date + s->cct->_conf->rgw_bos_worm_expiration_time;
    s->formatter->open_object_section("objectLock");
    s->formatter->dump_string("lockStatus", lock_status);
    s->formatter->dump_int("createDate", create_date);
    s->formatter->dump_int("expirationDate", expiration_date);
    s->formatter->dump_int("retentionDays", retention_days);
    s->formatter->close_section();
    rgw_flush_formatter_and_reset(s, s->formatter);
  }
}

void RGWDeleteBucketObjectLock_ObjStore_BOS::send_response()
{
  if (op_ret == 0) {
    op_ret = STATUS_NO_CONTENT;
  }
  set_req_state_err(s, op_ret);
  dump_errno(s);
  end_header(s);
}

void RGWCompleteBucketObjectLock_ObjStore_BOS::send_response()
{
  if (op_ret < 0) {
    set_req_state_err(s, op_ret);
  }
  dump_errno(s);
  end_header(s, NULL);
}

int RGWExtendBucketObjectLock_ObjStore_BOS::get_params()
{
  char* data = nullptr;
  int len = 0;
  int r = rgw_rest_read_all_input(s, &data, &len, s->cct->_conf->rgw_max_put_param_size, false);
  if (r < 0) {
    return r;
  }

  auto data_deleter = std::unique_ptr<char, decltype(free)*> {data, free};

  JSONParser parser;
  bool ret = parser.parse(data, len);
  if (!ret) {
    ldout(s->cct, 10) << __func__ << "() ERROR: malformed json error, data: " << data << dendl;
    return -ERR_MALFORMED_JSON;
  }

  JSONObj *jsonObj = parser.find_obj("extendRetentionDays");
  if (!jsonObj) {
    ldout(s->cct, 10) << __func__ << "() ERROR: parse extendRetentionDays error, data: " << data << dendl;
    return -EINVAL;
  }
  std::string extend_retention_days_str = jsonObj->get_data();
  if (extend_retention_days_str.empty()) {
    ldout(s->cct, 10) << __func__ << "() ERROR: extendRetentionDays is empty." << dendl;
    return -EINVAL;
  }

  std::string err;
  extend_retention_days = strict_strtoll(extend_retention_days_str.c_str(), 10, &err);
  if (!err.empty()) {
    ldout(s->cct, 10) << __func__ << "() ERROR: extendRetentionDays is not int." << dendl;
    return -EINVAL;
  }

  return r;

}

void RGWExtendBucketObjectLock_ObjStore_BOS::send_response()
{
  if (op_ret < 0) {
    set_req_state_err(s, op_ret);
  }
  dump_errno(s);
  end_header(s, NULL);
}

RGWOp *RGWHandler_REST_Service_BOS::op_put()
{
  if (is_userquota_op()){
    return new RGWPutUserQuota_ObjStore_BOS;
  }
  return new RGWPutUserQuota_ObjStore_BOS;
}

RGWOp *RGWHandler_REST_Service_BOS::op_delete()
{
  if (is_userquota_op()){
    return new RGWDeleteUserQuota_ObjStore_BOS;
  }
  return new RGWDeleteUserQuota_ObjStore_BOS;
}

RGWOp *RGWHandler_REST_Service_BOS::op_get()
{
  if (is_userquota_op()){
    return new RGWGetUserQuota_ObjStore_BOS;
  }
  return new RGWListBuckets_ObjStore_BOS;
}

RGWOp *RGWHandler_REST_Service_BOS::op_head()
{
  return new RGWListBuckets_ObjStore_BOS;
}

RGWOp *RGWHandler_REST_Service_BOS::op_post()
{
  if (s->info.args.exists("Action")) {
    string action = s->info.args.get("Action");
    if (action.compare("CreateRole") == 0)
      return new RGWCreateRole;
    if (action.compare("DeleteRole") == 0)
      return new RGWDeleteRole;
    if (action.compare("GetRole") == 0)
      return new RGWGetRole;
    if (action.compare("UpdateAssumeRolePolicy") == 0)
      return new RGWModifyRole;
    if (action.compare("ListRoles") == 0)
      return new RGWListRoles;
    if (action.compare("PutRolePolicy") == 0)
      return new RGWPutRolePolicy;
    if (action.compare("GetRolePolicy") == 0)
      return new RGWGetRolePolicy;
    if (action.compare("ListRolePolicies") == 0)
      return new RGWListRolePolicies;
    if (action.compare("DeleteRolePolicy") == 0)
      return new RGWDeleteRolePolicy;
  }
  if (s->info.args.exists("control")) {
    string control = s->info.args.get("control");
    if (control.compare("ban") == 0)
      return new RGWBanControl;
    if (control.compare("unban") == 0)
      return new RGWUnBanControl;
  }
  return NULL;
}

RGWOp *RGWHandler_REST_Bucket_BOS::get_obj_op(bool get_data)
{
  // Non-website mode
  if (get_data) {
    return new RGWListBucket_ObjStore_BOS;
  } else {
    return new RGWStatBucket_ObjStore_S3;
  }
}

RGWOp *RGWHandler_REST_Bucket_BOS::op_get()
{
  if (s->info.args.sub_resource_exists("location"))
    return new RGWGetBucketLocation_ObjStore_S3;

  if (s->info.args.sub_resource_exists("versioning"))
    return new RGWGetBucketVersioning_ObjStore_S3;

  if (s->info.args.sub_resource_exists("website")) {
    if (!s->cct->_conf->rgw_enable_static_website) {
      return NULL;
    }
    return new RGWGetBucketWebsite_ObjStore_BOS;
  }

  if (s->info.args.exists("mdsearch")) {
    return new RGWGetBucketMetaSearch_ObjStore_S3;
  }

  if (s->info.args.exists("mirroring")) {
    return new RGWGetBucketMirroring_ObjStore_S3;
  }

  if (s->info.args.exists("style")) {
    return new RGWGetImageStyle_ObjStore_S3;
  }
  if (s->info.args.exists("styles")) {
    return new RGWListImageStyle_ObjStore_S3;
  }

  if (s->info.args.exists("copyrightProtection")) {
    return new RGWGetImageProtection_ObjStore_S3;
  }

  if (is_acl_op()) {
    return new RGWGetBucketPolicy_ObjStore_BOS;
  } else if (is_cors_op()) {
    return new RGWGetCORS_ObjStore_S3;
  } else if (is_request_payment_op()) {
    return new RGWGetRequestPayment_ObjStore_S3;
  } else if (s->info.args.exists("uploads")) {
    return new RGWListBucketMultiparts_ObjStore_BOS;
  } else if (is_lc_op()) {
    return new RGWGetLC_ObjStore_S3;
  } else if (is_policy_op()) {
    return new RGWGetBucketPolicy;
  } else if (is_notification_op()) {
    return new RGWGetBucketNotification_ObjStore_S3;
  } else if (is_logging_op()) {
    return new RGWGetBucketLogging_S3;
  } else if (is_encryption_op()) {
    return new RGWGetBucketEncryption_ObjStore_S3;
  } else if (is_storage_class_op()) {
    return new RGWGetBucketStorageClass_BOS;
  } else if (is_quota_op()){
    return new RGWGetBucketQuota_ObjStore_BOS;
  } else if (is_object_lock_op()) {
    return new RGWGetBucketObjectLock_ObjStore_BOS;
  } else if (is_trash_op()) {
    return new RGWGetBucketTrash_BOS;
  }
  return get_obj_op(true);
}

RGWOp *RGWHandler_REST_Bucket_BOS::op_head()
{
  if (is_acl_op()) {
    return new RGWGetACLs_ObjStore_BOS;
  } else if (s->info.args.exists("uploads")) {
    return new RGWListBucketMultiparts_ObjStore_S3;
  }
  return get_obj_op(false);
}

RGWOp *RGWHandler_REST_Bucket_BOS::op_put()
{
  if (s->info.args.sub_resource_exists("website")) {
    if (!s->cct->_conf->rgw_enable_static_website) {
      return NULL;
    }
    return new RGWSetBucketWebsite_ObjStore_BOS;
  }
  if (s->info.args.sub_resource_exists("style")) {
    return new RGWPutImageStyle_ObjStore_S3;
  }
  if (s->info.args.sub_resource_exists("copyrightProtection")) {
    return new RGWPutImageProtection_ObjStore_S3;
  }
  if (s->info.args.exists("mirroring")) {
    return new RGWPutBucketMirroring_ObjStore_S3;
  }
  if (is_acl_op()) {
    return new RGWPutBucketPolicy_ObjStore_BOS;
  } else if (is_cors_op()) {
    return new RGWPutCORS_ObjStore_S3;
  } else if (is_request_payment_op()) {
    return new RGWSetRequestPayment_ObjStore_S3;
  } else if (is_lc_op()) {
    return new RGWPutLC_ObjStore_S3;
  } else if (is_policy_op()) {
    return new RGWPutBucketPolicy;
  } else if (is_notification_op()) {
    return new RGWPutBucketNotification_ObjStore_S3;
  } else if (is_logging_op()) {
    return new RGWPutBucketLogging_S3;
  } else if (is_encryption_op()) {
    return new RGWPutBucketEncryption_ObjStore_S3;
  } else if (is_storage_class_op()) {
    return new RGWPutBucketStorageClass_BOS;
  } else if (is_quota_op()) {
    return new RGWPutBucketQuota_ObjStore_BOS;
  } else if (is_trash_op()) {
    return new RGWPutBucketTrash_BOS;
  }
  return new RGWCreateBucket_ObjStore_S3;
}

RGWOp *RGWHandler_REST_Bucket_BOS::op_delete()
{
  // TODO: CORS, LC, Policy Delete by bos
  if (is_cors_op()) {
    return new RGWDeleteCORS_ObjStore_S3;
  } else if (is_lc_op()) {
    return new RGWDeleteLC_ObjStore_S3;
  } else if (is_policy_op()) {
    return new RGWDeleteBucketPolicy;
  } else if(is_notification_op()) {
    return new RGWDeleteBucketNotification_ObjStore_S3;
  } else if (is_logging_op()) {
    return new RGWDeleteBucketLogging_S3;
  } else if (is_encryption_op()) {
    return new RGWDeleteBucketEncryption_ObjStore_S3;
  } else if (is_quota_op()){
    return new RGWDeleteBucketQuota_ObjStore_BOS;
  } else if (is_object_lock_op()) {
    return new RGWDeleteBucketObjectLock_ObjStore_BOS;
  } else if (is_trash_op()) {
    return new RGWDeleteBucketTrash_BOS;
  }
  if (s->info.args.sub_resource_exists("style")) {
    return new RGWDeleteImageStyle_ObjStore_S3;
  }
  if (s->info.args.sub_resource_exists("copyrightProtection")) {
    return new RGWDeleteImageProtection_ObjStore_S3;
  }
  if (s->info.args.sub_resource_exists("website")) {
    if (!s->cct->_conf->rgw_enable_static_website) {
      return NULL;
    }
    return new RGWDeleteBucketWebsite_ObjStore_BOS;
  }

  if (s->info.args.exists("mirroring")) {
    return new RGWDeleteBucketMirroring_ObjStore_S3;
  }

  // using s3 api as bos
  return new RGWDeleteBucket_ObjStore_S3;
}

RGWOp *RGWHandler_REST_Bucket_BOS::op_post()
{
  if (s->info.args.exists("delete")) {
    return new RGWDeleteMultiObj_ObjStore_S3;
  }
  if (s->info.args.exists("mdsearch")) {
    return new RGWConfigBucketMetaSearch_ObjStore_S3;
  } else if (is_object_lock_op()) {
    return new RGWInitBucketObjectLock_ObjStore_BOS;
  } else if (is_complete_object_lock_op()) {
    return new RGWCompleteBucketObjectLock_ObjStore_BOS;
  } else if (is_extend_object_lock_op()) {
    return new RGWExtendBucketObjectLock_ObjStore_BOS;
  }

  return new RGWPostObj_ObjStore_S3;
}

RGWOp *RGWHandler_REST_Bucket_BOS::op_options()
{
  return new RGWOptionsCORS_ObjStore_S3;
}

RGWOp *RGWHandler_REST_Obj_BOS::get_obj_op(bool get_data)
{
  if (is_acl_op()) {
    return new RGWGetACLs_ObjStore_BOS;
  }
  RGWGetObj_ObjStore_S3 *get_obj_op = new RGWGetObj_ObjStore_S3;
  get_obj_op->set_get_data(get_data);
  return get_obj_op;
}

RGWOp *RGWHandler_REST_Obj_BOS::op_get()
{
  if (is_acl_op()) {
    return new RGWGetACLs_ObjStore_BOS;
  } else if (s->info.args.exists("uploadId")) {
    return new RGWListMultipart_ObjStore_BOS;
  } else if (s->info.args.exists("layout")) {
    return new RGWGetObjLayout_ObjStore_S3;
  } else if (is_tagging_op()) {
    return new RGWGetObjTags_ObjStore_S3;
  } else if (is_symlink_op()) {
    return new RGWGetSymlink_ObjStore_S3;
  }
  return get_obj_op(true);
}

RGWOp *RGWHandler_REST_Obj_BOS::op_head()
{
  if (is_acl_op()) {
    return new RGWGetACLs_ObjStore_BOS;
  } else if (s->info.args.exists("uploadId")) {
    return new RGWListMultipart_ObjStore_BOS;
  }
  return get_obj_op(false);
}

RGWOp *RGWHandler_REST_Obj_BOS::op_put()
{
  if (is_acl_op()) {
    return new RGWPutACLs_ObjStore_S3;
  } else if (is_tagging_op()) {
    return new RGWPutObjTags_ObjStore_S3;
  } else if (is_symlink_op()) {
    return new RGWPutSymlink_ObjStore_S3;
  }

  if (s->info.env->exists("HTTP_X_BCE_RENAME_KEY")) {
    return new RGWRenameObj_ObjStore_S3;
  }

  if (s->init_state.src_bucket.empty())
    return new RGWPutObj_ObjStore_S3;
  else
    return new RGWCopyObj_ObjStore_BOS;
}

RGWOp *RGWHandler_REST_Obj_BOS::op_delete()
{
  if (is_tagging_op()) {
    return new RGWDeleteObjTags_ObjStore_S3;
  } else if (is_acl_op()) {
    return new RGWDeleteACLs_ObjStore_BOS;
  }
  string upload_id = s->info.args.get("uploadId");

  if (upload_id.empty())
    return new RGWDeleteObj_ObjStore_S3;
  else
    return new RGWAbortMultipart_ObjStore_S3;
}

RGWOp *RGWHandler_REST_Obj_BOS::op_post()
{
  if (s->info.args.exists("uploadId"))
    return new RGWCompleteMultipart_ObjStore_BOS;

  if (s->info.args.exists("uploads"))
    return new RGWInitMultipart_ObjStore_BOS;

  if (s->info.env->exists("HTTP_X_BCE_RENAME_KEY")) {
    return new RGWRenameObj_ObjStore_S3;
  }

  if (!s->info.args.exists("Content-Type") || s->info.args.get("Content-Type") != "multipart/form-data") {
     return new RGWPutObj_ObjStore_S3;
  }

  return new RGWPostObj_ObjStore_S3;
}

RGWOp *RGWHandler_REST_Obj_BOS::op_options()
{
  return new RGWOptionsCORS_ObjStore_S3;
}

int RGWHandler_REST_BOS::postauth_init()
{
  struct req_init_state *t = &s->init_state;
  bool relaxed_names = s->cct->_conf->rgw_relaxed_s3_bucket_names;
  rgw_parse_url_bucket(t->url_bucket, s->user->user_id.tenant,
            s->bucket_tenant, s->bucket_name);

  dout(10) << "s->object=" << (!s->object.empty() ? s->object : rgw_obj_key("<NULL>"sv))
           << " s->bucket=" << rgw_make_bucket_entry_name(s->bucket_tenant, s->bucket_name) << dendl;

  int ret = rgw_validate_tenant_name(s->bucket_tenant);
  if (ret)
    return ret;
  if (!s->bucket_name.empty()) {
    if (s->cct->_conf->rgw_use_bos_bucket_names) {
      ret = valid_bos_bucket_name(s->bucket_name);
    } else {
      ret = valid_s3_bucket_name(s->bucket_name, relaxed_names);
    }
    if (ret)
      return ret;
    ret = validate_object_name(s->object.name);
    if (ret)
      return ret;
  }

  if (!t->src_bucket.empty()) {
    rgw_parse_url_bucket(t->src_bucket, s->user->user_id.tenant,
      s->src_tenant_name, s->src_bucket_name);
    ret = rgw_validate_tenant_name(s->src_tenant_name);
    if (ret)
      return ret;
    ret = valid_s3_bucket_name(s->src_bucket_name, relaxed_names);
    if (ret)
      return ret;
  }

  return 0;
}

int RGWHandler_REST_BOS::init(RGWRados *store, struct req_state *s,
                             rgw::io::BasicClient *cio)
{
  s->dialect = "bos";

  int ret = rgw_validate_tenant_name(s->bucket_tenant);
  if (ret)
    return ret;
  bool relaxed_names = s->cct->_conf->rgw_relaxed_s3_bucket_names;
  if (!s->bucket_name.empty()) {
    ret = valid_s3_bucket_name(s->bucket_name, relaxed_names);
    if (ret)
      return ret;
    ret = validate_object_name(s->object.name);
    if (ret)
      return ret;
  }

  const char *cacl = s->info.env->get("HTTP_X_BCE_ACL");
  if (cacl)
    s->canned_acl = cacl;

  s->has_acl_header = s->info.env->exists("HTTP_X_BCE_GRANT_READ") ||
                      s->info.env->exists("HTTP_X_BCE_GRANT_FULL_CONTROL");

  const char *copy_source = s->info.env->get("HTTP_X_BCE_COPY_SOURCE");
  if (copy_source &&
      (! s->info.env->get("HTTP_X_BCE_COPY_SOURCE_RANGE")) &&
      (! s->info.args.exists("uploadId"))) {

    ret = RGWCopyObj::parse_copy_location(url_decode(copy_source),
                                          s->init_state.src_bucket,
                                          s->src_object);
    if (!ret) {
      ldout(s->cct, 0) << __func__ << " failed to parse copy location" << dendl;
      return -EINVAL; // XXX why not -ERR_INVALID_BUCKET_NAME or -ERR_BAD_URL?
    }
  }

  const char *sc = s->info.env->get("HTTP_X_BCE_STORAGE_CLASS");
  if (sc) {
    s->info.storage_class = sc;
  }

  return RGWHandler_REST::init(store, s, cio);
}

int RGWHandler_REST_BOS::init_from_header(struct req_state* s,
          int default_formatter,
          bool configurable_format)
{
  string req;
  string first;

  const char *req_name = s->relative_uri.c_str();

  /* must be called after the args parsing */
  int ret = allocate_formatter(s, default_formatter, configurable_format);
  if (ret < 0)
    return ret;

  if (*req_name != '/')
    return 0;

  req_name++;

  if (!*req_name)
    return 0;

  req = req_name;
  auto pos = req.find("v1");

  ldout(s->cct, 30) << __func__ << " origin url:" << req << dendl;

  if (pos == 0) {
    if (req.length() <= 3) {
      req = "";
    } else {
      req = req.substr(3);
    }
  } else {
    pos = req.find("json-api/v1");
    if (pos == 0) {
      if (req.length() <= 12) {
        req = "";
      } else {
        req = req.substr(12);
      }
    } else {
      pos = req.find("json-api");
      if (pos == 0) {
        if (req.length() <= 9) {
          req = "";
        } else {
          req = req.substr(9);
        }
      }
    }
  }

  pos = string::npos;

  pos = req.find('/');
  if (pos != string::npos) {
    first = req.substr(0, pos);
  } else {
    first = req;
  }

  if (s->init_state.url_bucket.empty()) {
    // Save bucket to tide us over until token is parsed.
    s->init_state.url_bucket = first;
    if (pos != string::npos) {
      string encoded_obj_str = req.substr(pos+1);
      s->object = rgw_obj_key(encoded_obj_str, s->info.args.get("versionId"));
    }
  } else {
    s->object = rgw_obj_key(req_name, s->info.args.get("versionId"));
  }
  return 0;
}

RGWHandler_REST* RGWRESTMgr_BOS::get_handler(struct req_state* const s,
                                            const rgw::auth::StrategyRegistry& auth_registry,
                                            const std::string& frontend_prefix)
{
  int ret = RGWHandler_REST_BOS::init_from_header(s, RGW_FORMAT_JSON, true);
  if (ret < 0)
    return NULL;

  RGWHandler_REST* handler = nullptr;
  if (s->init_state.url_bucket.empty()) {
      handler = new RGWHandler_REST_Service_BOS(auth_registry);
  } else if (s->object.empty()) {
      handler = new RGWHandler_REST_Bucket_BOS(auth_registry);
  } else {
      handler = new RGWHandler_REST_Obj_BOS(auth_registry);
  }

  ldout(s->cct, 20) << __func__ << " handler=" << typeid(*handler).name() << dendl;
  return handler;
}

void RGWMultiJSONParser::decode_json(const char *data, int len)
{
  JSONParser parser;

  bool ret = parser.parse(data, len);
  if (!ret) {
    err_code = -ERR_MALFORMED_JSON;
    return;
  }
  JSONDecoder::decode_json("parts", multi_parts, &parser, true);
  return;
}

void RGWLifecycleJSONParser::decode_json(const char *data, int len)
{
  if (len <= 14) {
    err_code = -EINVAL;
    return;
  }
  JSONParser parser;
  bool ret = parser.parse(data, len);
  if (!ret) {
    err_code = -ERR_MALFORMED_JSON;
    return;
  }
  JSONDecoder::decode_json("rule", lifecycle_rules, &parser, true);

  return;
}

void RGWLifecycleJSONParser::dump_xml(Formatter *f, RGWLifecycleConfiguration_S3 *config, int& op_ret) {
  for (auto bos_rule : lifecycle_rules) {
    LCRule rule;
    string aws_time;
    bool prefix_exit = false;
    string pre_id;
    bool is_days = false;
    if (bos_rule.resource.empty()) {
      err_code = -EINVAL;
      return;
    }
    string prefix = bos_rule.resource[0];

    auto pos = prefix.find("/");
    if (pos != string::npos && pos + 1 < prefix.length()) {
      prefix = prefix.substr(pos+1);
    }
    if (prefix.find("*") != string::npos) {
      prefix = prefix.erase(prefix.find("*"));
    }
    for (auto pre_rule : config->get_rule_map()) {
      if (pre_rule.second.get_filter().get_prefix() == prefix) {
        prefix_exit = true;
        pre_id = pre_rule.first;
        break;
      }
    }

    rule.set_id(bos_rule.id);
    LCFilter_S3 filter;
    filter.set_prefix(prefix);
    rule.set_filter(filter);
    string status = bos_rule.status == "enabled" ? "Enabled" : "Disabled";
    rule.set_status(status);
    string days_prefix = "$(lastModified)+P";
    if (bos_rule.cond.bos_time.dateGreaterThan.find(days_prefix) == std::string::npos) {
      aws_time = bos_rule.cond.bos_time.dateGreaterThan;
    } else {
      is_days = true;
      aws_time = bos_rule.cond.bos_time.dateGreaterThan;
      aws_time.erase(aws_time.find(days_prefix), days_prefix.size());
      if (aws_time.size() >= 2) {
        aws_time.erase(aws_time.size()-1, 1);
      }
    }
    if (bos_rule.act.name == "Transition") {
      LCTransition_S3 transition;
      if (is_days) {
        transition.set_days(aws_time);
      } else {
        transition.set_date(aws_time);
      }
      if (bos_rule.act.storage_class == "COLD") {
        bos_rule.act.storage_class = "GLACIER";
      }
      transition.set_storage_class(bos_rule.act.storage_class);

      if (prefix_exit) {
        config->get_rule_map().find(pre_id)->second.add_transition(transition);
        continue;
      } else {
        rule.add_transition(transition);
      }

    } else if (bos_rule.act.name == "DeleteObject") {
      LCExpiration_S3 expiration;
      if (is_days) {
        expiration.set_days(aws_time);
      } else {
        expiration.set_date(aws_time);
      }

      if (prefix_exit) {
        config->get_rule_map().find(pre_id)->second.set_expiration(expiration);
        continue;
      } else {
        rule.set_expiration(expiration);
      }

    } else if (bos_rule.act.name == "AbortMultipartUpload") {
      LCMPExpiration_S3 mp_expiration;
      if (is_days) {
        mp_expiration.set_days(aws_time);
      } else {
        op_ret = -ERR_MALFORMED_JSON;
        return;
      }

      if (prefix_exit) {
        config->get_rule_map().find(pre_id)->second.set_mp_expiration(mp_expiration);
        continue;
      } else {
        rule.set_mp_expiration(mp_expiration);
      }
    } else {
      op_ret = -EINVAL;
      return;
    }

    config->add_rule(rule);
  }

  config->dump_xml(f);
  return;
}

void RGWLifecycleJSONParser::dump_json(Formatter *f, RGWLifecycleConfiguration_S3 *config, string& bucket_name) {
  for (auto rule : config->get_rule_map()) {
    lifecycle_rule bos_rule;
    LCRule aws_rule = rule.second;
    bos_rule.id = aws_rule.get_id();
    string status = aws_rule.get_status() == "Enabled" ? "enabled" : "disabled";
    bos_rule.status = status;
    std::ostringstream oss;
    oss << bucket_name << "/";
    oss << aws_rule.get_filter().get_prefix() << "*";
    bos_rule.resource.push_back(oss.str());
    string aws_time;

    if (aws_rule.get_expiration().has_days()) {
      bos_rule.act.name = "DeleteObject";
      aws_time = "$(lastModified)+P" + std::to_string(aws_rule.get_expiration().get_days()) + "D";
      bos_rule.cond.bos_time.dateGreaterThan = aws_time;
      lifecycle_rules.push_back(bos_rule);
    } else if (aws_rule.get_expiration().has_date()) {
      bos_rule.act.name  = "DeleteObject";
      aws_time = aws_rule.get_expiration().get_date();
      bos_rule.cond.bos_time.dateGreaterThan = aws_time;
      lifecycle_rules.push_back(bos_rule);
    }

    if (aws_rule.get_mp_expiration().has_days()) {
      bos_rule.act.name = "AbortMultipartUpload";
      aws_time = "$(lastModified)+P" + std::to_string(aws_rule.get_mp_expiration().get_days()) + "D";
      bos_rule.cond.bos_time.dateGreaterThan = aws_time;
      lifecycle_rules.push_back(bos_rule);
    } else if (aws_rule.get_mp_expiration().has_date()) {
      bos_rule.act.name  = "AbortMultipartUpload";
      aws_time = aws_rule.get_mp_expiration().get_date();
      bos_rule.cond.bos_time.dateGreaterThan = aws_time;
      lifecycle_rules.push_back(bos_rule);
    }

    for (auto tran : aws_rule.get_transitions()) {
      bos_rule.act.name = "Transition";
      bos_rule.act.storage_class = tran.second.get_storage_class();
      if (tran.second.has_days()) {
        aws_time = "$(lastModified)+P" + std::to_string(tran.second.get_days()) + "D";
      } else {
        aws_time = tran.second.get_date();
      }
      bos_rule.cond.bos_time.dateGreaterThan = aws_time;
      lifecycle_rules.push_back(bos_rule);
    }
  }
  return;
}

void RGWMultiDeleteObjParser::decode_json(const char *data, int len)
{
  JSONParser parser;
  bool ret = parser.parse(data, len);
  if (!ret) {
    err_code = -ERR_MALFORMED_JSON;
    return;
  }
  JSONDecoder::decode_json("objects", objects, &parser, true);
  return;
}

void RGWMultiDeleteObjParser::dump_xml(Formatter *f) const
{
  for (auto object : objects) {
    encode_xml("Object", object, f);
  }
  encode_xml("Quiet", "false", f);
}

void RGWACLsParser::set_default_grant(string& owner_id) {
  grant s3_grant;
  s3_grant.gran.id = s3_owner.id;
  s3_grant.permission = "FULL_CONTROL";
  s3_access_control_list.access_control_list.push_back(s3_grant);
}

void RGWACLsParser::decode_json(const char *data, int len)
{
  if (len <= 2) {
    err_code = -ERR_MALFORMED_JSON;
    return;
  }
  JSONParser parser;
  bool ret = parser.parse(data, len);
  if (!ret) {
    err_code = -ERR_MALFORMED_JSON;
    return;
  }

  JSONDecoder::decode_json("accessControlList", bos_access_control_list, &parser, true);
  if (bos_access_control_list.size() == 0) {
    dout(0) << "acl size is zero" << dendl;
    err_code = -ERR_MALFORMED_JSON;
    return;
  }

  for (auto bos_access_control : bos_access_control_list) {
    if (bos_access_control.bos_grantee.size() == 0) {
      dout(0) << "grantee is empty" << dendl;
      err_code = -ERR_MALFORMED_JSON;
      return;
    }
    for (auto to_s3_grantee : bos_access_control.bos_grantee) {
      if (bos_access_control.bos_permission.size() == 0) {
        dout(0) << "permission in acl is empty" << dendl;
        err_code = -ERR_MALFORMED_JSON;
        return;
      }
      for (auto to_s3_permission : bos_access_control.bos_permission) {
        grant s3_grant;
        if (to_s3_grantee.bos_id.empty()) {
          dout(0) << "grantee.id in acl is empty" << dendl;
          err_code = -ERR_MALFORMED_JSON;
          return;
        }
        s3_grant.gran.id = to_s3_grantee.bos_id;
        if (to_s3_permission.compare("READ") == 0 || to_s3_permission.compare("FULL_CONTROL") == 0) {
          s3_grant.permission = to_s3_permission;
        } else {
          err_code = -ERR_MALFORMED_JSON;
          return;
        }
        s3_access_control_list.access_control_list.push_back(s3_grant);
      }
    }
  }
}

void RGWACLsParser::dump_xml(Formatter *f) const
{
  encode_xml("AccessControlList", s3_access_control_list, f);
  encode_xml("Owner", s3_owner, f);
}
