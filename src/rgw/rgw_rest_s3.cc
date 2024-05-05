// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include <errno.h>
#include <array>
#include <string.h>

#include "common/ceph_crypto.h"
#include "common/Formatter.h"
#include "common/utf8.h"
#include "common/ceph_json.h"
#include "common/safe_io.h"
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <boost/utility/string_view.hpp>

#include <liboath/oath.h>

#include "rgw_rest.h"
#include "rgw_rest_s3.h"
#include "rgw_rest_bos.h"
#include "rgw_rest_s3website.h"
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
#include "rgw_rest_bos.h"

#include "include/assert.h"

#define dout_context g_ceph_context
#define dout_subsys ceph_subsys_rgw

using namespace rgw;
using namespace ceph::crypto;

using std::get;

void list_all_buckets_start(struct req_state *s)
{
  s->formatter->open_array_section_in_ns("ListAllMyBucketsResult", XMLNS_AWS_S3);
}

void list_all_buckets_end(struct req_state *s)
{
  s->formatter->close_section();
}

void dump_bucket(struct req_state *s, RGWBucketEnt& obj)
{
  s->formatter->open_object_section("Bucket");
  s->formatter->dump_string("Name", obj.bucket.name);
  dump_time(s, "CreationDate", &obj.creation_time);
  s->formatter->close_section();
}

void rgw_get_errno_s3(rgw_http_error *e , int err_no)
{
#ifdef WITH_BCEBOS
  auto r = rgw_http_bos_errors.find(err_no);

  if (r != rgw_http_bos_errors.end()) {
    e->http_ret = std::get<0>(r->second);
    e->s3_code = std::get<1>(r->second);
    e->message = std::get<2>(r->second);
  } else {
    e->http_ret = 500;
    e->s3_code = "UnknownError";
    e->message = "UnknownError";
  }

#else
  rgw_http_errors::const_iterator r = rgw_http_s3_errors.find(err_no);

  if (r != rgw_http_s3_errors.end()) {
    e->http_ret = r->second.first;
    e->s3_code = r->second.second;
  } else {
    e->http_ret = 500;
    e->s3_code = "UnknownError";
  }
#endif
}

static inline std::string get_s3_expiration_header(
  struct req_state* s,
  const ceph::real_time& mtime)
{
  return rgw::lc::s3_expiration_header(
    s, s->object, s->tagset, mtime, s->bucket_attrs);
}

static inline bool get_s3_multipart_abort_header(
  struct req_state* s, const ceph::real_time& mtime,
  ceph::real_time& date, std::string& rule_id)
{
  return rgw::lc::s3_multipart_abort_header(
          s, s->object, mtime, s->bucket_attrs, date, rule_id);
}

struct response_attr_param {
  const char *param;
  const char *http_attr;
};

static struct response_attr_param resp_attr_params[] = {
  {"response-content-type", "Content-Type"},
  {"response-content-language", "Content-Language"},
  {"response-expires", "Expires"},
  {"response-cache-control", "Cache-Control"},
  {"response-content-disposition", "Content-Disposition"},
  {"responseContentDisposition", "Content-Disposition"},
  {"response-content-encoding", "Content-Encoding"},
  {NULL, NULL},
};

int RGWGetObj_ObjStore_S3Website::send_response_data(bufferlist& bl, off_t bl_ofs, off_t bl_len) {
  map<string, bufferlist>::iterator iter;
  iter = attrs.find(RGW_ATTR_AMZ_WEBSITE_REDIRECT_LOCATION);
  if (iter != attrs.end()) {
    bufferlist &bl = iter->second;
    s->redirect = bl.c_str();
    s->err.http_ret = 301;
    ldout(s->cct, 20) << __CEPH_ASSERT_FUNCTION << " redirecting per x-amz-website-redirect-location=" << s->redirect << dendl;
    op_ret = -ERR_WEBSITE_REDIRECT;
    set_req_state_err(s, op_ret);
    dump_errno(s);
    dump_content_length(s, 0);
    dump_redirect(s, s->redirect);
    end_header(s, this);
    return op_ret;
  } else {
    return RGWGetObj_ObjStore_S3::send_response_data(bl, bl_ofs, bl_len);
  }
}

int RGWGetObj_ObjStore_S3Website::send_response_data_error()
{
  return RGWGetObj_ObjStore_S3::send_response_data_error();
}

int RGWGetObj_ObjStore_S3::get_params()
{
  // for multisite sync requests, only read the slo manifest itself, rather than
  // all of the data from its parts. the parts will sync as separate objects
  skip_manifest = s->info.args.exists(RGW_SYS_PARAM_PREFIX "sync-manifest");

  // multisite sync requests should fetch encrypted data, along with the
  // attributes needed to support decryption on the other zone
  if (s->system_request) {
    skip_decrypt = s->info.args.exists(RGW_SYS_PARAM_PREFIX "skip-decrypt");
  }

  return RGWGetObj_ObjStore::get_params();
}

int RGWGetObj_ObjStore_S3::send_response_data_error()
{
  bufferlist bl;
  return send_response_data(bl, 0 , 0);
}

int RGWGetObj_ObjStore_S3::verify_permission()
{
  int ret = RGWGetObj_ObjStore::verify_permission();
  if (ret < 0) {
    return ret;
  }
  if (s->is_symlink_obj && (s->prot_flags & RGW_REST_BOS) && !is_anonymous(s)) {
    // bos user should call ceph-proxy
    std::list<bceiam::VerifyContext> verify_context_list;
    std::set<std::string> permissions{"READ"};
    JSONParser parser;
    bceiam::IamUserInfo user_info;
    // permissions GET OP
    ret = rgw::auth::s3::IAMEngine::generate_verify_context_fast(s, s->bucket_name, s->object.name,
                                                      permissions, &verify_context_list, store);
    if (ret != 0) {
      return ret;
    }
    // sts and s3 verify
    ret = rgw::auth::s3::IAMEngine::get_iam_client()->verify_sts_token(s, verify_context_list, &user_info);
    if (ret != 0) {
      return ret;
    }
  }
  return 0;
}

template <class T>
int decode_attr_bl_single_value(map<string, bufferlist>& attrs, const char *attr_name, T *result, T def_val)
{
  map<string, bufferlist>::iterator iter = attrs.find(attr_name);
  if (iter == attrs.end()) {
    *result = def_val;
    return 0;
  }
  bufferlist& bl = iter->second;
  if (bl.length() == 0) {
    *result = def_val;
    return 0;
  }
  bufferlist::iterator bliter = bl.begin();
  try {
    decode(*result, bliter);
  } catch (buffer::error& err) {
    return -EIO;
  }
  return 0;
}

int RGWGetObj_ObjStore_S3::send_response_data(bufferlist& bl, off_t bl_ofs,
					      off_t bl_len)
{
  const char *content_type = NULL;
  string content_type_str;
  map<string, string> response_attrs;
  map<string, string>::iterator riter;
  bufferlist metadata_bl;
  string custom_meta = "";

  string expires = get_s3_expiration_header(s, lastmod);

  if (sent_header)
    goto send_data;

  if (custom_http_ret) {
    set_req_state_err(s, 0);
    dump_errno(s, custom_http_ret);
  } else if (retarget_op && !op_ret){
    set_req_state_err(s, op_ret);
    dump_errno(s, 404);
  } else {
    set_req_state_err(s, (partial_content && !op_ret) ? STATUS_PARTIAL_CONTENT
                  : op_ret);
    dump_errno(s);
  }

  if (op_ret)
    goto done;

  if (range_str)
    dump_range(s, start, end, s->obj_size);

  if (s->system_request &&
      s->info.args.exists(RGW_SYS_PARAM_PREFIX "prepend-metadata")) {

    dump_header(s, "Rgwx-Object-Size", (long long)total_len);

    if (rgwx_stat) {
      /*
       * in this case, we're not returning the object's content, only the prepended
       * extra metadata
       */
      total_len = 0;
    }

    /* JSON encode object metadata */
    JSONFormatter jf;
    jf.open_object_section("obj_metadata");
    encode_json("attrs", attrs, &jf);
    utime_t ut(lastmod);
    encode_json("mtime", ut, &jf);
    jf.close_section();
    stringstream ss;
    jf.flush(ss);
    metadata_bl.append(ss.str());
    dump_header(s, "Rgwx-Embedded-Metadata-Len", metadata_bl.length());
    total_len += metadata_bl.length();
  }

  if (s->system_request && !real_clock::is_zero(lastmod)) {
    /* we end up dumping mtime in two different methods, a bit redundant */
    dump_epoch_header(s, "Rgwx-Mtime", lastmod);
    uint64_t pg_ver = 0;
    int r = decode_attr_bl_single_value(attrs, RGW_ATTR_PG_VER, &pg_ver, (uint64_t)0);
    if (r < 0) {
      ldout(s->cct, 0) << "ERROR: failed to decode pg ver attr, ignoring" << dendl;
    }
    dump_header(s, "Rgwx-Obj-PG-Ver", pg_ver);

    uint32_t source_zone_short_id = 0;
    r = decode_attr_bl_single_value(attrs, RGW_ATTR_SOURCE_ZONE, &source_zone_short_id, (uint32_t)0);
    if (r < 0) {
      ldout(s->cct, 0) << "ERROR: failed to decode pg ver attr, ignoring" << dendl;
    }
    if (source_zone_short_id != 0) {
      dump_header(s, "Rgwx-Source-Zone-Short-Id", source_zone_short_id);
    }
  }

  for (auto &it : crypt_http_responses)
    dump_header(s, it.first, it.second);

  /* 
   * for symlink obj, should change http return headers:
   *   * content_length: return target_obj len
   *   * last_modified: return max(target_obj, symlink_obj)
   *   * x-bce-object-type: Symlink
   *   * ETAG && MD5: return target_obj etag and md5
  */

  if (!is_chunk) {
    dump_content_length(s, total_len);
  }

  if (s->is_symlink_obj) {
    if (symlink_lastmod < lastmod) {
      dump_last_modified(s, lastmod);
    } else {
      dump_last_modified(s, symlink_lastmod);
    }
  } else {
    dump_last_modified(s, lastmod);
    dump_header_if_nonempty(s, "x-amz-version-id", version_id);
    dump_header_if_nonempty(s, "x-amz-expiration", expires);
  }

  if (s->is_symlink_obj){
    dump_header(s, "x-bce-object-type", "Symlink");
  } else if (attrs.find(RGW_ATTR_TARGET_SIZE) != attrs.end()) {
    dump_header(s, "x-bce-object-type", "Appendable");
    dump_header(s, "x-bce-next-append-offset", s->obj_size);
  } else {
    dump_header(s, "x-bce-object-type", "Normal");
  }

  if (! op_ret) {
    if (! lo_etag.empty()) {
      /* Handle etag of Swift API's large objects (DLO/SLO). It's entirerly
       * legit to perform GET on them through S3 API. In such situation,
       * a client should receive the composited content with corresponding
       * etag value. */
      dump_etag(s, lo_etag);
    } else {
      /* dump etag and md5 code */
      auto iter = attrs.find(RGW_ATTR_ETAG);
      if (iter != attrs.end()) {
        dump_etag(s, iter->second.to_str());
      }
      iter = attrs.find(RGW_ATTR_CONTENT_MD5);
      if (iter != attrs.end()) {
        dump_header(s, "Content-Md5", iter->second.to_str());
      }
    }

    if (s->is_symlink_obj && is_head_obj()) {
      attrs = symlink_attrs;
    }

    for (struct response_attr_param *p = resp_attr_params; p->param; p++) {
      bool exists;
      string val = s->info.args.get(p->param, &exists);
      if (exists) {
        if (strcmp(p->param, "response-content-type") != 0) {
          response_attrs[p->http_attr] = val;
        } else {
          content_type_str = val;
          content_type = content_type_str.c_str();
        }
      }
    }

    for (auto iter = attrs.begin(); iter != attrs.end(); ++iter) {
      const char *name = iter->first.c_str();
      map<string, string>::iterator aiter = rgw_to_http_attrs.find(name);
      if (aiter != rgw_to_http_attrs.end()) {
        if (response_attrs.count(aiter->second) == 0) {
          /* Was not already overridden by a response param. */
          response_attrs[aiter->second] = iter->second.c_str();
        }
      } else if (iter->first.compare(RGW_ATTR_CONTENT_TYPE) == 0) {
        /* Special handling for content_type. */
        if (!content_type) {
          if (s->explicit_content_type.length() > 0) {
            content_type = s->explicit_content_type.c_str();
          } else {
            content_type_str = rgw_bl_to_str(iter->second);
            content_type = content_type_str.c_str();
          }
        }
      } else if (strcmp(name, RGW_ATTR_SLO_UINDICATOR) == 0) {
        // this attr has an extra length prefix from encode() in prior versions
        dump_header(s, "X-Object-Meta-Static-Large-Object", "True");
      } else if (strncmp(name, RGW_ATTR_META_PREFIX,
			 sizeof(RGW_ATTR_META_PREFIX)-1) == 0) {
        /* User custom metadata. */
#ifdef WITH_BCEBOS
        if (s->prot_flags & RGW_REST_BOS) {
          strncpy(const_cast<char*>(name), RGW_BCE_META_PREFIX, sizeof(RGW_BCE_META_PREFIX)-1);
        }
#endif
        name += sizeof(RGW_ATTR_PREFIX) - 1;
        dump_header(s, name, iter->second);
        custom_meta += ",";
        custom_meta += name;
      } else if (iter->first.compare(RGW_ATTR_TAGS) == 0) {
        RGWObjTags obj_tags;
        try{
          bufferlist::iterator it = iter->second.begin();
          obj_tags.decode(it);
        } catch (buffer::error &err) {
          ldout(s->cct,0) << "Error caught buffer::error couldn't decode TagSet " << dendl;
        }
        dump_header(s, RGW_AMZ_TAG_COUNT, obj_tags.count());
      } else if (iter->first.compare(RGW_ATTR_STORAGE_CLASS) == 0) {
        string storage_class = rgw_bl_to_str(iter->second);

#ifdef WITH_BCEBOS
        if (s->prot_flags & RGW_REST_BOS) {
          if (!storage_class.empty()) {
            dump_header(s, RGW_BCE_STORAGE_CLASS, storage_class);
          } else {
            dump_header(s, RGW_BCE_STORAGE_CLASS, "STANDARD");
          }
        } else
#endif
        {
          if (!storage_class.empty() && storage_class.compare("STANDARD") != 0) {
            dump_header(s, RGW_AMZ_STORAGE_CLASS, storage_class);
          }
        }
      } else if (iter->first.compare(RGW_ATTR_OBJECT_RETENTION) == 0 && get_retention){
        RGWObjectRetention retention;
        try {
          decode(retention, iter->second);
          dump_header(s, "x-amz-object-lock-mode", retention.get_mode());
          dump_time_header(s, "x-amz-object-lock-retain-until-date", retention.get_retain_until_date());
        } catch (buffer::error& err) {
          ldout(s->cct, 0) << "ERROR: failed to decode RGWObjectRetention" << dendl;
        }
      } else if (iter->first.compare(RGW_ATTR_OBJECT_LEGAL_HOLD) == 0 && get_legal_hold) {
        RGWObjectLegalHold legal_hold;
        try {
          decode(legal_hold, iter->second);
          dump_header(s, "x-amz-object-lock-legal-hold",legal_hold.get_status());
        } catch (buffer::error& err) {
          ldout(s->cct, 0) << "ERROR: failed to decode RGWObjectLegalHold" << dendl;
        }
      } else if (iter->first.compare(RGW_ATTR_VARY) == 0) {
        dump_header(s, "Vary", iter->second.to_str());
      }
    }
  }

done:
  for (riter = response_attrs.begin(); riter != response_attrs.end();
       ++riter) {
    dump_header(s, riter->first, riter->second);
  }

  if (op_ret == -ERR_NOT_MODIFIED) {
      end_header(s, this, nullptr, NO_CONTENT_LENGTH, false, false, custom_meta);
  } else {
      if (!content_type) {
          content_type = "binary/octet-stream";
      }
      if (is_chunk) {
        end_header(s, this, content_type, CHUNKED_TRANSFER_ENCODING, false, false, custom_meta);
      } else {
        end_header(s, this, content_type, NO_CONTENT_LENGTH, false, false, custom_meta);
      }
  }

  if (metadata_bl.length()) {
    dump_body(s, metadata_bl);
  }
  sent_header = true;

send_data:
  if (get_data && !op_ret) {
    int r = dump_body(s, bl.c_str() + bl_ofs, bl_len);
    if (r < 0)
      return r;
  }

  return 0;
}

int RGWGetObj_ObjStore_S3::get_decrypt_filter(std::unique_ptr<RGWGetObj_Filter> *filter, RGWGetObj_Filter* cb, bufferlist* manifest_bl)
{
  if (skip_decrypt) { // bypass decryption for multisite sync requests
    return 0;
  }

  int res = 0;
  std::unique_ptr<BlockCrypt> block_crypt;
#ifdef WITH_BCEBOS
  if (s->prot_flags & RGW_REST_BOS) {
    res = rgw_bos_prepare_decrypt(s, attrs, &block_crypt, crypt_http_responses);
  } else
#endif
  {
    res = rgw_s3_prepare_decrypt(s, attrs, &block_crypt, crypt_http_responses);
  }
  if (res == 0) {
    if (block_crypt != nullptr) {
      auto f = std::make_unique<RGWGetObj_BlockDecrypt>(s->cct, cb, std::move(block_crypt));
      if (manifest_bl != nullptr) {
        res = f->read_manifest(*manifest_bl);
        if (res == 0) {
          *filter = std::move(f);
        }
      }
    }
  }
  return res;
}

void RGWGetObjTags_ObjStore_S3::send_response_data(bufferlist& bl)
{
  dump_errno(s);
  end_header(s, this, "application/xml");
  dump_start(s);

  s->formatter->open_object_section_in_ns("Tagging", XMLNS_AWS_S3);
  s->formatter->open_object_section("TagSet");
  if (has_tags){
    RGWObjTagSet_S3 tagset;
    bufferlist::iterator iter = bl.begin();
    try {
      tagset.decode(iter);
    } catch (buffer::error& err) {
      ldout(s->cct,0) << "ERROR: caught buffer::error, couldn't decode TagSet" << dendl;
      op_ret= -EIO;
      return;
    }
    tagset.dump_xml(s->formatter);
  }
  s->formatter->close_section();
  s->formatter->close_section();
  rgw_flush_formatter_and_reset(s, s->formatter);
}


int RGWPutObjTags_ObjStore_S3::get_params()
{
  RGWObjTagsXMLParser parser;

  if (!parser.init()){
    return -EINVAL;
  }

  char *data=nullptr;
  int len=0;

  const auto max_size = s->cct->_conf->rgw_max_put_param_size;
  int r = rgw_rest_read_all_input(s, &data, &len, max_size, false);

  if (r < 0)
    return r;

  auto data_deleter = std::unique_ptr<char, decltype(free)*>{data, free};

  if (!parser.parse(data, len, 1)) {
    return -ERR_MALFORMED_XML;
  }

  RGWObjTagSet_S3 *obj_tags_s3;
  RGWObjTagging_S3 *tagging;

  tagging = static_cast<RGWObjTagging_S3 *>(parser.find_first("Tagging"));
  obj_tags_s3 = static_cast<RGWObjTagSet_S3 *>(tagging->find_first("TagSet"));
  if(!obj_tags_s3){
    return -ERR_MALFORMED_XML;
  }

  RGWObjTags obj_tags;
  r = obj_tags_s3->rebuild(obj_tags);
  if (r < 0)
    return r;

  obj_tags.encode(tags_bl);
  ldout(s->cct, 20) << "Read " << obj_tags.count() << "tags" << dendl;

  return 0;
}

void RGWPutObjTags_ObjStore_S3::send_response()
{
  if (op_ret)
    set_req_state_err(s, op_ret);
  dump_errno(s);
  end_header(s, this, "application/xml");
  dump_start(s);

}

void RGWDeleteObjTags_ObjStore_S3::send_response()
{
  int r = op_ret;
  if (r == -ENOENT)
    r = 0;
  if (!r)
    r = STATUS_NO_CONTENT;

  set_req_state_err(s, r);
  dump_errno(s);
  end_header(s, this);
}

void RGWListBuckets_ObjStore_S3::send_response_begin(bool has_buckets)
{
  if (op_ret)
    set_req_state_err(s, op_ret);
  dump_errno(s);
  dump_start(s);
  end_header(s, NULL, "application/xml");

  if (! op_ret) {
    list_all_buckets_start(s);
    dump_owner(s, s->user->user_id, s->user->display_name);
    s->formatter->open_array_section("Buckets");
    sent_data = true;
  }
}

void RGWListBuckets_ObjStore_S3::send_response_data(RGWUserBuckets& buckets)
{
  if (!sent_data)
    return;

  map<string, RGWBucketEnt>& m = buckets.get_buckets();
  map<string, RGWBucketEnt>::iterator iter;

  for (iter = m.begin(); iter != m.end(); ++iter) {
    RGWBucketEnt obj = iter->second;
    dump_bucket(s, obj);
  }
  rgw_flush_formatter(s, s->formatter);
}

void RGWListBuckets_ObjStore_S3::send_response_end()
{
  if (sent_data) {
    s->formatter->close_section();
    list_all_buckets_end(s);
    rgw_flush_formatter_and_reset(s, s->formatter);
  }
}

int RGWGetUsage_ObjStore_S3::get_params()
{
  start_date = s->info.args.get("start-date");
  end_date = s->info.args.get("end-date"); 
  return 0;
}

static void dump_usage_categories_info(Formatter *formatter, const rgw_usage_log_entry& entry, map<string, bool> *categories)
{
  formatter->open_array_section("categories");
  map<string, rgw_usage_data>::const_iterator uiter;
  for (uiter = entry.usage_map.begin(); uiter != entry.usage_map.end(); ++uiter) {
    if (categories && !categories->empty() && !categories->count(uiter->first))
      continue;
    const rgw_usage_data& usage = uiter->second;
    formatter->open_object_section("Entry");
    formatter->dump_string("Category", uiter->first);
    formatter->dump_int("BytesSent", usage.bytes_sent);
    formatter->dump_int("BytesReceived", usage.bytes_received);
    formatter->dump_int("Ops", usage.ops);
    formatter->dump_int("SuccessfulOps", usage.successful_ops);
    formatter->close_section(); // Entry
  }
  formatter->close_section(); // Category
}

static void dump_usage_bucket_info(Formatter *formatter, const std::string& name, const cls_user_bucket_entry& entry)
{
  formatter->open_object_section("Entry");
  formatter->dump_string("Bucket", name);
  formatter->dump_int("Bytes", entry.size);
  formatter->dump_int("Bytes_Rounded", entry.size_rounded);
  formatter->close_section(); // entry
}

void RGWGetUsage_ObjStore_S3::send_response()
{
  if (op_ret < 0)
    set_req_state_err(s, op_ret);
  dump_errno(s);

  end_header(s, this, "application/xml");
  dump_start(s);
  if (op_ret < 0)
    return;

  Formatter *formatter = s->formatter;
  string last_owner;
  bool user_section_open = false;
  
  formatter->open_object_section("Usage");
  if (show_log_entries) {
    formatter->open_array_section("Entries");
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
        formatter->open_object_section("User");
        formatter->dump_string("Owner", ub.user);
        formatter->open_array_section("Buckets");
        user_section_open = true;
        last_owner = ub.user;
      }
      formatter->open_object_section("Bucket");
      formatter->dump_string("Bucket", ub.bucket);
      utime_t ut(entry.epoch, 0);
      ut.gmtime(formatter->dump_stream("Time"));
      formatter->dump_int("Epoch", entry.epoch);
      dump_usage_categories_info(formatter, entry, &categories);
      formatter->close_section(); // bucket
    }

    summary_map[ub.user].aggregate(entry, &categories);
  }

  if (show_log_entries) {
     if (user_section_open) {
       formatter->close_section(); // buckets
       formatter->close_section(); //user
     }
     formatter->close_section(); // entries
   }

   if (show_log_sum) {
     formatter->open_array_section("Summary");
     map<string, rgw_usage_log_entry>::iterator siter;
     for (siter = summary_map.begin(); siter != summary_map.end(); ++siter) {
       const rgw_usage_log_entry& entry = siter->second;
       formatter->open_object_section("User");
       formatter->dump_string("User", siter->first);
       dump_usage_categories_info(formatter, entry, &categories);
       rgw_usage_data total_usage;
       entry.sum(total_usage, categories);
       formatter->open_object_section("Total");
       formatter->dump_int("BytesSent", total_usage.bytes_sent);
       formatter->dump_int("BytesReceived", total_usage.bytes_received);
       formatter->dump_int("Ops", total_usage.ops);
       formatter->dump_int("SuccessfulOps", total_usage.successful_ops);
       formatter->close_section(); // total
       formatter->close_section(); // user
     }

     if (s->cct->_conf->rgw_rest_getusage_op_compat) {
       formatter->open_object_section("Stats");
     }

     formatter->dump_int("TotalBytes", header.stats.total_bytes);
     formatter->dump_int("TotalBytesRounded", header.stats.total_bytes_rounded);
     formatter->dump_int("TotalEntries", header.stats.total_entries);

     if (s->cct->_conf->rgw_rest_getusage_op_compat) {
       formatter->close_section(); //Stats
     }

     formatter->close_section(); // summary
   }

  formatter->open_array_section("CapacityUsed");
  formatter->open_object_section("User");
  formatter->open_array_section("Buckets");
  for (const auto& biter : buckets_usage) {
    const cls_user_bucket_entry& entry = biter.second;
    dump_usage_bucket_info(formatter, biter.first, entry);
  }
  formatter->close_section(); // Buckets
  formatter->close_section(); // User
  formatter->close_section(); // CapacityUsed

  formatter->close_section(); // usage
  rgw_flush_formatter_and_reset(s, s->formatter);
}

int RGWListBucket_ObjStore_S3::get_common_params()
{
  list_versions = s->info.args.exists("versions");
  prefix = s->info.args.get("prefix");

  // non-standard
  s->info.args.get_bool("allow-unordered", &allow_unordered, false);
  delimiter = s->info.args.get("delimiter");
  max_keys = s->info.args.get("max-keys");
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
        ldout(s->cct, 5) << "bad shard id specified: " << shard_id_str << dendl;
        return -EINVAL;
      }
    } else {
     shard_id = s->bucket_instance_shard_id;
    }
  }
  return 0;
}

int RGWListBucket_ObjStore_S3::get_params()
{
  int ret = get_common_params();
  if (ret < 0) {
    return ret;
  }
  if (!list_versions) {
    marker = s->info.args.get("marker");
  } else {
    marker.name = s->info.args.get("key-marker");
    marker.instance = s->info.args.get("version-id-marker");
  }
  return 0;
}

void RGWListBucket_ObjStore_S3::send_versioned_response()
{
  s->formatter->open_object_section_in_ns("ListVersionsResult", XMLNS_AWS_S3);
  if (!s->bucket_tenant.empty()) {
    s->formatter->dump_string("Tenant", s->bucket_tenant);
  }
  s->formatter->dump_string("Name", s->bucket_name);
  s->formatter->dump_string("Prefix", prefix);
  s->formatter->dump_string("KeyMarker", marker.name);
  s->formatter->dump_string("VersionIdMarker", marker.instance);
  if (is_truncated && !next_marker.empty()) {
    s->formatter->dump_string("NextKeyMarker", next_marker.name);
    if (next_marker.instance.empty()) {
      s->formatter->dump_string("NextVersionIdMarker", "null");
    } else {
      s->formatter->dump_string("NextVersionIdMarker", next_marker.instance);
    }
  }
  s->formatter->dump_int("MaxKeys", max);
  if (!delimiter.empty()) {
    s->formatter->dump_string("Delimiter", delimiter);
  }
  s->formatter->dump_string("IsTruncated", (max && is_truncated ? "true"
              : "false"));

  if (strcasecmp(encoding_type.c_str(), "url") == 0) {
    s->formatter->dump_string("EncodingType", "url");
    encode_key = true;
  }

  if (op_ret >= 0) {
    if (objs_container) {
      s->formatter->open_array_section("Entries");
    }

    vector<rgw_bucket_dir_entry>::iterator iter;
    for (iter = objs.begin(); iter != objs.end(); ++iter) {
      const char *section_name = (iter->is_delete_marker() ? "DeleteMarker"
                                  : "Version");
      s->formatter->open_object_section(section_name);
      if (objs_container) {
        s->formatter->dump_bool("IsDeleteMarker", iter->is_delete_marker());
      }
      rgw_obj_key key(iter->key);
      if (encode_key) {
        string key_name;
        url_encode(key.name, key_name);
        s->formatter->dump_string("Key", key_name);
      } else {
        s->formatter->dump_string("Key", key.name);
      }
      string version_id = key.instance;
      if (version_id.empty()) {
        version_id = "null";
      }
      if (s->system_request) {
        if (iter->versioned_epoch > 0) {
          s->formatter->dump_int("VersionedEpoch", iter->versioned_epoch);
        }
        s->formatter->dump_string("RgwxTag", iter->tag);
        utime_t ut(iter->meta.mtime);
        ut.gmtime_nsec(s->formatter->dump_stream("RgwxMtime"));
      }
      s->formatter->dump_string("VersionId", version_id);
      s->formatter->dump_bool("IsLatest", iter->is_current());
      dump_time(s, "LastModified", &iter->meta.mtime);
      if (!iter->is_delete_marker()) {
        s->formatter->dump_format("ETag", "\"%s\"", iter->meta.etag.c_str());
        s->formatter->dump_int("Size", iter->meta.accounted_size);
        s->formatter->dump_string("StorageClass",
            rgw_placement_rule::get_canonical_storage_class(iter->meta.storage_class));
      }
      dump_owner(s, iter->meta.owner, iter->meta.owner_display_name);
      if (iter->meta.appendable) {
        s->formatter->dump_string("Type", "Appendable");
      } else {
        s->formatter->dump_string("Type", "Normal");
      }
      s->formatter->close_section();
    }
    if (objs_container) {
      s->formatter->close_section();
    }
    if (!common_prefixes.empty()) {
      map<string, bool>::iterator pref_iter;
      for (pref_iter = common_prefixes.begin();
           pref_iter != common_prefixes.end(); ++pref_iter) {
        s->formatter->open_array_section("CommonPrefixes");
        if (encode_key) {
          s->formatter->dump_string("Prefix", url_encode(pref_iter->first, false));
        } else {
          s->formatter->dump_string("Prefix", pref_iter->first);
        }
        s->formatter->close_section();
      }
    }
  }
  s->formatter->close_section();
  rgw_flush_formatter_and_reset(s, s->formatter);
}

void RGWListBucket_ObjStore_S3::send_common_response()
{
  if (!s->bucket_tenant.empty())
    s->formatter->dump_string("Tenant", s->bucket_tenant);
  s->formatter->dump_string("Name", s->bucket_name);
  s->formatter->dump_string("Prefix", prefix);
  s->formatter->dump_int("MaxKeys", max);
  if (!delimiter.empty()) {
    if (encode_key) {
      s->formatter->dump_string("Delimiter", url_encode(delimiter, false));
    } else {
      s->formatter->dump_string("Delimiter", delimiter);
    }
  }
  s->formatter->dump_string("IsTruncated", (max && is_truncated ? "true"
              : "false"));

  if (!common_prefixes.empty()) {
    map<string, bool>::iterator pref_iter;
    for (pref_iter = common_prefixes.begin();
         pref_iter != common_prefixes.end(); ++pref_iter) {
      s->formatter->open_array_section("CommonPrefixes");
      if (encode_key) {
        s->formatter->dump_string("Prefix", url_encode(pref_iter->first, false));
      } else {
        s->formatter->dump_string("Prefix", pref_iter->first);
      }
      s->formatter->close_section();
    }
  }
}

void RGWListBucket_ObjStore_S3::send_response()
{
  if (website_retarget) {
    return;
  }
  if (op_ret < 0)
    set_req_state_err(s, op_ret);
  dump_errno(s);

  end_header(s, this, "application/xml");
  dump_start(s);
  if (op_ret < 0)
    return;

  if (list_versions) {
    send_versioned_response();
    return;
  }

  s->formatter->open_object_section_in_ns("ListBucketResult", XMLNS_AWS_S3);
  s->formatter->dump_string("Marker", marker.name);
  if (is_truncated && !next_marker.empty())
    s->formatter->dump_string("NextMarker", next_marker.name);

  if (strcasecmp(encoding_type.c_str(), "url") == 0) {
    s->formatter->dump_string("EncodingType", "url");
    encode_key = true;
  }

  send_common_response();

  if (op_ret >= 0) {
    vector<rgw_bucket_dir_entry>::iterator iter;
    for (iter = objs.begin(); iter != objs.end(); ++iter) {
      rgw_obj_key *key = nullptr;
      if (!is_bucket_namespace_list) {
        key = new rgw_obj_key(iter->key);
      } else {
        key = new rgw_obj_key(iter->key.name);
      }

      s->formatter->open_array_section("Contents");
      if (encode_key) {
        string key_name;
        url_encode(key->name, key_name);
        s->formatter->dump_string("Key", key_name);
      } else {
        s->formatter->dump_string("Key", key->name);
      }
      delete key;

      dump_time(s, "LastModified", &iter->meta.mtime);
      s->formatter->dump_format("ETag", "\"%s\"", iter->meta.etag.c_str());
      s->formatter->dump_int("Size", iter->meta.accounted_size);

      // when bucket namespace list, etag is empty
      if (iter->meta.storage_class.empty() && iter->meta.etag.empty()) {
        s->formatter->dump_string("StorageClass", "");
      } else {
        s->formatter->dump_string("StorageClass",
          rgw_placement_rule::get_canonical_storage_class(iter->meta.storage_class));
      }
      dump_owner(s, iter->meta.owner, iter->meta.owner_display_name);
      if (s->system_request) {
        s->formatter->dump_string("RgwxTag", iter->tag);
      }
      if (iter->meta.appendable) {
        s->formatter->dump_string("Type", "Appendable");
      } else {
        s->formatter->dump_string("Type", "Normal");
      }
      s->formatter->close_section();
    }
  }
  s->formatter->close_section();
  rgw_flush_formatter_and_reset(s, s->formatter);
}

int RGWListBucket_ObjStore_S3v2::get_params()
{
  int ret = get_common_params();
  if (ret < 0) {
    return ret;
  }
  if (list_versions) {
    ldout(s->cct, 0) << "NOTICE: list objects v2 not support list versions" << dendl;
    return -ERR_NOT_IMPLEMENTED;
  }
  s->info.args.get_bool("fetch-owner", &fetchOwner, false);
  startAfter = s->info.args.get("start-after", &start_after_exist);
  continuation_token = s->info.args.get("continuation-token", &continuation_token_exist);
  if(!continuation_token_exist) {
    marker = startAfter;
  } else {
    marker = continuation_token;
  }
  return 0;
}

void RGWListBucket_ObjStore_S3v2::send_response()
{
  if (op_ret < 0) {
    set_req_state_err(s, op_ret);
  }
  dump_errno(s);

  end_header(s, this, "application/xml");
  dump_start(s);
  if (op_ret < 0) {
    return;
  }

  s->formatter->open_object_section_in_ns("ListBucketResult", XMLNS_AWS_S3);
  if (strcasecmp(encoding_type.c_str(), "url") == 0) {
    s->formatter->dump_string("EncodingType", "url");
    encode_key = true;
  }
  if (continuation_token_exist) {
    s->formatter->dump_string("ContinuationToken", continuation_token);
  }
  if (is_truncated && !next_marker.empty()) {
    s->formatter->dump_string("NextContinuationToken", next_marker.name);
  }
  s->formatter->dump_int("KeyCount", objs.size() + common_prefixes.size());
  if (start_after_exist) {
    s->formatter->dump_string("StartAfter", startAfter);
  }

  send_common_response();
  if (op_ret >= 0) {
    vector<rgw_bucket_dir_entry>::iterator iter;
    for (iter = objs.begin(); iter != objs.end(); ++iter) {
      rgw_obj_key *key = nullptr;
      if (!is_bucket_namespace_list) {
        key = new rgw_obj_key(iter->key);
      } else {
        key = new rgw_obj_key(iter->key.name);
      }

      s->formatter->open_array_section("Contents");
      if (encode_key) {
        string key_name;
        url_encode(key->name, key_name);
        s->formatter->dump_string("Key", key_name);
      }
      else {
        s->formatter->dump_string("Key", key->name);
      }
      delete key;

      dump_time(s, "LastModified", &iter->meta.mtime);
      s->formatter->dump_format("ETag", "\"%s\"", iter->meta.etag.c_str());
      s->formatter->dump_int("Size", iter->meta.accounted_size);

      // when bucket namespace list, etag is empty
      if (iter->meta.storage_class.empty() && iter->meta.etag.empty()) {
        s->formatter->dump_string("StorageClass", "");
      } else {
        s->formatter->dump_string("StorageClass",
          rgw_placement_rule::get_canonical_storage_class(iter->meta.storage_class));
      }
      if (fetchOwner == true) {
        dump_owner(s, rgw_user(iter->meta.owner), iter->meta.owner_display_name);
      }
      if (s->system_request) {
        s->formatter->dump_string("RgwxTag", iter->tag);
      }
      if (iter->meta.appendable) {
        s->formatter->dump_string("Type", "Appendable");
      } else {
        s->formatter->dump_string("Type", "Normal");
      }
      s->formatter->close_section();
    }
  }
  s->formatter->close_section();
  rgw_flush_formatter_and_reset(s, s->formatter);
}

void RGWGetBucketLocation_ObjStore_S3::send_response()
{
  if (op_ret) {
    set_req_state_err(s, op_ret);
  }
  dump_errno(s);
  end_header(s, this, nullptr, NO_CONTENT_LENGTH, true);
  dump_start(s);

#ifdef WITH_BCEBOS
  if (s->prot_flags & RGW_REST_BOS) {
    s->formatter->open_object_section("DisplayLocation");
    s->formatter->dump_string("locationConstraint", region);
    s->formatter->close_section();
  } else
#endif
  {
    s->formatter->dump_format_ns("LocationConstraint", XMLNS_AWS_S3,
        "%s", region.c_str());
  }
  rgw_flush_formatter_and_reset(s, s->formatter);
}

void RGWListRgw_ObjStore_S3::send_response()
{
  dump_errno(s);
  dump_header(s, "Last-Epoch", epoch);
  end_header(s, this, "application/xml");
  dump_start(s);

  s->formatter->open_object_section_in_ns("RgwConfiguration", XMLNS_AWS_S3);
  for (size_t i = 0; i < rgw_ip.size(); i++) {
    s->formatter->open_array_section("Rgw");
    s->formatter->dump_string("Ip", rgw_ip[i]);
    s->formatter->dump_string("Port", rgw_port[i]);
    s->formatter->close_section();
  }
  s->formatter->close_section();
  rgw_flush_formatter_and_reset(s, s->formatter);
}

void RGWGetBucketVersioning_ObjStore_S3::send_response()
{
  dump_errno(s);
  end_header(s, this, "application/xml");
  dump_start(s);

  s->formatter->open_object_section_in_ns("VersioningConfiguration", XMLNS_AWS_S3);
  if (versioned) {
    const char *status = (versioning_enabled ? "Enabled" : "Suspended");
    s->formatter->dump_string("Status", status);
    const char *mfa_status = (mfa_enabled ? "Enabled" : "Disabled");
    s->formatter->dump_string("MfaDelete", mfa_status);
  }
  s->formatter->close_section();
  rgw_flush_formatter_and_reset(s, s->formatter);
}
void RGWGetBucketMirroring_ObjStore_S3::send_response()
{
  if (op_ret) {
    set_req_state_err(s, op_ret);
  }
  dump_errno(s);
  end_header(s, this, nullptr, NO_CONTENT_LENGTH, true);
  dump_start(s);

  if (op_ret) {
    return;
  }

  s->formatter->open_object_section("");
  config.dump(s->formatter);
  s->formatter->close_section();

  rgw_flush_formatter_and_reset(s, s->formatter);
}


struct ver_config_status {
  int status{VersioningSuspended};

  enum MFAStatus {
    MFA_UNKNOWN,
    MFA_DISABLED,
    MFA_ENABLED,
  } mfa_status{MFA_UNKNOWN};
  int retcode{0};

  void decode_xml(XMLObj *obj) {
    string status_str;
    string mfa_str;
    RGWXMLDecoder::decode_xml("Status", status_str, obj);
    if (status_str == "Enabled") {
      status = VersioningEnabled;
    } else if (status_str != "Suspended") {
      status = VersioningStatusInvalid;
    }


    if (RGWXMLDecoder::decode_xml("MfaDelete", mfa_str, obj)) {
      if (mfa_str == "Enabled") {
        mfa_status = MFA_ENABLED;
      } else if (mfa_str == "Disabled") {
        mfa_status = MFA_DISABLED;
      } else {
        retcode = -EINVAL;
      }
    }
  }
};

int RGWSetBucketVersioning_ObjStore_S3::get_params()
{
  char *data = nullptr;
  int len = 0;
  int r =
    rgw_rest_read_all_input(s, &data, &len, s->cct->_conf->rgw_max_put_param_size, false);
  if (r < 0) {
    return r;
  }
  
  auto data_deleter = std::unique_ptr<char, decltype(free)*>{data, free};

  r = do_aws4_auth_completion();
  if (r < 0) {
    return r;
  }

  RGWXMLDecoder::XMLParser parser;
  if (!parser.init()) {
    ldout(s->cct, 0) << "ERROR: failed to initialize parser" << dendl;
    return -EIO;
  }

  if (!parser.parse(data, len, 1)) {
    ldout(s->cct, 10) << "NOTICE: failed to parse data: " << data << dendl;
    r = -EINVAL;
    return r;
  }

  ver_config_status status_conf;

  if (!RGWXMLDecoder::decode_xml("VersioningConfiguration", status_conf, &parser)) {
    ldout(s->cct, 10) << "NOTICE: bad versioning config input" << dendl;
    return -EINVAL;
  }

  if (!store->is_meta_master()) {
    /* only need to keep this data around if we're not meta master */
    in_data.append(data, len);
  }

  versioning_status = status_conf.status;
  if (versioning_status == VersioningStatusInvalid) {
    r = -EINVAL;
  }

  if (status_conf.mfa_status != ver_config_status::MFA_UNKNOWN) {
    mfa_set_status = true;
    switch (status_conf.mfa_status) {
      case ver_config_status::MFA_DISABLED:
        mfa_status = false;
        break;
      case ver_config_status::MFA_ENABLED:
        mfa_status = true;
        break;
      default:
        ldout(s->cct, 0) << "ERROR: RGWSetBucketVersioning_ObjStore_S3::get_params(): unexpected switch case mfa_status=" << status_conf.mfa_status << dendl;
        r = -EIO;
    }
  } else if (status_conf.retcode < 0) {
    r = status_conf.retcode;
  }
  return r;
}

void RGWSetBucketVersioning_ObjStore_S3::send_response()
{
  if (op_ret)
    set_req_state_err(s, op_ret);
  dump_errno(s);
  end_header(s, this, "application/xml");
}

int RGWPutBucketMirroring_ObjStore_S3::get_params() {
  const auto max_size = s->cct->_conf->rgw_max_put_param_size;
  op_ret = rgw_rest_read_all_input(s, &data, &len, max_size, false);
  return op_ret;
}

void RGWPutBucketMirroring_ObjStore_S3::send_response()
{
  if (op_ret)
    set_req_state_err(s, op_ret);
  dump_errno(s);
  end_header(s);
}

void RGWDeleteBucketMirroring_ObjStore_S3::send_response()
{
  if (op_ret == 0)
      op_ret = STATUS_NO_CONTENT;
  if (op_ret) {
    set_req_state_err(s, op_ret);
  }
  dump_errno(s);
  end_header(s);
  dump_start(s);
}

int RGWSetBucketWebsite_ObjStore_S3::get_params()
{
  char *data = nullptr;
  int len = 0;
  const auto max_size = s->cct->_conf->rgw_max_put_param_size;
  int r = rgw_rest_read_all_input(s, &data, &len, max_size, false);

  if (r < 0) {
    return r;
  }

  auto data_deleter = std::unique_ptr<char, decltype(free)*>{data, free};

  r = do_aws4_auth_completion();
  if (r < 0) {
    return r;
  }

  bufferptr in_ptr(data, len);
  in_data.append(in_ptr);

  RGWXMLDecoder::XMLParser parser;
  if (!parser.init()) {
    ldout(s->cct, 0) << "ERROR: failed to initialize parser" << dendl;
    return -EIO;
  }

  if (!parser.parse(data, len, 1)) {
    string str(data, len);
    ldout(s->cct, 5) << "failed to parse xml: " << str << dendl;
    return -EINVAL;
  }

  try {
    RGWXMLDecoder::decode_xml("WebsiteConfiguration", website_conf, &parser, true);
  } catch (RGWXMLDecoder::err& err) {
    string str(data, len);
    ldout(s->cct, 5) << "unexpected xml: " << str << dendl;
    return -EINVAL;
  }

  return 0;
}

void RGWSetBucketWebsite_ObjStore_S3::send_response()
{
  if (op_ret < 0)
    set_req_state_err(s, op_ret);
  dump_errno(s);
  end_header(s, this, "application/xml");
}

void RGWDeleteBucketWebsite_ObjStore_S3::send_response()
{
  if (op_ret == 0) {
    op_ret = STATUS_NO_CONTENT;
  }
  set_req_state_err(s, op_ret);
  dump_errno(s);
  end_header(s, this, "application/xml");
}

void RGWGetBucketWebsite_ObjStore_S3::send_response()
{
  if (op_ret)
    set_req_state_err(s, op_ret);
  dump_errno(s);
  end_header(s, this, "application/xml");
  dump_start(s);

  if (op_ret < 0) {
    return;
  }

  RGWBucketWebsiteConf& conf = s->bucket_info.website_conf;

  s->formatter->open_object_section_in_ns("WebsiteConfiguration", XMLNS_AWS_S3);
  conf.dump_xml(s->formatter);
  s->formatter->close_section(); // WebsiteConfiguration
  rgw_flush_formatter_and_reset(s, s->formatter);
}

void RGWSetBucketNamespace_ObjStore_S3::send_response()
{
  if (op_ret < 0)
    set_req_state_err(s, op_ret);
  dump_errno(s);
  end_header(s, this, "application/xml");
}

void RGWDeleteBucketNamespace_ObjStore_S3::send_response()
{
  if (op_ret == 0) {
    op_ret = STATUS_NO_CONTENT;
  }
  set_req_state_err(s, op_ret);
  dump_errno(s);
  end_header(s, this, "application/xml");
}

void RGWGetBucketNamespace_ObjStore_S3::send_response()
{
  if (op_ret < 0)
    set_req_state_err(s, op_ret);
  dump_errno(s);
  end_header(s, this, "application/xml");
}

void RGWPutImageStyle_ObjStore_S3::send_response()
{
  if (op_ret < 0)
    set_req_state_err(s, op_ret);
  dump_errno(s);
  end_header(s);
}

void RGWGetImageStyle_ObjStore_S3::send_response()
{
  if (op_ret < 0)
    set_req_state_err(s, op_ret);
  dump_errno(s);
  end_header(s, this, nullptr, NO_CONTENT_LENGTH, true);
  dump_start(s);

  if (op_ret < 0) {
    return;
  }

  s->formatter->open_object_section("result");
  s->formatter->dump_string("name", style.name);
  dump_time(s, "lastModified", &style.t);
  s->formatter->dump_string("commands", style.command);
  s->formatter->close_section(); // result
  rgw_flush_formatter_and_reset(s, s->formatter);
}

void RGWListImageStyle_ObjStore_S3::send_response()
{
  if (op_ret)
    set_req_state_err(s, op_ret);
  dump_errno(s);
  end_header(s, this, nullptr, NO_CONTENT_LENGTH, true);
  dump_start(s);

  s->formatter->open_object_section("result");
  s->formatter->dump_string("bucket", s->bucket.name);
  s->formatter->open_array_section("styleList");
  for (size_t i = 0; i < styles.size(); i++) {
    s->formatter->open_object_section("style");
    s->formatter->dump_string("name", styles[i].name);
    dump_time(s, "lastModified", &styles[i].t);
    s->formatter->dump_string("commands", styles[i].command);
    s->formatter->close_section(); // style
  }
  s->formatter->close_section(); // styleList
  s->formatter->close_section(); // result
  rgw_flush_formatter_and_reset(s, s->formatter);
}

void RGWDeleteImageStyle_ObjStore_S3::send_response()
{
  if (op_ret == 0) {
    op_ret = STATUS_NO_CONTENT;
  }
  set_req_state_err(s, op_ret);
  dump_errno(s);
  end_header(s);
}

void RGWPutImageProtection_ObjStore_S3::send_response()
{
  if (op_ret < 0)
    set_req_state_err(s, op_ret);
  dump_errno(s);
  end_header(s);
}

void RGWGetImageProtection_ObjStore_S3::send_response()
{
  if (op_ret < 0)
    set_req_state_err(s, op_ret);
  dump_errno(s);
  end_header(s, this, nullptr, NO_CONTENT_LENGTH, true);
  dump_start(s);
  if (op_ret < 0)
    return;

  s->formatter->open_object_section("result");
  s->formatter->open_array_section("resource");
  std::stringstream r_ss;
  for (const auto& r : resources) {
    r_ss << "\"" << s->bucket.name<< "/" << r << "\", ";
  }
  std::string perm_str = r_ss.str();
  s->formatter->write_raw_data(perm_str.substr(0, perm_str.size()-2).c_str());
  s->formatter->close_section(); // resource
  s->formatter->close_section(); // result
  rgw_flush_formatter_and_reset(s, s->formatter);
}

void RGWDeleteImageProtection_ObjStore_S3::send_response()
{
  if (op_ret == 0) {
    op_ret = STATUS_NO_CONTENT;
  }
  set_req_state_err(s, op_ret);
  dump_errno(s);
  end_header(s);
}

static void dump_bucket_metadata(struct req_state *s, RGWBucketEnt& bucket)
{
  dump_header(s, "X-RGW-Object-Count", static_cast<long long>(bucket.count));
  dump_header(s, "X-RGW-Bytes-Used", static_cast<long long>(bucket.size));
}

void RGWStatBucket_ObjStore_S3::send_response()
{
  if (op_ret >= 0) {
    dump_bucket_metadata(s, bucket);
  }

  set_req_state_err(s, op_ret);
  dump_errno(s);

  end_header(s, this);
  dump_start(s);
}

static int create_s3_policy(struct req_state *s, RGWRados *store,
			    RGWAccessControlPolicy_S3& s3policy,
			    ACLOwner& owner)
{
  if (s->has_acl_header) {
    if (!s->canned_acl.empty()) {
#ifdef WITH_BCEBOS
      if (s->prot_flags & RGW_REST_BOS) {
        return -EINVAL;
      } else
#endif
      {
        return -ERR_INVALID_REQUEST;
      }
    }

    s3policy.set_obj_same_with_bucket_acl(false);
    return s3policy.create_from_headers(store, s, owner);
  }

  int ret = s3policy.create_canned(owner, s->bucket_owner, s->canned_acl);
  if (ret == 0 && !s->canned_acl.empty()) {
    s3policy.set_obj_same_with_bucket_acl(false);
  }
  return ret;
}

class RGWLocationConstraint : public XMLObj
{
public:
  RGWLocationConstraint() {}
  ~RGWLocationConstraint() override {}
  bool xml_end(const char *el) override {
    if (!el)
      return false;

    location_constraint = get_data();

    return true;
  }

  string location_constraint;
};

class RGWCreateBucketConfig : public XMLObj
{
public:
  RGWCreateBucketConfig() {}
  ~RGWCreateBucketConfig() override {}
};

class RGWCreateBucketParser : public RGWXMLParser
{
  XMLObj *alloc_obj(const char *el) override {
    return new XMLObj;
  }

public:
  RGWCreateBucketParser() {}
  ~RGWCreateBucketParser() override {}

  bool get_location_constraint(string& zone_group) {
    XMLObj *config = find_first("CreateBucketConfiguration");
    if (!config)
      return false;

    XMLObj *constraint = config->find_first("LocationConstraint");
    if (!constraint)
      return false;

    zone_group = constraint->get_data();

    return true;
  }
};

int RGWCreateBucket_ObjStore_S3::get_params()
{
  RGWAccessControlPolicy_S3 s3policy(s->cct);

  int r = create_s3_policy(s, store, s3policy, s->owner);
  if (r < 0)
    return r;

  policy = s3policy;

  int len = 0;
  char *data = nullptr;

  const auto max_size = s->cct->_conf->rgw_max_put_param_size;
  op_ret = rgw_rest_read_all_input(s, &data, &len, max_size, false);

  if ((op_ret < 0) && (op_ret != -ERR_LENGTH_REQUIRED))
    return op_ret;

  auto data_deleter = std::unique_ptr<char, decltype(free)*>{data, free};

  const int auth_ret = do_aws4_auth_completion();
  if (auth_ret < 0) {
    return auth_ret;
  }

  bufferptr in_ptr(data, len);
  in_data.append(in_ptr);

  if (len) {
#ifdef WITH_BCEBOS
    if (s->prot_flags & RGW_REST_BOS) {
      RGWCreateBucketJSONParser parser;

      if (!parser.valid_placement_rule(data, len)) {
        ldout(s->cct, 0) << __func__ << " ERROR: Input not match specify location constraint" << dendl;
        return -EINVAL;
      }
      placement_rule.clear();
      if (parser.is_enable_dedicated()) {
        // use user name
        placement_rule.name = s->user->user_id.id;
        bufferlist bl;
        bl.append("true");
        emplace_attr(RGW_ATTR_DEDICATED, std::move(bl));
      }
      // bosapi use default zonegroup
      location_constraint = store->get_zonegroup().api_name;

      ldout(s->cct, 10) << __func__ << " Create bucket " << s->bucket.name
        << ", location constraint: " << location_constraint << dendl;
    } else 
#endif
    {
      RGWCreateBucketParser parser;

      if (!parser.init()) {
        ldout(s->cct, 0) << "ERROR: failed to initialize parser" << dendl;
        return -EIO;
      }

      bool success = parser.parse(data, len, 1);
      ldout(s->cct, 20) << "create bucket input data=" << data << dendl;

      if (!success) {
        ldout(s->cct, 0) << "failed to parse input: " << data << dendl;
        return -EINVAL;
      }

      if (!parser.get_location_constraint(location_constraint)) {
        ldout(s->cct, 0) << "provided input did not specify location constraint correctly" << dendl;
        return -EINVAL;
      }

      ldout(s->cct, 10) << "create bucket location constraint: "
        << location_constraint << dendl;
    }
  }

  size_t pos = location_constraint.find(':');
  if (pos != string::npos) {
    placement_rule.from_str(location_constraint.substr(pos + 1), ':');
    location_constraint = location_constraint.substr(0, pos);
  }

  auto iter = s->info.x_meta_map.find("x-amz-bucket-object-lock-enabled");
  if (iter != s->info.x_meta_map.end()) {
    if (!boost::algorithm::iequals(iter->second, "true") && !boost::algorithm::iequals(iter->second, "false")) {
      return -EINVAL;
    }
    obj_lock_enabled = boost::algorithm::iequals(iter->second, "true");
  }

  return 0;
}

void RGWCreateBucket_ObjStore_S3::send_response()
{
  if (op_ret == -ERR_BUCKET_EXISTS)
    op_ret = 0;
  if (op_ret)
    set_req_state_err(s, op_ret);
  dump_errno(s);
  end_header(s);

  if (op_ret < 0)
    return;

  if (s->system_request) {
    JSONFormatter f; /* use json formatter for system requests output */

    f.open_object_section("info");
    encode_json("entry_point_object_ver", ep_objv, &f);
    encode_json("object_ver", info.objv_tracker.read_version, &f);
    encode_json("bucket_info", info, &f);
    f.close_section();
    rgw_flush_formatter_and_reset(s, &f);
  }
}

std::pair<AwsVersion, AwsRoute>
discover_aws_flavour(const req_info& info)
{
  using rgw::auth::s3::AWS4_HMAC_SHA256_STR;

  AwsVersion version = AwsVersion::UNKNOWN;
  AwsRoute route = AwsRoute::UNKNOWN;

  const char* http_auth = info.env->get("HTTP_AUTHORIZATION");
  if (http_auth && http_auth[0]) {
    /* Authorization in Header */
    route = AwsRoute::HEADERS;

    if (!strncmp(http_auth, AWS4_HMAC_SHA256_STR,
                 strlen(AWS4_HMAC_SHA256_STR))) {
      /* AWS v4 */
      version = AwsVersion::V4;
    } else if (!strncmp(http_auth, "AWS ", 4)) {
      /* AWS v2 */
      version = AwsVersion::V2;
    }
  } else {
    route = AwsRoute::QUERY_STRING;

    if (info.args.get("X-Amz-Algorithm") == AWS4_HMAC_SHA256_STR) {
      /* AWS v4 */
      version = AwsVersion::V4;
    } else if (!info.args.get("AWSAccessKeyId").empty()) {
      /* AWS v2 */
      version = AwsVersion::V2;
    }
  }

  return std::make_pair(version, route);
}

void RGWDeleteBucket_ObjStore_S3::send_response()
{
  int r = op_ret;
  if (!r)
    r = STATUS_NO_CONTENT;

  set_req_state_err(s, r);
  dump_errno(s);
  end_header(s, this);

  if (s->system_request) {
    JSONFormatter f; /* use json formatter for system requests output */

    f.open_object_section("info");
    encode_json("object_ver", objv_tracker.read_version, &f);
    f.close_section();
    rgw_flush_formatter_and_reset(s, &f);
  }
}

static inline void map_qs_metadata(struct req_state* s)
{
  /* merge S3 valid user metadata from the query-string into
   * x_meta_map, which maps them to attributes */
  const auto& params = const_cast<RGWHTTPArgs&>(s->info.args).get_params();
  for (const auto& elt : params) {
    std::string k = boost::algorithm::to_lower_copy(elt.first);
    if (k.find("x-amz-meta-") == /* offset */ 0) {
      add_amz_meta_header(s->info.x_meta_map, k, elt.second);
    }
#ifdef WITH_BCEBOS
    if (k.find("x-bce-meta-") == 0) {
      k = k.erase(0, 5);
      k = "x-amz" + k;
      add_amz_meta_header(s->info.x_meta_map, k, elt.second);
    }
#endif
  }
}

int RGWPutObj_ObjStore_S3::get_params()
{
#ifdef WITH_BCEBOS
  if (!s->length && !(s->prot_flags & RGW_REST_BOS))
#else
  if (!s->length)
#endif
    return -ERR_LENGTH_REQUIRED;

  RGWObjectCtx& obj_ctx = *static_cast<RGWObjectCtx *>(s->obj_ctx);
  size_t pos;
  int ret;

  map_qs_metadata(s);

  RGWAccessControlPolicy_S3 s3policy(s->cct);
#ifdef WITH_BCEBOS
  if (s->prot_flags & RGW_REST_BOS) {
    ret = create_s3_policy(s, store, s3policy, s->bucket_owner);
  } else
#endif
  {
    ret = create_s3_policy(s, store, s3policy, s->owner);
  }
  if (ret < 0)
    return ret;

  policy = s3policy;

#ifdef WITH_BCEBOS
  if (s->prot_flags & RGW_REST_BOS) {
    if_match = s->info.env->get("HTTP_X_BCE_COPY_SOURCE_IF_MATCH");
    if_nomatch = s->info.env->get("HTTP_X_BCE_COPY_SOURCE_IF_NONE_MATCH");
    if_mod = s->info.env->get("HTTP_X_BCE_COPY_SOURCE_IF_MODIFIED_SINCE");
    if_unmod = s->info.env->get("HTTP_X_BCE_COPY_SOURCE_IF_UNMODIFIED_SINCE");
    if (s->info.env->exists("HTTP_X_BCE_COPY_SOURCE"))
      copy_source = s->info.env->get("HTTP_X_BCE_COPY_SOURCE", "");
    if (s->info.env->exists("HTTP_X_BCE_COPY_SOURCE_RANGE"))
      copy_source_range = s->info.env->get("HTTP_X_BCE_COPY_SOURCE_RANGE");
  } else
#endif
  {
    if_match = s->info.env->get("HTTP_IF_MATCH");
    if_nomatch = s->info.env->get("HTTP_IF_NONE_MATCH");
    if_mod = s->info.env->get("HTTP_IF_MODIFIED_SINCE");
    if_unmod = s->info.env->get("HTTP_IF_UNMODIFIED_SINCE");
    copy_source = s->info.env->get("HTTP_X_AMZ_COPY_SOURCE", "");
    copy_source_range = s->info.env->get("HTTP_X_AMZ_COPY_SOURCE_RANGE");
  }

  /* handle x-amz-copy-source */
  boost::string_view cs_view(copy_source);
  if (! cs_view.empty()) {
    if (cs_view[0] == '/')
      cs_view.remove_prefix(1);
    copy_source_bucket_name = cs_view.to_string();
    pos = copy_source_bucket_name.find("/");
    if (pos == std::string::npos) {
      ret = -EINVAL;
      ldout(s->cct, 5) << "x-amz-copy-source bad format" << dendl;
      return ret;
    }
    copy_source_object_name =
      copy_source_bucket_name.substr(pos + 1, copy_source_bucket_name.size());
    copy_source_bucket_name = copy_source_bucket_name.substr(0, pos);
#define VERSION_ID_STR "?versionId="
    pos = copy_source_object_name.find(VERSION_ID_STR);
    if (pos == std::string::npos) {
      copy_source_object_name = url_decode(copy_source_object_name);
    } else {
      copy_source_version_id =
	copy_source_object_name.substr(pos + sizeof(VERSION_ID_STR) - 1);
      copy_source_object_name =
	url_decode(copy_source_object_name.substr(0, pos));
    }
    pos = copy_source_bucket_name.find(":");
    if (pos == std::string::npos) {
       copy_source_tenant_name = s->src_tenant_name;
    } else {
       copy_source_tenant_name = copy_source_bucket_name.substr(0, pos);
       copy_source_bucket_name = copy_source_bucket_name.substr(pos + 1, copy_source_bucket_name.size());
       if (copy_source_bucket_name.empty()) {
         ret = -EINVAL;
         ldout(s->cct, 5) << "source bucket name is empty" << dendl;
         return ret;
       }
    }
    ret = store->get_bucket_info(obj_ctx,
                                 copy_source_tenant_name,
                                 copy_source_bucket_name,
                                 copy_source_bucket_info,
                                 NULL, &src_attrs);
    if (ret < 0) {
#ifdef WITH_BCEBOS
      if ((s->prot_flags & RGW_REST_BOS) && ret == -ENOENT) {
        ret = -ERR_NO_SUCH_BUCKET;
      }
#endif
      ldout(s->cct, 5) << __func__ << "(): get_bucket_info() returned ret=" << ret << dendl;
      return ret;
    }

    /* handle x-amz-copy-source-range */

    if (copy_source_range) {
      string range = copy_source_range;
      pos = range.find("=");
      if (pos == std::string::npos) {
        ret = -ERANGE;
        ldout(s->cct, 5) << "x-amz-copy-source-range bad format" << dendl;
        return ret;
      }
      range = range.substr(pos + 1);
      pos = range.find("-");
      if (pos == std::string::npos) {
        ret = -ERANGE;
        ldout(s->cct, 5) << "x-amz-copy-source-range bad format" << dendl;
        return ret;
      }
      string first = range.substr(0, pos);
      string last = range.substr(pos + 1);
      char* err = nullptr;
      copy_source_range_fst = strtoull(first.c_str(), &err, 10);
      if (*err) {
        ldout(s->cct, 5) << __func__ << "() ERROR: Invalid copy source range first value." << dendl;
        ret = -ERANGE;
        return ret;
      }
      copy_source_range_lst = strtoull(last.c_str(), &err, 10);
      if (*err) {
        ldout(s->cct, 5) << __func__ << "() ERROR: Invalid copy source range second value." << dendl;
        ret = -ERANGE;
        return ret;
      }
    }

  } /* copy_source */

  /* handle object tagging */
  auto tag_str = s->info.env->get("HTTP_X_AMZ_TAGGING");
  if (tag_str){
    obj_tags = std::make_unique<RGWObjTags>();
    ret = obj_tags->set_from_string(tag_str);
    if (ret < 0){
      ldout(s->cct,0) << "setting obj tags failed with " << ret << dendl;
      if (ret == -ERR_INVALID_TAG){
        ret = -EINVAL; //s3 returns only -EINVAL for PUT requests
      }

      return ret;
    }
  }

  //handle object lock
  ret = get_object_lock_configure(s, &obj_retention, &obj_legal_hold);
  if (ret < 0) {
    return ret;
  }
  return RGWPutObj_ObjStore::get_params();
}

int RGWPutObj_ObjStore_S3::get_data(bufferlist& bl)
{
  const int ret = RGWPutObj_ObjStore::get_data(bl);
  if (ret == 0) {
    const int ret_auth = do_aws4_auth_completion();
    if (ret_auth < 0) {
      return ret_auth;
    }
  }

  return ret;
}

static int get_success_retcode(int code)
{
  switch (code) {
    case 201:
      return STATUS_CREATED;
    case 204:
      return STATUS_NO_CONTENT;
  }
  return 0;
}

void RGWPutObj_ObjStore_S3::send_response()
{
  if (op_ret) {
    // for bucket namespace
    if (op_ret == -EEXIST) {
      op_ret = -ERROR_BUCKET_NAMESPACE_NAME_CONFLICT;
    }

    if (op_ret == -ENOENT && multipart && (s->prot_flags & RGW_REST_BOS)) {
      op_ret = -ERR_NO_SUCH_UPLOAD;
    }

    set_req_state_err(s, op_ret);
    dump_errno(s);
  } else {
    if (s->cct->_conf->rgw_s3_success_create_obj_status) {
      op_ret = get_success_retcode(
	s->cct->_conf->rgw_s3_success_create_obj_status);
      set_req_state_err(s, op_ret);
    }

    string expires = get_s3_expiration_header(s, mtime);

    if (copy_source.empty()) {
      dump_errno(s);
      dump_etag(s, etag);
      dump_header_if_nonempty(s, "x-amz-version-id", version_id);
      dump_header_if_nonempty(s, "x-amz-expiration", expires);
#ifdef WITH_BCEBOS
      dump_header_if_nonempty(s, "Content-MD5", bos_md5);
#endif
      for (auto &it : crypt_http_responses)
        dump_header(s, it.first, it.second);
      if (multipart && !s->dest_placement.storage_class.empty() && 
          s->dest_placement.storage_class != "STANDARD") {
#ifdef WITH_BCEBOS
        if (s->prot_flags & RGW_REST_BOS) {
          dump_header(s, RGW_BCE_STORAGE_CLASS, s->dest_placement.storage_class);
        } else
#endif
        {
          dump_header(s, RGW_AMZ_STORAGE_CLASS, s->dest_placement.storage_class);
        }

      }
    } else {
      dump_errno(s);
      dump_header_if_nonempty(s, "x-amz-version-id", version_id);
      dump_header_if_nonempty(s, "x-amz-expiration", expires);

      end_header(s, this, nullptr, NO_CONTENT_LENGTH, true);

      dump_start(s);
      struct tm tmp;
      utime_t ut(mtime);
      time_t secs = (time_t)ut.sec();
      gmtime_r(&secs, &tmp);
      char buf[TIME_BUF_SIZE];
      s->formatter->open_object_section_in_ns("CopyPartResult",
          "http://s3.amazonaws.com/doc/2006-03-01/");
#ifdef WITH_BCEBOS
      if (s->prot_flags & RGW_REST_BOS) {
        if (strftime(buf, sizeof(buf), "%Y-%m-%dT%T.000Z", &tmp) > 0) {
          s->formatter->dump_string("lastModified", buf);
        }
        s->formatter->dump_string("eTag", etag);
      } else
#endif
      {
        if (strftime(buf, sizeof(buf), "%Y-%m-%dT%T.000Z", &tmp) > 0) {
          s->formatter->dump_string("LastModified", buf);
        }
        s->formatter->dump_string("ETag", etag);
      }
      s->formatter->close_section();
      rgw_flush_formatter_and_reset(s, s->formatter);
      return;
    }
  }
  if (append) {
    if (0 == op_ret || -ERR_OFFSET_INCORRECT == op_ret) {
      dump_header(s, "x-bce-next-append-offset", cur_accounted_size);
    }
  }
  if (s->system_request && !real_clock::is_zero(mtime)) {
    dump_epoch_header(s, "Rgwx-Mtime", mtime);
  }

  if (op_ret == -ERR_CALLBACK_FAILED) {
    end_header(s, this, nullptr, NO_CONTENT_LENGTH, false, false, "", true);
  } else {
    end_header(s, this);
  }

  if (!s->response_body.is_zero()) {
    dump_start(s);
    s->formatter->open_object_section_in_ns("callback", XMLNS_AWS_S3);
    s->formatter->dump_string("result", s->response_body.to_str().c_str());
    s->formatter->close_section();
    rgw_flush_formatter_and_reset(s, s->formatter);
  }
}

static inline int get_obj_attrs(RGWRados *store, struct req_state *s, rgw_obj& obj, map<string, bufferlist>& attrs)
{
  RGWRados::Object op_target(store, s->bucket_info, *static_cast<RGWObjectCtx *>(s->obj_ctx), obj);
  RGWRados::Object::Read read_op(&op_target);

  read_op.params.attrs = &attrs;

  return read_op.prepare();
}

static inline void set_attr(map<string, bufferlist>& attrs, const char* key, const std::string& value)
{
  bufferlist bl;
  encode(value,bl);
  attrs.emplace(key, std::move(bl));
}

static inline void set_attr(map<string, bufferlist>& attrs, const char* key, const char* value)
{
  bufferlist bl;
  encode(value,bl);
  attrs.emplace(key, std::move(bl));
}

int RGWPutObj_ObjStore_S3::get_decrypt_filter(
    std::unique_ptr<RGWGetObj_Filter>* filter,
    RGWGetObj_Filter* cb,
    map<string, bufferlist>& attrs,
    bufferlist* manifest_bl)
{
  std::map<std::string, std::string> crypt_http_responses_unused;

  int res = 0;
  std::unique_ptr<BlockCrypt> block_crypt;
#ifdef WITH_BCEBOS
  if (s->prot_flags & RGW_REST_BOS) {
    res = rgw_bos_prepare_decrypt(s, attrs, &block_crypt, crypt_http_responses_unused);
  } else
#endif
  {
    res = rgw_s3_prepare_decrypt(s, attrs, &block_crypt, crypt_http_responses_unused);
  }
  if (res == 0) {
    if (block_crypt != nullptr) {
      auto f = std::unique_ptr<RGWGetObj_BlockDecrypt>(new RGWGetObj_BlockDecrypt(s->cct, cb, std::move(block_crypt)));
      //RGWGetObj_BlockDecrypt* f = new RGWGetObj_BlockDecrypt(s->cct, cb, std::move(block_crypt));
      if (f != nullptr) {
        if (manifest_bl != nullptr) {
          res = f->read_manifest(*manifest_bl);
          if (res == 0) {
            *filter = std::move(f);
          }
        }
      }
    }
  }
  return res;
}

int RGWPutObj_ObjStore_S3::get_encrypt_filter(
    std::unique_ptr<RGWPutObjDataProcessor>* filter,
    RGWPutObjDataProcessor* cb)
{
  int res = 0;
  RGWPutObjProcessor_Multipart* multi_processor=dynamic_cast<RGWPutObjProcessor_Multipart*>(cb);
  RGWPutObjProcessor_Append* append_processor=dynamic_cast<RGWPutObjProcessor_Append*>(cb);
  if (multi_processor != nullptr) {
    RGWMPObj* mp = nullptr;
    multi_processor->get_mp(&mp);
    if (mp != nullptr) {
      map<string, bufferlist> xattrs;
      string meta_oid;
      meta_oid = mp->get_meta();

      rgw_obj obj;
      obj.init_ns(s->bucket, meta_oid, RGW_OBJ_NS_MULTIPART);
      obj.set_in_extra_data(true);
      res = get_obj_attrs(store, s, obj, xattrs);

      if (res == 0) {
        //get object storage class, storage-class was set when InitMultipart
        auto iter = xattrs.find(RGW_ATTR_STORAGE_CLASS);
        if (iter != xattrs.end()) {
          s->dest_placement.storage_class = rgw_bl_to_str(iter->second);
        } else {
          s->dest_placement.storage_class.clear();
        }
        multi_processor->set_placement_rule(s->dest_placement);

        std::unique_ptr<BlockCrypt> block_crypt;
        /* We are adding to existing object.
         * We use crypto mode that configured as if we were decrypting. */
#ifdef WITH_BCEBOS
        if (s->prot_flags & RGW_REST_BOS) {
          res = rgw_bos_prepare_decrypt(s, xattrs, &block_crypt, crypt_http_responses);
        } else
#endif
        {
          res = rgw_s3_prepare_decrypt(s, xattrs, &block_crypt, crypt_http_responses);
        }
        if (res == 0 && block_crypt != nullptr)
          *filter = std::unique_ptr<RGWPutObj_BlockEncrypt>(
              new RGWPutObj_BlockEncrypt(s->cct, cb, std::move(block_crypt)));
      }
    }
  } else if (append_processor != nullptr) {
    map<string, bufferlist> xattrs;
    rgw_obj obj(s->bucket, s->object);
    store->set_atomic(s->obj_ctx, obj);

    if (append_processor->get_offset() != 0) {
      res = get_obj_attrs(store, s, obj, xattrs);
    }
    if (res == 0) {
      std::unique_ptr<BlockCrypt> block_crypt;
      if (s->prot_flags & RGW_REST_BOS) {
        if (append_processor->get_offset() != 0) {
          res = rgw_bos_prepare_decrypt(s, xattrs, &block_crypt, crypt_http_responses);
        } else {
          res = rgw_bos_prepare_encrypt(s, attrs, nullptr, &block_crypt, crypt_http_responses);
        }
      } else {
        if (append_processor->get_offset() != 0) {
          res = rgw_s3_prepare_decrypt(s, xattrs, &block_crypt, crypt_http_responses);
        } else {
          res = rgw_s3_prepare_encrypt(s, attrs, nullptr, &block_crypt, crypt_http_responses);
        }
      }
      if (res == 0 && block_crypt != nullptr)
        *filter = std::unique_ptr<RGWPutObj_BlockEncrypt>(
            new RGWPutObj_BlockEncrypt(s->cct, cb, std::move(block_crypt)));

    }
    /* it is ok, to not have encryption at all */
  } else {
    std::unique_ptr<BlockCrypt> block_crypt;
#ifdef WITH_BCEBOS
    if (s->prot_flags & RGW_REST_BOS) {
      res = rgw_bos_prepare_encrypt(s, attrs, nullptr, &block_crypt, crypt_http_responses);
    } else
#endif
    {
      res = rgw_s3_prepare_encrypt(s, attrs, nullptr, &block_crypt, crypt_http_responses);
    }
    if (res == 0 && block_crypt != nullptr) {
      *filter = std::unique_ptr<RGWPutObj_BlockEncrypt>(
          new RGWPutObj_BlockEncrypt(s->cct, cb, std::move(block_crypt)));
    }
  }
  return res;
}

void RGWPostObj_ObjStore_S3::rebuild_key(string& key)
{
  static string var = "${filename}";
  int pos = key.find(var);
  if (pos < 0)
    return;

  string new_key = key.substr(0, pos);
  new_key.append(filename);
  new_key.append(key.substr(pos + var.size()));

  key = new_key;
}

std::string RGWPostObj_ObjStore_S3::get_current_filename() const
{
  return s->object.name;
}

std::string RGWPostObj_ObjStore_S3::get_current_content_type() const
{
  return content_type;
}

int RGWPostObj_ObjStore_S3::get_params()
{
  op_ret = RGWPostObj_ObjStore::get_params();
  if (op_ret < 0) {
    return op_ret;
  }

  map_qs_metadata(s);

  ldout(s->cct, 20) << "adding bucket to policy env: " << s->bucket.name
		    << dendl;
  env.add_var("bucket", s->bucket.name);

  bool done;
  do {
    struct post_form_part part;
    int r = read_form_part_header(&part, done);
    if (r < 0)
      return r;

    if (s->cct->_conf->subsys.should_gather<ceph_subsys_rgw, 20>()) {
      ldout(s->cct, 20) << "read part header -- part.name="
                        << part.name << dendl;

      for (const auto& pair : part.fields) {
        ldout(s->cct, 20) << "field.name=" << pair.first << dendl;
        ldout(s->cct, 20) << "field.val=" << pair.second.val << dendl;
        ldout(s->cct, 20) << "field.params:" << dendl;

        for (const auto& param_pair : pair.second.params) {
          ldout(s->cct, 20) << " " << param_pair.first
                            << " -> " << param_pair.second << dendl;
        }
      }
    }

    if (done) { /* unexpected here */
      err_msg = "Malformed request";
      return -EINVAL;
    }

    if (stringcasecmp(part.name, "file") == 0) { /* beginning of data transfer */
      struct post_part_field& field = part.fields["Content-Disposition"];
      map<string, string>::iterator iter = field.params.find("filename");
      if (iter != field.params.end()) {
	filename = iter->second;
      }
      parts[part.name] = part;
      break;
    }

    bool boundary;
    uint64_t chunk_size = s->cct->_conf->rgw_max_chunk_size;
    r = read_data(part.data, chunk_size, boundary, done);
    if (r < 0 || !boundary) {
      err_msg = "Couldn't find boundary";
      return -EINVAL;
    }
    parts[part.name] = part;
    string part_str(part.data.c_str(), part.data.length());
    env.add_var(part.name, part_str);
  } while (!done);

  string object_str;
  if (!part_str(parts, "key", &object_str)) {
    err_msg = "Key not specified";
    return -EINVAL;
  }

  s->object = rgw_obj_key(object_str);

  rebuild_key(s->object.name);

  if (s->object.empty()) {
    err_msg = "Empty object name";
    return -EINVAL;
  }

  env.add_var("key", s->object.name);

  part_str(parts, "Content-Type", &content_type);

  /* AWS permits POST without Content-Type: http://tracker.ceph.com/issues/20201 */
  if (! content_type.empty()) {
    env.add_var("Content-Type", content_type);
  }

  map<string, struct post_form_part, ltstr_nocase>::iterator piter =
    parts.upper_bound(RGW_AMZ_META_PREFIX);
  for (; piter != parts.end(); ++piter) {
    string n = piter->first;
    if (strncasecmp(n.c_str(), RGW_AMZ_META_PREFIX,
		    sizeof(RGW_AMZ_META_PREFIX) - 1) != 0)
      break;

    string attr_name = RGW_ATTR_PREFIX;
    attr_name.append(n);

    /* need to null terminate it */
    bufferlist& data = piter->second.data;
    string str = string(data.c_str(), data.length());

    bufferlist attr_bl;
    attr_bl.append(str.c_str(), str.size() + 1);

    attrs[attr_name] = attr_bl;
  }
  // TODO: refactor this and the above loop to share code
  piter = parts.find(RGW_AMZ_WEBSITE_REDIRECT_LOCATION);
  if (piter != parts.end()) {
    string n = piter->first;
    string attr_name = RGW_ATTR_PREFIX;
    attr_name.append(n);
    /* need to null terminate it */
    bufferlist& data = piter->second.data;
    string str = string(data.c_str(), data.length());

    bufferlist attr_bl;
    attr_bl.append(str.c_str(), str.size() + 1);

    attrs[attr_name] = attr_bl;
  }

  int r = get_policy();
  if (r < 0)
    return r;

  r = get_tags();
  if (r < 0)
    return r;

  min_len = post_policy.min_length;
  max_len = post_policy.max_length;

  //handle object lock
  r = get_object_lock_configure(s, &obj_retention, &obj_legal_hold);
  if (r < 0) {
    return r;
  }
  return 0;
}

int RGWPostObj_ObjStore_S3::get_tags()
{
  string tags_str;
  if (part_str(parts, "tagging", &tags_str)) {
    RGWObjTagsXMLParser parser;
    if (!parser.init()){
      ldout(s->cct, 0) << "Couldn't init RGWObjTags XML parser" << dendl;
      err_msg = "Server couldn't process the request";
      return -EINVAL; // TODO: This class of errors in rgw code should be a 5XX error
    }
    if (!parser.parse(tags_str.c_str(), tags_str.size(), 1)) {
      ldout(s->cct,0 ) << "Invalid Tagging XML" << dendl;
      err_msg = "Invalid Tagging XML";
      return -EINVAL;
    }

    RGWObjTagSet_S3 *obj_tags_s3;
    RGWObjTagging_S3 *tagging;

    tagging = static_cast<RGWObjTagging_S3 *>(parser.find_first("Tagging"));
    obj_tags_s3 = static_cast<RGWObjTagSet_S3 *>(tagging->find_first("TagSet"));
    if(!obj_tags_s3){
      return -ERR_MALFORMED_XML;
    }

    RGWObjTags obj_tags;
    int r = obj_tags_s3->rebuild(obj_tags);
    if (r < 0)
      return r;

    bufferlist tags_bl;
    obj_tags.encode(tags_bl);
    ldout(s->cct, 20) << "Read " << obj_tags.count() << "tags" << dendl;
    attrs[RGW_ATTR_TAGS] = tags_bl;
  }


  return 0;
}

int RGWPostObj_ObjStore_S3::get_policy()
{
  if (part_bl(parts, "policy", &s->auth.s3_postobj_creds.encoded_policy)) {
    bool aws4_auth = false;

    /* x-amz-algorithm handling */
    using rgw::auth::s3::AWS4_HMAC_SHA256_STR;
    if ((part_str(parts, "x-amz-algorithm", &s->auth.s3_postobj_creds.x_amz_algorithm)) &&
        (s->auth.s3_postobj_creds.x_amz_algorithm == AWS4_HMAC_SHA256_STR)) {
      ldout(s->cct, 0) << "Signature verification algorithm AWS v4 (AWS4-HMAC-SHA256)" << dendl;
      aws4_auth = true;
    } else {
      ldout(s->cct, 0) << "Signature verification algorithm AWS v2" << dendl;
    }

    // check that the signature matches the encoded policy
    if (aws4_auth) {
      /* AWS4 */

      /* x-amz-credential handling */
      if (!part_str(parts, "x-amz-credential",
                    &s->auth.s3_postobj_creds.x_amz_credential)) {
        ldout(s->cct, 0) << "No S3 aws4 credential found!" << dendl;
        err_msg = "Missing aws4 credential";
        return -EINVAL;
      }

      /* x-amz-signature handling */
      if (!part_str(parts, "x-amz-signature",
                    &s->auth.s3_postobj_creds.signature)) {
        ldout(s->cct, 0) << "No aws4 signature found!" << dendl;
        err_msg = "Missing aws4 signature";
        return -EINVAL;
      }

      /* x-amz-date handling */
      std::string received_date_str;
      if (!part_str(parts, "x-amz-date", &received_date_str)) {
        ldout(s->cct, 0) << "No aws4 date found!" << dendl;
        err_msg = "Missing aws4 date";
        return -EINVAL;
      }
    } else {
      /* AWS2 */

      // check that the signature matches the encoded policy
      if (!part_str(parts, "AWSAccessKeyId",
                    &s->auth.s3_postobj_creds.access_key)) {
        ldout(s->cct, 0) << "No S3 aws2 access key found!" << dendl;
        err_msg = "Missing aws2 access key";
        return -EINVAL;
      }

      if (!part_str(parts, "signature", &s->auth.s3_postobj_creds.signature)) {
        ldout(s->cct, 0) << "No aws2 signature found!" << dendl;
        err_msg = "Missing aws2 signature";
        return -EINVAL;
      }
    }

    /* FIXME: this is a makeshift solution. The browser upload authentication will be
     * handled by an instance of rgw::auth::Completer spawned in Handler's authorize()
     * method. */
    const int ret = rgw::auth::Strategy::apply(auth_registry_ptr->get_s3_post(), s);
    if (ret != 0) {
      if (ret != -ETIMEDOUT) {
        return -EACCES;
      } else {
        return ret;
      }
    } else {
      /* Populate the owner info. */
      s->owner.set_id(s->user->user_id);
      s->owner.set_name(s->user->display_name);
      ldout(s->cct, 20) << "Successful Signature Verification!" << dendl;
    }

    ceph::bufferlist decoded_policy;
    try {
      decoded_policy.decode_base64(s->auth.s3_postobj_creds.encoded_policy);
    } catch (buffer::error& err) {
      ldout(s->cct, 0) << "failed to decode_base64 policy" << dendl;
      err_msg = "Could not decode policy";
      return -EINVAL;
    }

    decoded_policy.append('\0'); // NULL terminate
    ldout(s->cct, 20) << "POST policy: " << decoded_policy.c_str() << dendl;


    int r = post_policy.from_json(decoded_policy, err_msg);
    if (r < 0) {
      if (err_msg.empty()) {
	err_msg = "Failed to parse policy";
      }
      ldout(s->cct, 0) << "failed to parse policy" << dendl;
      return -EINVAL;
    }

    if (aws4_auth) {
      /* AWS4 */
      post_policy.set_var_checked("x-amz-signature");
    } else {
      /* AWS2 */
      post_policy.set_var_checked("AWSAccessKeyId");
      post_policy.set_var_checked("signature");
    }
    post_policy.set_var_checked("policy");

    r = post_policy.check(&env, err_msg);
    if (r < 0) {
      if (err_msg.empty()) {
	err_msg = "Policy check failed";
      }
      ldout(s->cct, 0) << "policy check failed" << dendl;
      return r;
    }

  } else {
    ldout(s->cct, 0) << "No attached policy found!" << dendl;
  }

  string canned_acl;
  part_str(parts, "acl", &canned_acl);

  RGWAccessControlPolicy_S3 s3policy(s->cct);
  ldout(s->cct, 20) << "canned_acl=" << canned_acl << dendl;
  if (s3policy.create_canned(s->owner, s->bucket_owner, canned_acl) < 0) {
    err_msg = "Bad canned ACLs";
    return -EINVAL;
  }

  policy = s3policy;

  return 0;
}

int RGWPostObj_ObjStore_S3::complete_get_params()
{
  bool done;
  do {
    struct post_form_part part;
    int r = read_form_part_header(&part, done);
    if (r < 0) {
      return r;
    }

    ceph::bufferlist part_data;
    bool boundary;
    uint64_t chunk_size = s->cct->_conf->rgw_max_chunk_size;
    r = read_data(part.data, chunk_size, boundary, done);
    if (r < 0 || !boundary) {
      return -EINVAL;
    }

    /* Just reading the data but not storing any results of that. */
  } while (!done);

  return 0;
}

int RGWPostObj_ObjStore_S3::get_data(ceph::bufferlist& bl, bool& again)
{
  bool boundary;
  bool done;

  const uint64_t chunk_size = s->cct->_conf->rgw_max_chunk_size;
  int r = read_data(bl, chunk_size, boundary, done);
  if (r < 0) {
    return r;
  }

  if (boundary) {
    if (!done) {
      /* Reached end of data, let's drain the rest of the params */
      r = complete_get_params();
      if (r < 0) {
       return r;
      }
    }
  }

  again = !boundary;
  return bl.length();
}

void RGWPostObj_ObjStore_S3::send_response()
{
  if (op_ret == 0 && parts.count("success_action_redirect")) {
    string redirect;

    part_str(parts, "success_action_redirect", &redirect);

    string tenant;
    string bucket;
    string key;
    string etag_str = "\"";

    etag_str.append(etag);
    etag_str.append("\"");

    string etag_url;

    url_encode(s->bucket_tenant, tenant); /* surely overkill, but cheap */
    url_encode(s->bucket_name, bucket);
    url_encode(s->object.name, key);
    url_encode(etag_str, etag_url);

    if (!s->bucket_tenant.empty()) {
      /*
       * What we really would like is to quaily the bucket name, so
       * that the client could simply copy it and paste into next request.
       * Unfortunately, in S3 we cannot know if the client will decide
       * to come through DNS, with "bucket.tenant" sytanx, or through
       * URL with "tenant\bucket" syntax. Therefore, we provide the
       * tenant separately.
       */
      redirect.append("?tenant=");
      redirect.append(tenant);
      redirect.append("&bucket=");
      redirect.append(bucket);
    } else {
      redirect.append("?bucket=");
      redirect.append(bucket);
    }
    redirect.append("&key=");
    redirect.append(key);
    redirect.append("&etag=");
    redirect.append(etag_url);

    int r = check_utf8(redirect.c_str(), redirect.size());
    if (r < 0) {
      op_ret = r;
      goto done;
    }
    dump_redirect(s, redirect);
    op_ret = STATUS_REDIRECT;
  } else if (op_ret == 0 && parts.count("success_action_status")) {
    string status_string;
    uint32_t status_int;

    part_str(parts, "success_action_status", &status_string);

    int r = stringtoul(status_string, &status_int);
    if (r < 0) {
      op_ret = r;
      goto done;
    }

    switch (status_int) {
      case 200:
	break;
      case 201:
	op_ret = STATUS_CREATED;
	break;
      default:
	op_ret = STATUS_NO_CONTENT;
	break;
    }
  } else if (! op_ret) {
    op_ret = STATUS_NO_CONTENT;
  }

done:
  if (op_ret == STATUS_CREATED) {
    for (auto &it : crypt_http_responses)
      dump_header(s, it.first, it.second);
    s->formatter->open_object_section("PostResponse");
    if (g_conf->rgw_dns_name.length())
      s->formatter->dump_format("Location", "%s/%s",
				s->info.script_uri.c_str(),
				s->object.name.c_str());
    if (!s->bucket_tenant.empty())
      s->formatter->dump_string("Tenant", s->bucket_tenant);
    s->formatter->dump_string("Bucket", s->bucket_name);
    s->formatter->dump_string("Key", s->object.name);
    if (!s->response_body.is_zero()) {
      s->formatter->dump_string("response_body", s->response_body.to_str().c_str());
    }
    s->formatter->close_section();
  }
  s->err.message = err_msg;

  set_req_state_err(s, op_ret);
  dump_errno(s);
  if (op_ret >= 0) {
    dump_content_length(s, s->formatter->get_len());
  }

#ifdef WITH_BCEBOS
  dump_header_if_nonempty(s, "Content-MD5", bos_md5);
#endif

  if (op_ret == -ERR_CALLBACK_FAILED) {
    end_header(s, this, nullptr, NO_CONTENT_LENGTH, false, false, "", true);
  } else {
    end_header(s, this);
  }

  if (op_ret != STATUS_CREATED)
    return;


  rgw_flush_formatter_and_reset(s, s->formatter);
}

int RGWPostObj_ObjStore_S3::get_encrypt_filter(
    std::unique_ptr<RGWPutObjDataProcessor>* filter, RGWPutObjDataProcessor* cb)
{
  int res = 0;
  std::unique_ptr<BlockCrypt> block_crypt;
#ifdef WITH_BCBOS
  if (s->prot_flags & RGW_REST_BOS) {
    res = rgw_bos_prepare_encrypt(s, attrs, &parts, &block_crypt, crypt_http_responses);
  } else
#endif
  {
    res = rgw_s3_prepare_encrypt(s, attrs, &parts, &block_crypt, crypt_http_responses);
  }
  if (res == 0 && block_crypt != nullptr) {
    *filter = std::unique_ptr<RGWPutObj_BlockEncrypt>(
        new RGWPutObj_BlockEncrypt(s->cct, cb, std::move(block_crypt)));
  }
  else
    *filter = nullptr;
  return res;
}

int RGWDeleteObj_ObjStore_S3::get_params()
{
  const char *if_unmod = s->info.env->get("HTTP_X_AMZ_DELETE_IF_UNMODIFIED_SINCE");

  if (s->system_request) {
    s->info.args.get_bool(RGW_SYS_PARAM_PREFIX "no-precondition-error", &no_precondition_error, false);
  }

  if (if_unmod) {
    std::string if_unmod_decoded = url_decode(if_unmod);
    uint64_t epoch;
    uint64_t nsec;
    if (utime_t::parse_date(if_unmod_decoded, &epoch, &nsec) < 0) {
      ldout(s->cct, 10) << "failed to parse time: " << if_unmod_decoded << dendl;
      return -EINVAL;
    }
    unmod_since = utime_t(epoch, nsec).to_real_time();
  }

  const char *bypass_gov_header = s->info.env->get("HTTP_X_AMZ_BYPASS_GOVERNANCE_RETENTION");
  if (bypass_gov_header) {
    std::string bypass_gov_decoded = url_decode(bypass_gov_header);
    bypass_governance_mode = boost::algorithm::iequals(bypass_gov_decoded, "true");
  }

  return 0;
}

void RGWDeleteObj_ObjStore_S3::send_response()
{
  int r = op_ret;
  if (r == -ENOENT)
    r = 0;
  if (!r) {
    r = STATUS_NO_CONTENT;
#ifdef WITH_BCEBOS
    if (op_ret == -ENOENT && (s->prot_flags & RGW_REST_BOS)) {
      r = -ENOENT;
    }
#endif
  }

  set_req_state_err(s, r);
  dump_errno(s);
  dump_header_if_nonempty(s, "x-amz-version-id", version_id);
  if (delete_marker) {
    dump_header(s, "x-amz-delete-marker", "true");
  }
  end_header(s, this);
}

int RGWCopyObj_ObjStore_S3::init_dest_policy()
{
  RGWAccessControlPolicy_S3 s3policy(s->cct);

  /* build a policy for the target object */
  int r;
#ifdef WITH_BCEBOS
  if (s->prot_flags & RGW_REST_BOS) {
    r = create_s3_policy(s, store, s3policy, s->bucket_owner);
  } else
#endif
  {
    r = create_s3_policy(s, store, s3policy, s->owner);
  }
  if (r < 0)
    return r;

  dest_policy = s3policy;

  return 0;
}

int RGWRenameObj_ObjStore_S3::get_params() {
  if (s->info.env->exists("HTTP_X_BCE_RENAME_KEY"))
    src_object = url_decode(s->info.env->get("HTTP_X_BCE_RENAME_KEY"));
  else if (s->info.env->exists("HTTP_X_AMZ_RENAME_KEY"))
    src_object = url_decode(s->info.env->get("HTTP_X_AMZ_RENAME_KEY"));
  return 0;
}

void RGWRenameObj_ObjStore_S3::send_response()
{
  if (op_ret) {
    set_req_state_err(s, op_ret);
  }
  dump_errno(s);
  end_header(s);
}

int RGWCopyObj_ObjStore_S3::get_params()
{
  
#ifdef WITH_BCEBOS
  if (s->prot_flags & RGW_REST_BOS) {
    if_mod = s->info.env->get("HTTP_X_BCE_COPY_SOURCE_IF_MODIFIED_SINCE");
    if_unmod = s->info.env->get("HTTP_X_BCE_COPY_SOURCE_IF_UNMODIFIED_SINCE");
    if_match = s->info.env->get("HTTP_X_BCE_COPY_SOURCE_IF_MATCH");
    if_nomatch = s->info.env->get("HTTP_X_BCE_COPY_SOURCE_IF_NONE_MATCH");
  } else
#endif
  {
    if_mod = s->info.env->get("HTTP_X_AMZ_COPY_IF_MODIFIED_SINCE");
    if_unmod = s->info.env->get("HTTP_X_AMZ_COPY_IF_UNMODIFIED_SINCE");
    if_match = s->info.env->get("HTTP_X_AMZ_COPY_IF_MATCH");
    if_nomatch = s->info.env->get("HTTP_X_AMZ_COPY_IF_NONE_MATCH");
  }

  src_tenant_name = s->src_tenant_name;
  src_bucket_name = s->src_bucket_name;
  src_object = s->src_object;
  dest_tenant_name = s->bucket.tenant;
  dest_bucket_name = s->bucket.name;
  dest_object = s->object.name;

  if (s->system_request) {
    source_zone = s->info.args.get(RGW_SYS_PARAM_PREFIX "source-zone");
    s->info.args.get_bool(RGW_SYS_PARAM_PREFIX "copy-if-newer", &copy_if_newer, false);
    if (!source_zone.empty()) {
      client_id = s->info.args.get(RGW_SYS_PARAM_PREFIX "client-id");
      op_id = s->info.args.get(RGW_SYS_PARAM_PREFIX "op-id");

      if (client_id.empty() || op_id.empty()) {
        ldout(s->cct, 5) <<
            RGW_SYS_PARAM_PREFIX "client-id or "
            RGW_SYS_PARAM_PREFIX "op-id were not provided, "
            "required for intra-region copy"
            << dendl;
        return -EINVAL;
      }
    }
  }

#ifdef WITH_BCEBOS
  if (s->prot_flags & RGW_REST_BOS) {
    if (s->info.env->exists("HTTP_X_BCE_COPY_SOURCE"))
      copy_source = s->info.env->get("HTTP_X_BCE_COPY_SOURCE");
    if (s->info.env->exists("HTTP_X_BCE_METADATA_DIRECTIVE"))
      md_directive = s->info.env->get("HTTP_X_BCE_METADATA_DIRECTIVE");
  } else
#endif
  {
    copy_source = s->info.env->get("HTTP_X_AMZ_COPY_SOURCE");
    md_directive = s->info.env->get("HTTP_X_AMZ_METADATA_DIRECTIVE");
  }

  if (md_directive) {
    if (strcasecmp(md_directive, "COPY") == 0) {
      attrs_mod = RGWRados::ATTRSMOD_NONE;
    } else if (strcasecmp(md_directive, "REPLACE") == 0) {
      attrs_mod = RGWRados::ATTRSMOD_REPLACE;
    } else if (!source_zone.empty()) {
      attrs_mod = RGWRados::ATTRSMOD_NONE; // default for intra-zone_group copy
    } else {
      s->err.message = "Unknown metadata directive.";
      ldout(s->cct, 0) << s->err.message << dendl;
      return -EINVAL;
    }
  }

  if (source_zone.empty() &&
      (dest_tenant_name.compare(src_tenant_name) == 0) &&
      (dest_bucket_name.compare(src_bucket_name) == 0) &&
      (dest_object.compare(src_object.name) == 0) &&
      src_object.instance.empty() &&
      (attrs_mod != RGWRados::ATTRSMOD_REPLACE)) {
    need_to_check_storage_class = true;
  }

  //handle object lock
  int ret = get_object_lock_configure(s, &obj_retention, &obj_legal_hold);
  if (ret < 0) {
    return ret;
  }
  return 0;
}

int RGWCopyObj_ObjStore_S3::check_storage_class(const rgw_placement_rule& src_placement)
{
  if (src_placement == s->dest_placement) {
    /* can only copy object into itself if replacing attrs */
    s->err.message = "This copy request is illegal because it is trying to copy "
      "an object to itself without changing the object's metadata, "
      "storage class, website redirect location or encryption attributes.";
    ldout(s->cct, 0) << s->err.message << dendl;
    return -ERR_INVALID_REQUEST;
  }
  return 0;
}

void RGWCopyObj_ObjStore_S3::send_partial_response(off_t ofs)
{
  if (! sent_header) {
    if (op_ret) {
#ifdef WITH_BCEBOS
      if (op_ret == -ENAMETOOLONG) {
        op_ret = -ERR_INVALID_OBJECT_NAME;
      }
#endif
      set_req_state_err(s, op_ret);
    }
    dump_errno(s);

    end_header(s, this, "application/xml");
    dump_start(s);
    if (op_ret == 0) {
      s->formatter->open_object_section_in_ns("CopyObjectResult", XMLNS_AWS_S3);
    }
    sent_header = true;
  } else {
    /* Send progress field. Note that this diverge from the original S3
     * spec. We do this in order to keep connection alive.
     */
    s->formatter->dump_int("Progress", (uint64_t)ofs);
  }
  rgw_flush_formatter(s, s->formatter);
}

void RGWCopyObj_ObjStore_S3::send_response()
{
  if (!sent_header)
    send_partial_response(0);

  if (op_ret == 0) {
    dump_header_if_nonempty(s, "x-amz-version-id", version_id);
    dump_time(s, "LastModified", &mtime);
    if (! etag.empty()) {
      s->formatter->dump_string("ETag", std::move(etag));
    }
    s->formatter->close_section();
    rgw_flush_formatter_and_reset(s, s->formatter);
  }
}

void RGWGetACLs_ObjStore_S3::send_response()
{
  if (op_ret)
    set_req_state_err(s, op_ret);
  dump_errno(s);
  end_header(s, this, "application/xml");
  dump_start(s);
  rgw_flush_formatter(s, s->formatter);
  dump_body(s, acls);
}

int RGWPutACLs_ObjStore_S3::get_params()
{
  int ret =  RGWPutACLs_ObjStore::get_params();
  if (ret >= 0) {
    const int ret_auth = do_aws4_auth_completion();
    if (ret_auth < 0) {
      return ret_auth;
    }
  }
 
#ifdef WITH_BCEBOS
  if (s->prot_flags & RGW_REST_BOS) {
    if (len == 0 && s->canned_acl.empty() && !s->has_acl_header) {
      ldout(s->cct, 10) << "bos acl body should not be null." << dendl;
      ret = -ERR_MALFORMED_JSON;
    }
  }
#endif
  return ret;
}

int RGWPutACLs_ObjStore_S3::get_policy_from_state(RGWRados *store,
						  struct req_state *s,
						  stringstream& ss)
{
  RGWAccessControlPolicy_S3 s3policy(s->cct);

  // bucket-* canned acls do not apply to bucket
  if (s->object.empty()) {
    if (s->canned_acl.find("bucket") != string::npos)
      s->canned_acl.clear();
  }

  int r = create_s3_policy(s, store, s3policy, owner);
  if (r < 0)
    return r;

  s3policy.to_xml(ss);

  return 0;
}

void RGWPutACLs_ObjStore_S3::send_response()
{
  if (op_ret)
    set_req_state_err(s, op_ret);
  dump_errno(s);
  end_header(s, this, "application/xml");
  dump_start(s);
}

void RGWGetLC_ObjStore_S3::execute()
{
  config.set_ctx(s->cct);

  map<string, bufferlist>::iterator aiter = s->bucket_attrs.find(RGW_ATTR_LC);
  if (aiter == s->bucket_attrs.end()) {
    op_ret = -ENOENT;
    return;
  }

  bufferlist::iterator iter(&aiter->second);
  try {
    config.decode(iter);
  } catch (const buffer::error& e) {
    ldout(s->cct, 0) << __func__ <<  "decode life cycle config failed" << dendl;
    op_ret = -EIO;
    return;
  }
}

void RGWGetLC_ObjStore_S3::send_response()
{
  if (op_ret) {
    if (op_ret == -ENOENT) {
      set_req_state_err(s, ERR_NO_SUCH_LC);
    } else {
      set_req_state_err(s, op_ret);
    }
  }
  dump_errno(s);
  if (s->is_from_platform_frontend()) {
    const auto& rule_map = config.get_rule_map();
    for (const auto& ri : rule_map) {
      const auto& rule = ri.second;
      auto& filter = rule.get_filter();

      if (!filter.has_suffix()) {
        continue;
      }

      auto& id = rule.get_id();
      dump_header(s, "x-amz-lc-suffix-" + id, filter.get_suffix());
    }
  }
  end_header(s, this, nullptr, NO_CONTENT_LENGTH, true);

  dump_start(s);

  if (op_ret < 0)
    return;

#ifdef WITH_BCEBOS
  if (s->prot_flags & RGW_REST_BOS) {
    RGWLifecycleJSONParser *json_parser = new RGWLifecycleJSONParser;
    json_parser->dump_json(s->formatter, &config, s->bucket.name);
    encode_json("", *json_parser, s->formatter);
    stringstream ss;
    s->formatter->flush(ss);
    std::string outs(ss.str());
    ldout(s->cct, 20) << "get lifecycle : " << outs << dendl;
    dump_body(s, outs);
    return;
  }
#endif
  encode_xml("LifecycleConfiguration", XMLNS_AWS_S3, config, s->formatter);
  rgw_flush_formatter_and_reset(s, s->formatter);
}

void RGWPutLC_ObjStore_S3::send_response()
{
  if (op_ret)
    set_req_state_err(s, op_ret);
  dump_errno(s);
  end_header(s, this, "application/xml");
  dump_start(s);
}

void RGWDeleteLC_ObjStore_S3::send_response()
{
  if (op_ret == 0)
    op_ret = STATUS_NO_CONTENT;
  if (op_ret) {
    set_req_state_err(s, op_ret);
  }
  dump_errno(s);
  end_header(s, this, "application/xml");
  dump_start(s);
}

void RGWPutBucketNotification_ObjStore_S3::send_response()
{
  if (op_ret) {
    set_req_state_err(s, op_ret);
  }
  dump_errno(s);
  end_header(s);
}

int RGWPutBucketNotification_ObjStore_S3::get_params()
{
  const auto max_size = s->cct->_conf->rgw_max_put_param_size;
  // At some point when I have more time I want to make a version of
  // rgw_rest_read_all_input that doesn't use malloc.
  op_ret = rgw_rest_read_all_input(s, &data, &len, max_size, false);
  // And throws exceptions.
  if (op_ret != 0) {
    return op_ret;
  }

  bufferlist in_data = bufferlist::static_from_mem(data, len);
  RGWNotification n;
  op_ret = n.gen_notification_bl(in_data, notification_bl, s->bucket_name);

  return op_ret;
}

void RGWGetBucketNotification_ObjStore_S3::send_response()
{
  if (op_ret) {
    set_req_state_err(s, op_ret);
  }
  dump_errno(s);
  end_header(s, this, CONTENT_TYPE_JSON);

  if (op_ret < 0) {
    return;
  }
  RGWNotification n;
  n.decode_notification_bl(notification_bl);
  stringstream ss;
  n.to_json(ss);

  std::string ret_notification = ss.str();
  dump_body(s, ret_notification);
}

void RGWDeleteBucketNotification_ObjStore_S3::send_response()
{
  if (op_ret == 0) {
    op_ret = STATUS_NO_CONTENT;
  }

  set_req_state_err(s, op_ret);
  dump_errno(s);
  end_header(s);
}

void RGWGetBucketLogging_S3::send_response()
{
  if (op_ret) {
    set_req_state_err(s, op_ret);
  }
  dump_errno(s);
  dump_start(s);

  map<string, bufferlist>::iterator aiter = s->bucket_attrs.find(RGW_ATTR_LOGGING);

  end_header(s, this, nullptr, NO_CONTENT_LENGTH, true);
#ifdef WITH_BCEBOS
  if (s->prot_flags & RGW_REST_BOS) {
    s->formatter->open_object_section("logging");
    if (aiter != s->bucket_attrs.end()) {
      pair<string, string> logging_conf;

      decode(logging_conf, aiter->second);
      RGWObjectCtx obj_ctx(store);
      RGWBucketInfo target_bucket_info;
      map<string, bufferlist> target_bucket_attrs;

      int r = store->get_bucket_info(obj_ctx, s->user->user_id.tenant,
        logging_conf.first, target_bucket_info, nullptr, &target_bucket_attrs);
      if (r < 0) {
        s->formatter->dump_string("status", "disabled");
      } else {
        s->formatter->dump_string("status", "enabled");
        s->formatter->dump_string("targetBucket", logging_conf.first);
        s->formatter->dump_string("targetPrefix", logging_conf.second);
      }
    } else {
      s->formatter->dump_string("status", "disabled");
    }
    s->formatter->close_section();
  } else
#endif
  {
    s->formatter->open_object_section_in_ns("BucketLoggingStatus", XMLNS_AWS_S3);
    if (aiter != s->bucket_attrs.end()) {
      pair<string, string> logging_conf;
      decode(logging_conf, aiter->second);
      s->formatter->open_object_section("LoggingEnabled");
      s->formatter->dump_string("TargetBucket", logging_conf.first);
      s->formatter->dump_string("TargetPrefix", logging_conf.second);
      s->formatter->close_section();
    }
    s->formatter->close_section();
  }
  rgw_flush_formatter_and_reset(s, s->formatter);
}

int RGWPutBucketLogging_S3::get_params()
{
  char* data = nullptr;
  int len = 0;
  int r = rgw_rest_read_all_input(s, &data, &len, s->cct->_conf->rgw_max_put_param_size, false);
  if (r < 0) {
    return r;
  }

  auto data_deleter = std::unique_ptr<char, decltype(free)*> {data, free};
  
  r = do_aws4_auth_completion();
  if (r < 0) {
    return r;
  }

#ifdef WITH_BCEBOS
  if (s->prot_flags & RGW_REST_BOS) {
    JSONParser parser;
    bool ret = parser.parse(data, len);
    if (!ret) {
      return -ERR_MALFORMED_JSON;
    }

    JSONObj *jsonObj = parser.find_obj("targetBucket");
    if (!jsonObj) {
      return -ERR_INAPPROPRIATE_JSON;
    }
    target_bucket = jsonObj->get_data();

    if (target_bucket.empty()) {
      return -ERR_INAPPROPRIATE_JSON;
    }

    if (valid_bos_bucket_name(target_bucket) < 0) {
      return -EINVAL;
    }

    jsonObj = parser.find_obj("targetPrefix");
    if (!jsonObj) {
      return -ERR_INAPPROPRIATE_JSON;
    }
    target_prefix = jsonObj->get_data();

    string data_str = data;
    if (target_prefix == "null" && data_str.find(" null") != std::string::npos) {
      target_prefix.clear();
    }
  } else
#endif
  {
    RGWXMLParser parser;
    if (!parser.init()) {
      return -EINVAL;
    }
    if (!data || parser.parse(data, len, 1)) {
      return -EINVAL;
    }

    XMLObj *xmlObj = parser.find_first("BucketLoggingStatus")->
      find_first("LoggingEnabled")->find_first("TargetBucket");
    if (!xmlObj) {
      return -EINVAL;
    }
    target_bucket = xmlObj->get_data();

    xmlObj = parser.find_first("BucketLoggingStatus")->
      find_first("LoggingEnabled")->find_first("TargetPrefix");
    if (!xmlObj) {
      return -EINVAL;
    }
    target_prefix = xmlObj->get_data();
  }
  return r;
}

void RGWPutBucketLogging_S3::send_response()
{
  if (op_ret < 0) {
    set_req_state_err(s, op_ret);
  }
  dump_errno(s);
  end_header(s, NULL);
}

void RGWDeleteBucketLogging_S3::send_response()
{
  int r = op_ret;
  if (!r || r == -ENOENT) {
    r = STATUS_NO_CONTENT;
  }

  set_req_state_err(s, r);
  dump_errno(s);
  end_header(s, NULL);
}

void RGWGetBucketEncryption_ObjStore_S3::send_response()
{
  if (op_ret) {
    set_req_state_err(s, op_ret);
  }

  string encryption = s->bucket_info.encryption_algorithm;
  if (encryption == "") {
    encryption = "none";
  }
  dump_errno(s);
  dump_start(s);

#ifdef WITH_BCEBOS
  if (s->prot_flags & RGW_REST_BOS) {
    end_header(s, this, CONTENT_TYPE_JSON);
    dump_header(s, "x-bce-server-side-encryption", encryption);
    s->formatter->open_object_section("encryption");
    s->formatter->dump_string("encryptionAlgorithm", encryption);
    if (!s->bucket_info.kms_master_key_id.empty()) {
      s->formatter->dump_string("kmsMasterKeyId", s->bucket_info.kms_master_key_id);
    }
    s->formatter->close_section();
  } else
#endif
  {
    end_header(s, this, "application/xml");
    s->formatter->open_object_section_in_ns("ServerSideEncryptionConfiguration", XMLNS_AWS_S3);
    s->formatter->open_object_section("Rule");
    s->formatter->open_object_section("ApplyServerSideEncryptionByDefault");
    s->formatter->dump_string("SSEAlgorithm", encryption);
    if (!s->bucket_info.kms_master_key_id.empty()) {
      s->formatter->dump_string("KMSMasterKeyID", s->bucket_info.kms_master_key_id);
    }
    s->formatter->close_section();
    s->formatter->close_section();
    s->formatter->close_section();
  }
  rgw_flush_formatter_and_reset(s, s->formatter);
}

int RGWPutBucketEncryption_ObjStore_S3::get_params()
{
  char *data = nullptr;
  int len = 0;
  int r = rgw_rest_read_all_input(s, &data, &len, s->cct->_conf->rgw_max_put_param_size, false);
  if (r < 0) {
    return r;
  }

  auto data_deleter = std::unique_ptr<char, decltype(free)*>{data, free};

  r = do_aws4_auth_completion();
  if (r < 0) {
    return r;
  }

#ifdef WITH_BCEBOS
  if (s->prot_flags & RGW_REST_BOS) {
    JSONParser parser;
    bool ret = parser.parse(data, len);
    if (!ret) {
      return ret;
    }

    JSONObj *json_obj = parser.find_obj("encryptionAlgorithm");
    if (!json_obj) {
      return -EINVAL;
    }
    encryption_algorithm = json_obj->get_data();

    //if body have kmsMasterKeyId, mode SSE-KMS
    JSONObj *kms_json_obj = parser.find_obj("kmsMasterKeyId");
    if (kms_json_obj) {
      kms_master_key_id = kms_json_obj->get_data();
      if (kms_master_key_id.empty()) {
        return -ERR_INVALID_ENCRY_KMS_MK_ID;
      }
    }
  } else
#endif
  {
    RGWXMLParser parser;
    if (!parser.init()) {
      return -EINVAL;
    }
    if (!data || !parser.parse(data, len, 1)) {
      return -EINVAL;
    }

    XMLObj *xmlObj = parser.find_first("ServerSideEncryptionConfiguration")->find_first("Rule")->
                            find_first("ApplyServerSideEncryptionByDefault")->find_first("SSEAlgorithm");
    if (!xmlObj) {
      return -EINVAL;
    }

    encryption_algorithm = xmlObj->get_data();

    //if body have KMSMasterKeyID, mode SSE-KMS
    XMLObj *kms_xml_obj = parser.find_first("ServerSideEncryptionConfiguration")->find_first("Rule")->
                                 find_first("ApplyServerSideEncryptionByDefault")->find_first("KMSMasterKeyID");
    if (kms_xml_obj) {
      kms_master_key_id = kms_xml_obj->get_data();
      if (kms_master_key_id.empty()) {
        return -ERR_INVALID_ENCRY_KMS_MK_ID;
      }
    }
  }
  return r;
}

void RGWPutBucketEncryption_ObjStore_S3::send_response()
{
  if (op_ret < 0) {
    set_req_state_err(s, op_ret);
  }
  dump_errno(s);

  if (!encryption_algorithm.empty()) {
    dump_header(s, "x-bce-server-side-encryption", encryption_algorithm);
    if (!kms_master_key_id.empty()) {
      dump_header(s, "x-bce-server-side-encryption-bos-kms-key-id", kms_master_key_id);
    }
  }
  end_header(s);
}

void RGWDeleteBucketEncryption_ObjStore_S3::send_response()
{
  int r = op_ret;
  if (!r || r == -ENOENT)
    r = STATUS_NO_CONTENT;

  set_req_state_err(s, r);
  dump_errno(s);
  end_header(s, NULL);
}

void RGWGetCORS_ObjStore_S3::send_response()
{
  if (op_ret) {
    if (op_ret == -ENOENT) {
#ifdef WITH_BCEBOS
      if (s->prot_flags & RGW_REST_BOS) {
        set_req_state_err(s, ERR_NO_SUCH_CORS);
      } else
#endif
      {
        set_req_state_err(s, ERR_NOT_FOUND);
      }
    } else {
      set_req_state_err(s, op_ret);
    }
  }
  dump_errno(s);
  end_header(s, nullptr, nullptr, NO_CONTENT_LENGTH, true);
  dump_start(s);
  if (! op_ret) {
    string cors;
    RGWCORSConfiguration_S3 *s3cors =
      static_cast<RGWCORSConfiguration_S3 *>(&bucket_cors);
    stringstream ss;
#ifdef WITH_BCEBOS
    if (s->prot_flags & RGW_REST_BOS) {
      s3cors->to_json(ss);
    } else
#endif
    {
      s3cors->to_xml(ss);
    }
    cors = ss.str();
    dump_body(s, cors);
  }
}

int RGWPutCORS_ObjStore_S3::get_params()
{
  int r;
  char *data = nullptr;
  int len = 0;
  RGWCORSXMLParser_S3 parser(s->cct);
  RGWCORSConfiguration_S3 *cors_config;
  RGWCORSJSONParser_S3 p;
  p.cors_config = new RGWCORSConfiguration_S3();

  const auto max_size = s->cct->_conf->rgw_max_put_param_size;
  r = rgw_rest_read_all_input(s, &data, &len, max_size, false);
  if (r < 0) {
    return r;
  }

#ifdef WITH_BCEBOS

#define MAX_CORS_LENGTH 20480
  if (len > MAX_CORS_LENGTH) return -ERR_MAX_MESSAGE_LENGTH_EXCEEDED;

  if (s->prot_flags & RGW_REST_BOS) {
    cors_config = p.cors_config;
    bool ret = p.parse(data, len);
    if (!ret) {
      ldout(s->cct, 10) << "json parse err:"<< ret << dendl;
      return -ERR_MALFORMED_JSON;
    }
    JSONObjIter iter = p.find_first("corsConfiguration");
    if (iter.end()) {
      ldout(s->cct, 10) << "corsConfiguration not found:" << dendl;
      return -ERR_MALFORMED_JSON; // change to a "no conditions" error following S3
    }

    JSONObj *obj = *iter;

    iter = obj->find_first();
    if (iter.end()) {
      ldout(s->cct, 10) << __func__ << " no obj in corsConfiguration" << dendl;
      return -ERR_MALFORMED_JSON;
    }
    for (; !iter.end(); ++iter) {
      uint8_t methods = 0;
      obj = *iter;
      auto allowedMethods = obj->find_first("allowedMethods");
      JSONObj *m_json = *allowedMethods;
      JSONObjIter m_iter = m_json->find_first();
      if (m_json->is_array()) {
        if (m_iter.end()) {
          ldout(s->cct, 10) << __func__ << " no allowedMethods" << dendl;
          return -ERR_MALFORMED_JSON;
        }
        for (; !m_iter.end(); ++m_iter) {
          JSONObj *child = *m_iter;
          const char *m = child->get_data().c_str();
          if (strcasecmp(m, "GET") == 0) {
            methods |= RGW_CORS_GET;
          } else if (strcasecmp(m, "POST") == 0) {
            methods  |= RGW_CORS_POST;
          } else if (strcasecmp(m, "DELETE") == 0) {
            methods  |= RGW_CORS_DELETE;
          } else if (strcasecmp(m, "HEAD") == 0) {
            methods  |= RGW_CORS_HEAD;
          } else if (strcasecmp(m, "PUT") == 0) {
            methods  |= RGW_CORS_PUT;
          } else if (strcasecmp(m, "COPY") == 0) {
            methods  |= RGW_CORS_COPY;
          } else {
            ldout(s->cct, 10) << __func__ << " method is invalid" << dendl;
            return -ERR_MALFORMED_JSON;
          }
        }
      } else {
         ldout(s->cct, 10) << __func__ << " allowedMethods is not array" << dendl;
         return -ERR_MALFORMED_JSON;
      }

      RGWCORSRule rule;
      rule.set_allowed_methods(methods);
      try {
        decode_json_obj(rule, *iter);
      } catch (JSONDecoder::err& e) {
        ldout(s->cct, 10) << __func__ << " decode josn error:" << e.message << dendl;
        return -ERR_MALFORMED_JSON;
      }
      JSONObj *o_json = *(obj->find_first("allowedOrigins"));
      if (!o_json->is_array()) {
        ldout(s->cct, 10) << __func__ << "(): allowedOrigins is not array" << dendl;
        return -ERR_MALFORMED_JSON;
      }
      if (!rule.have_allowed_origins()) {
        ldout(s->cct, 10) << __func__ << "(): no allowedOrigins" << dendl;
        return -ERR_MALFORMED_JSON;
      }
      if ((!rule.have_allowed_hdrs() && obj->find_obj("allowedHeaders") != nullptr) ||
          (!rule.have_exposable_hdrs() && obj->find_obj("allowedExposeHeaders") != nullptr)) {
        ldout(s->cct, 10) << __func__ << "(): format cors allowed origins faild." << dendl;
        return -ERR_MALFORMED_JSON;
      }

      /* Check maxAgeSeconds */
      JSONObjIter a_iter = obj->find_first("maxAgeSeconds");
      if (!a_iter.end()) {
        string err;
        JSONObj *child = *a_iter;
        int64_t max_age = strict_strtoll(child->get_data().c_str(), 10, &err);
        if (!err.empty()) {
          ldout(s->cct, 10) << __func__ << "(): get max_age error:" << err << dendl;
          return -ERR_MALFORMED_JSON;
        }
        if (max_age < 0) {
          ldout(s->cct, 10) << __func__ << "(): cors max age seconds can not be negative"  << dendl;
          return -EINVAL;
        } else if (!err.empty() || max_age >= (0x100000000ll / 2)) {
          ldout(s->cct, 10) << __func__ << "(): format cors max age seconds faild " << err << dendl;
          return -ERR_MALFORMED_JSON;
        } else {
          rule.set_max_age((uint32_t)max_age);
        }
      }

      /* Check allowedOrigins */
      for (JSONObjIter o_iter = o_json->find_first(); !o_iter.end(); ++o_iter) {
        JSONObj *child = *o_iter;
        if (child->is_object()) {
          ldout(s->cct, 10) << __func__ << "(): allowedOrigins is not object" << dendl;
          return -ERR_MALFORMED_JSON;
        }
        if (validate_name_string(child->get_data()) != 0) {
          ldout(s->cct, 10) << __func__ << "(): validate allowedOrigins name faild." << dendl;
          return -EINVAL;
        }
      }

      /* Check allowedHeaders */
      if (rule.have_allowed_hdrs()) {
        JSONObj *h_json = *(obj->find_first("allowedHeaders"));
        if (!h_json->is_array()) {
          ldout(s->cct, 10) << __func__ << "(): allowed headers is not array." << dendl;
          return -ERR_MALFORMED_JSON;
        }
        for (JSONObjIter h_iter = h_json->find_first(); !h_iter.end(); ++h_iter) {
          JSONObj *child = *h_iter;
          if (child->is_object()) {
            ldout(s->cct, 10) << __func__ << "(): allowedHeaders is not obj" << dendl;
            return -ERR_MALFORMED_JSON;
          }
          if (validate_name_string(child->get_data()) != 0) {
            ldout(s->cct, 10) << __func__ << "(): format cors allowed headers faild." << dendl;
            return -EINVAL;
          }
        }
      }

      /* Check allowedExposeHeaders */
      if (rule.have_exposable_hdrs()) {
        JSONObj *e_json = *(obj->find_first("allowedExposeHeaders"));
        if (!e_json->is_array()) {
          ldout(s->cct, 10) << __func__ << "(): allowedExposeHeaders is not array" << dendl;
          return -ERR_MALFORMED_JSON;
        }
        for (JSONObjIter e_iter = e_json->find_first(); !e_iter.end(); ++e_iter) {
          JSONObj *child = *e_iter;
          if (child->is_object()) {
            ldout(s->cct, 10) << __func__ << "(): allowedExposeHeaders is not obj" << dendl;
            return -ERR_MALFORMED_JSON;
          }
          if (child->get_data().find("*") != std::string::npos) {
            ldout(s->cct, 10) << __func__ << "(): allowedExposeHeaders don't support *." << dendl;
            return -EINVAL;
          }
        }
      }

      bufferlist bl;
      rule.encode(bl);
      cors_config->stack_rule(rule);
      if (cors_config->get_rules().size() > 100) {
        ldout(s->cct, 10) << __func__ << "(): cors rules size should less then 100, now curs rules size is "
                         << cors_config->get_rules().size() << dendl;
        return -EINVAL;
      }
      if (cors_config->get_rules().empty()) {
        ldout(s->cct, 10) << __func__ << "(): cors rules size is zero." << dendl;
        return -ERR_MALFORMED_JSON;
      }
    }
  } else
#endif
  {
    auto data_deleter = std::unique_ptr<char, decltype(free)*>{data, free};

    r = do_aws4_auth_completion();
    if (r < 0) {
      return r;
    }

    if (!parser.init()) {
      return -EINVAL;
    }

    if (!data || !parser.parse(data, len, 1)) {
      return -EINVAL;
    }
    cors_config =
      static_cast<RGWCORSConfiguration_S3 *>(parser.find_first(
    				     "CORSConfiguration"));
  }
  if (!cors_config) {
    ldout(s->cct, 10) << __func__ << " no CORSConfiguration" << dendl;
    return -EINVAL;
  }

  // forward bucket cors requests to meta master zone
  if (!store->is_meta_master()) {
    /* only need to keep this data around if we're not meta master */
    in_data.append(data, len);
  }

  if (s->cct->_conf->subsys.should_gather<ceph_subsys_rgw, 15>()) {
    ldout(s->cct, 15) << "CORSConfiguration";
    cors_config->to_xml(*_dout);
    *_dout << dendl;
  }

  cors_config->encode(cors_bl);

  return 0;
}

void RGWPutCORS_ObjStore_S3::send_response()
{
  if (op_ret)
    set_req_state_err(s, op_ret);
  dump_errno(s);
  end_header(s, NULL, nullptr, NO_CONTENT_LENGTH, true);
  dump_start(s);
}

void RGWDeleteCORS_ObjStore_S3::send_response()
{
  int r = op_ret;
  if (!r || r == -ENOENT)
    r = STATUS_NO_CONTENT;

  set_req_state_err(s, r);
  dump_errno(s);
  end_header(s, NULL);
}

void RGWOptionsCORS_ObjStore_S3::send_response()
{
  string hdrs, exp_hdrs;
  uint32_t max_age = CORS_MAX_AGE_INVALID;
  /*EACCES means, there is no CORS registered yet for the bucket
   *ENOENT means, there is no match of the Origin in the list of CORSRule
   */
  if (op_ret == -ENOENT)
    op_ret = -EACCES;

  const char* acl_hdrs = s->info.env->get("HTTP_ACCESS_CONTROL_REQUEST_HEADERS");
  if (acl_hdrs) {
    const string& ac_hdrs_string = acl_hdrs;
    if (ac_hdrs_string.find("x-amz-user-agent") != string::npos) {
      op_ret = 0;
      const char *origin_hdr = s->info.env->get("HTTP_ORIGIN");
      const char *method_hdr = s->info.env->get("HTTP_ACCESS_CONTROL_REQUEST_METHOD");
      dout(10) << "verify options request from console" << dendl;
      dump_errno(s);
      dump_access_control(s, origin_hdr, method_hdr, acl_hdrs, "Etag", CORS_MAX_AGE_INVALID);
      end_header(s, NULL);
      return;
    }
  }

  if (op_ret < 0) {
    set_req_state_err(s, op_ret);
    dump_errno(s);
    end_header(s, NULL);
    return;
  }
  get_response_params(hdrs, exp_hdrs, &max_age);

  dump_errno(s);
  dump_access_control(s, origin, req_meth, hdrs.c_str(), exp_hdrs.c_str(),
		      max_age);
  end_header(s, NULL);
}

void RGWGetRequestPayment_ObjStore_S3::send_response()
{
  dump_errno(s);
  end_header(s, this, "application/xml");
  dump_start(s);

  s->formatter->open_object_section_in_ns("RequestPaymentConfiguration", XMLNS_AWS_S3);
  const char *payer = requester_pays ? "Requester" :  "BucketOwner";
  s->formatter->dump_string("Payer", payer);
  s->formatter->close_section();
  rgw_flush_formatter_and_reset(s, s->formatter);
}

class RGWSetRequestPaymentParser : public RGWXMLParser
{
  XMLObj *alloc_obj(const char *el) override {
    return new XMLObj;
  }

public:
  RGWSetRequestPaymentParser() {}
  ~RGWSetRequestPaymentParser() override {}

  int get_request_payment_payer(bool *requester_pays) {
    XMLObj *config = find_first("RequestPaymentConfiguration");
    if (!config)
      return -EINVAL;

    *requester_pays = false;

    XMLObj *field = config->find_first("Payer");
    if (!field)
      return 0;

    string& s = field->get_data();

    if (stringcasecmp(s, "Requester") == 0) {
      *requester_pays = true;
    } else if (stringcasecmp(s, "BucketOwner") != 0) {
      return -EINVAL;
    }

    return 0;
  }
};

int RGWSetRequestPayment_ObjStore_S3::get_params()
{
  char *data;
  int len = 0;
  const auto max_size = s->cct->_conf->rgw_max_put_param_size;
  int r = rgw_rest_read_all_input(s, &data, &len, max_size, false);

  if (r < 0) {
    return r;
  }

  RGWSetRequestPaymentParser parser;

  if (!parser.init()) {
    ldout(s->cct, 0) << "ERROR: failed to initialize parser" << dendl;
    r = -EIO;
    goto done;
  }

  if (!parser.parse(data, len, 1)) {
    ldout(s->cct, 10) << "failed to parse data: " << data << dendl;
    r = -EINVAL;
    goto done;
  }

  r = parser.get_request_payment_payer(&requester_pays);

done:
  free(data);

  return r;
}

void RGWSetRequestPayment_ObjStore_S3::send_response()
{
  if (op_ret)
    set_req_state_err(s, op_ret);
  dump_errno(s);
  end_header(s);
}

int RGWInitMultipart_ObjStore_S3::get_params()
{
  RGWAccessControlPolicy_S3 s3policy(s->cct);
#ifdef WITH_BCEBOS
  if (s->prot_flags & RGW_REST_BOS) {
    op_ret = create_s3_policy(s, store, s3policy, s->bucket_owner);
  } else
#endif
  {
    op_ret = create_s3_policy(s, store, s3policy, s->owner);
  }
  if (op_ret < 0)
    return op_ret;

  policy = s3policy;

  //handle object lock
  int ret = get_object_lock_configure(s, &obj_retention, &obj_legal_hold);
  if (ret < 0) {
    return ret;
  }

  return 0;
}

void RGWInitMultipart_ObjStore_S3::send_response()
{
  if (op_ret)
    set_req_state_err(s, op_ret);
  dump_errno(s);
  for (auto &it : crypt_http_responses)
     dump_header(s, it.first, it.second);

  ceph::real_time abort_date;
  string rule_id;
  bool exist_multipart_abort = get_s3_multipart_abort_header(s, mtime, abort_date, rule_id);
  if (exist_multipart_abort) {
    dump_time_header(s, "x-amz-abort-date", abort_date);
    dump_header_if_nonempty(s, "x-amz-abort-rule-id", rule_id);
  }
  end_header(s, this, "application/xml");
  if (op_ret == 0) {
    dump_start(s);
    s->formatter->open_object_section_in_ns("InitiateMultipartUploadResult", XMLNS_AWS_S3);
    if (!s->bucket_tenant.empty())
      s->formatter->dump_string("Tenant", s->bucket_tenant);
    s->formatter->dump_string("Bucket", s->bucket_name);
    s->formatter->dump_string("Key", s->object.name);
    s->formatter->dump_string("UploadId", upload_id);
    s->formatter->close_section();
    rgw_flush_formatter_and_reset(s, s->formatter);
  }
}

int RGWInitMultipart_ObjStore_S3::prepare_encryption(map<string, bufferlist>& attrs)
{
  int res = 0;
#ifdef WITH_BCEBOS
  if (s->prot_flags & RGW_REST_BOS) {
    res = rgw_bos_prepare_encrypt(s, attrs, nullptr, nullptr, crypt_http_responses);
  } else
#endif
  {
    res = rgw_s3_prepare_encrypt(s, attrs, nullptr, nullptr, crypt_http_responses);
  }
  return res;
}

int RGWCompleteMultipart_ObjStore_S3::get_params()
{
  int ret = RGWCompleteMultipart_ObjStore::get_params();
  if (ret < 0) {
    return ret;
  }

  map_qs_metadata(s);

  return do_aws4_auth_completion();
}

void RGWCompleteMultipart_ObjStore_S3::send_response()
{
  if (op_ret)
    set_req_state_err(s, op_ret);
  dump_errno(s);
  dump_header_if_nonempty(s, "x-amz-version-id", version_id);
  if (op_ret == -ERR_CALLBACK_FAILED) {
    end_header(s, this, nullptr, NO_CONTENT_LENGTH, false, false, "", true);
  } else {
    end_header(s, this, "application/xml");
  }
  if (op_ret == 0) {
    dump_start(s);
    s->formatter->open_object_section_in_ns("CompleteMultipartUploadResult", XMLNS_AWS_S3);
    std::string base_uri = compute_domain_uri(s);
    if (!s->bucket_tenant.empty()) {
      s->formatter->dump_format("Location", "%s/%s:%s/%s",
	  base_uri.c_str(),
	  s->bucket_tenant.c_str(),
	  s->bucket_name.c_str(),
	  s->object.name.c_str()
          );
      s->formatter->dump_string("Tenant", s->bucket_tenant);
    } else {
      s->formatter->dump_format("Location", "%s/%s/%s",
	  base_uri.c_str(),
	  s->bucket_name.c_str(),
	  s->object.name.c_str()
          );
    }
    s->formatter->dump_string("Bucket", s->bucket_name);
    s->formatter->dump_string("Key", s->object.name);
    s->formatter->dump_string("ETag", etag);
    s->formatter->close_section();
    if (!s->response_body.is_zero()) {
      s->formatter->dump_string("response_body", s->response_body.to_str().c_str());
    }
    rgw_flush_formatter_and_reset(s, s->formatter);
  }
}

void RGWAbortMultipart_ObjStore_S3::send_response()
{
  int r = op_ret;
  if (!r)
    r = STATUS_NO_CONTENT;

  set_req_state_err(s, r);
  dump_errno(s);
  end_header(s, this);
}

void RGWListMultipart_ObjStore_S3::send_response()
{
  if (op_ret) {
#ifdef WITH_BCEBOS
    if (op_ret == -ENOENT && (s->prot_flags & RGW_REST_BOS)) {
      op_ret = -ERR_NO_SUCH_UPLOAD;
    }
#endif
    set_req_state_err(s, op_ret);
  }
  dump_errno(s);
  end_header(s, this, "application/xml");

  if (op_ret == 0) {
    dump_start(s);
    s->formatter->open_object_section_in_ns("ListPartsResult", XMLNS_AWS_S3);
    map<uint32_t, RGWUploadPartInfo>::iterator iter;
    map<uint32_t, RGWUploadPartInfo>::reverse_iterator test_iter;
    int cur_max = 0;

    iter = parts.begin();
    test_iter = parts.rbegin();
    if (test_iter != parts.rend()) {
      cur_max = test_iter->first;
    }
    if (!s->bucket_tenant.empty())
      s->formatter->dump_string("Tenant", s->bucket_tenant);
    s->formatter->dump_string("Bucket", s->bucket_name);
    s->formatter->dump_string("Key", s->object.name);
    s->formatter->dump_string("UploadId", upload_id);
    s->formatter->dump_string("StorageClass",
        rgw_placement_rule::get_canonical_storage_class(storage_class));
    s->formatter->dump_int("PartNumberMarker", marker);
    s->formatter->dump_int("NextPartNumberMarker", cur_max);
    s->formatter->dump_int("MaxParts", max_parts);
    s->formatter->dump_string("IsTruncated", (truncated ? "true" : "false"));

    ACLOwner& owner = policy.get_owner();
    dump_owner(s, owner.get_id(), owner.get_display_name());

    for (; iter != parts.end(); ++iter) {
      RGWUploadPartInfo& info = iter->second;

      s->formatter->open_object_section("Part");

      dump_time(s, "LastModified", &info.modified);

      s->formatter->dump_unsigned("PartNumber", info.num);
      s->formatter->dump_format("ETag", "\"%s\"", info.etag.c_str());
      s->formatter->dump_unsigned("Size", info.accounted_size);
      s->formatter->close_section();
    }
    s->formatter->close_section();
    rgw_flush_formatter_and_reset(s, s->formatter);
  }
}

void RGWListBucketMultiparts_ObjStore_S3::send_response()
{
  if (op_ret < 0) {
#ifdef WITH_BCEBOS
    if (op_ret == -ENOENT && (s->prot_flags & RGW_REST_BOS)) {
      op_ret = -ERR_NO_SUCH_UPLOAD;
    }
#endif
    set_req_state_err(s, op_ret);
  }
  dump_errno(s);

  end_header(s, this, "application/xml");
  dump_start(s);
  if (op_ret < 0)
    return;

  s->formatter->open_object_section_in_ns("ListMultipartUploadsResult", XMLNS_AWS_S3);
  if (!s->bucket_tenant.empty())
    s->formatter->dump_string("Tenant", s->bucket_tenant);
  s->formatter->dump_string("Bucket", s->bucket_name);
  if (!prefix.empty())
    s->formatter->dump_string("ListMultipartUploadsResult.Prefix", prefix);
  string& key_marker = marker.get_key();
  if (!key_marker.empty())
    s->formatter->dump_string("KeyMarker", key_marker);
  string& upload_id_marker = marker.get_upload_id();
  if (!upload_id_marker.empty())
    s->formatter->dump_string("UploadIdMarker", upload_id_marker);
  string next_key = next_marker.mp.get_key();
  if (!next_key.empty())
    s->formatter->dump_string("NextKeyMarker", next_key);
  string next_upload_id = next_marker.mp.get_upload_id();
  if (!next_upload_id.empty())
    s->formatter->dump_string("NextUploadIdMarker", next_upload_id);
  s->formatter->dump_int("MaxUploads", max_uploads);
  if (!delimiter.empty())
    s->formatter->dump_string("Delimiter", delimiter);
  s->formatter->dump_string("IsTruncated", (is_truncated ? "true" : "false"));

  if (op_ret >= 0) {
    vector<RGWMultipartUploadEntry>::iterator iter;
    for (iter = uploads.begin(); iter != uploads.end(); ++iter) {
      RGWMPObj& mp = iter->mp;
      s->formatter->open_array_section("Upload");
      if (encode_url) {
        s->formatter->dump_string("Key", url_encode(mp.get_key(), false));
      } else {
        s->formatter->dump_string("Key", mp.get_key());
      }
      s->formatter->dump_string("UploadId", mp.get_upload_id());

#ifdef WITH_BCEBOS
      dump_owner(s, s->bucket_owner.get_id(), s->bucket_owner.get_display_name(), "Initiator");
      dump_owner(s, s->bucket_owner.get_id(), s->bucket_owner.get_display_name());
#else
      dump_owner(s, s->user->user_id, s->user->display_name, "Initiator");
      dump_owner(s, s->user->user_id, s->user->display_name);
#endif

      s->formatter->dump_string("StorageClass",
          rgw_placement_rule::get_canonical_storage_class(iter->obj.meta.storage_class));
      dump_time(s, "Initiated", &iter->obj.meta.mtime);
      s->formatter->close_section();
    }
    if (!common_prefixes.empty()) {
      s->formatter->open_array_section("CommonPrefixes");
      for (const auto& kv : common_prefixes) {
        if (encode_url) {
          s->formatter->dump_string("CommonPrefixes.Prefix",
                                    url_encode(kv.first, false));
        } else {
          s->formatter->dump_string("CommonPrefixes.Prefix", kv.first);
        }
      }
      s->formatter->close_section();
    }
  }
  s->formatter->close_section();
  rgw_flush_formatter_and_reset(s, s->formatter);
}

int RGWDeleteMultiObj_ObjStore_S3::get_params()
{
  int ret = RGWDeleteMultiObj_ObjStore::get_params();
  if (ret < 0) {
    return ret;
  }

  const char *bypass_gov_header = s->info.env->get("HTTP_X_AMZ_BYPASS_GOVERNANCE_RETENTION");
  if (bypass_gov_header) {
    std::string bypass_gov_decoded = url_decode(bypass_gov_header);
    bypass_governance_mode = boost::algorithm::iequals(bypass_gov_decoded, "true");
  }

  return do_aws4_auth_completion();
}

void RGWDeleteMultiObj_ObjStore_S3::send_status()
{
  if (! status_dumped) {
    if (op_ret < 0) 
      set_req_state_err(s, op_ret);
    dump_errno(s);
    end_header(s, this, nullptr, NO_CONTENT_LENGTH, true);
    status_dumped = true;
  }
}

void RGWDeleteMultiObj_ObjStore_S3::begin_response()
{
  if (!status_dumped) {
    send_status();
  }

  dump_start(s);
#ifdef WITH_BCEBOS
  if (s->prot_flags & RGW_REST_BOS) {
    s->formatter->open_object_section_in_ns("DeleteResult", XMLNS_AWS_S3);
    s->formatter->open_array_section("errors");
  } else
#endif
  {
    s->formatter->open_object_section_in_ns("DeleteResult", XMLNS_AWS_S3);
  }
  rgw_flush_formatter(s, s->formatter);
}

void RGWDeleteMultiObj_ObjStore_S3::send_partial_response(rgw_obj_key& key,
							  bool delete_marker,
							  const string& marker_version_id, int ret)
{
#ifdef WITH_BCEBOS
  if (s->prot_flags & RGW_REST_BOS) {
    if (!key.empty() && ret < 0) {
      struct rgw_http_error r;
      int err_no = -ret;
      s->formatter->open_object_section_in_ns("error", XMLNS_AWS_S3);
      rgw_get_errno_s3(&r, err_no);
      s->formatter->dump_string("key", key.name);
      s->formatter->dump_string("code", r.s3_code);
      s->formatter->dump_string("message", r.message);
      s->formatter->close_section();
    }
  } else
#endif
  {
    if (!key.empty()) {
      if (ret == 0 && !quiet) {
        s->formatter->open_object_section("Deleted");
        s->formatter->dump_string("Key", key.name);
        if (!key.instance.empty()) {
          s->formatter->dump_string("VersionId", key.instance);
        }
        if (delete_marker) {
          s->formatter->dump_bool("DeleteMarker", true);
          s->formatter->dump_string("DeleteMarkerVersionId", marker_version_id);
        }
        s->formatter->close_section();
      } else if (ret < 0) {
        struct rgw_http_error r;
        int err_no;

        s->formatter->open_object_section("Error");

        err_no = -ret;
        rgw_get_errno_s3(&r, err_no);

        s->formatter->dump_string("Key", key.name);
        s->formatter->dump_string("VersionId", key.instance);
        s->formatter->dump_string("Code", r.s3_code);
#ifdef WITH_BCEBOS
        s->formatter->dump_string("Message", r.message);
#else
        s->formatter->dump_string("Message", r.s3_code);
#endif
        s->formatter->close_section();
      }

      rgw_flush_formatter(s, s->formatter);
    }
  }
}

void RGWDeleteMultiObj_ObjStore_S3::end_response()
{

  s->formatter->close_section();
#ifdef WITH_BCEBOS
  if (s->prot_flags & RGW_REST_BOS) {
    stringstream ss;
    s->formatter->close_section();
    s->formatter->flush(ss);
    std::string outs(ss.str());

    if (outs.find("[]") != std::string::npos) {
      outs = "{}";
    }
    ldout(s->cct, 10) << "response is :" << outs << dendl;
    dump_body(s, outs);
  } else
#endif
  {
    rgw_flush_formatter_and_reset(s, s->formatter);
  }
}

void RGWGetObjLayout_ObjStore_S3::send_response()
{
  if (op_ret)
    set_req_state_err(s, op_ret);
  dump_errno(s);
  end_header(s, this, CONTENT_TYPE_JSON);

  JSONFormatter f;

  if (op_ret < 0) {
    return;
  }

  f.open_object_section("result");
  ::encode_json("head", head_obj, &f);
  ::encode_json("manifest", *manifest, &f);
  f.open_array_section("data_location");
  for (auto miter = manifest->obj_begin(); miter != manifest->obj_end(); ++miter) {
    f.open_object_section("obj");
    rgw_raw_obj raw_loc = miter.get_location().get_raw_obj(store);
    ::encode_json("ofs", miter.get_ofs(), &f);
    ::encode_json("loc", raw_loc, &f);
    ::encode_json("loc_ofs", miter.location_ofs(), &f);
    ::encode_json("loc_size", miter.get_stripe_size(), &f);
    f.close_section();
    rgw_flush_formatter(s, &f);
  }
  f.close_section();
  f.close_section();
  rgw_flush_formatter(s, &f);
}

int RGWConfigBucketMetaSearch_ObjStore_S3::get_params()
{
  auto iter = s->info.x_meta_map.find("x-amz-meta-search");
  if (iter == s->info.x_meta_map.end()) {
    s->err.message = "X-Rgw-Meta-Search header not provided";
    ldout(s->cct, 5) << s->err.message << dendl;
    return -EINVAL;
  }

  list<string> expressions;
  get_str_list(iter->second, ",", expressions);

  for (auto& expression : expressions) {
    vector<string> args;
    get_str_vec(expression, ";", args);

    if (args.empty()) {
      s->err.message = "invalid empty expression";
      ldout(s->cct, 5) << s->err.message << dendl;
      return -EINVAL;
    }
    if (args.size() > 2) {
      s->err.message = string("invalid expression: ") + expression;
      ldout(s->cct, 5) << s->err.message << dendl;
      return -EINVAL;
    }

    string key = boost::algorithm::to_lower_copy(rgw_trim_whitespace(args[0]));
    string val;
    if (args.size() > 1) {
      val = boost::algorithm::to_lower_copy(rgw_trim_whitespace(args[1]));
    }

    if (!boost::algorithm::starts_with(key, RGW_AMZ_META_PREFIX)) {
      s->err.message = string("invalid expression, key must start with '" RGW_AMZ_META_PREFIX "' : ") + expression;
      ldout(s->cct, 5) << s->err.message << dendl;
      return -EINVAL;
    }

    key = key.substr(sizeof(RGW_AMZ_META_PREFIX) - 1);

    ESEntityTypeMap::EntityType entity_type;

    if (val.empty() || val == "str" || val == "string") {
      entity_type = ESEntityTypeMap::ES_ENTITY_STR;
    } else if (val == "int" || val == "integer") {
      entity_type = ESEntityTypeMap::ES_ENTITY_INT;
    } else if (val == "date" || val == "datetime") {
      entity_type = ESEntityTypeMap::ES_ENTITY_DATE;
    } else {
      s->err.message = string("invalid entity type: ") + val;
      ldout(s->cct, 5) << s->err.message << dendl;
      return -EINVAL;
    }

    mdsearch_config[key] = entity_type;
  }

  return 0;
}

void RGWConfigBucketMetaSearch_ObjStore_S3::send_response()
{
  if (op_ret)
    set_req_state_err(s, op_ret);
  dump_errno(s);
  end_header(s, this);
}

void RGWGetBucketMetaSearch_ObjStore_S3::send_response()
{
  if (op_ret)
    set_req_state_err(s, op_ret);
  dump_errno(s);
  end_header(s, NULL, nullptr, NO_CONTENT_LENGTH, true);

  Formatter *f = s->formatter;
  f->open_array_section("GetBucketMetaSearchResult");
  for (auto& e : s->bucket_info.mdsearch_config) {
    f->open_object_section("Entry");
    string k = string("x-amz-meta-") + e.first;
#ifdef WITH_BCEBOS
    if (s->prot_flags & RGW_REST_BOS) {
      k = string("x-bce-meta-") + e.first;
    }
#endif
    f->dump_string("Key", k.c_str());
    const char *type;
    switch (e.second) {
      case ESEntityTypeMap::ES_ENTITY_INT:
        type = "int";
        break;
      case ESEntityTypeMap::ES_ENTITY_DATE:
        type = "date";
        break;
      default:
        type = "str";
    }
    f->dump_string("Type", type);
    f->close_section();
  }
  f->close_section();
  rgw_flush_formatter(s, f);
}

void RGWDelBucketMetaSearch_ObjStore_S3::send_response()
{
  if (op_ret)
    set_req_state_err(s, op_ret);
  dump_errno(s);
  end_header(s, this);
}

void RGWPutBucketObjectLock_ObjStore_S3::send_response()
{
  if (op_ret) {
    set_req_state_err(s, op_ret);
  }
  dump_errno(s);
  end_header(s);
}

void RGWGetBucketObjectLock_ObjStore_S3::send_response()
{
  if (op_ret) {
    set_req_state_err(s, op_ret);
  }
  dump_errno(s);
  end_header(s, this, "application/xml");
  dump_start(s);

  if (op_ret) {
    return;
  }
  encode_xml("ObjectLockConfiguration", s->bucket_info.obj_lock, s->formatter);
  rgw_flush_formatter_and_reset(s, s->formatter);
}


int RGWPutObjRetention_ObjStore_S3::get_params()
{
  const char *bypass_gov_header = s->info.env->get("HTTP_X_AMZ_BYPASS_GOVERNANCE_RETENTION");
  if (bypass_gov_header) {
    std::string bypass_gov_decoded = url_decode(bypass_gov_header);
    bypass_governance_mode = boost::algorithm::iequals(bypass_gov_decoded, "true");
  }

  const auto max_size = s->cct->_conf->rgw_max_put_param_size;
  char *c = nullptr;
  int len = 0;
  op_ret = rgw_rest_read_all_input(s, &c, &len, max_size, false);
  if (op_ret < 0) {
    return op_ret;
  }
  bufferptr in_ptr(c, len);
  data.append(in_ptr);
  return op_ret;
}

void RGWPutObjRetention_ObjStore_S3::send_response()
{
  if (op_ret) {
    set_req_state_err(s, op_ret);
  }
  dump_errno(s);
  end_header(s);
}

void RGWGetObjRetention_ObjStore_S3::send_response()
{
  if (op_ret) {
    set_req_state_err(s, op_ret);
  }
  dump_errno(s);
  end_header(s, this, "application/xml");
  dump_start(s);

  if (op_ret) {
    return;
  }
  encode_xml("Retention", obj_retention, s->formatter);
  rgw_flush_formatter_and_reset(s, s->formatter);
}

void RGWPutObjLegalHold_ObjStore_S3::send_response()
{
  if (op_ret) {
    set_req_state_err(s, op_ret);
  }
  dump_errno(s);
  end_header(s);
}

void RGWGetObjLegalHold_ObjStore_S3::send_response()
{
  if (op_ret) {
    set_req_state_err(s, op_ret);
  }
  dump_errno(s);
  end_header(s, this, "application/xml");
  dump_start(s);

  if (op_ret) {
    return;
  }
  encode_xml("LegalHold", obj_legal_hold, s->formatter);
  rgw_flush_formatter_and_reset(s, s->formatter);
}

void RGWGetSymlink_ObjStore_S3::send_response() {
  if (op_ret)
    set_req_state_err(s, op_ret);
  dump_errno(s);
  if (!op_ret) {
    dump_header(s, "x-bce-object-type", "Symlink");
    dump_last_modified(s, state->mtime);
    dump_header_if_nonempty(s, "X-Bce-Symlink-Target", target_object);
    dump_header_if_nonempty(s, "X-Bce-Symlink-Bucket", target_bucket);
    /* dump etag and md5 code */
    auto iter = state->attrset.find(RGW_ATTR_ETAG);
    if (iter != state->attrset.end()) {
      dump_etag(s, iter->second.to_str());
    }
    iter = state->attrset.find(RGW_ATTR_CONTENT_MD5);
    if (iter != state->attrset.end()) {
      dump_header(s, "Content-Md5", iter->second.to_str());
    }
    for (auto iter = state->attrset.begin(); iter != state->attrset.end(); ++iter) {
      const char *name = iter->first.c_str();
      if (strncmp(name, RGW_ATTR_META_PREFIX, sizeof(RGW_ATTR_META_PREFIX)-1) == 0) {
        /* User custom metadata. */
        if (s->prot_flags & RGW_REST_BOS) {
          strncpy(const_cast<char*>(name), RGW_BCE_META_PREFIX, sizeof(RGW_BCE_META_PREFIX)-1);
        }
        name += sizeof(RGW_ATTR_PREFIX) - 1;
        dump_header(s, name, iter->second);
      } else if (iter->first.compare(RGW_ATTR_STORAGE_CLASS) == 0) {
        string storage_class = rgw_bl_to_str(iter->second);
        if (s->prot_flags & RGW_REST_BOS) {
          if (!storage_class.empty()) {
            dump_header(s, RGW_BCE_STORAGE_CLASS, storage_class);
          } else {
            dump_header(s, RGW_BCE_STORAGE_CLASS, "STANDARD");
          }
        } else {
          if (!storage_class.empty() && storage_class.compare("STANDARD") != 0) {
            dump_header(s, RGW_AMZ_STORAGE_CLASS, storage_class);
          }
        }
      }
    }
  }
  end_header(s);
}

/*
 * x-bce-symlink-target: <TargetObjectName>
 * x-bce-symlink-bucket: <TargetBucketName>
 */
int RGWPutSymlink_ObjStore_S3::get_params() {
  int ret = 0;
  if (!s->info.env->exists("HTTP_X_BCE_SYMLINK_TARGET")) {
    return -EINVAL;
  }

  // convert user metadata
  map_qs_metadata(s);

  /* should translate dir path to char */
  target_object_name = url_decode(s->info.env->get("HTTP_X_BCE_SYMLINK_TARGET"));
  if (target_object_name.empty()) {
    return -EINVAL;
  }

  if (s->info.env->exists("HTTP_X_BCE_SYMLINK_BUCKET")) {
    std::string temp_bucket_name = s->info.env->get("HTTP_X_BCE_SYMLINK_BUCKET");
    auto pos = temp_bucket_name.find(":");
    if (pos == string::npos) {
      target_bucket_name = temp_bucket_name;
      target_bucket_tenant = s->bucket_tenant;
    } else {
      target_bucket_tenant = temp_bucket_name.substr(0, pos);
      target_bucket_name = temp_bucket_name.substr(pos + 1);
    }
  } else {
    target_bucket_name = s->bucket.name;
  }

  if (s->info.env->exists("HTTP_X_BCE_STORAGE_CLASS")) {
    storage_class = s->info.env->get("HTTP_X_BCE_STORAGE_CLASS");
    rgw_placement_rule target_placement;
    target_placement.storage_class = rgw_placement_rule::get_canonical_storage_class(storage_class);
    target_placement.name = s->bucket_info.head_placement_rule.name;
    ldout(s->cct, 15) << "placement id: " << target_placement.name << " storage class: " << storage_class << dendl; 
    if (!store->get_zone_params().valid_placement(target_placement)) {
      ldout(s->cct, 5) << "NOTICE: invalid dest placement: " << target_placement.to_str() << dendl;
      s->err.message = "The specified storage class is invalid";
      return -ERR_INVALID_STORAGE_CLASS;
    }
  } else if (!s->bucket_info.storage_class.empty()) {
    // default bucket storage class
    storage_class = s->bucket_info.storage_class;
  }

  if (s->info.env->exists("HTTP_X_BCE_FORBID_OVERWRITE")) {
    std::string overwrite_str = s->info.env->get("HTTP_X_BCE_FORBID_OVERWRITE");
    if ((overwrite_str.compare("True") == 0) || (overwrite_str.compare("true") == 0)) {
      enable_overwrite = false;
    } else if ((overwrite_str.compare("False") == 0) || (overwrite_str.compare("false") == 0)) {
      enable_overwrite = true;
    } else {
      return -EINVAL;
    }
  }

  RGWAccessControlPolicy_S3 s3policy(s->cct);
  if (s->prot_flags & RGW_REST_BOS) {
    ret = create_s3_policy(s, store, s3policy, s->bucket_owner);
  } else {
    ret = create_s3_policy(s, store, s3policy, s->owner);
  }
  if (ret < 0)
    return ret;

  policy = s3policy;

  return 0;
}

int RGWPutSymlink_ObjStore_S3::verify_permission() {
  // normal permission check, but for bosapi, must check user can read target bucket and obj
  int ret = RGWPutSymlink_ObjStore::verify_permission();
  return ret;
}
void RGWPutSymlink_ObjStore_S3::send_response() {
  if (op_ret)
    set_req_state_err(s, op_ret);
  dump_errno(s);

  if (!op_ret) {
    dump_etag(s, target_etag);
  }

  end_header(s);
}

RGWOp *RGWHandler_REST_Service_S3::op_get()
{
  if (is_usage_op()) {
    return new RGWGetUsage_ObjStore_S3;
  } else if (is_list_rgw_op()) {
    return new RGWListRgw_ObjStore_S3;
  } else {
    return new RGWListBuckets_ObjStore_S3;
  }
}

RGWOp *RGWHandler_REST_Service_S3::op_head()
{
  return new RGWListBuckets_ObjStore_S3;
}

RGWOp *RGWHandler_REST_Service_S3::op_post()
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

RGWOp *RGWHandler_REST_Bucket_S3::get_obj_op(bool get_data)
{
  // Non-website mode
  if (get_data) {
    int list_type = 1;
    s->info.args.get_int("list-type", &list_type, 1);
    switch (list_type) {
      case 1:
        return new RGWListBucket_ObjStore_S3;
      case 2:
        return new RGWListBucket_ObjStore_S3v2;
      default:
        ldout(s->cct, 0) << __func__ << ": unsupported list-type " << list_type << dendl;
        return new RGWListBucket_ObjStore_S3;
    }
  } else {
    return new RGWStatBucket_ObjStore_S3;
  }
}

RGWOp *RGWHandler_REST_Bucket_S3::op_get()
{
  if (s->info.args.sub_resource_exists("location"))
    return new RGWGetBucketLocation_ObjStore_S3;

  if (s->info.args.sub_resource_exists("versioning"))
    return new RGWGetBucketVersioning_ObjStore_S3;

  if (s->info.args.sub_resource_exists("website")) {
    if (!s->cct->_conf->rgw_enable_static_website) {
      return NULL;
    }
    return new RGWGetBucketWebsite_ObjStore_S3;
  }

  if (s->info.args.sub_resource_exists("namespace"))
    return new RGWGetBucketNamespace_ObjStore_S3;

  if (s->info.args.exists("mdsearch")) {
    return new RGWGetBucketMetaSearch_ObjStore_S3;
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

  if (s->info.args.exists("mirroring")) {
    return new RGWGetBucketMirroring_ObjStore_S3;
  }

  if (is_acl_op()) {
    return new RGWGetACLs_ObjStore_S3;
  } else if (is_cors_op()) {
    return new RGWGetCORS_ObjStore_S3;
  } else if (is_request_payment_op()) {
    return new RGWGetRequestPayment_ObjStore_S3;
  } else if (s->info.args.exists("uploads")) {
    return new RGWListBucketMultiparts_ObjStore_S3;
  } else if (is_lc_op()) {
    return new RGWGetLC_ObjStore_S3;
  } else if (is_policy_op()) {
    return new RGWGetBucketPolicy;
  } else if(is_notification_op()) {
    return new RGWGetBucketNotification_ObjStore_S3;
  } else if (is_object_lock_op()) {
    return new RGWGetBucketObjectLock_ObjStore_S3;
  } else if (is_logging_op()) {
    return new RGWGetBucketLogging_S3;
  } else if (is_encryption_op()) {
    return new RGWGetBucketEncryption_ObjStore_S3;
  } else if (is_storage_class_op()) {
    return new RGWGetBucketStorageClass_BOS;
  } else if (is_trash_op()) {
    return new RGWGetBucketTrash_BOS;
  }
  return get_obj_op(true);
}

RGWOp *RGWHandler_REST_Bucket_S3::op_head()
{
  if (is_acl_op()) {
    return new RGWGetACLs_ObjStore_S3;
  } else if (s->info.args.exists("uploads")) {
    return new RGWListBucketMultiparts_ObjStore_S3;
  }
  return get_obj_op(false);
}

RGWOp *RGWHandler_REST_Bucket_S3::op_put()
{
  if (s->info.args.sub_resource_exists("versioning"))
    return new RGWSetBucketVersioning_ObjStore_S3;
  if (s->info.args.sub_resource_exists("website")) {
    if (!s->cct->_conf->rgw_enable_static_website) {
      return NULL;
    }
    return new RGWSetBucketWebsite_ObjStore_S3;
  }

  if (s->info.args.sub_resource_exists("namespace")) {
    return new RGWSetBucketNamespace_ObjStore_S3;
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
    return new RGWPutACLs_ObjStore_S3;
  } else if (is_cors_op()) {
    return new RGWPutCORS_ObjStore_S3;
  } else if (is_request_payment_op()) {
    return new RGWSetRequestPayment_ObjStore_S3;
  } else if (is_lc_op()) {
    return new RGWPutLC_ObjStore_S3;
  } else if (is_policy_op()) {
    return new RGWPutBucketPolicy;
  } else if (is_object_lock_op()) {
    return new RGWPutBucketObjectLock_ObjStore_S3;
  } else if (is_logging_op()) {
    return new RGWPutBucketLogging_S3;
  } else if (is_notification_op()) {
    return new RGWPutBucketNotification_ObjStore_S3;
  } else if (is_encryption_op()) {
    return new RGWPutBucketEncryption_ObjStore_S3;
  } else if (is_trash_op()) {
    return new RGWPutBucketTrash_BOS;
  }
  return new RGWCreateBucket_ObjStore_S3;
}

RGWOp *RGWHandler_REST_Bucket_S3::op_delete()
{
  if (is_cors_op()) {
    return new RGWDeleteCORS_ObjStore_S3;
  } else if (is_lc_op()) {
    return new RGWDeleteLC_ObjStore_S3;
  } else if (is_policy_op()) {
    return new RGWDeleteBucketPolicy;
  } else if (is_logging_op()) {
    return new RGWDeleteBucketLogging_S3;
  } else if (is_notification_op()) {
    return new RGWDeleteBucketNotification_ObjStore_S3;
  } else if (is_encryption_op()) {
    return new RGWDeleteBucketEncryption_ObjStore_S3;
  } else if (is_trash_op()) {
    return new RGWDeleteBucketTrash_BOS;
  }

  if (s->info.args.sub_resource_exists("website")) {
    if (!s->cct->_conf->rgw_enable_static_website) {
      return NULL;
    }
    return new RGWDeleteBucketWebsite_ObjStore_S3;
  }

  if (s->info.args.sub_resource_exists("namespace")) {
    return new RGWDeleteBucketNamespace_ObjStore_S3;
  }

  if (s->info.args.exists("mdsearch")) {
    return new RGWDelBucketMetaSearch_ObjStore_S3;
  }
  if (s->info.args.exists("mirroring")) {
    return new RGWDeleteBucketMirroring_ObjStore_S3;
  }

  if (s->info.args.sub_resource_exists("style")) {
    return new RGWDeleteImageStyle_ObjStore_S3;
  }
  if (s->info.args.sub_resource_exists("copyrightProtection")) {
    return new RGWDeleteImageProtection_ObjStore_S3;
  }

  return new RGWDeleteBucket_ObjStore_S3;
}

RGWOp *RGWHandler_REST_Bucket_S3::op_post()
{
  if (s->info.args.exists("delete")) {
    return new RGWDeleteMultiObj_ObjStore_S3;
  }

  if (s->info.args.exists("mdsearch")) {
    return new RGWConfigBucketMetaSearch_ObjStore_S3;
  }

  return new RGWPostObj_ObjStore_S3;
}

RGWOp *RGWHandler_REST_Bucket_S3::op_options()
{
  return new RGWOptionsCORS_ObjStore_S3;
}

RGWOp *RGWHandler_REST_Obj_S3::get_obj_op(bool get_data)
{
  if (is_acl_op()) {
    return new RGWGetACLs_ObjStore_S3;
  }
  RGWGetObj_ObjStore_S3 *get_obj_op = new RGWGetObj_ObjStore_S3;
  get_obj_op->set_get_data(get_data);
  return get_obj_op;
}

RGWOp *RGWHandler_REST_Obj_S3::op_get()
{
  if (is_acl_op()) {
    return new RGWGetACLs_ObjStore_S3;
  } else if (s->info.args.exists("uploadId")) {
    return new RGWListMultipart_ObjStore_S3;
  } else if (s->info.args.exists("layout")) {
    return new RGWGetObjLayout_ObjStore_S3;
  } else if (is_tagging_op()) {
    return new RGWGetObjTags_ObjStore_S3;
  } else if (is_obj_retention_op()) {
    return new RGWGetObjRetention_ObjStore_S3;
  } else if (is_obj_legal_hold_op()) {
    return new RGWGetObjLegalHold_ObjStore_S3;
  } else if (is_symlink_op()) {
    return new RGWGetSymlink_ObjStore_S3;
  }
  return get_obj_op(true);
}

RGWOp *RGWHandler_REST_Obj_S3::op_head()
{
  if (is_acl_op()) {
    return new RGWGetACLs_ObjStore_S3;
  } else if (s->info.args.exists("uploadId")) {
    return new RGWListMultipart_ObjStore_S3;
  }
  return get_obj_op(false);
}

RGWOp *RGWHandler_REST_Obj_S3::op_put()
{
  if (is_acl_op()) {
    return new RGWPutACLs_ObjStore_S3;
  } else if (is_tagging_op()) {
    return new RGWPutObjTags_ObjStore_S3;
  } else if (is_obj_retention_op()) {
    return new RGWPutObjRetention_ObjStore_S3;
  } else if (is_obj_legal_hold_op()) {
    return new RGWPutObjLegalHold_ObjStore_S3;
  } else if (is_symlink_op()) {
    return new RGWPutSymlink_ObjStore_S3;
  }

  if (s->info.env->exists("HTTP_X_BCE_RENAME_KEY") ||
      s->info.env->exists("HTTP_X_AMZ_RENAME_KEY")) {
    return new RGWRenameObj_ObjStore_S3;
  }

  if (s->init_state.src_bucket.empty())
    return new RGWPutObj_ObjStore_S3;
  else
    return new RGWCopyObj_ObjStore_S3;
}

RGWOp *RGWHandler_REST_Obj_S3::op_delete()
{
  if (is_tagging_op()) {
    return new RGWDeleteObjTags_ObjStore_S3;
  }
  string upload_id = s->info.args.get("uploadId");

  if (upload_id.empty())
    return new RGWDeleteObj_ObjStore_S3;
  else
    return new RGWAbortMultipart_ObjStore_S3;
}

RGWOp *RGWHandler_REST_Obj_S3::op_post()
{
  if (s->info.args.exists("uploadId"))
    return new RGWCompleteMultipart_ObjStore_S3;

  if (s->info.args.exists("uploads"))
    return new RGWInitMultipart_ObjStore_S3;

  if (s->info.env->exists("HTTP_X_AMZ_RENAME_KEY")) {
    return new RGWRenameObj_ObjStore_S3;
  }

  return new RGWPostObj_ObjStore_S3;
}

RGWOp *RGWHandler_REST_Obj_S3::op_options()
{
  return new RGWOptionsCORS_ObjStore_S3;
}

int RGWHandler_REST_S3::init_from_header(struct req_state* s,
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
#ifdef WITH_BCEBOS
  ldout(s->cct, 30) << __func__ << " origin url:" << req << dendl;
  if (pos == 0) {
    if (req.length() == 2) {
      req = "";
    } else if (req.length() > 3){
      req = req.substr(3);
    }
  } else {
    pos = req.find("json-api/v1");
    if (pos == 0) {
      if (req.length() == 11) {
        req = "";
      } else if (req.length() > 12){
        req = req.substr(12);
      }
    } else {
      pos = req.find("json-api");
      if (pos == 0) {
        if (req.length() == 8) {
          req = "";
        } else if (req.length() > 9) {
          req = req.substr(9);
        }
      }
    }
  }
#endif
  pos = string::npos;

  pos = req.find('/');
  if (pos != string::npos) {
    first = req.substr(0, pos);
  } else {
    first = req;
  }

  /*
   * XXX The intent of the check for empty is apparently to let the bucket
   * name from DNS to be set ahead. However, we currently take the DNS
   * bucket and re-insert it into URL in rgw_rest.cc:RGWREST::preprocess().
   * So, this check is meaningless.
   *
   * Rather than dropping this, the code needs to be changed into putting
   * the bucket (and its tenant) from DNS and Host: header (HTTP_HOST)
   * into req_status.bucket_name directly.
   */
  if (s->init_state.url_bucket.empty()) {
    // Save bucket to tide us over until token is parsed.
    s->init_state.url_bucket = first;
    if (pos != string::npos) {
      string encoded_obj_str = req.substr(pos+1);
      s->object = rgw_obj_key(encoded_obj_str, s->info.args.get("versionId"));
    }
  } else {
    s->object = rgw_obj_key(req, s->info.args.get("versionId"));
  }
  return 0;
}

static int verify_mfa(RGWRados *store, RGWUserInfo *user, const string& mfa_str, bool *verified)
{
  vector<string> params;
  get_str_vec(mfa_str, " ", params);

  if (params.size() != 2) {
    ldout(store->ctx(), 5) << "NOTICE: invalid mfa string provided: " << mfa_str << dendl;
    return -EINVAL;
  }

  string& serial = params[0];
  string& pin = params[1];

  auto i = user->mfa_ids.find(serial);
  if (i == user->mfa_ids.end()) {
    ldout(store->ctx(), 5) << "NOTICE: user does not have mfa device with serial=" << serial << dendl;
    return -EACCES;
  }

  int ret = store->check_mfa(user->user_id, serial, pin);
  if (ret < 0) {
    ldout(store->ctx(), 20) << "NOTICE: failed to check MFA, serial=" << serial << dendl;
    return -EACCES;
  }

  *verified = true;

  return 0;
}

int RGWHandler_REST_S3::postauth_init()
{
  struct req_init_state *t = &s->init_state;
  bool relaxed_names = s->cct->_conf->rgw_relaxed_s3_bucket_names;

  rgw_parse_url_bucket(t->url_bucket, s->user->user_id.tenant,
                       s->bucket_tenant, s->bucket_name);

  dout(10) << "init_state url_bucket=" << t->url_bucket
           << " s->object=" << (!s->object.empty() ? s->object : rgw_obj_key("<NULL>"sv))
           << " s->bucket=" << rgw_make_bucket_entry_name(s->bucket_tenant, s->bucket_name) << dendl;

  int ret;
  ret = rgw_validate_tenant_name(s->bucket_tenant);
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

  const char *mfa = s->info.env->get("HTTP_X_AMZ_MFA");
  if (mfa) {
    ret = verify_mfa(store, s->user, string(mfa), &s->mfa_verified);
  }

  return 0;
}

int RGWHandler_REST_S3::init(RGWRados *store, struct req_state *s,
                             rgw::io::BasicClient *cio)
{
  int ret;

  s->dialect = "s3";

  ret = rgw_validate_tenant_name(s->bucket_tenant);
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

  const char *cacl = s->info.env->get("HTTP_X_AMZ_ACL");
  if (cacl)
    s->canned_acl = cacl;

  s->has_acl_header = s->info.env->exists_prefix("HTTP_X_AMZ_GRANT");

  const char *copy_source = s->info.env->get("HTTP_X_AMZ_COPY_SOURCE");
  if (copy_source &&
      (! s->info.env->get("HTTP_X_AMZ_COPY_SOURCE_RANGE")) &&
      (! s->info.args.exists("uploadId"))) {

    ret = RGWCopyObj::parse_copy_location(url_decode(copy_source),
                                          s->init_state.src_bucket,
                                          s->src_object);
    if (!ret) {
      ldout(s->cct, 0) << "failed to parse copy location" << dendl;
      return -EINVAL; // XXX why not -ERR_INVALID_BUCKET_NAME or -ERR_BAD_URL?
    }
  }

  const char *sc = s->info.env->get("HTTP_X_AMZ_STORAGE_CLASS");
  if (sc) {
    s->info.storage_class = sc;
  }

  return RGWHandler_REST::init(store, s, cio);
}

/*
 * verify that a signed request comes from the keyholder
 * by checking the signature against our locally-computed version
 *
 * it tries AWS v4 before AWS v2
 */
int RGW_Auth_S3::authorize(RGWRados* const store,
                           const rgw::auth::StrategyRegistry& auth_registry,
                           struct req_state* const s)
{

  /* neither keystone and rados enabled; warn and exit! */
  if (!store->ctx()->_conf->rgw_s3_auth_use_rados &&
      !store->ctx()->_conf->rgw_s3_auth_use_keystone &&
      !store->ctx()->_conf->rgw_s3_auth_use_ldap &&
      !store->ctx()->_conf->rgw_s3_auth_use_iam) {
    dout(0) << "WARNING: no authorization backend enabled! Users will never authenticate." << dendl;
    return -EPERM;
  }

  const auto ret = rgw::auth::Strategy::apply(auth_registry.get_s3_main(), s);
  if (ret == 0) {
    /* Populate the owner info. */
    s->owner.set_id(s->user->user_id);
    s->owner.set_name(s->user->display_name);
  }
  return ret;
}

int RGWHandler_Auth_S3::init(RGWRados *store, struct req_state *state,
                             rgw::io::BasicClient *cio)
{
  int ret = RGWHandler_REST_S3::init_from_header(state, RGW_FORMAT_JSON,
						     true);
  if (ret < 0)
    return ret;

  return RGWHandler_REST::init(store, state, cio);
}

RGWHandler_REST* RGWRESTMgr_S3::get_handler(struct req_state* const s,
                                            const rgw::auth::StrategyRegistry& auth_registry,
                                            const std::string& frontend_prefix)
{
  bool is_s3website = enable_s3website && (s->prot_flags & RGW_REST_WEBSITE);
  int ret = 0;
#ifdef WITH_BCEBOS
  if (s->prot_flags & RGW_REST_BOS) {
    ret = RGWHandler_REST_S3::init_from_header(s, RGW_FORMAT_JSON, true);
    ldout(s->cct, 30) << __func__ << " origin url_bucket:" << s->init_state.url_bucket
                      << ", origin object:" << s->object
                      << dendl;
  } else
#endif
  {
    ret =
      RGWHandler_REST_S3::init_from_header(s,
                                           is_s3website ? RGW_FORMAT_HTML :
                                           RGW_FORMAT_XML, true);
  }
  if (ret < 0)
    return NULL;

  RGWHandler_REST* handler;
  // TODO: Make this more readable
  if (is_s3website) {
    if (s->init_state.url_bucket.empty()) {
      handler = new RGWHandler_REST_Service_S3Website(auth_registry);
    } else if (s->object.empty()) {
      handler = new RGWHandler_REST_Bucket_S3Website(auth_registry);
    } else {
      handler = new RGWHandler_REST_Obj_S3Website(auth_registry);
    }
  } else {
    if (s->init_state.url_bucket.empty()) {
      handler = new RGWHandler_REST_Service_S3(auth_registry);
    } else if (s->object.empty()) {
      handler = new RGWHandler_REST_Bucket_S3(auth_registry);
    } else {
      handler = new RGWHandler_REST_Obj_S3(auth_registry);
    }
  }

  ldout(s->cct, 20) << __func__ << " handler=" << typeid(*handler).name()
		    << dendl;
  return handler;
}

bool RGWHandler_REST_S3Website::web_dir() const {
  std::string subdir_name = url_decode(s->object.name);

  if (subdir_name.empty()) {
    return false;
  } else if (subdir_name.back() == '/') {
    subdir_name.pop_back();
  }

  rgw_obj obj(s->bucket, subdir_name);

  RGWObjectCtx& obj_ctx = *static_cast<RGWObjectCtx *>(s->obj_ctx);
  obj_ctx.obj.set_atomic(obj);
  obj_ctx.obj.set_prefetch_data(obj);

  RGWObjState* state = nullptr;
  if (store->get_obj_state(&obj_ctx, s->bucket_info, obj, &state, false) < 0) {
    return false;
  }
  if (! state->exists) {
    return false;
  }
  return state->exists;
}

int RGWHandler_REST_S3Website::init(RGWRados *store, req_state *s,
                                    rgw::io::BasicClient* cio)
{
  // save the original object name before retarget() replaces it with the
  // result of get_effective_key(). the error_handler() needs the original
  // object name for redirect handling
  original_object_name = s->object.name;

  return RGWHandler_REST_S3::init(store, s, cio);
}

int RGWHandler_REST_S3Website::retarget(RGWOp* op, RGWOp** new_op) {
  *new_op = op;
  ldout(s->cct, 10) << __func__ << " Starting retarget" << dendl;

  if (!(s->prot_flags & RGW_REST_WEBSITE))
    return 0;

  RGWObjectCtx& obj_ctx = *static_cast<RGWObjectCtx *>(s->obj_ctx);
  int ret = store->get_bucket_info(obj_ctx, s->bucket_tenant,
				  s->bucket_name, s->bucket_info, NULL,
				  &s->bucket_attrs);
  if (ret < 0) {
      // TODO-FUTURE: if the bucket does not exist, maybe expose it here?
      return -ERR_NO_SUCH_BUCKET;
  }
  if (!s->bucket_info.has_website) {
      // TODO-FUTURE: if the bucket has no WebsiteConfig, expose it here
      return -ERR_NO_SUCH_WEBSITE_CONFIGURATION;
  }

  rgw_obj_key new_obj;
  s->bucket_info.website_conf.get_effective_key(s->object.name, &new_obj.name, web_dir());
  ldout(s->cct, 10) << "retarget get_effective_key " << s->object << " -> "
		    << new_obj << dendl;

  RGWBWRoutingRule rrule;
  bool should_redirect =
    s->bucket_info.website_conf.should_redirect(new_obj.name, 0, &rrule);

  if (should_redirect) {
    const string& hostname = s->info.env->get("HTTP_HOST", "");
    const string& protocol =
      (s->info.env->get("SERVER_PORT_SECURE") ? "https" : "http");
    int redirect_code = 0;
    rrule.apply_rule(protocol, hostname, s->object.name, &s->redirect,
		    &redirect_code);
    // APply a custom HTTP response code
    if (redirect_code > 0)
      s->err.http_ret = redirect_code; // Apply a custom HTTP response code
    ldout(s->cct, 10) << "retarget redirect code=" << redirect_code
		      << " proto+host:" << protocol << "://" << hostname
		      << " -> " << s->redirect << dendl;
    return -ERR_WEBSITE_REDIRECT;
  }

  /*
   * FIXME: if s->object != new_obj, drop op and create a new op to handle
   * operation. Or remove this comment if it's not applicable anymore
   */

  s->object = new_obj;

  return 0;
}

RGWOp* RGWHandler_REST_S3Website::op_get()
{
  return get_obj_op(true);
}

RGWOp* RGWHandler_REST_S3Website::op_head()
{
  return get_obj_op(false);
}

int RGWHandler_REST_S3Website::serve_errordoc(int http_ret, const string& errordoc_key) {
  int ret = 0;
  s->formatter->reset(); /* Try to throw it all away */

  std::shared_ptr<RGWGetObj_ObjStore_S3Website> getop( static_cast<RGWGetObj_ObjStore_S3Website*>(op_get()));
  if (getop.get() == NULL) {
    return -1; // Trigger double error handler
  }
  getop->init(store, s, this);
  getop->range_str = NULL;
  getop->if_mod = NULL;
  getop->if_unmod = NULL;
  getop->if_match = NULL;
  getop->if_nomatch = NULL;
  s->object = errordoc_key;

  ret = init_permissions(getop.get());
  if (ret < 0) {
    ldout(s->cct, 20) << "serve_errordoc failed, init_permissions ret=" << ret << dendl;
    return -1; // Trigger double error handler
  }

  ret = read_permissions(getop.get());
  if (ret < 0) {
    ldout(s->cct, 20) << "serve_errordoc failed, read_permissions ret=" << ret << dendl;
    return -1; // Trigger double error handler
  }

  if (http_ret) {
     getop->set_custom_http_response(http_ret);
  }

  ret = getop->init_processing();
  if (ret < 0) {
    ldout(s->cct, 20) << "serve_errordoc failed, init_processing ret=" << ret << dendl;
    return -1; // Trigger double error handler
  }

  ret = getop->verify_op_mask();
  if (ret < 0) {
    ldout(s->cct, 20) << "serve_errordoc failed, verify_op_mask ret=" << ret << dendl;
    return -1; // Trigger double error handler
  }

  ret = getop->verify_permission();
  if (ret < 0) {
    ldout(s->cct, 20) << "serve_errordoc failed, verify_permission ret=" << ret << dendl;
    return -1; // Trigger double error handler
  }

  ret = getop->verify_params();
  if (ret < 0) {
    ldout(s->cct, 20) << "serve_errordoc failed, verify_params ret=" << ret << dendl;
    return -1; // Trigger double error handler
  }

  // No going back now
  getop->pre_exec();
  /*
   * FIXME Missing headers:
   * With a working errordoc, the s3 error fields are rendered as HTTP headers,
   *   x-amz-error-code: NoSuchKey
   *   x-amz-error-message: The specified key does not exist.
   *   x-amz-error-detail-Key: foo
   */
  getop->execute();
  getop->complete();
  return 0;

}

int RGWHandler_REST_S3Website::error_handler(int err_no,
					    string* error_content) {
  int new_err_no = -1;
  rgw_http_errors::const_iterator r = rgw_http_s3_errors.find(err_no > 0 ? err_no : -err_no);
  int http_error_code = -1;

  if (r != rgw_http_s3_errors.end()) {
    http_error_code = r->second.first;
  }
  ldout(s->cct, 10) << "RGWHandler_REST_S3Website::error_handler err_no=" << err_no << " http_ret=" << http_error_code << dendl;

  RGWBWRoutingRule rrule;
  bool should_redirect =
    s->bucket_info.website_conf.should_redirect(original_object_name,
                                                http_error_code, &rrule);

  if (should_redirect) {
    const string& hostname = s->info.env->get("HTTP_HOST", "");
    const string& protocol =
      (s->info.env->get("SERVER_PORT_SECURE") ? "https" : "http");
    int redirect_code = 0;
    rrule.apply_rule(protocol, hostname, original_object_name,
                     &s->redirect, &redirect_code);
    // Apply a custom HTTP response code
    if (redirect_code > 0)
      s->err.http_ret = redirect_code; // Apply a custom HTTP response code
    ldout(s->cct, 10) << "error handler redirect code=" << redirect_code
		      << " proto+host:" << protocol << "://" << hostname
		      << " -> " << s->redirect << dendl;
    return -ERR_WEBSITE_REDIRECT;
  } else if (err_no == -ERR_WEBSITE_REDIRECT) {
    // Do nothing here, this redirect will be handled in abort_early's ERR_WEBSITE_REDIRECT block
    // Do NOT fire the ErrorDoc handler
  } else if (!s->bucket_info.website_conf.error_doc.empty()) {
    /* This serves an entire page!
       On success, it will return zero, and no further content should be sent to the socket
       On failure, we need the double-error handler
     */
    new_err_no = RGWHandler_REST_S3Website::serve_errordoc(http_error_code, s->bucket_info.website_conf.error_doc);
    if (new_err_no && new_err_no != -1) {
      err_no = new_err_no;
    }
  } else {
    ldout(s->cct, 20) << "No special error handling today!" << dendl;
  }

  return err_no;
}

RGWOp* RGWHandler_REST_Obj_S3Website::get_obj_op(bool get_data)
{
  /** If we are in website mode, then it is explicitly impossible to run GET or
   * HEAD on the actual directory. We must convert the request to run on the
   * suffix object instead!
   */
  RGWGetObj_ObjStore_S3Website* op = new RGWGetObj_ObjStore_S3Website;
  op->set_get_data(get_data);
  return op;
}

RGWOp* RGWHandler_REST_Bucket_S3Website::get_obj_op(bool get_data)
{
  /** If we are in website mode, then it is explicitly impossible to run GET or
   * HEAD on the actual directory. We must convert the request to run on the
   * suffix object instead!
   */
  RGWGetObj_ObjStore_S3Website* op = new RGWGetObj_ObjStore_S3Website;
  op->set_get_data(get_data);
  return op;
}

RGWOp* RGWHandler_REST_Service_S3Website::get_obj_op(bool get_data)
{
  /** If we are in website mode, then it is explicitly impossible to run GET or
   * HEAD on the actual directory. We must convert the request to run on the
   * suffix object instead!
   */
  RGWGetObj_ObjStore_S3Website* op = new RGWGetObj_ObjStore_S3Website;
  op->set_get_data(get_data);
  return op;
}


namespace rgw {
namespace auth {
namespace s3 {

static rgw::auth::Completer::cmplptr_t
null_completer_factory(const boost::optional<std::string>& secret_key)
{
  return nullptr;
}


AWSEngine::VersionAbstractor::auth_data_t
AWSGeneralAbstractor::get_auth_data(const req_state* const s) const
{
#ifdef WITH_BCEBOS
  if (s->prot_flags & RGW_REST_BOS) {
    ldout(s->cct, 20) << "General signature verification algorithm BOS v1" << dendl;
    return AWSEngine::VersionAbstractor::get_auth_data_bos(s);
  }
#endif
  AwsVersion version;
  AwsRoute route;
  std::tie(version, route) = discover_aws_flavour(s->info);

  if (version == AwsVersion::V2) {
    return get_auth_data_v2(s);
  } else if (version == AwsVersion::V4) {
    return get_auth_data_v4(s, route == AwsRoute::QUERY_STRING);
  } else {
    /* FIXME(rzarzynski): handle anon user. */
    throw -EINVAL;
  }
}

boost::optional<std::string>
AWSGeneralAbstractor::get_v4_canonical_headers(
  const req_info& info,
  const boost::string_view& signedheaders,
  const bool using_qs) const
{
  return rgw::auth::s3::get_v4_canonical_headers(info, signedheaders,
                                                 using_qs, false);
}

AWSEngine::VersionAbstractor::auth_data_t
AWSGeneralAbstractor::get_auth_data_v4(const req_state* const s,
                                       const bool using_qs) const
{
  boost::string_view access_key_id;
  boost::string_view signed_hdrs;

  boost::string_view date;
  boost::string_view credential_scope;
  boost::string_view client_signature;

  int ret = rgw::auth::s3::parse_v4_credentials(s->info,
						access_key_id,
						credential_scope,
						signed_hdrs,
						client_signature,
						date,
						using_qs);
  if (ret < 0) {
    throw ret;
  }

  /* craft canonical headers */
  boost::optional<std::string> canonical_headers = \
    get_v4_canonical_headers(s->info, signed_hdrs, using_qs);
  if (canonical_headers) {
    using sanitize = rgw::crypt_sanitize::log_content;
    ldout(s->cct, 10) << "canonical headers format = "
                      << sanitize{*canonical_headers} << dendl;
  } else {
    throw -EPERM;
  }

  /* Get the expected hash. */
  auto exp_payload_hash = rgw::auth::s3::get_v4_exp_payload_hash(s->info);

  /* Craft canonical URI. Using std::move later so let it be non-const. */
  auto canonical_uri = rgw::auth::s3::get_v4_canonical_uri(s->info);

  /* Craft canonical query string. std::moving later so non-const here. */
  auto canonical_qs = rgw::auth::s3::get_v4_canonical_qs(s->info, using_qs);

  /* Craft canonical request. */
  auto canonical_req_hash = \
    rgw::auth::s3::get_v4_canon_req_hash(s->cct,
                                         s->info.method,
                                         std::move(canonical_uri),
                                         std::move(canonical_qs),
                                         std::move(*canonical_headers),
                                         signed_hdrs,
                                         exp_payload_hash);

  auto string_to_sign = \
    rgw::auth::s3::get_v4_string_to_sign(s->cct,
                                         AWS4_HMAC_SHA256_STR,
                                         date,
                                         credential_scope,
                                         std::move(canonical_req_hash));

  const auto sig_factory = std::bind(rgw::auth::s3::get_v4_signature,
                                     credential_scope,
                                     std::placeholders::_1,
                                     std::placeholders::_2,
                                     std::placeholders::_3);

  /* Requests authenticated with the Query Parameters are treated as unsigned.
   * From "Authenticating Requests: Using Query Parameters (AWS Signature
   * Version 4)":
   *
   *   You don't include a payload hash in the Canonical Request, because
   *   when you create a presigned URL, you don't know the payload content
   *   because the URL is used to upload an arbitrary payload. Instead, you
   *   use a constant string UNSIGNED-PAYLOAD.
   *
   * This means we have absolutely no business in spawning completer. Both
   * aws4_auth_needs_complete and aws4_auth_streaming_mode are set to false
   * by default. We don't need to change that. */
  if (is_v4_payload_unsigned(exp_payload_hash) || is_v4_payload_empty(s)) {
    return {
      access_key_id,
      client_signature,
      std::move(string_to_sign),
      sig_factory,
      null_completer_factory
    };
  } else {
    /* We're going to handle a signed payload. Be aware that even empty HTTP
     * body (no payload) requires verification:
     *
     *   The x-amz-content-sha256 header is required for all AWS Signature
     *   Version 4 requests. It provides a hash of the request payload. If
     *   there is no payload, you must provide the hash of an empty string. */
    if (!is_v4_payload_streamed(exp_payload_hash)) {
      ldout(s->cct, 10) << "delaying v4 auth" << dendl;

      /* payload in a single chunk */
      switch (s->op_type)
      {
        case RGW_OP_CREATE_BUCKET:
        case RGW_OP_PUT_OBJ:
        case RGW_OP_PUT_ACLS:
        case RGW_OP_DELETE_ACLS:
        case RGW_OP_PUT_CORS:
        case RGW_OP_INIT_MULTIPART: // in case that Init Multipart uses CHUNK encoding
        case RGW_OP_COMPLETE_MULTIPART:
        case RGW_OP_SET_BUCKET_VERSIONING:
        case RGW_OP_DELETE_MULTI_OBJ:
        case RGW_OP_ADMIN_SET_METADATA:
        case RGW_OP_SET_BUCKET_WEBSITE:
        case RGW_OP_PUT_BUCKET_POLICY:
        case RGW_OP_PUT_BUCKET_NOTIFICATION:
        case RGW_OP_GET_BUCKET_NOTIFICATION:
        case RGW_OP_DELETE_BUCKET_NOTIFICATION:
        case RGW_OP_PUT_OBJ_TAGGING:
        case RGW_OP_PUT_LC:
        case RGW_OP_SET_REQUEST_PAYMENT:
        case RGW_OP_PUT_BUCKET_OBJ_LOCK:
        case RGW_OP_PUT_OBJ_RETENTION:
        case RGW_OP_PUT_OBJ_LEGAL_HOLD:
        case RGW_OP_PUT_BUCKET_LOGGING:
        case RGW_OP_PUT_BUCKET_ENCRYPTION:
        case RGW_OP_PUT_SYMLINK_OBJ:
          break;
        default:
          dout(10) << "ERROR: AWS4 completion for this operation NOT IMPLEMENTED" << dendl;
          throw -ERR_NOT_IMPLEMENTED;
      }

      const auto cmpl_factory = std::bind(AWSv4ComplSingle::create,
                                          s,
                                          std::placeholders::_1);
      return {
        access_key_id,
        client_signature,
        std::move(string_to_sign),
        sig_factory,
        cmpl_factory
      };
    } else {
      /* IMHO "streamed" doesn't fit too good here. I would prefer to call
       * it "chunked" but let's be coherent with Amazon's terminology. */

      dout(10) << "body content detected in multiple chunks" << dendl;

      /* payload in multiple chunks */

      switch(s->op_type)
      {
        case RGW_OP_PUT_OBJ:
          break;
        default:
          dout(10) << "ERROR: AWS4 completion for this operation NOT IMPLEMENTED (streaming mode)" << dendl;
          throw -ERR_NOT_IMPLEMENTED;
      }

      dout(10) << "aws4 seed signature ok... delaying v4 auth" << dendl;

      /* In the case of streamed payload client sets the x-amz-content-sha256
       * to "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" but uses "UNSIGNED-PAYLOAD"
       * when constructing the Canonical Request. */

      /* In the case of single-chunk upload client set the header's value is
       * coherent with the one used for Canonical Request crafting. */

      /* In the case of query string-based authentication there should be no
       * x-amz-content-sha256 header and the value "UNSIGNED-PAYLOAD" is used
       * for CanonReq. */
      const auto cmpl_factory = std::bind(AWSv4ComplMulti::create,
                                          s,
                                          date,
                                          credential_scope,
                                          client_signature,
                                          std::placeholders::_1);
      return {
        access_key_id,
        client_signature,
        std::move(string_to_sign),
        sig_factory,
        cmpl_factory
      };
    }
  }
}


boost::optional<std::string>
AWSGeneralBoto2Abstractor::get_v4_canonical_headers(
  const req_info& info,
  const boost::string_view& signedheaders,
  const bool using_qs) const
{
  return rgw::auth::s3::get_v4_canonical_headers(info, signedheaders,
                                                 using_qs, true);
}


AWSEngine::VersionAbstractor::auth_data_t
AWSGeneralAbstractor::get_auth_data_v2(const req_state* const s) const
{
  boost::string_view access_key_id;
  boost::string_view signature;
  bool qsr = false;

  const char* http_auth = s->info.env->get("HTTP_AUTHORIZATION");
  if (! http_auth || http_auth[0] == '\0') {
    /* Credentials are provided in query string. We also need to verify
     * the "Expires" parameter now. */
    access_key_id = s->info.args.get("AWSAccessKeyId");
    signature = s->info.args.get("Signature");
    qsr = true;

    boost::string_view expires = s->info.args.get("Expires");
    if (expires.empty()) {
      throw -EPERM;
    }

    /* It looks we have the guarantee that expires is a null-terminated,
     * and thus string_view::data() can be safely used. */
    const time_t exp = atoll(expires.data());
    time_t now;
    time(&now);

    if (now >= exp) {
      throw -EPERM;
    }
  } else {
    /* The "Authorization" HTTP header is being used. */
    const boost::string_view auth_str(http_auth + strlen("AWS "));
    const size_t pos = auth_str.rfind(':');
    if (pos != boost::string_view::npos) {
      access_key_id = auth_str.substr(0, pos);
      signature = auth_str.substr(pos + 1);
    }
  }

  /* Let's canonize the HTTP headers that are covered by the AWS auth v2. */
  std::string string_to_sign;
  utime_t header_time;
  if (! rgw_create_s3_canonical_header(s->info, &header_time, string_to_sign,
        qsr)) {
    ldout(cct, 10) << "failed to create the canonized auth header\n"
                   << rgw::crypt_sanitize::auth{s,string_to_sign} << dendl;
    throw -EPERM;
  }

  ldout(cct, 10) << "string_to_sign:\n"
                 << rgw::crypt_sanitize::auth{s,string_to_sign} << dendl;

  if (!qsr && !is_time_skew_ok(header_time)) {
    throw -ERR_REQUEST_TIME_SKEWED;
  }

  return {
    std::move(access_key_id),
    std::move(signature),
    std::move(string_to_sign),
    rgw::auth::s3::get_v2_signature,
    null_completer_factory
  };
}


AWSEngine::VersionAbstractor::auth_data_t
AWSBrowserUploadAbstractor::get_auth_data_v2(const req_state* const s) const
{
  return {
    s->auth.s3_postobj_creds.access_key,
    s->auth.s3_postobj_creds.signature,
    s->auth.s3_postobj_creds.encoded_policy.to_str(),
    rgw::auth::s3::get_v2_signature,
    null_completer_factory
  };
}

AWSEngine::VersionAbstractor::auth_data_t
AWSBrowserUploadAbstractor::get_auth_data_v4(const req_state* const s) const
{
  const boost::string_view credential = s->auth.s3_postobj_creds.x_amz_credential;

  /* grab access key id */
  const size_t pos = credential.find("/");
  const boost::string_view access_key_id = credential.substr(0, pos);
  dout(10) << "access key id = " << access_key_id << dendl;

  /* grab credential scope */
  const boost::string_view credential_scope = credential.substr(pos + 1);
  dout(10) << "credential scope = " << credential_scope << dendl;

  const auto sig_factory = std::bind(rgw::auth::s3::get_v4_signature,
                                     credential_scope,
                                     std::placeholders::_1,
                                     std::placeholders::_2,
                                     std::placeholders::_3);

  return {
    access_key_id,
    s->auth.s3_postobj_creds.signature,
    s->auth.s3_postobj_creds.encoded_policy.to_str(),
    sig_factory,
    null_completer_factory
  };
}

AWSEngine::VersionAbstractor::auth_data_t
AWSBrowserUploadAbstractor::get_auth_data(const req_state* const s) const
{
#ifdef WITH_BCEBOS
  if (s->prot_flags & RGW_REST_BOS) {
    ldout(s->cct, 0) << "Signature verification algorithm BOS v1" << dendl;
    return AWSEngine::VersionAbstractor::get_auth_data_bos(s);
  }
#endif
  if (s->auth.s3_postobj_creds.x_amz_algorithm == AWS4_HMAC_SHA256_STR) {
    ldout(s->cct, 0) << "Signature verification algorithm AWS v4"
                     << " (AWS4-HMAC-SHA256)" << dendl;
    return get_auth_data_v4(s);
  } else {
    ldout(s->cct, 0) << "Signature verification algorithm AWS v2" << dendl;
    return get_auth_data_v2(s);
  }
}

#ifdef WITH_BCEBOS
AWSEngine::VersionAbstractor::auth_data_t
AWSEngine::VersionAbstractor::get_auth_data_bos(const req_state* const s) const
{
  /* parse bos authorization */
  boost::string_view access_key_id;
  boost::string_view signed_hdrs;
  boost::string_view bce_auth_version;
  boost::string_view date;
  boost::string_view expiration_periond;
  boost::string_view client_signature;

  const bool using_req_params = s->info.request_params.empty() != true;  // use request parameters in query string.
  const bool using_auth_qs = s->info.args.exists("authorization");  // 'authorization' content exists in query string.

  int ret = rgw::auth::s3::parse_bos_authorization(s->info,
                                                   access_key_id,
                                                   signed_hdrs,
                                                   bce_auth_version,
                                                   date,
                                                   expiration_periond,
                                                   client_signature,
                                                   using_auth_qs);
  if (ret < 0) {
    throw ret;
  }
  std::string s_hdrs = string(signed_hdrs);
  ldout(s->cct, 20) << "Start to parse bos authorization." << dendl;
  /* Prepare the data for calucating bos signature */
  // 1. authStringPrefix
  auto string_to_sign = \
    rgw::auth::s3::get_bos_string_to_sign(s->cct,
                                        bce_auth_version,
                                        access_key_id,
                                        date,
                                        expiration_periond);

  // 2. canonicalRequest
  // 2.1 get canonical qs
  std::string canonical_qs = "";
  if (using_req_params) {
    canonical_qs = rgw::auth::s3::get_bos_canonical_qs(s->info, using_auth_qs);
  }
  ldout(s->cct, 20) << "bos canonical qs =  " << canonical_qs << dendl;

  // 2.2 get canonical headers
  auto canonical_hdrs = \
    rgw::auth::s3::get_bos_canonical_headers(s->info, s_hdrs, using_auth_qs, false);
  ldout(s->cct, 20) << "bos canonical headers =  " << canonical_hdrs << dendl;

  // 2.3 get canonical request
  auto canonical_req = \
    rgw::auth::s3::get_bos_canonical_request(s->info, canonical_qs, canonical_hdrs);
  ldout(s->cct, 20) << "bos canonical request =  " << canonical_req << dendl;

  // 3. sig_factory && cmpl_factory
  const auto sig_factory = std::bind(rgw::auth::s3::get_bos_signature,
                                     canonical_req,
                                     std::placeholders::_1,
                                     std::placeholders::_2,
                                     std::placeholders::_3);

  const auto cmpl_factory = std::bind(AWSv4ComplSingle::create,
                                      s,
                                      std::placeholders::_1);
  return {
    access_key_id,
    client_signature,
    std::move(string_to_sign),
    sig_factory,
    cmpl_factory
  };
}
#endif

AWSEngine::result_t
AWSEngine::authenticate(const req_state* const s) const
{
  /* Small reminder: an ver_abstractor is allowed to throw! */
  const auto auth_data = ver_abstractor.get_auth_data(s);

  if (auth_data.access_key_id.empty() || auth_data.client_signature.empty()) {
    return result_t::deny(-EINVAL);
  } else {
    return authenticate(auth_data.access_key_id,
		        auth_data.client_signature,
			auth_data.string_to_sign,
                        auth_data.signature_factory,
			auth_data.completer_factory,
			s);
  }
}

} /* namespace s3 */
} /* namespace auth */
} /* namespace rgw */

rgw::LDAPHelper* rgw::auth::s3::LDAPEngine::ldh = nullptr;
std::mutex rgw::auth::s3::LDAPEngine::mtx;

void rgw::auth::s3::LDAPEngine::init(CephContext* const cct)
{
  if (! cct->_conf->rgw_s3_auth_use_ldap ||
      ! cct->_conf->rgw_ldap_uri.empty()) {
    return;
  }

  if (! ldh) {
    std::lock_guard<std::mutex> lck(mtx);
    if (! ldh) {
      const string& ldap_uri = cct->_conf->rgw_ldap_uri;
      const string& ldap_binddn = cct->_conf->rgw_ldap_binddn;
      const string& ldap_searchdn = cct->_conf->rgw_ldap_searchdn;
      const string& ldap_searchfilter = cct->_conf->rgw_ldap_searchfilter;
      const string& ldap_dnattr = cct->_conf->rgw_ldap_dnattr;
      std::string ldap_bindpw = parse_rgw_ldap_bindpw(cct);

      ldh = new rgw::LDAPHelper(ldap_uri, ldap_binddn, ldap_bindpw,
                                ldap_searchdn, ldap_searchfilter, ldap_dnattr);

      ldh->init();
      ldh->bind();
    }
  }
}

bool rgw::auth::s3::LDAPEngine::valid() {
  std::lock_guard<std::mutex> lck(mtx);
  return (!!ldh);
}

rgw::auth::RemoteApplier::acl_strategy_t
rgw::auth::s3::LDAPEngine::get_acl_strategy() const
{
  //This is based on the assumption that the default acl strategy in
  // get_perms_from_aclspec, will take care. Extra acl spec is not required.
  return nullptr;
}

rgw::auth::RemoteApplier::AuthInfo
rgw::auth::s3::LDAPEngine::get_creds_info(const rgw::RGWToken& token) const noexcept
{
  /* The short form of "using" can't be used here -- we're aliasing a class'
   * member. */
  using acct_privilege_t = \
    rgw::auth::RemoteApplier::AuthInfo::acct_privilege_t;

  return rgw::auth::RemoteApplier::AuthInfo {
    rgw_user(token.id),
    token.id,
    RGW_PERM_FULL_CONTROL,
    acct_privilege_t::IS_PLAIN_ACCT,
    TYPE_LDAP
  };
}

rgw::auth::Engine::result_t
rgw::auth::s3::LDAPEngine::authenticate(
  const boost::string_view& access_key_id,
  const boost::string_view& signature,
  const string_to_sign_t& string_to_sign,
  const signature_factory_t&,
  const completer_factory_t& completer_factory,
  const req_state* const s) const
{
  /* boost filters and/or string_ref may throw on invalid input */
  rgw::RGWToken base64_token;
  try {
    base64_token = rgw::from_base64(access_key_id);
  } catch (...) {
    base64_token = std::string("");
  }

  if (! base64_token.valid()) {
    return result_t::deny();
  }

  //TODO: Uncomment, when we have a migration plan in place.
  //Check if a user of type other than 'ldap' is already present, if yes, then
  //return error.
  /*RGWUserInfo user_info;
  user_info.user_id = base64_token.id;
  if (rgw_get_user_info_by_uid(store, user_info.user_id, user_info) >= 0) {
    if (user_info.type != TYPE_LDAP) {
      ldout(cct, 10) << "ERROR: User id of type: " << user_info.type << " is already present" << dendl;
      return nullptr;
    }
  }*/

  if (ldh->auth(base64_token.id, base64_token.key) != 0) {
    return result_t::deny();
  }

  auto apl = apl_factory->create_apl_remote(cct, s, get_acl_strategy(),
                                            get_creds_info(base64_token));
  return result_t::grant(std::move(apl), completer_factory(boost::none));
} /* rgw::auth::s3::LDAPEngine::authenticate */

#ifdef WITH_BCEIAM

bceiam::IamClientWrapper* rgw::auth::s3::IAMEngine::iam_client = nullptr;
std::mutex rgw::auth::s3::IAMEngine::mtx;

#ifdef WITH_ABCSTACK
std::unordered_map<int, int> rgw::auth::s3::IAMEngine::op_to_role = {
  {RGW_OP_GET_OBJ,                ABCS_ROLE_READ},
  {RGW_OP_STAT_OBJ,               ABCS_ROLE_READ},
  {RGW_OP_GET_OBJ_TAGGING,        ABCS_ROLE_READ},
  {RGW_OP_STAT_BUCKET,            ABCS_ROLE_READ},
  {RGW_OP_GET_ACLS,               ABCS_ROLE_READ},
  {RGW_OP_GET_CORS,               ABCS_ROLE_READ},
  {RGW_OP_LIST_BUCKET,            ABCS_ROLE_READ},
  {RGW_OP_LIST_BUCKETS,           ABCS_ROLE_READ},
  {RGW_OP_LIST_MULTIPART,         ABCS_ROLE_READ},
  {RGW_OP_LIST_BUCKET_MULTIPARTS, ABCS_ROLE_READ},
  {RGW_OP_OPTIONS_CORS,           ABCS_ROLE_READ},
  {RGW_OP_GET_SYMLINK_OBJ,        ABCS_ROLE_READ},

  {RGW_OP_PUT_OBJ,                ABCS_ROLE_OPERATE},
  {RGW_OP_POST_OBJ,               ABCS_ROLE_OPERATE},
  {RGW_OP_DELETE_OBJ,             ABCS_ROLE_OPERATE},
  {RGW_OP_PUT_METADATA_OBJECT,    ABCS_ROLE_OPERATE},
  {RGW_OP_DELETE_MULTI_OBJ,       ABCS_ROLE_OPERATE},
  {RGW_OP_ABORT_MULTIPART,        ABCS_ROLE_OPERATE},
  {RGW_OP_INIT_MULTIPART,         ABCS_ROLE_OPERATE},
  {RGW_OP_COMPLETE_MULTIPART,     ABCS_ROLE_OPERATE},
  {RGW_OP_PUT_OBJ_TAGGING,        ABCS_ROLE_OPERATE},
  {RGW_OP_DELETE_OBJ_TAGGING,     ABCS_ROLE_OPERATE},
  {RGW_OP_PUT_ACLS,               ABCS_ROLE_OPERATE},
  {RGW_OP_PUT_CORS,               ABCS_ROLE_OPERATE},
  {RGW_OP_DELETE_CORS,            ABCS_ROLE_OPERATE},
  {RGW_OP_COPY_OBJ,               ABCS_ROLE_OPERATE},
  {RGW_OP_PUT_SYMLINK_OBJ,        ABCS_ROLE_OPERATE},
};

int rgw::auth::s3::IAMEngine::generate_permissions(const req_state* const s,
    int api, std::set<std::string>& permissions) {
  int role = 0;
  auto iter = op_to_role.find(api);
    if (iter == op_to_role.end()) {
        return bceiam::CODE_ACCESS_DENIED;
    }
    role = iter->second;

    ldout(cct, 20)  << __func__ << s->trans_id << " op needs role:" << role << dendl;
    switch (role) {
      case ABCS_ROLE_READ:
        permissions.insert("Read");
      case ABCS_ROLE_OPERATE:
        permissions.insert("Operate");
      case ABCS_ROLE_ADMIN:
        permissions.insert("Admin");
        break;
      default:
        break;
    }
    return 0;
}

#else
/*
 * generate op_type to permission map, according to
 * bos/acl/common/permission_api.cpp
 * */
std::unordered_map<int, string> rgw::auth::s3::IAMEngine::op_to_coarse_permission = {
  {RGW_OP_GET_OBJ,                "READ"},
  {RGW_OP_STAT_OBJ,               "READ"},
  {RGW_OP_GET_OBJ_TAGGING,        "READ"},
  {RGW_OP_STAT_BUCKET,            "READ"},
  {RGW_OP_LIST_MULTIPART,         "READ"},
  // add options to READ
  {RGW_OP_OPTIONS_CORS,           "READ"}, // ??? need verify
  {RGW_OP_GET_BUCKET_LOCATION,    "READ"},
  {RGW_OP_GET_SYMLINK_OBJ,        "READ"},

  {RGW_OP_PUT_OBJ,                "WRITE"},
  {RGW_OP_POST_OBJ,               "WRITE"},
  {RGW_OP_DELETE_OBJ,             "WRITE"},
  {RGW_OP_PUT_METADATA_OBJECT,    "WRITE"},
  {RGW_OP_DELETE_MULTI_OBJ,       "WRITE"},
  {RGW_OP_ABORT_MULTIPART,        "WRITE"},
  {RGW_OP_INIT_MULTIPART,         "WRITE"},
  {RGW_OP_COMPLETE_MULTIPART,     "WRITE"},
  // append: WRITE
  {RGW_OP_PUT_OBJ_TAGGING,        "WRITE"},
  {RGW_OP_DELETE_OBJ_TAGGING,     "WRITE"},
  {RGW_OP_PUT_SYMLINK_OBJ,        "WRITE"},

  {RGW_OP_LIST_BUCKET,            "LIST"},
  {RGW_OP_LIST_BUCKET_MULTIPARTS, "LIST"},

  // MODIFY: include put object, post object, append, copy, multi_init
  {RGW_OP_COPY_OBJ,               "MODIFY"},

  // do not need FULL_CONTROL list, if not in this map -> just regard it as FULL_CONTROL
};

std::unordered_map<int, string> rgw::auth::s3::IAMEngine::op_to_fine_permission = {
  // GetObjectMeta: include RGW_OP_STAT_OBJ
  {RGW_OP_GET_OBJ,                 "GetObject"},
  {RGW_OP_STAT_OBJ,                "GetObject"}, // bos also add GetObjectMeta permission

  {RGW_OP_PUT_OBJ,                 "PutObject"},
  {RGW_OP_POST_OBJ,                "PutObject"},
  // append: "PutObject"
  {RGW_OP_INIT_MULTIPART,          "PutObject"},
  {RGW_OP_COMPLETE_MULTIPART,      "PutObject"},
  {RGW_OP_ABORT_MULTIPART,         "PutObject"},
  {RGW_OP_COPY_OBJ,                "PutObject"},

  {RGW_OP_DELETE_OBJ,              "DeleteObject"},
  {RGW_OP_DELETE_MULTI_OBJ,        "DeleteObject"},

  {RGW_OP_LIST_MULTIPART,          "ListParts"},

  {RGW_OP_LIST_BUCKET,             "GetBucket"},
  {RGW_OP_LIST_BUCKET_MULTIPARTS,  "GetBucket"},
  {RGW_OP_GET_BUCKET_LOCATION,     "GetBucket"},
  {RGW_OP_STAT_BUCKET,             "GetBucket"},

  {RGW_OP_CREATE_BUCKET,           "PutBucket"},

  {RGW_OP_LIST_BUCKETS,            "ListBucket"},

  // add options to GetBucketCors
  {RGW_OP_OPTIONS_CORS,            "GetBucketCors"},
  {RGW_OP_GET_CORS,                "GetBucketCors"},

  {RGW_OP_PUT_CORS,                "PutBucketCors"},
  {RGW_OP_DELETE_CORS,             "PutBucketCors"},
  {RGW_OP_PUT_IMAGE_STYLE,         "PutBucketStyle"},
  {RGW_OP_DELETE_IMAGE_STYLE,      "PutBucketStyle"},
  {RGW_OP_GET_IMAGE_STYLE,         "GetBucketStyle"},
  {RGW_OP_LIST_IMAGE_STYLE,        "GetBucketStyle"},
  {RGW_OP_PUT_IMAGE_PROTECTION,    "PutCopyRightProtection"},
  {RGW_OP_DELETE_IMAGE_PROTECTION, "PutCopyRightProtection"},
  {RGW_OP_GET_IMAGE_PROTECTION,    "GetCopyRightProtection"},
  {RGW_OP_PUT_BUCKET_MIRRORING,    "PutBucketMirroring"},
  {RGW_OP_GET_BUCKET_MIRRORING,    "GetBucketMirroring"},
};

int rgw::auth::s3::IAMEngine::generate_permissions(const req_state* const s,
    int api, std::set<std::string>& permissions) const{
  auto iter = op_to_coarse_permission.find(api);
  if (iter != op_to_coarse_permission.end()) {
    permissions.insert(iter->second);
  }
  permissions.insert("FULL_CONTROL");

  // For RGW_OP_LIST_BUCKETS, add one more permission "ListBuckets" to the perission field
  if (api == RGW_OP_LIST_BUCKETS) {
    permissions.insert("ListBuckets");
  } else if ((api == RGW_OP_PUT_OBJ && !s->info.args.exists("uploadId")) ||
             api == RGW_OP_POST_OBJ ||
             //api == RGW_OP_APPEND_OBJ ||
             api == RGW_OP_INIT_MULTIPART) {
    permissions.insert("MODIFY");
  } else if (api == RGW_OP_COPY_OBJ) {
    permissions.insert("WRITE");
  } else if (api == RGW_OP_STAT_OBJ) {
    permissions.insert("GetObjectMeta");
  } else if (api == RGW_OP_PUT_ACLS ||
             api == RGW_OP_DELETE_ACLS ||
             api == RGW_OP_PUT_BUCKET_POLICY ||
             api == RGW_OP_DELETE_BUCKET_POLICY) {
    if (s->object.empty()) {
      permissions.insert("PutBucketAcl");
    } else {
      permissions.insert("PutObjectAcl");
    }
  } else if (api == RGW_OP_GET_ACLS ||
             api == RGW_OP_GET_BUCKET_POLICY) {
    if (s->object.empty()) {
      permissions.insert("GetBucketAcl");
    } else {
      permissions.insert("GetObjectAcl");
    }
  }

  iter = op_to_fine_permission.find(api);
  if (iter != op_to_fine_permission.end()) {
    permissions.insert(iter->second);
  }

  return 0;
}

#endif

void rgw::auth::s3::IAMEngine::init(CephContext* const cct) {
 if (!iam_client) {
    std::lock_guard<std::mutex> lck(mtx);
    if (!iam_client) {
        dout(0) << "start to create iam client" << dendl;
        iam_client = new bceiam::IamClientWrapper;
        // TODO: Send ack to the iam proxy
        bool ok = iam_client->init();
        if (!ok) {
            dout(0) << "failed to init iam client" << dendl;
            exit(1);
        }
    }
  }
}

rgw::auth::RemoteApplier::acl_strategy_t
rgw::auth::s3::IAMEngine::get_acl_strategy() const
{
  //This is based on the assumption that the default acl strategy in
  // get_perms_from_aclspec, will take care. Extra acl spec is not required.
  return nullptr;
}

rgw::auth::RemoteApplier::AuthInfo
rgw::auth::s3::IAMEngine::get_creds_info(const bceiam::IamUserInfo& user_iam) const noexcept
{
  /* The short form of "using" can't be used here -- we're aliasing a class'
   * member. */
  using acct_privilege_t = \
    rgw::auth::RemoteApplier::AuthInfo::acct_privilege_t;

  return rgw::auth::RemoteApplier::AuthInfo {
    rgw_user(user_iam.id),
    user_iam.name,
    RGW_PERM_FULL_CONTROL,
    acct_privilege_t::IS_PLAIN_ACCT,
    TYPE_IAM,
    user_iam.subuser_id,
    true
  };
}

int rgw::auth::s3::IAMEngine::prepare_verify_context(const req_state* const s,
        std::list<bceiam::VerifyContext>* resource_context_list) const {
    int api = s->op_type;
    int ret = 0;
    std::set<std::string> permissions;
    ldout(cct, 20) << s->trans_id << " op = " << s->op_type << dendl;

    permissions.clear();
    if (api == RGW_OP_COPY_OBJ) {
      ret = generate_permissions(s, RGW_OP_GET_OBJ, permissions);
      if (ret != 0) {
        return ret;
      }
      ret = GetVerifyContext(s, s->init_state.src_bucket, s->src_object.name,
                             permissions, resource_context_list);
      if (ret != 0)
        return ret;
    } else if (api == RGW_OP_PUT_OBJ) {
      string copy_source;
      string src_bucket;
      rgw_obj_key src_object;
#ifdef WITH_BCEBOS
      if (s->prot_flags & RGW_REST_BOS) {
        if (s->info.env->exists("HTTP_X_BCE_COPY_SOURCE")) {
          copy_source = url_decode(s->info.env->get("HTTP_X_BCE_COPY_SOURCE", ""));
          if (!copy_source.empty()) {
            if (RGWCopyObj::parse_copy_location(url_decode(copy_source),
                                                  src_bucket,
                                                  src_object)) {
              ret = generate_permissions(s, RGW_OP_GET_OBJ, permissions);
              if (ret != 0) {
                return ret;
              }
              ret = GetVerifyContext(s, src_bucket, src_object.name,
                                     permissions, resource_context_list);
              if (ret != 0)
                return ret;
            }
          }
        }
      } else
#endif
      {
        if (s->info.env->exists("HTTP_X_AMZ_COPY_SOURCE")) {
          copy_source = url_decode(s->info.env->get("HTTP_X_AMZ_COPY_SOURCE", ""));
          if (!copy_source.empty()) {
            if (RGWCopyObj::parse_copy_location(url_decode(copy_source),
                                                  src_bucket,
                                                  src_object) == 0) {
              ret = generate_permissions(s, RGW_OP_GET_OBJ, permissions);
              if (ret != 0) {
                return ret;
              }
              ret = GetVerifyContext(s, src_bucket, src_object.name,
                                     permissions, resource_context_list);
              if (ret != 0)
                return ret;
            }
          }
        }
      }
    }

    permissions.clear();
    ret = generate_permissions(s, s->op_type, permissions);
    if (ret != 0) {
      return ret;
    }

    ret = GetVerifyContext(s, s->init_state.url_bucket, s->object.name,
                permissions, resource_context_list);
    return ret;
}

int rgw::auth::s3::IAMEngine::generate_verify_context_fast(
        const req_state* const s,
        const std::string bucket_name, const std::string object_name,
        std::set<std::string>& permissions,
        std::list<bceiam::VerifyContext>* verify_context_list,
        RGWRados* const store) {
    //Build VerifyContext
    bceiam::VerifyContext verify_context;

    verify_context.resource = bucket_name;

    //list bucket, resource contain "/[prefix]"
    if (s->info.args.exists("prefix")) {
      const string& prefix = s->info.args.get("prefix");
      if (prefix.length() > 0) {
        verify_context.resource += "/" + prefix;
      }
    }

    if (!object_name.empty()) {
      verify_context.resource += "/" + object_name;
    }
    const auto& m = s->info.env->get_map();
    const auto remote_addr_param = s->cct->_conf->rgw_remote_addr_param;
    auto i = m.find("REMOTE_ADDR");
    if (remote_addr_param.length()) {
      i = m.find(remote_addr_param);
    }
    if (i != m.end()) {
      verify_context.request_context.ip_address = i->second;
    } else {
      verify_context.request_context.ip_address = "";
    }
    verify_context.request_context.referer = "";

#ifdef WITH_ABCSTACK
    RGWBucketInfo bucket_info;
    map<string, bufferlist> attrs;
    RGWObjectCtx& obj_ctx = *static_cast<RGWObjectCtx *>(s->obj_ctx);
    if (!s->init_state.url_bucket.empty()) {
      int ret = 0;
      if (s->bucket_instance_id.empty())
        ret = store->get_bucket_info(obj_ctx, s->bucket_tenant,
                bucket_name, bucket_info, nullptr, &attrs);
      else {
        ldout(s->cct, 20) << __func__ << "(): req=" << s->trans_id
                       << "bucket_instance_id no empty:" << s->bucket_instance_id
                       << dendl;
        ret = store->get_bucket_instance_info(obj_ctx, s->bucket_instance_id,
                bucket_info, nullptr, &attrs);
      }
      if (ret < 0) {
        ldout(s->cct, 20) << s->trans_id << ", get_bucket_info returned ret=" << ret << dendl;
        return bceiam::CODE_NO_SUCH_BUCKET;
      }
    } else {
      ldout(s->cct, 5) << s->trans_id << "init_state.url_bucket is empty" << dendl;
    }

    map<string, bufferlist>::iterator iter;

    iter = attrs.find(RGW_ATTR_AFFILIATION);
    if (iter != attrs.end()) {
      bufferlist &bl = iter->second;
      std::string affiliation = string(bl.c_str(), bl.length());
      ldout(s->cct, 10) << s->trans_id << "bucket affiliation:" << affiliation << dendl;
 
      std::string organization = "";
      std::string project = "";
      if (!affiliation.empty()) {
        size_t position = affiliation.find("/");
        if (position != string::npos) {
          organization = affiliation.substr(0, position);
          project = affiliation.substr(position + 1, affiliation.size());
        }
      }

      std::string org = organization;
      std::string pro = project;

      verify_context.request_context.variables.insert(std::make_pair("organizationId", org));
      verify_context.request_context.variables.insert(std::make_pair("resourceGroupId", pro));
    }
#endif

    // use iam's region while iam sdk deny empty region in stable version
    verify_context.region = s->cct->_conf->rgw_default_location;
    verify_context.service = s->cct->_conf->rgw_play_service;

    for (auto p : permissions) {
      ldout(s->cct, 20) << s->trans_id << ", op permission:" << p << dendl;
      verify_context.permission.push_back(p);
    }

    ldout(s->cct, 20) << s->trans_id
                   << ", ip_address=" << verify_context.request_context.ip_address
                   << ", referer=" << verify_context.request_context.referer
                   << ", resource=" << verify_context.resource
                   << ", service=" << verify_context.service
                   << dendl;
 
    verify_context_list->push_back(verify_context);
    return 0;
}

int rgw::auth::s3::IAMEngine::GetVerifyContext(
        const req_state* const s,
        const std::string bucket_name, const std::string object_name,
        std::set<std::string>& permissions,
        std::list<bceiam::VerifyContext>* verify_context_list) const {
    return generate_verify_context_fast(s, bucket_name, object_name, permissions, verify_context_list, store);
}

int rgw::auth::s3::IAMEngine::verify_s3(
  const boost::string_view& access_key_id,
  const boost::string_view& signature,
  const string_to_sign_t& string_to_sign,
  const signature_factory_t& signature_factory,
  const req_state* const s,
  string& sk,
  bceiam::IamUserInfo* user_info) const
{
  /* there are two steps for IAM authorization */
  //step1. authenticate user
  const std::string ak = access_key_id.to_string();
  JSONParser parser;
  sk = iam_client->get_sk_from_ak(s, ak, &parser);
  if (sk.empty()) {
    ldout(cct, 5) << __func__ << s->trans_id
                  << ", cannot find sk by ak, ak=" << ak << dendl;
    return -ERR_INVALID_ACCESS_KEY;
  }
  ldout(cct, 30) << __func__ << "(): req_id=" << ", sk= " << sk << dendl;
  const VersionAbstractor::server_signature_t server_signature =
          signature_factory(cct, sk, string_to_sign);

  ldout(cct, 20) << s->trans_id
                 << ", string_to_sign=" << rgw::crypt_sanitize::log_content{string_to_sign}
                 << ", server signature=" << server_signature
                 << ", client signature=" << signature
                 << dendl;

  if (static_cast<boost::string_view>(server_signature) != signature) {
    return -ERR_SIGNATURE_NO_MATCH;
  }

  //step2. authorize user's acl
  int ret = iam_client->get_user_info(s, ak, user_info, &parser);
  ldout(cct, 20) << s->trans_id << ", ret = " << ret
                 << ", subuser_id " << user_info->subuser_id
                 << dendl;
  // ToModify
#ifdef WITH_BAIXIN
  if (ret == bceiam::CODE_NEED_VERIFY) {
    ret = bceiam::CODE_OK;
  }
#else
  if (ret == bceiam::CODE_NEED_VERIFY) {
    std::list<bceiam::VerifyContext> verify_context_list;
    ret = prepare_verify_context(s,  &verify_context_list);

    if (ret == 0) {
      ret = iam_client->verify_subuser(s,
                                       verify_context_list,
                                       user_info->subuser_id,
                                       &parser);
    } else {
      ldout(cct, 5) << s->trans_id << ", prepare_verify_context ret = " << ret << dendl;
      return -ERR_SERVICE_UNAVAILABLE;
    }
  }
#endif
  return ret;
}

int rgw::auth::s3::IAMEngine::verify_sts(const req_state* const s,
                                         bceiam::IamUserInfo* user_info) const
{
  std::list<bceiam::VerifyContext> verify_context_list;

  int ret = prepare_verify_context(s,  &verify_context_list);
  if (ret != 0) {
    ldout(cct, 5) << s->trans_id << ", prepare_verify_context ret = " << ret << dendl;
    return ret;
  }

  ret = iam_client->verify_sts_token(s, verify_context_list, user_info);
  return ret;
}

int rgw::auth::s3::check_batch_bucket_auth(const req_state* const s,
                            const map<string, RGWBucketEnt>& m,
                            std::vector<string>& allowed_buckets) {
  std::list<bceiam::VerifyContext> verify_context_list;
  std::string iam_req_id = "iam_auth_req_" + s->req_id;
  for (auto iter = m.begin(); iter != m.end(); iter++) {
    bceiam::VerifyContext verify_context;

    verify_context.resource = iter->first;
    const auto& env_map = s->info.env->get_map();
    const auto remote_addr_param = s->cct->_conf->rgw_remote_addr_param;
    auto i = env_map.find("REMOTE_ADDR");
    if (remote_addr_param.length()) {
      i = env_map.find(remote_addr_param);
    }
    if (i != env_map.end()) {
      verify_context.request_context.ip_address = i->second;
    } else {
      verify_context.request_context.ip_address = "";
    }
    verify_context.request_context.referer = "";
    if (s->cct->_conf->rgw_abcstore_multi_region) {
      verify_context.region = iter->second.region;
    } else {
      verify_context.region = s->cct->_conf->rgw_default_location;
    }
    verify_context.service = s->cct->_conf->rgw_play_service;
    verify_context.permission.push_back("READ");
    verify_context.permission.push_back("FULL_CONTROL");

    verify_context_list.push_back(verify_context);
  }

  return rgw::auth::s3::IAMEngine::get_iam_client()->verify_batch_auth(s, iam_req_id, verify_context_list, allowed_buckets);
}

rgw::auth::Engine::result_t
rgw::auth::s3::IAMEngine::authenticate(
  const boost::string_view& access_key_id,
  const boost::string_view& signature,
  const string_to_sign_t& string_to_sign,
  const signature_factory_t& signature_factory,
  const completer_factory_t& completer_factory,
  const req_state* const s) const
{
  string sk = "";
  bceiam::IamUserInfo user_info;
  int ret = 0;

#ifdef WITH_BCEBOS
  if (s->prot_flags & RGW_REST_BOS) {
    /**
     * fixed ak,sk pattern (withoud x-bce-session-token header),
     * bos-acl module handle it with VerifyAkSignature.
     * In ceph, just handle it by verify_sts, which works well.
     */
    ret = verify_sts(s, &user_info);
 } else
#endif
 {
   const char* security_token = s->info.env->get("HTTP_X_AMZ_SECURITY_TOKEN");
   if ((security_token && *security_token != '\0' ) ||
       (!s->info.args.get("x-amz-security-token").empty())) {
    ret = verify_sts(s, &user_info);
   } else {
    ret = verify_s3(access_key_id,
              signature,
              string_to_sign,
              signature_factory,
              s,
              sk,
              &user_info);
   }
  }

  if (ret != 0) {
    return result_t::deny(ret);
  }

  ldout(cct, 20) << __func__ << "() get user info, user_name="<< user_info.name
                 << ", user_id=" << user_info.id
                 << ", subuser_id=" << user_info.subuser_id
                 << ", req_id=" << s->req_id
                 << dendl;
    auto apl = apl_factory->create_apl_remote(cct, s, get_acl_strategy(),
            get_creds_info(user_info));
    return result_t::grant(std::move(apl), completer_factory(sk));
}
#endif

void rgw::auth::s3::LDAPEngine::shutdown() {
  if (ldh) {
    delete ldh;
    ldh = nullptr;
  }
}

/* LocalEndgine */
rgw::auth::Engine::result_t
rgw::auth::s3::LocalEngine::authenticate(
  const boost::string_view& _access_key_id,
  const boost::string_view& signature,
  const string_to_sign_t& string_to_sign,
  const signature_factory_t& signature_factory,
  const completer_factory_t& completer_factory,
  const req_state* const s) const
{
  /* get the user info */
  RGWUserInfo user_info;
  /* TODO(rzarzynski): we need to have string-view taking variant. */
  const std::string access_key_id = _access_key_id.to_string();
  int ret = rgw_get_user_info_by_access_key(store, access_key_id, user_info);
  if (ret < 0) {
    ldout(cct, 5) << "error reading user info, uid=" << access_key_id
            << " can't authenticate, ret=" << ret << dendl;
    if (ret != -ETIMEDOUT) {
      return result_t::deny(-ERR_INVALID_ACCESS_KEY);
    } else {
      return result_t::deny(-ETIMEDOUT);
    }
  }
  //TODO: Uncomment, when we have a migration plan in place.
  /*else {
    if (s->user->type != TYPE_RGW) {
      ldout(cct, 10) << "ERROR: User id of type: " << s->user->type
                     << " is present" << dendl;
      throw -EPERM;
    }
  }*/

  const auto iter = user_info.access_keys.find(access_key_id);
  if (iter == std::end(user_info.access_keys)) {
    ldout(cct, 0) << "ERROR: access key not encoded in user info" << dendl;
    return result_t::deny(-EPERM);
  }
  const RGWAccessKey& k = iter->second;

  const VersionAbstractor::server_signature_t server_signature = \
    signature_factory(cct, k.key, string_to_sign);
  auto compare = signature.compare(server_signature);

  ldout(cct, 15) << "string_to_sign="
                 << rgw::crypt_sanitize::log_content{string_to_sign}
                 << dendl;
  ldout(cct, 15) << "server signature=" << server_signature << dendl;
  ldout(cct, 15) << "client signature=" << signature << dendl;
  ldout(cct, 15) << "compare=" << compare << dendl;

  if (compare != 0) {
    return result_t::deny(-ERR_SIGNATURE_NO_MATCH);
  }

  auto apl = apl_factory->create_apl_local(cct, s, user_info, k.subuser);
  return result_t::grant(std::move(apl), completer_factory(k.key));
}

bool rgw::auth::s3::S3AnonymousEngine::is_applicable(
  const req_state* s
) const noexcept {
  if (s->op == OP_OPTIONS) {
    return true;
  }

#ifdef WITH_BCEBOS
  if (s->prot_flags & RGW_REST_BOS) {
    return is_anonymous(s);
  }
#endif

  AwsVersion version;
  AwsRoute route;
  std::tie(version, route) = discover_aws_flavour(s->info);
  return route == AwsRoute::QUERY_STRING && version == AwsVersion::UNKNOWN;
}
