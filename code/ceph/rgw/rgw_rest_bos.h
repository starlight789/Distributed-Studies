// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#ifndef CEPH_RGW_REST_BOS_H
#define CEPH_RGW_REST_BOS_H

#include <mutex>

#include <boost/utility/string_view.hpp>
#include <boost/container/static_vector.hpp>

#include "common/sstring.hh"
#include "common/ceph_json.h"
#include "rgw_op.h"
#include "rgw_rest.h"
#include "rgw_rest_s3.h"
#include "rgw_http_errors.h"
#include "rgw_acl_s3.h"
#include "rgw_policy_s3.h"
#include "rgw_lc_s3.h"
#include "rgw_keystone.h"
#include "rgw_rest_conn.h"
#include "rgw_ldap.h"

#include "rgw_token.h"
#include "include/assert.h"

#include "rgw_auth.h"
#include "rgw_auth_filters.h"
#include "rgw_common.h"

#define RGW_URI_ALL_USERS "http://acs.amazonaws.com/groups/global/AllUsers"
#define XMLNS_AWS_XSI_ID "http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"CanonicalUser"
#define XMLNS_AWS_XSI_GROUP "http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"Group"

class RGWListBuckets_ObjStore_BOS : public RGWListBuckets_ObjStore {
public:
  RGWListBuckets_ObjStore_BOS() {}
  ~RGWListBuckets_ObjStore_BOS() override {}

  int get_params() override {
    limit = -1; /* no limit */
    return 0;
  }
  virtual bool should_get_stats() { return true; }
  void send_response_begin(bool has_buckets) override;
  void send_response_data(RGWUserBuckets& buckets) override;
  void send_response_end() override;
};

class RGWListBucket_ObjStore_BOS : public RGWListBucket_ObjStore {
  bool objs_container;
public:
  RGWListBucket_ObjStore_BOS() : objs_container(false) {
    default_max = 1000;
  }
  ~RGWListBucket_ObjStore_BOS() override {}

  int get_params() override;
  void send_response() override;
};

class RGWGetACLs_ObjStore_BOS : public RGWGetACLs_ObjStore {
public:
  RGWGetACLs_ObjStore_BOS() {}
  ~RGWGetACLs_ObjStore_BOS() override {}

  void send_response() override;
};

class RGWDeleteACLs_ObjStore_BOS : public RGWDeleteACLs {
public:
  RGWDeleteACLs_ObjStore_BOS() {}
  ~RGWDeleteACLs_ObjStore_BOS() override {}

  void send_response() override;
};

class RGWGetBucketPolicy_ObjStore_BOS : public RGWGetBucketPolicy {
public:
  RGWGetBucketPolicy_ObjStore_BOS() {}
  ~RGWGetBucketPolicy_ObjStore_BOS() override {}

  void send_response() override;
};

// bosapi: static website
class RGWSetBucketWebsite_ObjStore_BOS : public RGWSetBucketWebsite {
public:
  RGWSetBucketWebsite_ObjStore_BOS() {}
  ~RGWSetBucketWebsite_ObjStore_BOS() override {}

  int get_params() override;
  void send_response() override;
};

class RGWGetBucketWebsite_ObjStore_BOS : public RGWGetBucketWebsite {
public:
  RGWGetBucketWebsite_ObjStore_BOS() {}
  ~RGWGetBucketWebsite_ObjStore_BOS() override {}

  void send_response() override;
};

class RGWDeleteBucketWebsite_ObjStore_BOS : public RGWDeleteBucketWebsite {
public:
  RGWDeleteBucketWebsite_ObjStore_BOS() {}
  ~RGWDeleteBucketWebsite_ObjStore_BOS() override {}

  void send_response() override;
};

class RGWPutBucketPolicy_ObjStore_BOS : public RGWPutBucketPolicy {
public:
  RGWPutBucketPolicy_ObjStore_BOS() {}
  ~RGWPutBucketPolicy_ObjStore_BOS() override {}

  int get_params() override;
  void send_response() override;
};

class RGWPutBucketQuota_ObjStore_BOS : public RGWPutBucketQuota_ObjStore {
public:
  RGWPutBucketQuota_ObjStore_BOS() {}
  ~RGWPutBucketQuota_ObjStore_BOS() override {}

  int verify_permission() override;
  int get_params() override;
  int check_quota_params() override;
  void send_response() override;
};

class RGWGetBucketQuota_ObjStore_BOS : public RGWGetBucketQuota_ObjStore {
public:
  RGWGetBucketQuota_ObjStore_BOS() {}
  ~RGWGetBucketQuota_ObjStore_BOS() override {}

  int verify_permission() override;
  void send_response() override;
};

class RGWDeleteBucketQuota_ObjStore_BOS : public RGWDeleteBucketQuota_ObjStore {
public:
  RGWDeleteBucketQuota_ObjStore_BOS() {}
  ~RGWDeleteBucketQuota_ObjStore_BOS() override {}

  int verify_permission() override;
  void send_response() override;
};

class RGWPutUserQuota_ObjStore_BOS : public RGWPutUserQuota_ObjStore {
public:
  RGWPutUserQuota_ObjStore_BOS() {}
  ~RGWPutUserQuota_ObjStore_BOS() override {}

  int verify_permission() override;
  int get_params() override;
  int check_quota_params() override;
  void send_response() override;
};

class RGWGetUserQuota_ObjStore_BOS : public RGWGetUserQuota_ObjStore {
public:
  RGWGetUserQuota_ObjStore_BOS() {}
  ~RGWGetUserQuota_ObjStore_BOS() override {}

  int verify_permission() override;
  void send_response() override;
};

class RGWDeleteUserQuota_ObjStore_BOS : public RGWDeleteUserQuota_ObjStore {
public:
  RGWDeleteUserQuota_ObjStore_BOS() {}
  ~RGWDeleteUserQuota_ObjStore_BOS() override {}

  int verify_permission() override;
  void send_response() override;
};

class RGWGetBucketStorageClass_BOS : public RGWGetBucketStorageClass {
public:
  RGWGetBucketStorageClass_BOS() {}
  ~RGWGetBucketStorageClass_BOS() override {}

  void send_response() override;
};

class RGWPutBucketStorageClass_BOS : public RGWPutBucketStorageClass {
public:
  RGWPutBucketStorageClass_BOS() {}
  ~RGWPutBucketStorageClass_BOS() override {}

  int get_params() override;
  void send_response() override;
};

class RGWGetBucketTrash_BOS : public RGWGetBucketTrash {
public:
  RGWGetBucketTrash_BOS() {}
  ~RGWGetBucketTrash_BOS() override {}

  void send_response() override;
};

class RGWPutBucketTrash_BOS : public RGWPutBucketTrash {
public:
  RGWPutBucketTrash_BOS() {}
  ~RGWPutBucketTrash_BOS() override {}

  int get_params() override;
  void send_response() override;
};

class RGWDeleteBucketTrash_BOS : public RGWDeleteBucketTrash {
public:
  RGWDeleteBucketTrash_BOS() {}
  ~RGWDeleteBucketTrash_BOS() override {}

  void send_response() override;
};

class RGWListBucketMultiparts_ObjStore_BOS : public RGWListBucketMultiparts_ObjStore {
public:
  RGWListBucketMultiparts_ObjStore_BOS() {
    default_max = 1000;
  }
  ~RGWListBucketMultiparts_ObjStore_BOS() override {}

  void send_response() override;
};

class RGWCopyObj_ObjStore_BOS : public RGWCopyObj_ObjStore_S3 {
public:
  RGWCopyObj_ObjStore_BOS() {}
  ~RGWCopyObj_ObjStore_BOS() override {}

  void send_response() override;
};

class RGWHandler_REST_BOS : public RGWHandler_REST {
  friend class RGWRESTMgr_BOS;

  const rgw::auth::StrategyRegistry& auth_registry;
public:
  static int init_from_header(struct req_state *s, int default_formatter, bool configurable_format);

  RGWHandler_REST_BOS(const rgw::auth::StrategyRegistry& auth_registry)
    : RGWHandler_REST(),
      auth_registry(auth_registry) {
  }
  ~RGWHandler_REST_BOS() override = default;

  int init(RGWRados *store,
           struct req_state *s,
           rgw::io::BasicClient *cio) override;
  int authorize() override {
    return RGW_Auth_S3::authorize(store, auth_registry, s);
  }
  int postauth_init() override;
};

class RGWInitMultipart_ObjStore_BOS : public RGWInitMultipart_ObjStore_S3 {
public:
  RGWInitMultipart_ObjStore_BOS() {}
  ~RGWInitMultipart_ObjStore_BOS() override {}

  void send_response() override;
};

class RGWListMultipart_ObjStore_BOS : public RGWListMultipart_ObjStore {
public:
  RGWListMultipart_ObjStore_BOS() {}
  ~RGWListMultipart_ObjStore_BOS() override {}

  void send_response() override;
};

class RGWCompleteMultipart_ObjStore_BOS : public RGWCompleteMultipart_ObjStore_S3 {
public:
  RGWCompleteMultipart_ObjStore_BOS() {}
  ~RGWCompleteMultipart_ObjStore_BOS() override {}

  void send_response() override;
};

class RGWInitBucketObjectLock_ObjStore_BOS : public RGWInitBucketObjectLock {
public:
  RGWInitBucketObjectLock_ObjStore_BOS() {}
  ~RGWInitBucketObjectLock_ObjStore_BOS() override {}

  int get_params() override;
  void send_response() override;
};

class RGWGetBucketObjectLock_ObjStore_BOS : public RGWGetBucketObjectLock {
public:
  RGWGetBucketObjectLock_ObjStore_BOS() {}
  ~RGWGetBucketObjectLock_ObjStore_BOS() override {}

  void send_response() override;
};

class RGWDeleteBucketObjectLock_ObjStore_BOS : public RGWDeleteBucketObjectLock {
public:
  RGWDeleteBucketObjectLock_ObjStore_BOS() {}
  ~RGWDeleteBucketObjectLock_ObjStore_BOS() override {}

  void send_response() override;
};

class RGWCompleteBucketObjectLock_ObjStore_BOS : public RGWCompleteBucketObjectLock {
public:
  RGWCompleteBucketObjectLock_ObjStore_BOS() {}
  ~RGWCompleteBucketObjectLock_ObjStore_BOS() override {}

  void send_response() override;
};

class RGWExtendBucketObjectLock_ObjStore_BOS : public RGWExtendBucketObjectLock {
public:
  RGWExtendBucketObjectLock_ObjStore_BOS() {}
  ~RGWExtendBucketObjectLock_ObjStore_BOS() override {}

  void send_response() override;
  int get_params() override;
};

class RGWHandler_REST_Service_BOS : public RGWHandler_REST_BOS {
protected:
  bool is_userquota_op(){
      return s->info.args.exists("userQuota");
  }
  RGWOp *op_put() override;
  RGWOp *op_get() override;
  RGWOp *op_head() override;
  RGWOp *op_post() override;
  RGWOp *op_delete() override;
public:
  using RGWHandler_REST_BOS::RGWHandler_REST_BOS;
  ~RGWHandler_REST_Service_BOS() override = default;
};

class RGWHandler_REST_Bucket_BOS : public RGWHandler_REST_BOS {
protected:
  bool is_acl_op() {
    return s->info.args.exists("acl");
  }
  bool is_cors_op() {
    return s->info.args.exists("cors");
  }
  bool is_lc_op() {
    return s->info.args.exists("lifecycle");
  }
  bool is_obj_update_op() override {
    return is_acl_op() || is_cors_op();
  }
  bool is_request_payment_op() {
    return s->info.args.exists("requestPayment");
  }
  bool is_policy_op() {
    return s->info.args.exists("policy");
  }
  bool is_notification_op() {
    return s->info.args.exists("notification");
  }
  bool is_logging_op() {
    return s->info.args.exists("logging");
  }
  bool is_encryption_op() {
    return s->info.args.exists("encryption");
  }
  bool is_quota_op(){
      return s->info.args.exists("quota");
  }
  bool is_storage_class_op() {
    return s->info.args.exists("storageClass");
  }
  bool is_object_lock_op() {
    return s->info.args.exists("objectlock");
  }
  bool is_complete_object_lock_op() {
    return s->info.args.exists("completeobjectlock");
  }
  bool is_extend_object_lock_op() {
    return s->info.args.exists("extendobjectlock");
  }
  bool is_trash_op() {
    return s->info.args.exists("trash");
  }
  RGWOp *get_obj_op(bool get_data);

  RGWOp *op_get() override;
  RGWOp *op_head() override;
  RGWOp *op_put() override;
  RGWOp *op_delete() override;
  RGWOp *op_post() override;
  RGWOp *op_options() override;
public:
  using RGWHandler_REST_BOS::RGWHandler_REST_BOS;
  ~RGWHandler_REST_Bucket_BOS() override = default;
};

class RGWHandler_REST_Obj_BOS : public RGWHandler_REST_BOS {
protected:
  bool is_acl_op() {
    return s->info.args.exists("acl");
  }
  bool is_cors_op() {
      return s->info.args.exists("cors");
  }
  bool is_tagging_op() {
    return s->info.args.exists("tagging");
  }
  bool is_obj_update_op() override {
    return is_acl_op() || is_tagging_op() ;
  }
  bool is_symlink_op() {
    return s->info.args.exists("symlink");
  }

  RGWOp *get_obj_op(bool get_data);

  RGWOp *op_get() override;
  RGWOp *op_head() override;
  RGWOp *op_put() override;
  RGWOp *op_delete() override;
  RGWOp *op_post() override;
  RGWOp *op_options() override;
public:
  using RGWHandler_REST_BOS::RGWHandler_REST_BOS;
  ~RGWHandler_REST_Obj_BOS() override = default;
};

class RGWRESTMgr_BOS : public RGWRESTMgr {
public:
  RGWRESTMgr_BOS() {}
  ~RGWRESTMgr_BOS() override = default;

  RGWHandler_REST *get_handler(struct req_state* s,
                               const rgw::auth::StrategyRegistry& auth_registry,
                               const std::string& frontend_prefix) override;
protected:
  RGWRESTMgr *get_resource_mgr(struct req_state* const s,
                               const std::string& uri,
                               std::string* const out_uri) override {
    return this;
  }
};

class RGWMultiJSONParser {
protected:
  friend class RGWCompleteMultipart;
  struct multi_part{
    int part_number;
    std::string e_tag;

    void decode_json(JSONObj *obj) {
      JSONDecoder::decode_json("partNumber", part_number, obj);
      JSONDecoder::decode_json("eTag", e_tag, obj);
    }
  };
  RGWMultiCompleteUpload *parts = nullptr;
  std::list<multi_part> multi_parts;

public:
  RGWMultiJSONParser() {}
  ~RGWMultiJSONParser() {
    if (parts)
      delete parts;
  }

  int err_code = 0;
  std::string xml;

  void decode_json(const char *data, int len);
};

class RGWLifecycleJSONParser {
protected:
  friend class RGWPutLC;

  struct action {
    std::string name;
    std::string storage_class;

    void decode_json(JSONObj *obj) {
      JSONDecoder::decode_json("name", name, obj);
      JSONDecoder::decode_json("storageClass", storage_class, obj);
    }

    void dump(Formatter *f) const {
      encode_json("name", name, f);
      if (storage_class != "") {
          encode_json("storageClass", storage_class, f);
      }
    }
  };

  struct bosTime {
    std::string dateGreaterThan;

    void decode_json(JSONObj *obj) {
      JSONDecoder::decode_json("dateGreaterThan", dateGreaterThan, obj);
    }

    void dump(Formatter *f) const {
      encode_json("dateGreaterThan", dateGreaterThan, f);
    }
  };

  struct condition {
    bosTime bos_time;

    void decode_json(JSONObj *obj) {
      JSONDecoder::decode_json("time", bos_time, obj);
    }

    void dump(Formatter *f) const {
      encode_json("time", bos_time, f);
    }
  };

  struct lifecycle_rule {
    std::string id;
    std::string status;
    std::vector<std::string> resource;
    condition cond;
    action act;

    void decode_json(JSONObj *obj) {
      JSONDecoder::decode_json("id", id, obj);
      JSONDecoder::decode_json("status", status, obj);
      JSONDecoder::decode_json("resource", resource, obj);
      JSONDecoder::decode_json("condition", cond, obj);
      JSONDecoder::decode_json("action", act, obj);
    }

    void dump(Formatter *f) const {
      encode_json("id", id, f);
      encode_json("status", status, f);
      encode_json("resource", resource, f);
      encode_json("condition", cond, f);
      encode_json("action", act, f);
    }
  };

  std::list<lifecycle_rule> lifecycle_rules;
public:
  int err_code = 0;
  RGWLifecycleJSONParser() {}
  ~RGWLifecycleJSONParser() {}

  void dump(Formatter *f) const {
    encode_json("rule", lifecycle_rules, f);
  }

  void decode_json(const char *data, int len);
  void dump_xml(Formatter *f, RGWLifecycleConfiguration_S3 *config, int& op_ret);
  void dump_json(Formatter *f, RGWLifecycleConfiguration_S3 *config, string& bucket_name);
};

class RGWMultiDeleteObjParser {
protected:
  friend class RGWDeleteMultiObj;
  struct object {
    std::string key;

    void decode_json(JSONObj *obj) {
      JSONDecoder::decode_json("key", key, obj);
    }

    void dump_xml(Formatter *f) const {
      encode_xml("Key", key, f);
    }
  };

  std::vector<object> objects;

public:
  int err_code = 0;
  RGWMultiDeleteObjParser() {}
  ~RGWMultiDeleteObjParser() {}

  void decode_json(const char *data, int len);
  void dump_xml(Formatter *f) const;
};

class RGWACLsParser {
protected:
  friend class RGWPutACLs;
  friend class RGWDeleteACLs;

  struct id {
    std::string bos_id;

    void decode_json(JSONObj *obj) {
      JSONDecoder::decode_json("id", bos_id, obj);
    }
  };

  struct access_control {
    std::vector<id> bos_grantee;
    std::vector<std::string> bos_permission;

    void decode_json(JSONObj *obj) {
      JSONDecoder::decode_json("grantee", bos_grantee, obj);
      JSONDecoder::decode_json("permission", bos_permission, obj);
    }
  };

  struct grantee {
    std::string id;

    void dump_xml(Formatter *f) const {
      if (id == "*") {
        encode_xml("URI", RGW_URI_ALL_USERS, f);
        encode_xml("Type", "Group", f);
      } else {
        encode_xml("ID", id, f);
        encode_xml("Type", "CanonicalUser", f);
      }
    };
  };

  struct grant {
    grantee gran;
    std::string permission;

    void dump_xml(Formatter *f) const {
      if (gran.id == "*") {
        encode_xml("Grantee",XMLNS_AWS_XSI_GROUP,  gran, f);
      } else {
        encode_xml("Grantee",XMLNS_AWS_XSI_ID,  gran, f);
      }
      encode_xml("Permission", permission, f);
    }
  };

  struct access_control_list {
    std::vector<grant> access_control_list;

    void dump_xml(Formatter *f) const {
      for (auto access_control : access_control_list) {
        encode_xml("Grant", access_control, f);
      }
    }
  };

  struct owner {
    std::string id;

    void dump_xml(Formatter *f) const {
      encode_xml("ID", id, f);
    }

    void set_owner_id(const std::string& owner_id) {
      id = owner_id;
    }
  };

  int err_code = 0;
  owner s3_owner;
  access_control_list s3_access_control_list;
  std::vector<access_control> bos_access_control_list;
public:
  RGWACLsParser() {}
  ~RGWACLsParser() {}

  void set_default_grant(string& owner_id);
  void decode_json(const char *data, int len);
  void dump_xml(Formatter *f) const;
};

class RGWCreateBucketJSONParser
{
private:
  bool enable_multiaz;
  bool enable_dedicated;

  bool decode_json(const char *data, int len) {
    JSONParser parser;
    bool ret = parser.parse(data, len);
    if (!ret)
      return ret;
    JSONDecoder::decode_json("enableMultiAz", enable_multiaz, &parser);
    JSONDecoder::decode_json("enableDedicated", enable_dedicated, &parser);
    return true;
  }

public:
  RGWCreateBucketJSONParser() {}
  virtual ~RGWCreateBucketJSONParser() {}

  bool valid_placement_rule(const char * text, int len) {
    try {
      bool ret = decode_json(text, len);
      if(!ret) {
        dout(5) << __func__ << " ERROR: JSONParser parse text: " << text << ", ret=" << ret << dendl;
        return false;
      }
    } catch (JSONDecoder::err& e) {
      dout(5) << __func__ << " ERROR: Bad placement rule configuration: " << e.message << dendl;
      return false;
    }
    return true;
  }

  bool is_enable_dedicated() {
    return enable_dedicated;
  }
};

#endif /* CEPH_RGW_REST_BOS_H */
