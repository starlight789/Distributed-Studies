// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#ifndef CEPH_RGW_REST_S3_H

#define CEPH_RGW_REST_S3_H
#define TIME_BUF_SIZE 128

#include <mutex>
#include <unordered_map>
#include <list>

#include <boost/utility/string_view.hpp>
#include <boost/container/static_vector.hpp>

#include "common/sstring.hh"
#include "rgw_op.h"
#include "rgw_rest.h"
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
#include "rgw_mirroring.h"

#ifdef WITH_BCEIAM
#include "bceiam.h"
#endif

#define RGW_AUTH_GRACE_MINS 15

struct rgw_http_error {
  int http_ret;
  const char *s3_code;
#ifdef WITH_BCEBOS
  const char *message;
#endif
};

void rgw_get_errno_s3(struct rgw_http_error *e, int err_no);

class RGWGetObj_ObjStore_S3 : public RGWGetObj_ObjStore
{
protected:
  // Serving a custom error page from an object is really a 200 response with
  // just the status line altered.
  int custom_http_ret = 0;
  std::map<std::string, std::string> crypt_http_responses;
public:
  RGWGetObj_ObjStore_S3() {}
  ~RGWGetObj_ObjStore_S3() override {}

  int get_params() override;
  int verify_permission() override;
  int send_response_data_error() override;
  int send_response_data(bufferlist& bl, off_t ofs, off_t len) override;
  void set_custom_http_response(int http_ret) { custom_http_ret = http_ret; }
  int get_decrypt_filter(std::unique_ptr<RGWGetObj_Filter>* filter,
                         RGWGetObj_Filter* cb,
                         bufferlist* manifest_bl) override;
};

class RGWGetObjTags_ObjStore_S3 : public RGWGetObjTags_ObjStore
{
  bufferlist tags_bl;
public:
  RGWGetObjTags_ObjStore_S3() {}
  ~RGWGetObjTags_ObjStore_S3() {}

  void send_response_data(bufferlist &bl) override;
};

class RGWPutObjTags_ObjStore_S3 : public RGWPutObjTags_ObjStore
{
public:
  RGWPutObjTags_ObjStore_S3() {}
  ~RGWPutObjTags_ObjStore_S3() {}

  int get_params() override;
  void send_response() override;
};

class RGWDeleteObjTags_ObjStore_S3 : public RGWDeleteObjTags
{
public:
  ~RGWDeleteObjTags_ObjStore_S3() override {}
  void send_response() override;
};

class RGWListBuckets_ObjStore_S3 : public RGWListBuckets_ObjStore {
public:
  RGWListBuckets_ObjStore_S3() {}
  ~RGWListBuckets_ObjStore_S3() override {}

  int get_params() override {
    limit = -1; /* no limit */
    return 0;
  }
  void send_response_begin(bool has_buckets) override;
  void send_response_data(RGWUserBuckets& buckets) override;
  void send_response_end() override;
};

class RGWGetUsage_ObjStore_S3 : public RGWGetUsage_ObjStore {
public:
  RGWGetUsage_ObjStore_S3() {}
  ~RGWGetUsage_ObjStore_S3() override {}

  int get_params() override ;
  void send_response() override;
};

class RGWListBucket_ObjStore_S3 : public RGWListBucket_ObjStore {
protected:
  bool objs_container;
  bool encode_key {false};
  int get_common_params();
  void send_common_response();
public:
  RGWListBucket_ObjStore_S3() : objs_container(false) {
    default_max = 1000;
  }
  ~RGWListBucket_ObjStore_S3() override {}

  int get_params() override;
  void send_response() override;
  void send_versioned_response();
};

class RGWListBucket_ObjStore_S3v2 : public RGWListBucket_ObjStore_S3 {
  bool fetchOwner;
  bool start_after_exist;
  bool continuation_token_exist;
  std::string startAfter;
  std::string continuation_token;
public:
  RGWListBucket_ObjStore_S3v2() :  fetchOwner(false) {
  }
  ~RGWListBucket_ObjStore_S3v2() override {}

  int get_params() override;
  void send_response() override;
};

class RGWGetBucketLocation_ObjStore_S3 : public RGWGetBucketLocation {
public:
  RGWGetBucketLocation_ObjStore_S3() {}
  ~RGWGetBucketLocation_ObjStore_S3() override {}

  void send_response() override;
};

class RGWListRgw_ObjStore_S3 : public RGWListRgw {
public:
  RGWListRgw_ObjStore_S3() {}
  ~RGWListRgw_ObjStore_S3() override {}

  void send_response() override;
};

class RGWGetBucketVersioning_ObjStore_S3 : public RGWGetBucketVersioning {
public:
  RGWGetBucketVersioning_ObjStore_S3() {}
  ~RGWGetBucketVersioning_ObjStore_S3() override {}

  void send_response() override;
};

class RGWSetBucketVersioning_ObjStore_S3 : public RGWSetBucketVersioning {
public:
  RGWSetBucketVersioning_ObjStore_S3() {}
  ~RGWSetBucketVersioning_ObjStore_S3() override {}

  int get_params() override;
  void send_response() override;
};

class RGWPutBucketMirroring_ObjStore_S3 : public RGWPutBucketMirroring {
public:
  RGWPutBucketMirroring_ObjStore_S3() {}
  ~RGWPutBucketMirroring_ObjStore_S3() override {}

  int get_params() override;
  void send_response() override;
};

class RGWGetBucketMirroring_ObjStore_S3 : public RGWGetBucketMirroring {
public:
  RGWGetBucketMirroring_ObjStore_S3() {}
  ~RGWGetBucketMirroring_ObjStore_S3() override {}

  void send_response() override;
};

class RGWDeleteBucketMirroring_ObjStore_S3 : public RGWDeleteBucketMirroring {
public:
  RGWDeleteBucketMirroring_ObjStore_S3() {}
  ~RGWDeleteBucketMirroring_ObjStore_S3() override {}

 void send_response() override;
};

class RGWGetBucketWebsite_ObjStore_S3 : public RGWGetBucketWebsite {
public:
  RGWGetBucketWebsite_ObjStore_S3() {}
  ~RGWGetBucketWebsite_ObjStore_S3() override {}

  void send_response() override;
};

class RGWSetBucketWebsite_ObjStore_S3 : public RGWSetBucketWebsite {
public:
  RGWSetBucketWebsite_ObjStore_S3() {}
  ~RGWSetBucketWebsite_ObjStore_S3() override {}

  int get_params() override;
  void send_response() override;
};

class RGWDeleteBucketWebsite_ObjStore_S3 : public RGWDeleteBucketWebsite {
public:
  RGWDeleteBucketWebsite_ObjStore_S3() {}
  ~RGWDeleteBucketWebsite_ObjStore_S3() override {}

  void send_response() override;
};

class RGWGetBucketNamespace_ObjStore_S3 : public RGWGetBucketNamespace {
public:
  RGWGetBucketNamespace_ObjStore_S3() {}
  ~RGWGetBucketNamespace_ObjStore_S3() override {}

  void send_response() override;
};

class RGWSetBucketNamespace_ObjStore_S3 : public RGWSetBucketNamespace {
public:
  RGWSetBucketNamespace_ObjStore_S3() {}
  ~RGWSetBucketNamespace_ObjStore_S3() override {}

  void send_response() override;
};

class RGWDeleteBucketNamespace_ObjStore_S3 : public RGWDeleteBucketNamespace {
public:
  RGWDeleteBucketNamespace_ObjStore_S3() {}
  ~RGWDeleteBucketNamespace_ObjStore_S3() override {}

  void send_response() override;
};

class RGWPutImageStyle_ObjStore_S3 : public RGWPutImageStyle_ObjStore {
public:
  RGWPutImageStyle_ObjStore_S3() {}
  ~RGWPutImageStyle_ObjStore_S3() override {}

  void send_response() override;
};

class RGWDeleteImageStyle_ObjStore_S3 : public RGWDeleteImageStyle {
public:
  RGWDeleteImageStyle_ObjStore_S3() {}
  ~RGWDeleteImageStyle_ObjStore_S3() override {}

  void send_response() override;
};

class RGWGetImageStyle_ObjStore_S3 : public RGWGetImageStyle {
public:
  RGWGetImageStyle_ObjStore_S3() {}
  ~RGWGetImageStyle_ObjStore_S3() override {}

  void send_response() override;
};

class RGWListImageStyle_ObjStore_S3 : public RGWListImageStyle {
public:
  RGWListImageStyle_ObjStore_S3() {}
  ~RGWListImageStyle_ObjStore_S3() override {}

  void send_response() override;
};

class RGWPutImageProtection_ObjStore_S3 : public RGWPutImageProtection_ObjStore {
public:
  RGWPutImageProtection_ObjStore_S3() {}
  ~RGWPutImageProtection_ObjStore_S3() override {}

  void send_response() override;
};

class RGWGetImageProtection_ObjStore_S3 : public RGWGetImageProtection {
public:
  RGWGetImageProtection_ObjStore_S3() {}
  ~RGWGetImageProtection_ObjStore_S3() override {}

  void send_response() override;
};

class RGWDeleteImageProtection_ObjStore_S3 : public RGWDeleteImageProtection {
public:
  RGWDeleteImageProtection_ObjStore_S3() {}
  ~RGWDeleteImageProtection_ObjStore_S3() override {}

  void send_response() override;
};

class RGWStatBucket_ObjStore_S3 : public RGWStatBucket_ObjStore {
public:
  RGWStatBucket_ObjStore_S3() {}
  ~RGWStatBucket_ObjStore_S3() override {}

  void send_response() override;
};

class RGWCreateBucket_ObjStore_S3 : public RGWCreateBucket_ObjStore {
public:
  RGWCreateBucket_ObjStore_S3() {}
  ~RGWCreateBucket_ObjStore_S3() override {}

  int get_params() override;
  void send_response() override;
};

class RGWDeleteBucket_ObjStore_S3 : public RGWDeleteBucket_ObjStore {
public:
  RGWDeleteBucket_ObjStore_S3() {}
  ~RGWDeleteBucket_ObjStore_S3() override {}

  void send_response() override;
};

class RGWGetBucketLogging_S3 : public RGWGetBucketLogging {
public: 
  RGWGetBucketLogging_S3() {}
  ~RGWGetBucketLogging_S3() override {}
  
  void send_response() override;
};

class RGWPutBucketLogging_S3 : public RGWPutBucketLogging {
public:
  RGWPutBucketLogging_S3() {}
  ~RGWPutBucketLogging_S3() override {}

  int get_params() override;
  void send_response() override;
};

class RGWDeleteBucketLogging_S3 : public RGWDeleteBucketLogging {
public:
  RGWDeleteBucketLogging_S3() {}
  ~RGWDeleteBucketLogging_S3() override {}

  void send_response() override;
};

class RGWGetBucketEncryption_ObjStore_S3 : public RGWGetBucketEncryption {
public:
  RGWGetBucketEncryption_ObjStore_S3() {}
  ~RGWGetBucketEncryption_ObjStore_S3() override {}

  void send_response() override;
};

class RGWPutBucketEncryption_ObjStore_S3 : public RGWPutBucketEncryption {
public:
  RGWPutBucketEncryption_ObjStore_S3() {}
  ~RGWPutBucketEncryption_ObjStore_S3() override {}

  int get_params() override;
  void send_response() override;
};

class RGWDeleteBucketEncryption_ObjStore_S3 : public RGWDeleteBucketEncryption {
public:
  RGWDeleteBucketEncryption_ObjStore_S3() {}
  ~RGWDeleteBucketEncryption_ObjStore_S3() override {}

  void send_response() override;
};

class RGWPutObj_ObjStore_S3 : public RGWPutObj_ObjStore {
private:
  std::map<std::string, std::string> crypt_http_responses;

public:
  RGWPutObj_ObjStore_S3() {}
  ~RGWPutObj_ObjStore_S3() override {}

  int get_params() override;
  int get_data(bufferlist& bl) override;
  void send_response() override;

  int get_encrypt_filter(std::unique_ptr<RGWPutObjDataProcessor>* filter,
                         RGWPutObjDataProcessor* cb) override;
  int get_decrypt_filter(std::unique_ptr<RGWGetObj_Filter>* filter,
                         RGWGetObj_Filter* cb,
                         map<string, bufferlist>& attrs,
                         bufferlist* manifest_bl) override;
};

class RGWRenameObj_ObjStore_S3 : public RGWRenameObj_ObjStore {
public:
  RGWRenameObj_ObjStore_S3() {}
  ~RGWRenameObj_ObjStore_S3() override {}

  int get_params() override;
  void send_response() override;
};

class RGWPostObj_ObjStore_S3 : public RGWPostObj_ObjStore {
  parts_collection_t parts;
  std::string filename;
  std::string content_type;
  RGWPolicyEnv env;
  RGWPolicy post_policy;
  map<string, string> crypt_http_responses;

  const rgw::auth::StrategyRegistry* auth_registry_ptr = nullptr;

  int get_policy();
  int get_tags();
  void rebuild_key(string& key);

  std::string get_current_filename() const override;
  std::string get_current_content_type() const override;

public:
  RGWPostObj_ObjStore_S3() {}
  ~RGWPostObj_ObjStore_S3() override {}

  int verify_requester(const rgw::auth::StrategyRegistry& auth_registry) {
    auth_registry_ptr = &auth_registry;
    return RGWPostObj_ObjStore::verify_requester(auth_registry);
  }

  int get_params() override;
  int complete_get_params();

  void send_response() override;
  int get_data(ceph::bufferlist& bl, bool& again) override;
  int get_encrypt_filter(std::unique_ptr<RGWPutObjDataProcessor>* filter,
                         RGWPutObjDataProcessor* cb) override;
};

class RGWDeleteObj_ObjStore_S3 : public RGWDeleteObj_ObjStore {
public:
  RGWDeleteObj_ObjStore_S3() {}
  ~RGWDeleteObj_ObjStore_S3() override {}

  int get_params() override;
  void send_response() override;
};

class RGWCopyObj_ObjStore_S3 : public RGWCopyObj_ObjStore {
public:
  RGWCopyObj_ObjStore_S3() : sent_header(false) {}
  ~RGWCopyObj_ObjStore_S3() override {}

  int init_dest_policy() override;
  int get_params() override;
  int check_storage_class(const rgw_placement_rule& src_placement) override;
  void send_partial_response(off_t ofs) override;
  void send_response() override;

  bool sent_header;
};

class RGWGetACLs_ObjStore_S3 : public RGWGetACLs_ObjStore {
public:
  RGWGetACLs_ObjStore_S3() {}
  ~RGWGetACLs_ObjStore_S3() override {}

  void send_response() override;
};

class RGWPutACLs_ObjStore_S3 : public RGWPutACLs_ObjStore {
public:
  RGWPutACLs_ObjStore_S3() {}
  ~RGWPutACLs_ObjStore_S3() override {}

  int get_policy_from_state(RGWRados *store, struct req_state *s, stringstream& ss) override;
  void send_response() override;
  int get_params() override;
};

class RGWGetLC_ObjStore_S3 : public RGWGetLC_ObjStore {
protected:
  RGWLifecycleConfiguration_S3  config;
public:
  RGWGetLC_ObjStore_S3() {}
  ~RGWGetLC_ObjStore_S3() override {}
  void execute() override;

 void send_response() override;
};

class RGWPutLC_ObjStore_S3 : public RGWPutLC_ObjStore {
public:
  RGWPutLC_ObjStore_S3() {}
  ~RGWPutLC_ObjStore_S3() override {}
  
 void send_response() override;
};

class RGWDeleteLC_ObjStore_S3 : public RGWDeleteLC_ObjStore {
public:
  RGWDeleteLC_ObjStore_S3() {}
  ~RGWDeleteLC_ObjStore_S3() override {}
  
 void send_response() override;
};

class RGWGetCORS_ObjStore_S3 : public RGWGetCORS_ObjStore {
public:
  RGWGetCORS_ObjStore_S3() {}
  ~RGWGetCORS_ObjStore_S3() override {}

  void send_response() override;
};

class RGWPutCORS_ObjStore_S3 : public RGWPutCORS_ObjStore {
public:
  RGWPutCORS_ObjStore_S3() {}
  ~RGWPutCORS_ObjStore_S3() override {}

  int get_params() override;
  void send_response() override;
};

class RGWDeleteCORS_ObjStore_S3 : public RGWDeleteCORS_ObjStore {
public:
  RGWDeleteCORS_ObjStore_S3() {}
  ~RGWDeleteCORS_ObjStore_S3() override {}

  void send_response() override;
};

class RGWPutBucketNotification_ObjStore_S3 : public RGWPutBucketNotification_ObjStore {
public:
  RGWPutBucketNotification_ObjStore_S3() {}
  ~RGWPutBucketNotification_ObjStore_S3() override {}

  int get_params() override;
  void send_response() override;
};

class RGWGetBucketNotification_ObjStore_S3 : public RGWGetBucketNotification_ObjStore {
public:
  RGWGetBucketNotification_ObjStore_S3() {}
  ~RGWGetBucketNotification_ObjStore_S3() override {}

  void send_response() override;
};

class RGWDeleteBucketNotification_ObjStore_S3 : public RGWDeleteBucketNotification_ObjStore {
public:
  RGWDeleteBucketNotification_ObjStore_S3() {}
  ~RGWDeleteBucketNotification_ObjStore_S3() override {}

  void send_response() override;
};

class RGWOptionsCORS_ObjStore_S3 : public RGWOptionsCORS_ObjStore {
public:
  RGWOptionsCORS_ObjStore_S3() {}
  ~RGWOptionsCORS_ObjStore_S3() override {}

  void send_response() override;
};

class RGWGetRequestPayment_ObjStore_S3 : public RGWGetRequestPayment {
public:
  RGWGetRequestPayment_ObjStore_S3() {}
  ~RGWGetRequestPayment_ObjStore_S3() override {}

  void send_response() override;
};

class RGWSetRequestPayment_ObjStore_S3 : public RGWSetRequestPayment {
public:
  RGWSetRequestPayment_ObjStore_S3() {}
  ~RGWSetRequestPayment_ObjStore_S3() override {}

  int get_params() override;
  void send_response() override;
};

class RGWInitMultipart_ObjStore_S3 : public RGWInitMultipart_ObjStore {
public:
  RGWInitMultipart_ObjStore_S3() {}
  ~RGWInitMultipart_ObjStore_S3() override {}

  int get_params() override;
  void send_response() override;
  int prepare_encryption(map<string, bufferlist>& attrs) override;

  std::map<std::string, std::string> crypt_http_responses;
};

class RGWCompleteMultipart_ObjStore_S3 : public RGWCompleteMultipart_ObjStore {
public:
  RGWCompleteMultipart_ObjStore_S3() {}
  ~RGWCompleteMultipart_ObjStore_S3() override {}

  int get_params() override;
  void send_response() override;
};

class RGWAbortMultipart_ObjStore_S3 : public RGWAbortMultipart_ObjStore {
public:
  RGWAbortMultipart_ObjStore_S3() {}
  ~RGWAbortMultipart_ObjStore_S3() override {}

  void send_response() override;
};

class RGWListMultipart_ObjStore_S3 : public RGWListMultipart_ObjStore {
public:
  RGWListMultipart_ObjStore_S3() {}
  ~RGWListMultipart_ObjStore_S3() override {}

  void send_response() override;
};

class RGWListBucketMultiparts_ObjStore_S3 : public RGWListBucketMultiparts_ObjStore {
public:
  RGWListBucketMultiparts_ObjStore_S3() {
    default_max = 1000;
  }
  ~RGWListBucketMultiparts_ObjStore_S3() override {}

  void send_response() override;
};

class RGWDeleteMultiObj_ObjStore_S3 : public RGWDeleteMultiObj_ObjStore {
public:
  RGWDeleteMultiObj_ObjStore_S3() {}
  ~RGWDeleteMultiObj_ObjStore_S3() override {}

  int get_params() override;
  void send_status() override;
  void begin_response() override;
  void send_partial_response(rgw_obj_key& key, bool delete_marker,
                             const string& marker_version_id, int ret) override;
  void end_response() override;
};

class RGWPutBucketObjectLock_ObjStore_S3 : public RGWPutBucketObjectLock_ObjStore {
public:
  RGWPutBucketObjectLock_ObjStore_S3() {}
  ~RGWPutBucketObjectLock_ObjStore_S3() override {}
  void send_response() override;
};

class RGWGetBucketObjectLock_ObjStore_S3 : public RGWGetBucketObjectLock_ObjStore {
public:
  RGWGetBucketObjectLock_ObjStore_S3() {}
  ~RGWGetBucketObjectLock_ObjStore_S3() {}
  void send_response() override;
};

class RGWPutObjRetention_ObjStore_S3 : public RGWPutObjRetention_ObjStore {
public:
  RGWPutObjRetention_ObjStore_S3() {}
  ~RGWPutObjRetention_ObjStore_S3() {}
  int get_params() override;
  void send_response() override;
};

class RGWGetObjRetention_ObjStore_S3 : public RGWGetObjRetention_ObjStore {
public:
  RGWGetObjRetention_ObjStore_S3() {}
  ~RGWGetObjRetention_ObjStore_S3() {}
  void send_response() override;
};

class RGWPutObjLegalHold_ObjStore_S3 : public RGWPutObjLegalHold_ObjStore {
public:
  RGWPutObjLegalHold_ObjStore_S3() {}
  ~RGWPutObjLegalHold_ObjStore_S3() {}
  void send_response() override;
};

class RGWGetObjLegalHold_ObjStore_S3 : public RGWGetObjLegalHold_ObjStore {
public:
  RGWGetObjLegalHold_ObjStore_S3() {}
  ~RGWGetObjLegalHold_ObjStore_S3() {}
  void send_response() override;
};

class RGWGetObjLayout_ObjStore_S3 : public RGWGetObjLayout {
public:
  RGWGetObjLayout_ObjStore_S3() {}
  ~RGWGetObjLayout_ObjStore_S3() {}

  void send_response();
};

class RGWConfigBucketMetaSearch_ObjStore_S3 : public RGWConfigBucketMetaSearch {
public:
  RGWConfigBucketMetaSearch_ObjStore_S3() {}
  ~RGWConfigBucketMetaSearch_ObjStore_S3() {}

  int get_params() override;
  void send_response() override;
};

class RGWGetBucketMetaSearch_ObjStore_S3 : public RGWGetBucketMetaSearch {
public:
  RGWGetBucketMetaSearch_ObjStore_S3() {}
  ~RGWGetBucketMetaSearch_ObjStore_S3() {}

  void send_response() override;
};

class RGWDelBucketMetaSearch_ObjStore_S3 : public RGWDelBucketMetaSearch {
public:
  RGWDelBucketMetaSearch_ObjStore_S3() {}
  ~RGWDelBucketMetaSearch_ObjStore_S3() {}

  void send_response() override;
};

class RGWGetSymlink_ObjStore_S3 : public RGWGetSymlink_ObjStore {
public:
  RGWGetSymlink_ObjStore_S3() {}
  ~RGWGetSymlink_ObjStore_S3() {}

  void send_response() override;
};

class RGWPutSymlink_ObjStore_S3 : public RGWPutSymlink_ObjStore {
public:
  RGWPutSymlink_ObjStore_S3() {}
  ~RGWPutSymlink_ObjStore_S3() {}

  int get_params() override;
  int verify_permission() override;
  void send_response() override;
};

class RGW_Auth_S3 {
public:
  static int authorize(RGWRados *store,
                       const rgw::auth::StrategyRegistry& auth_registry,
                       struct req_state *s);
};

class RGWHandler_Auth_S3 : public RGWHandler_REST {
  friend class RGWRESTMgr_S3;

  const rgw::auth::StrategyRegistry& auth_registry;

public:
  RGWHandler_Auth_S3(const rgw::auth::StrategyRegistry& auth_registry)
    : RGWHandler_REST(),
      auth_registry(auth_registry) {
  }
  ~RGWHandler_Auth_S3() override = default;

  static int validate_bucket_name(const string& bucket);
  static int validate_object_name(const string& bucket);

  int init(RGWRados *store,
           struct req_state *s,
           rgw::io::BasicClient *cio) override;
  int authorize() override {
    return RGW_Auth_S3::authorize(store, auth_registry, s);
  }
  int postauth_init() override { return 0; }
};

class RGWHandler_REST_S3 : public RGWHandler_REST {
  friend class RGWRESTMgr_S3;

  const rgw::auth::StrategyRegistry& auth_registry;
public:
  static int init_from_header(struct req_state *s, int default_formatter, bool configurable_format);

  RGWHandler_REST_S3(const rgw::auth::StrategyRegistry& auth_registry)
    : RGWHandler_REST(),
      auth_registry(auth_registry) {
  }
  ~RGWHandler_REST_S3() override = default;

  int init(RGWRados *store,
           struct req_state *s,
           rgw::io::BasicClient *cio) override;
  int authorize() override {
    return RGW_Auth_S3::authorize(store, auth_registry, s);
  }
  int postauth_init() override;
};

class RGWHandler_REST_Service_S3 : public RGWHandler_REST_S3 {
protected:
  bool is_usage_op() {
    return s->info.args.exists("usage");
  }
  bool is_list_rgw_op() {
    if (!s->cct->_conf->rgw_enable_list_rgw) {
      return false;
    }
    return s->info.args.exists("rgw");
  }
  RGWOp *op_get() override;
  RGWOp *op_head() override;
  RGWOp *op_post() override;
public:
  using RGWHandler_REST_S3::RGWHandler_REST_S3;
  ~RGWHandler_REST_Service_S3() override = default;
};

class RGWHandler_REST_Bucket_S3 : public RGWHandler_REST_S3 {
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
  bool is_object_lock_op() {
    return s->info.args.exists("object-lock");
  }
  bool is_logging_op() {
    return s->info.args.exists("logging");
  }
  bool is_notification_op() {
    return s->info.args.exists("notification");
  }
  bool is_encryption_op() {
    return s->info.args.exists("encryption");
  }
  bool is_storage_class_op() {
    return s->info.args.exists("storageClass");
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
  using RGWHandler_REST_S3::RGWHandler_REST_S3;
  ~RGWHandler_REST_Bucket_S3() override = default;
};

class RGWHandler_REST_Obj_S3 : public RGWHandler_REST_S3 {
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
  bool is_obj_retention_op() {
    return s->info.args.exists("retention");
  }
  bool is_obj_legal_hold_op() {
    return s->info.args.exists("legal-hold");
  }
  bool is_obj_update_op() override {
    return is_acl_op() || is_tagging_op() || is_obj_retention_op() || is_obj_legal_hold_op();
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
  using RGWHandler_REST_S3::RGWHandler_REST_S3;
  ~RGWHandler_REST_Obj_S3() override = default;
};

class RGWRESTMgr_S3 : public RGWRESTMgr {
private:
  bool enable_s3website;
public:
  explicit RGWRESTMgr_S3(bool enable_s3website = false)
    : enable_s3website(enable_s3website) {
  }

  ~RGWRESTMgr_S3() override = default;

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

class RGWHandler_REST_Obj_S3Website;

static inline bool looks_like_ip_address(const char *bucket)
{
  int num_periods = 0;
  bool expect_period = false;
  for (const char *b = bucket; *b; ++b) {
    if (*b == '.') {
      if (!expect_period)
	return false;
      ++num_periods;
      if (num_periods > 3)
	return false;
      expect_period = false;
    }
    else if (isdigit(*b)) {
      expect_period = true;
    }
    else {
      return false;
    }
  }
  return (num_periods == 3);
}

static inline int valid_s3_object_name(const string& name) {
  if (name.size() > 1024) {
    return -ERR_INVALID_OBJECT_NAME;
  }
  if (check_utf8(name.c_str(), name.size())) {
    return -ERR_INVALID_OBJECT_NAME;
  }
  return 0;
}

static inline int valid_s3_bucket_name(const string& name, bool relaxed=false)
{
  // This function enforces Amazon's spec for bucket names.
  // (The requirements, not the recommendations.)
  int len = name.size();
  if (len < 3) {
    // Name too short
    return -ERR_INVALID_BUCKET_NAME;
  } else if (len > 255) {
    // Name too long
    return -ERR_INVALID_BUCKET_NAME;
  }

  // bucket names must start with a number, letter, or underscore
  if (!(isalpha(name[0]) || isdigit(name[0]))) {
    if (!relaxed)
      return -ERR_INVALID_BUCKET_NAME;
    else if (!(name[0] == '_' || name[0] == '.' || name[0] == '-'))
      return -ERR_INVALID_BUCKET_NAME;
  }

  for (const char *s = name.c_str(); *s; ++s) {
    char c = *s;
    if (isdigit(c) || (c == '.'))
      continue;
    if (isalpha(c))
      continue;
    if ((c == '-') || (c == '_'))
      continue;
    // Invalid character
    return -ERR_INVALID_BUCKET_NAME;
  }

  if (looks_like_ip_address(name.c_str()))
    return -ERR_INVALID_BUCKET_NAME;

  return 0;
}

static inline int valid_bos_bucket_name(const string& bucket_name) {
    auto length = bucket_name.size();
    if (length < 3 || length > 63) {
        return -ERR_INVALID_BUCKET_NAME;
    }

    if ('-' == bucket_name[0] || '-' == bucket_name[length-1]) {
        return -ERR_INVALID_BUCKET_NAME;
    }

    for (auto c : bucket_name) {
        if ('-' == c ||
            isdigit(c) ||
            (isalpha(c) && islower(c))) {
            continue;
        }
        return -ERR_INVALID_BUCKET_NAME;
    }

    return 0;
}

enum class AwsVersion {
  UNKNOWN,
  V2,
  V4
};

enum class AwsRoute {
  UNKNOWN,
  QUERY_STRING,
  HEADERS
};

inline std::pair<AwsVersion, AwsRoute>
discover_aws_flavour(const req_info& info);

namespace rgw {
namespace auth {
namespace s3 {

class AWSEngine : public rgw::auth::Engine {
public:
  class VersionAbstractor {
    static constexpr size_t DIGEST_SIZE_V2 = CEPH_CRYPTO_HMACSHA1_DIGESTSIZE;
    static constexpr size_t DIGEST_SIZE_V4 = CEPH_CRYPTO_HMACSHA256_DIGESTSIZE;

    /* Knowing the signature max size allows us to employ the sstring, and thus
     * avoid dynamic allocations. The multiplier comes from representing digest
     * in the base64-encoded form. */
    static constexpr size_t SIGNATURE_MAX_SIZE = \
      std::max(DIGEST_SIZE_V2, DIGEST_SIZE_V4) * 2 + sizeof('\0');

  public:
    virtual ~VersionAbstractor() {};

    using access_key_id_t = boost::string_view;
    using client_signature_t = boost::string_view;
    using server_signature_t = basic_sstring<char, uint16_t, SIGNATURE_MAX_SIZE>;
    using string_to_sign_t = std::string;

    /* Transformation for crafting the AWS signature at server side which is
     * used later to compare with the user-provided one. The methodology for
     * doing that depends on AWS auth version. */
    using signature_factory_t = \
      std::function<server_signature_t(CephContext* cct,
                                       const std::string& secret_key,
                                       const string_to_sign_t& string_to_sign)>;

    /* Return an instance of Completer for verifying the payload's fingerprint
     * if necessary. Otherwise caller gets nullptr. Caller may provide secret
     * key */
    using completer_factory_t = \
      std::function<rgw::auth::Completer::cmplptr_t(
        const boost::optional<std::string>& secret_key)>;

    struct auth_data_t {
      access_key_id_t access_key_id;
      client_signature_t client_signature;
      string_to_sign_t string_to_sign;
      signature_factory_t signature_factory;
      completer_factory_t completer_factory;
    };

    virtual auth_data_t get_auth_data(const req_state* s) const = 0;
#ifdef WITH_BCEBOS
    auth_data_t get_auth_data_bos(const req_state* s) const;
#endif
  };

protected:
  CephContext* cct;
  const VersionAbstractor& ver_abstractor;

  AWSEngine(CephContext* const cct, const VersionAbstractor& ver_abstractor)
    : cct(cct),
      ver_abstractor(ver_abstractor) {
  }

  using result_t = rgw::auth::Engine::result_t;
  using string_to_sign_t = VersionAbstractor::string_to_sign_t;
  using signature_factory_t = VersionAbstractor::signature_factory_t;
  using completer_factory_t = VersionAbstractor::completer_factory_t;

  /* TODO(rzarzynski): clean up. We've too many input parameter hee. Also
   * the signature get_auth_data() of VersionAbstractor is too complicated.
   * Replace these thing with a simple, dedicated structure. */
  virtual result_t authenticate(const boost::string_view& access_key_id,
                                const boost::string_view& signature,
                                const string_to_sign_t& string_to_sign,
                                const signature_factory_t& signature_factory,
                                const completer_factory_t& completer_factory,
                                const req_state* s) const = 0;

public:
  result_t authenticate(const req_state* const s) const final;
};


class AWSGeneralAbstractor : public AWSEngine::VersionAbstractor {
  CephContext* const cct;

  virtual boost::optional<std::string>
  get_v4_canonical_headers(const req_info& info,
                           const boost::string_view& signedheaders,
                           const bool using_qs) const;

  auth_data_t get_auth_data_v2(const req_state* s) const;
  auth_data_t get_auth_data_v4(const req_state* s, const bool using_qs) const;

public:
  AWSGeneralAbstractor(CephContext* const cct)
    : cct(cct) {
  }

  auth_data_t get_auth_data(const req_state* s) const override;
};

class AWSGeneralBoto2Abstractor : public AWSGeneralAbstractor {
  boost::optional<std::string>
  get_v4_canonical_headers(const req_info& info,
                           const boost::string_view& signedheaders,
                           const bool using_qs) const override;

public:
  using AWSGeneralAbstractor::AWSGeneralAbstractor;
};

class AWSBrowserUploadAbstractor : public AWSEngine::VersionAbstractor {
  static std::string to_string(ceph::bufferlist bl) {
    return std::string(bl.c_str(),
                       static_cast<std::string::size_type>(bl.length()));
  }

  auth_data_t get_auth_data_v2(const req_state* s) const;
  auth_data_t get_auth_data_v4(const req_state* s) const;

public:
  AWSBrowserUploadAbstractor(CephContext*) {
  }

  auth_data_t get_auth_data(const req_state* s) const override;
};


class LDAPEngine : public AWSEngine {
  static rgw::LDAPHelper* ldh;
  static std::mutex mtx;

  static void init(CephContext* const cct);

  using acl_strategy_t = rgw::auth::RemoteApplier::acl_strategy_t;
  using auth_info_t = rgw::auth::RemoteApplier::AuthInfo;
  using result_t = rgw::auth::Engine::result_t;

protected:
  RGWRados* const store;
  const rgw::auth::RemoteApplier::Factory* const apl_factory;

  acl_strategy_t get_acl_strategy() const;
  auth_info_t get_creds_info(const rgw::RGWToken& token) const noexcept;

  result_t authenticate(const boost::string_view& access_key_id,
                        const boost::string_view& signature,
                        const string_to_sign_t& string_to_sign,
                        const signature_factory_t&,
                        const completer_factory_t& completer_factory,
                        const req_state* s) const override;
public:
  LDAPEngine(CephContext* const cct,
             RGWRados* const store,
             const VersionAbstractor& ver_abstractor,
             const rgw::auth::RemoteApplier::Factory* const apl_factory)
    : AWSEngine(cct, ver_abstractor),
      store(store),
      apl_factory(apl_factory) {
    init(cct);
  }

  using AWSEngine::authenticate;

  const char* get_name() const noexcept override {
    return "rgw::auth::s3::LDAPEngine";
  }

  static bool valid();
  static void shutdown();
};

#ifdef WITH_BCEIAM

class IAMEngine : public AWSEngine {
  static bceiam::IamClientWrapper* iam_client;
  static std::mutex mtx;
  static void init(CephContext* const cct);

  using acl_strategy_t = rgw::auth::RemoteApplier::acl_strategy_t;
  using auth_info_t = rgw::auth::RemoteApplier::AuthInfo;
  using result_t = rgw::auth::Engine::result_t;

protected:
  RGWRados* const store;
  const rgw::auth::RemoteApplier::Factory* const apl_factory;

  acl_strategy_t get_acl_strategy() const;
  auth_info_t get_creds_info(const bceiam::IamUserInfo& user_iam) const noexcept;

  int verify_s3(const boost::string_view& access_key_id,
                const boost::string_view& signature,
                const string_to_sign_t& string_to_sign,
                const signature_factory_t& signature_factory,
                const req_state* const s,
                string& sk,
                bceiam::IamUserInfo* user_info) const;
  int verify_sts(const req_state* const s,
                 bceiam::IamUserInfo* user_info) const;

  result_t authenticate(const boost::string_view& access_key_id,
                        const boost::string_view& signature,
                        const string_to_sign_t& string_to_sign,
                        const signature_factory_t& signature_factory,
                        const completer_factory_t& completer_factory,
                        const req_state* s) const override;

  int generate_permissions(const req_state* const s, int api,
                           std::set<std::string>& permissions) const;

public:
  IAMEngine(CephContext* const cct,
             RGWRados* const store,
             const VersionAbstractor& ver_abstractor,
             const rgw::auth::RemoteApplier::Factory* const apl_factory)
    : AWSEngine(cct, ver_abstractor),
      store(store),
      apl_factory(apl_factory) {
    if (cct->_conf->rgw_s3_auth_use_iam) {
      init(cct);
    }
  }

  using AWSEngine::authenticate;

  const char* get_name() const noexcept override {
    return "rgw::auth::s3::IAMEngine";
  }

  static bceiam::IamClientWrapper* get_iam_client() {return iam_client;}

  static int generate_verify_context_fast(const req_state* const s,
          const std::string bucket_name, const std::string object_name,
          std::set<std::string>& permissions,
          std::list<bceiam::VerifyContext>* verify_context_list,
          RGWRados* const store);

private:
  enum ABCStackRole {
    ABCS_ROLE_READ = 1,
    ABCS_ROLE_OPERATE,
    ABCS_ROLE_ADMIN,
    ABCS_ROLE_NEEDROOT,
  };
  
  static std::unordered_map<int, int> op_to_role;
  static std::unordered_map<int, string> op_to_coarse_permission;
  static std::unordered_map<int, string> op_to_fine_permission;

int GetVerifyContext(const req_state* const s,
        const std::string bucket_name, const std::string object_name,
        std::set<std::string>& permissions,
        std::list<bceiam::VerifyContext>* verify_context_list) const;

int prepare_verify_context(const req_state* const s,
        std::list<bceiam::VerifyContext>* resource_context_list) const;
};

#endif

class LocalEngine : public AWSEngine {
  RGWRados* const store;
  const rgw::auth::LocalApplier::Factory* const apl_factory;

  result_t authenticate(const boost::string_view& access_key_id,
                        const boost::string_view& signature,
                        const string_to_sign_t& string_to_sign,
                        const signature_factory_t& signature_factory,
                        const completer_factory_t& completer_factory,
                        const req_state* s) const override;
public:
  LocalEngine(CephContext* const cct,
              RGWRados* const store,
              const VersionAbstractor& ver_abstractor,
              const rgw::auth::LocalApplier::Factory* const apl_factory)
    : AWSEngine(cct, ver_abstractor),
      store(store),
      apl_factory(apl_factory) {
  }

  using AWSEngine::authenticate;

  const char* get_name() const noexcept override {
    return "rgw::auth::s3::LocalEngine";
  }
};


class S3AnonymousEngine : public rgw::auth::AnonymousEngine {
  bool is_applicable(const req_state* s) const noexcept override;

public:
  /* Let's reuse the parent class' constructor. */
  using rgw::auth::AnonymousEngine::AnonymousEngine;

  const char* get_name() const noexcept override {
    return "rgw::auth::s3::S3AnonymousEngine";
  }
};


class S3AuthFactory : public rgw::auth::RemoteApplier::Factory,
                      public rgw::auth::LocalApplier::Factory {
  typedef rgw::auth::IdentityApplier::aplptr_t aplptr_t;
  RGWRados* const store;

public:
  S3AuthFactory(RGWRados* const store)
    : store(store) {
  }

  aplptr_t create_apl_remote(CephContext* const cct,
                             const req_state* const s,
                             rgw::auth::RemoteApplier::acl_strategy_t&& acl_alg,
                             const rgw::auth::RemoteApplier::AuthInfo &info
                            ) const override {
    return aplptr_t(
      new rgw::auth::RemoteApplier(cct, store, std::move(acl_alg), info,
                                   cct->_conf->rgw_keystone_implicit_tenants));
  }

  aplptr_t create_apl_local(CephContext* const cct,
                            const req_state* const s,
                            const RGWUserInfo& user_info,
                            const std::string& subuser) const override {
      return aplptr_t(
        new rgw::auth::LocalApplier(cct, user_info, subuser));
  }
};

#ifdef WITH_BCEIAM
int check_batch_bucket_auth(const req_state* const s,
                            const map<string, RGWBucketEnt>& m,
                            std::vector<string>& allowed_buckets);
#endif

} /* namespace s3 */
} /* namespace auth */
} /* namespace rgw */


#endif /* CEPH_RGW_REST_S3_H */
