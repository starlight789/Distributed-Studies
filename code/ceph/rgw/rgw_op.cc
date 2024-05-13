// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include "include/compat.h"

#include <errno.h>
#include <stdlib.h>
#include <system_error>
#include <unistd.h>

#include <sstream>

#include <boost/algorithm/string/predicate.hpp>
#include <boost/bind.hpp>
#include <boost/optional.hpp>
#include <boost/utility/in_place_factory.hpp>
#include <boost/utility/string_view.hpp>

#include <regex>

#ifdef WITH_RADOSGW_BEAST_FRONTEND
#include "asio_sync.hpp"
#endif

#include "common/Clock.h"
#include "common/armor.h"
#include "common/errno.h"
#include "common/mime.h"
#include "common/utf8.h"
#include "common/ceph_json.h"

#include "rgw_rados.h"
#include "rgw_op.h"
#include "rgw_rest.h"
#include "rgw_acl.h"
#include "rgw_acl_s3.h"
#include "rgw_acl_swift.h"
#include "rgw_user.h"
#include "rgw_bucket.h"
#include "rgw_log.h"
#include "rgw_multi.h"
#include "rgw_multi_del.h"
#include "rgw_cors.h"
#include "rgw_cors_s3.h"
#include "rgw_rest_conn.h"
#include "rgw_rest_s3.h"
#include "rgw_rest_bos.h"
#include "rgw_tar.h"
#include "rgw_client_io.h"
#include "rgw_compression.h"
#include "rgw_role.h"
#include "rgw_tag_s3.h"
#include "rgw_http.h"
#include "cls/lock/cls_lock_client.h"
#include "cls/rgw/cls_rgw_client.h"
#include "rgw_image_process.h"
#include "rgw_notification.h"
#include "rgw_database.h"
#include "rgw_async_request.h"

#ifdef WITH_RADOSGW_BEAST_FRONTEND
#include "asio_sync.hpp"
#endif
#include "bceiam.h"

#include "include/assert.h"

#include "compressor/Compressor.h"

#ifdef WITH_LTTNG
#define TRACEPOINT_DEFINE
#define TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#include "tracing/rgw_op.h"
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_DEFINE
#else
#define tracepoint(...)
#endif

#define dout_context g_ceph_context
#define dout_subsys ceph_subsys_rgw

using namespace librados;
using ceph::crypto::MD5;
using boost::optional;
using boost::none;

using rgw::IAM::ARN;
using rgw::IAM::Effect;
using rgw::IAM::Policy;

using rgw::IAM::Policy;

static string mp_ns = RGW_OBJ_NS_MULTIPART;
static string shadow_ns = RGW_OBJ_NS_SHADOW;

static const string bucket_ns_dir = "dir";
static const string bucket_ns_file = "file";
static const string bucket_ns_dir_con_type = "type/dir"; // content type

struct DeleteMultiObjParams;
struct DeleteMultiObjState;
static std::shared_ptr<void> delete_multiobj_parallel(std::shared_ptr<void> params);

static void forward_req_info(CephContext *cct, req_info& info, const std::string& bucket_name);
static int forward_request_to_master(struct req_state *s, obj_version *objv, RGWRados *store,
                                     bufferlist& in_data, JSONParser *jp, req_info *forward_info = nullptr);

static MultipartMetaFilter mp_filter;

// this probably should belong in the rgw_iam_policy_keywords, I'll get it to it
// at some point
static constexpr auto S3_EXISTING_OBJTAG = "s3:ExistingObjectTag";

int RGWGetObj::parse_range(void)
{
  int r = -ERANGE;
  string rs(range_str);
  string ofs_str;
  string end_str;

  ignore_invalid_range = s->cct->_conf->rgw_ignore_get_invalid_range;
  partial_content = false;

  size_t pos = rs.find("bytes=");
  if (pos == string::npos) {
    pos = 0;
    while (isspace(rs[pos]))
      pos++;
    int end = pos;
    while (isalpha(rs[end]))
      end++;
    if (strncasecmp(rs.c_str(), "bytes", end - pos) != 0)
      return 0;
    while (isspace(rs[end]))
      end++;
    if (rs[end] != '=')
      return 0;
    rs = rs.substr(end + 1);
  } else {
    rs = rs.substr(pos + 6); /* size of("bytes=")  */
  }
  pos = rs.find('-');
  if (pos == string::npos)
    goto done;

  partial_content = true;

  ofs_str = rs.substr(0, pos);
  end_str = rs.substr(pos + 1);

#ifdef WITH_BCEBOS
  if (!boost::all(ofs_str, boost::is_digit()) ||
      !boost::all(end_str, boost::is_digit())) {
    goto done;
  }
  // ofs not allow minus
  pos = end_str.find('-');
  if (pos != string::npos)
    goto done;
#endif
  if (end_str.length()) {
    end = atoll(end_str.c_str());
    if (end < 0)
      goto done;
  }

  if (ofs_str.length()) {
    ofs = atoll(ofs_str.c_str());
  } else { // RFC2616 suffix-byte-range-spec
    ofs = -end;
    end = -1;
  }

  if (end >= 0 && end < ofs)
    goto done;

  range_parsed = true;
  return 0;

done:
  if (ignore_invalid_range) {
    partial_content = false;
    ofs = 0;
    end = -1;
    range_parsed = false; // allow retry
    r = 0;
  }

  return r;
}

static int decode_policy(CephContext *cct,
                         bufferlist& bl,
                         RGWAccessControlPolicy *policy)
{
  bufferlist::iterator iter = bl.begin();
  try {
    policy->decode(iter);
  } catch (buffer::error& err) {
    ldout(cct, 0) << "ERROR: could not decode policy, caught buffer::error" << dendl;
    return -EIO;
  }
  if (cct->_conf->subsys.should_gather<ceph_subsys_rgw, 15>()) {
    ldout(cct, 15) << __func__ << " Read AccessControlPolicy";
    RGWAccessControlPolicy_S3 *s3policy = static_cast<RGWAccessControlPolicy_S3 *>(policy);
    s3policy->to_xml(*_dout);
    *_dout << dendl;
  }
  return 0;
}


static int get_user_policy_from_attr(CephContext * const cct,
				     RGWRados * const store,
				     map<string, bufferlist>& attrs,
				     RGWAccessControlPolicy& policy    /* out */)
{
  auto aiter = attrs.find(RGW_ATTR_ACL);
  if (aiter != attrs.end()) {
    int ret = decode_policy(cct, aiter->second, &policy);
    if (ret < 0) {
      return ret;
    }
  } else {
    return -ENOENT;
  }

  return 0;
}

static int get_bucket_instance_policy_from_attr(CephContext *cct,
						RGWRados *store,
						RGWBucketInfo& bucket_info,
						map<string, bufferlist>& bucket_attrs,
						RGWAccessControlPolicy *policy)
{
  map<string, bufferlist>::iterator aiter = bucket_attrs.find(RGW_ATTR_ACL);

  if (aiter != bucket_attrs.end()) {
    int ret = decode_policy(cct, aiter->second, policy);
    if (ret < 0)
      return ret;
  } else {
    ldout(cct, 0) << "WARNING: couldn't find acl header for bucket, generating default" << dendl;
    RGWUserInfo uinfo;
    /* object exists, but policy is broken */
    int r = rgw_get_user_info_by_uid(store, bucket_info.owner, uinfo);
    if (r < 0)
      return r;

    policy->create_default(bucket_info.owner, uinfo.display_name);
  }
  return 0;
}

static int create_default_object_policy(RGWRados* store,
                                        RGWBucketInfo& bucket_info,
                                        RGWAccessControlPolicy* policy)
{
  RGWUserInfo uinfo;
  int ret = rgw_get_user_info_by_uid(store, bucket_info.owner, uinfo);
  if (ret < 0) {
    return ret;
  }
  policy->create_default(bucket_info.owner, uinfo.display_name);
  return 0;
}

static int get_obj_policy_from_attr(CephContext *cct,
                                    RGWRados *store,
                                    RGWObjectCtx& obj_ctx,
                                    RGWBucketInfo& bucket_info,
                                    map<string, bufferlist>& bucket_attrs,
                                    RGWAccessControlPolicy *policy,
                                    rgw_obj& obj,
                                    string *storage_class = nullptr,
                                    bool *is_symlink_obj = nullptr)
{
  bufferlist bl;
  int ret = 0;

  RGWRados::Object op_target(store, bucket_info, obj_ctx, obj);
  RGWRados::Object::Read rop(&op_target);

  bool delay_remove_head_obj = cct->_conf->rgw_delay_remove_head_obj;
  if (delay_remove_head_obj) {
    ret = rop.get_attr(RGW_ATTR_DELETED, bl);
    if (ret >= 0) {
      return -ENOENT;
    }
  }

  ret = rop.get_attr(RGW_ATTR_ACL, bl);
  if (ret >= 0) {
    ret = decode_policy(cct, bl, policy);
    if (ret < 0)
      return ret;
  } else if (ret == -ENODATA) {
    /* object exists, but policy is broken */
    ldout(cct, 0) << "WARNING: couldn't find acl header for object, generating default" << dendl;
    ret = create_default_object_policy(store, bucket_info, policy);
    if (ret < 0) {
      return ret;
    }
  }

  if (storage_class) {
    bufferlist scbl;
    int r = rop.get_attr(RGW_ATTR_STORAGE_CLASS, scbl);
    if (r >= 0) {
      *storage_class = scbl.to_str();
    } else {
      storage_class->clear();
    }
  }

  if (is_symlink_obj != nullptr) {
    int r = rop.get_attr(RGW_ATTR_TARGET_OBJECT, bl);
    if (r >= 0) {
      *is_symlink_obj = true;
    }
  }

  return ret;
}


/**
 * Get the AccessControlPolicy for an object off of disk.
 * policy: must point to a valid RGWACL, and will be filled upon return.
 * bucket: name of the bucket containing the object.
 * object: name of the object to get the ACL for.
 * Returns: 0 on success, -ERR# otherwise.
 */
static int get_bucket_policy_from_attr(CephContext *cct,
				       RGWRados *store,
				       RGWBucketInfo& bucket_info,
				       map<string, bufferlist>& bucket_attrs,
				       RGWAccessControlPolicy *policy)
{
  return get_bucket_instance_policy_from_attr(cct, store, bucket_info, bucket_attrs, policy);
}

static boost::optional<Policy> get_iam_policy_from_attr(CephContext* cct,
							RGWRados* store,
							map<string, bufferlist>& attrs,
							const string& tenant) {
  auto i = attrs.find(RGW_ATTR_IAM_POLICY);
  if (i != attrs.end()) {
    return Policy(cct, tenant, i->second);
  } else {
    return none;
  }
}

static int get_obj_attrs(RGWRados *store, struct req_state *s, rgw_obj& obj, map<string, bufferlist>& attrs, ceph::real_time* mtime = nullptr)
{
  RGWRados::Object op_target(store, s->bucket_info, *static_cast<RGWObjectCtx *>(s->obj_ctx), obj);
  RGWRados::Object::Read read_op(&op_target);

  read_op.params.attrs = &attrs;
  read_op.params.lastmod = mtime;

  return read_op.prepare();
}

static int modify_obj_attr(RGWRados *store, struct req_state *s, rgw_obj& obj, const char* attr_name, bufferlist& attr_val)
{
  map<string, bufferlist> attrs;
  RGWRados::Object op_target(store, s->bucket_info, *static_cast<RGWObjectCtx *>(s->obj_ctx), obj);
  RGWRados::Object::Read read_op(&op_target);

  read_op.params.attrs = &attrs;

  int r = read_op.prepare();
  if (r < 0) {
    return r;
  }
  store->set_atomic(s->obj_ctx, read_op.state.obj);
  attrs[attr_name] = attr_val;
  return store->set_attrs(s->obj_ctx, s->bucket_info, read_op.state.obj, attrs, NULL);
}

int read_bucket_policy(RGWRados *store,
                       struct req_state *s,
                       RGWBucketInfo& bucket_info,
                       map<string, bufferlist>& bucket_attrs,
                       RGWAccessControlPolicy *policy,
                       rgw_bucket& bucket)
{
  if (!s->system_request && bucket_info.flags & BUCKET_SUSPENDED) {
    ldout(s->cct, 0) << "NOTICE: bucket " << bucket_info.bucket.name << " is suspended" << dendl;
    return -ERR_USER_SUSPENDED;
  }

  if (bucket.name.empty()) {
    return 0;
  }

  int ret = get_bucket_policy_from_attr(s->cct, store, bucket_info, bucket_attrs, policy);
  if (ret == -ENOENT) {
      ret = -ERR_NO_SUCH_BUCKET;
  }

  return ret;
}

static int read_obj_policy(RGWRados *store,
                           struct req_state *s,
                           RGWBucketInfo& bucket_info,
                           map<string, bufferlist>& bucket_attrs,
                           RGWAccessControlPolicy* acl,
                           boost::optional<Policy>& policy,
                           rgw_bucket& bucket,
                           rgw_obj_key& object,
                           string *storage_class = nullptr)
{
  string upload_id;
  //if upload part copy op, this object is source object
  if (!s->info.env->exists("HTTP_X_BCE_COPY_SOURCE") && !s->info.env->exists("HTTP_X_AMZ_COPY_SOURCE")) {
    upload_id = s->info.args.get("uploadId");
  }
  rgw_obj obj;

  if (!s->system_request && bucket_info.flags & BUCKET_SUSPENDED) {
    ldout(s->cct, 0) << "NOTICE: bucket " << bucket_info.bucket.name << " is suspended" << dendl;
    return -ERR_USER_SUSPENDED;
  }

  if (!upload_id.empty()) {
    /* multipart upload */
    RGWMPObj mp(object.name, upload_id);
    string oid = mp.get_meta();
    obj.init_ns(bucket, oid, mp_ns);
    obj.set_in_extra_data(true);
  } else {
    obj = rgw_obj(bucket, object);
  }
  policy = get_iam_policy_from_attr(s->cct, store, bucket_attrs, bucket.tenant);

  RGWObjectCtx *obj_ctx = static_cast<RGWObjectCtx *>(s->obj_ctx);
  int ret = get_obj_policy_from_attr(s->cct, store, *obj_ctx,
                                     bucket_info, bucket_attrs, acl, obj, storage_class, &s->is_symlink_obj);
  if (ret == -ENOENT) {
    /* object does not exist checking the bucket's ACL to make sure
       that we send a proper error code */
    RGWAccessControlPolicy bucket_policy(s->cct);
    ret = get_bucket_policy_from_attr(s->cct, store, bucket_info, bucket_attrs, &bucket_policy);
    if (ret < 0) {
      return ret;
    }

    auto e = Effect::Pass;
    if (policy) {
      e = policy->eval(s->env, *s->auth.identity, rgw::IAM::bosRead, ARN(s->bucket));
    }
    const rgw_user& bucket_owner = bucket_policy.get_owner().get_id();
    if (bucket_owner.compare(s->user->user_id) != 0 &&
        e != Effect::Allow &&
        ! s->auth.identity->is_admin_of(bucket_owner) &&
        ! bucket_policy.verify_permission(*s->auth.identity, s->perm_mask,
                                          RGW_PERM_READ)) {
      ret = -EACCES;
    } else {
      ret = -ENOENT;
    }
  }

  return ret;
}

int verify_object_permission(req_state* s,
                             RGWRados* store,
                             string& bucket_name,
                             string& object_name,
                             std::uint64_t action,
                             const uint32_t perm,
                             bool only_bucket) {
  map<string, bufferlist> bucket_attrs;
  RGWBucketInfo bucket_info;
  RGWAccessControlPolicy obj_acl(s->cct);
  boost::optional<Policy> bucket_policy;

  RGWObjectCtx& obj_ctx = *static_cast<RGWObjectCtx *>(s->obj_ctx);

  int ret = store->get_bucket_info(obj_ctx, s->user->user_id.tenant, bucket_name,
                                    bucket_info, NULL, &bucket_attrs);
  if (ret < 0) {
    ldout(s->cct, 5) << "ERROR: get bucket " << bucket_name << " info return "
                     << ret << dendl;
    if (ret == -ENOENT) {
      return -ERR_NO_SUCH_BUCKET;
    }
    return ret;
  }

  bool bucket_allow = true;
  // bucket_policy : bucket acl
  RGWAccessControlPolicy bucket_acl(s->cct);

  rgw_bucket bucket = bucket_info.bucket;
  rgw_obj_key object;
  object.name = object_name;

  rgw_obj obj(bucket, object);

  /* check bucket permissions */
  ret = read_bucket_policy(store, s, bucket_info, bucket_attrs,
                              &bucket_acl, bucket);
  if (ret < 0) {
    return ret;
  }

  auto bucket_iam_policy = get_iam_policy_from_attr(s->cct, store, bucket_attrs, bucket.tenant);
  /* admin request overrides permission checks */
  if (! s->auth.identity->is_admin_of(bucket_acl.get_owner().get_id())) {
    if (bucket_iam_policy != boost::none) {
      auto e = bucket_iam_policy->eval(s->env, *s->auth.identity,
                                       action, ARN(obj));
      if (e == Effect::Deny) {
         bucket_allow = false;
      } else if (e == Effect::Pass &&
                 ! bucket_acl.verify_permission(*s->auth.identity,
                                                s->perm_mask,
                                                perm)){
          bucket_allow = false;
      }
    } else if (! bucket_acl.verify_permission(*s->auth.identity, s->perm_mask,
                                              perm)) {
       bucket_allow = false;
    }
  }

  if (only_bucket) {
    if (bucket_allow)
      return 0;
    return -EACCES;
  }

  store->set_atomic(s->obj_ctx, obj);
  store->set_prefetch_data(s->obj_ctx, obj);

  RGWObjState *astate;
  ret = store->get_obj_state(&obj_ctx, bucket_info, obj, &astate, false);
  if (ret < 0) {
    ldout(s->cct, 5) << "ERROR: get obj " << bucket_name << "/" << obj
                     << " state return " << ret << dendl;
    return ret;
  }
  if (!astate->exists) {
    ldout(s->cct, 5) << "ERROR: obj " << bucket_name << "/" << obj
                     << " not exist" << dendl;
    return -ENOENT;
  }

  if (!bucket_allow) {
    /* check source object permissions */
    ret = read_obj_policy(store, s, bucket_info, bucket_attrs, &obj_acl,
                          bucket_policy, bucket, object);
    if (ret < 0) {
      return ret;
    }

    /* admin request overrides permission checks */
    if (!s->auth.identity->is_admin_of(obj_acl.get_owner().get_id())) {
      if (bucket_policy) {
        auto e = bucket_policy->eval(s->env, *s->auth.identity,
                                     action,
                                     ARN(obj));
        if (e == Effect::Deny) {
          return -EACCES;
        } else if (e == Effect::Pass &&
                   !obj_acl.verify_permission(*s->auth.identity, s->perm_mask,
                     perm)) {
          return -EACCES;
        }
      } else if (!obj_acl.verify_permission(*s->auth.identity,
                 s->perm_mask, perm)) {
         return -EACCES;
      }
    }
  }
  return 0;
}

/**
 * Get the AccessControlPolicy for an user, bucket or object off of disk.
 * s: The req_state to draw information from.
 * only_bucket: If true, reads the user and bucket ACLs rather than the object ACL.
 * Returns: 0 on success, -ERR# otherwise.
 */
int rgw_build_bucket_policies(RGWRados* store, struct req_state* s)
{
  int ret = 0;
  rgw_obj_key obj;
  RGWUserInfo bucket_owner_info;
  RGWObjectCtx obj_ctx(store);

  string bi = s->info.args.get(RGW_SYS_PARAM_PREFIX "bucket-instance");
  if (!bi.empty()) {
    ret = rgw_bucket_parse_bucket_instance(bi, &s->bucket_instance_id, &s->bucket_instance_shard_id);
    if (ret < 0) {
      return ret;
    }
  }

  if(s->dialect.compare("s3") == 0) {
    s->bucket_acl = std::make_unique<RGWAccessControlPolicy_S3>(s->cct);
  } else if(s->dialect.compare("swift")  == 0) {
    /* We aren't allocating the account policy for those operations using
     * the Swift's infrastructure that don't really need req_state::user.
     * Typical example here is the implementation of /info. */
    if (!s->user->user_id.empty()) {
      s->user_acl = std::make_unique<RGWAccessControlPolicy_SWIFTAcct>(s->cct);
    }
    s->bucket_acl = std::make_unique<RGWAccessControlPolicy_SWIFT>(s->cct);
  } else {
    s->bucket_acl = std::make_unique<RGWAccessControlPolicy>(s->cct);
  }

  if (s->prot_flags & RGW_REST_BOS && s->decoded_uri.compare(0, 6, "/admin") == 0) {
    bool admin_req = false;
    string bucket_name;
    RESTArgs::get_bool(s, "admin", false, &admin_req);
    RESTArgs::get_string(s, "bucket", bucket_name, &bucket_name);
    if (admin_req && !bucket_name.empty()) {
      s->bucket_name = bucket_name;
    }
  }

  /* check if copy source is within the current domain */
  if (!s->src_bucket_name.empty()) {
    RGWBucketInfo source_info;

    if (s->bucket_instance_id.empty()) {
      ret = store->get_bucket_info(obj_ctx, s->src_tenant_name, s->src_bucket_name, source_info, NULL);
    } else {
      ret = store->get_bucket_instance_info(obj_ctx, s->bucket_instance_id, source_info, NULL, NULL);
    }
    if (ret == 0) {
      string& zonegroup = source_info.zonegroup;
      s->local_source = store->get_zonegroup().equals(zonegroup);
    }
  }

  struct {
    rgw_user uid;
    std::string display_name;
  } acct_acl_user = {
    s->user->user_id,
    s->user->display_name,
  };

  if (!s->bucket_name.empty()) {
    s->bucket_exists = true;
    if (s->bucket_instance_id.empty()) {
      ret = store->get_bucket_info(obj_ctx, s->bucket_tenant, s->bucket_name,
                                   s->bucket_info, &s->bucket_mtime,
                                   &s->bucket_attrs);
    } else {
      ret = store->get_bucket_instance_info(obj_ctx, s->bucket_instance_id,
                                            s->bucket_info, &s->bucket_mtime,
                                            &s->bucket_attrs);
    }
    if (ret < 0) {
      if (ret != -ENOENT) {
        string bucket_log;
        rgw_make_bucket_entry_name(s->bucket_tenant, s->bucket_name, bucket_log);
        ldout(s->cct, 0) << "NOTICE: couldn't get bucket from bucket_name (name=" << bucket_log << ")" << dendl;
        return ret;
      }
      s->bucket_exists = false;
    }
    s->bucket = s->bucket_info.bucket;

    if (s->bucket_exists) {
      ret = read_bucket_policy(store, s, s->bucket_info, s->bucket_attrs,
                               s->bucket_acl.get(), s->bucket);
      acct_acl_user = {
        s->bucket_info.owner,
        s->bucket_acl->get_owner().get_display_name(),
      };
    } else {
      s->bucket_acl->create_default(s->user->user_id, s->user->display_name);
      ret = -ERR_NO_SUCH_BUCKET;
    }

    s->bucket_owner = s->bucket_acl->get_owner();

    RGWZoneGroup zonegroup;
    int r = store->get_zonegroup(s->bucket_info.zonegroup, zonegroup);
    if (!r) {
      if (!zonegroup.endpoints.empty()) {
	s->zonegroup_endpoint = zonegroup.endpoints.front();
      } else {
        // use zonegroup's master zone endpoints
        auto z = zonegroup.zones.find(zonegroup.master_zone);
        if (z != zonegroup.zones.end() && !z->second.endpoints.empty()) {
          s->zonegroup_endpoint = z->second.endpoints.front();
        }
      }
      s->zonegroup_name = zonegroup.get_name();
    }
    if (r < 0 && ret == 0) {
      ret = r;
    }

    if (s->bucket_exists && !store->get_zonegroup().equals(s->bucket_info.zonegroup)) {
      ldout(s->cct, 0) << "NOTICE: request for data in a different zonegroup (" << s->bucket_info.zonegroup << " != " << store->get_zonegroup().get_id() << ")" << dendl;
      /* we now need to make sure that the operation actually requires copy source, that is
       * it's a copy operation
       */
      if (store->get_zonegroup().is_master_zonegroup() && s->system_request) {
        /*If this is the master, don't redirect*/
      } else if (s->op_type == RGW_OP_GET_BUCKET_LOCATION ) {
        /* If op is get bucket location, don't redirect */
      } else if (!s->local_source ||
          (s->op != OP_PUT && s->op != OP_COPY) ||
          s->object.empty()) {
        return -ERR_PERMANENT_REDIRECT;
      }
    }
  }

    /* init dest placement -- only if bucket exists, otherwise request is either not relevant, or
     * it's a create_bucket request, in which case the op will deal with the placement later */
    if (s->bucket_exists) {
      // default is standard
      if (s->info.storage_class.empty() && !s->bucket_info.storage_class.empty()) {
        s->info.storage_class = s->bucket_info.storage_class;
      }
      s->dest_placement.storage_class = rgw_placement_rule::get_canonical_storage_class(s->info.storage_class);
      s->dest_placement.name = s->bucket_info.head_placement_rule.name;
      ldout(s->cct, 15) << "placement id: " << s->dest_placement.name << " storage class: " << s->dest_placement.storage_class << dendl; 

      if (!store->get_zone_params().valid_placement(s->dest_placement)) {
        ldout(s->cct, 5) << "NOTICE: invalid dest placement: " << s->dest_placement.to_str() << dendl;
        s->err.message = "The specified storage class is invalid";
        return -ERR_INVALID_STORAGE_CLASS;
      }
    }

  /* handle user ACL only for those APIs which support it */
  if (s->user_acl) {
    map<string, bufferlist> uattrs;

    ret = rgw_get_user_attrs_by_uid(store, acct_acl_user.uid, uattrs);
    if (!ret) {
      ret = get_user_policy_from_attr(s->cct, store, uattrs, *s->user_acl);
    }
    if (-ENOENT == ret) {
      /* In already existing clusters users won't have ACL. In such case
       * assuming that only account owner has the rights seems to be
       * reasonable. That allows to have only one verification logic.
       * NOTE: there is small compatibility kludge for global, empty tenant:
       *  1. if we try to reach an existing bucket, its owner is considered
       *     as account owner.
       *  2. otherwise account owner is identity stored in s->user->user_id.  */
      s->user_acl->create_default(acct_acl_user.uid,
                                  acct_acl_user.display_name);
      ret = 0;
    } else {
      ldout(s->cct, 0) << "NOTICE: couldn't get user attrs for handling ACL (user_id="
                       << s->user->user_id << ", ret=" << ret << ")"
                       << dendl;
      return ret;
    }
  }

  try {
    s->iam_policy = get_iam_policy_from_attr(s->cct, store, s->bucket_attrs,
					     s->bucket_tenant);
  } catch (const std::exception& e) {
    // Really this is a can't happen condition. We parse the policy
    // when it's given to us, so perhaps we should abort or otherwise
    // raise bloody murder.
    lderr(s->cct) << "Error reading IAM Policy: " << e.what() << dendl;
    ret = -EACCES;
  }

  bool success = store->get_redirect_zone_endpoint(&s->redirect_zone_endpoint);
  if (success) {
    ldout(s->cct, 20) << "redirect_zone_endpoint=" << s->redirect_zone_endpoint << dendl;
  }

  return ret;
}

/**
 * Get the AccessControlPolicy for a bucket or object off of disk.
 * s: The req_state to draw information from.
 * only_bucket: If true, reads the bucket ACL rather than the object ACL.
 * Returns: 0 on success, -ERR# otherwise.
 */
int rgw_build_object_policies(RGWRados *store, struct req_state *s,
                              bool prefetch_data, bool is_head_op)
{
  int ret = 0;

  if (!s->object.empty()) {
    if (!s->bucket_exists) {
      return -ERR_NO_SUCH_BUCKET;
    }
    s->object_acl = std::make_unique<RGWAccessControlPolicy>(s->cct);
    // bucket namespace is enable
    // don't need to read data
    if (is_head_op && // only skip head object request
        s->cct->_conf->rgw_namespace_disable_object_policy &&
        s->bucket_info.namespace_type == BUCKET_NAMESPACE_ENABLE) {
      ldout(s->cct, 20) << __func__ << " skip fetch object policy of " 
                        << s->object << dendl;
      // create default policy
      RGWAccessControlPolicy* obj_acl = s->object_acl.get();
      return create_default_object_policy(store, s->bucket_info, obj_acl);
    }

    rgw_obj obj(s->bucket, s->object);
    store->set_atomic(s->obj_ctx, obj); // ? need check
    if (prefetch_data) {
      store->set_prefetch_data(s->obj_ctx, obj);
    }
    ret = read_obj_policy(store, s, s->bucket_info, s->bucket_attrs,
                          s->object_acl.get(), s->iam_policy, s->bucket,
                          s->object);

    ldout(s->cct, 20) << __func__ << " " << s->object << " ret=" << ret
                      << " namespace ename="
                      << (s->bucket_info.namespace_type == BUCKET_NAMESPACE_ENABLE)
                      << " is head=" << is_head_op << dendl;

    // this object maybe directory
    if (ret == -ENOENT && s->bucket_info.namespace_type == BUCKET_NAMESPACE_ENABLE &&
        is_head_op) {
      ldout(s->cct, 20) << __func__ << " object not exist!" << dendl;
      // create default policy for dir
      RGWAccessControlPolicy* obj_acl = s->object_acl.get();
      return create_default_object_policy(store, s->bucket_info, obj_acl);
    }
  }

  return ret;
}

void rgw_add_to_iam_environment(rgw::IAM::Environment& e, std::string_view key, std::string_view val){
  // This variant just adds non empty key pairs to IAM env., values can be empty
  // in certain cases like tagging
  if (!key.empty())
    e.emplace(key,val);
}

static int rgw_iam_add_tags_from_bl(struct req_state* s, bufferlist& bl){
  RGWObjTags& tagset = s->tagset;
  try {
    auto bliter = bl.begin();
    tagset.decode(bliter);
  } catch (buffer::error& err) {
    ldout(s->cct,0) << "ERROR: caught buffer::error, couldn't decode TagSet" << dendl;
    return -EIO;
  }

  for (const auto& tag: tagset.get_tags()){
    rgw_add_to_iam_environment(s->env, "s3:ExistingObjectTag/" + tag.first, tag.second);
  }
  return 0;
}

static int rgw_iam_add_existing_objtags(RGWRados* store, struct req_state* s, rgw_obj& obj, std::uint64_t action){
  map <string, bufferlist> attrs;
  store->set_atomic(s->obj_ctx, obj);
  int op_ret = get_obj_attrs(store, s, obj, attrs);
  if (op_ret < 0)
    return op_ret;
  auto tags = attrs.find(RGW_ATTR_TAGS);
  if (tags != attrs.end()){
    return rgw_iam_add_tags_from_bl(s, tags->second);
  }
  return 0;
}

static void rgw_add_grant_to_iam_environment(rgw::IAM::Environment& e, struct req_state *s){

  using header_pair_t = std::pair <const char*, const char*>;
  static const std::initializer_list <header_pair_t> acl_header_conditionals {
    {"HTTP_X_BCE_GRANT_READ", "s3:x-amz-grant-read"},
    {"HTTP_X_BCE_GRANT_WRITE", "s3:x-amz-grant-write"},
    {"HTTP_X_BCE_GRANT_FULL_CONTROL", "s3:x-amz-grant-full-control"},
    {"HTTP_X_AMZ_GRANT_READ", "s3:x-amz-grant-read"},
    {"HTTP_X_AMZ_GRANT_WRITE", "s3:x-amz-grant-write"},
    {"HTTP_X_AMZ_GRANT_READ_ACP", "s3:x-amz-grant-acp"},
    {"HTTP_X_AMZ_GRANT_WRITE_ACP", "s3:x-amz-grant-write-acp"},
    {"HTTP_X_AMZ_GRANT_FULL_CONTROL", "s3:x-amz-grant-full-control"}
  };

  if (s->has_acl_header){
    for (const auto& c: acl_header_conditionals){
      auto hdr = s->info.env->get(c.first);
      if(hdr) {
#ifdef WITH_BCEBOS
        string grant_data(hdr);
        if (grant_data.size() > 5 && (s->prot_flags & RGW_REST_BOS)) {
          grant_data = grant_data.substr(4);
          grant_data.pop_back();
          hdr = const_cast<char*>(grant_data.c_str());
        }
#endif
        e[c.second] = hdr;
      }
    }
  }
}

#ifdef WITH_BCEBOS
enum RGWBOSModifyCode {
  MODIFY_ALLOW = 0, // policy work, no need acl
  MODIFY_PASS = 1,  // modify not allow or deny, need acl further
  MODIFY_PASS_NEW = 2,  // only modify, pass new write condition
};

static int verify_bos_modify(RGWRados* store, struct req_state* const s,
                             rgw_obj& modify_obj, Effect& e) {
  map<string, bufferlist> modify_attrs;

  bool is_modify = false;
  auto m = s->iam_policy->eval(s->env, *s->auth.identity,
                               rgw::IAM::bosModify,
                               rgw_obj(s->bucket, s->object));

  if (m != Effect::Pass) {
    if (get_obj_attrs(store, s, modify_obj, modify_attrs) == 0) {
      is_modify = true;
    }
  }

  if (m == Effect::Allow) {
    if (e == Effect::Allow || (e == Effect::Pass && is_modify)) {
      return MODIFY_ALLOW;
    } else if (e == Effect::Deny) {
      return -EACCES;
    }
    return MODIFY_PASS_NEW;
  } else if (m == Effect::Deny) {
    if (e == Effect::Allow &&!is_modify) {
      return MODIFY_ALLOW;
    } else if (e == Effect::Deny) {
      return -EACCES;
    }
  } else {
    if (e == Effect::Allow) {
      return MODIFY_ALLOW;
    } else if (e == Effect::Deny) {
      return -EACCES;
    }
  }
  return MODIFY_PASS;
}
#endif

rgw::IAM::Environment rgw_build_iam_environment(RGWRados* store,
						struct req_state* s)
{
  rgw::IAM::Environment e;
  const auto& m = s->info.env->get_map();
  auto t = ceph::real_clock::now();
  e.emplace("aws:CurrentTime", std::to_string(ceph::real_clock::to_time_t(t)));
  e.emplace("aws:EpochTime", ceph::to_iso_8601(t));
  // TODO: This is fine for now, but once we have STS we'll need to
  // look and see. Also this won't work with the IdentityApplier
  // model, since we need to know the actual credential.
  e.emplace("aws:PrincipalType", "User");

  auto i = m.find("HTTP_REFERER");
  if (i != m.end()) {
    e.emplace("aws:Referer", i->second);
  }

  if (rgw_transport_is_secure(s->cct, *s->info.env)) {
    e.emplace("aws:SecureTransport", "true");
  }

  const auto remote_addr_param = s->cct->_conf->rgw_remote_addr_param;
  if (remote_addr_param.length()) {
    i = m.find(remote_addr_param);
  } else {
    i = m.find("REMOTE_ADDR");
  }
#ifdef WITH_BCEBOS
  //BOS API::if request have bos header x-client-ip
  //the real ip is the content of this header
  if ((s->prot_flags & RGW_REST_BOS) && m.find("HTTP_X_CLIENT_IP") != m.end()) {
    i = m.find("HTTP_X_CLIENT_IP");
  }
#endif
  if (i != m.end()) {
    const string* ip = &(i->second);
    string temp;
    if (remote_addr_param == "HTTP_X_FORWARDED_FOR") {
      const auto comma = ip->find(',');
      if (comma != string::npos) {
	temp.assign(*ip, 0, comma);
	ip = &temp;
      }
    }
    e.emplace("aws:SourceIp", *ip);
  }

  i = m.find("HTTP_USER_AGENT"); {
  if (i != m.end())
    e.emplace("aws:UserAgent", i->second);
  }

  if (s->user) {
    // What to do about aws::userid? One can have multiple access
    // keys so that isn't really suitable. Do we have a durable
    // identifier that can persist through name changes?
    e.emplace("aws:username", s->user->user_id.id);
  }
  return e;
}

void rgw_bucket_object_pre_exec(struct req_state *s)
{
  if (s->expect_cont)
    dump_continue(s);

  dump_bucket_from_state(s);
}

// So! Now and then when we try to update bucket information, the
// bucket has changed during the course of the operation. (Or we have
// a cache consistency problem that Watch/Notify isn't ruling out
// completely.)
//
// When this happens, we need to update the bucket info and try
// again. We have, however, to try the right *part* again.  We can't
// simply re-send, since that will obliterate the previous update.
//
// Thus, callers of this function should include everything that
// merges information to be changed into the bucket information as
// well as the call to set it.
//
// The called function must return an integer, negative on error. In
// general, they should just return op_ret.
namespace {
template<typename F>
int retry_raced_bucket_write(RGWRados* g, req_state* s, const F& f) {
  auto r = f();
  for (auto i = 0u; i < 15u && r == -ECANCELED; ++i) {
    r = g->try_refresh_bucket_info(s->bucket_info, nullptr,
				   &s->bucket_attrs);
    if (r >= 0) {
      r = f();
    }
  }
  return r;
}
}

int worm_verify_bos_write(const req_state* s, RGWRados* store, rgw_obj& obj,
                          RGWBOSObjectLock& bos_obj_lock, bool op_delete) {
  int op_ret = 0;
  auto bos_lock_status = bos_obj_lock.get_lock_status(nullptr);
  if (bos_lock_status == BOS_OBJECT_LOCK_STATUS_IN_PROGRESS ||
      bos_lock_status == BOS_OBJECT_LOCK_STATUS_LOCKED) {
    RGWObjState *astate;
    ldout(s->cct, 20) << __func__ << "() NOTICE: worm bucket, modify obj get obj state firstly "
                      << s->bucket_name << "/" << obj << dendl;
    op_ret = store->get_obj_state(static_cast<RGWObjectCtx *>(s->obj_ctx), s->bucket_info, obj, &astate, false);
    if (op_ret < 0) {
      ldout(s->cct, 0) << __func__ << "() ERROR: get obj " << s->bucket_name << "/" << obj
                       << " state return " << op_ret << dendl;
      return op_ret;
    }

    if (astate->exists) {
      op_ret = bos_obj_lock.verify_bos_obj_lock(s->cct->_conf->rgw_bos_worm_expiration_time, astate->mtime);
      if (op_ret < 0) {
        ldout(s->cct, 0) << __func__ << "() ERROR: bos object locked now." << dendl;
        return op_ret;
      }
    } else if (op_delete) {
      // object not exists, op delete
      ldout(store->ctx(), 0) << __func__ << "() ERROR: obj: " << obj << " not exists." << dendl;
      return -ENOENT;
    }
  }
  return op_ret;
}

int RGWGetObj::verify_target_object_permission(std::string& target_object_name, std::string& target_bucket_name)
{
  // first verify to iam
  std::list<bceiam::VerifyContext> verify_context_list;
  bceiam::IamUserInfo user_info;
  JSONParser parser;
  std::set<std::string> permissions{"READ"};
  // permissions GET OP
  int ret = rgw::auth::s3::IAMEngine::generate_verify_context_fast(s, target_bucket_name, target_object_name,
                                                    permissions, &verify_context_list, store);
  if (ret != 0) {
    ldout(s->cct, 0) << __func__ << " ERROR: symlink object cannot generate_verify_context_fast ret=" << op_ret << dendl;
    return ret;
  }

  // sts and s3 verify
  const char* security_token = s->info.env->get("HTTP_X_AMZ_SECURITY_TOKEN");
  if (!is_anonymous(s) && s->iam_check_user) {
    if ((s->prot_flags & RGW_REST_BOS) || (security_token && *security_token != '\0') ||
       (!s->info.args.get("x-amz-security-token").empty())) {
      /* for bos user && sts user && aws sts user */
      ret = rgw::auth::s3::IAMEngine::get_iam_client()->verify_sts_token(s, verify_context_list, &user_info);
    } else {
      // for s3 request, donot check permission from iam.
      ret = rgw::auth::s3::IAMEngine::get_iam_client()->verify_subuser(s,
                                        verify_context_list,
                                        /* maybe not subuser, we check user permission for target bucket and object */
                                        s->user->subusers.size() != 0 ?
                                            s->user->subusers.begin()->second.name : s->user->user_id.to_str(),
                                        &parser);
    }
  }

  if (ret != 0) {
    ldout(s->cct, 0) << __func__ << " ERROR: symlink object cannot verify_user ret=" << ret << dendl;
    return ret;
  }

  /* retarget name and check permission */
  RGWObjectCtx& obj_ctx = *static_cast<RGWObjectCtx *>(s->obj_ctx);
  RGWAccessControlPolicy target_acl(s->cct);
  boost::optional<Policy> target_policy;
  // refresh s->object, bucket_name, bucket info, bucket attrs and s->bucket(type rgw_bucket)
  s->object.set(target_object_name);
  s->bucket_name = target_bucket_name;

  ret = store->get_bucket_info(obj_ctx, s->bucket_tenant, s->bucket_name,
                                    s->bucket_info, NULL, &s->bucket_attrs);
  if (ret < 0) {
    // target bucket not exist
    if (ret == -ENOENT) {
      ldout(s->cct, 0) << __func__ << " ERROR: symlink object cannot find target bucket" << dendl;
      return -ERR_NO_SUCH_BUCKET;
    }
    return ret;
  }
  s->bucket = s->bucket_info.bucket;
  /* getop reinit */
  obj.init(s->bucket, target_object_name);
  bool target_bucket_allow = true;
  RGWAccessControlPolicy target_bucket_policy(s->cct);
  rgw_obj target_obj(s->bucket, s->object);
  store->set_atomic(s->obj_ctx, target_obj);

  /* check target bucket permissions */
  ret = read_bucket_policy(store, s, s->bucket_info, s->bucket_attrs,
                              &target_bucket_policy, s->bucket);
  if (ret < 0) {
    return ret;
  }
  auto target_iam_policy = get_iam_policy_from_attr(s->cct, store, s->bucket_attrs, s->bucket_tenant);
  /* admin request overrides permission checks */
  if (!s->auth.identity->is_admin_of(target_bucket_policy.get_owner().get_id())){
    if (target_iam_policy != boost::none) {
      auto e = target_iam_policy->eval(s->env, *s->auth.identity,
                                     rgw::IAM::s3GetObject, ARN(target_obj));
      if (e == Effect::Deny) {
         target_bucket_allow = false;
      } else if (e == Effect::Pass &&
                 !target_bucket_policy.verify_permission(*s->auth.identity,
                                                        s->perm_mask,
                                                        RGW_PERM_READ)){
          target_bucket_allow = false;
      }
    } else if (!target_bucket_policy.verify_permission(*s->auth.identity, s->perm_mask,
                                                    RGW_PERM_READ)) {
       target_bucket_allow = false;
    }
  }

  /* bucket allow user access, should check target object exist */
  if (target_bucket_allow) {
    goto done;
  }

  /* bucket access denied, check source object permissions */
  ret = read_obj_policy(store, s, s->bucket_info, s->bucket_attrs, &target_acl, target_policy,
                            s->bucket, s->object);
  if (ret < 0) {
    if (ret == -ENOENT) {
      ldout(s->cct, 15) << __func__ << " ERROR: symlink object cannot find target object" << dendl;
    }
    return ret;
  }

  /* admin request overrides permission checks */
  if (!s->auth.identity->is_admin_of(target_acl.get_owner().get_id())) {
    if (target_policy) {
      auto e = target_policy->eval(s->env, *s->auth.identity,
                                    rgw::IAM::s3GetObject,
                                    ARN(target_obj));
      if (e == Effect::Deny) {
        return -EACCES;
      } else if (e == Effect::Pass &&
                  !target_acl.verify_permission(*s->auth.identity, s->perm_mask,
                    RGW_PERM_READ)) {
        return -EACCES;
      }
    } else if (!target_acl.verify_permission(*s->auth.identity,
                s->perm_mask, RGW_PERM_READ)) {
        return -EACCES;
    }
  }

done:
  // check whether target object exists and obj type is not symlink
  RGWObjState *astate = nullptr;
  ret = store->get_obj_state(&obj_ctx, s->bucket_info, target_obj, &astate);


  if (ret < 0) {
    if (ret == -ENOENT) {
      ldout(s->cct, 15) << __func__ << " ERROR: symlink object cannot find target object" << dendl;
      return ret;
    }
  }
  if (!astate->exists) {
    ldout(s->cct, 15) << __func__ << " ERROR: symlink object cannot find target object" << dendl;
    return ret;
  }
  if (astate->attrset.find(RGW_ATTR_TARGET_OBJECT) != astate->attrset.end()) {
    return -ERR_INVAILD_TARGET_TYPE;
  }
  if (astate->attrset.find(RGW_ATTR_DELETED) != astate->attrset.end()) {
    return -ENOENT;
  }
  return 0;
}

int RGWGetObj::verify_permission()
{
  obj = rgw_obj(s->bucket, s->object);
  store->set_atomic(s->obj_ctx, obj);
  if (get_data) {
    store->set_prefetch_data(s->obj_ctx, obj);
  }

  if (torrent.get_flag()) {
    if (obj.key.instance.empty()) {
      action = rgw::IAM::s3GetObjectTorrent;
    } else {
      action = rgw::IAM::s3GetObjectVersionTorrent;
    }
  } else {
    if (!get_data) {
      action = rgw::IAM::s3GetObjectMeta;
    }
    if (obj.key.instance.empty()) {
      action = rgw::IAM::s3GetObject;
    } else {
      action = rgw::IAM::s3GetObjectVersion;
    }
    if (s->iam_policy && s->iam_policy->has_partial_conditional(S3_EXISTING_OBJTAG))
      rgw_iam_add_existing_objtags(store, s, obj, action);
  }

  if (!verify_object_permission(s, action)) {
    return -EACCES;
  }

  if (s->bucket_info.obj_lock_enabled()) {
    get_retention = verify_object_permission(s, rgw::IAM::s3GetObjectRetention);
    get_legal_hold = verify_object_permission(s, rgw::IAM::s3GetObjectLegalHold);
  }
  /* Image protection will refuse access to original picture by anonymous, even
   * with public read acl. Besides, image protection only allow image process
   * with style, refuse with specific command.
   *
   * In this function, verify image protection against anonymous
   * */
  if (s->auth.identity->is_anonymous() && !s->info.args.exists(RGW_BCE_PROCESS)) {
    int ret = verify_image_protection();
    if (ret < 0) {
      op_ret = ret;
      return op_ret;
    }
  }

  /* 
   * There are three conditions to skip symlink retarget:
   *   1. op user is system user
   *   2. symlink obj which is stored in versioning_enabled bucket
   *   3. donot catch RGW_ATTR_TARGET_OBJECT in xattrs
   * If object is the symlink type, STEPs are:
   *   1. should verify target_object permission
   *   2. should retarget object
   *   3. if bos api, should send verify context to iam
   */
  if (!s->system_request && !s->bucket_info.versioning_enabled() && s->is_symlink_obj) {
    RGWObjectCtx *obj_ctx = static_cast<RGWObjectCtx *>(s->obj_ctx);
    RGWObjState *symlink_obj_state = obj_ctx->obj.get_state(obj);
    std::string target_object, target_bucket;
    symlink_attrs = symlink_obj_state->attrset;
    symlink_lastmod = symlink_obj_state->mtime;
    auto iter = symlink_attrs.find(RGW_ATTR_TARGET_OBJECT);
    if (iter != symlink_attrs.end()) {
      target_object = (iter->second).to_str();
    }
    iter = symlink_attrs.find(RGW_ATTR_TARGET_BUCKET);
    if (iter != symlink_attrs.end()) {
      target_bucket = (iter->second).to_str();
    } else {
      target_bucket = s->bucket.name;
    }
    s->symlink_size_out = target_object.size() + target_bucket.size();
    /* verify target_object permission and retarget object */
    int ret = verify_target_object_permission(target_object, target_bucket);
    if (ret == -ENOENT && !is_head_obj()) {
      // maybe bucket mirroring, donot return error directly
      ldout(s->cct, 0) << __func__ << " ERROR: failed to verify target object permissions ret=" << ret
                      << " Try to check bucket mirroring" << dendl;
      set_exists(false);
      return 0;
    }
    if (ret < 0) {
      op_ret = ret;
      ldout(s->cct, 0) << __func__ << " ERROR: failed to verify target object permissions ret=" << ret << dendl;
      return ret;
    }
  } else {
    /* reset req_state symlink configure */
    s->is_symlink_obj = false;
  }

  return 0;
}


int RGWOp::verify_op_mask()
{
  uint32_t required_mask = op_mask();

  ldout(s->cct, 20) << "required_mask= " << required_mask
		    << " user.op_mask=" << s->user->op_mask << dendl;

  if ((s->user->op_mask & required_mask) != required_mask) {
    return -EPERM;
  }

  if (!s->system_request && (required_mask & RGW_OP_TYPE_MODIFY) && !store->zone_is_writeable()) {
    ldout(s->cct, 5) << "NOTICE: modify request to a read-only zone by a non-system user, permission denied"  << dendl;
    return -EPERM;
  }

  return 0;
}

int RGWGetObjTags::verify_permission()
{
  auto iam_action = s->object.instance.empty()?
    rgw::IAM::s3GetObjectTagging:
    rgw::IAM::s3GetObjectVersionTagging;
  // TODO since we are parsing the bl now anyway, we probably change
  // the send_response function to accept RGWObjTag instead of a bl
  if (s->iam_policy && s->iam_policy->has_partial_conditional(S3_EXISTING_OBJTAG)){
    rgw_obj obj = rgw_obj(s->bucket, s->object);
    rgw_iam_add_existing_objtags(store, s, obj, iam_action);
  }

  if (!verify_object_permission(s,iam_action))
    return -EACCES;

  return 0;
}

int RGWOp::verify_op_ban_stat() {
  if (s->system_request) {
    ldout(s->cct, 20) << __func__ << " the OP request is from user system." << dendl;
    return 0;
  }
  if (s->bucket_name.empty()) {
    ldout(s->cct, 20) << __func__ << " the OP does not operate any bucket." << dendl;
    return 0;
  }
  map<string, bufferlist> bucket_attrs = s->bucket_attrs;
  map<string, bufferlist>::iterator it = bucket_attrs.find(RGW_ATTR_BAN);
  if (it != bucket_attrs.end()) {
    switch(s->op_type) {
      case RGW_OP_GET_OBJ:
      case RGW_OP_PUT_OBJ:
        ldout(s->cct, 5) << __func__ << " NOTICE: the bucket has been banned, permission denied." << dendl;
        return -EPERM;
      default:
        break;
    }
  }

  if (!s->object.name.empty()) {
    switch(s->op_type) {
      case RGW_OP_GET_OBJ:
        break;
      default:
        return 0;
    }

    RGWObjState *astate;
    rgw_obj obj(s->bucket, s->object);
    op_ret = store->get_obj_state(static_cast<RGWObjectCtx *>(s->obj_ctx),
                        s->bucket_info, obj, &astate, true, false);
    if (op_ret < 0) {
      ldout(s->cct, 5) << "ERROR: get object state returned with error" << op_ret << dendl;
      return op_ret;
    }

    if (s->op_type == RGW_OP_RENAME_OBJ && !astate->exists) {
      ldout(s->cct, 20) << "ERROR: get object state no exist, obj:" << obj << dendl;
      return -ENOENT;
    }

    map<string, bufferlist>::iterator obj_it = astate->attrset.find(RGW_ATTR_BAN);
    if (obj_it != astate->attrset.end()) {
      ldout(s->cct, 5) << __func__ << " NOTICE: the object has been banned, permission denied." << dendl;
      return -EPERM;
    }
  }
  return 0;
}

void RGWGetObjTags::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

void RGWGetObjTags::execute()
{
  rgw_obj obj;
  map<string,bufferlist> attrs;

  obj = rgw_obj(s->bucket, s->object);

  store->set_atomic(s->obj_ctx, obj);

  op_ret = get_obj_attrs(store, s, obj, attrs);
  if (op_ret < 0) {
    ldout(s->cct, 0) << "ERROR: failed to get obj attrs, obj=" << obj
		     << " ret=" << op_ret << dendl;
    return;
  }

  auto tags = attrs.find(RGW_ATTR_TAGS);
  if(tags != attrs.end()){
    has_tags = true;
    tags_bl.append(tags->second);
  }
  send_response_data(tags_bl);
}

int RGWPutObjTags::verify_permission()
{
  auto iam_action = s->object.instance.empty() ?
    rgw::IAM::s3PutObjectTagging:
    rgw::IAM::s3PutObjectVersionTagging;

  if(s->iam_policy && s->iam_policy->has_partial_conditional(S3_EXISTING_OBJTAG)){
    auto obj = rgw_obj(s->bucket, s->object);
    rgw_iam_add_existing_objtags(store, s, obj, iam_action);
  }

  if (!verify_object_permission(s,iam_action))
    return -EACCES;
  return 0;
}

void RGWPutObjTags::execute()
{
  op_ret = get_params();
  if (op_ret < 0)
    return;

  if (s->object.empty()){
    op_ret= -EINVAL; // we only support tagging on existing objects
    return;
  }

  rgw_obj obj;
  obj = rgw_obj(s->bucket, s->object);
  store->set_atomic(s->obj_ctx, obj);
  op_ret = modify_obj_attr(store, s, obj, RGW_ATTR_TAGS, tags_bl);
  if (op_ret == -ECANCELED) {
    op_ret = -ERR_TAG_CONFLICT;
  }
}

void RGWDeleteObjTags::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}


int RGWDeleteObjTags::verify_permission()
{
  if (!s->object.empty()) {
    auto iam_action = s->object.instance.empty() ?
      rgw::IAM::s3DeleteObjectTagging:
      rgw::IAM::s3DeleteObjectVersionTagging;

    if (s->iam_policy && s->iam_policy->has_partial_conditional(S3_EXISTING_OBJTAG)){
      auto obj = rgw_obj(s->bucket, s->object);
      rgw_iam_add_existing_objtags(store, s, obj, iam_action);
    }

    if (!verify_object_permission(s, iam_action))
      return -EACCES;
  }
  return 0;
}

void RGWDeleteObjTags::execute()
{
  if (s->object.empty())
    return;

  rgw_obj obj;
  obj = rgw_obj(s->bucket, s->object);
  store->set_atomic(s->obj_ctx, obj);
  map <string, bufferlist> attrs;
  map <string, bufferlist> rmattr;
  bufferlist bl;
  rmattr[RGW_ATTR_TAGS] = bl;
  RGWRados::Object op_target(store, s->bucket_info, *static_cast<RGWObjectCtx *>(s->obj_ctx), obj);
  RGWRados::Object::Read read_op(&op_target);
  read_op.params.attrs = &attrs;
  op_ret = read_op.prepare();
  if (op_ret < 0) {
    ldout(s->cct, 0) << __func__ << " ERROR: read obj stat error " << obj
                     << " ret=" << op_ret << dendl;
    return;
  }
  op_ret = store->set_attrs(s->obj_ctx, s->bucket_info, obj, attrs, &rmattr);
}

int RGWOp::do_aws4_auth_completion()
{
#ifdef WITH_BCEBOS
  if ((s->prot_flags & RGW_REST_BOS) &&
      ! s->info.env->exists("HTTP_X_BCE_CONTENT_SHA256") &&
      ! s->info.args.exists("x-bce-content-sha256")) {
    dout(20) << "bos auth ok -- without [x-amz-content-sha256] header" << dendl;
    s->auth.completer = nullptr;
    return 0;
  }
#endif

  ldout(s->cct, 20) << "NOTICE: call to do_aws4_auth_completion"  << dendl;
  if (s->auth.completer) {
    if (!s->auth.completer->complete()) {
#ifdef WITH_BCEBOS
      if (s->prot_flags & RGW_REST_BOS)
        return -ERR_BAD_DIGEST;
#endif
      return -ERR_AMZ_CONTENT_SHA256_MISMATCH;
    } else {
      dout(20) << "v4 auth ok -- do_aws4_auth_completion" << dendl;
    }

    /* TODO(rzarzynski): yes, we're really called twice on PUTs. Only first
     * call passes, so we disable second one. This is old behaviour, sorry!
     * Plan for tomorrow: seek and destroy. */
    s->auth.completer = nullptr;
  }

  return 0;
}

int RGWOp::init_quota()
{
  /* no quota enforcement for system requests */
  if (s->system_request)
    return 0;

  /* init quota related stuff */
  if (!(s->user->op_mask & RGW_OP_TYPE_MODIFY)) {
    return 0;
  }

  /* only interested in object related ops */
  if (s->object.empty()) {
    return 0;
  }

  RGWUserInfo owner_info;
  RGWUserInfo *uinfo;

  if (s->user->user_id == s->bucket_owner.get_id()) {
    uinfo = s->user;
  } else {
    int r = rgw_get_user_info_by_uid(store, s->bucket_info.owner, owner_info);
    if (r < 0)
      return r;
    uinfo = &owner_info;
  }

  if (s->bucket_info.quota.enabled) {
    bucket_quota = s->bucket_info.quota;
  } else if (uinfo->bucket_quota.enabled) {
    bucket_quota = uinfo->bucket_quota;
  } else {
    bucket_quota = store->get_bucket_quota();
  }

  if (uinfo->user_quota.enabled) {
    user_quota = uinfo->user_quota;
  } else {
    user_quota = store->get_user_quota();
  }

  return 0;
}


static bool validate_cors_rule_method(RGWCORSRule *rule, const char *req_meth) {
  uint8_t flags = 0;

  if (!req_meth) {
    dout(5) << "req_meth is null" << dendl;
    return false;
  }

  if (strcmp(req_meth, "GET") == 0) flags = RGW_CORS_GET;
  else if (strcmp(req_meth, "POST") == 0) flags = RGW_CORS_POST;
  else if (strcmp(req_meth, "PUT") == 0) flags = RGW_CORS_PUT;
  else if (strcmp(req_meth, "DELETE") == 0) flags = RGW_CORS_DELETE;
  else if (strcmp(req_meth, "HEAD") == 0) flags = RGW_CORS_HEAD;

  if (rule->get_allowed_methods() & flags) {
    dout(10) << "Method " << req_meth << " is supported" << dendl;
  } else {
    dout(5) << "Method " << req_meth << " is not supported" << dendl;
    return false;
  }

  return true;
}

static bool validate_cors_rule_header(RGWCORSRule *rule, const char *req_hdrs) {
  if (req_hdrs) {
    vector<string> hdrs;
#ifdef WITH_BCEBOS
    get_bos_str_vec(req_hdrs, hdrs);
#else
    get_str_vec(req_hdrs, hdrs);
#endif
    for (const auto& hdr : hdrs) {
      if (!rule->is_header_allowed(hdr.c_str(), hdr.length())) {
        dout(5) << "Header " << hdr << " is not registered in this rule" << dendl;
        return false;
      }
    }
  }
  return true;
}

int RGWOp::read_bucket_cors()
{
  bufferlist bl;

  map<string, bufferlist>::iterator aiter = s->bucket_attrs.find(RGW_ATTR_CORS);
  if (aiter == s->bucket_attrs.end()) {
    ldout(s->cct, 20) << "no CORS configuration attr found" << dendl;
    cors_exist = false;
    return 0; /* no CORS configuration found */
  }

  cors_exist = true;

  bl = aiter->second;

  bufferlist::iterator iter = bl.begin();
  try {
    bucket_cors.decode(iter);
  } catch (buffer::error& err) {
    ldout(s->cct, 0) << "ERROR: could not decode policy, caught buffer::error" << dendl;
    return -EIO;
  }
  if (s->cct->_conf->subsys.should_gather<ceph_subsys_rgw, 15>()) {
    RGWCORSConfiguration_S3 *s3cors = static_cast<RGWCORSConfiguration_S3 *>(&bucket_cors);
    ldout(s->cct, 15) << "Read RGWCORSConfiguration";
    s3cors->to_xml(*_dout);
    *_dout << dendl;
  }
  return 0;
}

/** CORS 6.2.6.
 * If any of the header field-names is not a ASCII case-insensitive match for
 * any of the values in list of headers do not set any additional headers and
 * terminate this set of steps.
 * */
static void get_cors_response_headers(RGWCORSRule *rule, const char *req_hdrs, string& hdrs, string& exp_hdrs, unsigned *max_age) {
  if (req_hdrs) {
    list<string> hl;
#ifdef WITH_BCEBOS
    get_bos_str_list(req_hdrs, hl);
#else
    get_str_list(req_hdrs, hl);
#endif
    for(list<string>::iterator it = hl.begin(); it != hl.end(); ++it) {
      if (!rule->is_header_allowed((*it).c_str(), (*it).length())) {
        dout(5) << "Header " << (*it) << " is not registered in this rule" << dendl;
      } else {
        if (hdrs.length() > 0) hdrs.append(", ");
        hdrs.append((*it));
      }
    }
  }
  rule->format_exp_headers(exp_hdrs);
  *max_age = rule->get_max_age();
}

/**
 * Generate the CORS header response
 *
 * This is described in the CORS standard, section 6.2.
 */
bool RGWOp::generate_cors_headers(string& origin, string& method, string& headers, string& exp_headers, unsigned *max_age)
{
  /* CORS 6.2.1. */
  const char *orig = s->info.env->get("HTTP_ORIGIN");
  if (!orig) {
    return false;
  }

  /* Custom: */
  origin = orig;
  op_ret = read_bucket_cors();
  if (op_ret < 0) {
    return false;
  }

  if (!cors_exist) {
    dout(2) << "No CORS configuration set yet for this bucket" << dendl;
    return false;
  }

  /* CORS 6.2.2. */
  RGWCORSRule *rule = bucket_cors.host_name_rule(orig);
  if (!rule)
    return false;

  /*
   * Set the Allowed-Origin header to a asterisk if this is allowed in the rule
   * and no Authorization was send by the client
   *
   * The origin parameter specifies a URI that may access the resource.  The browser must enforce this.
   * For requests without credentials, the server may specify "*" as a wildcard,
   * thereby allowing any origin to access the resource.
   */
  const char *authorization = s->info.env->get("HTTP_AUTHORIZATION");
  if (!authorization && rule->has_wildcard_origin())
    origin = "*";

  /* CORS 6.2.3. */
  const char *req_meth = s->info.env->get("HTTP_ACCESS_CONTROL_REQUEST_METHOD");
  if (!req_meth) {
    req_meth = s->info.method;
  }

  if (req_meth) {
    method = req_meth;
    /* CORS 6.2.5. */
    if (!validate_cors_rule_method(rule, req_meth)) {
     return false;
    }
  }

  /* CORS 6.2.4. */
  const char *req_hdrs = s->info.env->get("HTTP_ACCESS_CONTROL_REQUEST_HEADERS");

  /* CORS 6.2.6. */
  get_cors_response_headers(rule, req_hdrs, headers, exp_headers, max_age);

  return true;
}

int RGWOp::get_object_lock_configure(req_state* s,
                                     RGWObjectRetention** retention,
                                     RGWObjectLegalHold** legal_hold) {
  auto obj_lock_mode_str = s->info.env->get("HTTP_X_AMZ_OBJECT_LOCK_MODE");
  auto obj_lock_date_str = s->info.env->get("HTTP_X_AMZ_OBJECT_LOCK_RETAIN_UNTIL_DATE");
  auto obj_legal_hold_str = s->info.env->get("HTTP_X_AMZ_OBJECT_LOCK_LEGAL_HOLD");
  if (obj_lock_mode_str && obj_lock_date_str) {
    boost::optional<ceph::real_time> date = ceph::from_iso_8601(obj_lock_date_str);
    if (boost::none == date || ceph::real_clock::to_time_t(*date) <= ceph_clock_now()) {
      ldout(s->cct, 10) << "invalid x-amz-object-lock-retain-until-date value" << dendl;
      return -EINVAL;
    }
    if (strcmp(obj_lock_mode_str, "GOVERNANCE") != 0 && strcmp(obj_lock_mode_str, "COMPLIANCE") != 0) {
      ldout(s->cct, 10) << "invalid x-amz-object-lock-mode value" << dendl;
      return -EINVAL;
    }
    *retention = new RGWObjectRetention(obj_lock_mode_str, *date);
  } else if ((obj_lock_mode_str && !obj_lock_date_str) || (!obj_lock_mode_str && obj_lock_date_str)) {
    ldout(s->cct, 10) << "need both x-amz-object-lock-mode and x-amz-object-lock-retain-until-date " << dendl;
    return -EINVAL;
  }
  if (obj_legal_hold_str) {
    if (strcmp(obj_legal_hold_str, "ON") != 0 && strcmp(obj_legal_hold_str, "OFF") != 0) {
      ldout(s->cct, 10) << "invalid x-amz-object-lock-legal-hold value" << dendl;
      return -EINVAL;
    }
    *legal_hold = new RGWObjectLegalHold(obj_legal_hold_str);
  }
  if (!s->bucket_info.obj_lock_enabled() && (*retention || *legal_hold)) {
    ldout(s->cct, 10) << "ERROR: object retention or legal hold can't be set if bucket object lock not configured" << dendl;
    return -ERR_INVALID_REQUEST;
  }
  return 0;
}


int RGWGetObj::read_user_manifest_part(rgw_bucket& bucket,
                                       const rgw_bucket_dir_entry& ent,
                                       RGWAccessControlPolicy * const bucket_acl,
                                       const boost::optional<Policy>& bucket_policy,
                                       const off_t start_ofs,
                                       const off_t end_ofs)
{
  ldout(s->cct, 20) << "user manifest obj=" << ent.key.name << "[" << ent.key.instance << "]" << dendl;
  RGWGetObj_CB cb(this);
  RGWGetObj_Filter* filter = &cb;
  boost::optional<RGWGetObj_Decompress> decompress;

  int64_t cur_ofs = start_ofs;
  int64_t cur_end = end_ofs;

  rgw_obj part(bucket, ent.key);

  map<string, bufferlist> attrs;

  uint64_t obj_size;
  RGWObjectCtx obj_ctx(store);
  RGWAccessControlPolicy obj_policy(s->cct);

  ldout(s->cct, 20) << "reading obj=" << part << " ofs=" << cur_ofs << " end=" << cur_end << dendl;

  obj_ctx.obj.set_atomic(part);
  store->set_prefetch_data(&obj_ctx, part);

  RGWRados::Object op_target(store, s->bucket_info, obj_ctx, part);
  RGWRados::Object::Read read_op(&op_target);

  read_op.conds.if_match = ent.meta.etag.c_str();
  read_op.params.attrs = &attrs;
  read_op.params.obj_size = &obj_size;

  op_ret = read_op.prepare();
  if (op_ret < 0)
    return op_ret;
  op_ret = read_op.range_to_ofs(ent.meta.accounted_size, cur_ofs, cur_end);
  if (op_ret < 0)
    return op_ret;
  bool need_decompress;
  op_ret = rgw_compression_info_from_attrset(attrs, need_decompress, cs_info);
  if (op_ret < 0) {
	  lderr(s->cct) << "ERROR: failed to decode compression info, cannot decompress" << dendl;
      return -EIO;
  }

  if (need_decompress)
  {
    if (cs_info.orig_size != ent.meta.accounted_size) {
      // hmm.. something wrong, object not as expected, abort!
      ldout(s->cct, 0) << "ERROR: expected cs_info.orig_size=" << cs_info.orig_size <<
          ", actual read size=" << ent.meta.size << dendl;
      return -EIO;
    }
    decompress.emplace(s->cct, &cs_info, partial_content, filter);
    filter = &*decompress;
  }
  else
  {
    if (obj_size != ent.meta.size) {
      // hmm.. something wrong, object not as expected, abort!
      ldout(s->cct, 0) << "ERROR: expected obj_size=" << obj_size << ", actual read size=" << ent.meta.size << dendl;
      return -EIO;
	  }
  }

  op_ret = rgw_policy_from_attrset(s->cct, attrs, &obj_policy);
  if (op_ret < 0)
    return op_ret;

  /* We can use global user_acl because LOs cannot have segments
   * stored inside different accounts. */
  if (s->system_request) {
    ldout(s->cct, 2) << "overriding permissions due to system operation" << dendl;
  } else if (s->auth.identity->is_admin_of(s->user->user_id)) {
    ldout(s->cct, 2) << "overriding permissions due to admin operation" << dendl;
  } else if (!verify_object_permission(s, part, s->user_acl.get(), bucket_acl,
				       &obj_policy, bucket_policy, action)) {
    return -EPERM;
  }

  if (ent.meta.size == 0) {
    return 0;
  }

  perfcounter->inc(l_rgw_get_b, cur_end - cur_ofs);
  filter->fixup_range(cur_ofs, cur_end);
  op_ret = read_op.iterate(cur_ofs, cur_end, filter);
  if (op_ret >= 0)
	  op_ret = filter->flush();
  return op_ret;
}

static int iterate_user_manifest_parts(CephContext * const cct,
                                       RGWRados * const store,
                                       const off_t ofs,
                                       const off_t end,
                                       RGWBucketInfo *pbucket_info,
                                       const string& obj_prefix,
                                       RGWAccessControlPolicy * const bucket_acl,
                                       const boost::optional<Policy>& bucket_policy,
                                       uint64_t * const ptotal_len,
                                       uint64_t * const pobj_size,
                                       string * const pobj_sum,
                                       int (*cb)(rgw_bucket& bucket,
                                                 const rgw_bucket_dir_entry& ent,
                                                 RGWAccessControlPolicy * const bucket_acl,
                                                 const boost::optional<Policy>& bucket_policy,
                                                 off_t start_ofs,
                                                 off_t end_ofs,
                                                 void *param),
                                       void * const cb_param)
{
  rgw_bucket& bucket = pbucket_info->bucket;
  uint64_t obj_ofs = 0, len_count = 0;
  bool found_start = false, found_end = false, handled_end = false;
  string delim;
  bool is_truncated;
  vector<rgw_bucket_dir_entry> objs;

  utime_t start_time = ceph_clock_now();

  RGWRados::Bucket target(store, *pbucket_info);
  RGWRados::Bucket::List list_op(&target);

  list_op.params.prefix = obj_prefix;
  list_op.params.delim = delim;

  MD5 etag_sum;
  do {
#define MAX_LIST_OBJS 100
    int r = list_op.list_objects(MAX_LIST_OBJS, &objs, NULL, &is_truncated);
    if (r < 0) {
      return r;
    }

    for (rgw_bucket_dir_entry& ent : objs) {
      const uint64_t cur_total_len = obj_ofs;
      const uint64_t obj_size = ent.meta.accounted_size;
      uint64_t start_ofs = 0, end_ofs = obj_size;

      if ((ptotal_len || cb) && !found_start && cur_total_len + obj_size > (uint64_t)ofs) {
	start_ofs = ofs - obj_ofs;
	found_start = true;
      }

      obj_ofs += obj_size;
      if (pobj_sum) {
        etag_sum.Update((const unsigned char *)ent.meta.etag.c_str(),
                        ent.meta.etag.length());
      }

      if ((ptotal_len || cb) && !found_end && obj_ofs > (uint64_t)end) {
	end_ofs = end - cur_total_len + 1;
	found_end = true;
      }

      perfcounter->tinc(l_rgw_get_lat,
			(ceph_clock_now() - start_time));

      if (found_start && !handled_end) {
        len_count += end_ofs - start_ofs;

        if (cb) {
          r = cb(bucket, ent, bucket_acl, bucket_policy, start_ofs, end_ofs, cb_param);
          if (r < 0) {
            return r;
          }
        }
      }

      handled_end = found_end;
      start_time = ceph_clock_now();
    }
  } while (is_truncated);

  if (ptotal_len) {
    *ptotal_len = len_count;
  }
  if (pobj_size) {
    *pobj_size = obj_ofs;
  }
  if (pobj_sum) {
    complete_etag(etag_sum, pobj_sum);
  }

  return 0;
}

struct rgw_slo_part {
  RGWAccessControlPolicy *bucket_acl = nullptr;
  Policy* bucket_policy = nullptr;
  rgw_bucket bucket;
  string obj_name;
  uint64_t size = 0;
  string etag;
};

static int iterate_slo_parts(CephContext *cct,
                             RGWRados *store,
                             off_t ofs,
                             off_t end,
                             map<uint64_t, rgw_slo_part>& slo_parts,
                             int (*cb)(rgw_bucket& bucket,
                                       const rgw_bucket_dir_entry& ent,
                                       RGWAccessControlPolicy *bucket_acl,
                                       const boost::optional<Policy>& bucket_policy,
                                       off_t start_ofs,
                                       off_t end_ofs,
                                       void *param),
                             void *cb_param)
{
  bool found_start = false, found_end = false;

  if (slo_parts.empty()) {
    return 0;
  }

  utime_t start_time = ceph_clock_now();

  map<uint64_t, rgw_slo_part>::iterator iter = slo_parts.upper_bound(ofs);
  if (iter != slo_parts.begin()) {
    --iter;
  }

  uint64_t obj_ofs = iter->first;

  for (; iter != slo_parts.end() && !found_end; ++iter) {
    rgw_slo_part& part = iter->second;
    rgw_bucket_dir_entry ent;

    ent.key.name = part.obj_name;
    ent.meta.accounted_size = ent.meta.size = part.size;
    ent.meta.etag = part.etag;

    uint64_t cur_total_len = obj_ofs;
    uint64_t start_ofs = 0, end_ofs = ent.meta.size;

    if (!found_start && cur_total_len + ent.meta.size > (uint64_t)ofs) {
      start_ofs = ofs - obj_ofs;
      found_start = true;
    }

    obj_ofs += ent.meta.size;

    if (!found_end && obj_ofs > (uint64_t)end) {
      end_ofs = end - cur_total_len + 1;
      found_end = true;
    }

    perfcounter->tinc(l_rgw_get_lat,
		      (ceph_clock_now() - start_time));

    if (found_start) {
      if (cb) {
	// SLO is a Swift thing, and Swift has no knowledge of S3 Policies.
        int r = cb(part.bucket, ent, part.bucket_acl,
		   (part.bucket_policy ?
		    boost::optional<Policy>(*part.bucket_policy) : none),
		   start_ofs, end_ofs, cb_param);
	if (r < 0)
          return r;
      }
    }

    start_time = ceph_clock_now();
  }

  return 0;
}

static int get_obj_user_manifest_iterate_cb(rgw_bucket& bucket,
                                            const rgw_bucket_dir_entry& ent,
                                            RGWAccessControlPolicy * const bucket_acl,
                                            const boost::optional<Policy>& bucket_policy,
                                            const off_t start_ofs,
                                            const off_t end_ofs,
                                            void * const param)
{
  RGWGetObj *op = static_cast<RGWGetObj *>(param);
  return op->read_user_manifest_part(bucket, ent, bucket_acl, bucket_policy, start_ofs, end_ofs);
}

int RGWGetObj::handle_user_manifest(const char *prefix)
{
  const boost::string_view prefix_view(prefix);
  ldout(s->cct, 2) << "RGWGetObj::handle_user_manifest() prefix="
                   << prefix_view << dendl;

  const size_t pos = prefix_view.find('/');
  if (pos == string::npos) {
    return -EINVAL;
  }

  const std::string bucket_name = url_decode(prefix_view.substr(0, pos));
  const std::string obj_prefix = url_decode(prefix_view.substr(pos + 1));

  rgw_bucket bucket;

  RGWAccessControlPolicy _bucket_acl(s->cct);
  RGWAccessControlPolicy *bucket_acl;
  boost::optional<Policy> _bucket_policy;
  boost::optional<Policy>* bucket_policy;
  RGWBucketInfo bucket_info;
  RGWBucketInfo *pbucket_info;

  if (bucket_name.compare(s->bucket.name) != 0) {
    map<string, bufferlist> bucket_attrs;
    RGWObjectCtx obj_ctx(store);
    int r = store->get_bucket_info(obj_ctx, s->user->user_id.tenant,
				  bucket_name, bucket_info, NULL,
				  &bucket_attrs);
    if (r < 0) {
      ldout(s->cct, 0) << "could not get bucket info for bucket="
		       << bucket_name << dendl;
      return r;
    }
    bucket = bucket_info.bucket;
    pbucket_info = &bucket_info;
    bucket_acl = &_bucket_acl;
    r = read_bucket_policy(store, s, bucket_info, bucket_attrs, bucket_acl, bucket);
    if (r < 0) {
      ldout(s->cct, 0) << "failed to read bucket policy" << dendl;
      return r;
    }
    _bucket_policy = get_iam_policy_from_attr(s->cct, store, bucket_attrs,
					      bucket_info.bucket.tenant);
    bucket_policy = &_bucket_policy;
  } else {
    bucket = s->bucket;
    pbucket_info = &s->bucket_info;
    bucket_acl = s->bucket_acl.get();
    bucket_policy = &s->iam_policy;
  }

  /* dry run to find out:
   * - total length (of the parts we are going to send to client),
   * - overall DLO's content size,
   * - md5 sum of overall DLO's content (for etag of Swift API). */
  int r = iterate_user_manifest_parts(s->cct, store, ofs, end,
        pbucket_info, obj_prefix, bucket_acl, *bucket_policy,
        nullptr, &s->obj_size, &lo_etag,
        nullptr /* cb */, nullptr /* cb arg */);
  if (r < 0) {
    return r;
  }

  r = RGWRados::Object::Read::range_to_ofs(s->obj_size, ofs, end);
  if (r < 0) {
    return r;
  }

  r = iterate_user_manifest_parts(s->cct, store, ofs, end,
        pbucket_info, obj_prefix, bucket_acl, *bucket_policy,
        &total_len, nullptr, nullptr,
        nullptr, nullptr);
  if (r < 0) {
    return r;
  }

  if (!get_data) {
    bufferlist bl;
    send_response_data(bl, 0, 0);
    return 0;
  }

  r = iterate_user_manifest_parts(s->cct, store, ofs, end,
        pbucket_info, obj_prefix, bucket_acl, *bucket_policy,
        nullptr, nullptr, nullptr,
        get_obj_user_manifest_iterate_cb, (void *)this);
  if (r < 0) {
    return r;
  }

  if (!total_len) {
    bufferlist bl;
    send_response_data(bl, 0, 0);
  }

  return 0;
}

int RGWGetObj::handle_slo_manifest(bufferlist& bl)
{
  RGWSLOInfo slo_info;
  bufferlist::iterator bliter = bl.begin();
  try {
    decode(slo_info, bliter);
  } catch (buffer::error& err) {
    ldout(s->cct, 0) << "ERROR: failed to decode slo manifest" << dendl;
    return -EIO;
  }
  ldout(s->cct, 2) << "RGWGetObj::handle_slo_manifest()" << dendl;

  vector<RGWAccessControlPolicy> allocated_acls;
  map<string, pair<RGWAccessControlPolicy *, boost::optional<Policy>>> policies;
  map<string, rgw_bucket> buckets;

  map<uint64_t, rgw_slo_part> slo_parts;

  MD5 etag_sum;
  total_len = 0;

  for (const auto& entry : slo_info.entries) {
    const string& path = entry.path;

    /* If the path starts with slashes, strip them all. */
    const size_t pos_init = path.find_first_not_of('/');
    /* According to the documentation of std::string::find following check
     * is not necessary as we should get the std::string::npos propagation
     * here. This might be true with the accuracy to implementation's bugs.
     * See following question on SO:
     * http://stackoverflow.com/questions/1011790/why-does-stdstring-findtext-stdstringnpos-not-return-npos
     */
    if (pos_init == string::npos) {
      return -EINVAL;
    }

    const size_t pos_sep = path.find('/', pos_init);
    if (pos_sep == string::npos) {
      return -EINVAL;
    }

    string bucket_name = path.substr(pos_init, pos_sep - pos_init);
    string obj_name = path.substr(pos_sep + 1);

    rgw_bucket bucket;
    RGWAccessControlPolicy *bucket_acl;
    Policy* bucket_policy;

    if (bucket_name.compare(s->bucket.name) != 0) {
      const auto& piter = policies.find(bucket_name);
      if (piter != policies.end()) {
        bucket_acl = piter->second.first;
        bucket_policy = piter->second.second.get_ptr();
	bucket = buckets[bucket_name];
      } else {
	allocated_acls.push_back(RGWAccessControlPolicy(s->cct));
	RGWAccessControlPolicy& _bucket_acl = allocated_acls.back();

        RGWBucketInfo bucket_info;
        map<string, bufferlist> bucket_attrs;
        RGWObjectCtx obj_ctx(store);
        int r = store->get_bucket_info(obj_ctx, s->user->user_id.tenant,
                                       bucket_name, bucket_info, nullptr,
                                       &bucket_attrs);
        if (r < 0) {
          ldout(s->cct, 0) << "could not get bucket info for bucket="
			   << bucket_name << dendl;
          return r;
        }
        bucket = bucket_info.bucket;
        bucket_acl = &_bucket_acl;
        r = read_bucket_policy(store, s, bucket_info, bucket_attrs, bucket_acl,
                               bucket);
        if (r < 0) {
          ldout(s->cct, 0) << "failed to read bucket ACL for bucket "
                           << bucket << dendl;
          return r;
	}
	auto _bucket_policy = get_iam_policy_from_attr(
	  s->cct, store, bucket_attrs, bucket_info.bucket.tenant);
        bucket_policy = _bucket_policy.get_ptr();
	buckets[bucket_name] = bucket;
        policies[bucket_name] = make_pair(bucket_acl, _bucket_policy);
      }
    } else {
      bucket = s->bucket;
      bucket_acl = s->bucket_acl.get();
      bucket_policy = s->iam_policy.get_ptr();
    }

    rgw_slo_part part;
    part.bucket_acl = bucket_acl;
    part.bucket_policy = bucket_policy;
    part.bucket = bucket;
    part.obj_name = obj_name;
    part.size = entry.size_bytes;
    part.etag = entry.etag;
    ldout(s->cct, 20) << "slo_part: ofs=" << ofs
                      << " bucket=" << part.bucket
                      << " obj=" << part.obj_name
                      << " size=" << part.size
                      << " etag=" << part.etag
                      << dendl;

    etag_sum.Update((const unsigned char *)entry.etag.c_str(),
                    entry.etag.length());

    slo_parts[total_len] = part;
    total_len += part.size;
  }

  complete_etag(etag_sum, &lo_etag);

  s->obj_size = slo_info.total_size;
  ldout(s->cct, 20) << "s->obj_size=" << s->obj_size << dendl;

  int r = RGWRados::Object::Read::range_to_ofs(total_len, ofs, end);
  if (r < 0) {
    return r;
  }

  total_len = end - ofs + 1;

  r = iterate_slo_parts(s->cct, store, ofs, end, slo_parts,
        get_obj_user_manifest_iterate_cb, (void *)this);
  if (r < 0) {
    return r;
  }

  return 0;
}

int RGWGetObj::get_data_cb(bufferlist& bl, off_t bl_ofs, off_t bl_len)
{
  /* garbage collection related handling */
  utime_t start_time = ceph_clock_now();
  if (start_time > gc_invalidate_time) {
    int r = store->defer_gc(s->obj_ctx, s->bucket_info, obj);
    if (r < 0) {
      dout(0) << "WARNING: could not defer gc entry for obj" << dendl;
    }
    gc_invalidate_time = start_time;
    gc_invalidate_time += (s->cct->_conf->rgw_gc_obj_min_wait / 2);
  }
  return send_response_data(bl, bl_ofs, bl_len);
}

bool RGWGetObj::prefetch_data()
{
  /* HEAD request, stop prefetch*/
  if (!get_data) {
    return false;
  }

  bool prefetch_first_chunk = true;
  range_str = s->info.env->get("HTTP_RANGE");

  if (range_str) {
    int r = parse_range();
    /* error on parsing the range, stop prefetch and will fail in execute() */
    if (r < 0) {
      return false; /* range_parsed==false */
    }
  }

  if (range_parsed) {
    /* range get goes to shadow objects, stop prefetch */
    if (ofs >= s->cct->_conf->rgw_max_chunk_size) {
      prefetch_first_chunk = false;
    } else {
      s->obj_ofs = ofs;
      s->obj_end = end;
    }
  }

  return get_data && prefetch_first_chunk;
}

void RGWGetObj::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

static bool object_is_expired(map<string, bufferlist>& attrs) {
  map<string, bufferlist>::iterator iter = attrs.find(RGW_ATTR_DELETE_AT);
  if (iter != attrs.end()) {
    utime_t delete_at;
    try {
      decode(delete_at, iter->second);
    } catch (buffer::error& err) {
      dout(0) << "ERROR: " << __func__ << ": failed to decode " RGW_ATTR_DELETE_AT " attr" << dendl;
      return false;
    }

    if (delete_at <= ceph_clock_now() && !delete_at.is_zero()) {
      return true;
    }
  }

  return false;
}

void RGWGetObj::head_namespce_obj(bufferlist& bl)
{
  bool is_dir = false;
  bool is_appendable = false;

  // at present, namespace don't support these parameters
  if (mod_ptr != nullptr || unmod_ptr != nullptr || if_match != nullptr || if_nomatch != nullptr) {
    op_ret = EINVAL;
    send_response_data_error();
    return;
  }

  op_ret = RGWRados::Bucket::Namespace::head_obj(store, s->bucket_info, obj.key.name, s->obj_size,
      lastmod, is_dir, is_appendable);

  if (op_ret < 0) {
    send_response_data_error();
    return;
  }

  total_len = s->obj_size;
  ldout(s->cct, 20) << __func__ << " " << obj.key.name << " size=" << s->obj_size
                    << " lastmod=" << lastmod << "is dir=" << is_dir << dendl;

  if (is_dir) {
    attrs[RGW_NAMESPACE_HEAD_ATTR].append(bucket_ns_dir.c_str(), bucket_ns_dir.size() + 1);
    attrs[RGW_ATTR_CONTENT_TYPE].append(bucket_ns_dir_con_type.c_str(),
        bucket_ns_dir_con_type.size() + 1);
  } else {
    if (is_appendable) {
      attrs[RGW_ATTR_TARGET_SIZE].append(s->obj_size);
    }
    attrs[RGW_NAMESPACE_HEAD_ATTR].append(bucket_ns_file.c_str(), bucket_ns_file.size() + 1);
  }
  send_response_data(bl, 0, 0);
}

#ifdef WITH_RADOSGW_BEAST_FRONTEND
static void asio_send_http_cb(void *arg, int ret) {
  auto sync = (SyncPoint *) arg;
  sync->put(ret);
}
#endif

inline void generate_text_blind_watermark_response(bufferlist& text_watermark_bl,
                                                   uint64_t& content_length,
                                                   const string& req_id) {
  JSONFormatter f;
  f.open_object_section("");
  f.dump_string("code", "success");
  f.dump_string("text", rgw_bl_to_str(text_watermark_bl));
  f.dump_string("requestId", req_id);
  f.close_section();

  std::ostringstream oss;
  f.flush(oss);
  text_watermark_bl.clear();

  string response = oss.str();
  text_watermark_bl.append(response.c_str(), response.length());
  content_length = response.length();
}

int RGWGetObj::forward_to_timg(const std::string& origin_request) {
  std::string image_proxy = s->cct->_conf->rgw_abcstore_proxy_address;
  if (image_proxy == "") {
    ldout(s->cct, 0) << "ERROR: rgw_abcstore_proxy_address is empty" << dendl;
    op_ret = -ERR_INTERNAL_ERROR;
    return op_ret;
  }
  auto pos = image_proxy.find(':');
  std::string host;
  std::string port;
  if (pos == string::npos) {
    host = image_proxy;
    port = "80";
  } else {
    host = image_proxy.substr(0, pos);
    port = image_proxy.substr(pos + 1, image_proxy.size());
  }
  map<string, bufferlist>::iterator iter;
  unsigned char m[CEPH_CRYPTO_MD5_DIGESTSIZE];
  MD5 hash;
  char calc_md5[CEPH_CRYPTO_MD5_DIGESTSIZE * 2 + 1];
  string etag;
  bufferlist etag_bl;
  string request_body;
  bufferlist image_bl;
  string uri = "/timg/v1/process";

  if (convert_to_timg_format(origin_request, request_body) != 0) {
    ldout(s->cct, 0) << "ERROR: convert to timg format error" << dendl;
    return op_ret;
  }
  ldout(s->cct, 30) << __func__ << "(): send to timg request body:" << request_body << dendl;

  void **asio_ctx = (void **) s->asio_ctx;

#ifdef WITH_RADOSGW_BEAST_FRONTEND
  // only if with beast fronted, we'll try async send http request
  if (asio_ctx != NULL) {
    static ConnectionPool _async_conn_pool = ConnectionPool(
        *((boost::asio::io_service *) asio_ctx[0]), host, port,
        s->cct->_conf->rgw_abcstore_proxy_connect_number,
        s->cct->_conf->rgw_abcstore_proxy_connect_retry, true);
    std::shared_ptr<ssl::stream<tcp::socket> > stream_ptr;

    int idx = _async_conn_pool.fetch_socket(stream_ptr, asio_ctx);

    if (idx < 0 || idx >= s->cct->_conf->rgw_abcstore_proxy_connect_number) {
      ldout(s->cct, 0) << "ConnectionPool fetch_socket return error idx:" << idx << dendl;
      op_ret = -ERR_INTERNAL_ERROR;
      return op_ret;
    }

    auto client = std::make_shared<RgwAsyncHttpClient>(stream_ptr, uri);

    SyncPoint sync(*((boost::asio::io_service *) asio_ctx[0]),
                   *((boost::asio::yield_context *) asio_ctx[1]));

    client->set_reqid(s->trans_id);
    client->set_cb(&sync, asio_send_http_cb);

    retry_send_request_by_connection_pool(s, op_ret, _async_conn_pool, idx, [&] {
          return client->send_request(host, request_body, &image_bl, "post");
        });

    if (op_ret < 0) {
      ldout(s->cct, 0) << "ERROR: send request to abcstore_proxy error:" << op_ret << dendl;
      _async_conn_pool.free_socket(idx);
      return op_ret;
    }
    // wait for response
    op_ret = sync.get();

    _async_conn_pool.free_socket(idx);
  } else
#endif
  {
    static boost::asio::io_context ioc;
    static ConnectionPool _sync_conn_pool = ConnectionPool(ioc, host, port,
        s->cct->_conf->rgw_abcstore_proxy_connect_number,
        s->cct->_conf->rgw_abcstore_proxy_connect_retry, false);
    std::shared_ptr<ssl::stream<tcp::socket> > stream_ptr;

    int idx = _sync_conn_pool.fetch_socket(stream_ptr);
    if (idx < 0 || idx >= s->cct->_conf->rgw_abcstore_proxy_connect_number) {
      ldout(s->cct, 0) << "ConnectionPool fetch_socket return error idx:" << idx << dendl;
      op_ret = -ERR_INTERNAL_ERROR;
      return op_ret;
    }

    RgwSyncHttpClient client = RgwSyncHttpClient(stream_ptr, uri);

    client.set_reqid(s->trans_id);

    retry_send_request_by_connection_pool(s, op_ret, _sync_conn_pool, idx, [&] {
          return client.send_request(host, request_body, &image_bl, "post");
        });

    if (op_ret < 0) {
      ldout(s->cct, 0) << "ERROR: send request to abcstore_proxy error:" << op_ret << dendl;
      _sync_conn_pool.free_socket(idx);
      return op_ret;
    }

    _sync_conn_pool.free_socket(idx);
  }


  if (op_ret == 0) {
    total_len = image_bl.length();

    //calculate etag instead of using etag stored in head object attrs
    iter = attrs.find(RGW_ATTR_ETAG);
    if (iter != attrs.end()) {
      hash.Update((const unsigned char *)image_bl.c_str(), image_bl.length());
      hash.Final(m);
      buf_to_hex(m, CEPH_CRYPTO_MD5_DIGESTSIZE, calc_md5);
      etag = calc_md5;
      etag_bl.append(etag.c_str(), etag.size());
      attrs[RGW_ATTR_ETAG] = etag_bl;
    }

    if (s->explicit_content_type.compare(CONTENT_TYPE_JSON) == 0) {
      generate_text_blind_watermark_response(image_bl, total_len, s->trans_id);
    }

    op_ret = send_response_data(image_bl, 0, total_len);
    if (op_ret < 0) {
      ldout(s->cct, 0) << "ERROR: dump response data err:"<< op_ret << dendl;
      op_ret = -ERR_INTERNAL_ERROR;
      return -ERR_INTERNAL_ERROR;
    }
    return 0;
  }

  // process error message
  if (image_bl.length() != 0) {
    JSONParser p;
    p.parse(image_bl.c_str(), image_bl.length());
    auto data = p.find_obj("errcode");
    if (data) {
      int err_code = stoi(data->get_data());
      switch (err_code) {
        case IMAGE_OK:
          return 0;
        case IMAGE_TOO_LARGE:
          ldout(s->cct, 20) << "ERROR: image process, response:"<< image_bl.to_str() << dendl;
          op_ret = -ERR_TOO_LARGE;
          return op_ret;
        case IMAGE_INVALID_PARAMS:
          ldout(s->cct, 20) << "ERROR: image process, response:"<< image_bl.to_str() << dendl;
          op_ret = -EINVAL;
          return op_ret;
        case IMAGE_INVALID:
          ldout(s->cct, 20) << "ERROR: image process, response:"<< image_bl.to_str() << dendl;
          op_ret = -ERR_INVALID_IMAGE;
          return op_ret;
        default:
          ldout(s->cct, 0) << "ERROR: image process internal error, response:"
                           << image_bl.to_str() << dendl;
          op_ret = -ERR_INTERNAL_ERROR;
          return -ERR_INTERNAL_ERROR;
      }
    } else {
        ldout(s->cct, 0) << "ERROR: abcstore_proxy error response without err_code" << dendl;
        op_ret = -ERR_INTERNAL_ERROR;
        return -ERR_INTERNAL_ERROR;
    }
  }
  ldout(s->cct, 0) << "ERROR: abcstore_proxy response body is empty" << dendl;
  op_ret = -ERR_INTERNAL_ERROR;
  return -ERR_INTERNAL_ERROR;
}

static int read_bucket_image_process_style(struct req_state* s,
                                           map<string, bufferlist>& bucket_attrs,
                                           std::string& style_name,
                                           std::string& cmd) {
  auto iter = bucket_attrs.find(RGW_ATTR_IMAGE_STYLE);
  if (iter == bucket_attrs.end()) {
    return -ENOENT;
  }
  std::map<std::string, bufferlist> styles_bl;

  bufferlist::iterator bliter = iter->second.begin();

  try {
    decode(styles_bl, bliter);
  } catch (buffer::error& err) {
    ldout(s->cct, 0) << "ERROR: failed to decode image styles, bucket:"
                     << s->bucket.name
                     << dendl;
    return -EIO;
  }

  auto it = styles_bl.find(style_name);
  if (it == styles_bl.end()) {
    ldout(s->cct, 0) << "couldn't find image style, bucket:" << s->bucket.name
                     << ",style name:" << style_name
                     << dendl;
    return -ENOENT;
  }

  RGWImageStyle style;
  bliter = it->second.begin();
  try {
    decode(style, bliter);
  } catch (buffer::error& err) {
    ldout(s->cct, 0) << "ERROR: failed to decode image style, bucket:"
                     << s->bucket.name << ", style:" << style_name
                     << dendl;
    return -EIO;
  }

  cmd = std::move(style.command);
  return 0;
}

int RGWGetObj::convert_to_timg_format(const std::string& origin_request, std::string& result) {
  std::vector<std::string> actions;
  boost::split(actions, origin_request, boost::is_any_of("/"));
  if (actions.size() < 2 || actions.size() > 17) {
    ldout(s->cct, 0) << __func__ << "() invalid image process req:"
                     << origin_request << dendl;
    op_ret = -EINVAL;
    return op_ret;
  }

  if (s->obj_size == 0) {
    ldout(s->cct, 0) << __func__ << "() invalid image, size = 0" << dendl;
    op_ret = -ERR_INVALID_IMAGE;
    return op_ret;
  }

  vector<std::shared_ptr<ImageBase>> timg_cmds;
  timg_cmds.clear();

  // verify image protection
  if (s->auth.identity->is_anonymous() && actions[0].compare("style") != 0) {
    int ret = verify_image_protection();
    if (ret < 0) {
      op_ret = ret;
      return op_ret;
    }
  }

  ImageProcess image_process(s, store, this);

  if (actions[0] == "image") {
    int r = image_process.parse_commands(actions, 1, timg_cmds);
    if (r < 0) {
      ldout(s->cct, 0) << __func__ << "() ERROR: parse_commands:" << r << dendl;
      op_ret = -EINVAL;
      return op_ret;
    }

    image_process.generate_timg_body(timg_cmds, result);

  } else if (actions[0] == "style") {
    RGWBucketInfo bucket_info;
    map<string, bufferlist> bucket_attrs;
    RGWObjectCtx obj_ctx(store);
    int r = store->get_bucket_info(obj_ctx, s->user->user_id.tenant,
                                   s->bucket.name, bucket_info, NULL,
                                   &bucket_attrs);
    if (r < 0) {
      ldout(s->cct, 0) << "ERROR: could not get bucket info for bucket="
           << s->bucket.name << dendl;
      op_ret = -EIO;
      return op_ret;
    }
    string cmd = "";
    op_ret = read_bucket_image_process_style(s, bucket_attrs, actions[1], cmd);
    if (op_ret < 0) {
      ldout(s->cct, 10) << "ERROR: get style error, bucket=" << s->bucket.name
                        << "style name:" << actions[1]
                        << ", error:" << op_ret
                        << dendl;
      return op_ret;
    }

    std::vector<std::string> cmds;
    boost::split(cmds, cmd, boost::is_any_of("/"));
    r = image_process.parse_commands(cmds, 0, timg_cmds);
    if (r < 0) {
      ldout(s->cct, 0) << __func__ << "() ERROR: parse_commands:" << r << dendl;
      op_ret = -EINVAL;
      return op_ret;
    }

    image_process.generate_timg_body(timg_cmds, result);
  } else {
    op_ret = -EINVAL;
    return op_ret;
  }
  return 0;
}

int RGWGetObj::verify_image_protection() {
  auto attr_iter = s->bucket_attrs.find(RGW_ATTR_IMAGE_PROTECTION);
  if (attr_iter != s->bucket_attrs.end()) {
    bufferlist::iterator bliter = attr_iter->second.begin();
    vector<string> resources;
    try {
      decode(resources, bliter);
    } catch (buffer::error& err) {
      ldout(s->cct, 0) << "ERROR: failed to decode image protection config, bucket:" << s->bucket.name << dendl;
      return -EINTR;
    }
    // deny if satisfy in resources
    for (uint32_t i = 0; i < resources.size(); i++) {
       auto pos = resources[i].find('*');
       if (pos == string::npos) {
         ldout(s->cct, 0) << "ERROR: invalid resources:" << resources[i] << dendl;
         continue;
       }
       if (pos == 0) { // suffix
         if (resources[i].length() == 1) {
           return -EACCES;
         }
         if (boost::algorithm::ends_with(s->object.name,
             std::string_view(resources[i]).substr(pos + 1))) {
           return -EACCES;
         }
       } else { // prefix
         if (pos != resources[i].length() - 1) {
           ldout(s->cct, 0) << "ERROR: invalid resources:" << resources[i] << dendl;
           continue;
         }
         if (boost::algorithm::starts_with(s->object.name,
             std::string_view(resources[i]).substr(0, pos))) {
           return -EACCES;
         }
       }
    }
  }
  return 0;
}

void RGWGetObj::execute()
{
  bufferlist bl;
  gc_invalidate_time = ceph_clock_now();
  gc_invalidate_time += (s->cct->_conf->rgw_gc_obj_min_wait / 2);

  op_ret = get_params();
  if (op_ret < 0) {
    send_response_data_error();
    return;
  }

  op_ret = init_common();
  if (op_ret < 0) {
    send_response_data_error();
    return;
  }

  perfcounter->inc(l_rgw_get);

  // check is namespace head dir
  if (!get_data && // it is head object
      s->bucket_info.namespace_type == BUCKET_NAMESPACE_ENABLE && // bucket namespace is enable
      !s->cct->_conf->rgw_bucket_namespace_disable_force &&
      s->cct->_conf->rgw_namespace_head_cheap) { // cheap
    head_namespce_obj(bl);
    return;
  }

  bool need_decompress;
  int64_t ofs_x, end_x;

  RGWGetObj_CB cb(this);
  RGWGetObj_Filter* filter = (RGWGetObj_Filter *)&cb;
  boost::optional<RGWGetObj_Decompress> decompress;
  std::unique_ptr<RGWGetObj_Filter> decrypt;
  map<string, bufferlist>::iterator attr_iter;

  RGWRados::Object op_target(store, s->bucket_info, *static_cast<RGWObjectCtx *>(s->obj_ctx), obj);
  RGWRados::Object::Read read_op(&op_target);

  if (!exists) {
    op_ret = store->fetch_mirror_obj(s, &lastmod, attrs, &version_id, &cb);
    ldout(s->cct, 20) << __func__ << " fetch_mirror_obj err:" << op_ret << dendl;
    if (op_ret < 0) {
      goto done_err;
    }
    goto done;  // done: filter->flush() and send empty bufferlist to client again
  }

  read_op.conds.mod_ptr = mod_ptr;
  read_op.conds.unmod_ptr = unmod_ptr;
  read_op.conds.high_precision_time = s->system_request; /* system request need to use high precision time */
  read_op.conds.mod_zone_id = mod_zone_id;
  read_op.conds.mod_pg_ver = mod_pg_ver;
  read_op.conds.if_match = if_match;
  read_op.conds.if_nomatch = if_nomatch;
  read_op.params.attrs = &attrs;
  read_op.params.lastmod = &lastmod;
  read_op.params.obj_size = &s->obj_size;

  op_ret = read_op.prepare();
  // for namespace
  // this object don't exist, but it maybe a directory
  if (op_ret == -ENOENT &&
      !get_data &&
      s->bucket_info.namespace_type == BUCKET_NAMESPACE_ENABLE &&
      !s->cct->_conf->rgw_bucket_namespace_disable_force) {
    head_namespce_obj(bl);
    return;
  } else if (op_ret < 0) {
    goto done_err;
  }


  version_id = read_op.state.obj.key.instance;

// add image process after read_op prepare() for fetching obj attrs and lastModified
  if (s->info.args.exists(RGW_BCE_PROCESS)) {
    const std::string image_process_req = s->info.args.get(RGW_BCE_PROCESS);
    if (image_process_req.length() == 0) {
      op_ret = -EINVAL;
      return;
    }
    // ignore range param, and return 200 instead of 206
    partial_content = false;

    if (forward_to_timg(image_process_req) < 0) {
      goto done_err;
    }
    op_ret = filter->flush();
    if (op_ret < 0) {
      ldout(s->cct, 0) << "ERROR: flush response data err:"<< op_ret << dendl;
      goto done_err;
    }
    return;
  }

  /* STAT ops don't need data, and do no i/o */
  if (get_type() == RGW_OP_STAT_OBJ) {
    return;
  }

  /* start gettorrent */
  if (torrent.get_flag())
  {
    attr_iter = attrs.find(RGW_ATTR_CRYPT_MODE);
    if (attr_iter != attrs.end() && attr_iter->second.to_str() == "SSE-C-AES256") {
      ldout(s->cct, 0) << "ERROR: torrents are not supported for objects "
          "encrypted with SSE-C" << dendl;
      op_ret = -EINVAL;
      goto done_err;
    }
    torrent.init(s, store);
    op_ret = torrent.get_torrent_file(read_op, total_len, bl, obj);
    if (op_ret < 0)
    {
      ldout(s->cct, 0) << "ERROR: failed to get_torrent_file ret= " << op_ret
                       << dendl;
      goto done_err;
    }
    op_ret = send_response_data(bl, 0, total_len);
    if (op_ret < 0)
    {
      ldout(s->cct, 0) << "ERROR: failed to send_response_data ret= " << op_ret 
                       << dendl;
      goto done_err;
    }
    return;
  }
  /* end gettorrent */

  op_ret = rgw_compression_info_from_attrset(attrs, need_decompress, cs_info);
  if (op_ret < 0) {
    lderr(s->cct) << "ERROR: failed to decode compression info, cannot decompress" << dendl;
    goto done_err;
  }
  if (need_decompress) {
      s->obj_size = cs_info.orig_size;
      decompress.emplace(s->cct, &cs_info, partial_content, filter);
      filter = &*decompress;
  }

  attr_iter = attrs.find(RGW_ATTR_USER_MANIFEST);
  if (attr_iter != attrs.end() && !skip_manifest) {
    op_ret = handle_user_manifest(attr_iter->second.c_str());
    if (op_ret < 0) {
      ldout(s->cct, 0) << "ERROR: failed to handle user manifest ret="
		       << op_ret << dendl;
      goto done_err;
    }
    return;
  }

  attr_iter = attrs.find(RGW_ATTR_SLO_MANIFEST);
  if (attr_iter != attrs.end() && !skip_manifest) {
    is_slo = true;
    op_ret = handle_slo_manifest(attr_iter->second);
    if (op_ret < 0) {
      ldout(s->cct, 0) << "ERROR: failed to handle slo manifest ret=" << op_ret
		       << dendl;
      goto done_err;
    }
    return;
  }

  // for range requests with obj size 0
  if (range_str && !(s->obj_size)) {
    total_len = 0;
    op_ret = -ERANGE;
    goto done_err;
  }

  op_ret = read_op.range_to_ofs(s->obj_size, ofs, end);
  if (op_ret < 0)
    goto done_err;
  total_len = (ofs <= end ? end + 1 - ofs : 0);

  /* Check whether the object has expired. Swift API documentation
   * stands that we should return 404 Not Found in such case. */
  if (need_object_expiration() && object_is_expired(attrs)) {
    op_ret = -ENOENT;
    goto done_err;
  }

  start = ofs;

  attr_iter = attrs.find(RGW_ATTR_MANIFEST);

  op_ret = this->get_decrypt_filter(&decrypt, filter,
                                    attr_iter != attrs.end() ? &(attr_iter->second) : nullptr);
  if (decrypt != nullptr) {
    filter = decrypt.get();
  }
  if (op_ret < 0) {
    goto done_err;
  }

  if (!get_data || ofs > end) {
    send_response_data(bl, 0, 0);
    return;
  }

  perfcounter->inc(l_rgw_get_b, end - ofs);

  ofs_x = ofs;
  end_x = end;
  filter->fixup_range(ofs_x, end_x);
  op_ret = read_op.iterate(ofs_x, end_x, filter);

done:
  if (op_ret >= 0)
    op_ret = filter->flush();

  perfcounter->tinc(l_rgw_get_lat, s->time_elapsed());
  if (op_ret < 0) {
    goto done_err;
  }

  op_ret = send_response_data(bl, 0, 0);
  if (op_ret < 0) {
    goto done_err;
  }
  return;

done_err:
  if (op_ret == -ENOENT && is_anonymous(s) && !s->bucket_info.website_conf.is_empty() && is_browser_client(s)) {
    // if bucket has static website configure && op is anoymous user && browser client
    if (s->object.name != s->bucket_info.website_conf.get_error_doc()) {
      // donot response error information
      website_retarget = true;
      return;
    }
  }
  if (op_ret == -ENOENT && s->is_symlink_obj) {
    op_ret = -ERR_SYMLINK_TARGET_NOT_EXIST;
  }
  send_response_data_error();
}

int RGWGetObj::init_common()
{
  if (range_str) {
    /* range parsed error when prefetch */
    if (!range_parsed) {
      int r = parse_range();
      if (r < 0)
        return r;
    }
  }
  if (if_mod) {
    if (parse_time(if_mod, &mod_time) < 0)
      return -EINVAL;
    mod_ptr = &mod_time;
  }

  if (if_unmod) {
    if (parse_time(if_unmod, &unmod_time) < 0)
      return -EINVAL;
    unmod_ptr = &unmod_time;
  }

  return 0;
}

int RGWListBuckets::verify_permission()
{
  if (!verify_user_permission(s, RGW_PERM_READ)) {
    return -EACCES;
  }

  return 0;
}

int RGWGetUsage::verify_permission()
{
  if (s->auth.identity->is_anonymous()) {
    return -EACCES;
  }

  return 0;
}

void RGWListBuckets::execute()
{
  bool done;
  bool started = false;
  uint64_t total_count = 0;

  const uint64_t max_buckets = s->cct->_conf->rgw_list_buckets_max_chunk;

  op_ret = get_params();
  if (op_ret < 0) {
    goto send_end;
  }

  if (supports_account_metadata()) {
    op_ret = rgw_get_user_attrs_by_uid(store, s->user->user_id, attrs);
    if (op_ret < 0) {
      goto send_end;
    }
  }

  is_truncated = false;
  do {
    RGWUserBuckets buckets;
    uint64_t read_count;
    if (limit >= 0) {
      read_count = min(limit - total_count, max_buckets);
    } else {
      read_count = max_buckets;
    }

    if (s->cct->_conf->rgw_abcstore_multi_region) {
      op_ret = database::DBClient::instance().list_bucket_by_user(s, s->user->user_id.id, buckets, read_count);
    } else {
      op_ret = rgw_read_user_buckets(store, s->user->user_id, buckets,
                                     marker, end_marker, read_count,
                                     should_get_stats(), &is_truncated,
                                     get_default_max());
    }
    if (op_ret < 0) {
      /* hmm.. something wrong here.. the user was authenticated, so it
         should exist */
      ldout(s->cct, 10) << "WARNING: failed on rgw_get_user_buckets uid="
                        << s->user->user_id << dendl;
      break;
    }

    /* We need to have stats for all our policies - even if a given policy
     * isn't actually used in a given account. In such situation its usage
     * stats would be simply full of zeros. */
    for (const auto& policy : store->get_zonegroup().placement_targets) {
      policies_stats.emplace(policy.second.name,
                             decltype(policies_stats)::mapped_type());
    }

    std::map<std::string, RGWBucketEnt>& m = buckets.get_buckets();

    if (!m.empty()) {
      map<string, RGWBucketEnt>::reverse_iterator riter = m.rbegin();
      marker = riter->first;
    }
#ifdef WITH_BCEIAM
    if (s->user->subusers.size() != 0) {
      std::vector<string> allowed_buckets;
      int r = rgw::auth::s3::check_batch_bucket_auth(s, m, allowed_buckets);
      if (r != 0) {
        ldout(s->cct, 10) << "WARNING: failed on check_batch_bucket_auth uid="
                          << s->user->user_id << ",ret:" << r << dendl;
        break;
      }
      std::unordered_map<string, bool> inner_map;
      for (auto b : allowed_buckets) {
        inner_map[b] = true;
      }
      std::unordered_map<string, bool>::iterator i;
      for (auto iter = m.begin(); iter != m.end(); ) {
        i = inner_map.find(iter->first);
        if (i == inner_map.end()) {
          m.erase(iter++);
        } else {
          iter++;
        }
      }
    }
#endif
    /* only work for swift api
    for (const auto& kv : m) {
      const auto& bucket = kv.second;

      global_stats.bytes_used += bucket.size;
      global_stats.bytes_used_rounded += bucket.size_rounded;
      global_stats.objects_count += bucket.count;

      // operator[] still can create a new entry for storage policy seen
      // for first time.
      auto& policy_stats = policies_stats[bucket.placement_rule.to_str()];
      policy_stats.bytes_used += bucket.size;
      policy_stats.bytes_used_rounded += bucket.size_rounded;
      policy_stats.buckets_count++;
      policy_stats.objects_count += bucket.count;
    }
    global_stats.buckets_count += m.size();
    */
    total_count += m.size();

    done = (m.size() < read_count || (limit >= 0 && total_count >= (uint64_t)limit));

    if (!started) {
      send_response_begin(buckets.count() > 0);
      started = true;
    }

    if (!m.empty()) {
      handle_listing_chunk(std::move(buckets));
    }
  } while (is_truncated && !done);

send_end:
  if (!started) {
    send_response_begin(false);
  }
  send_response_end();
}

void RGWGetUsage::execute()
{
  uint64_t start_epoch = 0;
  uint64_t end_epoch = (uint64_t)-1;
  op_ret = get_params();
  if (op_ret < 0)
    return;
    
  if (!start_date.empty()) {
    op_ret = utime_t::parse_date(start_date, &start_epoch, NULL);
    if (op_ret < 0) {
      ldout(store->ctx(), 0) << "ERROR: failed to parse start date" << dendl;
      return;
    }
  }
    
  if (!end_date.empty()) {
    op_ret = utime_t::parse_date(end_date, &end_epoch, NULL);
    if (op_ret < 0) {
      ldout(store->ctx(), 0) << "ERROR: failed to parse end date" << dendl;
      return;
    }
  }
     
  uint32_t max_entries = 1000;

  bool is_truncated = true;

  RGWUsageIter usage_iter;
  
  while (is_truncated) {
    op_ret = store->read_usage(s->user->user_id, start_epoch, end_epoch, max_entries,
                                &is_truncated, usage_iter, usage);

    if (op_ret == -ENOENT) {
      op_ret = 0;
      is_truncated = false;
    }

    if (op_ret < 0) {
      return;
    }    
  }

  op_ret = rgw_user_sync_all_stats(store, s->user->user_id);
  if (op_ret < 0) {
    ldout(store->ctx(), 0) << "ERROR: failed to sync user stats" << dendl;
    return;
  }

  op_ret = rgw_user_get_all_buckets_stats(store, s->user->user_id, buckets_usage);
  if (op_ret < 0) {
    ldout(store->ctx(), 0) << "ERROR: failed to get user's buckets stats" << dendl;
    return;
  }

  string user_str = s->user->user_id.to_str();
  op_ret = store->cls_user_get_header(user_str, &header);
  if (op_ret < 0) {
    ldout(store->ctx(), 0) << "ERROR: can't read user header"  << dendl;
    return;
  }
  
  return;
}

int RGWStatAccount::verify_permission()
{
  if (!verify_user_permission(s, RGW_PERM_READ)) {
    return -EACCES;
  }

  return 0;
}

void RGWStatAccount::execute()
{
  string marker;
  bool is_truncated = false;
  uint64_t max_buckets = s->cct->_conf->rgw_list_buckets_max_chunk;

  do {
    RGWUserBuckets buckets;

    op_ret = rgw_read_user_buckets(store, s->user->user_id, buckets, marker,
				   string(), max_buckets, true, &is_truncated);
    if (op_ret < 0) {
      /* hmm.. something wrong here.. the user was authenticated, so it
         should exist */
      ldout(s->cct, 10) << "WARNING: failed on rgw_get_user_buckets uid="
			<< s->user->user_id << dendl;
      break;
    } else {
      /* We need to have stats for all our policies - even if a given policy
       * isn't actually used in a given account. In such situation its usage
       * stats would be simply full of zeros. */
      for (const auto& policy : store->get_zonegroup().placement_targets) {
        policies_stats.emplace(policy.second.name,
                               decltype(policies_stats)::mapped_type());
      }

      std::map<std::string, RGWBucketEnt>& m = buckets.get_buckets();
      for (const auto& kv : m) {
        const auto& bucket = kv.second;

        global_stats.bytes_used += bucket.size;
        global_stats.bytes_used_rounded += bucket.size_rounded;
        global_stats.objects_count += bucket.count;

        /* operator[] still can create a new entry for storage policy seen
         * for first time. */
        auto& policy_stats = policies_stats[bucket.placement_rule.to_str()];
        policy_stats.bytes_used += bucket.size;
        policy_stats.bytes_used_rounded += bucket.size_rounded;
        policy_stats.buckets_count++;
        policy_stats.objects_count += bucket.count;
      }
      global_stats.buckets_count += m.size();

    }
  } while (is_truncated);
}

int RGWListRgw::verify_permission()
{

  //TODO: need verify permission
  //if (!verify_user_permission(s, RGW_PERM_READ)) {
  //  return -EACCES;
  //}

  return 0;
}

void RGWListRgw::execute()
{
  librados::Rados* handle = store->get_rados_handle();
  bufferlist inbl;
  bufferlist outbl;
  int op_ret = handle->mon_command("{\"prefix\": \"status\" ,\"format\": \"json\"}", inbl, &outbl, NULL);
  if (op_ret < 0) {
    return;
  }
  JSONParser parser;
  op_ret = parser.parse(outbl.c_str(), outbl.length());
  if (op_ret < 0) {
    return;
  }
  JSONObjIter iter;
  JSONObj* obj = nullptr;
  do {
    iter = parser.find_first("servicemap");
    if (iter.end()) {
      break;
    }
    obj = *iter;
    iter = obj->find_first("epoch");
    if (iter.end()) {
      break;
    }
    decode_json_obj(epoch, *iter);
    iter = obj->find_first("modified");
    if (iter.end()) {
      break;
    }
    decode_json_obj(last_modified, *iter);
    iter = obj->find_first("services");
    if (iter.end()) {
      break;
    }
    obj = *iter;
    iter = obj->find_first("rgw");
    if (iter.end()) {
      break;
    }
    obj = *iter;
    iter = obj->find_first("daemons");
    if (iter.end()) {
      break;
    }
    obj = *iter;
    iter = obj->find_first();
    for (; !iter.end(); ++iter) {
      if ((*iter)->get_name() == "summary") {
        continue;
      }
      obj = *iter;
      JSONObjIter aiter;
      aiter = obj->find_first("addr");
      if (!aiter.end()) {
        string ip;
        string port;
        decode_json_obj(ip, *aiter);
        auto pos = ip.find(":");
        rgw_ip.push_back(ip.substr(0, pos));
        aiter = obj->find_first("metadata");
        if (!aiter.end()) {
          obj = *aiter;
          aiter = obj->find_first("frontend_config#0");
          string config;
          decode_json_obj(config, *aiter);
          for (auto& entry : get_str_vec(config, " ")) {
            string key;
            string val;

            ssize_t pos = entry.find('=');
            if (pos < 0) {
              continue;
            }

            op_ret = parse_key_value(entry, key, val);
            if (op_ret < 0) {
              return;
            }
            if (key == "port") {
              port = val;
            }
          }
        }

        if (port.empty()) {
          port = "80";
        }
        rgw_port.push_back(port);
      }
    }
  } while (0);
}

int RGWGetBucketVersioning::verify_permission()
{
  return verify_bucket_owner_or_policy(s, rgw::IAM::s3GetBucketVersioning);
}

void RGWGetBucketVersioning::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

void RGWGetBucketVersioning::execute()
{
  versioned = s->bucket_info.versioned();
  versioning_enabled = s->bucket_info.versioning_enabled();
  mfa_enabled = s->bucket_info.mfa_enabled();
}

int RGWSetBucketVersioning::verify_permission()
{
  if (!s->bucket_info.trash_dir.empty()) {
    ldout(s->cct, 0) << __func__ << "() ERROR: versioning not work with trash " << s->bucket_info.bucket << dendl;
    op_ret = -ERR_METHOD_NOT_ALLOWED;
    return op_ret;
  }
  return verify_bucket_owner_or_policy(s, rgw::IAM::s3PutBucketVersioning);
}

void RGWSetBucketVersioning::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

void RGWSetBucketVersioning::execute()
{
  op_ret = get_params();
  if (op_ret < 0)
    return;

  if (s->bucket_info.obj_lock_enabled() && versioning_status != VersioningEnabled) {
    op_ret = -ERR_INVALID_BUCKET_STATE;
    return;
  }

  bool cur_mfa_status = (s->bucket_info.flags & BUCKET_MFA_ENABLED) != 0;

  mfa_set_status &= (mfa_status != cur_mfa_status);

  if (mfa_set_status &&
      !s->mfa_verified) {
    op_ret = -ERR_MFA_REQUIRED;
    return;
  }

  // don't allow to enable versioning when bucket namespace is enable
  if (s->bucket_info.namespace_type == BUCKET_NAMESPACE_ENABLE) {
    op_ret = -ERROR_BUCKET_VERSION_SET_NOT_ALLOWED;
    return;
  }

  if (!store->is_meta_master()) {
    op_ret = forward_request_to_master(s, NULL, store, in_data, nullptr);
    if (op_ret < 0) {
      ldout(s->cct, 20) << __func__ << " forward_request_to_master returned ret=" << op_ret << dendl;
      return;
    }
  }

  bool modified = mfa_set_status;

  op_ret = retry_raced_bucket_write(store, s, [&] {
      if (mfa_set_status) {
        if (mfa_status) {
          s->bucket_info.flags |= BUCKET_MFA_ENABLED;
        } else {
          s->bucket_info.flags &= ~BUCKET_MFA_ENABLED;
        }
      }

      if (versioning_status == VersioningEnabled) {
	s->bucket_info.flags |= BUCKET_VERSIONED;
	s->bucket_info.flags &= ~BUCKET_VERSIONS_SUSPENDED;
        modified = true;
      } else if (versioning_status == VersioningSuspended) {
	s->bucket_info.flags |= (BUCKET_VERSIONED | BUCKET_VERSIONS_SUSPENDED);
        modified = true;
      } else {
	return op_ret;
      }
      return store->put_bucket_instance_info(s->bucket_info, false, real_time(),
                                             &s->bucket_attrs);
    });

  if (!modified) {
    return;
  }

  if (op_ret < 0) {
    ldout(s->cct, 0) << "NOTICE: put_bucket_info on bucket=" << s->bucket.name
		     << " returned err=" << op_ret << dendl;
    return;
  }
}

int RGWPutBucketMirroring::verify_permission()
{
  return verify_bucket_owner_or_policy(s, rgw::IAM::s3PutBucketMirroring);
}

void RGWPutBucketMirroring::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

void RGWPutBucketMirroring::execute()
{
  op_ret = get_params();
  if (op_ret < 0) {
    ldout(s->cct, 0) << __func__ << "() get_params ret=" << op_ret <<dendl;
    return;
  }
#define MAX_MIRROR_CONTENT_LENGTH 20480
  if (len > MAX_MIRROR_CONTENT_LENGTH) {
    op_ret = -ERR_MAX_MESSAGE_LENGTH_EXCEEDED;
    return;
  }

  if (!store->is_meta_master()) {
    bufferlist in_data;
    in_data.append(data, len);
    op_ret = forward_request_to_master(s, NULL, store, in_data, nullptr);
    if (op_ret < 0) {
      ldout(s->cct, 0) << __func__ << "ERROR: forward_request_to_master returned ret="
                       << op_ret << dendl;
      return;
    }
  }

  RGWMirroringConfiguration config;
  JSONParser parser;

  const char* content_md5 = s->info.env->get("HTTP_CONTENT_MD5");

  ldout(s->cct, 15) << "read len=" << len << " data=" << (data ? data : "") << dendl;

  if (content_md5) {
    std::string content_md5_bin;
    try {
      content_md5_bin = rgw::from_base64(boost::string_view(content_md5));
    } catch (...) {
      s->err.message = "Request header Content-MD5 contains character "
                       "that is not base64 encoded.";
      ldout(s->cct, 0) << s->err.message << dendl;
      op_ret = -ERR_BAD_DIGEST;
      return;
    }

    MD5 data_hash;
    unsigned char data_hash_res[CEPH_CRYPTO_MD5_DIGESTSIZE];
    data_hash.Update(reinterpret_cast<const unsigned char*>(data), len);
    data_hash.Final(data_hash_res);

    if (memcmp(data_hash_res, content_md5_bin.c_str(), CEPH_CRYPTO_MD5_DIGESTSIZE) != 0) {
      op_ret = -ERR_BAD_DIGEST;
      s->err.message = "The Content-MD5 you specified did not match what we received.";
      ldout(s->cct, 0) << s->err.message
                       << " Specified content md5: " << content_md5
                       << ", calculated content md5: " << data_hash_res
                       << dendl;
      return;
    }
  }

  if (!parser.parse(data, len)) {
    ldout(s->cct, 0) << "ERROR: json parser mirroring configuration failed" << dendl;
    op_ret = -ERR_MALFORMED_JSON;
    return;
  }

  try {
    JSONDecoder::decode_json("bucketMirroringConfiguration", config, &parser);
  } catch (JSONDecoder::err& err) {
    ldout(s->cct, 0) << "ERROR: bad mirroring configuration: " << err.message << dendl;
    op_ret = -ERR_MALFORMED_JSON;
    return;
  }

  op_ret = config.is_valid(s->cct->_conf->rgw_mirror_url_blacklist);
  if (op_ret < 0) {
    ldout(s->cct, 0) << "ERROR: mirroring configuration invalid, op_ret:" << op_ret << dendl;
    return;
  }

  bufferlist mirroring_bl;
  config.encode(mirroring_bl);

  op_ret = retry_raced_bucket_write(store, s, [&] {
      map<string, bufferlist> attrs = s->bucket_attrs;
      attrs[RGW_ATTR_MIRRORING] = mirroring_bl;
      return rgw_bucket_set_attrs(store, s->bucket_info, attrs, &s->bucket_info.objv_tracker);
    });
}

int RGWGetBucketMirroring::verify_permission()
{
  return verify_bucket_owner_or_policy(s, rgw::IAM::s3GetBucketMirroring);
}

void RGWGetBucketMirroring::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

void RGWGetBucketMirroring::execute()
{
  map<string, bufferlist>::iterator aiter = s->bucket_attrs.find(RGW_ATTR_MIRRORING);
  if (aiter == s->bucket_attrs.end()) {
    ldout(s->cct, 20) << "no mirroring configuration attr found" << dendl;
    op_ret = -ERR_NO_SUCH_MIRRORING;
    return;
  }

  bufferlist::iterator iter = aiter->second.begin();
  try {
    config.decode(iter);
  } catch (buffer::error& err) {
    ldout(s->cct, 0) << "ERROR: could not decode mirroring, caught error:" << err << dendl;
    op_ret = -EIO;
    return;
  }
}

int RGWDeleteBucketMirroring::verify_permission()
{
  return verify_bucket_owner_or_policy(s, rgw::IAM::s3PutBucketMirroring);
}

void RGWDeleteBucketMirroring::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

void RGWDeleteBucketMirroring::execute()
{
   if (!store->is_meta_master()) {
    bufferlist in_data;
    op_ret = forward_request_to_master(s, nullptr, store, in_data, nullptr);
    if (op_ret < 0) {
      ldout(s->cct, 0) << "forward_request_to_master returned ret=" << op_ret << dendl;
      return;
    }
  }

  op_ret = retry_raced_bucket_write(store, s, [&] {
      map<string, bufferlist> attrs = s->bucket_attrs;
      auto iter = attrs.find(RGW_ATTR_MIRRORING);
      if (iter != attrs.end()) {
        attrs.erase(iter);
        return rgw_bucket_set_attrs(store, s->bucket_info, attrs, &s->bucket_info.objv_tracker);
      } else {
        return 0;
      }
    });
}

int RGWGetBucketWebsite::verify_permission()
{
  return verify_bucket_owner_or_policy(s, rgw::IAM::s3GetBucketWebsite);
}

void RGWGetBucketWebsite::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

void RGWGetBucketWebsite::execute()
{
  if (!s->bucket_info.has_website) {
    op_ret = -ERR_NO_SUCH_WEBSITE_CONFIGURATION;
  }
}

int RGWSetBucketWebsite::verify_permission()
{
  return verify_bucket_owner_or_policy(s, rgw::IAM::s3PutBucketWebsite);
}

void RGWSetBucketWebsite::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

void RGWSetBucketWebsite::execute()
{
  op_ret = get_params();

  if (op_ret < 0)
    return;

  if (!store->is_meta_master()) {
    op_ret = forward_request_to_master(s, NULL, store, in_data, nullptr);
    if (op_ret < 0) {
      ldout(s->cct, 20) << __func__ << " forward_request_to_master returned ret=" << op_ret << dendl;
      return;
    }
  }

  op_ret = retry_raced_bucket_write(store, s, [this] {
      s->bucket_info.has_website = true;
      s->bucket_info.website_conf = website_conf;
      op_ret = store->put_bucket_instance_info(s->bucket_info, false,
					       real_time(), &s->bucket_attrs);
      return op_ret;
    });

  if (op_ret < 0) {
    ldout(s->cct, 0) << "NOTICE: put_bucket_info on bucket=" << s->bucket.name << " returned err=" << op_ret << dendl;
    return;
  }
}

int RGWDeleteBucketWebsite::verify_permission()
{
  return verify_bucket_owner_or_policy(s, rgw::IAM::s3DeleteBucketWebsite);
}

void RGWDeleteBucketWebsite::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

void RGWDeleteBucketWebsite::execute()
{
  op_ret = retry_raced_bucket_write(store, s, [this] {
      s->bucket_info.has_website = false;
      s->bucket_info.website_conf = RGWBucketWebsiteConf();
      op_ret = store->put_bucket_instance_info(s->bucket_info, false,
					       real_time(), &s->bucket_attrs);
      return op_ret;
    });
  if (op_ret < 0) {
    ldout(s->cct, 0) << "NOTICE: put_bucket_info on bucket=" << s->bucket.name << " returned err=" << op_ret << dendl;
    return;
  }
}

// namespace
int RGWGetBucketNamespace::verify_permission()
{
  return verify_bucket_owner_or_policy(s, rgw::IAM::s3GetBucketNamespace);
}

void RGWGetBucketNamespace::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

void RGWGetBucketNamespace::execute()
{
  if (s->bucket_info.namespace_type != BUCKET_NAMESPACE_ENABLE) {
    op_ret = -ERR_NO_BUCKET_NAMESPACE;
  }
}

int RGWSetBucketNamespace::verify_permission()
{
  return verify_bucket_owner_or_policy(s, rgw::IAM::s3PutBucketNamespace);
}

void RGWSetBucketNamespace::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

void RGWSetBucketNamespace::execute()
{
  if (s->cct->_conf->rgw_bucket_namespace_disable_force) {
    op_ret = -ERR_INVALID_REQUEST;
    return;
  }

  // don't allow to enable bucket namespace when versioning is enable
  if ((s->bucket_info.versioning_status() & (BUCKET_VERSIONED | BUCKET_VERSIONS_SUSPENDED))) {
    op_ret = -ERROR_BUCKET_NAMESPACE_SET_NOT_ALLOWED;
    return;
  }

  if (!store->is_meta_master()) {
    op_ret = forward_request_to_master(s, NULL, store, in_data, nullptr);
    if (op_ret < 0) {
      ldout(s->cct, 0) << __func__ << " ERROR: forward_request_to_master returned ret="
                       << op_ret << dendl;
      return;
    }
  }

  op_ret = retry_raced_bucket_write(store, s, [this] {
      op_ret = store->check_bucket_empty(s->bucket_info);
      if (op_ret < 0) {
        return op_ret;
      }

      s->bucket_info.namespace_type = BUCKET_NAMESPACE_ENABLE;
      op_ret = store->put_bucket_instance_info(s->bucket_info, false, real_time(),
                                               &s->bucket_attrs);
      return op_ret;
    });

  if (op_ret < 0) {
    ldout(s->cct, 0) << "NOTICE: put_bucket_info on bucket=" << s->bucket.name
                     << " returned err=" << op_ret << dendl;
    return;
  }
}

int RGWDeleteBucketNamespace::verify_permission()
{
  return verify_bucket_owner_or_policy(s, rgw::IAM::s3DeleteBucketNamespace);
}

void RGWDeleteBucketNamespace::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

void RGWDeleteBucketNamespace::execute()
{
  // namespace is disable
  if (s->bucket_info.namespace_type == BUCKET_NAMESPACE_DISABLE) {
    return;
  }

  // try to delete the namespace root of bucket
  op_ret = store->bucket_namespace_delete_root(s->bucket_info);
  if (op_ret < 0 && op_ret != -ENOENT) {
    ldout(s->cct, 0) << "ERROR: failed delete namespace root of bucket=" << s->bucket.name
                     << " returned err=" << op_ret << dendl;
    return;
  }

  s->bucket_info.namespace_type = BUCKET_NAMESPACE_DISABLE;
  op_ret = store->put_bucket_instance_info(s->bucket_info, false, real_time(), &s->bucket_attrs);
  if (op_ret < 0) {
    ldout(s->cct, 0) << "NOTICE: put_bucket_info on bucket=" << s->bucket.name
                     << " returned err=" << op_ret << dendl;
    return;
  }
}

int RGWPutImageStyle::verify_permission()
{
  return verify_bucket_owner_or_policy(s, rgw::IAM::s3PutImageStyle);
}

void RGWPutImageStyle::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

void RGWPutImageStyle::execute()
{
  if (!store->is_meta_master()) {
    op_ret = forward_request_to_master(s, NULL, store, in_data, nullptr);
    if (op_ret < 0) {
      ldout(s->cct, 0) << __func__ << " ERROR: forward_request_to_master returned ret="
                       << op_ret << dendl;
      return;
    }
  }

  string style_name = s->info.args.get("style");
  if (style_name.empty()) {
    ldout(s->cct, 10) << "ERROR: style_name empty" << dendl;
    op_ret = -EINVAL;
    return;
  }
  std::regex regex_name("[A-Za-z0-9_]+");
  if (!std::regex_match(style_name, regex_name) ||
      boost::algorithm::starts_with(style_name, "_") ||
      boost::algorithm::ends_with(style_name, "_") ||
      style_name.length() > 64) {
    ldout(s->cct, 10) << "ERROR: invalid style_name:" << style_name << dendl;
    op_ret = -EINVAL;
    return;
  }

  op_ret = get_params();
  if (op_ret < 0)
    return;

  ldout(s->cct, 15) << __func__<< "() read len=" << in_data.length() 
                    << " data=" << in_data.c_str() << dendl;
  JSONParser parser;
  string cmd;
  if (!parser.parse(in_data.c_str(), in_data.length())) {
    op_ret = -ERR_MALFORMED_JSON;
    return;
  }

  if (in_data.length() != s->content_length) {
    op_ret = -ERR_REQUEST_TIMEOUT;
    return;
  }

  JSONDecoder::decode_json("commands", cmd, &parser);

  std::vector<std::string> cmds;
  vector<std::shared_ptr<ImageBase>> timg_cmds;
  boost::split(cmds, cmd, boost::is_any_of("/"));
  ImageProcess image_process(s, store, nullptr);
  int r = image_process.parse_commands(cmds, 0, timg_cmds);
  if (r < 0) {
    ldout(s->cct, 0) << __func__ << "() parse_commands err:" << r
                     << ", style command:" << cmd
                     << dendl;
    op_ret = -EINVAL;
    return;
  }

  RGWImageStyle image_style(style_name, cmd);

  bufferlist style_bl;
  image_style.encode(style_bl);

  op_ret = retry_raced_bucket_write(store, s, [&] {
    std::map<std::string, bufferlist> styles_bl;

    auto iter = s->bucket_attrs.find(RGW_ATTR_IMAGE_STYLE);
    if (iter != s->bucket_attrs.end()) {
      bufferlist::iterator bliter = iter->second.begin();
      try {
        decode(styles_bl, bliter);
      } catch (buffer::error& err) {
        ldout(s->cct, 0) << "ERROR: failed to decode image styles, bucket:"
                         << s->bucket.name
                         << dendl;
        op_ret = -EIO;
        return op_ret;
      }
    }
    styles_bl[style_name] = style_bl;
    bufferlist style_attr_bl;

    encode(styles_bl, style_attr_bl);
    s->bucket_attrs[RGW_ATTR_IMAGE_STYLE] = style_attr_bl;

    op_ret = store->put_bucket_instance_info(s->bucket_info, false, real_time(),
                                             &s->bucket_attrs);
    return op_ret;
  });

  if (op_ret < 0) {
    ldout(s->cct, 0) << "NOTICE: put_bucket_info on bucket=" << s->bucket.name
                     << " returned err=" << op_ret << dendl;
    return;
  }
}

int RGWDeleteImageStyle::verify_permission()
{
  return verify_bucket_owner_or_policy(s, rgw::IAM::s3PutImageStyle);
}

void RGWDeleteImageStyle::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

void RGWDeleteImageStyle::execute()
{
  if (!store->is_meta_master()) {
    bufferlist data;
    op_ret = forward_request_to_master(s, NULL, store, data, nullptr);
    if (op_ret < 0) {
      ldout(s->cct, 0) << __func__ << " ERROR: forward_request_to_master returned ret="
                       << op_ret << dendl;
      return;
    }
  }

  string style_name = s->info.args.get("style");
  if (style_name.empty()) {
    ldout(s->cct, 0) << "ERROR: style_name empty" << dendl;
    op_ret = -EINVAL;
    return;
  }

  op_ret = retry_raced_bucket_write(store, s, [&] {
    std::map<std::string, bufferlist> styles_bl;

    auto attr_iter = s->bucket_attrs.find(RGW_ATTR_IMAGE_STYLE);
    if (attr_iter != s->bucket_attrs.end()) {
      bufferlist::iterator bliter = attr_iter->second.begin();
      try {
        decode(styles_bl, bliter);
      } catch (buffer::error& err) {
        ldout(s->cct, 0) << "ERROR: failed to decode image styles, bucket:"
                         << s->bucket.name
                         << dendl;
        op_ret = -EIO;
        return op_ret;
      }
    }
    auto style_iter = styles_bl.find(style_name);
    if (style_iter != styles_bl.end()) {
      styles_bl.erase(style_iter);
    }
    bufferlist style_attr_bl;

    encode(styles_bl, style_attr_bl);
    s->bucket_attrs[RGW_ATTR_IMAGE_STYLE] = style_attr_bl;

    op_ret = store->put_bucket_instance_info(s->bucket_info, false, real_time(),
                                             &s->bucket_attrs);
    return op_ret;
  });

  if (op_ret < 0) {
    ldout(s->cct, 0) << "NOTICE: put_bucket_info on bucket=" << s->bucket.name
                     << " returned err=" << op_ret << dendl;
    return;
  }
}

int RGWGetImageStyle::verify_permission() {
  return verify_bucket_owner_or_policy(s, rgw::IAM::s3GetImageStyle);
}

void RGWGetImageStyle::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

void RGWGetImageStyle::execute() {
  string style_name = s->info.args.get("style");
  if (style_name.empty()) {
    ldout(s->cct, 0) << "ERROR: style_name empty" << dendl;
    op_ret = -EINVAL;
    return;
  }


  std::map<std::string, bufferlist> styles_bl;

  auto attr_iter = s->bucket_attrs.find(RGW_ATTR_IMAGE_STYLE);
  if (attr_iter != s->bucket_attrs.end()) {
    bufferlist::iterator bliter = attr_iter->second.begin();
    try {
      decode(styles_bl, bliter);
    } catch (buffer::error& err) {
      ldout(s->cct, 0) << "ERROR: failed to decode image styles, bucket:"
                       << s->bucket.name
                       << dendl;
      op_ret = -EIO;
      return;
    }
  }
  auto style_iter = styles_bl.find(style_name);
  if (style_iter != styles_bl.end()) {
    auto bliter = style_iter->second.begin();
    try {
      decode(style, bliter);
    } catch (buffer::error& err) {
      ldout(s->cct, 0) << "ERROR: failed to decode image style, bucket:"
                       << s->bucket.name << ", style:" << style_iter->first
                       << dendl;
      op_ret = -EIO;
      return;
    }
  } else {
    op_ret = -ERR_NO_SUCH_IMAGE_STYLE;
  }
  return;
}

int RGWListImageStyle::verify_permission() {
  return verify_bucket_owner_or_policy(s, rgw::IAM::s3GetImageStyle);
}

void RGWListImageStyle::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

void RGWListImageStyle::execute() {
  std::map<std::string, bufferlist> styles_bl;
  auto attr_iter = s->bucket_attrs.find(RGW_ATTR_IMAGE_STYLE);
  if (attr_iter != s->bucket_attrs.end()) {
    bufferlist::iterator bliter = attr_iter->second.begin();
    try {
      decode(styles_bl, bliter);
    } catch (buffer::error& err) {
      ldout(s->cct, 0) << "ERROR: failed to decode image styles, bucket:"
                       << s->bucket.name
                       << dendl;
      op_ret = -EIO;
      return;
    }
    for (auto iter = styles_bl.begin(); iter != styles_bl.end(); iter++) {
      RGWImageStyle style;
      bliter = iter->second.begin();
      try {
        decode(style, bliter);
      } catch (buffer::error& err) {
        ldout(s->cct, 0) << "ERROR: failed to decode image style, bucket:"
                         << s->bucket.name << ", style:" << iter->first
                         << dendl;
        op_ret = -EIO;
        return;
      }
      styles.push_back(style);
    }
  }
  return;
}

int RGWPutImageProtection::verify_permission()
{
  return verify_bucket_owner_or_policy(s, rgw::IAM::s3PutImageProtection);
}

void RGWPutImageProtection::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

void RGWPutImageProtection::execute()
{
  if (!store->is_meta_master()) {
    op_ret = forward_request_to_master(s, NULL, store, in_data, nullptr);
    if (op_ret < 0) {
      ldout(s->cct, 0) << __func__ << " ERROR: forward_request_to_master returned ret="
                       << op_ret << dendl;
      return;
    }
  }

  op_ret = get_params();
  if (op_ret < 0)
    return;

  ldout(s->cct, 15) << __func__ << "() read len=" << in_data.length()
                    << " data=" << in_data.c_str() << dendl;
  JSONParser parser;
  vector<string> resources;
  if (!parser.parse(in_data.c_str(), in_data.length())) {
    ldout(s->cct, 15) << __func__ << "() parse body err" << dendl;
    op_ret = -ERR_MALFORMED_JSON;
    return;
  }

  if (in_data.length() != s->content_length) {
    op_ret = -ERR_REQUEST_TIMEOUT;
    return;
  }

  JSONDecoder::decode_json("resource", resources, &parser);
  if (resources.size() == 0) {
    ldout(s->cct, 15) << __func__ << "() resource is empty" << dendl;
    op_ret = -ERR_MALFORMED_JSON;
    return;
  }
  for (uint32_t i = 0; i < resources.size(); i++) {
    auto pos = resources[i].find('/');
    if (pos == string::npos || pos == resources[i].length() - 1) {
      ldout(s->cct, 15) << __func__ << "() resource is not legal:" << resources[i] << dendl;
      op_ret = -ERR_MALFORMED_JSON;
      return;
    }
    if (s->bucket.name.compare(resources[i].substr(0, pos)) != 0) {
      ldout(s->cct, 15) << __func__ << "() bucket name not equal to resource:" << resources[i] << dendl;
      op_ret = -ERR_MALFORMED_JSON;
      return;
    }
    resources[i] = resources[i].substr(pos + 1);
    // only support prefix or suffix
    if (!boost::algorithm::starts_with(resources[i], "*") &&
        !boost::algorithm::ends_with(resources[i], "*")) {
      ldout(s->cct, 15) << __func__ << "() no * in resource:" << resources[i] << dendl;
      op_ret = -ERR_MALFORMED_JSON;
      return;
    }
    if (std::count(resources[i].begin(), resources[i].end(), '*') > 1) {
      ldout(s->cct, 15) << __func__ << "() multi * in resource:" << resources[i] << dendl;
      op_ret = -ERR_MALFORMED_JSON;
      return;
    }
  }

  bufferlist protection_bl;
  encode(resources, protection_bl);

  op_ret = retry_raced_bucket_write(store, s, [&] {
    s->bucket_attrs[RGW_ATTR_IMAGE_PROTECTION] = protection_bl;

    op_ret = store->put_bucket_instance_info(s->bucket_info, false, real_time(),
                                             &s->bucket_attrs);
    return op_ret;
  });

  if (op_ret < 0) {
    ldout(s->cct, 0) << "NOTICE: put_bucket_info on bucket=" << s->bucket.name
                     << " returned err=" << op_ret << dendl;
    return;
  }
}

int RGWGetImageProtection::verify_permission()
{
  return verify_bucket_owner_or_policy(s, rgw::IAM::s3GetImageProtection);
}

void RGWGetImageProtection::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

void RGWGetImageProtection::execute()
{
  auto attr_iter = s->bucket_attrs.find(RGW_ATTR_IMAGE_PROTECTION);
  if (attr_iter != s->bucket_attrs.end()) {
    bufferlist::iterator bliter = attr_iter->second.begin();
    try {
      decode(resources, bliter);
    } catch (buffer::error& err) {
      ldout(s->cct, 0) << "ERROR: failed to decode image protection config, bucket:" << s->bucket.name << dendl;
      op_ret = -EIO;
      return;
    }
  } else {
    ldout(s->cct, 10) << "ERROR: cann't find image protection config, bucket:" << s->bucket.name << dendl;
    op_ret = -ERR_NO_IMAGE_PROTECTION;
    return;
  }
}

int RGWDeleteImageProtection::verify_permission()
{
  return verify_bucket_owner_or_policy(s, rgw::IAM::s3PutImageProtection);
}

void RGWDeleteImageProtection::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

void RGWDeleteImageProtection::execute()
{
  if (!store->is_meta_master()) {
    bufferlist data;
    op_ret = forward_request_to_master(s, NULL, store, data, nullptr);
    if (op_ret < 0) {
      ldout(s->cct, 0) << __func__ << " ERROR: forward_request_to_master returned ret="
                       << op_ret << dendl;
      return;
    }
  }

  op_ret = retry_raced_bucket_write(store, s, [&] {
    map<string, bufferlist>::iterator aiter = s->bucket_attrs.find(RGW_ATTR_IMAGE_PROTECTION);
    if (aiter != s->bucket_attrs.end()) {
      s->bucket_attrs.erase(RGW_ATTR_IMAGE_PROTECTION);
      op_ret = rgw_bucket_set_attrs(store, s->bucket_info, s->bucket_attrs,
                                    &s->bucket_info.objv_tracker);
    }
    return op_ret;
  });

  if (op_ret < 0) {
    ldout(s->cct, 0) << "NOTICE: put_bucket_info on bucket=" << s->bucket.name
                     << " returned err=" << op_ret << dendl;
    return;
  }
}

int RGWStatBucket::verify_permission()
{
  if (s->cct->_conf->rgw_abcstore_multi_region) {
    return 0;
  }
#ifdef WITH_BCEBOS
  if (s->prot_flags & RGW_REST_BOS) {
    if (verify_bucket_owner_or_policy(s, rgw::IAM::s3HeadBucket) != 0) {
      return -EACCES;
    }
  } else
#endif
  {
    // This (a HEAD request on a bucket) is governed by the s3:ListBucket permission.
    if (!verify_bucket_permission(s, rgw::IAM::s3ListBucket)) {
      return -EACCES;
    }
  }

  return 0;
}

void RGWStatBucket::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

void RGWStatBucket::execute()
{
  if (s->cct->_conf->rgw_abcstore_multi_region) {
    auto bucket_info = database::DBClient::instance().query_bucket_info(s, s->bucket_name);
    if (!bucket_info) {
      ldout(s->cct, 0) << __func__ << "query bucket region from database failed. bucket: " << s->bucket_name << dendl;
      op_ret = -ERR_NO_SUCH_BUCKET;
    }
    return;
  }

  if (!s->bucket_exists) {
    op_ret = -ERR_NO_SUCH_BUCKET;
    return;
  }

  RGWUserBuckets buckets;
  bucket.bucket = s->bucket;
  buckets.add(bucket);
  map<string, RGWBucketEnt>& m = buckets.get_buckets();
  op_ret = store->update_containers_stats(m);
  if (! op_ret)
    op_ret = -EEXIST;
  if (op_ret > 0) {
    op_ret = 0;
    map<string, RGWBucketEnt>::iterator iter = m.find(bucket.bucket.name);
    if (iter != m.end()) {
      bucket = iter->second;
    } else {
      op_ret = -EINVAL;
    }
  }
}

int RGWListBucket::verify_permission()
{
  op_ret = get_params();
  if (op_ret < 0) {
    return op_ret;
  }
  if (!prefix.empty())
    s->env.emplace("s3:prefix", prefix);

  if (!delimiter.empty())
    s->env.emplace("s3:delimiter", delimiter);

  s->env.emplace("s3:max-keys", std::to_string(max));

  if (prefix.empty() && is_anonymous(s) && !s->bucket_info.website_conf.is_empty() && is_browser_client(s)) {
    website_retarget = true;
    return op_ret;
  }

  auto perm = rgw::IAM::s3ListBucket;
#ifdef WITH_BCEBOS
  if (s->prot_flags & RGW_REST_BOS) {
    perm = rgw::IAM::s3ListObjects;
  }
#endif

  if (!verify_bucket_permission(s,
                                list_versions ?
                                rgw::IAM::s3ListBucketVersions :
                                perm)) {
    return -EACCES;
  }

  return 0;
}

int RGWListBucket::parse_max_keys()
{
  // Bound max value of max-keys to configured value for security
  // Bound min value of max-keys to '0'
  // Some S3 clients explicitly send max-keys=0 to detect if the bucket is
  // empty without listing any items.
  return parse_value_and_bound(max_keys, max, 0,
			s->cct->_conf->get_val<uint64_t>("rgw_max_listing_results"),
			default_max);
}

void RGWListBucket::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

void RGWListBucket::execute()
{
  if (!s->bucket_exists) {
    op_ret = -ERR_NO_SUCH_BUCKET;
    return;
  }

  if (website_retarget) {
    return;
  }

  if (allow_unordered && !delimiter.empty()) {
    ldout(s->cct, 0) <<
      "ERROR: unordered bucket listing requested with a delimiter" << dendl;
    op_ret = -EINVAL;
    return;
  } else if (delimiter.size() > 1) {
    ldout(s->cct, 5) << __func__ << " bad delimiter '" << delimiter << "', size greater than 1" << dendl;
    op_ret = -EINVAL;
    return;
  }

  if (need_container_stats()) {
    map<string, RGWBucketEnt> m;
    m[s->bucket.name] = RGWBucketEnt();
    m.begin()->second.bucket = s->bucket;
    op_ret = store->update_containers_stats(m);
    if (op_ret > 0) {
      bucket = m.begin()->second;
    }
  }

  RGWRados::Bucket target(store, s->bucket_info);

  // namespace : while delimiter is "/"
  if (s->bucket_info.namespace_type == BUCKET_NAMESPACE_ENABLE &&
      delimiter == S3_PATH_DELIMITER &&
      !s->cct->_conf->rgw_bucket_namespace_disable_force) {
    is_bucket_namespace_list = true;
    RGWRados::Bucket::Namespace::list_dir(s, &target, prefix, marker.name, end_marker.name, max,
        &objs, &common_prefixes, &is_truncated, &next_marker);
  } else {
    if (shard_id >= 0) {
      target.set_shard_id(shard_id);
    }
    RGWRados::Bucket::List list_op(&target);

    list_op.params.prefix = prefix;
    list_op.params.delim = delimiter;
    list_op.params.marker = marker;
    list_op.params.end_marker = end_marker;
    list_op.params.list_versions = list_versions;
    list_op.params.allow_unordered = allow_unordered;

    op_ret = list_op.list_objects(max, &objs, &common_prefixes, &is_truncated);
    if (op_ret >= 0) {
      next_marker = list_op.get_next_marker();
    }
  }
}

int RGWGetBucketStorageClass::verify_permission()
{
  if (!verify_bucket_permission(s, rgw::IAM::s3GetBucketStorageClass)) {
    return -EACCES;
  }
  return 0;
}

void RGWGetBucketStorageClass::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

int RGWPutBucketStorageClass::verify_permission()
{
  if (!verify_bucket_permission(s, rgw::IAM::s3PutBucketStorageClass)) {
    return -EACCES;
  }
  return 0;
}

void RGWPutBucketStorageClass::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

void RGWPutBucketStorageClass::execute()
{
  op_ret = get_params();
  if (op_ret < 0) {
    return;
  }
  rgw_placement_rule verify_placement(s->bucket_info.head_placement_rule.name,
                                      rgw_placement_rule::get_canonical_storage_class(s->bucket_info.storage_class));

  if (!store->get_zone_params().valid_placement(verify_placement)) {
    ldout(s->cct, 5) << "NOTICE: invalid placement: " << s->dest_placement.to_str()
                     << " put storage class is " << s->bucket_info.storage_class << " but don't have this storage class." <<dendl;
    op_ret =  -ERR_INVALID_STORAGE_CLASS;
    return;
  }

  op_ret = retry_raced_bucket_write(store, s, [this] {
    op_ret = store->put_bucket_instance_info(s->bucket_info, false, real_time(), &s->bucket_attrs);
    if (op_ret < 0) {
      ldout(s->cct, 20) << __func__ << "() ERRPR: put_bucket_info on bucket=" << s->bucket.name
                        << " returned err=" << op_ret << dendl;
    }
    return op_ret;
  });
}

int RGWGetBucketLogging::verify_permission()
{
  if (!verify_bucket_permission(s, rgw::IAM::s3GetBucketLogging)) {
    return -EACCES;
  }
  return 0;
}

void RGWGetBucketLogging::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

int RGWPutBucketLogging::verify_permission()
{
  if (!verify_bucket_permission(s, rgw::IAM::s3PutBucketLogging)) {
    return -EACCES;
  }
  return 0;
}

void RGWPutBucketLogging::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

void RGWPutBucketLogging::execute()
{
  op_ret = get_params();
  if (op_ret < 0) {
    return;
  }

  RGWObjectCtx obj_ctx(store);
  RGWBucketInfo target_bucket_info;
  map<string, bufferlist> target_bucket_attrs;

  int r = store->get_bucket_info(obj_ctx, s->user->user_id.tenant,
                                 target_bucket, target_bucket_info,
                                 nullptr, &target_bucket_attrs);
  if (r < 0) {
    ldout(s->cct, 10) << "RGWPutBucketLogging::execute: target bucket not exits." << dendl;
    op_ret = -ERR_MALFORMED_JSON;
    return;
  }

  if (target_bucket_info.owner.id != s->bucket_info.owner.id) {
    op_ret = -EACCES;
    return;
  }

  bufferlist buffer_logging;
  map<string, bufferlist> source_bucket_attrs = s->bucket_attrs;
  pair<string, string> logging_conf(target_bucket, target_prefix);
  encode(logging_conf, buffer_logging);
  source_bucket_attrs[RGW_ATTR_LOGGING] = buffer_logging;
  op_ret = rgw_bucket_set_attrs(store, s->bucket_info, source_bucket_attrs, &s->bucket_info.objv_tracker);
}

int RGWDeleteBucketLogging::verify_permission()
{
  if (!verify_bucket_permission(s, rgw::IAM::s3DeleteBucketLogging)) {
    return -EACCES;
  }
  return 0;
}

void RGWDeleteBucketLogging::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

void RGWDeleteBucketLogging::execute()
{
  map<string, bufferlist> attrs = s->bucket_attrs;
  map<string, bufferlist>::iterator aiter = attrs.find(RGW_ATTR_LOGGING);
  if (aiter != attrs.end()) {
    attrs.erase(RGW_ATTR_LOGGING);
    op_ret = rgw_bucket_set_attrs(store, s->bucket_info, attrs, &s->bucket_info.objv_tracker);
  }
}

int RGWGetBucketEncryption::verify_permission()
{
  if (!verify_bucket_permission(s, rgw::IAM::s3GetBucketEncryption)) {
    return -EACCES;
  }
  return 0;
}

void RGWGetBucketEncryption::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

int RGWPutBucketEncryption::verify_permission()
{
  if (!verify_bucket_permission(s, rgw::IAM::s3PutBucketEncryption)) {
    return -EACCES;
  }
  return 0;
}

void RGWPutBucketEncryption::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

void RGWPutBucketEncryption::execute()
{
  op_ret = get_params();
  if (op_ret < 0) {
    return;
  }

  //now just support AES256 and SM4
  if (encryption_algorithm != "AES256" && encryption_algorithm != "SM4") {
    ldout(s->cct, 10) << __func__ << "(): unknow encryption algorithm: " << encryption_algorithm << dendl;
    op_ret = -ERR_INVALID_ENCRYPTION_ALGORITHM;
    return;
  }

  //kms master key id like xxxxxxxx-xxxx-xxxx-xxxxxxxxxxxxxxxx
  if (!kms_master_key_id.empty() && kms_master_key_id.size() != 36) {
    ldout(s->cct, 10) << __func__ << "(): kms master key size must 32 bytes." << dendl;
     op_ret = -ERR_INVALID_ENCRY_KMS_MK_ID;
     return;
  }

  s->bucket_info.kms_master_key_id = kms_master_key_id;
  s->bucket_info.encryption_algorithm = encryption_algorithm;

  op_ret = store->put_bucket_instance_info(s->bucket_info, false, real_time(), &s->bucket_attrs);
  if (op_ret < 0) {
    ldout(s->cct, 0) << __func__ << "(): NOTICE: put_bucket_info on bucket="
                     << s->bucket.name << " returned err=" << op_ret << dendl;
    return;
  }
}

int RGWDeleteBucketEncryption::verify_permission()
{
  if (!verify_bucket_permission(s, rgw::IAM::s3DeleteBucketEncryption)) {
    return -EACCES;
  }
  return 0;
}

void RGWDeleteBucketEncryption::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

void RGWDeleteBucketEncryption::execute()
{
  if (s->bucket_info.encryption_algorithm.empty()) {
    op_ret = -ERR_NO_SUCH_ENCRYPTION;
    ldout(s->cct, 0) << __func__ << "(): ERROR no such bucket encryption." << dendl;
    return;
  }
  s->bucket_info.encryption_algorithm.clear();

  op_ret = store->put_bucket_instance_info(s->bucket_info, false, real_time(), &s->bucket_attrs);
  if (op_ret < 0) {
    ldout(s->cct, 0) << __func__ << "(): NOTICE: put_bucket_info on bucket="
                     << s->bucket.name << " returned err=" << op_ret << dendl;
    return;
  }
}

void RGWGetBucketLocation::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

int RGWGetBucketLocation::verify_permission()
{
  if (s->cct->_conf->rgw_abcstore_multi_region) {
    return 0;
  }
#ifdef WITH_BCEBOS
  if (s->prot_flags & RGW_REST_BOS) {
    if (!verify_bucket_permission(s, rgw::IAM::s3GetBucketLocation)) {
      return -EACCES;
    }
  } else
#endif
  {
    return verify_bucket_owner_or_policy(s, rgw::IAM::s3GetBucketLocation);
  }
  return 0;
}

void RGWGetBucketLocation::execute()
{
  if (!s->cct->_conf->rgw_abcstore_multi_region) {
    region = s->cct->_conf->rgw_default_location;
    if (region.empty()) {
      RGWZoneGroup zonegroup;
      int ret = store->get_zonegroup(s->bucket_info.zonegroup, zonegroup);
      if (ret >= 0) {
        region = zonegroup.api_name;
      } else {
        if (s->bucket_info.zonegroup != "default") {
          region = s->bucket_info.zonegroup;
        }
      }
    }
    return;
  }

  auto bucket_info = database::DBClient::instance().query_bucket_info(s, s->bucket_name);
  if (!bucket_info) {
    ldout(s->cct, 0) << __func__ << "query bucket region from database failed. bucket: " << s->bucket_name << dendl;
    op_ret = -ERR_NO_SUCH_BUCKET;
    return;
  }
  region = bucket_info->region;

}

int RGWCreateBucket::verify_permission()
{
  /* This check is mostly needed for S3 that doesn't support account ACL.
   * Swift doesn't allow to delegate any permission to an anonymous user,
   * so it will become an early exit in such case. */
  if (s->auth.identity->is_anonymous()) {
    return -EACCES;
  }

  if (!verify_user_permission(s, RGW_PERM_WRITE)) {
    return -EACCES;
  }

  if (s->user->user_id.tenant != s->bucket_tenant) {
    ldout(s->cct, 10) << "user cannot create a bucket in a different tenant"
                      << " (user_id.tenant=" << s->user->user_id.tenant
                      << " requested=" << s->bucket_tenant << ")"
                      << dendl;
    return -EACCES;
  }
  if (s->user->max_buckets < 0) {
    return -EPERM;
  }

#ifdef WITH_BCEBOS
  if (s->user->max_buckets == 0) {
    return -ERR_TOO_MANY_BUCKETS;
  }
#endif

  if (s->user->max_buckets) {
    int buckets_count = 0;
    if (s->cct->_conf->rgw_abcstore_multi_region) {
      op_ret = database::DBClient::instance().get_bucket_count_by_user(s, s->user->user_id.id, buckets_count);
      if (op_ret < 0) {
        return op_ret;
      }
    } else {
      RGWUserBuckets buckets;
      string marker;
      bool is_truncated = false;
      op_ret = rgw_read_user_buckets(store, s->user->user_id, buckets,
                                     marker, string(), s->user->max_buckets,
                                     false, &is_truncated);
      if (op_ret < 0) {
        return op_ret;
      }
      buckets_count = buckets.count();
    }
    if (buckets_count >= s->user->max_buckets) {
      return -ERR_TOO_MANY_BUCKETS;
    }
  }

  return 0;
}

static int forward_request_to_master(struct req_state *s, obj_version *objv,
				    RGWRados *store, bufferlist& in_data,
				    JSONParser *jp, req_info *forward_info)
{
  if (!store->rest_master_conn) {
    ldout(s->cct, 0) << "rest connection is invalid" << dendl;
    return -EINVAL;
  }
  ldout(s->cct, 0) << "sending request to master zonegroup" << dendl;
  bufferlist response;
  string uid_str = s->user->user_id.to_str();
#define MAX_REST_RESPONSE (128 * 1024) // we expect a very small response
  int ret = store->rest_master_conn->forward(uid_str, (forward_info ? *forward_info : s->info),
                                             objv, MAX_REST_RESPONSE, &in_data, &response);
  if (ret < 0)
    return ret;

  ldout(s->cct, 20) << "response: " << response.c_str() << dendl;
  if (jp && !jp->parse(response.c_str(), response.length())) {
    ldout(s->cct, 0) << "failed parsing response from master zonegroup" << dendl;
    return -EINVAL;
  }

  return 0;
}

void RGWCreateBucket::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

static void prepare_add_del_attrs(const map<string, bufferlist>& orig_attrs,
                                  map<string, bufferlist>& out_attrs,
                                  map<string, bufferlist>& out_rmattrs)
{
  for (const auto& kv : orig_attrs) {
    const string& name = kv.first;

    /* Check if the attr is user-defined metadata item. */
    if (name.compare(0, sizeof(RGW_ATTR_META_PREFIX) - 1,
                     RGW_ATTR_META_PREFIX) == 0) {
      /* For the objects all existing meta attrs have to be removed. */
      out_rmattrs[name] = kv.second;
    } else if (out_attrs.find(name) == std::end(out_attrs)) {
      out_attrs[name] = kv.second;
    }
  }
}

/* Fuse resource metadata basing on original attributes in @orig_attrs, set
 * of _custom_ attribute names to remove in @rmattr_names and attributes in
 * @out_attrs. Place results in @out_attrs.
 *
 * NOTE: it's supposed that all special attrs already present in @out_attrs
 * will be preserved without any change. Special attributes are those which
 * names start with RGW_ATTR_META_PREFIX. They're complement to custom ones
 * used for X-Account-Meta-*, X-Container-Meta-*, X-Amz-Meta and so on.  */
static void prepare_add_del_attrs(const map<string, bufferlist>& orig_attrs,
                                  const set<string>& rmattr_names,
                                  map<string, bufferlist>& out_attrs)
{
  for (const auto& kv : orig_attrs) {
    const string& name = kv.first;

    /* Check if the attr is user-defined metadata item. */
    if (name.compare(0, strlen(RGW_ATTR_META_PREFIX),
                     RGW_ATTR_META_PREFIX) == 0) {
      /* For the buckets all existing meta attrs are preserved,
         except those that are listed in rmattr_names. */
      if (rmattr_names.find(name) != std::end(rmattr_names)) {
        const auto aiter = out_attrs.find(name);

        if (aiter != std::end(out_attrs)) {
          out_attrs.erase(aiter);
        }
      } else {
        /* emplace() won't alter the map if the key is already present.
         * This behaviour is fully intensional here. */
        out_attrs.emplace(kv);
      }
    } else if (out_attrs.find(name) == std::end(out_attrs)) {
      out_attrs[name] = kv.second;
    }
  }
}


static void populate_with_generic_attrs(const req_state * const s,
                                        map<string, bufferlist>& out_attrs)
{
  for (const auto& kv : s->generic_attrs) {
    bufferlist& attrbl = out_attrs[kv.first];
    const string& val = kv.second;
    attrbl.clear();
    attrbl.append(val.c_str(), val.size() + 1);
  }
}


static int filter_out_quota_info(std::map<std::string, bufferlist>& add_attrs,
                                 const std::set<std::string>& rmattr_names,
                                 RGWQuotaInfo& quota,
                                 bool * quota_extracted = nullptr)
{
  bool extracted = false;

  /* Put new limit on max objects. */
  auto iter = add_attrs.find(RGW_ATTR_QUOTA_NOBJS);
  std::string err;
  if (std::end(add_attrs) != iter) {
    quota.max_objects =
      static_cast<int64_t>(strict_strtoll(iter->second.c_str(), 10, &err));
    if (!err.empty()) {
      return -EINVAL;
    }
    add_attrs.erase(iter);
    extracted = true;
  }

  /* Put new limit on bucket (container) size. */
  iter = add_attrs.find(RGW_ATTR_QUOTA_MSIZE);
  if (iter != add_attrs.end()) {
    quota.max_size =
      static_cast<int64_t>(strict_strtoll(iter->second.c_str(), 10, &err));
    if (!err.empty()) {
      return -EINVAL;
    }
    add_attrs.erase(iter);
    extracted = true;
  }

  for (const auto& name : rmattr_names) {
    /* Remove limit on max objects. */
    if (name.compare(RGW_ATTR_QUOTA_NOBJS) == 0) {
      quota.max_objects = -1;
      extracted = true;
    }

    /* Remove limit on max bucket size. */
    if (name.compare(RGW_ATTR_QUOTA_MSIZE) == 0) {
      quota.max_size = -1;
      extracted = true;
    }
  }

  /* Swift requries checking on raw usage instead of the 4 KiB rounded one. */
  quota.check_on_raw = true;
  quota.enabled = quota.max_size > 0 || quota.max_objects > 0;

  if (quota_extracted) {
    *quota_extracted = extracted;
  }

  return 0;
}


static void filter_out_website(std::map<std::string, ceph::bufferlist>& add_attrs,
                               const std::set<std::string>& rmattr_names,
                               RGWBucketWebsiteConf& ws_conf)
{
  std::string lstval;

  /* Let's define a mapping between each custom attribute and the memory where
   * attribute's value should be stored. The memory location is expressed by
   * a non-const reference. */
  const auto mapping  = {
    std::make_pair(RGW_ATTR_WEB_INDEX,     std::ref(ws_conf.index_doc_suffix)),
    std::make_pair(RGW_ATTR_WEB_ERROR,     std::ref(ws_conf.error_doc)),
    std::make_pair(RGW_ATTR_WEB_LISTINGS,  std::ref(lstval)),
    std::make_pair(RGW_ATTR_WEB_LIST_CSS,  std::ref(ws_conf.listing_css_doc)),
    std::make_pair(RGW_ATTR_SUBDIR_MARKER, std::ref(ws_conf.subdir_marker))
  };

  for (const auto& kv : mapping) {
    const char * const key = kv.first;
    auto& target = kv.second;

    auto iter = add_attrs.find(key);

    if (std::end(add_attrs) != iter) {
      /* The "target" is a reference to ws_conf. */
      target = iter->second.c_str();
      add_attrs.erase(iter);
    }

    if (rmattr_names.count(key)) {
      target = std::string();
    }
  }

  if (! lstval.empty()) {
    ws_conf.listing_enabled = boost::algorithm::iequals(lstval, "true");
  }
}
#ifdef WITH_BCEIAM
#define MAX_RETRY_BCM 3
int notify_bcm_resource(const req_state* s, bool is_create) {
  /* create the connection pool */
  void **asio_ctx = (void **) s->asio_ctx;
  std::stringstream ss;
  string key = (is_create) ? "create" : "delete";
  ss << "/notify/bcm/" << key
     <<"?bucket=" << s->bucket_name << "&uid=" << s->user->user_id;
  std::string uri = ss.str();

  string addr = s->cct->_conf->rgw_bos_monitor_address;
  string host, port;
  get_ip_port_from_url(addr, host, port);
#ifdef WITH_RADOSGW_BEAST_FRONTEND
  // only if with beast fronted, we'll try async send http request
  if (asio_ctx != NULL) {
    static ConnectionPool _monitor_async_conn_pool = ConnectionPool(
          *((boost::asio::io_service *) asio_ctx[0]), host, port, // bos_monitor endpoint
          s->cct->_conf->rgw_bos_monitor_connect_number,
          s->cct->_conf->rgw_abcstore_proxy_connect_retry, true);

    std::shared_ptr<ssl::stream<tcp::socket> > stream_ptr;

    int idx = _monitor_async_conn_pool.fetch_socket(stream_ptr, asio_ctx);
    if (idx < 0 || idx >= s->cct->_conf->rgw_bos_monitor_connect_number) {
      ldout(s->cct, 0) << "ConnectionPool fetch_socket return error idx:" << idx << dendl;
      return -ENOTSOCK;
    }

    SyncPoint sync(*((boost::asio::io_service *) asio_ctx[0]), *((boost::asio::yield_context *) asio_ctx[1]));

    auto client = std::make_shared<RgwAsyncHttpClient>(stream_ptr, uri);

    client->set_cb(&sync, asio_send_http_cb);
    // call send async http request
    int ret = 0;
    retry_send_request_by_connection_pool(s, ret, _monitor_async_conn_pool, idx, [&] {
          return client->send_request(host, "", nullptr, "post");
        });

    if (ret != 0) {
      ldout(s->cct, 0) << "ERROR: send request to abcstore_proxy error:" << ret << dendl;
      _monitor_async_conn_pool.free_socket(idx);
      return ret;
    }
    // wait for response
    ret = sync.get();

    _monitor_async_conn_pool.free_socket(idx);
  } else
#endif
  {
    static boost::asio::io_context ioc;
    static ConnectionPool _monitor_sync_conn_pool = ConnectionPool(ioc, host, port,
          s->cct->_conf->rgw_bos_monitor_connect_number,
          s->cct->_conf->rgw_abcstore_proxy_connect_retry, false);

    std::shared_ptr<ssl::stream<tcp::socket> > stream_ptr;
    int idx = _monitor_sync_conn_pool.fetch_socket(stream_ptr);
    if (idx < 0 || idx >= s->cct->_conf->rgw_bos_monitor_connect_number) {
      ldout(s->cct, 0) << "ConnectionPool fetch_socket return error idx:" << idx << dendl;
      return -1;
    }

    RgwSyncHttpClient client = RgwSyncHttpClient(stream_ptr, uri);
    int ret = 0;

    retry_send_request_by_connection_pool(s, ret, _monitor_sync_conn_pool, idx, [&] {
          return client.send_request(host, "", nullptr, "post");
        });

    if (ret != 0) {
      ldout(s->cct, 0) << "send request error:" << ret << dendl;
      _monitor_sync_conn_pool.free_socket(idx);
      return ret;
    }

    _monitor_sync_conn_pool.free_socket(idx);
  }
  return 0;
}
#endif

void RGWCreateBucket::execute()
{
  RGWAccessControlPolicy old_policy(s->cct);
  buffer::list aclbl;
  buffer::list corsbl;
  bool existed;
  string bucket_name;
#ifdef WITH_BCEBOS
  if (s->bucket_name.compare("json-api") == 0) {
    op_ret = -EINVAL;
    return;
  }
#endif
  rgw_make_bucket_entry_name(s->bucket_tenant, s->bucket_name, bucket_name);
  rgw_raw_obj obj(store->get_zone_params().domain_root, bucket_name);
  obj_version objv, *pobjv = NULL;

  op_ret = get_params();
  if (op_ret < 0)
    return;

  if (!location_constraint.empty() &&
      !store->has_zonegroup_api(location_constraint)) {
      ldout(s->cct, 0) << "location constraint (" << location_constraint << ")"
                       << " can't be found." << dendl;
      op_ret = -ERR_INVALID_LOCATION_CONSTRAINT;
      s->err.message = "The specified location-constraint is not valid";
      return;
  }

  if (!store->get_zonegroup().is_master_zonegroup() && !location_constraint.empty() &&
      store->get_zonegroup().api_name != location_constraint) {
    ldout(s->cct, 0) << "location constraint (" << location_constraint << ")"
                     << " doesn't match zonegroup" << " (" << store->get_zonegroup().api_name << ")"
                     << dendl;
    op_ret = -ERR_INVALID_LOCATION_CONSTRAINT;
    s->err.message = "The specified location-constraint is not valid";
    return;
  }

  const auto& zonegroup = store->get_zonegroup();
  if (!placement_rule.name.empty() &&
      !zonegroup.placement_targets.count(placement_rule.name)) {
    ldout(s->cct, 0) << "placement target (" << placement_rule << ")"
                     << " doesn't exist in the placement targets of zonegroup"
                     << " (" << store->get_zonegroup().api_name << ")" << dendl;
    op_ret = -ERR_INVALID_LOCATION_CONSTRAINT;
    s->err.message = "The specified placement target does not exist";
    return;
  }

  /* we need to make sure we read bucket info, it's not read before for this
   * specific request */
  RGWObjectCtx& obj_ctx = *static_cast<RGWObjectCtx *>(s->obj_ctx);
  op_ret = store->get_bucket_info(obj_ctx, s->bucket_tenant, s->bucket_name,
				  s->bucket_info, nullptr, &s->bucket_attrs);
  if (op_ret < 0 && op_ret != -ENOENT)
    return;
  s->bucket_exists = (op_ret != -ENOENT);

#ifdef WITH_BCEBOS
  if ((s->prot_flags & RGW_REST_BOS) && s->bucket_exists) {
    op_ret = -EEXIST;
    return;
  }
#endif

  s->bucket_owner.set_id(s->user->user_id);
  s->bucket_owner.set_name(s->user->display_name);
  if (s->bucket_exists) {
    int r = get_bucket_policy_from_attr(s->cct, store, s->bucket_info,
                                        s->bucket_attrs, &old_policy);
    if (r >= 0)  {
      if (old_policy.get_owner().get_id().compare(s->user->user_id) != 0) {
        op_ret = -EEXIST;
        return;
      }
    }
  }

  RGWBucketInfo master_info;
  rgw_bucket *pmaster_bucket;
  uint32_t *pmaster_num_shards;
  real_time creation_time;

  if (!store->is_meta_master()) {
    JSONParser jp;
    op_ret = forward_request_to_master(s, NULL, store, in_data, &jp);
    if (op_ret < 0) {
      return;
    }

    JSONDecoder::decode_json("entry_point_object_ver", ep_objv, &jp);
    JSONDecoder::decode_json("object_ver", objv, &jp);
    JSONDecoder::decode_json("bucket_info", master_info, &jp);
    ldout(s->cct, 20) << "parsed: objv.tag=" << objv.tag << " objv.ver=" << objv.ver << dendl;
    ldout(s->cct, 20) << "got creation time: << " << master_info.creation_time << dendl;
    pmaster_bucket= &master_info.bucket;
    creation_time = master_info.creation_time;
    pmaster_num_shards = &master_info.num_shards;
    pobjv = &objv;
    obj_lock_enabled = master_info.obj_lock_enabled();
  } else {
    pmaster_bucket = NULL;
    pmaster_num_shards = NULL;
  }

  string zonegroup_id;

  if (s->system_request) {
    zonegroup_id = s->info.args.get(RGW_SYS_PARAM_PREFIX "zonegroup");
    if (zonegroup_id.empty()) {
      zonegroup_id = store->get_zonegroup().get_id();
    }
  } else {
    zonegroup_id = store->get_zonegroup().get_id();
  }

  // BOS API: if have default storage class from x-bce-storage-class, check
  // placement_targets->storage_class have this storage class.
  string bucket_storage_class;
  if ((s->prot_flags & RGW_REST_BOS) && s->info.env->exists("HTTP_X_BCE_STORAGE_CLASS")) {
    bucket_storage_class = s->info.env->get("HTTP_X_BCE_STORAGE_CLASS");
  } else if ((s->prot_flags & RGW_REST_S3) && s->info.env->exists("HTTP_X_AMZ_STORAGE_CLASS")) {
    bucket_storage_class = s->info.env->get("HTTP_X_AMZ_STORAGE_CLASS");
  }
  if (!bucket_storage_class.empty()) {
    RGWZoneGroup verify_zg;
    rgw_placement_rule selected_placement_rule;
    store->get_zonegroup(zonegroup_id, verify_zg);
    store->select_bucket_placement(*(s->user), zonegroup_id, placement_rule, &selected_placement_rule, nullptr);
    if (verify_zg.placement_targets[selected_placement_rule.name].storage_classes.count(bucket_storage_class) == 0) {
      ldout(s->cct, 10) << __func__ << "() ERROR: bucket default storage class not exist." << dendl;
      op_ret = -ERR_INVALID_STORAGE_CLASS;
      return;
    } else {
      ldout(s->cct, 20) << __func__ << "() INFO: set defult bucket storage class." << dendl;
      info.storage_class = bucket_storage_class;
    }
  }
  if (s->bucket_exists) {
    rgw_placement_rule selected_placement_rule;
    rgw_bucket bucket;
    bucket.tenant = s->bucket_tenant;
    bucket.name = s->bucket_name;
    op_ret = store->select_bucket_placement(*(s->user), zonegroup_id,
					    placement_rule,
					    &selected_placement_rule, nullptr);
    if (selected_placement_rule != s->bucket_info.head_placement_rule) {
      op_ret = -EEXIST;
      return;
    }
  }

  /* Encode special metadata first as we're using std::map::emplace under
   * the hood. This method will add the new items only if the map doesn't
   * contain such keys yet. */
  policy.encode(aclbl);
  emplace_attr(RGW_ATTR_ACL, std::move(aclbl));

  if (has_cors) {
    cors_config.encode(corsbl);
    emplace_attr(RGW_ATTR_CORS, std::move(corsbl));
  }

  RGWQuotaInfo quota_info;
  const RGWQuotaInfo * pquota_info = nullptr;
  if (need_metadata_upload()) {
    /* It's supposed that following functions WILL NOT change any special
     * attributes (like RGW_ATTR_ACL) if they are already present in attrs. */
    op_ret = rgw_get_request_metadata(s->cct, s->info, attrs, false);
    if (op_ret < 0) {
      return;
    }
    prepare_add_del_attrs(s->bucket_attrs, rmattr_names, attrs);
    populate_with_generic_attrs(s, attrs);

    op_ret = filter_out_quota_info(attrs, rmattr_names, quota_info);
    if (op_ret < 0) {
      return;
    } else {
      pquota_info = &quota_info;
    }

    /* Web site of Swift API. */
    filter_out_website(attrs, rmattr_names, s->bucket_info.website_conf);
    s->bucket_info.has_website = !s->bucket_info.website_conf.is_empty();
  }

  s->bucket.tenant = s->bucket_tenant; /* ignored if bucket exists */
  s->bucket.name = s->bucket_name;

  /* Handle updates of the metadata for Swift's object versioning. */
  if (swift_ver_location) {
    s->bucket_info.swift_ver_location = *swift_ver_location;
    s->bucket_info.swift_versioning = (! swift_ver_location->empty());
  }

  if (obj_lock_enabled) {
    info.flags = BUCKET_VERSIONED | BUCKET_OBJ_LOCK_ENABLED;
  }
#ifdef WITH_BCEIAM
  if (s->cct->_conf->rgw_with_bcm_restrict) {
    int bcm_ret = 0;
    for (int retry = 0; retry < MAX_RETRY_BCM; retry++) {
      bcm_ret = notify_bcm_resource(s, true);
      if (bcm_ret < 0) {
        ldout(s->cct, 20) << __func__ << " notify bcm ret=" << bcm_ret << dendl;
        continue;
      }
    }
  }
#endif

  if (real_clock::is_zero(creation_time)) {
    creation_time = ceph::real_clock::now();
  }

  if (s->cct->_conf->rgw_abcstore_multi_region)  {
    database::db_bucket_info db_bucket(s->bucket_name, s->user->user_id.id,
                                       s->cct->_conf->rgw_default_location,
                                       ceph::real_clock::to_time_t(creation_time));
    op_ret = database::DBClient::instance().insert_bucket_info(s, db_bucket);
    if (op_ret < 0) {
      return;
    }
  }

  op_ret = store->create_bucket(*(s->user), s->bucket, zonegroup_id,
                                placement_rule, s->bucket_info.swift_ver_location,
                                pquota_info, attrs,
                                info, pobjv, &ep_objv, creation_time,
                                pmaster_bucket, pmaster_num_shards, true);
  /* continue if EEXIST and create_bucket will fail below.  this way we can
   * recover from a partial create by retrying it. */

  if (op_ret && op_ret != -EEXIST) {
    ldout(s->cct, 0) << __func__ << "rgw_create_bucket returned ret=" << op_ret << " bucket=" << s->bucket << dendl;
    if (s->cct->_conf->rgw_abcstore_multi_region) {
      auto db_ret = database::DBClient::instance().delete_bucket_info(s, s->bucket_name);
      if (db_ret < 0) {
        ldout(s->cct, 0) << __func__ << "() ERROR: create bucket failed, delete bucket from database also failed, ret: "
                         << db_ret << dendl;
      }
    }
    return;
  }

  existed = (op_ret == -EEXIST);

  if (existed) {
    /* bucket already existed, might have raced with another bucket creation, or
     * might be partial bucket creation that never completed. Read existing bucket
     * info, verify that the reported bucket owner is the current user.
     * If all is ok then update the user's list of buckets.
     * Otherwise inform client about a name conflict.
     */
    if (info.owner.compare(s->user->user_id) != 0) {
      op_ret = -EEXIST;
      return;
    }
    s->bucket = info.bucket;
  }

  op_ret = rgw_link_bucket(store, s->user->user_id, s->bucket,
			   info.creation_time, false);
  if (op_ret && !existed && op_ret != -EEXIST) {
    /* if it exists (or previously existed), don't remove it! */
    op_ret = rgw_unlink_bucket(store, s->user->user_id, s->bucket.tenant,
			       s->bucket.name);
    if (op_ret < 0) {
      ldout(s->cct, 0) << "WARNING: failed to unlink bucket: ret=" << op_ret
		       << dendl;
    }
  } else if (op_ret == -EEXIST || (op_ret == 0 && existed)) {
    op_ret = -ERR_BUCKET_EXISTS;
  }

  if (need_metadata_upload() && existed) {
    /* OK, it looks we lost race with another request. As it's required to
     * handle metadata fusion and upload, the whole operation becomes very
     * similar in nature to PutMetadataBucket. However, as the attrs may
     * changed in the meantime, we have to refresh. */
    short tries = 0;
    do {
      RGWObjectCtx& obj_ctx = *static_cast<RGWObjectCtx *>(s->obj_ctx);
      RGWBucketInfo binfo;
      map<string, bufferlist> battrs;

      op_ret = store->get_bucket_info(obj_ctx, s->bucket_tenant, s->bucket_name,
                                      binfo, nullptr, &battrs);
      if (op_ret < 0) {
        return;
      } else if (binfo.owner.compare(s->user->user_id) != 0) {
        /* New bucket doesn't belong to the account we're operating on. */
        op_ret = -EEXIST;
        return;
      } else {
        s->bucket_info = binfo;
        s->bucket_attrs = battrs;
      }

      attrs.clear();

      op_ret = rgw_get_request_metadata(s->cct, s->info, attrs, false);
      if (op_ret < 0) {
        return;
      }
      prepare_add_del_attrs(s->bucket_attrs, rmattr_names, attrs);
      populate_with_generic_attrs(s, attrs);
      op_ret = filter_out_quota_info(attrs, rmattr_names, s->bucket_info.quota);
      if (op_ret < 0) {
        return;
      }

      /* Handle updates of the metadata for Swift's object versioning. */
      if (swift_ver_location) {
        s->bucket_info.swift_ver_location = *swift_ver_location;
        s->bucket_info.swift_versioning = (! swift_ver_location->empty());
      }

      /* Web site of Swift API. */
      filter_out_website(attrs, rmattr_names, s->bucket_info.website_conf);
      s->bucket_info.has_website = !s->bucket_info.website_conf.is_empty();

      /* This will also set the quota on the bucket. */
      op_ret = rgw_bucket_set_attrs(store, s->bucket_info, attrs,
                                    &s->bucket_info.objv_tracker);
    } while (op_ret == -ECANCELED && tries++ < 20);

    /* Restore the proper return code. */
    if (op_ret >= 0) {
      op_ret = -ERR_BUCKET_EXISTS;
    }
  }
}

int RGWDeleteBucket::verify_permission()
{
#ifdef WITH_BCEBOS
  if (s->prot_flags & RGW_REST_BOS) {
    if (s->auth.identity->is_owner_of(s->bucket_info.owner)) {
      return 0;
    } else {
      return -EACCES;
    }
  } else
#endif
  {
    if (!verify_bucket_permission(s, rgw::IAM::s3DeleteBucket)) {
      return -EACCES;
    }
  }

  return 0;
}

void RGWDeleteBucket::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

void RGWDeleteBucket::execute()
{
  if (s->bucket_name.empty()) {
    op_ret = -EINVAL;
    return;
  }

  if (!s->bucket_exists) {
    ldout(s->cct, 0) << "ERROR: bucket " << s->bucket_name << " not found" << dendl;
    op_ret = -ERR_NO_SUCH_BUCKET;
    return;
  }
  RGWObjVersionTracker ot;
  ot.read_version = s->bucket_info.ep_objv;

  if (s->system_request) {
    string tag = s->info.args.get(RGW_SYS_PARAM_PREFIX "tag");
    string ver_str = s->info.args.get(RGW_SYS_PARAM_PREFIX "ver");
    if (!tag.empty()) {
      ot.read_version.tag = tag;
      uint64_t ver;
      string err;
      ver = strict_strtol(ver_str.c_str(), 10, &err);
      if (!err.empty()) {
        ldout(s->cct, 0) << "failed to parse ver param" << dendl;
        op_ret = -EINVAL;
        return;
      }
      ot.read_version.ver = ver;
    }
  }

  op_ret = rgw_bucket_sync_user_stats(store, s->user->user_id, s->bucket_info);
  if ( op_ret < 0) {
     ldout(s->cct, 1) << "WARNING: failed to sync user stats before bucket delete: op_ret= " << op_ret << dendl;
  }
  op_ret = store->check_bucket_empty(s->bucket_info);
  if (op_ret < 0) {
    ldout(s->cct, 1) << "WARNING: bucket not empty: op_ret= " << op_ret << dendl;
    return;
  }

  if (!store->is_meta_master()) {
    bufferlist in_data;
    op_ret = forward_request_to_master(s, &ot.read_version, store, in_data,
				       NULL);
    if (op_ret < 0) {
      if (op_ret == -ENOENT) {
        /* adjust error, we want to return with NoSuchBucket and not
	 * NoSuchKey */
        op_ret = -ERR_NO_SUCH_BUCKET;
      }
      return;
    }
  }

  string prefix, delimiter;

  if (s->prot_flags & RGW_REST_SWIFT) {
    string path_args;
    path_args = s->info.args.get("path");
    if (!path_args.empty()) {
      if (!delimiter.empty() || !prefix.empty()) {
        op_ret = -EINVAL;
        return;
      }
      prefix = path_args;
      delimiter="/";
    }
  }

  // delete lifecyle
  op_ret = store->get_lc()->remove_lc_entries(s->bucket_info.bucket, 0, int(s->bucket_info.num_shards));
  if (op_ret < 0) {
    ldout(s->cct, 0) << "WARNING: failed to delete lifecyle entry"
                     << ", bucket_name:" << s->bucket_name
                     << ", ret=" << op_ret << dendl;
    return;
  }

#ifdef WITH_BCEBOS
  if (s->prot_flags & RGW_REST_BOS) {
    vector<rgw_bucket_dir_entry> objs;
    bool id_truncated;
    int max = 1000;
    string marker;
    op_ret = list_bucket_multiparts(store, s->bucket_info, prefix, marker, delimiter,
                                        max, &objs, nullptr, &id_truncated);
    if (op_ret < 0) {
      return;
    }

    if (!objs.empty()) {
      op_ret = -ENOTEMPTY;
      return;
    }
  }
#endif

  op_ret = abort_bucket_multiparts(store, s->cct, s->bucket_info, prefix, delimiter);

  if (op_ret < 0) {
    return;
  }

#ifdef WITH_BCEIAM
  if (s->cct->_conf->rgw_with_bcm_restrict) {
    int bcm_ret = 0;
    for (int retry = 0; retry < MAX_RETRY_BCM; retry++) {
      bcm_ret = notify_bcm_resource(s, false);
      if (bcm_ret < 0) {
        ldout(s->cct, 20) << __func__ << " notify bcm ret=" << bcm_ret << dendl;
        continue;
      }
    }
  }
#endif

  if (s->cct->_conf->rgw_abcstore_multi_region) {
    op_ret = database::DBClient::instance().delete_bucket_info(s, s->bucket_name);
    if (op_ret < 0) {
      return;
    }
  }

  op_ret = store->delete_bucket(s->bucket_info, ot, false);

  if (op_ret == -ECANCELED) {
    // lost a race, either with mdlog sync or another delete bucket operation.
    // in either case, we've already called rgw_unlink_bucket()
    op_ret = 0;
    return;
  }

  if (op_ret == 0) {
    op_ret = rgw_unlink_bucket(store, s->bucket_info.owner, s->bucket.tenant,
			       s->bucket.name, false);
    if (op_ret < 0) {
      ldout(s->cct, 0) << "WARNING: failed to unlink bucket: ret=" << op_ret
		       << dendl;
    }
  }
}

int RGWPutObj::verify_permission()
{
  auto op_ret = get_params();
  if (op_ret < 0) {
    ldout(s->cct, 20) << "get_params() returned ret=" << op_ret << dendl;
    return op_ret;
  }

  if (! copy_source.empty()) {
    if (if_mod) {
      if (parse_time(if_mod, &mod_time) < 0) {
        return -EINVAL;
      }
      mod_ptr = &mod_time;
    }

    if (if_unmod) {
      if (parse_time(if_unmod, &unmod_time) < 0) {
        return -EINVAL;
      }
      unmod_ptr = &unmod_time;
    }

    RGWAccessControlPolicy cs_acl(s->cct);
    boost::optional<Policy> policy;
    rgw_bucket cs_bucket(copy_source_bucket_info.bucket);
    rgw_obj_key cs_object(copy_source_object_name, copy_source_version_id);

    rgw_obj obj(cs_bucket, cs_object);
    store->set_atomic(s->obj_ctx, obj);
    store->set_prefetch_data(s->obj_ctx, obj);

    /* check source object permissions */
    op_ret = read_obj_policy(store, s, copy_source_bucket_info, src_attrs,
                             &cs_acl, policy, cs_bucket, cs_object);
    if (op_ret < 0 ) {
#ifdef WITH_BCEBOS
      if (s->prot_flags & RGW_REST_BOS) {
        if (op_ret == -ENAMETOOLONG) {
          return -ERR_INVALID_OBJECT_NAME;
        } else {
          return op_ret;
        }
      } else
#endif
      {
        return -EACCES;
      }
    }

    /* admin request overrides permission checks */
    if (! s->auth.identity->is_admin_of(cs_acl.get_owner().get_id())) {
      if (policy) {
        auto e = policy->eval(s->env, *s->auth.identity,
                              cs_object.instance.empty() ?
                              rgw::IAM::s3GetObject :
                              rgw::IAM::s3GetObjectVersion,
                              rgw::IAM::ARN(obj));
        if (e == Effect::Deny) {
          return -EACCES;
        } else if (e == Effect::Pass &&
                   !cs_acl.verify_permission(*s->auth.identity, s->perm_mask, RGW_PERM_READ)) {
          return -EACCES;
        }
      } else if (!cs_acl.verify_permission(*s->auth.identity, s->perm_mask, RGW_PERM_READ)) {
          return -EACCES;
      }
    }
  }

  bool modify_pass_new = false;
  if (s->iam_policy) {
    rgw_add_grant_to_iam_environment(s->env, s);

    rgw_add_to_iam_environment(s->env, "s3:x-amz-acl", s->canned_acl);

    if (obj_tags != nullptr && obj_tags->count() > 0){
      auto tags = obj_tags->get_tags();
      for (const auto& kv: tags){
        rgw_add_to_iam_environment(s->env, "s3:RequestObjectTag/"+kv.first, kv.second);
      }
    }

    constexpr auto encrypt_attr = "x-amz-server-side-encryption";
    constexpr auto s3_encrypt_attr = "s3:x-amz-server-side-encryption";
    auto enc_header = s->info.x_meta_map.find(encrypt_attr);
    if (enc_header != s->info.x_meta_map.end()){
      rgw_add_to_iam_environment(s->env, s3_encrypt_attr, enc_header->second);
    }

    constexpr auto kms_attr = "x-amz-server-side-encryption-aws-kms-key-id";
    constexpr auto s3_kms_attr = "s3:x-amz-server-side-encryption-aws-kms-key-id";
    auto kms_header = s->info.x_meta_map.find(kms_attr);
    if (kms_header != s->info.x_meta_map.end()){
      rgw_add_to_iam_environment(s->env, s3_kms_attr, kms_header->second);
    }

    auto e = s->iam_policy->eval(s->env, *s->auth.identity,
                                 rgw::IAM::s3PutObject,
                                 rgw_obj(s->bucket, s->object));

#ifdef WITH_BCEBOS
    if (s->prot_flags & RGW_REST_BOS) {
      rgw_obj modify_obj(s->bucket, s->object);
      int ret = verify_bos_modify(store, s, modify_obj, e);
      if (ret <= MODIFY_ALLOW) {
        return ret;
      }
      if (ret == MODIFY_PASS_NEW) {
        modify_pass_new = true;
      }
    } else
#endif
    {
      if (e == Effect::Allow) {
        return 0;
      } else if (e == Effect::Deny) {
        return -EACCES;
      }
    }
  }

  if (!verify_bucket_permission_no_policy(s, RGW_PERM_WRITE)) {
    return modify_pass_new ? -ERR_ONLY_ALLOW_MODIFY : -EACCES;
  }

  return 0;
}

void RGWPutObjProcessor_Multipart::get_mp(RGWMPObj** _mp){
  *_mp = &mp;
}

void RGWPutObjProcessor_Multipart::set_mp(string *oid_rand) {
  upload_id = s->info.args.get("uploadId");
  if (!oid_rand) {
    mp.init(obj_str, upload_id);
  } else {
    mp.init(obj_str, upload_id, *oid_rand);
  }
}

int RGWPutObjProcessor_Multipart::rewrite_repeated_part_omap_key(RGWRados *store, string p, rgw_raw_obj raw_meta_obj, bufferlist & bl) {
  // get the part_obj's omap by the key
  map<string, bufferlist> parts_map;
  rgw_rados_ref ref;
  set<string> keys;
  keys.insert(p);

  int r = store->get_raw_obj_ref(raw_meta_obj, &ref);
  if (r < 0) {
    return 0;
  }
  r = ref.ioctx.omap_get_vals_by_keys(ref.oid, keys, &parts_map);
  if (r < 0) {
    lderr(s->cct) << "ERROR: get ompa val failed, please retry" << dendl;
    return r;
  }

  map<string, bufferlist>::iterator iter = parts_map.begin();
  if (iter == parts_map.end()) {
    ldout(s->cct, 20) << "No such part object, caught buffer::error" << dendl;
    return -ENOENT;
  }

  // copy this part info in the omap of multipart meta
  bl = iter->second;
  return 0;
}

int RGWPutObjProcessor_Multipart::prepare(RGWRados *store, string *oid_rand)
{
  RGWPutObjProcessor_Aio::prepare(store, oid_rand);
  string oid = obj_str;
  part_num = s->info.args.get("partNumber");
  if (part_num.empty()) {
    ldout(s->cct, 10) << "part number is empty" << dendl;
    return -EINVAL;
  }

  string err;
  uint64_t num = (uint64_t)strict_strtol(part_num.c_str(), 10, &err);

  if (!err.empty() || num < 1 ||
      num > uint64_t(store->ctx()->_conf->rgw_multipart_part_upload_limit)) {
    ldout(s->cct, 10) << "bad part number: " << part_num << ": " << err << dendl;
    return -EINVAL;
  }

  string upload_prefix = oid + ".";

  if (!oid_rand) {
    upload_prefix.append(upload_id);
  } else {
    upload_prefix.append(*oid_rand);
    repeat_part = true;
  }

  rgw_obj target_obj;
  target_obj.init(bucket, oid);

  manifest.set_prefix(upload_prefix);

  manifest.set_multipart_part_rule(store->ctx()->_conf->rgw_obj_stripe_size, num);

  try_file_shuntflow();

  manifest.set_skip_cache(get_skip_cache_flag());

  int r = manifest_gen.create_begin(store->ctx(), &manifest, tail_placement_rule, tail_placement_rule, bucket, target_obj);
  if (r < 0) {
    return r;
  }

  cur_obj = manifest_gen.get_cur_obj(store);
  rgw_raw_obj_to_obj(bucket, cur_obj, &head_obj);
  head_obj.index_hash_source = obj_str;

  r = store->get_max_chunk_size(tail_placement_rule, head_obj, &max_chunk_size);
  if (r < 0) {
    return r;
  }

  return 0;
}

int RGWPutObjProcessor_Multipart::do_complete(size_t accounted_size,
                                              const string& etag,
                                              real_time *mtime, real_time set_mtime,
                                              map<string, bufferlist>& attrs,
                                              real_time delete_at,
                                              const char *if_match,
                                              const char *if_nomatch, const string *user_data, rgw_zone_set *zones_trace)
{
  complete_writing_data();

  RGWRados::Object op_target(store, s->bucket_info, obj_ctx, head_obj);
  op_target.set_versioning_disabled(true);
  op_target.set_bilog_write_enable(false);
  RGWRados::Object::Write head_obj_op(&op_target);

  head_obj_op.meta.set_mtime = set_mtime;
  head_obj_op.meta.mtime = mtime;
  head_obj_op.meta.owner = s->owner.get_id();
  head_obj_op.meta.delete_at = delete_at;
  head_obj_op.meta.zones_trace = zones_trace;
  head_obj_op.meta.modify_tail = true;
  head_obj_op.meta.head_placement_rule = manifest.get_head_placement_rule();
  head_obj_op.meta.storage_class = manifest.get_tail_placement().placement_rule.storage_class;
  head_obj_op.meta.accounted_entry = false;
  head_obj_op.skip_cache = enable_skip_cache;

  int r = head_obj_op.write_meta_without_namespace(obj_len, accounted_size, attrs);
  if (r < 0)
    return r;

  bufferlist bl;
  RGWUploadPartInfo info;
  string p = "part.";
  bool sorted_omap = is_v2_upload_id(upload_id);

  if (sorted_omap) {
    string err;
    int part_num_int = strict_strtol(part_num.c_str(), 10, &err);
    if (!err.empty()) {
      dout(10) << "bad part number specified: " << part_num << dendl;
      return -EINVAL;
    }
    char buf[32];
    snprintf(buf, sizeof(buf), "%08d", part_num_int);
    p.append(buf);
  } else {
    p.append(part_num);
  }
  info.num = atoi(part_num.c_str());
  info.etag = etag;
  info.size = obj_len;
  info.accounted_size = accounted_size;
  info.modified = real_clock::now();
  info.manifest = manifest;

  bool compressed;
  r = rgw_compression_info_from_attrset(attrs, compressed, info.cs_info);
  if (r < 0) {
    dout(1) << "cannot get compression info" << dendl;
    return r;
  }

  encode(info, bl);

  string multipart_meta_obj = mp.get_meta();

  rgw_obj meta_obj;
  meta_obj.init_ns(bucket, multipart_meta_obj, mp_ns);
  meta_obj.set_in_extra_data(true);

  rgw_raw_obj raw_meta_obj;

  store->obj_to_raw(s->bucket_info.head_placement_rule, meta_obj, &raw_meta_obj);
  const bool must_exist = true;// detect races with abort

  // if there exists a repeated multi part, firstly read&copy this part
  if (repeat_part) {
    bufferlist tmp_bl;
    string tmp_p = "orphan.";
    char tmp_buf[32];

    r = rewrite_repeated_part_omap_key(store, p, raw_meta_obj, tmp_bl);
    if (r < 0) {
      return r;
    }

    gen_rand_alphanumeric(store->ctx(), tmp_buf, sizeof(tmp_buf) - 1);
    tmp_p.append(tmp_buf);
    r = store->omap_set(raw_meta_obj, tmp_p, tmp_bl, must_exist);
    if (r < 0) {
      return r;
    }
  }

  // set the new part info to the omap of mp.meta obj
  r = store->omap_set(raw_meta_obj, p, bl, must_exist);
  return r;
}

RGWPutObjProcessor *RGWPutObj::select_processor(RGWObjectCtx& obj_ctx, int* const op_ret)
{
  RGWPutObjProcessor *processor = nullptr;

  multipart = s->info.args.exists("uploadId");

  append = s->info.args.exists("append");

  uint64_t part_size = s->cct->_conf->rgw_obj_stripe_size;

  if (append) {
    string err;
    string offset_str = s->info.args.get("offset");
    if (s->info.args.exists("offset")) {
      if (offset_str.empty()) {
        ldout(s->cct, 0) << "ERROR: offset exist but offset = NULL" << dendl;
        return nullptr;
      }
      offset = strict_strtoll(offset_str.c_str(), 10, &err);
      if (!err.empty()) {
        ldout(s->cct, 0) << "bad offset specified: " << offset_str << dendl;
        *op_ret = -EINVAL;
        return nullptr;
      }
    }
    processor = new RGWPutObjProcessor_Append(obj_ctx, s->bucket_info, part_size, s, offset, &cur_accounted_size);
    (static_cast<RGWPutObjProcessor_Append *>(processor))->set_olh_epoch(olh_epoch);
    (static_cast<RGWPutObjProcessor_Append *>(processor))->set_placement_rule(s->dest_placement);
    (static_cast<RGWPutObjProcessor_Append *>(processor))->set_content_length(s->cct->_conf->rgw_file_shuntflow_size);
    (static_cast<RGWPutObjProcessor_Append *>(processor))->set_unknown_actual_size(true);
  } else if (!multipart) {
    processor = new RGWPutObjProcessor_Atomic(obj_ctx, s->bucket_info, s->bucket, s->object.name, part_size, s->req_id, s->bucket_info.versioning_enabled());
    (static_cast<RGWPutObjProcessor_Atomic *>(processor))->set_olh_epoch(olh_epoch);
    (static_cast<RGWPutObjProcessor_Atomic *>(processor))->set_version_id(version_id);
    (static_cast<RGWPutObjProcessor_Atomic *>(processor))->set_placement_rule(s->dest_placement);
    (static_cast<RGWPutObjProcessor_Atomic *>(processor))->set_content_length(s->content_length);
  } else {
    processor = new RGWPutObjProcessor_Multipart(obj_ctx, s->bucket_info, part_size, s);
    (static_cast<RGWPutObjProcessor_Multipart *>(processor))->set_mp(NULL);
    (static_cast<RGWPutObjProcessor_Multipart *>(processor))->set_content_length(s->content_length);
  }

  (static_cast<RGWPutObjProcessor_Aio *>(processor))->set_skip_cache_flag(s->cct->_conf->rgw_enable_skip_cachepool);
  (static_cast<RGWPutObjProcessor_Aio *>(processor))->set_file_shuntflow_size(s->cct->_conf->rgw_file_shuntflow_size);

  return processor;
}

void RGWPutObj::dispose_processor(RGWPutObjDataProcessor *processor)
{
  delete processor;
}

void RGWPutObj::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

class RGWPutObj_CB : public RGWGetObj_Filter
{
  RGWPutObj *op;
public:
  RGWPutObj_CB(RGWPutObj *_op) : op(_op) {}
  ~RGWPutObj_CB() override {}

  int handle_data(bufferlist& bl, off_t bl_ofs, off_t bl_len) override {
    return op->get_data_cb(bl, bl_ofs, bl_len);
  }
};

int RGWPutObj::get_data_cb(bufferlist& bl, off_t bl_ofs, off_t bl_len)
{
  bufferlist bl_tmp;
  bl.copy(bl_ofs, bl_len, bl_tmp);

  bl_aux.append(bl_tmp);

  return bl_len;
}

int RGWPutObj::get_data(const off_t fst, const off_t lst, bufferlist& bl)
{
  RGWPutObj_CB cb(this);
  RGWGetObj_Filter* filter = &cb;
  boost::optional<RGWGetObj_Decompress> decompress;
  std::unique_ptr<RGWGetObj_Filter> decrypt;
  RGWCompressionInfo cs_info;
  map<string, bufferlist> attrs;
  map<string, bufferlist>::iterator attr_iter;
  int ret = 0;

  uint64_t obj_size;
  int64_t new_ofs, new_end;

  new_ofs = fst;
  new_end = lst;

  rgw_obj_key obj_key(copy_source_object_name, copy_source_version_id);
  rgw_obj obj(copy_source_bucket_info.bucket, obj_key);

  RGWRados::Object op_target(store, copy_source_bucket_info, *static_cast<RGWObjectCtx *>(s->obj_ctx), obj);
  RGWRados::Object::Read read_op(&op_target);
  read_op.conds.mod_ptr = mod_ptr;
  read_op.conds.unmod_ptr = unmod_ptr;
  read_op.conds.if_match = if_match;
  read_op.conds.if_nomatch = if_nomatch;
  read_op.params.obj_size = &obj_size;
  read_op.params.attrs = &attrs;

  ret = read_op.prepare();

  if (ret < 0) {
#ifdef WITH_BCEBOS
    if ((s->prot_flags & RGW_REST_BOS) && ret == -ERR_NOT_MODIFIED) {
      ret = -ERR_PRECONDITION_FAILED;
    }
#endif
    return ret;
  }

  bool need_decompress;
  op_ret = rgw_compression_info_from_attrset(attrs, need_decompress, cs_info);
  if (op_ret < 0) {
	  lderr(s->cct) << "ERROR: failed to decode compression info, cannot decompress" << dendl;
      return -EIO;
  }

  bool partial_content = true;
  if (need_decompress)
  {
    obj_size = cs_info.orig_size;
    decompress.emplace(s->cct, &cs_info, partial_content, filter);
    filter = &*decompress;
  }

  attr_iter = attrs.find(RGW_ATTR_MANIFEST);

  for (auto numattr : attrs) {
    ldout(s->cct, 5) << "attr: " << numattr.first << "=" << numattr.second.c_str() <<dendl;
  }

  op_ret = this->get_decrypt_filter(&decrypt,
                                    filter,
                                    attrs,
                                    attr_iter != attrs.end() ? &(attr_iter->second) : nullptr);
  if (decrypt != nullptr) {
    filter = decrypt.get();
  }
  if (op_ret < 0) {
    return ret;
  }

  ret = read_op.range_to_ofs(obj_size, new_ofs, new_end);
  if (ret < 0)
    return ret;

  filter->fixup_range(new_ofs, new_end);
  ret = read_op.iterate(new_ofs, new_end, filter);

  if (ret >= 0)
    ret = filter->flush();

  bl.claim_append(bl_aux);

  return ret;
}

// special handling for compression type = "random" with multipart uploads
static CompressorRef get_compressor_plugin(const req_state *s,
                                           const std::string& compression_type)
{
  if (compression_type != "random") {
    return Compressor::create(s->cct, compression_type);
  }

  bool is_multipart{false};
  const auto& upload_id = s->info.args.get("uploadId", &is_multipart);

  if (!is_multipart) {
    return Compressor::create(s->cct, compression_type);
  }

  // use a hash of the multipart upload id so all parts use the same plugin
  const auto alg = std::hash<std::string>{}(upload_id) % Compressor::COMP_ALG_LAST;
  if (alg == Compressor::COMP_ALG_NONE) {
    return nullptr;
  }
  return Compressor::create(s->cct, alg);
}

void RGWPutObj::execute()
{
  RGWPutObjProcessor *processor = NULL;
  RGWPutObjDataProcessor *filter = nullptr;
  std::unique_ptr<RGWPutObjDataProcessor> encrypt;
  char supplied_md5_bin[CEPH_CRYPTO_MD5_DIGESTSIZE + 1];
  char supplied_md5[CEPH_CRYPTO_MD5_DIGESTSIZE * 2 + 1];
  char calc_md5[CEPH_CRYPTO_MD5_DIGESTSIZE * 2 + 1];
  unsigned char m[CEPH_CRYPTO_MD5_DIGESTSIZE];
  MD5 hash;
  bufferlist bl, aclbl, bs, md5bl;
  int len;
  bool need_to_wait = false;
  bool bool_false = false;

  off_t fst;
  off_t lst;
  const auto& compression_type = store->get_zone_params().get_compression_type(
      s->dest_placement);
  CompressorRef plugin;
  boost::optional<RGWPutObj_Compress> compressor;
  rgw_obj obj(s->bucket, s->object);

  bool need_calc_md5 = ((dlo_manifest == NULL) && (slo_info == NULL))
#ifdef WITH_BCEBOS
                        || (s->prot_flags & RGW_REST_BOS)
#endif
                       ;
  perfcounter->inc(l_rgw_put);
  op_ret = -EINVAL;
  if (s->object.empty()) {
    goto done;
  }

  if (!s->bucket_exists) {
    op_ret = -ERR_NO_SUCH_BUCKET;
    return;
  }

  // Namespace: it is make dir
  if (RGWRados::Bucket::Namespace::is_make_dir_request(s)) {
    if (s->content_length != 0) {
      // content-length must be 0
      ldout(s->cct, 1) << __func__ << " WARNING: the content-length of dir "
                       << s->object << " is not 0" << dendl;
      op_ret = ERR_INVALID_REQUEST;
    } else if (!copy_source.empty()) {
      // don't support copy dir
      ldout(s->cct, 1) << __func__ << " WARNING: can't copy dir " << s->object << dendl;
      op_ret = ERR_INVALID_REQUEST;
    } else {
      ldout(s->cct, 20) << __func__ << " RGWPutObj::execute() it is mkdir "
                        << s->object << dendl;
      op_ret = RGWRados::Bucket::Namespace::make_dir(store, s);
    }
    return;
  }

  op_ret = get_system_versioning_params(s, &olh_epoch, &version_id);
  if (op_ret < 0) {
    ldout(s->cct, 20) << "get_system_versioning_params() returned ret="
		      << op_ret << dendl;
    goto done;
  }

  if (supplied_md5_b64) {
    need_calc_md5 = true;

    ldout(s->cct, 15) << "supplied_md5_b64=" << supplied_md5_b64 << dendl;
    op_ret = ceph_unarmor(supplied_md5_bin, &supplied_md5_bin[CEPH_CRYPTO_MD5_DIGESTSIZE + 1],
                       supplied_md5_b64, supplied_md5_b64 + strlen(supplied_md5_b64));
    ldout(s->cct, 15) << "ceph_armor ret=" << op_ret << dendl;
    if (op_ret != CEPH_CRYPTO_MD5_DIGESTSIZE) {
#ifdef WITH_BCEBOS
      if (s->prot_flags & RGW_REST_BOS) {
        op_ret = -ERR_BAD_DIGEST;
      } else
#endif
      {
        op_ret = -ERR_INVALID_DIGEST;
      }
      goto done;
    }

    buf_to_hex((const unsigned char *)supplied_md5_bin, CEPH_CRYPTO_MD5_DIGESTSIZE, supplied_md5);
    ldout(s->cct, 15) << "supplied_md5=" << supplied_md5 << dendl;
  }

  if (supplied_etag) {
    strncpy(supplied_md5, supplied_etag, sizeof(supplied_md5) - 1);
    supplied_md5[sizeof(supplied_md5) - 1] = '\0';
  }

  processor = select_processor(*static_cast<RGWObjectCtx *>(s->obj_ctx), &op_ret);
  if (!processor) {
    ldout(s->cct, 20) << "NOTICE: select_processor return nullptr only occur in append obj " << dendl;
    op_ret = -EINVAL;
    return;
  }

  // no filters by default
  filter = processor;

  if (!chunked_upload) { /* with chunked upload we don't know how big is the upload.
                            we also check sizes at the end anyway */
    op_ret = store->check_quota(s->bucket_owner.get_id(), s->bucket,
                                 user_quota, bucket_quota, s->content_length, multipart);
    if (op_ret < 0) {
      ldout(s->cct, 20) << "check_quota() returned ret=" << op_ret << dendl;
      goto done;
    }
    op_ret = store->check_bucket_shards(s->bucket_info, s->bucket, bucket_quota);
    if (op_ret < 0) {
      ldout(s->cct, 20) << "check_bucket_shards() returned ret=" << op_ret << dendl;
      goto done;
    }
  }

  if (!append || (append && offset == 0)) {
    op_ret = worm_verify_bos_write(s, store, obj, s->bucket_info.bos_obj_lock, false);
    if (op_ret < 0) {
      ldout(s->cct, 0) << __func__ << "() ERROR: worm verify bos write " << obj
                       << "err: " << op_ret << dendl;
      return;
    }
  }

  /* Handle object versioning of Swift API. */
  if (! multipart) {
    op_ret = store->swift_versioning_copy(*static_cast<RGWObjectCtx *>(s->obj_ctx),
                                          s->bucket_owner.get_id(),
                                          s->bucket_info,
                                          obj, user_quota, bucket_quota);
    if (op_ret < 0) {
      goto done;
    }

  }

  if (! copy_source.empty()) {
    rgw_obj_key obj_key(copy_source_object_name, copy_source_version_id);
    rgw_obj obj(copy_source_bucket_info.bucket, obj_key.name);

    RGWObjState *astate;
    op_ret = store->get_obj_state(static_cast<RGWObjectCtx *>(s->obj_ctx),
                                  copy_source_bucket_info, obj, &astate, true, false);
    if (op_ret < 0) {
      ldout(s->cct, 0) << "ERROR: get copy source obj state returned with error" << op_ret << dendl;
      goto done;
    }
    if (!astate->exists){
      op_ret = -ENOENT;
      goto done;
    }
    if (copy_source_range) {
      lst = std::min(off_t(astate->accounted_size - 1), copy_source_range_lst);
    } else {
      lst = astate->accounted_size - 1;
    }

    // symlink object etag
    auto iter = astate->attrset.find(RGW_ATTR_TARGET_OBJECT);
    if(iter != astate->attrset.end()){
      auto target_object_name = rgw_bl_to_str(iter->second);
      hash.Update((const unsigned char *)target_object_name.c_str(), target_object_name.length());
    }
  } else {
    lst = copy_source_range_lst;
  }

  fst = copy_source_range_fst;

  //get multipart object storage class before prepare
  op_ret = get_encrypt_filter(&encrypt, filter);
  if (op_ret < 0) {
    goto done;
  }
  if (encrypt != nullptr) {
    filter = encrypt.get();
  } else {
    //no encryption, we can try compression
    if (compression_type != "none") {
      plugin = get_compressor_plugin(s, compression_type);
      if (!plugin) {
        ldout(s->cct, 1) << "Cannot load plugin for compression type "
            << compression_type << dendl;
      } else {
        compressor.emplace(s->cct, plugin, filter);
        filter = &*compressor;
      }
    }
  }

  tracepoint(rgw_op, before_data_transfer, s->req_id.c_str());
  op_ret = processor->prepare(store, NULL);
  if (op_ret < 0) {
    ldout(s->cct, 20) << "processor->prepare() returned ret=" << op_ret << dendl;
    goto done;
  }

  if (multipart) {
    // wait to store first chunk, in case of existing same part number
    need_to_wait = true;
  }

  do {
    bufferlist data;
    if (fst > lst)
      break;
    if (copy_source.empty()) {
      len = get_data(data);
    } else {
      uint64_t cur_lst = min(fst + s->cct->_conf->rgw_max_chunk_size - 1, lst);
      op_ret = get_data(fst, cur_lst, data);
      if (op_ret < 0)
        goto done;
      len = data.length();
      s->content_length += len;
      fst += len;
    }
    if (len < 0) {
      op_ret = len;
      ldout(s->cct, 20) << "get_data() returned ret=" << op_ret << dendl;
      goto done;
    }

    if (need_calc_md5) {
      hash.Update((const unsigned char *)data.c_str(), data.length());
    }

    /* update torrrent */
    torrent.update(data);

    /* do we need this operation to be synchronous? if we're dealing with an object with immutable
     * head, e.g., multipart object we need to make sure we're the first one writing to this object
     */
    //bool need_to_wait = (ofs == 0) && multipart;


    op_ret = put_data_and_throttle(filter, data, ofs, need_to_wait);
    if (op_ret < 0) {
      if (op_ret != -EEXIST) {
        ldout(s->cct, 20) << "processor->thottle_data() returned ret="
                          << op_ret << dendl;
        goto done;
      }
      /* need_to_wait == true and op_ret == -EEXIST */
      ldout(s->cct, 5) << "NOTICE: processor->throttle_data() returned -EEXIST, need to restart write" << dendl;


      /* restart processing with different oid suffix
       * 
       * Upload part by multiple chunks model, will call put_data_and_throttle()
       * one time when received every chunk.
       *
       * So the input param 'data' only contains current chunk data, when store
       * first chunk to rados, RGWPutObjProcessor_Atomic::handle_data will pass
       * back the whole data by reference param 'data'. In order to restart to
       * store the whole data.
       * */

      dispose_processor(processor);
      processor = select_processor(*static_cast<RGWObjectCtx *>(s->obj_ctx), &op_ret);
      if (!processor) {
        ldout(s->cct, 20) << "NOTICE: select_processor return nullptr only occur in append obj " << dendl;
        op_ret = -EINVAL;
        return;
      }
      filter = processor;

      op_ret = get_encrypt_filter(&encrypt, filter);
      if (op_ret < 0) {
        goto done;
      }
      if (encrypt != nullptr) {
        filter = encrypt.get();
      } else {
        if (compressor) {
          compressor.emplace(s->cct, plugin, filter);
          filter = &*compressor;
        }
      }

      string oid_rand;
      char buf[33];
      gen_rand_alphanumeric(store->ctx(), buf, sizeof(buf) - 1);
      oid_rand.append(buf);

      op_ret = processor->prepare(store, &oid_rand);
      if (op_ret < 0) {
        ldout(s->cct, 0) << "ERROR: processor->prepare() returned "
                         << op_ret << dendl;
        goto done;
      }

      op_ret = put_data_and_throttle(filter, data, ofs, bool_false);
      if (op_ret < 0) {
        goto done;
      }
    }

    ofs += len;
  } while (len > 0);
  tracepoint(rgw_op, after_data_transfer, s->req_id.c_str(), ofs);

  {
    bufferlist flush;
    op_ret = put_data_and_throttle(filter, flush, ofs, bool_false);
    if (op_ret < 0) {
      goto done;
    }
  }

  if (!chunked_upload && ofs != s->content_length) {
    op_ret = -ERR_REQUEST_TIMEOUT;
    goto done;
  }
  s->obj_size = ofs;

  perfcounter->inc(l_rgw_put_b, s->obj_size);

  op_ret = do_aws4_auth_completion();

  if (op_ret < 0) {
    goto done;
  }
  
  op_ret = store->check_quota(s->bucket_owner.get_id(), s->bucket,
                               user_quota, bucket_quota, s->obj_size, multipart);
  if (op_ret < 0) {
    ldout(s->cct, 20) << "second check_quota() returned op_ret=" << op_ret << dendl;
    goto done;
  }

  op_ret = store->check_bucket_shards(s->bucket_info, s->bucket, bucket_quota);
  if (op_ret < 0) {
    ldout(s->cct, 20) << "check_bucket_shards() returned ret=" << op_ret << dendl;
    goto done;
  }

  hash.Final(m);

  if (compressor && compressor->is_compressed()) {
    bufferlist tmp;
    RGWCompressionInfo cs_info;
    cs_info.compression_type = plugin->get_type_name();
    cs_info.orig_size = s->obj_size;
    cs_info.blocks = move(compressor->get_compression_blocks());
    encode(cs_info, tmp);
    attrs[RGW_ATTR_COMPRESSION] = tmp;
    ldout(s->cct, 20) << "storing " << RGW_ATTR_COMPRESSION
        << " with type=" << cs_info.compression_type
        << ", orig_size=" << cs_info.orig_size
        << ", blocks=" << cs_info.blocks.size() << dendl;
  }

#ifdef WITH_BCEBOS
  bos_md5 = rgw::to_base64(boost::string_view((char *)m, sizeof(m)));
  md5bl.append(bos_md5);
  emplace_attr(RGW_ATTR_CONTENT_MD5, std::move(md5bl));
#endif
  buf_to_hex(m, CEPH_CRYPTO_MD5_DIGESTSIZE, calc_md5);

  etag = calc_md5;

  if (supplied_md5_b64 && strcmp(calc_md5, supplied_md5)) {
    ldout(s->cct, 10) << __func__ << "() calculated md5 (" << calc_md5
                      << ") not match supplied_md5:" << supplied_md5 << dendl;
    op_ret = -ERR_BAD_DIGEST;
    goto done;
  }

  policy.encode(aclbl);
  emplace_attr(RGW_ATTR_ACL, std::move(aclbl));

  if (dlo_manifest) {
    op_ret = encode_dlo_manifest_attr(dlo_manifest, attrs);
    if (op_ret < 0) {
      ldout(s->cct, 0) << "bad user manifest: " << dlo_manifest << dendl;
      goto done;
    }
    complete_etag(hash, &etag);
    ldout(s->cct, 10) << __func__ << ": calculated md5 for user manifest: " << etag << dendl;
  }

  if (slo_info) {
    bufferlist manifest_bl;
    encode(*slo_info, manifest_bl);
    emplace_attr(RGW_ATTR_SLO_MANIFEST, std::move(manifest_bl));

    hash.Update((unsigned char *)slo_info->raw_data, slo_info->raw_data_len);
    complete_etag(hash, &etag);
    ldout(s->cct, 10) << __func__ << ": calculated md5 for user manifest: " << etag << dendl;
  }

  if (supplied_etag && etag.compare(supplied_etag) != 0) {
    op_ret = -ERR_UNPROCESSABLE_ENTITY;
    goto done;
  }
  bl.append(etag.c_str(), etag.size());
  emplace_attr(RGW_ATTR_ETAG, std::move(bl));

  populate_with_generic_attrs(s, attrs);
  if (offset != 0) {
    for (auto meta_header : s->info.x_meta_map) {
      if (meta_header.first.find("x-amz-meta-") == 0) {
        s->info.x_meta_map.erase(meta_header.first);
      }
    }
  }
  op_ret = rgw_get_request_metadata(s->cct, s->info, attrs);
  if (op_ret < 0) {
    goto done;
  }
  encode_delete_at_attr(delete_at, attrs);
  encode_obj_tags_attr(obj_tags.get(), attrs);

  /* Add a custom metadata to expose the information whether an object
   * is an SLO or not. Appending the attribute must be performed AFTER
   * processing any input from user in order to prohibit overwriting. */
  if (slo_info) {
    bufferlist slo_userindicator_bl;
    slo_userindicator_bl.append("True", 4);
    emplace_attr(RGW_ATTR_SLO_UINDICATOR, std::move(slo_userindicator_bl));
  }

  perfcounter->tinc(l_rgw_put_before_put_meta, s->time_elapsed());
  if (obj_legal_hold) {
    bufferlist obj_legal_hold_bl;
    obj_legal_hold->encode(obj_legal_hold_bl);
    emplace_attr(RGW_ATTR_OBJECT_LEGAL_HOLD, std::move(obj_legal_hold_bl));
  }
  if (obj_retention) {
    bufferlist obj_retention_bl;
    obj_retention->encode(obj_retention_bl);
    emplace_attr(RGW_ATTR_OBJECT_RETENTION, std::move(obj_retention_bl));
  }

  tracepoint(rgw_op, processor_complete_enter, s->req_id.c_str());
  op_ret = processor->complete(s->obj_size, etag, &mtime, real_time(), attrs,
                               (delete_at ? *delete_at : real_time()), if_match, if_nomatch,
                               (user_data.empty() ? nullptr : &user_data));
  tracepoint(rgw_op, processor_complete_exit, s->req_id.c_str());

  // only atomic upload will upate version_id here
  if (!multipart) 
    version_id = (static_cast<RGWPutObjProcessor_Atomic *>(processor))->get_version_id();

  /* produce torrent */
  if (s->cct->_conf->rgw_torrent_flag && (ofs == torrent.get_data_len()))
  {
    torrent.init(s, store);
    torrent.set_create_date(mtime);
    op_ret =  torrent.complete();
    if (0 != op_ret)
    {
      ldout(s->cct, 0) << "ERROR: torrent.handle_data() returned " << op_ret << dendl;
      goto done;
    }
  }

  if (op_ret == 0) {
    op_ret = process_callback(etag, attrs[RGW_ATTR_CONTENT_TYPE].to_str());

    bufferlist notification_bl;
    if (get_bucket_notification(notification_bl) == 0) {
      RGWNotification n;
      op_ret = n.decode_notification_bl(notification_bl);
      if (op_ret != 0) return;
      int notification_ret = handle_notification(n, etag, name(), s->object.name, s->bucket_name);
      if (notification_ret != 0) {
        op_ret = notification_ret;
      }
    }
  }

done:
  dispose_processor(processor);
  perfcounter->tinc(l_rgw_put_lat, s->time_elapsed());
}

#ifdef WITH_RADOSGW_BEAST_OPENSSL
namespace ssl = boost::asio::ssl;
#endif

int RGWOp::process_callback(const string& etag, const string& contentType) {
  std::string callback_req = s->info.args.get(RGW_BCE_PROCESS);
  if (!callback_req.length()) {
    const char* c = s->info.env->get("HTTP_X_BCE_PROCESS");
    if (c) callback_req = c;
  }
  if (!callback_req.length()) {
    return 0;
  }

  std::vector<std::string> actions;
  boost::split(actions, callback_req, boost::is_any_of("/"));
  if (actions.size() < 2) {
    return -ERR_INVALID_REQUEST;
  }

  if (actions[0] != "callback") {
    return 0;
  }

  if (actions.size() != 2) {
    return -ERR_INVALID_REQUEST;
  }

  std::vector<std::string> details;
  boost::split(details, actions[1], boost::is_any_of(","));
  if (details.size() < 2 || details[0] != "callback") {
    return -ERR_INVALID_REQUEST;
  }

  std::vector<std::string>::iterator it_detail = details.begin();
  it_detail++;

  string endpoints;
  string host;
  uint32_t port;
  string uri = "";
  string vars = "";
  string method = "";
  int result = 0;

  for (; it_detail != details.end(); it_detail++) {
    std::vector<std::string> kvs;
    boost::split(kvs, *it_detail, boost::is_any_of("_"));
    if (kvs.size() != 2) {
      return -ERR_INVALID_REQUEST;
    }
    if (kvs[0] == "u") {
      endpoints = kvs[1];
    } else if (kvs[0] == "v") {
      vars = kvs[1];
    } else if (kvs[0] == "m") {
      method = kvs[1];
    }
  }
  if (vars.length() > 1024) return -ERR_INVALID_REQUEST;

  bufferlist end_bl;
  bufferlist temp;
  temp.append(endpoints.c_str(), endpoints.length());
  try {
    end_bl.decode_base64(temp);
  } catch (buffer::error& err) {
    return -ERR_INVALID_REQUEST;
  }

  endpoints = url_decode(end_bl.to_str());
  JSONParser parser;
  if (!parser.parse(endpoints.c_str(), endpoints.length()) || !parser.is_array()) {
    return -ERR_INVALID_REQUEST;
  }
  vector<string> v = parser.get_array_elements();

  string request_body;
  generate_callback_body(request_body, vars, etag, contentType);

  for (auto endpoint : v) {
    bool is_ssl = false;
    auto pos = endpoint.find("\"");
    if (pos == 0) endpoint = endpoint.substr(1);

    pos = endpoint.find_last_of("\"");
    if (pos == endpoint.length() - 1) endpoint = endpoint.substr(0, pos);

    if (boost::algorithm::starts_with(endpoint, "http://")) {
      endpoint = endpoint.substr(strlen("http://"));
    } else if (boost::algorithm::starts_with(endpoint, "https://")) {
      endpoint = endpoint.substr(strlen("https://"));
      is_ssl = true;
    }

    pos = endpoint.find('/');
    if (pos != endpoint.npos) {
      uri = endpoint.substr(pos);
      endpoint = endpoint.substr(0, pos);
    }
    if (is_ssl) port = 443;
    else port = 80;
    pos = endpoint.find(':');
    if (pos != endpoint.npos) {
      if (pos == endpoint.length() - 1) return -ERR_INVALID_REQUEST;

      string err;
      port = strict_strtol(endpoint.substr(pos+1).c_str(), 10, &err);
      if (!err.empty()) return -ERR_INVALID_REQUEST;

      endpoint = endpoint.substr(0, pos);
    }
    host = endpoint;

    ldout(s->cct, 25) << "send request to callback server:" << host
                      << ":" << port
                      << ", uri:" << uri
                      << ", request body:" << request_body << dendl;

    void **asio_ctx = (void **) s->asio_ctx;

    boost::asio::io_context ioc_temp;
    boost::asio::io_context *ioc;
#ifdef WITH_RADOSGW_BEAST_FRONTEND
    if (asio_ctx != NULL) {
      ioc = (boost::asio::io_service *) asio_ctx[0];
    } else
#endif
    {
      ioc = &ioc_temp;
    }
    ssl::context context(ssl::context::sslv23_client);
    // can't set verify peer!!!
    context.set_verify_mode(boost::asio::ssl::verify_none);

    std::shared_ptr<ssl::stream<tcp::socket> > stream = std::make_shared<ssl::stream<tcp::socket> >(*ioc, context);
    tcp::resolver resolver(*ioc);

    try {
      // Set SNI Hostname (many hosts need this to handshake successfully)
      if(! SSL_set_tlsext_host_name(stream->native_handle(), host.c_str())) {
        boost::system::error_code ec{static_cast<int>(::ERR_get_error()),
                                     boost::asio::error::get_ssl_category()};
        throw boost::system::system_error{ec};
      }

      auto const results = resolver.resolve(host, std::to_string(port));

      boost::asio::connect(stream->next_layer(), results.begin(), results.end());

      auto& socket = stream->lowest_layer();
      socket.set_option(tcp::no_delay(true));
#ifdef WITH_RADOSGW_BEAST_OPENSSL
      if (is_ssl) {
        stream->handshake(ssl::stream_base::client);
      }
#endif
    } catch (std::exception const& e) {
      ldout(s->cct, 0) << "ERROR: prepare connect catch error:"<< e.what() << dendl;
      result = -ERR_CALLBACK_FAILED;
      continue;
    }

#ifdef WITH_RADOSGW_BEAST_FRONTEND
    // only if with beast fronted, we'll try async send http request
    if (asio_ctx != NULL) {
      auto client = std::make_shared<RgwAsyncHttpClient>(stream, uri);
      SyncPoint sync(*((boost::asio::io_service *) asio_ctx[0]),
                     *((boost::asio::yield_context *) asio_ctx[1]));
      client->set_reqid(s->trans_id);
      client->set_ssl(is_ssl);
      client->set_cb(&sync, asio_send_http_cb);

      int ret = client->send_request(host, request_body, &s->response_body, method);
      if (ret != 0) {
        ldout(s->cct, 0) << "ERROR: send request to callback server err:" << ret
          << ", server:" << host << ":" << port << dendl;
        result = -ERR_CALLBACK_FAILED;
        continue;
      }

      ret = sync.get();
      if (ret != 0) {
        result = -ERR_CALLBACK_FAILED;
        continue;
      }
    } else
#endif
    {
      try {
        auto client = std::make_shared<RgwSyncHttpClient>(stream, uri);

        client->set_reqid(s->trans_id);
        client->set_ssl(is_ssl);

        int ret = client->send_request(host, request_body, &s->response_body, method);
        if (ret != 0) {
          ldout(s->cct, 0) << "ERROR: send request to callback server err:" << ret
            << ", server:" << host << ":" << port << dendl;
          result = -ERR_CALLBACK_FAILED;
          continue;
        }
      } catch (std::exception const& e) {
        ldout(s->cct, 0) << "ERROR: try send request catch error:"<< e.what() << dendl;
        result = -ERR_CALLBACK_FAILED;
        continue;
      }
    }
    result = 0;
    ldout(s->cct, 25) << "send request to callback server success, response:"
                      << s->response_body.to_str() << dendl;
    boost::system::error_code ec;
    if (is_ssl) {
      stream->lowest_layer().cancel();
      stream->shutdown(ec);
      if(ec && ec != boost::asio::error::eof &&
          !(ec.category() == boost::asio::error::get_ssl_category() &&
            ec.value() == ERR_PACK(ERR_LIB_SSL, 0, SSL_R_SHORT_READ))) {
        ldout(s->cct, 0) << "ERROR: shutdown stream error:"<< ec.message()
                         << ", request_id:" << s->trans_id << dendl;
        result = -ERR_CALLBACK_FAILED;
        continue;
      }
    } else {
      stream->next_layer().shutdown(tcp::socket::shutdown_both, ec);
      if(ec) {
        ldout(s->cct, 0) << "ERROR: shutdown socket error:"<< ec.message()
                         << ", request_id:" << s->trans_id << dendl;
        result = -ERR_CALLBACK_FAILED;
        continue;
      }
    }
    break;
  }
  return result;
}

void RGWOp::generate_callback_body(string& request_body, const string& vars,
    const string& etag, const string& contentType) {
  JSONFormatter f;
  f.open_object_section("");
  f.open_array_section("events");
  f.open_object_section("");

  f.dump_string("version", "1.0");
  f.dump_string("eventId", s->trans_id);

  auto time = ceph::to_iso_8601(ceph::real_clock::now());
  f.dump_string("eventTime", time);
  f.dump_string("eventSource", "bos:callback");

  string opType;
  switch (get_type()) {
    case RGW_OP_PUT_OBJ: opType = "PutObject"; break;
    case RGW_OP_POST_OBJ: opType = "PostObject"; break;
    case RGW_OP_COMPLETE_MULTIPART: opType = "CompleteMultipartUpload"; break;
    default: break;
  }
  f.dump_string("eventType", opType);

  f.open_object_section("content");
  f.dump_string("userId", s->user->user_id.id);
  f.dump_string("domain", s->info.host);
  f.dump_string("bucket", s->bucket.name);
  f.dump_string("object", s->object.name);
  f.dump_string("etag", etag);
  if (contentType.length() == 0) {
    f.dump_string("contentType", "binary/octet-stream");
  } else {
    f.dump_string("contentType", contentType);
  }
  f.dump_unsigned("filesize", s->content_length);
  f.dump_string("lastModified", time);
  f.close_section();

  f.dump_string("xVars", vars);
  f.close_section();
  f.close_section();
  f.close_section();

  std::ostringstream oss;
  f.flush(oss);
  request_body = oss.str();
}

void RGWOp::generate_notification_body(string& request_body, const string& vars, const string& etag)
{
  JSONFormatter f;
  f.open_object_section("");
  f.open_array_section("events");
  f.open_object_section("");

  f.dump_string("version", "1.0");
  f.dump_string("eventId", s->trans_id);

  string time = ceph::to_iso_8601(ceph::real_clock::now());
  size_t pos = time.find('.');
  if (pos != string::npos) {
    time = time.substr(0, pos) + 'Z';
  }

  f.dump_string("eventTime", time);
  f.dump_string("eventSource", "bos:notification");

  string opType;
  switch (get_type()) {
    case RGW_OP_PUT_OBJ: opType = "PutObject"; break;
    case RGW_OP_POST_OBJ: opType = "PostObject"; break;
    case RGW_OP_COMPLETE_MULTIPART: opType = "CompleteMultipartUpload"; break;
    case RGW_OP_DELETE_OBJ: opType = "DeleteObject"; break;
    case RGW_OP_DELETE_MULTI_OBJ: opType = "DeleteMultipleObjects"; break;
    case RGW_OP_COPY_OBJ: opType = "CopyObject"; break;
    default: break;
  }
  f.dump_string("eventType", opType);

  f.open_object_section("content");
  f.dump_string("userId", s->user->user_id.id);
  f.dump_string("ownerId", s->user->user_id.id);
  f.dump_string("domain", s->info.host);
  f.dump_string("bucket", s->bucket.name);
  f.dump_string("object", s->object.name);
  f.dump_string("etag", etag);
  f.dump_string("contentType", CONTENT_TYPE_JSON);

  f.dump_unsigned("filesize", s->content_length);
  f.dump_string("lastModified", time);
  f.dump_string("xVars", vars);
  f.close_section();

  f.close_section();
  f.close_section();
  f.close_section();

  std::ostringstream oss;
  f.flush(oss);
  request_body = oss.str();
}

int RGWOp::send_notification(rgw_notification_entry& entry, const string& etag)
{
  int result = 0;
  std::vector<rgw_notification_app>::iterator iter;

  for (iter = entry.apps.begin(); iter != entry.apps.end(); ++iter) {
    rgw_notification_app& app = *iter;
    string& url = app.eventurl;
    string& vars = app.xvars;

    string request_body;
    generate_notification_body(request_body, vars, etag);

    std::string endpoint = "";
    std::string host;
    uint32_t port;
    std::string uri = "";
    bool is_ssl = false;

    if ((url.substr(0, 7) == "http://")) {
      endpoint = url.substr(7);
    } else if ((url.substr(0, 8) == "https://")) {
      endpoint = url.substr(8);
      is_ssl = true;
    } else {
      dout(0) << __func__ << " ERROR: the input app url is invalid. url:" << url << dendl;
    }

    size_t pos = endpoint.find('/');
    if (pos != endpoint.npos) {
      uri = endpoint.substr(pos);
      endpoint = endpoint.substr(0, pos);
    }
    if (is_ssl) {
      port = HTTPS_PORT;
    } else {
      port = HTTP_PORT;
    }
    pos = endpoint.find(':');
    if (pos != endpoint.npos) {
      if (pos == endpoint.length() - 1) {
        return -ERR_NOTIFICATIONS_FORMAT_ERROR;
      }
      std::string err;
      port = strict_strtol(endpoint.substr(pos+1).c_str(), 10, &err);
      if (!err.empty()) {
        return -ERR_NOTIFICATIONS_FORMAT_ERROR;
      }
      endpoint = endpoint.substr(0, pos);
    }
    host = endpoint;

    ldout(s->cct, 10) << __func__ << " send request to notification server: "
                      << host << ":" << port << ", uri: " << uri
                      << ", request body:" << request_body << dendl;

    void **asio_ctx = (void **) s->asio_ctx;

    boost::asio::io_context ioc_temp;
    boost::asio::io_context *ioc;
#ifdef WITH_RADOSGW_BEAST_FRONTEND
    if (asio_ctx != NULL) {
      ioc = (boost::asio::io_service *) asio_ctx[0];
    } else
#endif
    {
      ioc = &ioc_temp;
    }
    ssl::context context(ssl::context::sslv23_client);
    // can't set verify peer!!!
    context.set_verify_mode(boost::asio::ssl::verify_none);

    std::shared_ptr<ssl::stream<tcp::socket> > stream = std::make_shared<ssl::stream<tcp::socket> >(*ioc, context);
    tcp::resolver resolver(*ioc);

    try {
      // Set SNI Hostname (many hosts need this to handshake successfully)
      if (!SSL_set_tlsext_host_name(stream->native_handle(), host.c_str())) {
        boost::system::error_code ec{static_cast<int>(::ERR_get_error()),
                                     boost::asio::error::get_ssl_category()};
        throw boost::system::system_error{ec};
      }

      auto const results = resolver.resolve(host, std::to_string(port));

      boost::asio::connect(stream->next_layer(), results.begin(), results.end());

      auto& socket = stream->lowest_layer();
      socket.set_option(tcp::no_delay(true));
#ifdef WITH_RADOSGW_BEAST_OPENSSL
      if (is_ssl) {
        stream->handshake(ssl::stream_base::client);
      }
#endif
    } catch (std::exception const& e) {
      ldout(s->cct, 0) << __func__ << "ERROR: prepare connect catch error:"<< e.what() << dendl;
      result = -ERR_NOTIFICATION_FAILED;
      continue;
    }

#ifdef WITH_RADOSGW_BEAST_FRONTEND
    // only if with beast fronted, we'll try async send http request
    if (asio_ctx != NULL) {
      auto client = std::make_shared<RgwAsyncHttpClient>(stream, uri);
      SyncPoint sync(*((boost::asio::io_service *) asio_ctx[0]),
                     *((boost::asio::yield_context *) asio_ctx[1]));
      client->set_reqid(s->trans_id);
      client->set_ssl(is_ssl);
      client->set_cb(&sync, asio_send_http_cb);

      int ret = client->send_request(host, request_body, &s->response_body, "post", CONTENT_TYPE_JSON);
      if (ret != 0) {
        ldout(s->cct, 10) << __func__ << "ERROR: send request to notification server err, ret=" << ret
          << ", server:" << host << ":" << port << dendl;
        result = -ERR_NOTIFICATION_FAILED;
        continue;
      }

      ret = sync.get();
      if (ret != 0) {
        result = -ERR_NOTIFICATION_FAILED;
        continue;
      }
    } else
#endif
    {
      try {
        auto client = std::make_shared<RgwSyncHttpClient>(stream, uri);

        client->set_reqid(s->trans_id);
        client->set_ssl(is_ssl);

        int ret = client->send_request(host, request_body, &s->response_body, "post", CONTENT_TYPE_JSON);
        if (ret != 0) {
          ldout(s->cct, 0) << __func__ << " ERROR: send request to notification server err, ret=" << ret
            << ", server:" << host << ":" << port << dendl;
          result = -ERR_NOTIFICATION_FAILED;
          continue;
        }
      } catch (std::exception const& e) {
        ldout(s->cct, 0) << __func__ << " ERROR: try send request catch exception, "<< e.what() << dendl;
        result = -ERR_NOTIFICATION_FAILED;
        continue;
      }
    }
    result = 0;
    ldout(s->cct, 25) << __func__ << " send request to notification server success, response:"
                      << s->response_body.to_str() << dendl;
    boost::system::error_code ec;
    if (is_ssl) {
      stream->lowest_layer().cancel();
      stream->shutdown(ec);
      if(ec && ec != boost::asio::error::eof &&
          !(ec.category() == boost::asio::error::get_ssl_category() &&
            ec.value() == ERR_PACK(ERR_LIB_SSL, 0, SSL_R_SHORT_READ))) {
        ldout(s->cct, 0) << __func__ << " ERROR: shutdown stream error:"<< ec.message()
                         << ", request_id:" << s->trans_id << dendl;
        result = -ERR_NOTIFICATION_FAILED;
        continue;
      }
    } else {
      stream->next_layer().shutdown(tcp::socket::shutdown_both, ec);
      if(ec) {
        ldout(s->cct, 0) << __func__ << " ERROR: shutdown socket error:"<< ec.message()
                         << ", request_id:" << s->trans_id << dendl;
        result = -ERR_NOTIFICATION_FAILED;
        continue;
      }
    }
    break;
  }
  return result;
}

int RGWOp::handle_notification(RGWNotification& n, const string& etag,
      string event, const string& obj_name, const string& bucket_name)
{
  int ret = 0;
  rgw_notification* notification = n.get_rgw_notification();
  std::vector<rgw_notification_entry>::iterator iter;

  for (iter = notification->notification.begin(); iter != notification->notification.end(); ++iter) {
    if (ret != 0) {
      break;
    }

    rgw_notification_entry& entry = *iter;
    if (entry.status == "disabled") {
      continue;
    }

    map<string, string>::const_iterator event_it = event_map.find(event);
    if (event_it != event_map.end()) {
      event = event_it->second;
    } else {
      ldout(s->cct, 10) << __func__ << " current op event is not in notification events, event=:" << event << dendl;
      break;
    }

    vector<string>::iterator it = find(entry.events.begin(), entry.events.end(), event);
    if (it == entry.events.end()) {
      continue;
    }

    bool is_send = false;
    for (std::string& e : entry.resource) {
      size_t pos = e.find('/');
      if (pos != 0) {
        std::string e_bucket = e.substr(0, pos);
        std::string e_obj = e.substr(pos+1);

        if (e_bucket != bucket_name) {
          continue;
        }
        if (!check_notification_object_match(obj_name, e_obj)) {
          continue;
        }
        is_send = true;
        break;
      } else {
        std::string e_obj = e.substr(1);
        if (!check_notification_object_match(obj_name, e_obj)) {
          continue;
        }
        is_send = true;
        break;
      }
    }
    if (is_send) {
      ret = send_notification(entry, etag);
      if (ret != 0) {
        break;
      }
    }
  }
  return ret;
}

int RGWOp::get_bucket_notification(bufferlist& notification_bl)
{
  auto attrs = s->bucket_attrs;
  map<string, bufferlist>::iterator aiter = attrs.find(RGW_ATTR_NOTIFICATION);
  if (aiter == attrs.end()) {
    return -ERR_NO_SUCH_BUCKET_NOTIFICATION;
  } else {
    bufferlist notification = attrs[RGW_ATTR_NOTIFICATION];
    if (notification.length() == 0) {
      return -ERR_NO_SUCH_BUCKET_NOTIFICATION;
    }
    notification_bl = notification;
  }
  return 0;
}

int RGWPostObj::verify_permission()
{
  return 0;
}

void RGWPostObj::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

void RGWPostObj::execute()
{
  RGWPutObjDataProcessor *filter = nullptr;
  boost::optional<RGWPutObj_Compress> compressor;
  CompressorRef plugin;
  char supplied_md5[CEPH_CRYPTO_MD5_DIGESTSIZE * 2 + 1];

  /* Read in the data from the POST form. */
  op_ret = get_params();
  if (op_ret < 0) {
    return;
  }

  op_ret = verify_params();
  if (op_ret < 0) {
    return;
  }

  if (s->iam_policy) {
    auto e = s->iam_policy->eval(s->env, *s->auth.identity,
				 rgw::IAM::s3PutObject,
				 rgw_obj(s->bucket, s->object));
    if (e == Effect::Deny) {
      op_ret = -EACCES;
      return;
    } else if (e == Effect::Pass && !verify_bucket_permission_no_policy(s, RGW_PERM_WRITE)) {
      op_ret = -EACCES;
      return;
    }
  } else if (!verify_bucket_permission_no_policy(s, RGW_PERM_WRITE)) {
    op_ret = -EACCES;
    return;
  }

  //verify bos obj lock
  rgw_obj target_obj(s->bucket, s->object);
  op_ret = worm_verify_bos_write(s, store, target_obj, s->bucket_info.bos_obj_lock, false);
  if (op_ret < 0) {
    ldout(s->cct, 0) << __func__ << "() ERRPR: verify bos write " << target_obj
                     << " err:" << op_ret << dendl;
    return;
  }

  // Namespace: it is make dir
  if (RGWRados::Bucket::Namespace::is_make_dir_request(s)) {
    // content-length must be 0
    if (s->content_length != 0) {
      ldout(s->cct, 1) << __func__ << " WARNING: the content-length of dir "
                       << s->object << " is not 0" << dendl;
      op_ret = ERR_INVALID_REQUEST;
    } else {
      op_ret = RGWRados::Bucket::Namespace::make_dir(store, s);
    }
    return;
  }

  /* Start iteration over data fields. It's necessary as Swift's FormPost
   * is capable to handle multiple files in single form. */
  do {
    std::unique_ptr<RGWPutObjDataProcessor> encrypt;
    char calc_md5[CEPH_CRYPTO_MD5_DIGESTSIZE * 2 + 1];
    unsigned char m[CEPH_CRYPTO_MD5_DIGESTSIZE];
    MD5 hash;
    ceph::buffer::list bl, aclbl;
    int len = 0;

    op_ret = store->check_quota(s->bucket_owner.get_id(),
                                s->bucket,
                                user_quota,
                                bucket_quota,
                                s->content_length);
    if (op_ret < 0) {
      return;
    }

    op_ret = store->check_bucket_shards(s->bucket_info, s->bucket, bucket_quota);
    if (op_ret < 0) {
      return;
    }

    if (supplied_md5_b64) {
      char supplied_md5_bin[CEPH_CRYPTO_MD5_DIGESTSIZE + 1];
      ldout(s->cct, 15) << "supplied_md5_b64=" << supplied_md5_b64 << dendl;
      op_ret = ceph_unarmor(supplied_md5_bin, &supplied_md5_bin[CEPH_CRYPTO_MD5_DIGESTSIZE + 1],
                            supplied_md5_b64, supplied_md5_b64 + strlen(supplied_md5_b64));
      ldout(s->cct, 15) << "ceph_armor ret=" << op_ret << dendl;
      if (op_ret != CEPH_CRYPTO_MD5_DIGESTSIZE) {
#ifdef WITH_BCEBOS
      if (s->prot_flags & RGW_REST_BOS) {
        op_ret = -ERR_BAD_DIGEST;
      } else
#endif
      {
        op_ret = -ERR_INVALID_DIGEST;
      }
        return;
      }

      buf_to_hex((const unsigned char *)supplied_md5_bin, CEPH_CRYPTO_MD5_DIGESTSIZE, supplied_md5);
      ldout(s->cct, 15) << "supplied_md5=" << supplied_md5 << dendl;
    }

    RGWPutObjProcessor_Atomic processor(*static_cast<RGWObjectCtx *>(s->obj_ctx),
                                        s->bucket_info,
                                        s->bucket,
                                        get_current_filename(),
                                        /* part size */
                                        s->cct->_conf->rgw_obj_stripe_size,
                                        s->req_id,
                                        s->bucket_info.versioning_enabled());
    processor.set_placement_rule(s->dest_placement);
    processor.set_olh_epoch(0);
    processor.set_skip_cache_flag(s->cct->_conf->rgw_enable_skip_cachepool);
    processor.set_file_shuntflow_size(s->cct->_conf->rgw_file_shuntflow_size);
    processor.set_content_length(s->cct->_conf->rgw_file_shuntflow_size);
    processor.set_unknown_actual_size(true);
    /* No filters by default. */
    filter = &processor;

    op_ret = processor.prepare(store, nullptr);
    if (op_ret < 0) {
      return;
    }

    op_ret = get_encrypt_filter(&encrypt, filter);
    if (op_ret < 0) {
      return;
    }
    if (encrypt != nullptr) {
      filter = encrypt.get();
    } else {
      const auto& compression_type = store->get_zone_params().get_compression_type(
          s->dest_placement);
      if (compression_type != "none") {
        plugin = Compressor::create(s->cct, compression_type);
        if (!plugin) {
          ldout(s->cct, 1) << "Cannot load plugin for compression type "
                           << compression_type << dendl;
        } else {
          compressor.emplace(s->cct, plugin, filter);
          filter = &*compressor;
        }
      }
    }

    bool again;
    bool bool_false = false;
    do {
      ceph::bufferlist data;
      len = get_data(data, again);

      if (len < 0) {
        op_ret = len;
        return;
      }

      if (!len) {
        break;
      }

      hash.Update((const unsigned char *)data.c_str(), data.length());
      op_ret = put_data_and_throttle(filter, data, ofs, bool_false);

      ofs += len;

      if (ofs > max_len) {
        op_ret = -ERR_TOO_LARGE;
        return;
      }
    } while (again);

    {
      bufferlist flush;
      op_ret = put_data_and_throttle(filter, flush, ofs, bool_false);
    }

    if (len < min_len) {
      op_ret = -ERR_TOO_SMALL;
      return;
    }

    s->obj_size = ofs;


    op_ret = store->check_quota(s->bucket_owner.get_id(), s->bucket,
                                user_quota, bucket_quota, s->obj_size);
    if (op_ret < 0) {
      return;
    }

    op_ret = store->check_bucket_shards(s->bucket_info, s->bucket, bucket_quota);
    if (op_ret < 0) {
      return;
    }

    hash.Final(m);
#ifdef WITH_BCEBOS
    bos_md5 = rgw::to_base64(boost::string_view((char *)m, sizeof(m)));
#endif
    buf_to_hex(m, CEPH_CRYPTO_MD5_DIGESTSIZE, calc_md5);

    etag = calc_md5;
 
    if (supplied_md5_b64 && strcmp(calc_md5, supplied_md5)) {
      op_ret = -ERR_BAD_DIGEST;
      return;
    }

    bl.append(etag.c_str(), etag.size());
    emplace_attr(RGW_ATTR_ETAG, std::move(bl));

    policy.encode(aclbl);
    emplace_attr(RGW_ATTR_ACL, std::move(aclbl));

    const std::string content_type = get_current_content_type();
    if (! content_type.empty()) {
      ceph::bufferlist ct_bl;
      ct_bl.append(content_type.c_str(), content_type.size() + 1);
      emplace_attr(RGW_ATTR_CONTENT_TYPE, std::move(ct_bl));
    }

    if (compressor && compressor->is_compressed()) {
      ceph::bufferlist tmp;
      RGWCompressionInfo cs_info;
      cs_info.compression_type = plugin->get_type_name();
      cs_info.orig_size = s->obj_size;
      cs_info.blocks = move(compressor->get_compression_blocks());
      encode(cs_info, tmp);
      emplace_attr(RGW_ATTR_COMPRESSION, std::move(tmp));
    }

    if (obj_legal_hold) {
    bufferlist obj_legal_hold_bl;
    obj_legal_hold->encode(obj_legal_hold_bl);
    emplace_attr(RGW_ATTR_OBJECT_LEGAL_HOLD, std::move(obj_legal_hold_bl));
  }
  if (obj_retention) {
    bufferlist obj_retention_bl;
    obj_retention->encode(obj_retention_bl);
    emplace_attr(RGW_ATTR_OBJECT_RETENTION, std::move(obj_retention_bl));
  }

    op_ret = processor.complete(s->obj_size, etag, nullptr, real_time(),
                                attrs, (delete_at ? *delete_at : real_time()));
  } while (is_next_file_to_upload());

  if (op_ret == 0) {
    op_ret = process_callback(etag, attrs[RGW_ATTR_CONTENT_TYPE].to_str());

    bufferlist notification_bl;
    if (get_bucket_notification(notification_bl) == 0) {
      RGWNotification n;
      op_ret = n.decode_notification_bl(notification_bl);
      if (op_ret != 0) return;
      int notification_ret = handle_notification(n, etag, name(), s->object.name, s->bucket_name);
      if (notification_ret != 0) {
        op_ret = notification_ret;
      }
    }
  }
}


void RGWPutMetadataAccount::filter_out_temp_url(map<string, bufferlist>& add_attrs,
                                                const set<string>& rmattr_names,
                                                map<int, string>& temp_url_keys)
{
  map<string, bufferlist>::iterator iter;

  iter = add_attrs.find(RGW_ATTR_TEMPURL_KEY1);
  if (iter != add_attrs.end()) {
    temp_url_keys[0] = iter->second.c_str();
    add_attrs.erase(iter);
  }

  iter = add_attrs.find(RGW_ATTR_TEMPURL_KEY2);
  if (iter != add_attrs.end()) {
    temp_url_keys[1] = iter->second.c_str();
    add_attrs.erase(iter);
  }

  for (const string& name : rmattr_names) {
    if (name.compare(RGW_ATTR_TEMPURL_KEY1) == 0) {
      temp_url_keys[0] = string();
    }
    if (name.compare(RGW_ATTR_TEMPURL_KEY2) == 0) {
      temp_url_keys[1] = string();
    }
  }
}

int RGWPutMetadataAccount::init_processing()
{
  /* First, go to the base class. At the time of writing the method was
   * responsible only for initializing the quota. This isn't necessary
   * here as we are touching metadata only. I'm putting this call only
   * for the future. */
  op_ret = RGWOp::init_processing();
  if (op_ret < 0) {
    return op_ret;
  }

  op_ret = get_params();
  if (op_ret < 0) {
    return op_ret;
  }

  op_ret = rgw_get_user_attrs_by_uid(store, s->user->user_id, orig_attrs,
                                     &acct_op_tracker);
  if (op_ret < 0) {
    return op_ret;
  }

  if (has_policy) {
    bufferlist acl_bl;
    policy.encode(acl_bl);
    attrs.emplace(RGW_ATTR_ACL, std::move(acl_bl));
  }

  op_ret = rgw_get_request_metadata(s->cct, s->info, attrs, false);
  if (op_ret < 0) {
    return op_ret;
  }
  prepare_add_del_attrs(orig_attrs, rmattr_names, attrs);
  populate_with_generic_attrs(s, attrs);

  /* Try extract the TempURL-related stuff now to allow verify_permission
   * evaluate whether we need FULL_CONTROL or not. */
  filter_out_temp_url(attrs, rmattr_names, temp_url_keys);

  /* The same with quota except a client needs to be reseller admin. */
  op_ret = filter_out_quota_info(attrs, rmattr_names, new_quota,
                                 &new_quota_extracted);
  if (op_ret < 0) {
    return op_ret;
  }

  return 0;
}

int RGWPutMetadataAccount::verify_permission()
{
  if (s->auth.identity->is_anonymous()) {
    return -EACCES;
  }

  if (!verify_user_permission(s, RGW_PERM_WRITE)) {
    return -EACCES;
  }

  /* Altering TempURL keys requires FULL_CONTROL. */
  if (!temp_url_keys.empty() && s->perm_mask != RGW_PERM_FULL_CONTROL) {
    return -EPERM;
  }

  /* We are failing this intensionally to allow system user/reseller admin
   * override in rgw_process.cc. This is the way to specify a given RGWOp
   * expect extra privileges.  */
  if (new_quota_extracted) {
    return -EACCES;
  }

  return 0;
}

void RGWPutMetadataAccount::execute()
{
  /* Params have been extracted earlier. See init_processing(). */
  RGWUserInfo new_uinfo;
  op_ret = rgw_get_user_info_by_uid(store, s->user->user_id, new_uinfo,
                                    &acct_op_tracker);
  if (op_ret < 0) {
    return;
  }

  /* Handle the TempURL-related stuff. */
  if (!temp_url_keys.empty()) {
    for (auto& pair : temp_url_keys) {
      new_uinfo.temp_url_keys[pair.first] = std::move(pair.second);
    }
  }

  /* Handle the quota extracted at the verify_permission step. */
  if (new_quota_extracted) {
    new_uinfo.user_quota = std::move(new_quota);
  }

  /* We are passing here the current (old) user info to allow the function
   * optimize-out some operations. */
  op_ret = rgw_store_user_info(store, new_uinfo, s->user,
                               &acct_op_tracker, real_time(), false, &attrs);
}

int RGWPutMetadataBucket::verify_permission()
{
  if (!verify_bucket_permission_no_policy(s, RGW_PERM_WRITE)) {
    return -EACCES;
  }

  return 0;
}

void RGWPutMetadataBucket::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

void RGWPutMetadataBucket::execute()
{
  op_ret = get_params();
  if (op_ret < 0) {
    return;
  }

  op_ret = rgw_get_request_metadata(s->cct, s->info, attrs, false);
  if (op_ret < 0) {
    return;
  }

  if (!placement_rule.empty() &&
      placement_rule.name != s->bucket_info.head_placement_rule.name) {
    op_ret = -EEXIST;
    return;
  }

  op_ret = retry_raced_bucket_write(store, s, [this] {
      /* Encode special metadata first as we're using std::map::emplace under
       * the hood. This method will add the new items only if the map doesn't
       * contain such keys yet. */
      if (has_policy) {
	if (s->dialect.compare("swift") == 0) {
	  auto old_policy =						\
	    static_cast<RGWAccessControlPolicy_SWIFT*>(s->bucket_acl.get());
	  auto new_policy = static_cast<RGWAccessControlPolicy_SWIFT*>(&policy);
	  new_policy->filter_merge(policy_rw_mask, old_policy);
	  policy = *new_policy;
	}
	buffer::list bl;
	policy.encode(bl);
	emplace_attr(RGW_ATTR_ACL, std::move(bl));
      }

      if (has_cors) {
	buffer::list bl;
	cors_config.encode(bl);
	emplace_attr(RGW_ATTR_CORS, std::move(bl));
      }

      /* It's supposed that following functions WILL NOT change any
       * special attributes (like RGW_ATTR_ACL) if they are already
       * present in attrs. */
      prepare_add_del_attrs(s->bucket_attrs, rmattr_names, attrs);
      populate_with_generic_attrs(s, attrs);

      /* According to the Swift's behaviour and its container_quota
       * WSGI middleware implementation: anyone with write permissions
       * is able to set the bucket quota. This stays in contrast to
       * account quotas that can be set only by clients holding
       * reseller admin privileges. */
      op_ret = filter_out_quota_info(attrs, rmattr_names, s->bucket_info.quota);
      if (op_ret < 0) {
	return op_ret;
      }

      if (swift_ver_location) {
	s->bucket_info.swift_ver_location = *swift_ver_location;
	s->bucket_info.swift_versioning = (!swift_ver_location->empty());
      }

      /* Web site of Swift API. */
      filter_out_website(attrs, rmattr_names, s->bucket_info.website_conf);
      s->bucket_info.has_website = !s->bucket_info.website_conf.is_empty();

      /* Setting attributes also stores the provided bucket info. Due
       * to this fact, the new quota settings can be serialized with
       * the same call. */
      op_ret = rgw_bucket_set_attrs(store, s->bucket_info, attrs,
				    &s->bucket_info.objv_tracker);
      return op_ret;
    });
}

int RGWPutMetadataObject::verify_permission()
{
  // This looks to be something specific to Swift. We could add
  // operations like swift:PutMetadataObject to the Policy Engine.
  if (!verify_object_permission_no_policy(s, RGW_PERM_WRITE)) {
    return -EACCES;
  }

  return 0;
}

void RGWPutMetadataObject::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

void RGWPutMetadataObject::execute()
{
  rgw_obj obj(s->bucket, s->object);
  map<string, bufferlist> attrs, orig_attrs, rmattrs;

  store->set_atomic(s->obj_ctx, obj);

  op_ret = get_params();
  if (op_ret < 0) {
    return;
  }

  op_ret = rgw_get_request_metadata(s->cct, s->info, attrs);
  if (op_ret < 0) {
    return;
  }

  /* check if obj exists, read orig attrs */
  op_ret = get_obj_attrs(store, s, obj, orig_attrs);
  if (op_ret < 0) {
    return;
  }

  /* Check whether the object has expired. Swift API documentation
   * stands that we should return 404 Not Found in such case. */
  if (need_object_expiration() && object_is_expired(orig_attrs)) {
    op_ret = -ENOENT;
    return;
  }

  /* Filter currently existing attributes. */
  prepare_add_del_attrs(orig_attrs, attrs, rmattrs);
  populate_with_generic_attrs(s, attrs);
  encode_delete_at_attr(delete_at, attrs);

  if (dlo_manifest) {
    op_ret = encode_dlo_manifest_attr(dlo_manifest, attrs);
    if (op_ret < 0) {
      ldout(s->cct, 0) << "bad user manifest: " << dlo_manifest << dendl;
      return;
    }
  }

  op_ret = store->set_attrs(s->obj_ctx, s->bucket_info, obj, attrs, &rmattrs);
}

int RGWDeleteObj::handle_slo_manifest(bufferlist& bl)
{
  RGWSLOInfo slo_info;
  bufferlist::iterator bliter = bl.begin();
  try {
    decode(slo_info, bliter);
  } catch (buffer::error& err) {
    ldout(s->cct, 0) << "ERROR: failed to decode slo manifest" << dendl;
    return -EIO;
  }

  try {
    deleter = std::unique_ptr<RGWBulkDelete::Deleter>(\
          new RGWBulkDelete::Deleter(store, s));
  } catch (const std::bad_alloc&) {
    return -ENOMEM;
  }

  list<RGWBulkDelete::acct_path_t> items;
  for (const auto& iter : slo_info.entries) {
    const string& path_str = iter.path;

    const size_t sep_pos = path_str.find('/', 1 /* skip first slash */);
    if (boost::string_view::npos == sep_pos) {
      return -EINVAL;
    }

    RGWBulkDelete::acct_path_t path;

    path.bucket_name = url_decode(path_str.substr(1, sep_pos - 1));
    path.obj_key = url_decode(path_str.substr(sep_pos + 1));

    items.push_back(path);
  }

  /* Request removal of the manifest object itself. */
  RGWBulkDelete::acct_path_t path;
  path.bucket_name = s->bucket_name;
  path.obj_key = s->object;
  items.push_back(path);

  int ret = deleter->delete_chunk(items);
  if (ret < 0) {
    return ret;
  }

  return 0;
}

int RGWDeleteObj::verify_permission()
{
  int op_ret = get_params();
  if (op_ret) {
    return op_ret;
  }
  if (s->iam_policy) {
    if (s->bucket_info.obj_lock_enabled() && bypass_governance_mode) {
      auto r = s->iam_policy->eval(s->env, *s->auth.identity, rgw::IAM::s3BypassGovernanceRetention,
                                       ARN(s->bucket, s->object.name));
      if (r == Effect::Deny) {
        bypass_perm = false;
      }
    }

    auto r = s->iam_policy->eval(s->env, *s->auth.identity,
				 s->object.instance.empty() ?
				 rgw::IAM::s3DeleteObject :
				 rgw::IAM::s3DeleteObjectVersion,
				 ARN(s->bucket, s->object.name));
    if (r == Effect::Allow)
      return 0;
    else if (r == Effect::Deny)
      return -EACCES;
  }

  if (!verify_bucket_permission_no_policy(s, RGW_PERM_WRITE)) {
    return -EACCES;
  }

  if (s->bucket_info.mfa_enabled() &&
      !s->object.instance.empty() &&
      !s->mfa_verified) {
    ldout(s->cct, 5) << "NOTICE: object delete request with a versioned object, mfa auth not provided" << dendl;
    return -ERR_MFA_REQUIRED;
  }

  return 0;
}

void RGWDeleteObj::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

void RGWDeleteObj::execute()
{
  if (!s->bucket_exists) {
    op_ret = -ERR_NO_SUCH_BUCKET;
    return;
  }
  if (s->object.empty()) {
    op_ret = -EINVAL;
    return;
  }

  rgw_obj obj(s->bucket, s->object);
  map<string, bufferlist> attrs;
  bool translate_to_trash = false;

  if (!s->bucket_info.trash_dir.empty() &&
      !boost::algorithm::starts_with(obj.key.name, s->bucket_info.trash_dir)) {
    if (s->bucket_info.trash_dir.length() + obj.key.name.length() > MAX_OBJ_NAME_LEN) {
      ldout(s->cct, 0) << __func__ << "() NOTICE: object name with trash dir is too long:" << obj << dendl;
      op_ret = -ERR_INVALID_OBJECT_NAME;
      return;
    }
    translate_to_trash = true;
    // translate delete into rename to trash obj, need prefetch data in head obj
    store->set_prefetch_data(s->obj_ctx, obj);
  }
  bool check_obj_lock = obj.key.have_instance() && s->bucket_info.obj_lock_enabled();
  ceph::real_time mtime;
  op_ret = get_obj_attrs(store, s, obj, attrs, &mtime);

  if (need_object_expiration() || multipart_delete) {
    /* check if obj exists, read orig attrs */
    if (op_ret < 0) {
      return;
    }
  }

  if (check_obj_lock) {
    /* check if obj exists, read orig attrs */
    if (op_ret < 0) {
      if (op_ret == -ENOENT) {
        /* object maybe delete_marker, skip check_obj_lock*/
        check_obj_lock = false;
      } else {
        return;
      }
    }
  }

  if (check_obj_lock) {
    op_ret = verify_object_lock(s->cct, attrs, bypass_perm,
                                bypass_governance_mode, mtime);
    if (op_ret < 0) {
      return;
    }
  }

  //verify bos obj lock
  op_ret = worm_verify_bos_write(s, store, obj, s->bucket_info.bos_obj_lock, true);
  if (op_ret < 0) {
    ldout(s->cct, 0) << __func__ << "() ERROR: verify bos delete " << obj
                     << " err:" << op_ret << dendl;
    return;
  }

  if (multipart_delete) {
    const auto slo_attr = attrs.find(RGW_ATTR_SLO_MANIFEST);

    if (slo_attr != attrs.end()) {
      op_ret = handle_slo_manifest(slo_attr->second);
      if (op_ret < 0) {
        ldout(s->cct, 0) << "ERROR: failed to handle slo manifest ret=" << op_ret << dendl;
      }
    } else {
      op_ret = -ERR_NOT_SLO_MANIFEST;
    }

    return;
  }

  RGWObjectCtx *obj_ctx = static_cast<RGWObjectCtx *>(s->obj_ctx);
  obj_ctx->obj.set_atomic(obj);

  bool ver_restored = false;
  op_ret = store->swift_versioning_restore(*obj_ctx, s->bucket_owner.get_id(),
                                           s->bucket_info, obj, ver_restored,
                                           user_quota, bucket_quota);
  if (op_ret < 0) {
    return;
  }

  // bucket trash: if bucket have trash dir, put object to trash.
  if (translate_to_trash) {
    auto dst_object = rgw_obj_key(s->bucket_info.trash_dir + obj.key.name);
    rgw_obj dst_obj(s->bucket, dst_object);
    obj_ctx->obj.set_atomic(dst_obj);

    op_ret = store->rename_obj(*obj_ctx, obj, dst_obj, s->bucket_info);
    if (op_ret < 0) {
      ldout(s->cct, 0) << __func__ << "() ERROR: trash obj failed. return:" << op_ret << dendl;
    }
    ldout(s->cct, 10) << __func__ << "NOTICE: trash obj " << obj << " ret=" << op_ret << dendl;
    return;
  }

  if (!ver_restored) {
    /* Swift's versioning mechanism hasn't found any previous version of
     * the object that could be restored. This means we should proceed
     * with the regular delete path. */
    RGWRados::Object del_target(store, s->bucket_info, *obj_ctx, obj);
    RGWRados::Object::Delete del_op(&del_target);

    op_ret = get_system_versioning_params(s, &del_op.params.olh_epoch,
                                          &del_op.params.marker_version_id);
    if (op_ret < 0) {
      return;
    }

    del_op.params.bucket_owner = s->bucket_owner.get_id();
    del_op.params.versioning_status = s->bucket_info.versioning_status();
    del_op.params.obj_owner = s->owner;
    del_op.params.unmod_since = unmod_since;
    del_op.params.high_precision_time = s->system_request; /* system request uses high precision time */

    op_ret = del_op.delete_obj();
    if (op_ret >= 0) {
      delete_marker = del_op.result.delete_marker;
      version_id = del_op.result.version_id;
    }

    /* Check whether the object has expired. Swift API documentation
     * stands that we should return 404 Not Found in such case. */
    if (need_object_expiration() && object_is_expired(attrs)) {
      op_ret = -ENOENT;
      return;
    }
  }

  if (op_ret == -ECANCELED) {
    op_ret = 0;
  }
  if (op_ret == -ERR_PRECONDITION_FAILED && no_precondition_error) {
    op_ret = 0;
  }

  if (op_ret == 0) {
    string etag = "";
    const auto etag_attr = attrs.find(RGW_ATTR_ETAG);
    if (etag_attr != attrs.end()) {
      bufferlist etag_bl = etag_attr->second;
      etag = rgw_bl_to_str(etag_bl);
    }

    bufferlist notification_bl;
    if (get_bucket_notification(notification_bl) == 0) {
      RGWNotification n;
      op_ret = n.decode_notification_bl(notification_bl);
      if (op_ret != 0) return;
      int notification_ret = handle_notification(n, etag, name(), s->object.name, s->bucket_name);
      if (notification_ret != 0) {
        op_ret = notification_ret;
      }
    }
  }
}

// just judge bucket permission, dst obj only judge by bucket permission,
// but, we need read ahead src obj attr, to fetch manifest in RENAME_INFO
// only prefetch data for getobj op
int RGWRenameObj::verify_permission() {
  RGWAccessControlPolicy src_acl(s->cct);
  boost::optional<Policy> src_policy;

  op_ret = get_params();
  if (op_ret < 0) {
    ldout(s->cct, 10) << __func__ << "(): get_params error:" << op_ret << dendl;
    return op_ret;
  }

  map<string, bufferlist> src_attrs;

  RGWObjectCtx& obj_ctx = *static_cast<RGWObjectCtx *>(s->obj_ctx);

  if (s->bucket_instance_id.empty()) {
    op_ret = store->get_bucket_info(obj_ctx, s->user->user_id.tenant, s->bucket.name,
                                    s->bucket_info, NULL, &src_attrs);
  } else {
    /* will only happen in intra region sync where the source and dest bucket is the same */
    op_ret = store->get_bucket_instance_info(obj_ctx, s->bucket_instance_id,
                                             s->bucket_info, NULL, &src_attrs);
  }

  if (op_ret < 0) {
    ldout(s->cct, 0) << __func__ << "() ERROR: get bucket " << s->bucket_info.bucket
                     << " info error:" << op_ret << dendl;
    if (op_ret == -ENOENT) {
      op_ret = -ERR_NO_SUCH_BUCKET;
    }
    return op_ret;
  }

  if ((s->bucket_info.versioning_status() & (BUCKET_VERSIONED | BUCKET_VERSIONS_SUSPENDED))) {
    ldout(s->cct, 0) << __func__ << "() ERROR: rename not work with versioning " << s->bucket_info.bucket << dendl;
    op_ret = -ERR_METHOD_NOT_ALLOWED;
    return op_ret;
  }

  if (s->bucket_info.namespace_type == BUCKET_NAMESPACE_ENABLE) {
    ldout(s->cct, 0) << __func__ << "() ERROR: rename not work with namespace " << s->bucket_info.bucket << dendl;
    op_ret = -ERR_METHOD_NOT_ALLOWED;
    return op_ret;
  }

  bool src_bucket_allow = true;
  RGWAccessControlPolicy src_bucket_policy(s->cct);

  //rgw_obj src_obj(s->bucket, s->object);
  rgw_obj src_obj(s->bucket, src_object);
  rgw_obj_key src_obj_key(src_object);
  store->set_atomic(s->obj_ctx, src_obj);
  store->set_prefetch_data(s->obj_ctx, src_obj);

  /* check src bucket permissions */
  op_ret = read_bucket_policy(store, s, s->bucket_info, src_attrs,
                              &src_bucket_policy, s->bucket);
  if (op_ret < 0) {
    ldout(s->cct, 0) << __func__ << "() ERROR: read_bucket_policy " << s->bucket_info.bucket
                     << " error:" << op_ret << dendl;
    return op_ret;
  }

  // judge 1 : src need delete permission
  auto src_iam_policy = get_iam_policy_from_attr(s->cct, store, src_attrs, s->bucket.tenant);
  /* admin request overrides permission checks */
  if (! s->auth.identity->is_admin_of(src_bucket_policy.get_owner().get_id())){
    if (src_iam_policy != boost::none) {

      auto e = src_iam_policy->eval(s->env, *s->auth.identity,
                                     rgw::IAM::s3DeleteObject, ARN(src_obj));
      if (e == Effect::Deny) {
         src_bucket_allow = false;
         ldout(s->cct, 5) << __func__ << "(): deny delete_obj by bucket policy" << dendl;
         ldout(s->cct, 5) << __func__ << "(): bucket policy not allow delete, try verify obj acl" << dendl;
      } else if (e == Effect::Pass &&
                 ! src_bucket_policy.verify_permission(*s->auth.identity,
                                                       s->perm_mask,
                                                       RGW_PERM_WRITE)){
        ldout(s->cct, 5) << __func__ << "(): bucket acl not allow delete, try verify obj acl" << dendl;
        src_bucket_allow = false;
      }
    } else if (! src_bucket_policy.verify_permission(*s->auth.identity,
                                                     s->perm_mask,
                                                     RGW_PERM_WRITE)) {
      ldout(s->cct, 5) << __func__ << "(): bucket acl not allow delete, try verify obj acl" << dendl;
      src_bucket_allow = false;
    }
  }
  // src need delete permission -> judge src object permission
  if (!src_bucket_allow) {

    op_ret = read_obj_policy(store, s, s->bucket_info, src_attrs, &src_acl, src_policy,
                             s->bucket, src_obj_key);
    if (op_ret < 0) {
      if (op_ret == -ENOENT) {
        ldout(s->cct, 5) << __func__ << "(): src obj not exist" << dendl;
      } else {
        ldout(s->cct, 0) << __func__ << "() ERROR: read src obj policy error:" << op_ret << dendl;
      }
      return op_ret;
    }

    if (!s->auth.identity->is_admin_of(src_acl.get_owner().get_id())) {
      if (src_policy) {
        auto e = src_policy->eval(s->env, *s->auth.identity,
                                  rgw::IAM::s3DeleteObject,
                                  ARN(src_obj));
        if (e == Effect::Deny) {
          ldout(s->cct, 5) << __func__ << "(): deny read by src policy" << dendl;
          return -EACCES;
        } else if (e == Effect::Pass &&
             !src_acl.verify_permission(*s->auth.identity, s->perm_mask,
                      RGW_PERM_WRITE)) {
          ldout(s->cct, 5) << __func__ << "(): deny read by src acl with policy pass" << dendl;
          return -EACCES;
        }
      } else if (!src_acl.verify_permission(*s->auth.identity,
                 s->perm_mask, RGW_PERM_WRITE)) {
        ldout(s->cct, 5) << __func__ << "(): deny read by src acl without policy" << dendl;
        return -EACCES;
      }
    }
  }

  src_bucket_allow = true;

  // judge 2 : src need get permission
  if (! s->auth.identity->is_admin_of(src_bucket_policy.get_owner().get_id())){
    if (src_iam_policy != boost::none) {

      auto e = src_iam_policy->eval(s->env, *s->auth.identity,
                                     rgw::IAM::s3GetObject, ARN(src_obj));
      if (e == Effect::Deny) {
        src_bucket_allow = false;
        ldout(s->cct, 5) << __func__ << "(): bucket policy not allow read, try verify obj acl" << dendl;
      } else if (e == Effect::Pass &&
                 ! src_bucket_policy.verify_permission(*s->auth.identity,
                                                       s->perm_mask,
                                                       RGW_PERM_READ)){
        ldout(s->cct, 5) << __func__ << "(): bucket acl not allow read, try verify obj acl" << dendl;
        src_bucket_allow = false;
      }
    } else if (! src_bucket_policy.verify_permission(*s->auth.identity,
                                                     s->perm_mask,
                                                     RGW_PERM_READ)) {
      ldout(s->cct, 5) << __func__ << "(): bucket acl not allow read without policy"
                       << ", try verify obj acl" << dendl;
      src_bucket_allow = false;
    }
  }
  // src need get permission -> judge src object permission
  if (!src_bucket_allow) {
    if (!s->auth.identity->is_admin_of(src_acl.get_owner().get_id())) {
      if (src_policy) {
        auto e = src_policy->eval(s->env, *s->auth.identity,
                                  rgw::IAM::s3GetObject,
                                  ARN(src_obj));
        if (e == Effect::Deny) {
          ldout(s->cct, 5) << __func__ << "(): deny read by src policy" << dendl;
          return -EACCES;
        } else if (e == Effect::Pass &&
             !src_acl.verify_permission(*s->auth.identity,
                                        s->perm_mask,
                                        RGW_PERM_READ)) {
          ldout(s->cct, 5) << __func__ << "(): deny read by src acl with policy pass" << dendl;
          return -EACCES;
        }
      } else if (!src_acl.verify_permission(*s->auth.identity,
                                            s->perm_mask,
                                            RGW_PERM_READ)) {
        ldout(s->cct, 5) << __func__ << "(): deny read by src acl without policy" << dendl;
        return -EACCES;
      }
    }
  }

  rgw_obj dest_obj(s->bucket_info.bucket, s->object);
  store->set_atomic(s->obj_ctx, dest_obj);

  /* admin request overrides permission checks */
  if (! s->auth.identity->is_admin_of(src_bucket_policy.get_owner().get_id())){
    if (src_iam_policy != boost::none) {
      auto e = src_iam_policy->eval(s->env, *s->auth.identity,
                                    rgw::IAM::s3PutObject, ARN(dest_obj));
      if (e == Effect::Deny) {
        ldout(s->cct, 5) << __func__ << "(): deny put by bucket policy" << dendl;
        return -EACCES;
      } else if (e == Effect::Pass &&
                 ! src_bucket_policy.verify_permission(*s->auth.identity,
                                                       s->perm_mask,
                                                       RGW_PERM_WRITE)){
        ldout(s->cct, 5) << __func__ << "(): deny put by bucket acl with policy pass" << dendl;
        return -EACCES;
      }
    } else if (! src_bucket_policy.verify_permission(*s->auth.identity,
                                                     s->perm_mask,
                                                     RGW_PERM_WRITE)) {
      ldout(s->cct, 5) << __func__ << "(): deny put by bucket acl without policy" << dendl;
      return -EACCES;
    }
  }
  return 0;
}

void RGWRenameObj::pre_exec() {
  rgw_bucket_object_pre_exec(s);
}


void RGWRenameObj::execute() {
  rgw_obj src_obj(s->bucket, src_object);
  rgw_obj dst_obj(s->bucket, s->object);

  RGWObjectCtx& obj_ctx = *static_cast<RGWObjectCtx *>(s->obj_ctx);
  obj_ctx.obj.set_atomic(src_obj);
  obj_ctx.obj.set_atomic(dst_obj);

  // Donot verify src bos obj lock
  // because for bucket worm, we can rename src object to dst object when dst obj don't exist

  //verify bos obj lock
  op_ret = worm_verify_bos_write(s, store, dst_obj, s->bucket_info.bos_obj_lock, false);
  if (op_ret < 0) {
    ldout(s->cct, 0) << __func__ << "() ERROR: worm verify bos write "
                     << dst_obj << " err=" << op_ret << dendl;
    return;
  }

  op_ret = store->rename_obj(obj_ctx,
                             src_obj,
                             dst_obj,
                             s->bucket_info);
  if (op_ret < 0) {
    ldout(s->cct, 0) << __func__ << "() ERROR: rename_obj return:" << op_ret << dendl;
  }
  return;
}

int RGWGetBucketTrash::verify_permission()
{
  if (!s->auth.identity->is_owner_of(s->bucket_info.owner)) {
    return -EACCES;
  }
  return 0;
}

void RGWGetBucketTrash::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

int RGWPutBucketTrash::verify_permission()
{
  if (!s->auth.identity->is_owner_of(s->bucket_info.owner)) {
    return -EACCES;
  }
  if ((s->bucket_info.versioning_status() & (BUCKET_VERSIONED | BUCKET_VERSIONS_SUSPENDED))) {
    ldout(s->cct, 0) << __func__ << "() ERROR: trash not work with versioning " << s->bucket_info.bucket << dendl;
    op_ret = -ERR_METHOD_NOT_ALLOWED;
    return op_ret;
  }
  return 0;
}

void RGWPutBucketTrash::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

void RGWPutBucketTrash::execute()
{
  op_ret = get_params();
  if (op_ret < 0) {
    return;
  }

  if (trash_dir.empty()) {
    trash_dir = s->cct->_conf->rgw_default_trash_dir;
  }

  if (trash_dir.size() > 1024) {
    ldout(s->cct, 0) << __func__ << "() ERROR: trash dir size more than 1024. " << dendl;
    op_ret = -ERR_TOO_LARGE;
  }

  for (size_t i = 0; i < trash_dir.length(); ++i) {
    // chinese word contain two char, each is & 0x80
    if (trash_dir[i] & 0x80) {
      if (i == trash_dir.length() - 1 || !(trash_dir[++i] & 0x80)) {
        ldout(s->cct, 0) << __func__ << "() NOTICE: invalid trash dir name with chinese word:" << trash_dir << dendl;
        op_ret = -ERR_INVAL_TRASH_DIR_NAME;
        return;
      }
      continue;
    }
    if ((trash_dir[i] > '9' || trash_dir[i] < '0') &&
        (trash_dir[i] > 'z' || trash_dir[i] < 'a') &&
        (trash_dir[i] > 'Z' || trash_dir[i] < 'A') &&
        trash_dir[i] != '_' && trash_dir[i] != '-' && trash_dir[i] != '.') {
      ldout(s->cct, 0) << __func__ << "() NOTICE: invalid trash dir name: " << trash_dir << dendl;
      op_ret = -ERR_INVAL_TRASH_DIR_NAME;
      return;
    }
  }

  op_ret = retry_raced_bucket_write(store, s, [this] {
    s->bucket_info.trash_dir = trash_dir + '/';
    op_ret = store->put_bucket_instance_info(s->bucket_info, false, real_time(), &s->bucket_attrs);
    if (op_ret < 0) {
      ldout(s->cct, 20) << __func__ << "() ERRPR: put_bucket_info on bucket=" << s->bucket.name
                        << " returned err=" << op_ret << dendl;
    }
    return op_ret;
  });
}

int RGWDeleteBucketTrash::verify_permission()
{
  if (!s->auth.identity->is_owner_of(s->bucket_info.owner)) {
    return -EACCES;
  }
  return 0;
}

void RGWDeleteBucketTrash::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

void RGWDeleteBucketTrash::execute()
{
  op_ret = retry_raced_bucket_write(store, s, [this] {
    s->bucket_info.trash_dir.clear();
    op_ret = store->put_bucket_instance_info(s->bucket_info, false, real_time(), &s->bucket_attrs);
    if (op_ret < 0) {
      ldout(s->cct, 20) << __func__ << "() ERRPR: put_bucket_info on bucket=" << s->bucket.name
                        << " returned err=" << op_ret << dendl;
    }
    return op_ret;
  });
}

bool RGWCopyObj::parse_copy_location(const boost::string_view& url_src,
				     string& bucket_name,
				     rgw_obj_key& key)
{
  boost::string_view name_str;
  boost::string_view params_str;

  size_t pos = url_src.rfind('?');
  if (pos == string::npos) {
    name_str = url_src;
  } else {
    auto url_tail_str = url_src.substr(pos + 1);
    if (url_tail_str.find("versionId=") == string::npos) {
      name_str = url_src;
    } else{
      name_str = url_src.substr(0, pos);
      params_str = url_src.substr(pos + 1);
    }
  }

  boost::string_view dec_src{name_str};
  if (dec_src[0] == '/')
    dec_src.remove_prefix(1);

  pos = dec_src.find('/');
  if (pos ==string::npos)
    return false;

  boost::string_view bn_view{dec_src.substr(0, pos)};
  bucket_name = std::string{bn_view.data(), bn_view.size()};

  boost::string_view kn_view{dec_src.substr(pos + 1)};
  key.name = std::string{kn_view.data(), kn_view.size()};

  if (key.name.empty()) {
    return false;
  }

  if (! params_str.empty()) {
    RGWHTTPArgs args;
    args.set(params_str.to_string());
    args.parse();

    key.instance = args.get("versionId", NULL);
  }

  return true;
}

int RGWCopyObj::verify_permission()
{
  RGWAccessControlPolicy src_acl(s->cct);
  boost::optional<Policy> src_policy;

  op_ret = get_params();
  if (op_ret < 0) {
    ldout(s->cct, 20) << __func__ << "(): get_params error:" << op_ret << dendl;
    return op_ret;
  }

  op_ret = get_system_versioning_params(s, &olh_epoch, &version_id);
  if (op_ret < 0) {
    ldout(s->cct, 20) << __func__ << "(): get_system_versioning_params error:" << op_ret << dendl;
    return op_ret;
  }
  map<string, bufferlist> src_attrs;

  RGWObjectCtx& obj_ctx = *static_cast<RGWObjectCtx *>(s->obj_ctx);

  if (s->bucket_instance_id.empty()) {
    op_ret = store->get_bucket_info(obj_ctx, src_tenant_name, src_bucket_name,
                                    src_bucket_info, NULL, &src_attrs);
  } else {
    /* will only happen in intra region sync where the source and dest bucket is the same */
    op_ret = store->get_bucket_instance_info(obj_ctx, s->bucket_instance_id,
                                             src_bucket_info, NULL, &src_attrs);
  }
  if (op_ret < 0) {
    ldout(s->cct, 20) << __func__ << "(): get bucket info error:" << op_ret << dendl;
    if (op_ret == -ENOENT) {
      op_ret = -ERR_NO_SUCH_BUCKET;
    }
    return op_ret;
  }

  bool src_bucket_allow = true;
  RGWAccessControlPolicy src_bucket_policy(s->cct);

  src_bucket = src_bucket_info.bucket;

  rgw_obj src_obj(src_bucket, src_object);
  store->set_atomic(s->obj_ctx, src_obj);
  store->set_prefetch_data(s->obj_ctx, src_obj);

  /* check src bucket permissions */
  op_ret = read_bucket_policy(store, s, src_bucket_info, src_attrs,
                              &src_bucket_policy, src_bucket);
  if (op_ret < 0) {
    ldout(s->cct, 20) << __func__ << "(): read_bucket_policy error:" << op_ret << dendl;
    return op_ret;
  }
  auto src_iam_policy = get_iam_policy_from_attr(s->cct, store, src_attrs, src_bucket.tenant);
  /* admin request overrides permission checks */
  if (! s->auth.identity->is_admin_of(src_bucket_policy.get_owner().get_id())){
    if (src_iam_policy != boost::none) {
      auto e = src_iam_policy->eval(s->env, *s->auth.identity,
                                     rgw::IAM::s3GetObject, ARN(src_obj));
      if (e == Effect::Deny) {
         src_bucket_allow = false;
      } else if (e == Effect::Pass &&
                 ! src_bucket_policy.verify_permission(*s->auth.identity,
                                                        s->perm_mask,
                                                        RGW_PERM_READ)){
          src_bucket_allow = false;
      }
    } else if (! src_bucket_policy.verify_permission(*s->auth.identity, s->perm_mask,
                                                    RGW_PERM_READ)) {
       src_bucket_allow = false;
    }
  }

  if (!src_bucket_allow) {
    if (s->local_source &&  source_zone.empty()) {

      rgw_placement_rule src_placement;
      /* check source object permissions */
      op_ret = read_obj_policy(store, s, src_bucket_info, src_attrs, &src_acl, src_policy,
                               src_bucket, src_object, &src_placement.storage_class);
      if (op_ret < 0) {
        ldout(s->cct, 20) << __func__ << "(): read src obj policy error:" << op_ret << dendl;
        return op_ret;
      }

      /* follow up on previous checks that required reading source object head */
      if (need_to_check_storage_class) {
        src_placement.inherit_from(src_bucket_info.head_placement_rule);

        op_ret = check_storage_class(src_placement);
        if (op_ret < 0) {
          ldout(s->cct, 20) << __func__ << "(): check src storage class error:" << op_ret << dendl;
          return op_ret;
        }
      }

      /* admin request overrides permission checks */
      if (!s->auth.identity->is_admin_of(src_acl.get_owner().get_id())) {
        if (src_policy) {
          auto e = src_policy->eval(s->env, *s->auth.identity,
                  src_object.instance.empty() ?
                  rgw::IAM::s3GetObject :
                  rgw::IAM::s3GetObjectVersion,
                  ARN(src_obj));
          if (e == Effect::Deny) {
            ldout(s->cct, 20) << __func__ << "(): deny read by src policy" << dendl;
            return -EACCES;
          } else if (e == Effect::Pass &&
               !src_acl.verify_permission(*s->auth.identity, s->perm_mask,
                        RGW_PERM_READ)) {
            ldout(s->cct, 20) << __func__ << "(): deny read by src acl" << dendl;
            return -EACCES;
          }
        } else if (!src_acl.verify_permission(*s->auth.identity,
                   s->perm_mask, RGW_PERM_READ)) {
           ldout(s->cct, 20) << __func__ << "(): deny read by src acl" << dendl;
           return -EACCES;
        }
      }
    }
  }

  bool dest_bucket_allow = true;
  RGWAccessControlPolicy dest_bucket_policy(s->cct);
  map<string, bufferlist> dest_attrs;

  if (src_bucket_name.compare(dest_bucket_name) == 0) { /* will only happen if s->local_source
                                                           or intra region sync */
    dest_bucket_info = src_bucket_info;
    dest_attrs = src_attrs;
  } else {
    op_ret = store->get_bucket_info(obj_ctx, dest_tenant_name, dest_bucket_name,
                                    dest_bucket_info, nullptr, &dest_attrs);
    if (op_ret < 0) {
      ldout(s->cct, 20) << __func__ << "(): get dest bucket info error:" << op_ret << dendl;
      if (op_ret == -ENOENT) {
        op_ret = -ERR_NO_SUCH_BUCKET;
      }
      return op_ret;
    }
  }

  dest_bucket = dest_bucket_info.bucket;

  rgw_obj dest_obj(dest_bucket, dest_object);
  store->set_atomic(s->obj_ctx, dest_obj);

  /* check dest bucket permissions */
  op_ret = read_bucket_policy(store, s, dest_bucket_info, dest_attrs,
                              &dest_bucket_policy, dest_bucket);
  if (op_ret < 0) {
    ldout(s->cct, 20) << __func__ << "(): read dest bucket policy error:" << op_ret << dendl;
    return op_ret;
  }
  auto dest_iam_policy = get_iam_policy_from_attr(s->cct, store, dest_attrs, dest_bucket.tenant);

#ifdef WITH_BCEBOS
  bool modify_pass_new = false;
#endif
  /* admin request overrides permission checks */
  if (! s->auth.identity->is_admin_of(dest_policy.get_owner().get_id())){
    if (dest_iam_policy != boost::none) {
      rgw_add_to_iam_environment(s->env, "s3:x-amz-copy-source", copy_source);
      rgw_add_to_iam_environment(s->env, "s3:x-amz-metadata-directive", md_directive);

      auto e = dest_iam_policy->eval(s->env, *s->auth.identity,
                                     rgw::IAM::s3PutObject,
                                     ARN(dest_obj));
#ifdef WITH_BCEBOS
      if (s->prot_flags & RGW_REST_BOS) {
        int modify_ret = verify_bos_modify(store, s, dest_obj, e);
        ldout(s->cct, 20) << __func__ << "(): verify_bos_modify ret:" << op_ret << dendl;
        if (modify_ret < 0) {
          dest_bucket_allow = false;
        } else if (modify_ret == 0) {
          dest_bucket_allow = true;
        } else {
          if (modify_ret == MODIFY_PASS_NEW) {
            modify_pass_new = true;
          }
          dest_bucket_allow = dest_bucket_policy.verify_permission(*s->auth.identity, s->perm_mask, RGW_PERM_WRITE);
          ldout(s->cct, 20) << __func__ << "(): dest bucket policy verify write ret:" << dest_bucket_allow << dendl;
        }
      } else
#endif
      {
        if (e == Effect::Deny) {
          dest_bucket_allow = false;
        } else if (e == Effect::Pass &&
                    ! dest_bucket_policy.verify_permission(*s->auth.identity,
                                                           s->perm_mask,
                                                           RGW_PERM_WRITE)) {
          ldout(s->cct, 20) << __func__ << "(): dest bucket policy not allow write" << dendl;
          dest_bucket_allow = false;
        }
      }

    } else if (! dest_bucket_policy.verify_permission(*s->auth.identity, s->perm_mask,
                                                    RGW_PERM_WRITE)) {
        ldout(s->cct, 20) << __func__ << "(): dest bucket policy not allow write" << dendl;
        dest_bucket_allow = false;
    }
  }

  RGWAccessControlPolicy dest_acl(s->cct);
  boost::optional<Policy> dest_policy;
  rgw_obj_key temp_dest_object;
  temp_dest_object.name = dest_object;

  if (!dest_bucket_allow) {
    if (s->local_source &&  source_zone.empty()) {

      rgw_placement_rule dest_placement;
      /* check dest object permissions */
      op_ret = read_obj_policy(store, s, dest_bucket_info, dest_attrs, &dest_acl, dest_policy,
                               dest_bucket, temp_dest_object, &dest_placement.storage_class);
      if (op_ret < 0) {
        ldout(s->cct, 20) << __func__ << "(): read dest obj policy error:" << op_ret << dendl;
#ifdef WITH_BCEBOS
        if ((s->prot_flags & RGW_REST_BOS) && modify_pass_new) {
          op_ret = -ERR_ONLY_ALLOW_MODIFY;
        } else if (op_ret == -ENOENT) {
          op_ret = -EACCES;
        }
#endif
        return op_ret;
      }

      /* follow up on previous checks that required reading dest object head */
      if (need_to_check_storage_class) {
        dest_placement.inherit_from(dest_bucket_info.head_placement_rule);

        op_ret = check_storage_class(dest_placement);
        if (op_ret < 0) {
          ldout(s->cct, 20) << __func__ << "(): check dest storage class error:" << op_ret << dendl;
          return op_ret;
        }
      }

      /* admin request overrides permission checks */
      if (!s->auth.identity->is_admin_of(dest_acl.get_owner().get_id())) {
        if (dest_policy) {
          auto e = dest_policy->eval(s->env, *s->auth.identity,
                  temp_dest_object.instance.empty() ?
                  rgw::IAM::s3GetObject :
                  rgw::IAM::s3GetObjectVersion,
                  ARN(dest_obj));
#ifdef WITH_BCEBOS
          // bos copy op need to verify read src object permission and
          // put dest object permission,
          // dont need to verify read dest object perimsision
          if (s->prot_flags & RGW_REST_BOS) {
            ldout(s->cct, 20) << __func__ << "(): bos req don't check dest read "
                              << "permission, return -EACCES" << dendl;
            return -EACCES;
          }
#endif
          if (e == Effect::Deny) {
            return -EACCES;
          } else if (e == Effect::Pass &&
               !dest_acl.verify_permission(*s->auth.identity, s->perm_mask,
                        RGW_PERM_WRITE)) {
            ldout(s->cct, 20) << __func__ << "(): dest obj acl deny write" << dendl;
            return -EACCES;
          }
        } else if (!dest_acl.verify_permission(*s->auth.identity,
                   s->perm_mask, RGW_PERM_WRITE)) {
           ldout(s->cct, 20) << __func__ << "(): dest obj acl deny write" << dendl;
           return -EACCES;
        }
      }
    }
  }

#ifdef WITH_BCEBOS
  if ((s->prot_flags & RGW_REST_BOS) && (md_directive == nullptr || strcasecmp(md_directive, "COPY") == 0)) {
    if (src_bucket_allow && s->local_source && source_zone.empty()) {
      op_ret = read_obj_policy(store, s, src_bucket_info, src_attrs, &src_acl, src_policy,
                               src_bucket, src_object);

      if (op_ret == -ENAMETOOLONG) {
        op_ret = -ERR_INVALID_OBJECT_NAME;
      }

      if (op_ret < 0) {
        ldout(s->cct, 10) << __func__ << "(): ERROR read_obj_policy ret:" << op_ret << dendl;
        return op_ret;
      }
    }
    this->dest_policy = src_acl;
    //mode replace: don't allowed meta header

    for (auto meta_header : s->info.x_meta_map) {
      if (meta_header.first.find("x-amz-meta-") == 0) {
        ldout(s->cct, 10) << __func__ << "(): ERROR mode replace don't allowed meta header" << dendl;
        op_ret = -EINVAL;
        return op_ret;
      }
    }
    return 0;
  }
#endif

  op_ret = init_dest_policy();
  if (op_ret < 0) {
    ldout(s->cct, 10) << __func__ << "(): init_dest_policy err:" << op_ret << dendl;
    return op_ret;
  }

  return 0;
}

int RGWCopyObj::init_common()
{
  if (if_mod) {
    if (parse_time(if_mod, &mod_time) < 0) {
      op_ret = -EINVAL;
      return op_ret;
    }
    mod_ptr = &mod_time;
  }

  if (if_unmod) {
    if (parse_time(if_unmod, &unmod_time) < 0) {
      op_ret = -EINVAL;
      return op_ret;
    }
    unmod_ptr = &unmod_time;
  }

  bufferlist aclbl;
  dest_policy.encode(aclbl);
  emplace_attr(RGW_ATTR_ACL, std::move(aclbl));

  op_ret = rgw_get_request_metadata(s->cct, s->info, attrs);
  if (op_ret < 0) {
    return op_ret;
  }
  populate_with_generic_attrs(s, attrs);

  return 0;
}

static void copy_obj_progress_cb(off_t ofs, void *param)
{
  RGWCopyObj *op = static_cast<RGWCopyObj *>(param);
  op->progress_cb(ofs);
}

void RGWCopyObj::progress_cb(off_t ofs)
{
  if (!s->cct->_conf->rgw_copy_obj_progress)
    return;

  if (ofs - last_ofs < s->cct->_conf->rgw_copy_obj_progress_every_bytes)
    return;

  send_partial_response(ofs);

  last_ofs = ofs;
}

void RGWCopyObj::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

void RGWCopyObj::execute()
{
  if (init_common() < 0)
    return;

  rgw_obj src_obj(src_bucket, src_object);
  rgw_obj dst_obj(dest_bucket, dest_object);

  //verify bos obj lock
  op_ret = worm_verify_bos_write(s, store, dst_obj, s->bucket_info.bos_obj_lock, false);
  if (op_ret < 0) {
    ldout(s->cct, 0) << __func__ << "() ERROR: worm verify bos write " << dst_obj
                     << " err: " << op_ret << dendl;
    return;
  }

  RGWObjectCtx& obj_ctx = *static_cast<RGWObjectCtx *>(s->obj_ctx);
  obj_ctx.obj.set_atomic(src_obj);
  obj_ctx.obj.set_atomic(dst_obj);

  encode_delete_at_attr(delete_at, attrs);

  if (obj_legal_hold) {
    bufferlist obj_legal_hold_bl;
    obj_legal_hold->encode(obj_legal_hold_bl);
    emplace_attr(RGW_ATTR_OBJECT_LEGAL_HOLD, std::move(obj_legal_hold_bl));
  }
  if (obj_retention) {
    bufferlist obj_retention_bl;
    obj_retention->encode(obj_retention_bl);
    emplace_attr(RGW_ATTR_OBJECT_RETENTION, std::move(obj_retention_bl));
  }

  bool high_precision_time = (s->system_request);

  /* Handle object versioning of Swift API. In case of copying to remote this
   * should fail gently (op_ret == 0) as the dst_obj will not exist here. */
  op_ret = store->swift_versioning_copy(obj_ctx,
                                        dest_bucket_info.owner,
                                        dest_bucket_info,
                                        dst_obj, user_quota, bucket_quota);

  if (op_ret < 0) {
    return;
  }

  op_ret = store->copy_obj(obj_ctx,
                           s->user->user_id,
                           client_id,
                           op_id,
                           &s->info,
                           source_zone,
                           dst_obj,
                           src_obj,
                           dest_bucket_info,
                           src_bucket_info,
                           s->dest_placement,
                           &src_mtime,
                           &mtime,
                           mod_ptr,
                           unmod_ptr,
                           high_precision_time,
                           if_match,
                           if_nomatch,
                           md_directive,
                           attrs_mod,
                           copy_if_newer,
                           attrs, RGW_OBJ_CATEGORY_MAIN,
                           olh_epoch,
                           (delete_at ? *delete_at : real_time()),
                           (version_id.empty() ? NULL : &version_id),
                           &s->req_id, /* use req_id as tag */
                           &etag,
                           copy_obj_progress_cb,
                           (void *)this,
                           user_quota,
                           bucket_quota
  );
  if (!dst_obj.key.get_instance().empty()) {
    version_id = dst_obj.key.get_instance();
  }

  if (op_ret == 0) {
    bufferlist notification_bl;
    if (get_bucket_notification(notification_bl) == 0) {
      RGWNotification n;
      op_ret = n.decode_notification_bl(notification_bl);
      if (op_ret != 0) return;
      int notification_ret = handle_notification(n, etag, name(), s->object.name, s->bucket_name);
      if (notification_ret != 0) {
        op_ret = notification_ret;
      }
    }
  }
}

int RGWGetACLs::verify_permission()
{
  bool perm;
  if (!s->object.empty()) {
    auto iam_action = s->object.instance.empty() ?
      rgw::IAM::s3GetObjectAcl :
      rgw::IAM::s3GetObjectVersionAcl;

    if (s->iam_policy && s->iam_policy->has_partial_conditional(S3_EXISTING_OBJTAG)){
      rgw_obj obj = rgw_obj(s->bucket, s->object);
      rgw_iam_add_existing_objtags(store, s, obj, iam_action);
    }
    perm = verify_object_permission(s, iam_action);
  } else {
    perm = verify_bucket_permission(s, rgw::IAM::s3GetBucketAcl);
  }
  if (!perm)
    return -EACCES;

  return 0;
}

void RGWGetACLs::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

void RGWGetACLs::execute()
{
  stringstream ss;
  RGWAccessControlPolicy* const acl = \
    (!s->object.empty() ? s->object_acl.get() : s->bucket_acl.get());
  bos_acl = acl;
  RGWAccessControlPolicy_S3* const s3policy = \
    static_cast<RGWAccessControlPolicy_S3*>(acl);
  s3policy->to_xml(ss);
  acls = ss.str();

#ifdef WITH_BCEBOS
  if (s->prot_flags & RGW_REST_BOS) {
    if (!s->object.empty() && s->object_acl->is_obj_same_with_bucket_acl()) {
      op_ret = -ERR_NO_SUCH_OBJECT_ACL;
    }
  }
#endif
}

int RGWDeleteACLs::verify_permission()
{
#ifdef WITH_BCEBOS
  if (s->prot_flags & RGW_REST_BOS) {
    if (!verify_object_permission(s, rgw::IAM::s3PutObjectAcl)) {
      return -EACCES;
    }
    return 0;
  } else
#endif
  {
    return verify_bucket_owner_or_policy(s, rgw::IAM::s3DeleteObjectAcl);
  }
}

void RGWDeleteACLs::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}


int RGWPutACLs::verify_permission()
{
  bool perm;

  rgw_add_to_iam_environment(s->env, "s3:x-amz-acl", s->canned_acl);

  rgw_add_grant_to_iam_environment(s->env, s);
  if (!s->object.empty()) {
    auto iam_action = s->object.instance.empty() ? rgw::IAM::s3PutObjectAcl : rgw::IAM::s3PutObjectVersionAcl;
    auto obj = rgw_obj(s->bucket, s->object);
    op_ret = rgw_iam_add_existing_objtags(store, s, obj, iam_action);
    perm = verify_object_permission(s, iam_action);
  } else {
    perm = verify_bucket_permission(s, rgw::IAM::s3PutBucketAcl);
  }
  if (!perm)
    return -EACCES;

  return 0;
}

int RGWGetLC::verify_permission()
{
  bool perm;
  perm = verify_bucket_permission(s, rgw::IAM::s3GetLifecycleConfiguration);
  if (!perm)
    return -EACCES;

  return 0;
}

int RGWPutLC::verify_permission()
{
  bool perm;
  perm = verify_bucket_permission(s, rgw::IAM::s3PutLifecycleConfiguration);
  if (!perm)
    return -EACCES;

  return 0;
}

int RGWDeleteLC::verify_permission()
{
  bool perm;
  perm = verify_bucket_permission(s, rgw::IAM::s3PutLifecycleConfiguration);
  if (!perm)
    return -EACCES;

  return 0;
}

void RGWPutACLs::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

void RGWGetLC::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

void RGWPutLC::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

void RGWDeleteLC::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

void RGWDeleteACLs::execute()
{
  bufferlist bl;
  
  char* data = nullptr;
  int len = 0;
  RGWAccessControlPolicy_S3 *policy = NULL;
  RGWACLXMLParser_S3 parser(s->cct);
  RGWAccessControlPolicy_S3 new_policy(s->cct);
  stringstream ss;
  rgw_obj obj;

  op_ret = 0; /* XXX redundant? */

  if (!parser.init()) {
    op_ret = -EINVAL;
    return;
  }

  RGWAccessControlPolicy* const existing_policy = \
    (s->object.empty() ? s->bucket_acl.get() : s->object_acl.get());
 
  if (existing_policy != nullptr) {
    owner = existing_policy->get_owner();
  }


#ifdef WITH_BCEBOS
  if (s->prot_flags & RGW_REST_BOS) {
    RGWACLsParser acl_parser;
    if (!s->bucket_owner.get_id().id.empty()) {
      acl_parser.s3_owner.set_owner_id(s->bucket_owner.get_id().id);
    }

    acl_parser.set_default_grant(s->bucket_owner.get_id().id);

    XMLFormatter bos_formatter;
    encode_xml("AccessControlPolicy", XMLNS_AWS_S3, acl_parser, &bos_formatter);
    stringstream bos_ss;
    bos_formatter.flush(bos_ss);
    char* new_out = strdup(bos_ss.str().c_str());
    free(data);
    data = new_out;
    len = bos_ss.str().size();
    ldout(s->cct, 15) << "read len=" << len << " data=" << (data ? data : "") << dendl;
  }
#endif

  if (!parser.parse(data, len, 1)) {
    op_ret = -EINVAL;
    return;
  }
  policy = static_cast<RGWAccessControlPolicy_S3 *>(parser.find_first("AccessControlPolicy"));
  if (!policy) {
    op_ret = -EINVAL;
    return;
  }

  const RGWAccessControlList& req_acl = policy->get_acl();
  const multimap<string, ACLGrant>& req_grant_map = req_acl.get_grant_map();
#define ACL_GRANTS_MAX_NUM      100
  int max_num = s->cct->_conf->rgw_acl_grants_max_num;
  if (max_num < 0) {
    max_num = ACL_GRANTS_MAX_NUM;
  }

  int grants_num = req_grant_map.size();
  if (grants_num > max_num) {
    ldout(s->cct, 10) << "An acl can have up to " << max_num
                     << " grants, request acl grants num: " << grants_num << dendl;
    op_ret = -ERR_MALFORMED_ACL_ERROR;
    s->err.message = "The request is rejected, \
                      because the acl grants number you requested is larger than the maximum "
                     + std::to_string(max_num)
                     + " grants allowed in an acl.";
    return;
  }

  // forward bucket acl requests to meta master zone
  if (s->object.empty() && !store->is_meta_master()) {
    bufferlist in_data;
    op_ret = forward_request_to_master(s, NULL, store, in_data, NULL);
    if (op_ret < 0) {
      ldout(s->cct, 20) << __func__ << " forward_request_to_master returned ret=" << op_ret << dendl;
      return;
    }
  }

#ifdef WITH_BCEBOS
  if(s->prot_flags & RGW_REST_BOS) {
    op_ret = policy->rebuild_with_bos(store, existing_policy ? &owner : &(policy->get_owner()), new_policy);
  } else
#endif
  {
    op_ret = policy->rebuild(store, &owner, new_policy);
  }
  if (op_ret < 0)
    return;

  new_policy.set_obj_same_with_bucket_acl(true);
  new_policy.encode(bl);
  map<string, bufferlist> attrs;

  if (!s->object.empty()) {
    obj = rgw_obj(s->bucket, s->object);
    store->set_atomic(s->obj_ctx, obj);

    op_ret = worm_verify_bos_write(s, store, obj, s->bucket_info.bos_obj_lock, true);
    if (op_ret < 0) {
      ldout(s->cct, 0) << __func__ << "() ERROR: worm verify bos modify " << obj
                       << " err: " << op_ret << dendl;
      return;
    }
    //if instance is empty, we should modify the latest object
    op_ret = modify_obj_attr(store, s, obj, RGW_ATTR_ACL, bl);
  } else {
    attrs = s->bucket_attrs;
    attrs[RGW_ATTR_ACL] = bl;
    op_ret = rgw_bucket_set_attrs(store, s->bucket_info, attrs, &s->bucket_info.objv_tracker);
  }
  if (op_ret == -ECANCELED) {
    op_ret = 0; /* lost a race, but it's ok because acls are immutable */
  }
}

void RGWPutACLs::execute()
{
  bufferlist bl;

  RGWAccessControlPolicy_S3 *policy = NULL;
  RGWACLXMLParser_S3 parser(s->cct);
  RGWAccessControlPolicy_S3 new_policy(s->cct);
  stringstream ss;
  char *new_data = NULL;
  rgw_obj obj;

  op_ret = 0; /* XXX redundant? */

  if (!parser.init()) {
    op_ret = -EINVAL;
    return;
  }


  RGWAccessControlPolicy* const existing_policy = \
    (s->object.empty() ? s->bucket_acl.get() : s->object_acl.get());

  owner = existing_policy->get_owner();

  op_ret = get_params();
  if (op_ret < 0) {
    if (op_ret == -ERANGE) {
      ldout(s->cct, 4) << "The size of request xml data is larger than the max limitation, data size = "
                       << s->length << dendl;
      op_ret = -ERR_MALFORMED_XML;
      s->err.message = "The XML you provided was larger than the maximum " +
                       std::to_string(s->cct->_conf->rgw_max_put_param_size) +
                       " bytes allowed.";
    }
    return;
  }

  ldout(s->cct, 15) << "read len=" << len << " data=" << (data ? data : "") << dendl;

  if (!s->canned_acl.empty() && len) {
#ifdef WITH_BCEBOS
    if (s->prot_flags & RGW_REST_BOS) {
      op_ret = -ERR_MALFORMED_JSON;
    } else
#endif
    {
      op_ret = -EINVAL;
    }
    return;
  }

  if (!s->canned_acl.empty() || s->has_acl_header) {
    op_ret = get_policy_from_state(store, s, ss);
    if (op_ret < 0) {
      ldout(s->cct, 20) << __func__ << " get policy err:" << op_ret << dendl;
      return;
    }

    new_data = strdup(ss.str().c_str());
    free(data);
    data = new_data;
    len = ss.str().size();
  }

#ifdef WITH_BCEBOS
  if ((s->prot_flags & RGW_REST_BOS) && s->canned_acl.empty() && !s->has_acl_header) {
    RGWACLsParser acl_parser;
    if (!s->bucket_owner.get_id().id.empty()) {
      acl_parser.s3_owner.set_owner_id(s->bucket_owner.get_id().id);
    }

    acl_parser.decode_json(data, len);
    if (acl_parser.err_code < 0) {
      op_ret = acl_parser.err_code;
      return;
    }

    XMLFormatter bos_formatter;
    encode_xml("AccessControlPolicy", XMLNS_AWS_S3, acl_parser, &bos_formatter);
    stringstream bos_ss;
    bos_formatter.flush(bos_ss);
    free(data);
    char* new_out = strdup(bos_ss.str().c_str());
    data = new_out;
    len = bos_ss.str().size();
  }
#endif

  if (!parser.parse(data, len, 1)) {
    ldout(s->cct, 20) << __func__ << " parse data err:" << data << dendl;
    op_ret = -EINVAL;
    return;
  }
  policy = static_cast<RGWAccessControlPolicy_S3 *>(parser.find_first("AccessControlPolicy"));
  if (!policy) {
    ldout(s->cct, 20) << __func__ << " can not find AccessControlPolicy" << dendl;
    op_ret = -EINVAL;
    return;
  }

  const RGWAccessControlList& req_acl = policy->get_acl();
  const multimap<string, ACLGrant>& req_grant_map = req_acl.get_grant_map();
#define ACL_GRANTS_MAX_NUM      100
  int max_num = s->cct->_conf->rgw_acl_grants_max_num;
  if (max_num < 0) {
    max_num = ACL_GRANTS_MAX_NUM;
  }

  int grants_num = req_grant_map.size();
  if (grants_num > max_num) {
    ldout(s->cct, 4) << "An acl can have up to "
                     << max_num
                     << " grants, request acl grants num: "
                     << grants_num << dendl;
    op_ret = -ERR_MALFORMED_ACL_ERROR;
    s->err.message = "The request is rejected, because the acl grants number you requested is larger than the maximum "
                     + std::to_string(max_num)
                     + " grants allowed in an acl.";
    return;
  }

  // forward bucket acl requests to meta master zone
  if (s->object.empty() && !store->is_meta_master()) {
    bufferlist in_data;
    // include acl data unless it was generated from a canned_acl
    if (s->canned_acl.empty()) {
      in_data.append(data, len);
    }
    op_ret = forward_request_to_master(s, NULL, store, in_data, NULL);
    if (op_ret < 0) {
      ldout(s->cct, 20) << __func__ << " forward_request_to_master returned ret=" << op_ret << dendl;
      return;
    }
  }

  if (s->cct->_conf->subsys.should_gather<ceph_subsys_rgw, 15>()) {
    ldout(s->cct, 15) << "Old AccessControlPolicy";
    policy->to_xml(*_dout);
    *_dout << dendl;
  }

#ifdef WITH_BCEBOS
  if (s->prot_flags & RGW_REST_BOS) {
    op_ret = policy->rebuild_with_bos(store, existing_policy ? &owner : &(policy->get_owner()),new_policy);
  } else
#endif
  {
    op_ret = policy->rebuild(store, &owner, new_policy);
  }
  if (op_ret < 0) {
    ldout(s->cct, 20) << __func__ << " rebuild policy err:" << op_ret << dendl;
    return;
  }

  if (s->cct->_conf->subsys.should_gather<ceph_subsys_rgw, 15>()) {
    ldout(s->cct, 15) << "New AccessControlPolicy:";
    new_policy.to_xml(*_dout);
    *_dout << dendl;
  }

  new_policy.set_obj_same_with_bucket_acl(false);
  new_policy.encode(bl);
  map<string, bufferlist> attrs;

  if (!s->object.empty()) {
    obj = rgw_obj(s->bucket, s->object);
    store->set_atomic(s->obj_ctx, obj);

    op_ret = worm_verify_bos_write(s, store, obj, s->bucket_info.bos_obj_lock, false);
    if (op_ret < 0) {
      ldout(s->cct, 0) << __func__ << "() ERROR: worm verify bos write " << obj
                       << " err: " << op_ret << dendl;
      return;
    }
    //if instance is empty, we should modify the latest object
    op_ret = modify_obj_attr(store, s, obj, RGW_ATTR_ACL, bl);
  } else {
    attrs = s->bucket_attrs;
    attrs[RGW_ATTR_ACL] = bl;
    op_ret = rgw_bucket_set_attrs(store, s->bucket_info, attrs, &s->bucket_info.objv_tracker);
  }
  if (op_ret == -ECANCELED) {
    op_ret = 0; /* lost a race, but it's ok because acls are immutable */
  }
}


int RGWPutLC::valid_lifecycle_placement(RGWLifecycleConfiguration& config) {
  multimap<string, lc_op>& prefix_map = config.get_prefix_map();
  rgw_placement_rule placement_rule;
  for (auto iter = prefix_map.begin(); iter != prefix_map.end(); ++iter) {
    for (auto sc_iter = iter->second.transitions.begin(); sc_iter != iter->second.transitions.end(); ++sc_iter) {
      placement_rule.storage_class = sc_iter->first;
      placement_rule.inherit_from(s->bucket_info.head_placement_rule);
      if (!store->get_zone_params().valid_placement(placement_rule)) {
        ldout(s->cct, 10) << "NOTICE: lifecycle configuration invalid dest placement: " << placement_rule.to_str() << dendl;
        s->err.message = "The specified storage class is not implemented";
#ifdef WITH_BCEBOS
        if (s->prot_flags & RGW_REST_BOS)
          return -EINVAL;
#endif
        return -ERR_INVALID_REQUEST;
      }
    }
    for (auto sc_iter = iter->second.noncur_transitions.begin(); sc_iter != iter->second.noncur_transitions.end(); ++sc_iter) {
      placement_rule.storage_class = sc_iter->first;
      placement_rule.inherit_from(s->bucket_info.head_placement_rule);
      if (!store->get_zone_params().valid_placement(placement_rule)) {
        ldout(s->cct, 10) << "NOTICE: lifecycle configuration invalid dest placement: " << placement_rule.to_str() << dendl;
        s->err.message = "The specified storage class is not implemented";
#ifdef WITH_BCEBOS
        if (s->prot_flags & RGW_REST_BOS)
          return -EINVAL;
#endif
        return -ERR_INVALID_REQUEST;
      }
    }
  }
  return 0;
}

void RGWPutLC::execute()
{
  bufferlist bl;

  RGWLifecycleConfiguration_S3 config(s->cct);
  RGWXMLParser parser;
  RGWLifecycleConfiguration_S3 new_config(s->cct);

  if (!parser.init()) {
    op_ret = -EINVAL;
    return;
  }

  op_ret = get_params();
  if (op_ret < 0)
    return;

  ldout(s->cct, 15) << "read len=" << len << " data=" << (data ? data : "") << dendl;

#ifdef WITH_BCEBOS
  // console-bos don't transmit content_md5 header
  if (!(s->prot_flags & RGW_REST_BOS))
#endif
  {
    content_md5 = s->info.env->get("HTTP_CONTENT_MD5");
    if (content_md5 == nullptr) {
      op_ret = -ERR_INVALID_REQUEST;
      s->err.message = "Missing required header for this request: Content-MD5";
      ldout(s->cct, 5) << s->err.message << dendl;
      return;
    }

    std::string content_md5_bin;
    try {
      content_md5_bin = rgw::from_base64(boost::string_view(content_md5));
    } catch (...) {
      s->err.message = "Request header Content-MD5 contains character "
                       "that is not base64 encoded.";
      ldout(s->cct, 5) << s->err.message << dendl;
      op_ret = -ERR_BAD_DIGEST;
      return;
    }


    MD5 data_hash;
    unsigned char data_hash_res[CEPH_CRYPTO_MD5_DIGESTSIZE];
    data_hash.Update(reinterpret_cast<const unsigned char*>(data), len);
    data_hash.Final(data_hash_res);

    if (memcmp(data_hash_res, content_md5_bin.c_str(), CEPH_CRYPTO_MD5_DIGESTSIZE) != 0) {
      op_ret = -ERR_BAD_DIGEST;
      s->err.message = "The Content-MD5 you specified did not match what we received.";
      string md5 = rgw::to_base64(boost::string_view((char *)data_hash_res, CEPH_CRYPTO_MD5_DIGESTSIZE));
      ldout(s->cct, 5) << s->err.message
                       << " Specified content md5: " << content_md5
                       << ", calculated content md5: " << data_hash_res
                       << ", calculated content md5 base64: " << md5
                       << dendl;
      return;
    }
  }

#ifdef WITH_BCEBOS
  if (s->prot_flags & RGW_REST_BOS) {
    RGWLifecycleJSONParser json_parser;
    json_parser.decode_json(data, len);
    if (json_parser.err_code < 0) {
      ldout(s->cct, 0) << __func__ << "decode bos lifecycle body faild." << dendl;
      op_ret = json_parser.err_code;
      return;
    }

    XMLFormatter bos_xf;
    RGWLifecycleConfiguration_S3 bos_config(s->cct);
    json_parser.dump_xml(&bos_xf, &bos_config, op_ret);
    if (op_ret < 0) {
      ldout(s->cct, 0) << __func__ << "dump bos lifecycle to xml faild." << dendl;
      return;
    }
    if (json_parser.err_code < 0) {
      op_ret = json_parser.err_code;
      return;
    }
    bos_config.rebuild(store, config);
    stringstream bos_data;
    bos_xf.flush(bos_data);
    ldout(s->cct, 5) << "format bos lifecycle rules:" << bos_data.str() << dendl;
  } else
#endif
  {
    if (!parser.parse(data, len, 1)) {
      op_ret = -ERR_MALFORMED_XML;
      return;
    }

    try {
      RGWXMLDecoder::decode_xml("LifecycleConfiguration", config, &parser);
    } catch (RGWXMLDecoder::err& err) {
      ldout(s->cct, 5) << "Bad lifecycle configuration: " << err << dendl;
      op_ret = -ERR_MALFORMED_XML;
      return;
    }
  }

  op_ret = config.fill_suffix(s);
  if (op_ret < 0) {
    ldout(s->cct, 0) << "Bad lifecycle configuration suffix err " << op_ret << dendl;
    return;
  }

  op_ret = config.rebuild(store, new_config);
  if (op_ret < 0) {
    ldout(s->cct, 0) << "Bad lifecycle configuration rebuild err " << op_ret << dendl;
    return;
  }

  if (s->cct->_conf->subsys.should_gather<ceph_subsys_rgw, 15>()) {
    XMLFormatter xf;
    new_config.dump_xml(&xf);
    stringstream ss;
    xf.flush(ss);
    ldout(s->cct, 15) << "New LifecycleConfiguration:" << ss.str() << dendl;
  }

  op_ret = valid_lifecycle_placement(new_config);
  if (op_ret < 0) {
    ldout(s->cct, 0) << "Invalid lifecycle configuration " << op_ret << dendl;
    return;
  }

  if (!store->is_meta_master()) {
    bufferlist in_data;
    in_data.append(data, len);
    op_ret = forward_request_to_master(s, nullptr, store, in_data, nullptr);
    if (op_ret < 0) {
      ldout(s->cct, 0) << "forward_request_to_master returned ret=" << op_ret << dendl;
      return;
    }
  }

  op_ret = retry_raced_bucket_write(store, s, [&] {
      op_ret = store->get_lc()->set_bucket_config(s->bucket_info, s->bucket_attrs, &new_config);
      return op_ret;
  });

  if (op_ret < 0) {
    ldout(s->cct, 0) << "set bucket lifecyle config failed, ret=" << op_ret << dendl;
    return;
  }
  return;
}

void RGWDeleteLC::execute()
{
   if (!store->is_meta_master()) {
    bufferlist in_data;
    in_data.append(data, len);
    op_ret = forward_request_to_master(s, nullptr, store, in_data, nullptr);
    if (op_ret < 0) {
      ldout(s->cct, 0) << "forward_request_to_master returned ret=" << op_ret << dendl;
      return;
    }
  }

  op_ret = store->get_lc()->remove_bucket_config(s->bucket_info, s->bucket_attrs);
  if (op_ret < 0) {
    return;
  }
  return;
}

int RGWGetCORS::verify_permission()
{
#ifdef WITH_BCEBOS
  if (s->prot_flags & RGW_REST_BOS) {
    if (!verify_bucket_permission(s, rgw::IAM::s3GetBucketCors)) {
      return -EACCES;
    }
    return 0;
  } else
#endif
  {
    return verify_bucket_owner_or_policy(s, rgw::IAM::s3GetBucketCORS);
  }
}

void RGWGetCORS::execute()
{
  op_ret = read_bucket_cors();
  if (op_ret < 0)
    return ;

  if (!cors_exist) {
    dout(2) << "No CORS configuration set yet for this bucket" << dendl;
    op_ret = -ENOENT;
    return;
  }
}

int RGWPutCORS::verify_permission()
{
#ifdef WITH_BCEBOS
  if (s->prot_flags & RGW_REST_BOS) {
    if (!verify_bucket_permission(s, rgw::IAM::s3PutBucketCors)) {
      return -EACCES;
    }
    return 0;
  } else
#endif
  {
    return verify_bucket_owner_or_policy(s, rgw::IAM::s3PutBucketCORS);
  }
}

void RGWPutCORS::execute()
{
  rgw_raw_obj obj;

  op_ret = get_params();
  if (op_ret < 0)
    return;

  if (!store->is_meta_master()) {
    op_ret = forward_request_to_master(s, NULL, store, in_data, nullptr);
    if (op_ret < 0) {
      ldout(s->cct, 20) << __func__ << " forward_request_to_master returned ret=" << op_ret << dendl;
      return;
    }
  }

  op_ret = retry_raced_bucket_write(store, s, [this] {
      map<string, bufferlist> attrs = s->bucket_attrs;
      attrs[RGW_ATTR_CORS] = cors_bl;
      return rgw_bucket_set_attrs(store, s->bucket_info, attrs, &s->bucket_info.objv_tracker);
    });
}

int RGWDeleteCORS::verify_permission()
{
  // No separate delete permission
#ifdef WITH_BCEBOS
  if (s->prot_flags & RGW_REST_BOS) {
    if (!verify_bucket_permission(s, rgw::IAM::s3PutBucketCors)) {
      return -EACCES;
    }
    return 0;
  } else
#endif
  {
    return verify_bucket_owner_or_policy(s, rgw::IAM::s3PutBucketCORS);
  }
}

void RGWDeleteCORS::execute()
{
  op_ret = retry_raced_bucket_write(store, s, [this] {
      op_ret = read_bucket_cors();
      if (op_ret < 0)
	return op_ret;

      if (!cors_exist) {
	dout(2) << "No CORS configuration set yet for this bucket" << dendl;
	op_ret = -ENOENT;
	return op_ret;
      }

      map<string, bufferlist> attrs = s->bucket_attrs;
      attrs.erase(RGW_ATTR_CORS);
      op_ret = rgw_bucket_set_attrs(store, s->bucket_info, attrs,
				&s->bucket_info.objv_tracker);
      if (op_ret < 0) {
	ldout(s->cct, 0) << "RGWLC::RGWDeleteCORS() failed to set attrs on bucket=" << s->bucket.name
			 << " returned err=" << op_ret << dendl;
      }
      return op_ret;
    });
}

void RGWOptionsCORS::get_response_params(string& hdrs, string& exp_hdrs, unsigned *max_age) {
  get_cors_response_headers(rule, req_hdrs, hdrs, exp_hdrs, max_age);
}

int RGWOptionsCORS::validate_cors_request(RGWCORSConfiguration *cc) {
  rule = cc->host_name_rule(origin);
  if (!rule) {
    dout(10) << "There is no cors rule present for " << origin << dendl;
    return -ENOENT;
  }

  if (!validate_cors_rule_method(rule, req_meth)) {
    return -ENOENT;
  }

  if (!validate_cors_rule_header(rule, req_hdrs)) {
    return -ENOENT;
  }

  return 0;
}

void RGWOptionsCORS::execute()
{
  op_ret = read_bucket_cors();
  if (op_ret < 0)
    return;

  origin = s->info.env->get("HTTP_ORIGIN");
  if (!origin) {
    dout(0) <<
    "Preflight request without mandatory Origin header"
    << dendl;
    op_ret = -EINVAL;
    return;
  }
  req_meth = s->info.env->get("HTTP_ACCESS_CONTROL_REQUEST_METHOD");
  if (!req_meth) {
    dout(0) <<
    "Preflight request without mandatory Access-control-request-method header"
    << dendl;
    op_ret = -EINVAL;
    return;
  }
  if (!cors_exist) {
    dout(2) << "No CORS configuration set yet for this bucket" << dendl;
    op_ret = -ENOENT;
    return;
  }
  req_hdrs = s->info.env->get("HTTP_ACCESS_CONTROL_REQUEST_HEADERS");
  op_ret = validate_cors_request(&bucket_cors);
  if (!rule) {
    origin = req_meth = NULL;
    return;
  }
  return;
}

int RGWGetRequestPayment::verify_permission()
{
  return verify_bucket_owner_or_policy(s, rgw::IAM::s3GetBucketRequestPayment);
}

void RGWGetRequestPayment::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

void RGWGetRequestPayment::execute()
{
  requester_pays = s->bucket_info.requester_pays;
}

int RGWSetRequestPayment::verify_permission()
{
  return verify_bucket_owner_or_policy(s, rgw::IAM::s3PutBucketRequestPayment);
}

void RGWSetRequestPayment::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

void RGWSetRequestPayment::execute()
{
  op_ret = get_params();

  if (op_ret < 0)
    return;

  s->bucket_info.requester_pays = requester_pays;
  op_ret = store->put_bucket_instance_info(s->bucket_info, false, real_time(),
					   &s->bucket_attrs);
  if (op_ret < 0) {
    ldout(s->cct, 0) << "NOTICE: put_bucket_info on bucket=" << s->bucket.name
		     << " returned err=" << op_ret << dendl;
    return;
  }
}

int RGWInitMultipart::verify_permission()
{
  bool modify_pass_new = false;
  if (s->iam_policy) {
    auto e = s->iam_policy->eval(s->env, *s->auth.identity,
                                 rgw::IAM::s3PutObject,
                                 rgw_obj(s->bucket, s->object));

#ifdef WITH_BCEBOS
    if (s->prot_flags & RGW_REST_BOS) {
      rgw_obj modify_obj(s->bucket, s->object);
      int ret = verify_bos_modify(store, s, modify_obj, e);
      if (ret <= MODIFY_ALLOW) {
        return ret;
      }
      if (ret == MODIFY_PASS_NEW) {
        modify_pass_new = true;
      }
    } else
#endif
    {
      if (e == Effect::Allow) {
        return 0;
      } else if (e == Effect::Deny) {
        return -EACCES;
      }
    }
  }

  if (!verify_bucket_permission_no_policy(s, RGW_PERM_WRITE)) {
    return modify_pass_new ? -ERR_ONLY_ALLOW_MODIFY : -EACCES;
  }

  return 0;
}

void RGWInitMultipart::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

void RGWInitMultipart::execute()
{
  bufferlist aclbl;
  map<string, bufferlist> attrs;
  rgw_obj obj;

  if (get_params() < 0)
    return;

  if (s->object.empty())
    return;

  policy.encode(aclbl);
  attrs[RGW_ATTR_ACL] = aclbl;

  //verify bos obj lock
  rgw_obj target_obj(s->bucket, s->object);
  op_ret = worm_verify_bos_write(s, store, target_obj, s->bucket_info.bos_obj_lock, false);
  if (op_ret < 0) {
    ldout(s->cct, 0) << __func__ << "() ERROR: worm verify bos write " << target_obj
                     << "err: " << op_ret << dendl;
    return;
  }

  if (obj_legal_hold) {
    bufferlist obj_legal_hold_bl;
    obj_legal_hold->encode(obj_legal_hold_bl);
    attrs.emplace(RGW_ATTR_OBJECT_LEGAL_HOLD, obj_legal_hold_bl);
  }
  if (obj_retention) {
    bufferlist obj_retention_bl;
    obj_retention->encode(obj_retention_bl);
    attrs.emplace(RGW_ATTR_OBJECT_RETENTION, obj_retention_bl);
  }

  populate_with_generic_attrs(s, attrs);

  /* select encryption mode */
  op_ret = prepare_encryption(attrs);
  if (op_ret != 0)
    return;

  op_ret = rgw_get_request_metadata(s->cct, s->info, attrs);
  if (op_ret < 0) {
    return;
  }

  /* check quota before init and create multipart meta_obj */
  op_ret = store->check_quota(s->bucket_owner.get_id(), s->bucket,
                                 user_quota, bucket_quota, 0);
  if (op_ret < 0) {
    ldout(s->cct, 20) << "Multipart-Init: check_quota() returned ret=" << op_ret << dendl;
    return;
  }

  do {
    char buf[33];
    gen_rand_alphanumeric(s->cct, buf, sizeof(buf) - 1);
    upload_id = MULTIPART_UPLOAD_ID_PREFIX; /* v2 upload id */
    upload_id.append(buf);

    string tmp_obj_name;
    RGWMPObj mp(s->object.name, upload_id);
    tmp_obj_name = mp.get_meta();

    obj.init_ns(s->bucket, tmp_obj_name, mp_ns);
    // the meta object will be indexed with 0 size, we c
    obj.set_in_extra_data(true);
    obj.index_hash_source = s->object.name;

    RGWRados::Object op_target(store, s->bucket_info, *static_cast<RGWObjectCtx *>(s->obj_ctx), obj);
    op_target.set_versioning_disabled(true); /* no versioning for multipart meta */
    op_target.set_bilog_write_enable(false);

    RGWRados::Object::Write obj_op(&op_target);

    obj_op.meta.owner = s->owner.get_id();
    obj_op.meta.category = RGW_OBJ_CATEGORY_MULTIMETA;
    obj_op.meta.flags = PUT_OBJ_CREATE_EXCL;
    obj_op.meta.storage_class = s->info.storage_class.empty() ? "STANDARD" : s->info.storage_class;
    obj_op.meta.head_placement_rule = s->bucket_info.head_placement_rule;

    op_ret = obj_op.write_meta_without_namespace(0, 0, attrs);
  } while (op_ret == -EEXIST);
}

static int get_multipart_info(RGWRados *store, struct req_state *s,
			      string& meta_oid,
                              RGWAccessControlPolicy *policy,
			      map<string, bufferlist>& attrs)
{
  map<string, bufferlist>::iterator iter;
  bufferlist header;

  rgw_obj obj;
  obj.init_ns(s->bucket, meta_oid, mp_ns);
  obj.set_in_extra_data(true);

  int op_ret = get_obj_attrs(store, s, obj, attrs);
  if (op_ret < 0) {
    if (op_ret == -ENOENT) {
      return -ERR_NO_SUCH_UPLOAD;
    }
    return op_ret;
  }

  if (policy) {
    for (iter = attrs.begin(); iter != attrs.end(); ++iter) {
      string name = iter->first;
      if (name.compare(RGW_ATTR_ACL) == 0) {
        bufferlist& bl = iter->second;
        bufferlist::iterator bli = bl.begin();
        try {
          decode(*policy, bli);
        } catch (buffer::error& err) {
          ldout(s->cct, 0) << "ERROR: could not decode policy, caught buffer::error" << dendl;
          return -EIO;
        }
        break;
      }
    }
  }

  return 0;
}

int RGWCompleteMultipart::verify_permission()
{
  if (s->iam_policy) {
    auto e = s->iam_policy->eval(s->env, *s->auth.identity,
                                 rgw::IAM::s3PutObject,
                                 rgw_obj(s->bucket, s->object));

#ifdef WITH_BCEBOS
    if (s->prot_flags & RGW_REST_BOS) {
      rgw_obj modify_obj(s->bucket, s->object);
      int ret = verify_bos_modify(store, s, modify_obj, e);
      if (ret <= MODIFY_ALLOW) {
        return ret;
      }
    } else
#endif
    {
      if (e == Effect::Allow) {
        return 0;
      } else if (e == Effect::Deny) {
        return -EACCES;
      }
    }
  }

  if (!verify_bucket_permission_no_policy(s, RGW_PERM_WRITE)) {
    return -EACCES;
  }

  return 0;
}

void RGWCompleteMultipart::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

void RGWCompleteMultipart::execute()
{
  RGWMultiCompleteUpload* parts;
  map<int, string>::iterator iter;
  RGWMultiXMLParser parser;
  RGWMultiJSONParser json_parser;
  string meta_oid;
  map<uint32_t, RGWUploadPartInfo> obj_parts;
  map<uint32_t, RGWUploadPartInfo>::iterator obj_iter;
  map<string, RGWUploadPartInfo> orphan_obj_parts;
  map<string, RGWUploadPartInfo>::iterator orphan_obj_iter;
  map<string, bufferlist> attrs;
  off_t ofs = 0;
  MD5 hash;
  char final_etag[CEPH_CRYPTO_MD5_DIGESTSIZE];
  char final_etag_str[CEPH_CRYPTO_MD5_DIGESTSIZE * 2 + 16];
  bufferlist etag_bl;
  rgw_obj meta_obj;
  rgw_obj target_obj;
  RGWMPObj mp;
  RGWObjManifest manifest;
  uint64_t olh_epoch = 0;

  op_ret = get_params();
  if (op_ret < 0)
    return;
  op_ret = get_system_versioning_params(s, &olh_epoch, &version_id);
  if (op_ret < 0) {
    return;
  }

  if (!data || !len) {
    op_ret = -ERR_MALFORMED_XML;
    return;
  }

#ifdef WITH_BCEBOS
  if (s->prot_flags & RGW_REST_BOS) {
    json_parser.parts = new RGWMultiCompleteUpload;
    parts = json_parser.parts;
    json_parser.decode_json(data, len);
    if (json_parser.err_code < 0) {
      op_ret = json_parser.err_code;
      return;
    }
    if (json_parser.multi_parts.empty()) {
      op_ret = -ERR_INAPPROPRIATE_JSON;
      return;
    }
    for (auto &iter : json_parser.multi_parts) {
      parts->parts.insert(make_pair(iter.part_number, iter.e_tag));
      dout(20) << "partNumber = " << iter.part_number << ", etag = " << iter.e_tag << dendl;
    }
  } else {
#endif
    if (!parser.init()) {
      op_ret = -EIO;
      return;
    }

    if (!parser.parse(data, len, 1)) {
      op_ret = -ERR_MALFORMED_XML;
      return;
    }

    parts = static_cast<RGWMultiCompleteUpload *>(parser.find_first("CompleteMultipartUpload"));
    if (!parts || parts->parts.empty()) {
      op_ret = -ERR_MALFORMED_XML;
      return;
    }
#ifdef WITH_BCEBOS
  }
#endif

  if ((int)parts->parts.size() >
      s->cct->_conf->rgw_multipart_part_upload_limit) {
    op_ret = -ERANGE;
    return;
  }

  mp.init(s->object.name, upload_id);
  meta_oid = mp.get_meta();

  int total_parts = 0;
  int handled_parts = 0;
  int max_parts = 1000;
  int marker = 0;
  bool truncated;
  RGWCompressionInfo cs_info;
  bool compressed = false;
  uint64_t accounted_size = 0;

  uint64_t min_part_size = s->cct->_conf->rgw_multipart_min_part_size;

  list<rgw_obj_index_key> remove_objs; /* objects to be removed from index listing */

  bool versioned_object = s->bucket_info.versioning_enabled();

  iter = parts->parts.begin();

  meta_obj.init_ns(s->bucket, meta_oid, mp_ns);
  meta_obj.set_in_extra_data(true);
  meta_obj.index_hash_source = s->object.name;

  /*take a cls lock on meta_obj to prevent racing completions (or retries)
    from deleting the parts*/
  rgw_raw_obj raw_obj;
  int max_lock_secs_mp =
    s->cct->_conf->get_val<int64_t>("rgw_mp_lock_max_time");

  target_obj.init(s->bucket, s->object.name);
  if (versioned_object) {
    if (!version_id.empty()) {
      target_obj.key.set_instance(version_id);
    } else {
      store->gen_rand_obj_instance_name(&target_obj);
      version_id = target_obj.key.get_instance();
    }
  }
  op_ret = worm_verify_bos_write(s, store, target_obj, s->bucket_info.bos_obj_lock, false);
  if (op_ret < 0) {
    ldout(s->cct, 0) << __func__ << "() ERROR: worm verify bos write " << target_obj
                     << "err: " << op_ret << dendl;
    return;
  }

  utime_t dur(max_lock_secs_mp, 0);

  store->obj_to_raw((s->bucket_info).head_placement_rule, meta_obj, &raw_obj);
  store->open_pool_ctx(raw_obj.pool, serializer.ioctx);

  op_ret = serializer.try_lock(raw_obj.oid, dur);
  if (op_ret < 0) {
    dout(0) << __func__ << " failed to acquire lock of " << raw_obj.oid
            << " ret=" <<  op_ret << dendl;
    if (op_ret == -ENOENT) {
      s->err.message = "The specified multipart upload does not exist. The upload ID might "
                       "be invalid, or the multipart upload might have been aborted or completed.";
      op_ret = -ERR_NO_SUCH_UPLOAD;
    } else if (op_ret == -EBUSY) {
      s->err.message = "This multipart completion is already in progress";
      op_ret= -ERR_KEY_EXIST;
    } else {
      s->err.message = "We encountered an internal error. Please try again.";
      op_ret = -ERR_INTERNAL_ERROR;
    }
    return;
  }

  op_ret = get_obj_attrs(store, s, meta_obj, attrs);

  if (op_ret < 0) {
    ldout(s->cct, 0) << "ERROR: failed to get obj attrs, obj=" << meta_obj
		     << " ret=" << op_ret << dendl;
    return;
  }

#ifdef WITH_BCEBOS
    if (s->prot_flags & RGW_REST_BOS) {
      op_ret = rgw_get_request_metadata(s->cct, s->info, attrs);
      if (op_ret < 0) {
        return;
      }
    }
#endif

  do {
    op_ret = list_multipart_parts(store, s, upload_id, meta_oid, max_parts,
				  marker, obj_parts, &marker, &truncated);
    if (op_ret == -ENOENT) {
      op_ret = -ERR_NO_SUCH_UPLOAD;
    }
    if (op_ret < 0)
      return;

    // get the orphan parts
    op_ret = get_orphan_parts(store, s->bucket_info, s->cct, meta_oid, max_parts, orphan_obj_parts);
    if (op_ret < 0)
      return;

    total_parts += obj_parts.size();
    if (!truncated && total_parts != (int)parts->parts.size()) {
      ldout(s->cct, 0) << "NOTICE: total parts mismatch: have: " << total_parts
		       << " expected: " << parts->parts.size() << dendl;
      op_ret = -ERR_INVALID_PART;
      return;
    }

    for (obj_iter = obj_parts.begin(); iter != parts->parts.end() && obj_iter != obj_parts.end(); ++iter, ++obj_iter, ++handled_parts) {
      uint64_t part_size = obj_iter->second.accounted_size;
      if (handled_parts < (int)parts->parts.size() - 1 &&
          part_size < min_part_size) {
        op_ret = -ERR_TOO_SMALL;
        return;
      }

      char petag[CEPH_CRYPTO_MD5_DIGESTSIZE];
      if (iter->first != (int)obj_iter->first) {
        ldout(s->cct, 0) << "NOTICE: parts num mismatch: next requested: "
			 << iter->first << " next uploaded: "
			 << obj_iter->first << dendl;
        op_ret = -ERR_INVALID_PART;
        return;
      }
      string part_etag = rgw_string_unquote(iter->second);
      if (part_etag.compare(obj_iter->second.etag) != 0) {
        ldout(s->cct, 0) << "NOTICE: etag mismatch: part: " << iter->first
			 << " etag: " << iter->second << dendl;
        op_ret = -ERR_INVALID_PART;
        return;
      }

      hex_to_buf(obj_iter->second.etag.c_str(), petag, CEPH_CRYPTO_MD5_DIGESTSIZE);
      hash.Update((const unsigned char *)petag, sizeof(petag));

      RGWUploadPartInfo& obj_part = obj_iter->second;

      /* update manifest for part */
      string oid = mp.get_part(obj_iter->second.num);
      rgw_obj src_obj;
      src_obj.init_ns(s->bucket, oid, mp_ns);

      if (obj_part.manifest.empty()) {
        ldout(s->cct, 0) << "ERROR: empty manifest for object part: obj="
			 << src_obj << dendl;
        op_ret = -ERR_INVALID_PART;
        return;
      } else {
        manifest.append(obj_part.manifest, store);
      }

      bool part_compressed = (obj_part.cs_info.compression_type != "none");
      if ((obj_iter != obj_parts.begin()) &&
          ((part_compressed != compressed) ||
            (cs_info.compression_type != obj_part.cs_info.compression_type))) {
          ldout(s->cct, 0) << "ERROR: compression type was changed during multipart upload ("
                           << cs_info.compression_type << ">>" << obj_part.cs_info.compression_type << ")" << dendl;
          op_ret = -ERR_INVALID_PART;
          return; 
      }

      if (part_compressed) {
        int64_t new_ofs; // offset in compression data for new part
        if (cs_info.blocks.size() > 0)
          new_ofs = cs_info.blocks.back().new_ofs + cs_info.blocks.back().len;
        else
          new_ofs = 0;
        for (const auto& block : obj_part.cs_info.blocks) {
          compression_block cb;
          cb.old_ofs = block.old_ofs + cs_info.orig_size;
          cb.new_ofs = new_ofs;
          cb.len = block.len;
          cs_info.blocks.push_back(cb);
          new_ofs = cb.new_ofs + cb.len;
        } 
        if (!compressed)
          cs_info.compression_type = obj_part.cs_info.compression_type;
        cs_info.orig_size += obj_part.cs_info.orig_size;
        compressed = true;
      }

      rgw_obj_index_key remove_key;
      src_obj.key.get_index_key(&remove_key);

      remove_objs.push_back(remove_key);

      ofs += obj_part.size;
      accounted_size += obj_part.accounted_size;
    }

    // remove the orphan part
    RGWUploadPartInfo orphan_info;
    for (orphan_obj_iter = orphan_obj_parts.begin(); orphan_obj_iter != orphan_obj_parts.end(); ++orphan_obj_iter) {
      string orphan_oid = orphan_obj_iter->first;
      orphan_info = orphan_obj_iter->second;

      RGWObjManifest::obj_iterator orphan_iter = orphan_info.manifest.obj_begin();
      if (orphan_iter != orphan_info.manifest.obj_end()) {
        rgw_obj orphan;
        rgw_raw_obj orphan_head = orphan_iter.get_location().get_raw_obj(store);
        rgw_raw_obj_to_obj(s->bucket, orphan_head, &orphan);

        rgw_obj_index_key orphan_key;
        orphan.key.get_index_key(&orphan_key);
        remove_objs.push_back(orphan_key);
      }

      op_ret = erase_orphan_part(store, orphan_info, orphan_oid, meta_obj);
      if (op_ret < 0){
        return;
      }
    }
  } while (truncated);
  hash.Final((unsigned char *)final_etag);

  buf_to_hex((unsigned char *)final_etag, sizeof(final_etag), final_etag_str);
  snprintf(&final_etag_str[CEPH_CRYPTO_MD5_DIGESTSIZE * 2],  sizeof(final_etag_str) - CEPH_CRYPTO_MD5_DIGESTSIZE * 2,
           "-%lld", (long long)parts->parts.size());
  etag = final_etag_str;
  ldout(s->cct, 10) << "calculated etag: " << final_etag_str << dendl;

  etag_bl.append(final_etag_str, strlen(final_etag_str));

  attrs[RGW_ATTR_ETAG] = etag_bl;

  if (compressed) {
    // write compression attribute to full object
    bufferlist tmp;
    encode(cs_info, tmp);
    attrs[RGW_ATTR_COMPRESSION] = tmp;
  }

  RGWObjectCtx& obj_ctx = *static_cast<RGWObjectCtx *>(s->obj_ctx);

  obj_ctx.obj.set_atomic(target_obj);

  RGWRados::Object op_target(store, s->bucket_info, *static_cast<RGWObjectCtx *>(s->obj_ctx), target_obj);
  op_target.set_bilog_delete_enable(false);
  RGWRados::Object::Write obj_op(&op_target);

  obj_op.meta.manifest = &manifest;
  obj_op.meta.remove_objs = &remove_objs;

  obj_op.meta.ptag = &s->req_id; /* use req_id as operation tag */
  obj_op.meta.owner = s->owner.get_id();
  obj_op.meta.flags = PUT_OBJ_CREATE;
  obj_op.meta.modify_tail = true;
  obj_op.meta.completeMultipart = true;
  obj_op.meta.olh_epoch = olh_epoch;
  obj_op.meta.head_placement_rule = s->bucket_info.head_placement_rule;
  auto aiter = attrs.find(RGW_ATTR_STORAGE_CLASS);
  if (aiter != attrs.end()) {
    obj_op.meta.storage_class = rgw_bl_to_str(aiter->second);
    attrs.erase(RGW_ATTR_STORAGE_CLASS);
  }
  op_ret = obj_op.write_meta(ofs, accounted_size, attrs);
  if (op_ret < 0)
    return;

  // remove the upload obj
  int r = store->delete_obj(*static_cast<RGWObjectCtx *>(s->obj_ctx),
          s->bucket_info, meta_obj, 0, true, 0, ceph::real_time(), nullptr, true, nullptr, false);
  if (r >= 0)  {
    /* serializer's exclusive lock is released */
    serializer.clear_locked();
  } else {
      ldout(store->ctx(), 0) << "WARNING: failed to remove object "
			     << meta_obj << dendl;
  }

  if (op_ret == 0) {
    op_ret = process_callback(etag, attrs[RGW_ATTR_CONTENT_TYPE].to_str());

    bufferlist notification_bl;
    if (get_bucket_notification(notification_bl) == 0) {
      RGWNotification n;
      op_ret = n.decode_notification_bl(notification_bl);
      if (op_ret != 0) return;
      int notification_ret = handle_notification(n, etag, name(), s->object.name, s->bucket_name);
      if (notification_ret != 0) {
        op_ret = notification_ret;
      }
    }
  }
}

int RGWCompleteMultipart::MPSerializer::try_lock(
  const std::string& _oid,
  utime_t dur)
{
  oid = _oid;
  op.assert_exists();
  lock.set_duration(dur);
  lock.lock_exclusive(&op);
  int ret = ioctx.operate(oid, &op);
  if (! ret) {
    locked = true;
  }
  return ret;
}

void RGWCompleteMultipart::complete()
{
  /* release exclusive lock iff not already */
  if (unlikely(serializer.locked)) {
    int r = serializer.unlock();
    if (r < 0) {
      ldout(store->ctx(), 0) << "WARNING: failed to unlock "
			     << serializer.oid << dendl;
    }
  }
  send_response();
}

int RGWAbortMultipart::verify_permission()
{
  if (s->iam_policy) {
    auto e = s->iam_policy->eval(s->env, *s->auth.identity,
                                 rgw::IAM::s3AbortMultipartUpload,
                                 rgw_obj(s->bucket, s->object));

#ifdef WITH_BCEBOS
    if (s->prot_flags & RGW_REST_BOS) {
    e = s->iam_policy->eval(s->env, *s->auth.identity,
                            rgw::IAM::s3PutObject,
                            rgw_obj(s->bucket, s->object));

      rgw_obj modify_obj(s->bucket, s->object);
      int ret = verify_bos_modify(store, s, modify_obj, e);
      if (ret <= MODIFY_ALLOW) {
        return ret;
      }
    } else
#endif
    {
      if (e == Effect::Allow) {
        return 0;
      } else if (e == Effect::Deny) {
        return -EACCES;
      }
    }
  }

  if (!verify_bucket_permission_no_policy(s, RGW_PERM_WRITE)) {
    return -EACCES;
  }

  return 0;
}

void RGWAbortMultipart::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

void RGWAbortMultipart::execute()
{
  op_ret = -EINVAL;
  string upload_id;
  string meta_oid;
  upload_id = s->info.args.get("uploadId");
  map<string, bufferlist> attrs;
  rgw_obj meta_obj;
  RGWMPObj mp;

  if (upload_id.empty() || s->object.empty())
    return;

  mp.init(s->object.name, upload_id);
  meta_oid = mp.get_meta();

  op_ret = get_multipart_info(store, s, meta_oid, NULL, attrs);
  if (op_ret < 0)
    return;

  auto iter = attrs.find(RGW_ATTR_STORAGE_CLASS);
  string storage_class;
  if (iter != attrs.end()) {
    storage_class = iter->second.c_str();
  }

  RGWObjectCtx *obj_ctx = static_cast<RGWObjectCtx *>(s->obj_ctx);
  op_ret = abort_multipart_upload(store, s->cct, obj_ctx, s->bucket_info, mp);
}

int RGWListMultipart::verify_permission()
{
#ifdef WITH_BCEBOS
  if (s->prot_flags & RGW_REST_BOS) {
    if (!verify_object_permission(s, rgw::IAM::s3ListParts)) {
      return -EACCES;
    }
  } else
#endif
  {
    if (!verify_object_permission(s, rgw::IAM::s3ListMultipartUploadParts))
      return -EACCES;
  }

  return 0;
}

void RGWListMultipart::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

void RGWListMultipart::execute()
{
  map<string, bufferlist> xattrs;
  string meta_oid;
  RGWMPObj mp;

  op_ret = get_params();
  if (op_ret < 0)
    return;

  mp.init(s->object.name, upload_id);
  meta_oid = mp.get_meta();

  op_ret = get_multipart_info(store, s, meta_oid, &policy, xattrs);
  if (op_ret < 0) {
#ifdef WITH_BCEBOS
    if (op_ret == -ENOENT && (s->prot_flags & RGW_REST_BOS)) {
      op_ret = -ERR_NO_SUCH_UPLOAD;
    }
#endif
    return;
  }

  auto iter = xattrs.find(RGW_ATTR_STORAGE_CLASS);
  if (iter != xattrs.end()) {
    storage_class = rgw_bl_to_str(iter->second);
  }
  op_ret = list_multipart_parts(store, s, upload_id, meta_oid, max_parts,
				marker, parts, NULL, &truncated);
  if (op_ret == -ENOENT) {
    op_ret = -ERR_NO_SUCH_UPLOAD;
  }
}

int RGWListBucketMultiparts::verify_permission()
{
#ifdef WITH_BCEBOS
  if (s->prot_flags & RGW_REST_BOS) {
    if (!verify_bucket_permission(s, rgw::IAM::s3ListMultiObjects)) {
      return -EACCES;
    }
  } else
#endif
  {
    if (!verify_bucket_permission(s, rgw::IAM::s3ListBucketMultipartUploads)) {
      return -EACCES;
    }
  }

  return 0;
}

void RGWListBucketMultiparts::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

void RGWListBucketMultiparts::execute()
{
  vector<rgw_bucket_dir_entry> objs;
  string marker_meta;

  op_ret = get_params();
  if (op_ret < 0)
    return;

  if (s->prot_flags & RGW_REST_SWIFT) {
    string path_args;
    path_args = s->info.args.get("path");
    if (!path_args.empty()) {
      if (!delimiter.empty() || !prefix.empty()) {
        op_ret = -EINVAL;
        return;
      }
      prefix = path_args;
      delimiter="/";
    }
  }
#ifdef WITH_BCEBOS
  if (s->prot_flags & RGW_REST_BOS) {
    if (delimiter.size() > 1) {
      op_ret = -EINVAL;
      return;
    }
  }
#endif
  marker_meta = marker.get_meta();

  op_ret = list_bucket_multiparts(store, s->bucket_info, prefix, marker_meta, delimiter,
                                  max_uploads, &objs, &common_prefixes, &is_truncated);
  if (op_ret < 0) {
    return;
  }

  if (!objs.empty()) {
    vector<rgw_bucket_dir_entry>::iterator iter;
    RGWMultipartUploadEntry entry;
    for (iter = objs.begin(); iter != objs.end(); ++iter) {
      rgw_obj_key key(iter->key);
      if (!entry.mp.from_meta(key.name))
        continue;
      entry.obj = *iter;
      uploads.push_back(entry);
    }
    next_marker = entry;
  }
}

void RGWGetHealthCheck::execute()
{
  if (!g_conf->rgw_healthcheck_disabling_path.empty() &&
      (::access(g_conf->rgw_healthcheck_disabling_path.c_str(), F_OK) == 0)) {
    /* Disabling path specified & existent in the filesystem. */
    op_ret = -ERR_SERVICE_UNAVAILABLE; /* 503 */
  } else {
    op_ret = 0; /* 200 OK */
  }
}

struct DeleteMultiObjParams {
  RGWRados* store;
  RGWObjectCtx *obj_ctx;
  req_state * const s;
  bool bypass_governance_mode;
  bool acl_allowed;
  rgw_obj_key key;

  DeleteMultiObjParams(RGWRados* store,
                       RGWObjectCtx *obj_ctx,
                       req_state * const s,
                       bool bypass_governance_mode,
                       bool acl_allowed,
                       rgw_obj_key& key)
            : store(store),
              obj_ctx(obj_ctx),
              s(s),
              bypass_governance_mode(bypass_governance_mode),
              acl_allowed(acl_allowed),
              key(key){}
};

struct DeleteMultiObjState {
  rgw_obj_key key;
  bool delete_marker;
  string marker_version_id;
  int ret;
  DeleteMultiObjState(rgw_obj_key& k, bool dm, const string& mvid, int r)
        : key(k), delete_marker(dm), marker_version_id(mvid), ret(r) {}
};

static std::shared_ptr<void> delete_multiobj_parallel(std::shared_ptr<void> params)
{
  auto castedParams = std::static_pointer_cast<DeleteMultiObjParams>(params);
  bool bypass_perm = true;
  int op_ret;

  rgw_obj obj(castedParams->s->bucket, castedParams->key);
  if (castedParams->s->iam_policy) {
    if (castedParams->s->bucket_info.obj_lock_enabled() && castedParams->bypass_governance_mode) {
      auto r = castedParams->s->iam_policy->eval(castedParams->s->env,
                                    *castedParams->s->auth.identity,
                                    rgw::IAM::s3BypassGovernanceRetention,
                                    ARN(castedParams->s->bucket, castedParams->key.name));
      if (r == Effect::Deny) {
        bypass_perm = false;
      }
    }

    auto e = castedParams->s->iam_policy->eval(castedParams->s->env,
                                   *castedParams->s->auth.identity,
                                   castedParams->key.instance.empty() ?
                                   rgw::IAM::s3DeleteObject :
                                   rgw::IAM::s3DeleteObjectVersion,
                                   obj);
    if ((e == Effect::Deny) ||
        (e == Effect::Pass && !castedParams->acl_allowed)) {
      return std::make_shared<DeleteMultiObjState>(castedParams->key, false, "", -EACCES);
    }
  }

  map<string, bufferlist> attrs;
  bool check_obj_lock = obj.key.have_instance() && castedParams->s->bucket_info.obj_lock_enabled();
  ceph::real_time mtime;
  if (!castedParams->s->bucket_info.trash_dir.empty() &&
      obj.key.name.find(castedParams->s->bucket_info.trash_dir) != 0) {
    castedParams->store->set_prefetch_data(castedParams->obj_ctx, obj);
  }
  int get_attrs_response = get_obj_attrs(castedParams->store, castedParams->s, obj, attrs, &mtime);
#ifdef WITH_BCEBOS
  if (castedParams->s->prot_flags & RGW_REST_BOS) {
    if (get_attrs_response < 0) {
      ldout(castedParams->s->cct, 5) << "NOTICE: get obj attrs error:"<< get_attrs_response << dendl;
      return std::make_shared<DeleteMultiObjState>(castedParams->key, false, "", get_attrs_response);
    } else {
      auto attr_iter = attrs.find(RGW_ATTR_DELETED);
      if (attr_iter != attrs.end()) {
        if (attr_iter->second.to_str().compare("true") == 0) {
          return std::make_shared<DeleteMultiObjState>(castedParams->key, false, "", -ENOENT);
        }
      }
    }
  }
#endif
  if (check_obj_lock) {
    if (get_attrs_response < 0) {
      if (get_attrs_response == -ENOENT) {
        // object maybe delete_marker, skip check_obj_lock
        check_obj_lock = false;
      } else {
        // Something went wrong.
        return std::make_shared<DeleteMultiObjState>(castedParams->key, false, "", get_attrs_response);
      }
    }
  }

  if (check_obj_lock) {
    int object_lock_response = verify_object_lock(castedParams->s->cct, attrs, bypass_perm,
                                castedParams->bypass_governance_mode, mtime);
    if (object_lock_response < 0) {
      return std::make_shared<DeleteMultiObjState>(castedParams->key, false, "", object_lock_response);
    }
  }

  //verify bos obj lock
  int bos_lock_ret = worm_verify_bos_write(castedParams->s, castedParams->store, obj, castedParams->s->bucket_info.bos_obj_lock, true);
  if (bos_lock_ret < 0) {
    ldout(castedParams->s->cct, 0) << __func__ << "() ERROR: verify bos delete " << obj
                      << " err=" << bos_lock_ret << dendl;
    return std::make_shared<DeleteMultiObjState>(castedParams->key, false, "", bos_lock_ret);
  }

  castedParams->obj_ctx->obj.set_atomic(obj);
  // bucket trash: if bucket have trash dir, put object to trash.
  if (!castedParams->s->bucket_info.trash_dir.empty() && obj.key.name.find(castedParams->s->bucket_info.trash_dir) != 0) {
    auto dst_object = rgw_obj_key(castedParams->s->bucket_info.trash_dir + obj.key.name);
    rgw_obj dst_obj(castedParams->s->bucket, dst_object);
    castedParams->obj_ctx->obj.set_atomic(dst_obj);

    op_ret = castedParams->store->rename_obj(*castedParams->obj_ctx, obj, dst_obj, castedParams->s->bucket_info);
    if (op_ret < 0) {
      ldout(castedParams->s->cct, 0) << __func__ << "() ERROR: trash obj failed. return:" << op_ret << dendl;
      return std::make_shared<DeleteMultiObjState>(castedParams->key, false, "", op_ret);
    }
    ldout(castedParams->s->cct, 0) << __func__ << "NOTICE: trash obj " << obj << " ret=" << op_ret << dendl;
    return std::make_shared<DeleteMultiObjState>(castedParams->key, false, "", op_ret);
  }

  RGWRados::Object del_target(castedParams->store, castedParams->s->bucket_info, *castedParams->obj_ctx, obj);
  RGWRados::Object::Delete del_op(&del_target);

  del_op.params.bucket_owner = castedParams->s->bucket_owner.get_id();
  del_op.params.versioning_status = castedParams->s->bucket_info.versioning_status();
  del_op.params.obj_owner = castedParams->s->owner;

  op_ret = del_op.delete_obj();
  if (op_ret < 0) {
    ldout(castedParams->s->cct, 5) << "NOTICE: delete obj error:"<< op_ret << dendl;
    if (op_ret == -ENOENT) {
      op_ret = 0;
    }
  }
  ldout(castedParams->s->cct, 0) << __func__ << "NOTICE: delete obj " << obj << " ret=" << op_ret << dendl;
  return std::make_shared<DeleteMultiObjState>(castedParams->key, del_op.result.delete_marker, del_op.result.version_id, op_ret);
}

int RGWDeleteMultiObj::verify_permission()
{
#ifdef WITH_BCEBOS
  if (s->prot_flags & RGW_REST_BOS) {
    acl_allowed = verify_bucket_permission(s, rgw::IAM::s3DeleteObject);
    if (!acl_allowed) {
      return -EACCES;
    }
    return 0;
  }
#endif
  acl_allowed = verify_bucket_permission_no_policy(s, RGW_PERM_WRITE);
  if (!acl_allowed && !s->iam_policy)
    return -EACCES;

  return 0;
}

void RGWDeleteMultiObj::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

void RGWDeleteMultiObj::execute()
{
  RGWMultiDelDelete *multi_delete;
  vector<rgw_obj_key>::iterator iter;
  RGWMultiDelXMLParser parser;
  int num_processed = 0;
  RGWObjectCtx *obj_ctx = static_cast<RGWObjectCtx *>(s->obj_ctx);
  std::list<RGWAsyncRequest*> lst;
#ifdef WITH_BCEBOS
  std::set<rgw_obj_key> bos_objs;
#endif

  op_ret = get_params();
  if (op_ret < 0) {
    goto error;
  }

  if (!data) {
    op_ret = -EINVAL;
    goto error;
  }

  if (!parser.init()) {
    op_ret = -EINVAL;
    goto error;
  }

#ifdef WITH_BCEBOS
  if (s->prot_flags & RGW_REST_BOS) {
    RGWMultiDeleteObjParser multi;
    std::string out;
    multi.decode_json(data, len);
    if (multi.err_code < 0) {
      op_ret = multi.err_code;
      goto error;
   }

    XMLFormatter formatter;
    encode_xml("Delete", multi, &formatter);
    stringstream ss;
    formatter.flush(ss);
    std::string outs(ss.str());

    if (!parser.parse(outs.c_str(), outs.size(), 1)) {
      op_ret = -EINVAL;
      goto error;
    }
  } else
#endif
  {
    if (!parser.parse(data, len, 1)) {
      op_ret = -EINVAL;
      goto error;
    }
  }

  multi_delete = static_cast<RGWMultiDelDelete *>(parser.find_first("Delete"));
  if (!multi_delete) {
    op_ret = -EINVAL;
    goto error;
  }

  if (multi_delete->is_quiet())
    quiet = true;

  if (s->bucket_info.mfa_enabled()) {
    bool has_versioned = false;
    for (auto i : multi_delete->objects) {
      if (!i.instance.empty()) {
        has_versioned = true;
        break;
      }
    }
    if (has_versioned && !s->mfa_verified) {
      ldout(s->cct, 5) << "NOTICE: multi-object delete request with a versioned object, mfa auth not provided" << dendl;
      op_ret = -ERR_MFA_REQUIRED;
      goto error;
    }
  }

  begin_response();
  if (multi_delete->objects.empty()) {
    goto done;
  }

  for (iter = multi_delete->objects.begin();
       iter != multi_delete->objects.end() && num_processed < max_to_delete;
       ++iter, num_processed++) {
#ifdef WITH_BCEBOS
    if (s->prot_flags & RGW_REST_BOS) {
      if (bos_objs.find(*iter) != bos_objs.end()) {
        continue;
      } else {
        bos_objs.insert(*iter);
      }
    }
#endif
    RGWAsyncRequest* req = new RGWAsyncRequest(delete_multiobj_parallel,
          std::make_shared<DeleteMultiObjParams>(store, obj_ctx, s, bypass_governance_mode, acl_allowed, *iter));
    store->get_async_processor()->queue(req);
    lst.push_back(req);
  }

  while(!lst.empty()) {
    auto req = lst.front();
    lst.pop_front();
    req->aio_wait();
    auto result = std::static_pointer_cast<DeleteMultiObjState>(req->get_ret_status());
    req->release();
    send_partial_response(result->key, result->delete_marker, result->marker_version_id, result->ret);
  }

  /*  set the return code to zero, errors at this point will be
  dumped to the response */
  op_ret = 0;

  if (op_ret == 0) {
    rgw_obj obj(s->bucket, s->object);
    map<string, bufferlist> attrs;

    ceph::real_time mtime;
    op_ret = get_obj_attrs(store, s, obj, attrs, &mtime);

    string etag = "";
    const auto etag_attr = attrs.find(RGW_ATTR_ETAG);
    if (etag_attr != attrs.end()) {
      bufferlist etag_bl = etag_attr->second;
      etag = etag_bl.c_str();
    }

    bufferlist notification_bl;
    if (get_bucket_notification(notification_bl) == 0) {
      RGWNotification n;
      op_ret = n.decode_notification_bl(notification_bl);
      if (op_ret != 0) return;
      int notification_ret = handle_notification(n, etag, name(), s->object.name, s->bucket_name);
      if (notification_ret != 0) {
        op_ret = notification_ret;
      }
    }
  }
done:
  // will likely segfault if begin_response() has not been called
  end_response();
  free(data);
  return;

error:
  send_status();
  free(data);
  return;
}

bool RGWBulkDelete::Deleter::verify_permission(RGWBucketInfo& binfo,
                                               map<string, bufferlist>& battrs,
                                               ACLOwner& bucket_owner /* out */)
{
  RGWAccessControlPolicy bacl(store->ctx());
  int ret = read_bucket_policy(store, s, binfo, battrs, &bacl, binfo.bucket);
  if (ret < 0) {
    return false;
  }

  auto policy = get_iam_policy_from_attr(s->cct, store, battrs, binfo.bucket.tenant);

  bucket_owner = bacl.get_owner();

  /* We can use global user_acl because each BulkDelete request is allowed
   * to work on entities from a single account only. */
  return verify_bucket_permission(s, binfo.bucket, s->user_acl.get(),
				  &bacl, policy, rgw::IAM::s3DeleteBucket);
}

bool RGWBulkDelete::Deleter::delete_single(const acct_path_t& path)
{
  auto& obj_ctx = *static_cast<RGWObjectCtx *>(s->obj_ctx);

  RGWBucketInfo binfo;
  map<string, bufferlist> battrs;
  ACLOwner bowner;

  int ret = store->get_bucket_info(obj_ctx, s->user->user_id.tenant,
                                   path.bucket_name, binfo, nullptr,
                                   &battrs);
  if (ret < 0) {
    goto binfo_fail;
  }

  if (!verify_permission(binfo, battrs, bowner)) {
    ret = -EACCES;
    goto auth_fail;
  }

  if (!path.obj_key.empty()) {
    rgw_obj obj(binfo.bucket, path.obj_key);
    obj_ctx.obj.set_atomic(obj);

    RGWRados::Object del_target(store, binfo, obj_ctx, obj);
    RGWRados::Object::Delete del_op(&del_target);

    del_op.params.bucket_owner = binfo.owner;
    del_op.params.versioning_status = binfo.versioning_status();
    del_op.params.obj_owner = bowner;

    ret = del_op.delete_obj();
    if (ret < 0) {
      goto delop_fail;
    }
  } else {
    RGWObjVersionTracker ot;
    ot.read_version = binfo.ep_objv;

    ret = store->delete_bucket(binfo, ot);
    if (0 == ret) {
      ret = rgw_unlink_bucket(store, binfo.owner, binfo.bucket.tenant,
                              binfo.bucket.name, false);
      if (ret < 0) {
        ldout(s->cct, 0) << "WARNING: failed to unlink bucket: ret=" << ret
                         << dendl;
      }
    }
    if (ret < 0) {
      goto delop_fail;
    }

    if (!store->is_meta_master()) {
      bufferlist in_data;
      ret = forward_request_to_master(s, &ot.read_version, store, in_data,
                                      nullptr);
      if (ret < 0) {
        if (ret == -ENOENT) {
          /* adjust error, we want to return with NoSuchBucket and not
           * NoSuchKey */
          ret = -ERR_NO_SUCH_BUCKET;
        }
        goto delop_fail;
      }
    }
  }

  num_deleted++;
  return true;


binfo_fail:
    if (-ENOENT == ret) {
      ldout(store->ctx(), 20) << "cannot find bucket = " << path.bucket_name << dendl;
      num_unfound++;
    } else {
      ldout(store->ctx(), 20) << "cannot get bucket info, ret = " << ret
                              << dendl;

      fail_desc_t failed_item = {
        .err  = ret,
        .path = path
      };
      failures.push_back(failed_item);
    }
    return false;

auth_fail:
    ldout(store->ctx(), 20) << "wrong auth for " << path << dendl;
    {
      fail_desc_t failed_item = {
        .err  = ret,
        .path = path
      };
      failures.push_back(failed_item);
    }
    return false;

delop_fail:
    if (-ENOENT == ret) {
      ldout(store->ctx(), 20) << "cannot find entry " << path << dendl;
      num_unfound++;
    } else {
      fail_desc_t failed_item = {
        .err  = ret,
        .path = path
      };
      failures.push_back(failed_item);
    }
    return false;
}

bool RGWBulkDelete::Deleter::delete_chunk(const std::list<acct_path_t>& paths)
{
  ldout(store->ctx(), 20) << "in delete_chunk" << dendl;
  for (auto path : paths) {
    ldout(store->ctx(), 20) << "bulk deleting path: " << path << dendl;
    delete_single(path);
  }

  return true;
}

int RGWBulkDelete::verify_permission()
{
  return 0;
}

void RGWBulkDelete::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

void RGWBulkDelete::execute()
{
  deleter = std::unique_ptr<Deleter>(new Deleter(store, s));

  bool is_truncated = false;
  do {
    list<RGWBulkDelete::acct_path_t> items;

    int ret = get_data(items, &is_truncated);
    if (ret < 0) {
      return;
    }

    ret = deleter->delete_chunk(items);
  } while (!op_ret && is_truncated);

  return;
}


constexpr std::array<int, 2> RGWBulkUploadOp::terminal_errors;

int RGWBulkUploadOp::verify_permission()
{
  if (s->auth.identity->is_anonymous()) {
    return -EACCES;
  }

  if (! verify_user_permission(s, RGW_PERM_WRITE)) {
    return -EACCES;
  }

  if (s->user->user_id.tenant != s->bucket_tenant) {
    ldout(s->cct, 10) << "user cannot create a bucket in a different tenant"
                      << " (user_id.tenant=" << s->user->user_id.tenant
                      << " requested=" << s->bucket_tenant << ")"
                      << dendl;
    return -EACCES;
  }

  if (s->user->max_buckets < 0) {
    return -EPERM;
  }

  return 0;
}

void RGWBulkUploadOp::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

boost::optional<std::pair<std::string, rgw_obj_key>>
RGWBulkUploadOp::parse_path(const boost::string_ref& path)
{
  /* We need to skip all slashes at the beginning in order to preserve
   * compliance with Swift. */
  const size_t start_pos = path.find_first_not_of('/');

  if (boost::string_ref::npos != start_pos) {
    /* Seperator is the first slash after the leading ones. */
    const size_t sep_pos = path.substr(start_pos).find('/');

    if (boost::string_ref::npos != sep_pos) {
      const auto bucket_name = path.substr(start_pos, sep_pos - start_pos);
      const auto obj_name = path.substr(sep_pos + 1);

      return std::make_pair(bucket_name.to_string(),
                            rgw_obj_key(obj_name.to_string()));
    } else {
      /* It's guaranteed here that bucket name is at least one character
       * long and is different than slash. */
      return std::make_pair(path.substr(start_pos).to_string(),
                            rgw_obj_key());
    }
  }

  return none;
}

std::pair<std::string, std::string>
RGWBulkUploadOp::handle_upload_path(struct req_state *s)
{
  std::string bucket_path, file_prefix;
  if (! s->init_state.url_bucket.empty()) {
    file_prefix = bucket_path = s->init_state.url_bucket + "/";
    if (! s->object.empty()) {
      std::string& object_name = s->object.name;

      /* As rgw_obj_key::empty() already verified emptiness of s->object.name,
       * we can safely examine its last element. */
      if (object_name.back() == '/') {
        file_prefix.append(object_name);
      } else {
        file_prefix.append(object_name).append("/");
      }
    }
  }
  return std::make_pair(bucket_path, file_prefix);
}

int RGWBulkUploadOp::handle_dir_verify_permission()
{
  if (s->user->max_buckets > 0) {
    RGWUserBuckets buckets;
    std::string marker;
    bool is_truncated = false;
    op_ret = rgw_read_user_buckets(store, s->user->user_id, buckets,
                                   marker, std::string(), s->user->max_buckets,
                                   false, &is_truncated);
    if (op_ret < 0) {
      return op_ret;
    }

    if (buckets.count() >= static_cast<size_t>(s->user->max_buckets)) {
      return -ERR_TOO_MANY_BUCKETS;
    }
  }

  return 0;
}

static void forward_req_info(CephContext *cct, req_info& info, const std::string& bucket_name)
{
  /* the request of container or object level will contain bucket name.
   * only at account level need to append the bucket name */
  if (info.script_uri.find(bucket_name) != std::string::npos) {
    return;
  }

  ldout(cct, 20) << "append the bucket: "<< bucket_name << " to req_info" << dendl;
  info.script_uri.append("/").append(bucket_name);
  info.request_uri_aws4 = info.request_uri = info.script_uri;
  info.effective_uri = "/" + bucket_name;
}

int RGWBulkUploadOp::handle_dir(const boost::string_ref path)
{
  ldout(s->cct, 20) << "bulk upload: got directory=" << path << dendl;

  op_ret = handle_dir_verify_permission();
  if (op_ret < 0) {
    return op_ret;
  }

  std::string bucket_name;
  rgw_obj_key object_junk;
  std::tie(bucket_name, object_junk) =  *parse_path(path);

  rgw_raw_obj obj(store->get_zone_params().domain_root,
                  rgw_make_bucket_entry_name(s->bucket_tenant, bucket_name));

  /* we need to make sure we read bucket info, it's not read before for this
   * specific request */
  RGWBucketInfo binfo;
  std::map<std::string, ceph::bufferlist> battrs;
  op_ret = store->get_bucket_info(*dir_ctx, s->bucket_tenant, bucket_name,
                                  binfo, nullptr, &battrs);
  if (op_ret < 0 && op_ret != -ENOENT) {
    return op_ret;
  }
  const bool bucket_exists = (op_ret != -ENOENT);

  if (bucket_exists) {
    RGWAccessControlPolicy old_policy(s->cct);
    int r = get_bucket_policy_from_attr(s->cct, store, binfo,
                                        battrs, &old_policy);
    if (r >= 0)  {
      if (old_policy.get_owner().get_id().compare(s->user->user_id) != 0) {
        op_ret = -EEXIST;
        return op_ret;
      }
    }
  }

  RGWBucketInfo master_info;
  rgw_bucket *pmaster_bucket = nullptr;
  uint32_t *pmaster_num_shards = nullptr;
  real_time creation_time;
  obj_version objv, ep_objv, *pobjv = nullptr;

  if (! store->is_meta_master()) {
    JSONParser jp;
    ceph::bufferlist in_data;
    req_info info = s->info;
    forward_req_info(s->cct, info, bucket_name);
    op_ret = forward_request_to_master(s, nullptr, store, in_data, &jp, &info);
    if (op_ret < 0) {
      return op_ret;
    }

    JSONDecoder::decode_json("entry_point_object_ver", ep_objv, &jp);
    JSONDecoder::decode_json("object_ver", objv, &jp);
    JSONDecoder::decode_json("bucket_info", master_info, &jp);

    ldout(s->cct, 20) << "parsed: objv.tag=" << objv.tag << " objv.ver="
                      << objv.ver << dendl;
    ldout(s->cct, 20) << "got creation_time="<< master_info.creation_time
                      << dendl;

    pmaster_bucket= &master_info.bucket;
    creation_time = master_info.creation_time;
    pmaster_num_shards = &master_info.num_shards;
    pobjv = &objv;
  } else {
    pmaster_bucket = nullptr;
    pmaster_num_shards = nullptr;
  }


  rgw_placement_rule placement_rule;
  if (bucket_exists) {
    rgw_placement_rule selected_placement_rule;
    rgw_bucket bucket;
    bucket.tenant = s->bucket_tenant;
    bucket.name = s->bucket_name;
    op_ret = store->select_bucket_placement(*(s->user),
                                            store->get_zonegroup().get_id(),
                                            placement_rule,
                                            &selected_placement_rule,
                                            nullptr);
    if (selected_placement_rule.name != binfo.head_placement_rule.name) {
      op_ret = -EEXIST;
      ldout(s->cct, 20) << "bulk upload: non-coherent placement rule" << dendl;
      return op_ret;
    }
  }

  /* Create metadata: ACLs. */
  std::map<std::string, ceph::bufferlist> attrs;
  RGWAccessControlPolicy policy;
  policy.create_default(s->user->user_id, s->user->display_name);
  ceph::bufferlist aclbl;
  policy.encode(aclbl);
  attrs.emplace(RGW_ATTR_ACL, std::move(aclbl));

  RGWQuotaInfo quota_info;
  const RGWQuotaInfo * pquota_info = nullptr;

  rgw_bucket bucket;
  bucket.tenant = s->bucket_tenant; /* ignored if bucket exists */
  bucket.name = bucket_name;


  RGWBucketInfo out_info;
  op_ret = store->create_bucket(*(s->user),
                                bucket,
                                store->get_zonegroup().get_id(),
                                placement_rule, binfo.swift_ver_location,
                                pquota_info, attrs,
                                out_info, pobjv, &ep_objv, creation_time,
                                pmaster_bucket, pmaster_num_shards, true);
  /* continue if EEXIST and create_bucket will fail below.  this way we can
   * recover from a partial create by retrying it. */
  ldout(s->cct, 20) << "rgw_create_bucket returned ret=" << op_ret
                    << ", bucket=" << bucket << dendl;

  if (op_ret && op_ret != -EEXIST) {
    return op_ret;
  }

  const bool existed = (op_ret == -EEXIST);
  if (existed) {
    /* bucket already existed, might have raced with another bucket creation, or
     * might be partial bucket creation that never completed. Read existing bucket
     * info, verify that the reported bucket owner is the current user.
     * If all is ok then update the user's list of buckets.
     * Otherwise inform client about a name conflict.
     */
    if (out_info.owner.compare(s->user->user_id) != 0) {
      op_ret = -EEXIST;
      ldout(s->cct, 20) << "bulk upload: conflicting bucket name" << dendl;
      return op_ret;
    }
    bucket = out_info.bucket;
  }

  op_ret = rgw_link_bucket(store, s->user->user_id, bucket,
                           out_info.creation_time, false);
  if (op_ret && !existed && op_ret != -EEXIST) {
    /* if it exists (or previously existed), don't remove it! */
    op_ret = rgw_unlink_bucket(store, s->user->user_id,
                               bucket.tenant, bucket.name);
    if (op_ret < 0) {
      ldout(s->cct, 0) << "bulk upload: WARNING: failed to unlink bucket: ret="
                       << op_ret << dendl;
    }
  } else if (op_ret == -EEXIST || (op_ret == 0 && existed)) {
    ldout(s->cct, 20) << "bulk upload: containers already exists"
                      << dendl;
    op_ret = -ERR_BUCKET_EXISTS;
  }

  return op_ret;
}


bool RGWBulkUploadOp::handle_file_verify_permission(RGWBucketInfo& binfo,
						    const rgw_obj& obj,
                                                    std::map<std::string, ceph::bufferlist>& battrs,
                                                    ACLOwner& bucket_owner /* out */)
{
  RGWAccessControlPolicy bacl(store->ctx());
  op_ret = read_bucket_policy(store, s, binfo, battrs, &bacl, binfo.bucket);
  if (op_ret < 0) {
    ldout(s->cct, 20) << "bulk upload: cannot read_policy() for bucket"
                      << dendl;
    return false;
  }

  auto policy = get_iam_policy_from_attr(s->cct, store, battrs, binfo.bucket.tenant);

  bucket_owner = bacl.get_owner();
  if (policy) {
    auto e = policy->eval(s->env, *s->auth.identity,
			  rgw::IAM::s3PutObject, obj);
    if (e == Effect::Allow) {
      return true;
    } else if (e == Effect::Deny) {
      return false;
    }
  }
    
  return verify_bucket_permission_no_policy(s, s->user_acl.get(),
					    &bacl, RGW_PERM_WRITE);
}

int RGWBulkUploadOp::handle_file(const boost::string_ref path,
                                 const size_t size,
                                 AlignedStreamGetter& body)
{

  ldout(s->cct, 20) << "bulk upload: got file=" << path << ", size=" << size
                    << dendl;

  RGWPutObjDataProcessor *filter = nullptr;
  boost::optional<RGWPutObj_Compress> compressor;

  if (size > static_cast<size_t>(s->cct->_conf->rgw_max_put_size)) {
    op_ret = -ERR_TOO_LARGE;
    return op_ret;
  }

  std::string bucket_name;
  rgw_obj_key object;
  std::tie(bucket_name, object) = *parse_path(path);

  auto& obj_ctx = *static_cast<RGWObjectCtx *>(s->obj_ctx);
  RGWBucketInfo binfo;
  std::map<std::string, ceph::bufferlist> battrs;
  ACLOwner bowner;
  op_ret = store->get_bucket_info(obj_ctx, s->user->user_id.tenant,
                                  bucket_name, binfo, nullptr, &battrs);
  if (op_ret == -ENOENT) {
    ldout(s->cct, 20) << "bulk upload: non existent directory=" << bucket_name
                      << dendl;
  } else if (op_ret < 0) {
    return op_ret;
  }

  if (! handle_file_verify_permission(binfo,
				      rgw_obj(binfo.bucket, object),
				      battrs, bowner)) {
    ldout(s->cct, 20) << "bulk upload: object creation unauthorized" << dendl;
    op_ret = -EACCES;
    return op_ret;
  }

  op_ret = store->check_quota(bowner.get_id(), binfo.bucket,
                              user_quota, bucket_quota, size);
  if (op_ret < 0) {
    return op_ret;
  }

  op_ret = store->check_bucket_shards(s->bucket_info, s->bucket, bucket_quota);
  if (op_ret < 0) {
    return op_ret;
  }

  RGWPutObjProcessor_Atomic processor(obj_ctx,
                                      binfo,
                                      binfo.bucket,
                                      object.name,
                                      /* part size */
                                      s->cct->_conf->rgw_obj_stripe_size,
                                      s->req_id,
                                      binfo.versioning_enabled());

  /* No filters by default. */
  filter = &processor;

  op_ret = processor.prepare(store, nullptr);
  if (op_ret < 0) {
    ldout(s->cct, 20) << "bulk upload: cannot prepare processor due to ret="
                      << op_ret << dendl;
    return op_ret;
  }

  const auto& compression_type = store->get_zone_params().get_compression_type(
      s->dest_placement);
  CompressorRef plugin;
  if (compression_type != "none") {
    plugin = Compressor::create(s->cct, compression_type);
    if (! plugin) {
      ldout(s->cct, 1) << "Cannot load plugin for rgw_compression_type "
                       << compression_type << dendl;
    } else {
      compressor.emplace(s->cct, plugin, filter);
      filter = &*compressor;
    }
  }

  /* Upload file content. */
  ssize_t len = 0;
  size_t ofs = 0;
  MD5 hash;
  do {
    ceph::bufferlist data;
    len = body.get_at_most(s->cct->_conf->rgw_max_chunk_size, data);

    ldout(s->cct, 20) << "bulk upload: body=" << data.c_str() << dendl;
    if (len < 0) {
      op_ret = len;
      return op_ret;
    } else if (len > 0) {
      bool bool_false = false;
      hash.Update((const unsigned char *)data.c_str(), data.length());
      op_ret = put_data_and_throttle(filter, data, ofs, bool_false);
      if (op_ret < 0) {
        ldout(s->cct, 20) << "processor->thottle_data() returned ret="
			  << op_ret << dendl;
        return op_ret;
      }

      ofs += len;
    }

  } while (len > 0);

  if (ofs != size) {
    ldout(s->cct, 10) << "bulk upload: real file size different from declared"
                      << dendl;
    op_ret = -EINVAL;
  }

  op_ret = store->check_quota(bowner.get_id(), binfo.bucket,
			      user_quota, bucket_quota, size);
  if (op_ret < 0) {
    ldout(s->cct, 20) << "bulk upload: quota exceeded for path=" << path
                      << dendl;
    return op_ret;
  }

  op_ret = store->check_bucket_shards(s->bucket_info, s->bucket, bucket_quota);
  if (op_ret < 0) {
    return op_ret;
  }

  char calc_md5[CEPH_CRYPTO_MD5_DIGESTSIZE * 2 + 1];
  unsigned char m[CEPH_CRYPTO_MD5_DIGESTSIZE];
  hash.Final(m);
  buf_to_hex(m, CEPH_CRYPTO_MD5_DIGESTSIZE, calc_md5);

  /* Create metadata: ETAG. */
  std::map<std::string, ceph::bufferlist> attrs;
  std::string etag = calc_md5;
  ceph::bufferlist etag_bl;
  etag_bl.append(etag.c_str(), etag.size() + 1);
  attrs.emplace(RGW_ATTR_ETAG, std::move(etag_bl));

  /* Create metadata: ACLs. */
  RGWAccessControlPolicy policy;
  policy.create_default(s->user->user_id, s->user->display_name);
  ceph::bufferlist aclbl;
  policy.encode(aclbl);
  attrs.emplace(RGW_ATTR_ACL, std::move(aclbl));

  /* Create metadata: compression info. */
  if (compressor && compressor->is_compressed()) {
    ceph::bufferlist tmp;
    RGWCompressionInfo cs_info;
    cs_info.compression_type = plugin->get_type_name();
    cs_info.orig_size = s->obj_size;
    cs_info.blocks = std::move(compressor->get_compression_blocks());
    encode(cs_info, tmp);
    attrs.emplace(RGW_ATTR_COMPRESSION, std::move(tmp));
  }

  /* Complete the transaction. */
  op_ret = processor.complete(size, etag, nullptr, ceph::real_time(), attrs,
                              ceph::real_time() /* delete_at */);
  if (op_ret < 0) {
    ldout(s->cct, 20) << "bulk upload: processor::complete returned op_ret="
                      << op_ret << dendl;
  }

  return op_ret;
}

void RGWBulkUploadOp::execute()
{
  ceph::bufferlist buffer(64 * 1024);

  ldout(s->cct, 20) << "bulk upload: start" << dendl;

  /* Create an instance of stream-abstracting class. Having this indirection
   * allows for easy introduction of decompressors like gzip and bzip2. */
  auto stream = create_stream();
  if (! stream) {
    return;
  }

  /* Handling the $UPLOAD_PATH accordingly to the Swift's Bulk middleware. See: 
   * https://github.com/openstack/swift/blob/2.13.0/swift/common/middleware/bulk.py#L31-L41 */
  std::string bucket_path, file_prefix;
  std::tie(bucket_path, file_prefix) = handle_upload_path(s);

  auto status = rgw::tar::StatusIndicator::create();
  do {
    op_ret = stream->get_exactly(rgw::tar::BLOCK_SIZE, buffer);
    if (op_ret < 0) {
      ldout(s->cct, 2) << "bulk upload: cannot read header" << dendl;
      return;
    }

    /* We need to re-interpret the buffer as a TAR block. Exactly two blocks
     * must be tracked to detect out end-of-archive. It occurs when both of
     * them are empty (zeroed). Tracing this particular inter-block dependency
     * is responsibility of the rgw::tar::StatusIndicator class. */
    boost::optional<rgw::tar::HeaderView> header;
    std::tie(status, header) = rgw::tar::interpret_block(status, buffer);

    if (! status.empty() && header) {
      /* This specific block isn't empty (entirely zeroed), so we can parse
       * it as a TAR header and dispatch. At the moment we do support only
       * regular files and directories. Everything else (symlinks, devices)
       * will be ignored but won't cease the whole upload. */
      switch (header->get_filetype()) {
        case rgw::tar::FileType::NORMAL_FILE: {
          ldout(s->cct, 2) << "bulk upload: handling regular file" << dendl;

          boost::string_ref filename = bucket_path.empty() ? header->get_filename() : \
                            file_prefix + header->get_filename().to_string();
          auto body = AlignedStreamGetter(0, header->get_filesize(),
                                          rgw::tar::BLOCK_SIZE, *stream);
          op_ret = handle_file(filename,
                               header->get_filesize(),
                               body);
          if (! op_ret) {
            /* Only regular files counts. */
            num_created++;
          } else {
            failures.emplace_back(op_ret, filename.to_string());
          }
          break;
        }
        case rgw::tar::FileType::DIRECTORY: {
          ldout(s->cct, 2) << "bulk upload: handling regular directory" << dendl;

          boost::string_ref dirname = bucket_path.empty() ? header->get_filename() : bucket_path;
          op_ret = handle_dir(dirname);
          if (op_ret < 0 && op_ret != -ERR_BUCKET_EXISTS) {
            failures.emplace_back(op_ret, dirname.to_string());
          }
          break;
        }
        default: {
          /* Not recognized. Skip. */
          op_ret = 0;
          break;
        }
      }

      /* In case of any problems with sub-request authorization Swift simply
       * terminates whole upload immediately. */
      if (boost::algorithm::contains(std::initializer_list<int>{ op_ret },
                                     terminal_errors)) {
        ldout(s->cct, 2) << "bulk upload: terminating due to ret=" << op_ret
                         << dendl;
        break;
      }
    } else {
      ldout(s->cct, 2) << "bulk upload: an empty block" << dendl;
      op_ret = 0;
    }

    buffer.clear();
  } while (! status.eof());

  return;
}

RGWBulkUploadOp::AlignedStreamGetter::~AlignedStreamGetter()
{
  const size_t aligned_legnth = length + (-length % alignment);
  ceph::bufferlist junk;

  DecoratedStreamGetter::get_exactly(aligned_legnth - position, junk);
}

ssize_t RGWBulkUploadOp::AlignedStreamGetter::get_at_most(const size_t want,
                                                          ceph::bufferlist& dst)
{
  const size_t max_to_read = std::min(want, length - position);
  const auto len = DecoratedStreamGetter::get_at_most(max_to_read, dst);
  if (len > 0) {
    position += len;
  }
  return len;
}

ssize_t RGWBulkUploadOp::AlignedStreamGetter::get_exactly(const size_t want,
                                                          ceph::bufferlist& dst)
{
  const auto len = DecoratedStreamGetter::get_exactly(want, dst);
  if (len > 0) {
    position += len;
  }
  return len;
}

int RGWSetAttrs::verify_permission()
{
  // This looks to be part of the RGW-NFS machinery and has no S3 or
  // Swift equivalent.
  bool perm;
  if (!s->object.empty()) {
    perm = verify_object_permission_no_policy(s, RGW_PERM_WRITE);
  } else {
    perm = verify_bucket_permission_no_policy(s, RGW_PERM_WRITE);
  }
  if (!perm)
    return -EACCES;

  return 0;
}

void RGWSetAttrs::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

void RGWSetAttrs::execute()
{
  op_ret = get_params();
  if (op_ret < 0)
    return;

  rgw_obj obj(s->bucket, s->object);

  if (!s->object.empty()) {
    store->set_atomic(s->obj_ctx, obj);
    op_ret = store->set_attrs(s->obj_ctx, s->bucket_info, obj, attrs, nullptr);
  } else {
    for (auto& iter : attrs) {
      s->bucket_attrs[iter.first] = std::move(iter.second);
    }
    op_ret = rgw_bucket_set_attrs(store, s->bucket_info, s->bucket_attrs,
				  &s->bucket_info.objv_tracker);
  }
}

void RGWGetObjLayout::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

void RGWGetObjLayout::execute()
{
  rgw_obj obj(s->bucket, s->object);
  RGWRados::Object target(store,
                          s->bucket_info,
                          *static_cast<RGWObjectCtx *>(s->obj_ctx),
                          rgw_obj(s->bucket, s->object));
  RGWRados::Object::Read stat_op(&target);

  op_ret = stat_op.prepare();
  if (op_ret < 0) {
    return;
  }

  head_obj = stat_op.state.head_obj;

  op_ret = target.get_manifest(&manifest);
}


int RGWConfigBucketMetaSearch::verify_permission()
{
  if (!s->auth.identity->is_owner_of(s->bucket_owner.get_id())) {
    return -EACCES;
  }

  return 0;
}

void RGWConfigBucketMetaSearch::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

void RGWConfigBucketMetaSearch::execute()
{
  op_ret = get_params();
  if (op_ret < 0) {
    ldout(s->cct, 20) << "NOTICE: get_params() returned ret=" << op_ret << dendl;
    return;
  }

  s->bucket_info.mdsearch_config = mdsearch_config;

  op_ret = store->put_bucket_instance_info(s->bucket_info, false, real_time(), &s->bucket_attrs);
  if (op_ret < 0) {
    ldout(s->cct, 0) << "NOTICE: put_bucket_info on bucket=" << s->bucket.name << " returned err=" << op_ret << dendl;
    return;
  }
}

int RGWGetBucketMetaSearch::verify_permission()
{
  if (!s->auth.identity->is_owner_of(s->bucket_owner.get_id())) {
    return -EACCES;
  }

  return 0;
}

void RGWGetBucketMetaSearch::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

int RGWDelBucketMetaSearch::verify_permission()
{
  if (!s->auth.identity->is_owner_of(s->bucket_owner.get_id())) {
    return -EACCES;
  }

  return 0;
}

void RGWDelBucketMetaSearch::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

void RGWDelBucketMetaSearch::execute()
{
  s->bucket_info.mdsearch_config.clear();

  op_ret = store->put_bucket_instance_info(s->bucket_info, false, real_time(), &s->bucket_attrs);
  if (op_ret < 0) {
    ldout(s->cct, 0) << "NOTICE: put_bucket_info on bucket=" << s->bucket.name << " returned err=" << op_ret << dendl;
    return;
  }
}


RGWHandler::~RGWHandler()
{
}

int RGWHandler::init(RGWRados *_store,
                     struct req_state *_s,
                     rgw::io::BasicClient *cio)
{
  store = _store;
  s = _s;

  return 0;
}

int RGWHandler::do_init_permissions()
{
  int ret = rgw_build_bucket_policies(store, s);
  if (ret < 0) {
    ldout(s->cct, 10) << "init_permissions on " << s->bucket
        << " failed, ret=" << ret << dendl;
    return ret==-ENODATA ? -EACCES : ret;
  }

  s->env = rgw_build_iam_environment(store, s);
  return ret;
}

int RGWHandler::do_read_permissions(RGWOp *op, bool only_bucket)
{
  if (only_bucket) {
    /* already read bucket info */
    return 0;
  }
  int ret = rgw_build_object_policies(store, s, op->prefetch_data(), op->is_head_obj());

  if (ret < 0) {
    ldout(s->cct, 10) << "read_permissions on " << s->bucket << ":"
		      << s->object << " only_bucket=" << only_bucket
		      << " ret=" << ret << dendl;
#ifdef WITH_BCEBOS
    if (op->name().compare("list_multipart") == 0 && ret == -ENOENT &&
        (s->prot_flags & RGW_REST_BOS)) {
      ret = -ERR_NO_SUCH_UPLOAD;
    }
#endif
    if (ret == -ENODATA) {
      ret = -EACCES;
    }
  }

  return ret;
}

int RGWOp::error_handler(int err_no, string *error_content) {
  return dialect_handler->error_handler(err_no, error_content);
}

int RGWHandler::error_handler(int err_no, string *error_content) {
  // This is the do-nothing error handler
  return err_no;
}


void RGWPutBucketPolicy::send_response()
{
  if (op_ret) {
    set_req_state_err(s, op_ret);
  }
  dump_errno(s);
  end_header(s);
}

int RGWPutBucketPolicy::verify_permission()
{
#ifdef WITH_BCEBOS
  if (s->prot_flags & RGW_REST_BOS) {
    if (!verify_bucket_permission(s, rgw::IAM::s3PutBucketAcl)) {
      return -EACCES;
    }
  } else
#endif
  {
    if (!verify_bucket_permission(s, rgw::IAM::s3PutBucketPolicy)) {
      return -EACCES;
    }
  }

  return 0;
}

int RGWPutBucketPolicy::get_params()
{
  const auto max_size = s->cct->_conf->rgw_max_put_param_size;
  // At some point when I have more time I want to make a version of
  // rgw_rest_read_all_input that doesn't use malloc.
  op_ret = rgw_rest_read_all_input(s, &data, &len, max_size, false);
  // And throws exceptions.
  return op_ret;
}

void RGWPutBucketPolicy::execute()
{
  op_ret = get_params();
  if (op_ret < 0) {
    return;
  }

  bufferlist in_data = bufferlist::static_from_mem(data, len);

  if (!store->is_meta_master()) {
    op_ret = forward_request_to_master(s, NULL, store, in_data, nullptr);
    if (op_ret < 0) {
      ldout(s->cct, 20) << "forward_request_to_master returned ret=" << op_ret << dendl;
      return;
    }
  }

  try {
    const Policy p(s->cct, s->bucket_tenant, in_data);
    op_ret = retry_raced_bucket_write(store, s, [&p, this] {
      auto attrs = s->bucket_attrs;
      attrs[RGW_ATTR_IAM_POLICY].clear();
      attrs[RGW_ATTR_IAM_POLICY].append(p.text);
      op_ret = rgw_bucket_set_attrs(store, s->bucket_info, attrs,
                                    &s->bucket_info.objv_tracker);
      return op_ret;
    });
  } catch (rgw::IAM::PolicyParseException& e) {
    ldout(s->cct, 20) << "failed to parse policy: " << e.what() << dendl;
#ifdef WITH_BCEBOS
    if (s->prot_flags & RGW_REST_BOS)
      op_ret = -ERR_MALFORMED_JSON;
    else
#endif
    op_ret = -EINVAL;
  }
}

void RGWGetBucketPolicy::send_response()
{
  if (op_ret) {
    set_req_state_err(s, op_ret);
  }
  dump_errno(s);
  end_header(s, this, "application/json");
  dump_body(s, policy);
}

int RGWGetBucketPolicy::verify_permission()
{
#ifdef WITH_BCEBOS
  if (s->prot_flags & RGW_REST_BOS) {
    if (!verify_bucket_permission(s, rgw::IAM::s3GetBucketAcl)) {
      return -EACCES;
    }
  } else
#endif
  {
    if (!verify_bucket_permission(s, rgw::IAM::s3GetBucketPolicy)) {
      return -EACCES;
    }
  }

  return 0;
}

void RGWGetBucketPolicy::execute()
{
  auto attrs = s->bucket_attrs;
  map<string, bufferlist>::iterator aiter = attrs.find(RGW_ATTR_IAM_POLICY);

#ifdef WITH_BCEBOS
  if (s->prot_flags & RGW_REST_BOS) {
    if (aiter != attrs.end()) {
      policy = attrs[RGW_ATTR_IAM_POLICY];
    }
    return;
  }
#endif

  if (aiter == attrs.end()) {
    ldout(s->cct, 0) << __func__ << " can't find bucket IAM POLICY attr" 
                     << " bucket_name = " << s->bucket_name << dendl;
    op_ret = -ERR_NO_SUCH_BUCKET_POLICY;
    s->err.message = "The bucket policy does not exist";
    return;
  } else {
    policy = attrs[RGW_ATTR_IAM_POLICY];

    if (policy.length() == 0) {
      ldout(s->cct, 10) << "The bucket policy does not exist, bucket: " << s->bucket_name << dendl;
      op_ret = -ERR_NO_SUCH_BUCKET_POLICY;
      s->err.message = "The bucket policy does not exist";
      return;
    }
  }
}

void RGWDeleteBucketPolicy::send_response()
{
  if (op_ret) {
    set_req_state_err(s, op_ret);
  }
  dump_errno(s);
  end_header(s);
}

int RGWDeleteBucketPolicy::verify_permission()
{
  if (!verify_bucket_permission(s, rgw::IAM::s3DeleteBucketPolicy)) {
    return -EACCES;
  }

  return 0;
}

void RGWDeleteBucketPolicy::execute()
{
  op_ret = retry_raced_bucket_write(store, s, [this] {
      auto attrs = s->bucket_attrs;
      attrs.erase(RGW_ATTR_IAM_POLICY);
      op_ret = rgw_bucket_set_attrs(store, s->bucket_info, attrs,
				    &s->bucket_info.objv_tracker);
      return op_ret;
    });
}

void RGWInitBucketObjectLock::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

int RGWInitBucketObjectLock::verify_permission()
{
  return verify_bucket_owner_or_policy(s, rgw::IAM::s3InitBucketObjectLockConfiguration);
}

void RGWInitBucketObjectLock::execute()
{
  op_ret = get_params();
  if (op_ret < 0) {
    return;
  }

  if (retention_days <= 0) {
    ldout(s->cct, 0) << __func__ << "() ERORR: invalid retention days: " << retention_days << dendl;
    op_ret = -EINVAL;
    return;
  }


  op_ret = retry_raced_bucket_write(store, s, [this] {
    op_ret = s->bucket_info.bos_obj_lock.init_object_lock(retention_days, s->cct->_conf->rgw_bos_worm_expiration_time);
    if (op_ret < 0) {
      ldout(s->cct, 0) << __func__ << "() ERROR: invalid object lock status." << dendl;
      return op_ret;
    }
    op_ret = store->put_bucket_instance_info(s->bucket_info, false,
                                             real_time(), &s->bucket_attrs);
    return op_ret;
  });
}

void RGWGetBucketObjectLock::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

int RGWGetBucketObjectLock::verify_permission()
{
  return verify_bucket_owner_or_policy(s, rgw::IAM::s3GetBucketObjectLockConfiguration);
}

void RGWGetBucketObjectLock::execute() {
  if (s->prot_flags & RGW_REST_S3) {
    if (!s->bucket_info.obj_lock_enabled()) {
      op_ret = -ERR_NO_SUCH_OBJECT_LOCK_CONFIGURATION;
    }
    return;
  }

  // bucket object lock status update, update bucket info
  BOSObjectLockStatus bos_lock_status = BOS_OBJECT_LOCK_STATUS_UNLOCK;
  op_ret = retry_raced_bucket_write(store, s, [&bos_lock_status, this] {
    bool status_update = false;
    bos_lock_status = s->bucket_info.bos_obj_lock.get_lock_status(&status_update);
    if (status_update) {
      op_ret = store->put_bucket_instance_info(s->bucket_info, false,
                                               real_time(), &s->bucket_attrs);
    }
    return op_ret;
  });
  if (bos_lock_status == BOS_OBJECT_LOCK_STATUS_UNLOCK) {
    ldout(s->cct, 0) << __func__ << "() ERROR: no such bucket object lock, you should init bucket object lock first." << dendl;
    op_ret = -ERR_NO_SUCH_OBJECT_LOCK_CONFIGURATION;
    return;
  }

  switch (bos_lock_status) {
    case BOS_OBJECT_LOCK_STATUS_EXPIRED:
      lock_status = BOS_WORM_EXPIRED; break;
    case BOS_OBJECT_LOCK_STATUS_IN_PROGRESS:
      lock_status = BOS_WORM_IN_PROGRESS; break;
    case BOS_OBJECT_LOCK_STATUS_LOCKED:
      lock_status = BOS_WORM_LOCKED; break;
    case BOS_OBJECT_LOCK_STATUS_UNLOCK:
      lock_status = BOS_WORM_UNLOCK; break;
  }

  create_date = s->bucket_info.bos_obj_lock.get_create_date();
  retention_days = s->bucket_info.bos_obj_lock.get_retention_days();
}

void RGWDeleteBucketObjectLock::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

int RGWDeleteBucketObjectLock::verify_permission()
{
  return verify_bucket_owner_or_policy(s, rgw::IAM::s3DeleteBucketObjectLockConfiguration);
}

void RGWDeleteBucketObjectLock::execute()
{
  op_ret = retry_raced_bucket_write(store, s, [this] {
    op_ret = s->bucket_info.bos_obj_lock.delete_object_lock();
    if (op_ret < 0) {
      ldout(s->cct, 0) << __func__ << "() ERROR: invalid bucket object lock status." << dendl;
      return op_ret;
    }

    op_ret = store->put_bucket_instance_info(s->bucket_info, false,
                                             real_time(), &s->bucket_attrs);
    return op_ret;
  });
}

void RGWCompleteBucketObjectLock::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

int RGWCompleteBucketObjectLock::verify_permission()
{
  return verify_bucket_owner_or_policy(s, rgw::IAM::s3CompleteBucketObjectLockConfiguration);
}

void RGWCompleteBucketObjectLock::execute()
{
  op_ret = retry_raced_bucket_write(store, s, [this] {
    op_ret = s->bucket_info.bos_obj_lock.complete_object_lock();
    if (op_ret < 0) {
      ldout(s->cct, 0) << __func__ << "() ERROR: invalid bucket object lock status." << dendl;
      return op_ret;
    }

    op_ret = store->put_bucket_instance_info(s->bucket_info, false,
                                             real_time(), &s->bucket_attrs);
    return op_ret;
  });
}

void RGWExtendBucketObjectLock::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

int RGWExtendBucketObjectLock::verify_permission()
{
  return verify_bucket_owner_or_policy(s, rgw::IAM::s3ExtendBucketObjectLockConfiguration);
}

void RGWExtendBucketObjectLock::execute()
{
  op_ret = get_params();
  if (op_ret < 0) {
    return;
  }

  if (extend_retention_days <= 0) {
    ldout(s->cct, 0) << __func__ << "() ERORR: invalid extend retention days: " << extend_retention_days << dendl;
    op_ret = -EINVAL;
    return;
  }

  op_ret = retry_raced_bucket_write(store, s, [this] {
    op_ret = s->bucket_info.bos_obj_lock.update_retention_days(extend_retention_days);
    if (op_ret < 0) {
      ldout(s->cct, 0) << __func__ << "() ERROR: invalid object lock status or extend retention days less than retention days." << dendl;
      return op_ret;
    }

    op_ret = store->put_bucket_instance_info(s->bucket_info, false,
                                             real_time(), &s->bucket_attrs);
    return op_ret;
  });
}

void RGWPutBucketObjectLock::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

int RGWPutBucketObjectLock::verify_permission()
{
  return verify_bucket_owner_or_policy(s, rgw::IAM::s3PutBucketObjectLockConfiguration);
}

void RGWPutBucketObjectLock::execute()
{
  if (!s->bucket_info.obj_lock_enabled()) {
    ldout(s->cct, 0) << "ERROR: object Lock configuration cannot be enabled on existing buckets" << dendl;
    op_ret = -ERR_INVALID_BUCKET_STATE;
    return;
  }

  RGWXMLDecoder::XMLParser parser;
  if (!parser.init()) {
    ldout(s->cct, 0) << "ERROR: failed to initialize parser" << dendl;
    op_ret = -EINVAL;
    return;
  }
  op_ret = get_params();
  if (op_ret < 0) {
    return;
  }
  if (!parser.parse(data.c_str(), data.length(), 1)) {
    op_ret = -ERR_MALFORMED_XML;
    return;
  }

  try {
    RGWXMLDecoder::decode_xml("ObjectLockConfiguration", obj_lock, &parser, true);
  } catch (RGWXMLDecoder::err& err) {
    ldout(s->cct, 5) << "unexpected xml:" << err << dendl;
    op_ret = -ERR_MALFORMED_XML;
    return;
  }
  if (obj_lock.has_rule() && !obj_lock.retention_period_valid()) {
    ldout(s->cct, 0) << "ERROR: retention period must be a positive integer value" << dendl;
    op_ret = -ERR_INVALID_RETENTION_PERIOD;
    return;
  }

  if (!store->is_meta_master()) {
    op_ret = forward_request_to_master(s, NULL, store, data, nullptr);
    if (op_ret < 0) {
      ldout(s->cct, 20) << __func__ << "forward_request_to_master returned ret=" << op_ret << dendl;
      return;
    }
  }

  op_ret = retry_raced_bucket_write(store, s, [this] {
    s->bucket_info.obj_lock = obj_lock;
    op_ret = store->put_bucket_instance_info(s->bucket_info, false,
                                             real_time(), &s->bucket_attrs);
    return op_ret;
  });
  return;
}

int RGWPutObjRetention::verify_permission()
{
  if (!verify_object_permission(s, rgw::IAM::s3PutObjectRetention)) {
    return -EACCES;
  }
  op_ret = get_params();
  if (op_ret) {
    return op_ret;
  }
  if (bypass_governance_mode) {
    bypass_perm = verify_object_permission(s, rgw::IAM::s3BypassGovernanceRetention);
  }
  return 0;
}

void RGWPutObjRetention::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

void RGWPutObjRetention::execute()
{
  if (!s->bucket_info.obj_lock_enabled()) {
    ldout(s->cct, 0) << "ERROR: object retention can't be set if bucket object lock not configured" << dendl;
    op_ret = -ERR_INVALID_REQUEST;
    return;
  }

  RGWXMLDecoder::XMLParser parser;
  if (!parser.init()) {
    ldout(s->cct, 0) << "ERROR: failed to initialize parser" << dendl;
    op_ret = -EINVAL;
    return;
  }

  if (!parser.parse(data.c_str(), data.length(), 1)) {
    op_ret = -ERR_MALFORMED_XML;
    return;
  }

  try {
    RGWXMLDecoder::decode_xml("Retention", obj_retention, &parser, true);
  } catch (RGWXMLDecoder::err& err) {
    ldout(s->cct, 5) << "unexpected xml:" << err << dendl;
    op_ret = -ERR_MALFORMED_XML;
    return;
  }

  if (ceph::real_clock::to_time_t(obj_retention.get_retain_until_date()) < ceph_clock_now()) {
    ldout(s->cct, 0) << "ERROR: the retain until date must be in the future" << dendl;
    op_ret = -EINVAL;
    return;
  }
  bufferlist bl;
  obj_retention.encode(bl);
  rgw_obj obj(s->bucket, s->object);

  //check old retention
  map<string, bufferlist> attrs;
  op_ret = get_obj_attrs(store, s, obj, attrs);
  if (op_ret < 0) {
    ldout(s->cct, 0) << "ERROR: get obj attr error"<< dendl;
    return;
  }
  auto aiter = attrs.find(RGW_ATTR_OBJECT_RETENTION);
  if (aiter != attrs.end()) {
    RGWObjectRetention old_obj_retention;
    try {
      decode(old_obj_retention, aiter->second);
    } catch (buffer::error& err) {
      ldout(s->cct, 0) << "ERROR: failed to decode RGWObjectRetention" << dendl;
      op_ret = -EIO;
      return;
    }
    if (ceph::real_clock::to_time_t(obj_retention.get_retain_until_date()) < ceph::real_clock::to_time_t(old_obj_retention.get_retain_until_date())) {
      if (old_obj_retention.get_mode().compare("GOVERNANCE") != 0 || !bypass_perm || !bypass_governance_mode) {
        op_ret = -EACCES;
        return;
      }
    }
  }

  op_ret = modify_obj_attr(store, s, obj, RGW_ATTR_OBJECT_RETENTION, bl);

  return;
}

int RGWGetObjRetention::verify_permission()
{
  if (!verify_object_permission(s, rgw::IAM::s3GetObjectRetention)) {
    return -EACCES;
  }
  return 0;
}

void RGWGetObjRetention::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

void RGWGetObjRetention::execute()
{
  if (!s->bucket_info.obj_lock_enabled()) {
    ldout(s->cct, 0) << "ERROR: bucket object lock not configured" << dendl;
    op_ret = -ERR_INVALID_REQUEST;
    return;
  }
  rgw_obj obj(s->bucket, s->object);
  map<string, bufferlist> attrs;
  op_ret = get_obj_attrs(store, s, obj, attrs);
  if (op_ret < 0) {
    ldout(s->cct, 0) << "ERROR: failed to get obj attrs, obj=" << obj
                       << " ret=" << op_ret << dendl;
    return;
  }
  auto aiter = attrs.find(RGW_ATTR_OBJECT_RETENTION);
  if (aiter == attrs.end()) {
    op_ret = -ERR_NO_SUCH_OBJECT_LOCK_CONFIGURATION;
    return;
  }

  bufferlist::iterator iter{&aiter->second};
  try {
    obj_retention.decode(iter);
  } catch (const buffer::error& e) {
    ldout(s->cct, 0) << __func__ <<  "decode object retention config failed" << dendl;
    op_ret = -EIO;
    return;
  }
  return;
}

int RGWPutObjLegalHold::verify_permission()
{
  if (!verify_object_permission(s, rgw::IAM::s3PutObjectLegalHold)) {
    return -EACCES;
  }
  return 0;
}

void RGWPutObjLegalHold::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

void RGWPutObjLegalHold::execute() {
  if (!s->bucket_info.obj_lock_enabled()) {
    ldout(s->cct, 0) << "ERROR: object legal hold can't be set if bucket object lock not configured" << dendl;
    op_ret = -ERR_INVALID_REQUEST;
    return;
  }

  RGWXMLDecoder::XMLParser parser;
  if (!parser.init()) {
    ldout(s->cct, 0) << "ERROR: failed to initialize parser" << dendl;
    op_ret = -EINVAL;
    return;
  }

  op_ret = get_params();
  if (op_ret < 0)
    return;

  if (!parser.parse(data.c_str(), data.length(), 1)) {
    op_ret = -ERR_MALFORMED_XML;
    return;
  }

  try {
    RGWXMLDecoder::decode_xml("LegalHold", obj_legal_hold, &parser, true);
  } catch (RGWXMLDecoder::err &err) {
    ldout(s->cct, 5) << "unexpected xml:" << err << dendl;
    op_ret = -ERR_MALFORMED_XML;
    return;
  }
  bufferlist bl;
  obj_legal_hold.encode(bl);
  rgw_obj obj(s->bucket, s->object);
  //if instance is empty, we should modify the latest object
  op_ret = modify_obj_attr(store, s, obj, RGW_ATTR_OBJECT_LEGAL_HOLD, bl);
  return;
}

int RGWGetObjLegalHold::verify_permission()
{
  if (!verify_object_permission(s, rgw::IAM::s3GetObjectLegalHold)) {
    return -EACCES;
  }
  return 0;
}

void RGWGetObjLegalHold::pre_exec()
{
  rgw_bucket_object_pre_exec(s);
}

void RGWGetObjLegalHold::execute()
{
  if (!s->bucket_info.obj_lock_enabled()) {
    ldout(s->cct, 0) << "ERROR: bucket object lock not configured" << dendl;
    op_ret = -ERR_INVALID_REQUEST;
    return;
  }
  rgw_obj obj(s->bucket, s->object);
  map<string, bufferlist> attrs;
  op_ret = get_obj_attrs(store, s, obj, attrs);
  if (op_ret < 0) {
    ldout(s->cct, 0) << "ERROR: failed to get obj attrs, obj=" << obj
                       << " ret=" << op_ret << dendl;
    return;
  }
  auto aiter = attrs.find(RGW_ATTR_OBJECT_LEGAL_HOLD);
  if (aiter == attrs.end()) {
    op_ret = -ERR_NO_SUCH_OBJECT_LOCK_CONFIGURATION;
    return;
  }

  bufferlist::iterator iter{&aiter->second};
  try {
    obj_legal_hold.decode(iter);
  } catch (const buffer::error& e) {
    ldout(s->cct, 0) << __func__ <<  "decode object legal hold config failed" << dendl;
    op_ret = -EIO;
    return;
  }
  return;
}

void RGWGetClusterStat::execute()
{
  op_ret = this->store->get_rados_handle()->cluster_stat(stats_op);
}

void RGWControl::send_response()
{
  if (op_ret) {
    set_req_state_err(s, op_ret);
  }
  dump_errno(s);
  end_header(s);
}

int RGWControl::verify_permission()
{
  int ret = check_caps(s->user->caps);
  ldout(s->cct, 0) << "INFO: verify_permissions ret" << ret << dendl;
  return ret;
}

int RGWControl::check_caps(RGWUserCaps& caps)
{
    return caps.check_cap("control", RGW_CAP_WRITE);
}

int RGWBanControl::get_params()
{
  bucket_name = s->info.args.get("bucketName");
  object_name = s->info.args.get("objectName");

  if (bucket_name.empty()) {
    ldout(s->cct, 0) << "ERROR: bucket is empty"<< dendl;
    return -EINVAL;
  }
  return 0;
}

void RGWBanControl::execute()
{
  op_ret = get_params();
  if (op_ret < 0) {
    return;
  }

  if (!bucket_name.empty()) {
    RGWObjectCtx obj_ctx(store);
    RGWBucketInfo target_bucket_info;
    map<string, bufferlist> target_bucket_attrs;

    int ret = store->get_bucket_info(obj_ctx, s->user->user_id.tenant,
                                     bucket_name, target_bucket_info, nullptr,
                                     &target_bucket_attrs);
    if (ret < 0) {
      ldout(s->cct, 0) << __func__ << " ERROR: could not fetch bucket info, bucket: "
                       << bucket_name << ", ret=" << ret << dendl;
      op_ret = -ERR_NO_SUCH_BUCKET;
      return;
    }

    // set bucket ban xattr
    if (object_name.empty()) {
      if (!store->is_meta_master()) {
        op_ret = forward_request_to_master(s, NULL, store, in_data, nullptr);
        if (op_ret < 0) {
          ldout(s->cct, 0) << __func__ << " ERROR: forward_request_to_master returned ret="
                           << op_ret << dendl;
          return;
        }
      }

      bufferlist bl;
      string is_ban = "true";
      encode(is_ban, bl);

      target_bucket_attrs[RGW_ATTR_BAN] = bl;
      op_ret = rgw_bucket_set_attrs(store, target_bucket_info, target_bucket_attrs, &target_bucket_info.objv_tracker);
    // set object ban xattr
    } else {
      rgw_obj obj(target_bucket_info.bucket, object_name);
      map<string, bufferlist> attrs;
      RGWRados::Object op_target(store, target_bucket_info, *static_cast<RGWObjectCtx *>(s->obj_ctx), obj);
      RGWRados::Object::Read read_op(&op_target);
      read_op.params.attrs = &attrs;
      bufferlist bl;
      string is_ban = "true";
      encode(is_ban, bl);

      op_ret = read_op.prepare();
      if (op_ret < 0) {
        ldout(s->cct, 0) << __func__ << " ERROR: read obj stat error " << obj
                         << " ret=" << op_ret << dendl;
        return;
      }

      store->set_atomic(&obj_ctx, read_op.state.obj);
      attrs[RGW_ATTR_BAN] = bl;
      store->set_attrs(s->obj_ctx, target_bucket_info, obj, attrs, NULL);
    }
  }

  op_ret = 0;
}

int RGWUnBanControl::get_params()
{
  bucket_name = s->info.args.get("bucketName");
  object_name = s->info.args.get("objectName");

  if (bucket_name.empty()) {
    ldout(s->cct, 0) << "ERROR: bucket is empty"<< dendl;
    return -EINVAL;
  }
  return 0;
}

void RGWUnBanControl::execute()
{
  op_ret = get_params();
  if (op_ret < 0) {
    return;
  }

  if (!bucket_name.empty()) {
    RGWBucketInfo bucket_info;
    map<string, bufferlist> bucket_attrs;
    RGWObjectCtx obj_ctx(store);

    int ret = store->get_bucket_info(obj_ctx, s->user->user_id.tenant,
                                     bucket_name, bucket_info, NULL,
                                     &bucket_attrs);
    if (ret < 0) {
      ldout(s->cct, 0) << __func__ << " ERROR: could not fetch bucket info, bucket: " << bucket_name
          << ", ret=" << ret << dendl;
      op_ret = -ERR_NO_SUCH_BUCKET;
    }
    // set bucket unban xattr
    if (object_name.empty()) {
      if (!store->is_meta_master()) {
        op_ret = forward_request_to_master(s, NULL, store, in_data, nullptr);
        if (op_ret < 0) {
          ldout(s->cct, 0) << __func__ << " ERROR: forward_request_to_master returned ret="
                           << op_ret << dendl;
          return;
        }
      }

      map<string, bufferlist>::iterator aiter = bucket_attrs.find(RGW_ATTR_BAN);
      if (aiter != bucket_attrs.end()) {
        bucket_attrs.erase(RGW_ATTR_BAN);
        op_ret = rgw_bucket_set_attrs(store, bucket_info, bucket_attrs, &bucket_info.objv_tracker);
      }
    } else {
      // set object unban xattr
      rgw_obj obj(bucket_info.bucket, object_name);
      map<string, bufferlist> attrs;
      map<string, bufferlist> rmattr;
      RGWRados::Object op_target(store, bucket_info, *static_cast<RGWObjectCtx *>(s->obj_ctx), obj);
      RGWRados::Object::Read read_op(&op_target);
      read_op.params.attrs = &attrs;
      op_ret = read_op.prepare();
      if (op_ret < 0) {
        ldout(s->cct, 0) << __func__ << " ERROR: read obj stat error " << obj
                         << " ret=" << op_ret << dendl;
        return;
      }
      bufferlist bl;
      rmattr[RGW_ATTR_BAN] = bl;
      store->set_attrs(s->obj_ctx, bucket_info, obj, attrs, &rmattr);
    }
  }

  op_ret = 0;
}

int RGWPutBucketNotification::verify_permission()
{
  if (!verify_bucket_permission(s, rgw::IAM::s3PutBucketPolicy)) {
    return -EACCES;
  }

  return 0;
}

void RGWPutBucketNotification::execute()
{
  op_ret = get_params();
  if (op_ret < 0) {
    return;
  }

  if (!store->is_meta_master()) {
    bufferlist in_data = bufferlist::static_from_mem(data, len);
    op_ret = forward_request_to_master(s, NULL, store, in_data, nullptr);
    if (op_ret < 0) {
      ldout(s->cct, 0) << __func__ << " ERROR: forward_request_to_master returned ret=" << op_ret << dendl;
      return;
    }
  }

  op_ret = retry_raced_bucket_write(store, s, [this] {
    auto attrs = s->bucket_attrs;
    attrs[RGW_ATTR_NOTIFICATION].clear();
    attrs[RGW_ATTR_NOTIFICATION] = notification_bl;
    op_ret = rgw_bucket_set_attrs(store, s->bucket_info, attrs, &s->bucket_info.objv_tracker);
    return op_ret;
  });
}

int RGWGetBucketNotification::verify_permission()
{
  if (!s->auth.identity->is_owner_of(s->bucket_owner.get_id())) {
    return -EACCES;
  }

  return 0;
}

void RGWGetBucketNotification::execute()
{
  auto attrs = s->bucket_attrs;
  map<string, bufferlist>::iterator aiter = attrs.find(RGW_ATTR_NOTIFICATION);
  if (aiter == attrs.end()) {
    ldout(s->cct, 0) << __func__ << " ERROR: can't find bucket NOTIFICATION attr"
                     << " bucket_name = " << s->bucket_name << dendl;
    op_ret = -ERR_NO_SUCH_BUCKET_NOTIFICATION;
    s->err.message = "The bucket notification does not exist";
    return;
  } else {
    notification_bl = attrs[RGW_ATTR_NOTIFICATION];

    if (notification_bl.length() == 0) {
      ldout(s->cct, 0) << __func__ << " ERROR: the bucket notification does not exist, bucket: "
                      << s->bucket_name << dendl;
      op_ret = -ERR_NO_SUCH_BUCKET_NOTIFICATION;
      s->err.message = "The bucket notification does not exist";
      return;
    }
  }
}

int RGWDeleteBucketNotification::verify_permission()
{
  if (!s->auth.identity->is_owner_of(s->bucket_owner.get_id())) {
    return -EACCES;
  }

  return 0;
}

void RGWDeleteBucketNotification::execute()
{
  op_ret = retry_raced_bucket_write(store, s, [this] {
    auto attrs = s->bucket_attrs;
    attrs.erase(RGW_ATTR_NOTIFICATION);
    op_ret = rgw_bucket_set_attrs(store, s->bucket_info, attrs,
                                  &s->bucket_info.objv_tracker);
    return op_ret;
  });
}

void RGWPutBucketQuota::execute()
{
  op_ret = get_params();
  if (op_ret < 0) {
    ldout(s->cct, 0) << __func__ << " ERROR: can not get the parameters from the request body: bucket_name = " << s->bucket_name << " ret=" << op_ret << dendl;
    return;
  }

  op_ret = check_quota_params();
  if (op_ret < 0) {
    ldout(s->cct, 0) << __func__ << " ERROR: check the quota of bucket: bucket_name = " << s->bucket_name << " ret=" << op_ret << dendl;
    return;
  }

  quota.max_objects = max_objects;
  quota.max_size = max_size_kb;
  quota.enabled = true;

  if (!store->is_meta_master()) {
    op_ret = forward_request_to_master(s, nullptr, store, in_data, nullptr);
    if (op_ret < 0) {
      ldout(s->cct, 0) << "forward_request_to_master returned ret=" << op_ret << dendl;
      return;
    }
  }

  op_ret = retry_raced_bucket_write(store, s, [this] {
    s->bucket_info.quota = quota;
    op_ret = store->put_bucket_instance_info(s->bucket_info, false,
                                             real_time(), &s->bucket_attrs);
    return op_ret;
  });
  if (op_ret < 0) {
    ldout(s->cct, 0) << __func__ << " ERROR: update the quota of bucket: bucket_name = " << s->bucket_name << " ret=" << op_ret << dendl;
    return;
  }
}

void RGWDeleteBucketQuota::execute()
{
  RGWQuotaInfo quota;
  quota.max_objects = -1;
  quota.max_size = -1;
  quota.enabled = true;

  if (!store->is_meta_master()) {
    bufferlist in_data;
    op_ret = forward_request_to_master(s, nullptr, store, in_data, nullptr);
    if (op_ret < 0) {
      ldout(s->cct, 0) << "forward_request_to_master returned ret=" << op_ret << dendl;
      return;
    }
  }

  op_ret = retry_raced_bucket_write(store, s, [this, quota] {
    s->bucket_info.quota = quota;
    op_ret = store->put_bucket_instance_info(s->bucket_info, false,
                                             real_time(), &s->bucket_attrs);
    return op_ret;
  });
  if (op_ret < 0) {
    ldout(s->cct, 0) << __func__ << " ERROR: update the quota of bucket: bucket_name = " << s->bucket_name << " ret=" << op_ret << dendl;
    return;
  }
}

void RGWPutUserQuota::execute()
{
  op_ret = get_params();
  if (op_ret < 0) {
    ldout(s->cct, 0) << __func__ << " ERROR: can not get the parameters from the request body: user_id = " << uid_str << " ret=" << op_ret << dendl;
    return;
  }

  rgw_user uid(uid_str);
  RGWObjVersionTracker objv;
  RGWUserInfo matched_user_info;
  op_ret = rgw_get_user_info_by_uid(store, uid, matched_user_info, &objv, NULL, NULL);
  if (op_ret < 0) {
    ldout(s->cct, 0) << " ERROR: no such user: user_id = " << uid_str << " ret=" << op_ret << dendl;
    op_ret = -ERR_NO_SUCH_USER;
    return;
  }
  user_info = matched_user_info;
  op_ret = check_quota_params();
  if (op_ret < 0) {
    ldout(s->cct, 0) << __func__ << " ERROR: check the quota of user: user_id = " << uid_str << " ret=" << op_ret << dendl;
    return;
  }

  RGWQuotaInfo quota;
  quota.max_size = max_size_kb;
  quota.max_objects = max_objects;
  quota.enabled = true;
  user_info.max_buckets = max_bucket_count;
  user_info.user_quota = quota;
  op_ret = rgw_store_user_info(store, user_info, &matched_user_info, &objv, real_time(), false);
  if (op_ret < 0) {
    ldout(s->cct, 0) << __func__ << " ERROR: failed updating user info: user_id = " << uid_str << " ret=" << op_ret << dendl;
    return;
  }
}

void RGWGetUserQuota::execute()
{
  std::string uid_str;
  RESTArgs::get_string(s, "uid", uid_str, &uid_str);
  if (uid_str.empty()) {
    uid_str = s->user->user_id.id;
  }
  rgw_user uid(uid_str);

  op_ret = rgw_get_user_info_by_uid(store, uid, user_info);
  if (op_ret < 0) {
    ldout(s->cct, 0) << __func__ << " ERROR: failed updating user info: user_id = " << uid_str << " ret=" << op_ret << dendl;
    return;
  }
}

void RGWDeleteUserQuota::execute()
{
  std::string uid_str;
  RESTArgs::get_string(s, "uid", uid_str, &uid_str);
  if (uid_str.empty()) {
    uid_str = s->user->user_id.id;
  }
  rgw_user uid(uid_str);

  RGWUserInfo user_info;
  op_ret = rgw_get_user_info_by_uid(store, uid, user_info);
  if (op_ret < 0) {
    ldout(s->cct, 0) << __func__ << " ERROR: no such user: user_id = " << uid_str << " ret=" << op_ret << dendl;
    op_ret = -ERR_NO_SUCH_USER;
    return;
  }

  RGWQuotaInfo quota;
  quota.max_size = -1;
  quota.max_objects = -1;
  quota.enabled =  true;
  user_info.max_buckets = s->cct->_conf->rgw_user_max_buckets;
  user_info.user_quota = quota;
  op_ret = rgw_store_user_info(store, user_info, s->user, NULL, real_time(), false);
  if (op_ret < 0) {
    ldout(s->cct, 0) << __func__ << " ERROR: failed updating user info: user_id = " << uid_str << " ret=" << op_ret << dendl;
    return;
  }
}

int RGWGetSymlink::verify_permission()
{
  auto obj = rgw_obj(s->bucket, s->object);
  store->set_atomic(s->obj_ctx, obj);

  auto action = rgw::IAM::s3GetObjectMeta;
  if (obj.key.instance.empty()) {
    action = rgw::IAM::s3GetObject;
  } else {
    action = rgw::IAM::s3GetObjectVersion;
  }
  if (s->iam_policy && s->iam_policy->has_partial_conditional(S3_EXISTING_OBJTAG))
    rgw_iam_add_existing_objtags(store, s, obj, action);


  if (!verify_object_permission(s, action)) {
    return -EACCES;
  }

  return 0;
}
void RGWGetSymlink::execute()
{
  RGWObjectCtx& obj_ctx = *static_cast<RGWObjectCtx *>(s->obj_ctx);
  rgw_obj obj = rgw_obj(s->bucket, s->object);
  store->set_atomic(s->obj_ctx, obj);

  op_ret = store->get_obj_state(&obj_ctx, s->bucket_info, obj, &state);
  if (op_ret < 0) {
    ldout(s->cct, 0) << __func__ << " ERROR: failed to get obj state, obj = " << obj << " ret = " << op_ret << dendl;
    return;
  }

  auto iter = state->attrset.find(RGW_ATTR_TARGET_BUCKET);
  if(iter != state->attrset.end()){
    target_bucket = rgw_bl_to_str(iter->second);
  }

  if (target_bucket == s->bucket.name) {
    target_bucket.clear();
  }

  iter = state->attrset.find(RGW_ATTR_TARGET_TENANT);
  if(iter != state->attrset.end()){
    target_bucket_tenant = rgw_bl_to_str(iter->second);
  } else {
    target_bucket_tenant = s->user->user_id.tenant;
  }

  iter = state->attrset.find(RGW_ATTR_TARGET_OBJECT);
  if(iter != state->attrset.end()){
    target_object = rgw_bl_to_str(iter->second);
    s->symlink_size_out = target_bucket.size() + target_object.size();
  } else {
    op_ret = -ERR_NOT_SYMLINK_OBJECT;
  }
}

/* 
 * When bucket is only one, we don't check read && write policy together.
 * For write operation, we need check bucket policy and acl.
 * But on the other hand, we just need read permission of target object, 
 * which means we may lose the permission verification of target bucket.
 */
int RGWPutSymlink::verify_permission()
{
  op_ret = get_params();
  if (op_ret < 0) {
    ldout(s->cct, 0) << __func__ << ": ERROR get_params op_ret=" << op_ret << dendl;
    return op_ret;
  }

  bool policy_allow = false;
  // 1. check symlink object policy and acl, and symlink policy and acl promote when handler->init_permission
  if (s->iam_policy) {
    rgw_add_grant_to_iam_environment(s->env, s);
    rgw_add_to_iam_environment(s->env, "s3:x-amz-acl", s->canned_acl);
    auto e = s->iam_policy->eval(s->env, *s->auth.identity,
				 rgw::IAM::s3PutObject,
				 rgw_obj(s->bucket, s->object));
    if (e == Effect::Deny) {
      return -EACCES;
    } else if (e == Effect::Allow) {
      policy_allow = true;
    }
  }
  // 2. policy enable PERM_WRITE
  if (!policy_allow) {
    if (!verify_bucket_permission_no_policy(s, RGW_PERM_WRITE)) {
      return -EACCES;
    }
  }

  // 3. retarget name and but not check permission
  RGWObjectCtx& obj_ctx = *static_cast<RGWObjectCtx *>(s->obj_ctx);
  RGWAccessControlPolicy target_acl(s->cct);
  boost::optional<Policy> target_policy;
  // refresh s->object (type rgw_obj_key)
  target_object.set(target_object_name);
  // refresh bucket_name, bucket info, bucket attrs and s->bucket(type rgw_bucket)
  op_ret = store->get_bucket_info(obj_ctx, target_bucket_tenant, target_bucket_name,
                                    target_bucket_info, NULL, &target_bucket_attrs);
  if (op_ret < 0) {
    if (op_ret == -ENOENT) {
      op_ret = -ERR_NO_SUCH_BUCKET;
    }
    return op_ret;
  }
  target_bucket = target_bucket_info.bucket;
  // when symlink bucket is same as target bucket, should not check bucket && object acl
  if (target_bucket_name.compare(s->bucket.name) == 0) {
    return 0;
  }

  // donot should check target bucket&object permission, becase mirroring bucket case is meaningful
  return 0;
}

/*
 * for symlink object, donot support multi version.
*/
void RGWPutSymlink::execute()
{
  if (s->bucket_info.versioning_enabled()) {
    // do not support create symlink in versioning_enabled bucket
    ldout(s->cct, 0) << __func__ << "ERROR: Cannot create symlink in versioning_enabled bucket" << dendl;
    op_ret = -EINVAL;
    return;
  }

  bufferlist bl, aclbl;
  rgw_obj symlink_obj;
  symlink_obj.init(s->bucket, s->object.name);
  RGWObjectCtx& obj_ctx = *static_cast<RGWObjectCtx *>(s->obj_ctx);
  if (!enable_overwrite) {
    RGWObjState *astate = nullptr;
    op_ret = store->get_obj_state(&obj_ctx, s->bucket_info, symlink_obj, &astate, false);
    if (op_ret < 0) {
      return;
    }
    if (astate->exists) {
      ldout(s->cct, 0) << __func__ << "ERROR: file already exists and request forbid overwrite" << dendl;
      op_ret = -ERR_FILE_ALREADY_EXISTS;
      return;
    }
  }

  op_ret = rgw_get_request_metadata(s->cct, s->info, attrs);
  if (op_ret < 0) {
    return ;
  }

  size_t account_size = target_bucket_name.size() + target_object_name.size();
  bl.append(target_object_name);
  emplace_attr(RGW_ATTR_TARGET_OBJECT, std::move(bl));
  bl.append(target_bucket_name);
  emplace_attr(RGW_ATTR_TARGET_BUCKET, std::move(bl));

  if (!target_bucket_tenant.empty()) {
    bl.append(target_bucket_tenant);
    emplace_attr(RGW_ATTR_TARGET_TENANT, std::move(bl));
  }
  policy.encode(aclbl);
  emplace_attr(RGW_ATTR_ACL, std::move(aclbl));

  unsigned char md5[CEPH_CRYPTO_MD5_DIGESTSIZE];
  char md5_str[CEPH_CRYPTO_MD5_DIGESTSIZE * 2 + 1];
  MD5 hash;
  hash.Update((const unsigned char *)target_object_name.c_str(), target_object_name.length());
  hash.Final(md5);
  buf_to_hex(md5, CEPH_CRYPTO_MD5_DIGESTSIZE, md5_str);
  target_etag = md5_str;
  bl.append(target_etag.c_str(), target_etag.size());
  emplace_attr(RGW_ATTR_ETAG, std::move(bl));

  obj_ctx.obj.set_atomic(symlink_obj);
  RGWRados::Object op_target(store, s->bucket_info, obj_ctx, symlink_obj);
  RGWRados::Object::Write obj_op(&op_target);

  obj_op.meta.ptag = &s->req_id; /* use req_id as operation tag */
  obj_op.meta.owner = s->owner.get_id(); /* symlink obj owner is op user_id, not bucket owner */
  obj_op.meta.flags = PUT_OBJ_CREATE;
  obj_op.meta.modify_tail = true;
  obj_op.meta.head_placement_rule = s->bucket_info.head_placement_rule; 
  if (!storage_class.empty()) {
    obj_op.meta.storage_class = storage_class;
  }
  /* for access log to calculate op size */
  s->symlink_size_in = account_size;
  op_ret = obj_op.write_meta(0, account_size, attrs);
  if (op_ret < 0) {
    return;
  }
  return;
}
