// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include <array>

#include "rgw_common.h"
#include "rgw_auth.h"
#include "rgw_quota.h"
#include "rgw_user.h"
#include "rgw_http_client.h"
#include "rgw_keystone.h"
#include "rgw_rest_s3.h"
#include "rgw_auth_s3.h"

#include "include/str_list.h"

#define dout_context g_ceph_context
#define dout_subsys ceph_subsys_rgw


namespace rgw {
namespace auth {

std::unique_ptr<rgw::auth::Identity>
transform_old_authinfo(const req_state* const s)
{
  /* This class is not intended for public use. Should be removed altogether
   * with this function after moving all our APIs to the new authentication
   * infrastructure. */
  class DummyIdentityApplier : public rgw::auth::Identity {
    CephContext* const cct;

    /* For this particular case it's OK to use rgw_user structure to convey
     * the identity info as this was the policy for doing that before the
     * new auth. */
    const rgw_user id;
    const int perm_mask;
    const bool is_admin;
  public:
    DummyIdentityApplier(CephContext* const cct,
                         const rgw_user& auth_id,
                         const int perm_mask,
                         const bool is_admin)
      : cct(cct),
        id(auth_id),
        perm_mask(perm_mask),
        is_admin(is_admin) {
    }

    uint32_t get_perms_from_aclspec(const aclspec_t& aclspec) const override {
      return rgw_perms_from_aclspec_default_strategy(id, aclspec);
    }

    bool is_admin_of(const rgw_user& acct_id) const override {
      return is_admin;
    }

    bool is_owner_of(const rgw_user& acct_id) const override {
      return id == acct_id;
    }

    bool is_identity(const idset_t& ids) const override {
      for (auto& p : ids) {
	if (p.is_wildcard()) {
	  return true;
	} else if (p.is_tenant() && p.get_tenant() == id.tenant) {
	  return true;
	} else if (p.is_user() &&
		   (p.get_tenant() == id.tenant) &&
		   (p.get_id() == id.id)) {
	  return true;
	}
      }
      return false;
    }

    uint32_t get_perm_mask() const override {
      return perm_mask;
    }

    void to_str(std::ostream& out) const override {
      out << "RGWDummyIdentityApplier(auth_id=" << id
          << ", perm_mask=" << perm_mask
          << ", is_admin=" << is_admin << ")";
    }
  };

  return std::unique_ptr<rgw::auth::Identity>(
        new DummyIdentityApplier(s->cct,
                                 s->user->user_id,
                                 s->perm_mask,
  /* System user has admin permissions by default - it's supposed to pass
   * through any security check. */
                                 s->system_request));
}

} /* namespace auth */
} /* namespace rgw */


uint32_t rgw_perms_from_aclspec_default_strategy(
  const rgw_user& uid,
  const rgw::auth::Identity::aclspec_t& aclspec)
{
  dout(5) << "Searching permissions for uid=" << uid <<  dendl;

  const auto iter = aclspec.find(uid.to_str());
  if (std::end(aclspec) != iter) {
    dout(5) << "Found permission: " << iter->second << dendl;
    return iter->second;
  }

  dout(5) << "Permissions for user not found" << dendl;
  return 0;
}


static inline const std::string make_spec_item(const std::string& tenant,
                                               const std::string& id)
{
  return tenant + ":" + id;
}


static inline std::pair<bool, rgw::auth::Engine::result_t>
strategy_handle_rejected(rgw::auth::Engine::result_t&& engine_result,
                         const rgw::auth::Strategy::Control policy,
                         rgw::auth::Engine::result_t&& strategy_result)
{
  using Control = rgw::auth::Strategy::Control;
  switch (policy) {
    case Control::REQUISITE:
      /* Don't try next. */
      return std::make_pair(false, std::move(engine_result));

    case Control::SUFFICIENT:
      /* Don't try next. */
      return std::make_pair(false, std::move(engine_result));

    case Control::FALLBACK:
      /* Don't try next. */
      return std::make_pair(false, std::move(strategy_result));

    default:
      /* Huh, memory corruption? */
      abort();
  }
}

static inline std::pair<bool, rgw::auth::Engine::result_t>
strategy_handle_denied(rgw::auth::Engine::result_t&& engine_result,
                       const rgw::auth::Strategy::Control policy,
                       rgw::auth::Engine::result_t&& strategy_result)
{
  using Control = rgw::auth::Strategy::Control;
  switch (policy) {
    case Control::REQUISITE:
      /* Don't try next. */
      return std::make_pair(false, std::move(engine_result));

    case Control::SUFFICIENT:
      /* Just try next. */
      return std::make_pair(true, std::move(engine_result));

    case Control::FALLBACK:
      return std::make_pair(true, std::move(strategy_result));

    default:
      /* Huh, memory corruption? */
      abort();
  }
}

static inline std::pair<bool, rgw::auth::Engine::result_t>
strategy_handle_granted(rgw::auth::Engine::result_t&& engine_result,
                        const rgw::auth::Strategy::Control policy,
                        rgw::auth::Engine::result_t&& strategy_result)
{
  using Control = rgw::auth::Strategy::Control;
  switch (policy) {
    case Control::REQUISITE:
      /* Try next. */
      return std::make_pair(true, std::move(engine_result));

    case Control::SUFFICIENT:
      /* Don't try next. */
      return std::make_pair(false, std::move(engine_result));

    case Control::FALLBACK:
      /* Don't try next. */
      return std::make_pair(false, std::move(engine_result));

    default:
      /* Huh, memory corruption? */
      abort();
  }
}

#ifdef WITH_BCEIAM
bool enforce_local_order(const req_state* const s) {
  boost::string_view ak = "";
#ifdef WITH_BCEBOS
  if (s->prot_flags & RGW_REST_BOS) {
    const bool using_auth_qs = s->info.args.exists("authorization");  // 'authorization' content exists in query string.
    string_view input;
    if (using_auth_qs) {
      input = s->info.args.get("authorization");
    } else {
      input = s->info.env->get("HTTP_AUTHORIZATION", "");
    }
    if (input.length() == 0) {
      ldout(s->cct, 10) << "ERROR: invalid bos request without authorization" << dendl;
      return false;
    }
    std::vector<std::string> auths;
    boost::split(auths, input, boost::is_any_of("/"));
    if (auths.size() < 6) {
      ldout(s->cct, 10) << "NOTICE: invalid authorization in bos format request:"
               << input << dendl;
      return false;
    }
    ak = auths[1];
  } else
#endif
  {
    AwsVersion version;
    AwsRoute route;
    std::tie(version, route) = discover_aws_flavour(s->info);

    if (version == AwsVersion::V2) {

      ldout(s->cct, 20) << "Signature verification algorithm AWS v2" << dendl;
      const char* http_auth = s->info.env->get("HTTP_AUTHORIZATION");
      if (! http_auth || http_auth[0] == '\0') {
        /* Credentials are provided in query string. We also need to verify
         * the "Expires" parameter now. */
        ak = s->info.args.get("AWSAccessKeyId");
      } else {
        const boost::string_view auth_str(http_auth + strlen("AWS "));
        const size_t pos = auth_str.rfind(':');
        if (pos != boost::string_view::npos) {
          ak = auth_str.substr(0, pos);
        } else {
          ldout(s->cct, 10) << "NOTICE: bad AUTHORIZATION" << s->info.env->get("HTTP_AUTHORIZATION") << dendl;
          return false;
        }
      }

    } else if (version == AwsVersion::V4) {

      ldout(s->cct, 20) << "Signature verification algorithm AWS v4"
                       << " (AWS4-HMAC-SHA256)" << dendl;
      bool using_qs = route == AwsRoute::QUERY_STRING;
      boost::string_view credential;
      if (using_qs) {
        credential = s->info.args.get("X-Amz-Credential");
      } else {
        string input(s->info.env->get("HTTP_AUTHORIZATION", ""));
        try {
          input = input.substr(::strlen(rgw::auth::s3::AWS4_HMAC_SHA256_STR) + 1);
        } catch (std::out_of_range&) {
          /* We should never ever run into this situation as the presence of
           * AWS4_HMAC_SHA256_STR had been verified earlier. */
          ldout(s->cct, 10) << "credentials string is too short" << dendl;
          return false;
        }

        std::map<boost::string_view, boost::string_view> kv;
        for (const auto& str : get_str_vec(input, ",")) {
          const auto parsed_pair = parse_key_value(str);
          if (parsed_pair && parsed_pair->first.compare("Credential") == 0) {
            credential = parsed_pair->second;
            break;
          } else {
            ldout(s->cct, 10) << "NOTICE: failed to parse auth header (" << str << ")"
                     << dendl;
            return false;
          }
        }
      }
      const size_t pos = credential.find("/");
      if (pos == string::npos) {
        ldout(s->cct, 10) << "NOTICE: bad credential:"<< credential
                 << dendl;
        return false;
      }
      ak = credential.substr(0, pos);
    } else {
      ldout(s->cct, 20) << "NOTICE: anon user" << dendl;
      return false;
    }
  }
  if (ak.length() == PUBLIC_ID_LEN) {
    return true;
  }
  return false;
}
#endif

rgw::auth::Engine::result_t
rgw::auth::Strategy::authenticate(const req_state* const s) const
{
  result_t strategy_result = result_t::deny();

#ifdef WITH_BCEIAM
  bool enforced_local = false;
  if (local_first_auth_stack.size() == auth_stack.size()) {
    enforced_local = enforce_local_order(s);
  } else {
    ldout(s->cct, 0) << __func__ << "() ERROR local_first_auth_stack size"
      << local_first_auth_stack.size() << ", auth_stack size"
      << auth_stack.size() << dendl;
  }
#endif
  for (uint32_t p = 0; p < auth_stack.size(); p++) {
    const rgw::auth::Engine* engine = &(auth_stack[p].first.get());
    const rgw::auth::Strategy::Control* policy = &(auth_stack[p].second);

#ifdef WITH_BCEIAM
    if (enforced_local) {
     if (local_first_auth_stack[p] < auth_stack.size()) {
        engine = &(auth_stack[local_first_auth_stack[p]].first.get());
        policy = &(auth_stack[local_first_auth_stack[p]].second);
        if (engine == nullptr || policy == nullptr) {
          ldout(s->cct, 0) << __func__ << "() ERROR engine or policy nullptr" << dendl;
          engine = &(auth_stack[p].first.get());
          policy = &(auth_stack[p].second);
        }
      } else {
          ldout(s->cct, 0) << __func__ << "() ERROR local_first_auth_stack["
            << p << "]=" << local_first_auth_stack[p]
            << " out_of_range, auth_stack.size:" << auth_stack.size()
            << dendl;
      }
    }
#endif
    dout(20) << get_name() << ": trying " << engine->get_name() << dendl;

    result_t engine_result = result_t::deny();
    try {
      engine_result = engine->authenticate(s);
    } catch (const int err) {
      engine_result = result_t::deny(err);
    }

    // Some error has occurred and there is no need to try another engine
    if (engine_result.get_status() == result_t::Status::DENIED &&
        engine_result.get_reason() == -ETIMEDOUT) {
      return engine_result;
    }

    bool try_next = true;
    switch (engine_result.get_status()) {
      case result_t::Status::REJECTED: {
        dout(20) << engine->get_name() << " rejected with reason="
                 << engine_result.get_reason() << dendl;

        std::tie(try_next, strategy_result) = \
          strategy_handle_rejected(std::move(engine_result), *policy,
                                   std::move(strategy_result));
        break;
      }
      case result_t::Status::DENIED: {
        dout(20) << engine->get_name() << " denied with reason="
                 << engine_result.get_reason() << dendl;

        std::tie(try_next, strategy_result) = \
          strategy_handle_denied(std::move(engine_result), *policy,
                                 std::move(strategy_result));
        break;
      }
      case result_t::Status::GRANTED: {
        dout(20) << engine->get_name() << " granted access" << dendl;

        std::tie(try_next, strategy_result) = \
          strategy_handle_granted(std::move(engine_result), *policy,
                                  std::move(strategy_result));
        break;
      }
      default: {
        abort();
      }
    }

    if (! try_next) {
      break;
    }
  }

  return strategy_result;
}

int
rgw::auth::Strategy::apply(const rgw::auth::Strategy& auth_strategy,
                           req_state* const s) noexcept
{
  try {
    auto result = auth_strategy.authenticate(s);
    if (result.get_status() != decltype(result)::Status::GRANTED) {
      /* Access denied is acknowledged by returning a std::unique_ptr with
       * nullptr inside. */
      ldout(s->cct, 5) << "Failed the auth strategy, reason="
                       << result.get_reason() << dendl;
      return result.get_reason();
    }

    try {
      rgw::auth::IdentityApplier::aplptr_t applier = result.get_applier();
      rgw::auth::Completer::cmplptr_t completer = result.get_completer();

      /* Account used by a given RGWOp is decoupled from identity employed
       * in the authorization phase (RGWOp::verify_permissions). */
      applier->load_acct_info(*s->user);
      s->iam_check_user = applier->is_iam_applier();
      s->perm_mask = applier->get_perm_mask();

      /* This is the single place where we pass req_state as a pointer
       * to non-const and thus its modification is allowed. In the time
       * of writing only RGWTempURLEngine needed that feature. */
      applier->modify_request_state(s);
      if (completer) {
        completer->modify_request_state(s);
      }

      s->auth.identity = std::move(applier);
      s->auth.completer = std::move(completer);

      return 0;
    } catch (const int err) {
      ldout(s->cct, 5) << "applier throwed err=" << err << dendl;
      return err;
    }
  } catch (const int err) {
    ldout(s->cct, 5) << "auth engine throwed err=" << err << dendl;
    return err;
  }

  /* We never should be here. */
  return -EPERM;
}

void
rgw::auth::Strategy::add_engine(const Control ctrl_flag,
                                const Engine& engine) noexcept
{
  auth_stack.push_back(std::make_pair(std::cref(engine), ctrl_flag));
#ifdef WITH_BCEIAM
  local_first_auth_stack.push_back(auth_stack.size() - 1);

  if (string_view(engine.get_name()).find("LocalEngine") != boost::string_view::npos) {
    int32_t pos = -1;
    for (uint32_t i = 0; i < local_first_auth_stack.size(); i++) {
      const rgw::auth::Engine& e = auth_stack[local_first_auth_stack[i]].first;
      if (string_view(e.get_name()).find("LocalEngine") == string::npos) {
        pos = i;
        break;
      }
    }
    if (pos != -1) {
      std::swap(local_first_auth_stack[pos], local_first_auth_stack[local_first_auth_stack.size() - 1]);
    }
  }
#endif

}

/* rgw::auth::RemoteAuthApplier */
uint32_t rgw::auth::RemoteApplier::get_perms_from_aclspec(const aclspec_t& aclspec) const
{
  uint32_t perm = 0;

  /* For backward compatibility with ACLOwner. */
  perm |= rgw_perms_from_aclspec_default_strategy(info.acct_user,
                                                  aclspec);

  /* We also need to cover cases where rgw_keystone_implicit_tenants
   * was enabled. */
  if (info.acct_user.tenant.empty()) {
    const rgw_user tenanted_acct_user(info.acct_user.id, info.acct_user.id);

    perm |= rgw_perms_from_aclspec_default_strategy(tenanted_acct_user,
                                                    aclspec);
  }

  /* Now it's a time for invoking additional strategy that was supplied by
   * a specific auth engine. */
  if (extra_acl_strategy) {
    perm |= extra_acl_strategy(aclspec);
  }

  ldout(cct, 20) << "from ACL got perm=" << perm << dendl;
  return perm;
}

bool rgw::auth::RemoteApplier::is_admin_of(const rgw_user& uid) const
{
  return info.is_admin;
}

bool rgw::auth::RemoteApplier::is_owner_of(const rgw_user& uid) const
{
  if (info.acct_user.tenant.empty()) {
    const rgw_user tenanted_acct_user(info.acct_user.id, info.acct_user.id);

    if (tenanted_acct_user == uid) {
      return true;
    }
  }

  return info.acct_user == uid;
}

bool rgw::auth::RemoteApplier::is_identity(const idset_t& ids) const {
  for (auto& id : ids) {
    if (id.is_wildcard()) {
      return true;

      // We also need to cover cases where rgw_keystone_implicit_tenants
      // was enabled. */
    } else if (id.is_tenant() &&
	       (info.acct_user.tenant.empty() ?
		info.acct_user.id :
		info.acct_user.tenant) == id.get_tenant()) {
      return true;
    } else if (id.is_user() &&
               info.acct_user.id == id.get_id() &&
#ifdef WITH_BAIXIN
               (info.acct_user.tenant.empty() && !id.get_tenant().empty() ?
#else
               (info.acct_user.tenant.empty() ?
#endif
		info.acct_user.id :
		info.acct_user.tenant) == id.get_tenant()) {
      return true;
    }
#ifdef WITH_BCEBOS
    if (id.is_user() && info.acct_user.id == id.get_id() && info.acct_user.tenant == id.get_tenant()) {
      return true;
    }
#endif
  }
  return false;
}

void rgw::auth::RemoteApplier::to_str(std::ostream& out) const
{
  out << "rgw::auth::RemoteApplier(acct_user=" << info.acct_user
      << ", acct_name=" << info.acct_name
      << ", perm_mask=" << info.perm_mask
      << ", is_admin=" << info.is_admin << ")";
}

void rgw::auth::RemoteApplier::create_account(const rgw_user& acct_user,
                                              RGWUserInfo& user_info) const      /* out */
{
  rgw_user new_acct_user = acct_user;

  if (info.acct_type) {
    //ldap/keystone for s3 users
    user_info.type = info.acct_type;
  }

  /* An upper layer may enforce creating new accounts within their own
   * tenants. */
  if (new_acct_user.tenant.empty() && implicit_tenants) {
    new_acct_user.tenant = new_acct_user.id;
  }

  user_info.user_id = new_acct_user;
  user_info.display_name = info.acct_name;

  user_info.max_buckets = cct->_conf->rgw_user_max_buckets;
  rgw_apply_default_bucket_quota(user_info.bucket_quota, *cct->_conf);
  rgw_apply_default_user_quota(user_info.user_quota, *cct->_conf);

  int ret = rgw_store_user_info(store, user_info, nullptr, nullptr,
                                real_time(), true);
  if (ret < 0) {
    ldout(cct, 0) << "ERROR: failed to store new user info: user="
                  << user_info.user_id << " ret=" << ret << dendl;
    throw ret;
  }
}

/* TODO(rzarzynski): we need to handle display_name changes. */
void rgw::auth::RemoteApplier::load_acct_info(RGWUserInfo& user_info) const      /* out */
{
  /* It's supposed that RGWRemoteAuthApplier tries to load account info
   * that belongs to the authenticated identity. Another policy may be
   * applied by using a RGWThirdPartyAccountAuthApplier decorator. */
  const rgw_user& acct_user = info.acct_user;

  /* Normally, empty "tenant" field of acct_user means the authenticated
   * identity has the legacy, global tenant. However, due to inclusion
   * of multi-tenancy, we got some special compatibility kludge for remote
   * backends like Keystone.
   * If the global tenant is the requested one, we try the same tenant as
   * the user name first. If that RGWUserInfo exists, we use it. This way,
   * migrated OpenStack users can get their namespaced containers and nobody's
   * the wiser.
   * If that fails, we look up in the requested (possibly empty) tenant.
   * If that fails too, we create the account within the global or separated
   * namespace depending on rgw_keystone_implicit_tenants. */
#ifndef WITH_BCEIAM
  if (acct_user.tenant.empty()) {
    const rgw_user tenanted_uid(acct_user.id, acct_user.id);

    if (rgw_get_user_info_by_uid(store, tenanted_uid, user_info) >= 0) {
      /* Succeeded. */
      return;
    }
  }
#endif

  if (rgw_get_user_info_by_uid(store, acct_user, user_info) < 0) {
    ldout(cct, 0) << "NOTICE: couldn't map remote user " << acct_user << dendl;
    create_account(acct_user, user_info);
  }
#ifdef WITH_BCEIAM
  if (!info.subuser_id.empty()) {
    RGWSubUser sub_user;
    sub_user.name = info.subuser_id;
    user_info.subusers[info.subuser_id] = sub_user;
  }
#endif

  /* Succeeded if we are here (create_account() hasn't throwed). */
}


/* rgw::auth::LocalApplier */
/* static declaration */
const std::string rgw::auth::LocalApplier::NO_SUBUSER;

uint32_t rgw::auth::LocalApplier::get_perms_from_aclspec(const aclspec_t& aclspec) const
{
  return rgw_perms_from_aclspec_default_strategy(user_info.user_id, aclspec);
}

bool rgw::auth::LocalApplier::is_admin_of(const rgw_user& uid) const
{
  return user_info.admin || user_info.system;
}

bool rgw::auth::LocalApplier::is_owner_of(const rgw_user& uid) const
{
  return uid == user_info.user_id;
}

bool rgw::auth::LocalApplier::is_identity(const idset_t& ids) const {
  for (auto& id : ids) {
    if (id.is_wildcard()) {
      return true;
    } else if (id.is_tenant() &&
	       id.get_tenant() == user_info.user_id.tenant) {
      return true;
    } else if (id.is_user() &&
	       (id.get_tenant() == user_info.user_id.tenant) &&
	       (id.get_id() == user_info.user_id.id)) {
      return true;
    }
  }
  return false;
}

void rgw::auth::LocalApplier::to_str(std::ostream& out) const {
  out << "rgw::auth::LocalApplier(acct_user=" << user_info.user_id
      << ", acct_name=" << user_info.display_name
      << ", subuser=" << subuser
      << ", perm_mask=" << get_perm_mask()
      << ", is_admin=" << static_cast<bool>(user_info.admin) << ")";
}

uint32_t rgw::auth::LocalApplier::get_perm_mask(const std::string& subuser_name,
                                                const RGWUserInfo &uinfo) const
{
  if (! subuser_name.empty() && subuser_name != NO_SUBUSER) {
    const auto iter = uinfo.subusers.find(subuser_name);

    if (iter != std::end(uinfo.subusers)) {
      return iter->second.perm_mask;
    } else {
      /* Subuser specified but not found. */
      return RGW_PERM_NONE;
    }
  } else {
    /* Due to backward compatibility. */
    return RGW_PERM_FULL_CONTROL;
  }
}

void rgw::auth::LocalApplier::load_acct_info(RGWUserInfo& user_info) const /* out */
{
  /* Load the account that belongs to the authenticated identity. An extra call
   * to RADOS may be safely skipped in this case. */
  user_info = this->user_info;
}


rgw::auth::Engine::result_t
rgw::auth::AnonymousEngine::authenticate(const req_state* const s) const
{
  if (! is_applicable(s)) {
    return result_t::deny(-EPERM);
  } else {
    RGWUserInfo user_info;
    rgw_get_anon_user(user_info);

    auto apl = \
      apl_factory->create_apl_local(cct, s, user_info,
                                    rgw::auth::LocalApplier::NO_SUBUSER);
    return result_t::grant(std::move(apl));
  }
}
