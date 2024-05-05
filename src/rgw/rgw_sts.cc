#include "rgw_sts.h"
#include "rgw_crypt.h"
#include "rapidjson/reader.h"
#include "rapidjson/prettywriter.h"
#include "rapidjson/document.h"
#include "rapidjson/error/error.h"
#include "rapidjson/error/en.h"

BEGIN_STS_NAMESPACE

using rapidjson::BaseReaderHandler;
using rapidjson::UTF8;
using rapidjson::SizeType;
using rapidjson::StringStream;

lru_map<std::string, RGWRoleInfo> STSClient::_role_cache(1000);

boost::optional<RGWRoleInfo> STSClient::assume_role(const req_state* s) {
  RGWRoleInfo role_info;
  if (_role_cache.find(s->user->user_id.id, role_info)) {
    ldout(s->cct, 20) << __func__ << "(): get role info from role cache." << dendl;
    if (role_info.expiration > (uint64_t)ceph_clock_now()) {
      return role_info;
    }
  }

  std::stringstream ss;
  ss << "/sts/assume_role?user_id=" << s->user->user_id.id.c_str();
  std::string target = ss.str();
  std::string request_body = "";
  bufferlist response_body;

  int ret = http_connect(s, target, "get", request_body, response_body);
  if (ret != 0 || response_body.length() == 0) {
    return boost::none;
  }
  return prase_assume_role_response(s, response_body);
}

boost::optional<RGWRoleInfo> STSClient::prase_assume_role_response(const req_state* s, bufferlist& response_body) {
  rapidjson::Document dom;
  RGWRoleInfo role_info;
  ldout(s->cct, 20) << "assume role response: " << response_body.to_str() << dendl;
  if (dom.Parse(response_body.to_str().c_str()).HasParseError()) {
    ldout(s->cct, 5) << __func__ << "() ERROR: assume role malfored json." << dendl;
    return boost::none;
  }

  if (!dom.HasMember("errcode") || !dom["errcode"].IsInt()) {
    ldout(s->cct, 5) << __func__ << "() ERROR: assume role result lost err code." << dendl;
    return boost::none;
  }

  if (!dom.HasMember("access_key_id") || !dom["access_key_id"].IsString()) {
    ldout(s->cct, 5) << __func__ << "() ERROR: assume role result lost access key id." << dendl;
    return boost::none;
  }

  if (!dom.HasMember("secret_access_key") || !dom["secret_access_key"].IsString()) {
    ldout(s->cct, 5) << __func__ << "() ERROR: assume role result lost secret access key." << dendl;
    return boost::none;
  }

  if (!dom.HasMember("session_token") || !dom["session_token"].IsString()) {
    ldout(s->cct, 5) << __func__ << "() ERROR: assume role result lost session token." << dendl;
    return boost::none;
  }

  if (!dom.HasMember("expiration") || !dom["expiration"].IsString()) {
    ldout(s->cct, 5) << __func__ << "() ERROR: assume role result lost expiration." << dendl;
    return boost::none;
  }

  role_info.key.id = dom["access_key_id"].GetString();
  role_info.key.key = dom["secret_access_key"].GetString();
  role_info.session_token = dom["session_token"].GetString();

  struct tm t;
  if (!parse_iso8601(dom["expiration"].GetString(), &t)) {
    ldout(s->cct, 5) << __func__ << "() ERROR: expiration is not iso8601." << dendl;
    return boost::none;
  }

  std::string now_str;
  ceph::real_time real_time = ceph::real_clock::now();
  rgw_to_iso8601(real_time, &now_str);

  uint64_t req_sec = (uint64_t)internal_timegm(&t);
  role_info.expiration = req_sec;
  uint64_t now = ceph_clock_now();
  if (req_sec > now) {
    _role_cache.add(s->user->user_id.id, role_info);
  }

  return role_info;
}

END_STS_NAMESPACE
