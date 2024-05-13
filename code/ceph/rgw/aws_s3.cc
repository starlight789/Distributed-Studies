#include <string>
#include "aws_s3.h"
#include "rgw_auth_s3.h"

#define AMZ_ALGORITHM_HEADER "X-Amz-Algorithm"
#define AMZ_CREDENTIAL_HEADER "X-Amz-Credential"
#define AMZ_DATE_HEADER "X-Amz-Date"
#define AMZ_EXPIRES_HEADER "X-Amz-Expires"
#define AMZ_SIGNEDHEADERS_HEADER "X-Amz-SignedHeaders"
#define AMZ_SIGNATURE_HEADER "X-Amz-Signature"

#define EXPIRES_SECOND "3600"
#define AWS4_HMAC_SHA256 "AWS4-HMAC-SHA256"
#define AWS4_UNSIGNED_PAYLOAD_HASH "UNSIGNED-PAYLOAD"
#define AWS_REGION "us-east-1"
#define AWS_SERVICE "s3"
#define AWS_REQUEST "aws4_request"

BEGIN_AWSS3_NAMESPACE

std::string get_presign_url(const req_state* const s, const std::string& host, const std::string& ak,
                            const std::string& sk, const std::string& bucket, const std::string& object) {
  std::string date;
  std::map<std::string, std::string> canonical_qs_map;

  ceph::real_time real_time = ceph::real_clock::now();
  rgw_to_iso8601(real_time, &date);
  date.erase(std::remove(date.begin(), date.end(), '-'), date.end());
  date.erase(std::remove(date.begin(), date.end(), ':'), date.end());

  //format canonical_headers, just host will be used
  std::string canonical_hdrs = string_cat_reserve("host:", host.c_str(), "\n");
  std::string canonical_uri = string_cat_reserve("/", bucket.c_str(), "/", object.c_str());

  //format credential scope like date/aws_region/aws_service/aws_request
  std::string credential_scope = string_join_reserve("/", date.substr(0, date.find("T")).c_str(),
                                                     AWS_REGION, AWS_SERVICE, AWS_REQUEST);

  //format credential scope qs like ak%2Fdate%2Faws_region%2Faws_service%2Faws_request
  std::string credential_scope_qs = string_join_reserve("%2F", ak.c_str(),
                                                        date.substr(0, date.find("T")).c_str(),
                                                        AWS_REGION, AWS_SERVICE, AWS_REQUEST);

  canonical_qs_map[AMZ_ALGORITHM_HEADER] = AWS4_HMAC_SHA256;
  canonical_qs_map[AMZ_CREDENTIAL_HEADER] = credential_scope_qs;
  canonical_qs_map[AMZ_DATE_HEADER] = date;
  canonical_qs_map[AMZ_EXPIRES_HEADER] = EXPIRES_SECOND;
  canonical_qs_map[AMZ_SIGNEDHEADERS_HEADER] = "host";

  auto iter = std::begin(canonical_qs_map);
  std::string canonical_qs = string_cat_reserve(iter->first.c_str(), "=", iter->second.c_str());

  for (iter++; iter != std::end(canonical_qs_map); iter++) {
    canonical_qs = string_cat_reserve(canonical_qs.c_str(), "&", iter->first.c_str(), "=", iter->second.c_str());
  }

  auto canonical_req_hash = rgw::auth::s3::get_v4_canon_req_hash(s->cct, "GET", canonical_uri,
                                                                 canonical_qs, canonical_hdrs,
                                                                 "host", AWS4_UNSIGNED_PAYLOAD_HASH);
  //StringToSign:
  //"AWS-HMAC_SHA256" + "\n" + TimeStamp + "\n" + CredentialScope + "\n" +
  //Hex(SHA256Hash(CanonicalRequest))
  auto string_to_sign = rgw::auth::s3::get_v4_string_to_sign(s->cct, AWS4_HMAC_SHA256, date,
                                                             credential_scope, canonical_req_hash);
  //signature = Hex(SHA256Hash(SigingKey, StrignToSign))
  auto signature = rgw::auth::s3::get_v4_signature(credential_scope, s->cct, sk, string_to_sign);

  std::string ret = string_cat_reserve("http://", host.c_str(), canonical_uri.c_str(), "?",
                                       canonical_qs.c_str(), "&", AMZ_SIGNATURE_HEADER, "=", signature.c_str());
  ldout(s->cct, 20) << __func__ << "() get presion url: " << ret << dendl;
  return ret;
}

END_AWSS3_NAMESPACE
