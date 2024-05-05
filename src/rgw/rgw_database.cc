#include "rgw_database.h"
#include "rapidjson/reader.h"
#include "rapidjson/prettywriter.h"
#include "rapidjson/document.h"
#include "rapidjson/error/error.h"
#include "rapidjson/error/en.h"

BEGIN_DATABASE_NAMESPACE

using rapidjson::BaseReaderHandler;
using rapidjson::UTF8;
using rapidjson::SizeType;
using rapidjson::StringStream;

bool parse_bucket_info_list(const req_state* s, RGWUserBuckets& buckets, const rapidjson::Value& result) {
  if (!result.IsArray()) {
    ldout(s->cct, 5) << __func__ << "parse bucket info list malford json." << dendl;
    return false;
  }
  buckets.clear();
  for (SizeType index = 0; index < result.Size(); index++) {
    if (!result[index].HasMember("bucket")) {
      ldout(s->cct, 5) << __func__ << "() ERROR: parse bucket info form proxy lost bucket." << dendl;
      return false;
    }
    if (!result[index]["bucket"].IsString()) {
      ldout(s->cct, 5) << __func__ << "() ERROR: parse bucket info from proxy bucket is not string." << dendl;
      return false;
    }
    if (!result[index].HasMember("region")) {
      ldout(s->cct, 5) << __func__ << "() ERROR: parse bucket info form proxy lost region." << dendl;
      return false;
    }
    if (!result[index]["region"].IsString()) {
      ldout(s->cct, 5) << __func__ << "() ERROR: parse bucket info from proxy region is not string." << dendl;
      return false;
    }
    if (!result[index].HasMember("user_id")) {
      ldout(s->cct, 5) << __func__ << "() ERROR: parse bucket info form proxy lost user_id." << dendl;
      return false;
    }
    if (!result[index]["user_id"].IsString()) {
      ldout(s->cct, 5) << __func__ << "() ERROR: parse bucket info from proxy user_id is not string." << dendl;
      return false;
    }
    if (!result[index].HasMember("create_time")) {
      ldout(s->cct, 5) << __func__ << "() ERROR: parse bucket info form proxy lost create_time." << dendl;
      return false;
    }
    if (!result[index]["create_time"].IsInt()) {
      ldout(s->cct, 5) << __func__ << "() ERROR: parse bucket info from proxy create_time is not int." << dendl;
      return false;
    }
    RGWBucketEnt bucket_info;
    bucket_info.bucket.name = result[index]["bucket"].GetString();
    bucket_info.region = result[index]["region"].GetString();
    bucket_info.creation_time = ceph::real_clock::from_time_t(result[index]["create_time"].GetInt());
    buckets.add(bucket_info);
  }
  return true;
}

boost::optional<RGWBucketEnt> DBClient::query_bucket_info(const req_state* s, const std::string& bucket) {
  std::stringstream ss;
  ss << "/db/query/bucket?bucket=" << bucket.c_str();
  std::string target = ss.str();
  std::string request_body = "";
  bufferlist response_body;

  rapidjson::Document dom;
  int ret = http_connect(s, target, "get", request_body, response_body);
  if (ret != 0 || response_body.length() == 0) {
    return boost::none;
  }

  ldout(s->cct, 20) << "query db response: " << response_body.to_str() << dendl;
  if (dom.Parse(response_body.to_str().c_str()).HasParseError()) {
    ldout(s->cct, 5) << __func__ << "() ERROR: query bucket info malfored json, bucket: " << bucket << dendl;
    return boost::none;
  }

  if (!dom.HasMember("errcode")) {
    ldout(s->cct, 5) << __func__ << "() ERROR: query bucket info from proxy result lost errocde, bucket:" << bucket <<  dendl;
    return boost::none;
  }
  if (!dom["errcode"].IsInt()) {
    ldout(s->cct, 5) << __func__ << " () ERROR: query bucket info from proxy errocode is not int, bucket: " << bucket << dendl;
    return boost::none;
  }

  if (dom.HasMember("result") && dom["result"].IsArray()) {
    RGWUserBuckets buckets;
    if (!parse_bucket_info_list(s, buckets, dom["result"])) {
      return boost::none;
    }
    if (buckets.count() != 1) {
      ldout(s->cct, 5) << __func__ << " query more than one bucket." << dendl;
      return boost::none;
    }
    return buckets.get_buckets()[bucket];
  }

  return boost::none;
}

int DBClient::list_bucket_by_user(const req_state* s, const std::string user_id, RGWUserBuckets& buckets, uint64_t read_count) {
  std::stringstream ss;
  ss << "/db/list/bucket?user_id=" << user_id.c_str() << "&count=" << read_count;
  std::string target = ss.str();
  std::string request_body = "";
  bufferlist response_body;

  rapidjson::Document dom;
  int ret = http_connect(s, target, "get", request_body, response_body);
  if (ret != 0 || response_body.length() == 0) {
    return -ERR_INTERNAL_ERROR;
  }

  ldout(s->cct, 20) << "list buckets form db response: " << response_body.to_str() << dendl;
  if (dom.Parse(response_body.to_str().c_str()).HasParseError()) {
    ldout(s->cct, 5) << __func__ << " list bucket info malfored json" << dendl;
    return -ERR_INTERNAL_ERROR;
  }

  if (!dom.HasMember("errcode")) {
    ldout(s->cct, 5) << __func__ << "() ERROR: list buckets from proxy result lost errcode." << dendl;
  }
  if (!dom["errcode"].IsInt()) {
    ldout(s->cct, 5) << __func__ << "() ERROR: list buckets from proxy errcode is not int." << dendl;
    return -ERR_INTERNAL_ERROR;
  }

  if (dom.HasMember("result") && dom["result"].IsArray()) {
    if (!parse_bucket_info_list(s, buckets, dom["result"])) {
      return -ERR_INTERNAL_ERROR;
    }
  }

  return 0;
}

int DBClient::get_bucket_count_by_user(const req_state* s, const std::string user_id, int& count) {
  std::stringstream ss;
  ss << "/db/count/bucket?user_id=" << user_id.c_str();
  std::string target = ss.str();
  std::string request_body = "";
  bufferlist response_body;

  rapidjson::Document dom;
  int ret = http_connect(s, target, "get",request_body, response_body);
  if (ret < 0 || response_body.length() == 0) {
    return -ERR_INTERNAL_ERROR;
  }

  ldout(s->cct, 20) << "get bucket count form db response: " << response_body.to_str() << dendl;
  if (dom.Parse(response_body.to_str().c_str()).HasParseError()) {
    ldout(s->cct, 5) << __func__ << " get bucket count malfored json." << dendl;
    return -ERR_INTERNAL_ERROR;
  }

  if (!dom.HasMember("errcode")) {
    ldout(s->cct, 5) << __func__ << "() ERROR: get bucket count result from proxy lost errcode." << dendl;
    return -ERR_INTERNAL_ERROR;
  }
  if (!dom["errcode"].IsInt()) {
    ldout(s->cct, 5) << __func__ << "() ERROR: get bucket count result from proxy errcode is not int." << dendl;
    return -ERR_INTERNAL_ERROR;
  }
  if (dom["errcode"].GetInt() > 0) {
    ldout(s->cct, 5) << __func__ << "() ERROR: get bucket count result from proxy is not 0, errcode: " << dom["errcode"].GetInt() << dendl;
    return -ERR_INTERNAL_ERROR;
  }
  if (!dom.HasMember("count")) {
    ldout(s->cct, 5) << __func__ << "() ERROR: get bucket count result from proxy lost count." << dendl;
    return -ERR_INTERNAL_ERROR;
  }
  if (!dom["count"].IsInt()) {
    ldout(s->cct, 5) << __func__ << "() ERROR: get bucket count result from proxy count is not int." << dendl;
    return -ERR_INTERNAL_ERROR;
  }
  if (!dom.HasMember("errmsg")) {
    ldout(s->cct, 5) << __func__ << "() ERROR: get bucket count result from proxy lost errmsg." << dendl;
    return -ERR_INTERNAL_ERROR;
  }
  if (!dom["errmsg"].IsString()) {
    ldout(s->cct, 5) << __func__ << "() ERROR: get bucket count result from proxy count is not string." << dendl;
    return -ERR_INTERNAL_ERROR;
  }

  count = dom["count"].GetInt();
  return 0;
}

int DBClient::insert_bucket_info(const req_state* s, db_bucket_info& bucket_info) {
  std::stringstream ss;
  ss << "/db/insert/bucket";
  std::string target = ss.str();

  rapidjson::Document dom;
  rapidjson::StringBuffer buf;
  rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(buf);

  writer.StartObject();
  writer.Key("bucket"); writer.String(bucket_info.bucket.c_str());
  writer.Key("region"); writer.String(bucket_info.region.c_str());
  writer.Key("user_id"); writer.String(bucket_info.user.c_str());
  writer.Key("create_time"); writer.Int(bucket_info.create_time);
  writer.EndObject();

  std::string request_body = buf.GetString();
  bufferlist response_body;

  int ret = http_connect(s, target, "put", request_body, response_body);
  if (ret < 0 || response_body.length() == 0) {
    return -ERR_INTERNAL_ERROR;
  }

  ldout(s->cct, 0) << "insert db response: " << response_body.to_str() << dendl;
  if (dom.Parse(response_body.to_str().c_str()).HasParseError()) {
    ldout(s->cct, 5) << __func__ << "() ERROR: insert bucket info malfored json, bucket: " << bucket_info.bucket << dendl;
    return -ERR_INTERNAL_ERROR;
  }

  if (!dom.HasMember("errcode")) {
    ldout(s->cct, 5) << __func__ << "() ERROR: insert bucket info into proxy result lost errcode, bucket: " << bucket_info.bucket << dendl;
    return -ERR_INTERNAL_ERROR;
  }
  if (!dom["errcode"].IsInt()) {
    ldout(s->cct, 5) << __func__ << "() ERROR: insert bucket info into proxy result errcode is not int, bucket: " << bucket_info.bucket << dendl;
    return -ERR_INTERNAL_ERROR;
  }
  if (!dom.HasMember("errmsg")) {
    ldout(s->cct, 5) << __func__ << "() ERROR: insert bucket info into proxy result lost errmag, bucket: " << bucket_info.bucket << dendl;
    return -ERR_INTERNAL_ERROR;
  }
  if (!dom["errmsg"].IsString()) {
    ldout(s->cct, 5) << __func__ << "() ERROR: insert bucket info into proxy result errmsg is not string, bucket: " << bucket_info.bucket << dendl;
    return -ERR_INTERNAL_ERROR;
  }

  if (dom["errcode"].GetInt() > 0) {
    ldout(s->cct, 5) << __func__ << " insert bucket info err, err msg: " << dom["errmsg"].GetString() << dendl;
    return -EEXIST;
  }

  return 0;
}

int DBClient::delete_bucket_info(const req_state* s, const std::string& bucket) {
  std::stringstream ss;
  ss << "/db/delete/bucket?bucket=" << bucket.c_str();
  std::string target = ss.str();
  std::string request_body = "";
  bufferlist response_body;

  rapidjson::Document dom;
  int ret = http_connect(s, target, "get",request_body, response_body);
  if (ret < 0 || response_body.length() == 0) {
    return -ERR_INTERNAL_ERROR;
  }

  ldout(s->cct, 20) << "delete db response: " << response_body.to_str() << dendl;
  if (dom.Parse(response_body.to_str().c_str()).HasParseError()) {
    ldout(s->cct, 5) << __func__ << " delete bucket info malfored json, bucket: " << bucket << dendl;
    return -ERR_INTERNAL_ERROR;
  }

  if (!dom.HasMember("errcode")) {
    ldout(s->cct, 5) << __func__ << "() ERROR: delete bucket from into proxy result lost errcode, bucket: " << bucket << dendl;
    return -ERR_INTERNAL_ERROR;
  }
  if (!dom["errcode"].IsInt()) {
    ldout(s->cct, 5) << __func__ << "() ERROR: delete bucket info from proxy result errcode is not int, bucket: " << bucket << dendl;
    return -ERR_INTERNAL_ERROR;
  }
  if (!dom.HasMember("errmsg")) {
    ldout(s->cct, 5) << __func__ << "() ERROR: delete bucket info from proxy result lost errmag, bucket: " << bucket << dendl;
    return -ERR_INTERNAL_ERROR;
  }
  if (!dom["errmsg"].IsString()) {
    ldout(s->cct, 5) << __func__ << "() ERROR: delete bucket info from proxy result errmsg is not string, bucket: " << bucket << dendl;
    return -ERR_INTERNAL_ERROR;
  }

  if (dom["errcode"].GetInt() > 0) {
    ldout(s->cct, 5) << __func__ << "delete bucket from db failed, bucket: " << bucket << dendl;
    return -ERR_NO_SUCH_BUCKET;
  }

  return 0;
}

END_DATABASE_NAMESPACE
