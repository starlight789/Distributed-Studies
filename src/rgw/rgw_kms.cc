#include "rgw/rgw_b64.h"
#include "rgw/rgw_sts.h"
#include "rgw_kms.h"
#include "common/lru_map.h"
#include "rapidjson/reader.h"
#include "rapidjson/prettywriter.h"
#include "rapidjson/document.h"
#include "rapidjson/error/error.h"
#include "rapidjson/error/en.h"

#define AES256_KEYSIZE 32
#define SM4_KEYSIZE 16
#define RGW_KMS_CACHE_SIZE 10000

BEGIN_KMS_NAMESPACE

using rapidjson::BaseReaderHandler;
using rapidjson::UTF8;
using rapidjson::SizeType;
using rapidjson::StringStream;

lru_map<std::string, key_info> KMSClient::_AES256_master_key_cache(RGW_KMS_CACHE_SIZE);
lru_map<std::string, key_info> KMSClient::_SM4_master_key_cache(RGW_KMS_CACHE_SIZE);
lru_map<std::string, std::string> KMSClient::_data_key_cache(RGW_KMS_CACHE_SIZE);

#ifdef WITH_RADOSGW_BEAST_FRONTEND
static void asio_send_http_cb(void *arg, int ret) {
  auto sync = (SyncPoint *) arg;
  sync->put(ret);
}
#endif

// Parse Ip and Port from Url
void get_ip_port_from_url(const std::string& url, std::string & host, std::string & port)
{
  if (url == "") {
    return;
  }

  auto pos = url.find(':');
  if (pos == std::string::npos) {
    host = url;
    port = "80";
  } else {
    host = url.substr(0, pos);
    port = url.substr(pos+1, url.size());
  }
  return;
}

int KMSClient::http_connect(const req_state* s, std::string& uri, std::string method,
                            const std::string& request_body, bufferlist& response_bl, bool iam_sign) const {
  std::string host, port, kms_address;
  /* create the connection pool */
  void **asio_ctx = (void **) s->asio_ctx;
  if (iam_sign) {
    kms_address = s->cct->_conf->rgw_abcstore_proxy_address;
  } else {
    kms_address = s->cct->_conf->rgw_kms_address;
  }
  get_ip_port_from_url(kms_address, host, port);
  ldout(s->cct, 20) << "kms address: " << host << " and " << port << dendl;

#ifdef WITH_RADOSGW_BEAST_FRONTEND
  if (asio_ctx != NULL) {
    static ConnectionPool _async_conn_pool = ConnectionPool(
        *((boost::asio::io_service *) asio_ctx[0]), host, port,
        s->cct->_conf->rgw_kms_connect_number,
        s->cct->_conf->rgw_kms_connect_retry, true);

    std::shared_ptr<ssl::stream<tcp::socket> > stream_ptr;

    int idx = _async_conn_pool.fetch_socket(stream_ptr, asio_ctx);

    if (idx < 0 || idx >= s->cct->_conf->rgw_kms_connect_number) {
      ldout(s->cct, 5) << __func__ << "(): ConnectionPool fetch_socket return error idx:" << idx << dendl;
      return -1;
    }

    SyncPoint sync(*((boost::asio::io_service *) asio_ctx[0]), *((boost::asio::yield_context *) asio_ctx[1]));

    auto client = std::make_shared<RgwAsyncHttpClient>(stream_ptr, uri);
    client->set_cb(&sync, asio_send_http_cb);
    client->set_reqid(s->trans_id);

    if (!iam_sign) {
      client->set_ssl(true);
    }
    std::string content_type;
    if (method == "post" || method == "put") {
      content_type = "application/json";
    }
    int op_ret = client->send_request(host, request_body, &response_bl, method, content_type);
    if (op_ret != 0) {
      ldout(s->cct, 0) << __func__ << "send request to abcstore_proxy error:" << op_ret << dendl;
      _async_conn_pool.free_socket(idx);
      return op_ret;
    }

    op_ret = sync.get();
    _async_conn_pool.free_socket(idx);
  } else
#endif
  {
    static boost::asio::io_context ioc;
    static ConnectionPool _sync_conn_pool = ConnectionPool(ioc, host, port,
        s->cct->_conf->rgw_kms_connect_number,
        s->cct->_conf->rgw_kms_connect_retry, false);

    std::shared_ptr<ssl::stream<tcp::socket> > stream_ptr;
    int idx = _sync_conn_pool.fetch_socket(stream_ptr);
    if (idx < 0 || idx >= s->cct->_conf->rgw_kms_connect_number) {
      ldout(s->cct, 0) << __func__ << "(): ConnectionPool fetch_socket return error idx:" << idx << dendl;
      return -1;
    }
    RgwSyncHttpClient client = RgwSyncHttpClient(stream_ptr, uri);

    if (!iam_sign) {
      client.set_ssl(true);
    }
    std::string content_type;
    if (method == "post" || method == "put") {
      content_type = "application/json";
    }
    client.set_reqid(s->trans_id);
    int op_ret = client.send_request(host, request_body, &response_bl, method, content_type);
    if (op_ret != 0) {
      ldout(s->cct, 0) << __func__ << "send request error:" << op_ret << dendl;
      _sync_conn_pool.free_socket(idx);
      return op_ret;
    }

     _sync_conn_pool.free_socket(idx);
  }
  return 0;
}

boost::optional<std::pair<std::string, std::string>>
KMSClient::generate_data_key(const req_state* s, const string& master_key_id, int key_length) {
  std::string ciphertext_data_key, plaintext_data_key;
  key_info data_key;
  if (key_length == AES256_KEYSIZE) {
    if (_AES256_master_key_cache.find(master_key_id, data_key)) {
      ciphertext_data_key = data_key.ciphertext;
      plaintext_data_key = data_key.plaintext;
      ldout(s->cct, 10) << "generate data key from cache." << dendl;
      return std::make_pair(ciphertext_data_key, plaintext_data_key);
    }
  } else if (key_length == SM4_KEYSIZE) {
    if (_SM4_master_key_cache.find(master_key_id, data_key)) {
      ciphertext_data_key = data_key.ciphertext;
      plaintext_data_key = data_key.plaintext;
      ldout(s->cct, 10) << "generate data key from cache." << dendl;
      return std::make_pair(ciphertext_data_key, plaintext_data_key);
    }
  }

  rapidjson::StringBuffer buf;
  rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(buf);
  std::stringstream ss;
  ss << "/?action=GenerateDataKey&userId=" << s->cct->_conf->rgw_kms_admin_user.c_str();
  std::string target = ss.str();

  writer.StartObject();
  writer.Key("keyId"); writer.String(master_key_id.c_str());
  writer.Key("numberOfBytes"); writer.Int(key_length);
  writer.EndObject();

  std::string request_body = buf.GetString();
  bufferlist response_body;

  int ret = http_connect(s, target, "post", request_body, response_body);
  if (ret != 0 || response_body.length() == 0) {
    ldout(s->cct, 5) << "http connect faild." << dendl;
    return boost::none;
  }

  //parse data key from json
  rapidjson::Document dom;
  if (dom.Parse(response_body.to_str().c_str()).HasParseError()) {
    ldout(s->cct, 5) << __func__ << "() ERROR: generate data key from kms return body don't format json." << dendl;
    return boost::none;
  }

  if (!dom.HasMember("ciphertext") || !dom["ciphertext"].IsString() ||
      !dom.HasMember("plaintext") || !dom["plaintext"].IsString()) {
    ldout(s->cct, 5) << __func__ << "() ERROR: generate data key from kms return body don't format json." << dendl;
    return boost::none;
  }

  try {
    ciphertext_data_key = rgw::from_base64(dom["ciphertext"].GetString());
    plaintext_data_key = rgw::from_base64(dom["plaintext"].GetString());
    ldout(s->cct, 30) << "generate kms data key, master key id: " << master_key_id
                      << " plaintext: " << plaintext_data_key << dendl;
  } catch (...) {
    ldout(s->cct, 5) << __func__ << "kms data key is not base64 encode." << dendl;
    return boost::none;
  }

  data_key.ciphertext = ciphertext_data_key;
  data_key.plaintext = plaintext_data_key;
  if (key_length == AES256_KEYSIZE) {
    _AES256_master_key_cache.add(master_key_id, data_key);
  } else if (key_length == SM4_KEYSIZE) {
    _SM4_master_key_cache.add(master_key_id, data_key);
  }
  _data_key_cache.add(ciphertext_data_key, plaintext_data_key);
  return std::make_pair(ciphertext_data_key, plaintext_data_key);
}

boost::optional<std::pair<std::string, std::string>>
KMSClient::generate_data_key_to_proxy(const req_state* s, const string& master_key_id, int key_length) {
  std::string ciphertext_data_key, plaintext_data_key;
  key_info data_key;
  if (key_length == AES256_KEYSIZE) {
    if (_AES256_master_key_cache.find(master_key_id, data_key)) {
      ciphertext_data_key = data_key.ciphertext;
      plaintext_data_key = data_key.plaintext;
      ldout(s->cct, 10) << "generate data key from cache." << dendl;
      return std::make_pair(ciphertext_data_key, plaintext_data_key);
    }
  } else if (key_length == SM4_KEYSIZE) {
    if (_SM4_master_key_cache.find(master_key_id, data_key)) {
      ciphertext_data_key = data_key.ciphertext;
      plaintext_data_key = data_key.plaintext;
      ldout(s->cct, 10) << "generate data key from cache." << dendl;
      return std::make_pair(ciphertext_data_key, plaintext_data_key);
    }
  }

  //send request to STS: assume role
  auto role_info = sts::STSClient::instance().assume_role(s);
  if (!role_info) {
    ldout(s->cct, 0) << __func__ << "(): ERROR assume role falid." << dendl;
    return boost::none;
  }

  std::stringstream ss;
  ss << "/kms/generateDataKey";
  std::string target = ss.str();

  rapidjson::Document dom;
  rapidjson::StringBuffer buf;
  rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(buf);

  writer.StartObject();
  writer.Key("user_ak"); writer.String(role_info->key.id.c_str());
  writer.Key("user_sk"); writer.String(role_info->key.key.c_str());
  writer.Key("session_token"); writer.String(role_info->session_token.c_str());
  writer.Key("master_key_id"); writer.String(master_key_id.c_str());
  if (key_length == SM4_KEYSIZE) {
    writer.Key("encrypt_algorithm"); writer.String("SM4");
  } else if (key_length == AES256_KEYSIZE) {
    writer.Key("encrypt_algorithm"); writer.String("AES256");
  }
  writer.EndObject();

  std::string request_body = buf.GetString();
  bufferlist response_body;

  int ret = http_connect(s, target, "get", request_body, response_body, true);
  if (ret != 0 || response_body.length() == 0) {
    ldout(s->cct, 5) << "http connect faild response body: " << response_body.to_str() << dendl;
    return boost::none;
  }

  if (dom.Parse(response_body.to_str().c_str()).HasParseError()) {
    ldout(s->cct, 5) << "generate data key malformed json." << dendl;
    return boost::none;
  }
  if (!dom.HasMember("errcode") || !dom["errcode"].IsInt()) {
    ldout(s->cct, 5) << "generate data key malformed json."<< dendl;
    return boost::none;
  }
  if (dom["errcode"].GetInt() != 0) {
    ldout(s->cct, 5) << "generate data key kms return " << dom["errcode"].GetInt() << " , errmsg: "
                     << dom["errmsg"].GetString() << dendl;
    return boost::none;
  }
  if (!dom.HasMember("result") || !dom["result"].IsString()) {
    ldout(s->cct, 5) << "generate data key malformed json." << dendl;
    return boost::none;
  }

  rapidjson::Document result;
  if (result.Parse(dom["result"].GetString()).HasParseError()) {
    ldout(s->cct, 5) << "generate data key malformed json." << dendl;
    return boost::none;
  }
  if (!result.HasMember("ciphertext") || !result.HasMember("plaintext")) {
    ldout(s->cct, 5) << "generate data key malformed json." << dendl;
    return boost::none;
  }

  try {
    ciphertext_data_key = rgw::from_base64(result["ciphertext"].GetString());
    plaintext_data_key = rgw::from_base64(result["plaintext"].GetString());
  } catch (...) {
    ldout(s->cct, 5) << __func__ << "kms data key is not base64 encode." << dendl;
    return boost::none;
  }

  if (plaintext_data_key.size() != key_length) {
    ldout(s->cct, 0) << __func__ << "get data key from kms key size: " << plaintext_data_key.size() << dendl;
    return boost::none;
  }

  data_key.plaintext = plaintext_data_key;
  data_key.ciphertext = ciphertext_data_key;
  if (key_length == AES256_KEYSIZE) {
    _AES256_master_key_cache.add(master_key_id, data_key);
  } else if (key_length == SM4_KEYSIZE) {
    _SM4_master_key_cache.add(master_key_id, data_key);
  }
  _data_key_cache.add(ciphertext_data_key, plaintext_data_key);
  return std::make_pair(ciphertext_data_key, plaintext_data_key);
}

std::string KMSClient::decrypt_data_key(const req_state* s, const std::string& ciphertext) {
  std::string plaintext;
  if (_data_key_cache.find(ciphertext, plaintext)) {
    ldout(s->cct, 20) << "decrypt data key from cache." << dendl;
    return plaintext;
  }

  rapidjson::StringBuffer buf;
  rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(buf);
  std::string ciphertext_b64 = rgw::to_base64(ciphertext);
  std::stringstream ss;
  ss << "/?action=Decrypt&userId=" << s->cct->_conf->rgw_kms_admin_user.c_str();
  std::string target = ss.str();

  writer.StartObject();
  writer.Key("ciphertext"); writer.String(ciphertext_b64.c_str());
  writer.EndObject();
  std::string request_body = buf.GetString();
  bufferlist response_body;

  int http_ret = http_connect(s, target, "post", request_body, response_body);
  if (http_ret != 0 || response_body.length() == 0) {
    ldout(s->cct, 5) << "http connect faild" << dendl;
    return plaintext;
  }

  rapidjson::Document dom;
  if (dom.Parse(response_body.to_str().c_str()).HasParseError()) {
    ldout(s->cct, 5) << __func__ << "() ERROR: decrypt data key from kms return body don't format json." << dendl;
    return plaintext;
  }

  if (!dom.HasMember("plaintext") || !dom["plaintext"].IsString()) {
    ldout(s->cct, 5) << __func__ << "() ERROR: decrypt data key from kms return body don't format json." << dendl;
    return plaintext;
  }

  try {
    plaintext = rgw::from_base64(dom["plaintext"].GetString());
  } catch (...) {
    ldout(s->cct, 5) << __func__ << "kms data key is not base64 encode." << dendl;
    return plaintext;
  }
  _data_key_cache.add(ciphertext, plaintext);

  return plaintext;
}

std::string KMSClient::decrypt_data_key_to_proxy(const req_state* s, const std::string& ciphertext) {
  std::string plaintext;
  if (_data_key_cache.find(ciphertext, plaintext)) {
    ldout(s->cct, 20) << "decrypt data key from cache." << dendl;
    return plaintext;
  }

  //send request to STS: assume role
  auto role_info = sts::STSClient::instance().assume_role(s);
  if (!role_info) {
    ldout(s->cct, 0) << __func__ << "(): ERROR assume role falid." << dendl;
    return plaintext;
  }

  std::string ciphertext_b64 = rgw::to_base64(ciphertext);
  std::stringstream ss;
  ss << "/kms/decryptDataKey";
  std::string target = ss.str();

  rapidjson::Document dom;
  rapidjson::StringBuffer buf;
  rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(buf);

  writer.StartObject();
  writer.Key("user_ak"); writer.String(role_info->key.id.c_str());
  writer.Key("user_sk"); writer.String(role_info->key.key.c_str());
  writer.Key("session_token"); writer.String(role_info->session_token.c_str());
  writer.Key("ciphertext"); writer.String(ciphertext_b64.c_str());
  writer.EndObject();

  std::string request_body = buf.GetString();
  bufferlist response_body;

  int ret = http_connect(s, target, "get", request_body, response_body, true);
  if (ret != 0 || response_body.length() == 0) {
    ldout(s->cct, 5) << "http connect faild." << dendl;
    return plaintext;
  }

  if (dom.Parse(response_body.to_str().c_str()).HasParseError()) {
    ldout(s->cct, 5) << "decrypt data key malformed json." << dendl;
    return plaintext;
  }
  if (!dom.HasMember("errcode") || !dom["errcode"].IsInt()) {
    ldout(s->cct, 5) << "decrypt data key malformed json."<< dendl;
    return plaintext;
  }
  if (dom["errcode"].GetInt() != 0) {
    ldout(s->cct, 5) << "decrypt data key kms return " << dom["errcode"].GetInt() << " , errmsg: "
                     << dom["errmsg"].GetString() << dendl;
    return plaintext;
  }
  if (!dom.HasMember("result") || !dom["result"].IsString()) {
    ldout(s->cct, 5) << "decrypt data key malformed json." << dendl;
    return plaintext;
  }

  rapidjson::Document result;
  if (result.Parse(dom["result"].GetString()).HasParseError()) {
    ldout(s->cct, 5) << "decrypt data key malformed json." << dendl;
    return plaintext;
  }
  if (!result.HasMember("plaintext") || !result["plaintext"].IsString()) {
    ldout(s->cct, 5) << "decrypt data key malformed json." << dendl;
    return plaintext;
  }

  try {
    plaintext = rgw::from_base64(result["plaintext"].GetString());
  } catch (...) {
    ldout(s->cct, 5) << __func__ << "kms data key is not base64 encode." << dendl;
  }

  _data_key_cache.add(ciphertext, plaintext);
  return plaintext;
}

END_KMS_NAMESPACE
