#ifndef BAIDU_BOS_CEPH_KMS_H
#define BAIDU_BOS_CEPH_KMS_H

#include <iostream>
#include "include/buffer.h"

#include "common/dout.h"
#include "common/lru_map.h"
#include "rgw_http.h"
#include "rgw_common.h"

#ifdef WITH_RADOSGW_BEAST_FRONTEND
#include "asio_sync.hpp"
#endif

#define dout_context g_ceph_context
#define dout_subsys ceph_subsys_rgw

#define BEGIN_KMS_NAMESPACE namespace kms {
#define END_KMS_NAMESPACE } /* namespace kms */

BEGIN_KMS_NAMESPACE

struct key_info {
  std::string plaintext;
  std::string ciphertext;
};

class KMSClient {
public:
  KMSClient() {};

  static KMSClient& instance() {
    static KMSClient kms_client;
    return kms_client;
  }

  int create_master_key(const req_state* s);

  int list_master_keys(const req_state* s);

  boost::optional<std::pair<std::string, std::string>>
    generate_data_key(const req_state* s, const std::string& master_key_id, int key_length);

  boost::optional<std::pair<std::string, std::string>>
     generate_data_key_to_proxy(const req_state* s, const std::string& master_key_id, int key_length);

  std::string decrypt_data_key(const req_state* s, const std::string& ciphertext);

  std::string decrypt_data_key_to_proxy(const req_state* s, const std::string& ciphertext);

private:
  static ConnectionPool _async_conn_pool;
public:
  static lru_map<std::string, key_info>    _AES256_master_key_cache;
  static lru_map<std::string, key_info>    _SM4_master_key_cache;
  static lru_map<std::string, std::string> _data_key_cache;

  int http_connect(const req_state* s, std::string& uri, std::string method,
                   const std::string& request_body, bufferlist& response_bl, bool iam_sign = false) const;
};

END_KMS_NAMESPACE
#endif /* BAIDU_BOS_CEPH_KMS_H */
