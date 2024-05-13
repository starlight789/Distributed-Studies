#ifndef CEPH_RGW_STS_H
#define CEPH_RGW_STS_H

#include "include/buffer.h"
#include "rgw_http.h"
#include "rgw_common.h"

#ifdef WITH_RADOSGW_BEAST_FRONTEND
#include "asio_sync.hpp"
#endif

#define dout_context g_ceph_context
#define dout_subsys ceph_subsys_rgw

#define BEGIN_STS_NAMESPACE namespace sts {
#define END_STS_NAMESPACE } /* namespace sts */

BEGIN_STS_NAMESPACE

struct RGWRoleInfo {
  RGWAccessKey key;
  std::string session_token;
  uint64_t expiration;
};

class STSClient : public RGWHttpConnect {
public:
  STSClient() {};
  virtual ~STSClient() {};

  static STSClient& instance() {
    static STSClient sts_client;
    return sts_client;
  }

  virtual boost::optional<RGWRoleInfo> assume_role(const req_state* s);

protected:
  boost::optional<RGWRoleInfo> prase_assume_role_response(const req_state* s, bufferlist& response_body);

  static lru_map<std::string, RGWRoleInfo> _role_cache;
};

END_STS_NAMESPACE
#endif /* CEPH_RGW_STS_H */
