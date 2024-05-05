#ifndef BAIDU_CEPH_CEPH_RGW_RGW_BHTTP_FRONTEND_H
#define BAIDU_CEPH_CEPH_RGW_RGW_BHTTP_FRONTEND_H

#include <memory>
#include "rgw_frontend.h"

class RGWBhttpFrontend : public RGWFrontend {
  class Impl;
  std::unique_ptr<Impl> impl;
public:
  RGWBhttpFrontend(const RGWProcessEnv& env, RGWFrontendConfig* conf);
  ~RGWBhttpFrontend() override;

  int init() override;
  int run() override;
  void stop() override;
  void join() override;

  void pause_for_new_config() override {};
  void unpause_with_new_config(RGWRados *store, rgw_auth_registry_ptr_t auth_registry) override {};
};

#endif
