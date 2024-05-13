#ifndef BAIDU_CEPH_CEPH_RGW_RGW_BHTTP_CLIENT_H
#define BAIDU_CEPH_CEPH_RGW_RGW_BHTTP_CLIENT_H

#include "rgw_client_io.h"
#include "rgw_throttle.h"
#include "common/bthread_wrapper.hpp"

class HttpConnection;

class RGWBhttpClient : public rgw::io::RestfulClient,
                    public rgw::io::BuffererSink {
public:
  RGWBhttpClient(HttpConnection *conn)
      : _conn(conn), _txbuf(*this), _oss(&_txbuf) {}

  int init_env(CephContext *cct) override;

  size_t send_status(int status, const char *status_name) override;
  size_t send_100_continue() override;
  size_t send_header(const boost::string_ref& name, const boost::string_ref& value) override;
  size_t send_content_length(uint64_t len) override;
  size_t complete_header() override;

  size_t recv_body(char* buf, size_t max) override;

  size_t write_data(const char *buf, size_t len) override;
  size_t send_body(const char* buf, size_t len) override {
    return write_data(buf, len);
  }

  size_t complete_request() override {
    perfcounter->inc(l_rgw_qlen, -1);
    perfcounter->inc(l_rgw_qactive, -1);
    return 0;
  }

  void flush() override;

  RGWEnv& get_env() noexcept override {
    return _env;
  }

  void get_throttle_token(int num, shared_ptr<TokenBucketThrottle> token_bucket) override;

private:
  struct ThrottleRequest {
    Butex butex;
    ButexCond ready_cond;
    bool ready{false};
  };

  void get_throttle_token_callback(int r, ThrottleRequest* req) {
    ScopedMutex<Butex> lock(req->butex);
    req->ready = true;
    req->ready_cond.notify();
  }

  RGWEnv _env;
  HttpConnection *_conn;
  rgw::io::StaticOutputBufferer<> _txbuf;
  std::ostream _oss;
};

#endif
