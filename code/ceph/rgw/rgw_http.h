#ifndef CEPH_RGW_HTTP_H
#define CEPH_RGW_HTTP_H
#include <errno.h>
#include <stdlib.h>
#include <system_error>
#include <unistd.h>

#include <sstream>

#include <boost/utility/string_view.hpp>

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/ssl/error.hpp>
#include <boost/lexical_cast.hpp>
#include <rgw/rgw_common.h>

#ifdef WITH_RADOSGW_BEAST_FRONTEND
#include "asio_sync.hpp"
#endif

using tcp = boost::asio::ip::tcp;
namespace http = boost::beast::http;
namespace ssl = boost::asio::ssl;

class RgwBaseHttpClient {
protected:
  std::shared_ptr<ssl::stream<tcp::socket> > _stream;
  string _uri;
  string _req_id;
  bufferlist* _body_bl = nullptr;
  bool is_ssl = false;
  http::request<http::string_body> req;
  http::response_parser<http::string_body> resp;
  boost::beast::flat_buffer buffer; // Must persist between read
public:
  // use ssl::stream to compat http and https
  RgwBaseHttpClient(std::shared_ptr<ssl::stream<tcp::socket> >& stream) : _stream(stream) {
    resp.body_limit((std::numeric_limits<std::uint64_t>::max)());
  }
  RgwBaseHttpClient(std::shared_ptr<ssl::stream<tcp::socket> >& stream, string& uri)
    : _stream(stream), _uri(std::move(uri)) {
      resp.body_limit((std::numeric_limits<std::uint64_t>::max)());
  }

  void set_uri(std::string& uri) {
    _uri = std::move(uri);
  }

  void set_reqid(const std::string& req_id) {
    _req_id = req_id;
  }

  void set_ssl(bool _ssl) {
    is_ssl = _ssl;
  }

  /**
   * send_request - support sync and async send http client.
   *                sync work with civetweb, async work with beast and bhttp.
   * PARAMS:
   *     - host: Host in http headers
   *     - request_body: content to send
   *     - body_bl: response body
   *     - method: http method, support put or post
   * RETURN:
   *     - int: 0 on success, otherwise return negative
   */
  virtual int send_request(const std::string& host, const std::string& request_body,
                          bufferlist* body_bl, std::string method, const std::string& content_type="") = 0;
  virtual ~RgwBaseHttpClient() {}
};

typedef void (*FP)(void*, int);
class RgwAsyncHttpClient : public std::enable_shared_from_this<RgwAsyncHttpClient>,
                           public RgwBaseHttpClient {
  void* _sync_pt = nullptr;
  FP _fp = nullptr;
  void send();
  void on_write(boost::system::error_code ec, std::size_t bytes_sent);
  void on_read(boost::system::error_code ec, std::size_t bytes_received);
public:
  RgwAsyncHttpClient(std::shared_ptr<ssl::stream<tcp::socket> >& stream)
    : RgwBaseHttpClient(stream) {}
  RgwAsyncHttpClient(std::shared_ptr<ssl::stream<tcp::socket> >& stream, string& uri)
    : RgwBaseHttpClient(stream, uri) {}

  ~RgwAsyncHttpClient() override {}

  int send_request(const std::string& host, const std::string& request_body,
                  bufferlist* body_bl, std::string method, const std::string& content_type="") override;

  void set_cb(void* sync_pt, FP fp) {
    _sync_pt = sync_pt;
    _fp = fp;
  }
};

class RgwSyncHttpClient : public RgwBaseHttpClient {
public:
  RgwSyncHttpClient(std::shared_ptr<ssl::stream<tcp::socket> >& stream)
    : RgwBaseHttpClient(stream) {}
  RgwSyncHttpClient(std::shared_ptr<ssl::stream<tcp::socket> >& stream, string& uri)
    : RgwBaseHttpClient(stream, uri) {}

  ~RgwSyncHttpClient() override {}

  int send_request(const std::string& host, const std::string& request_body,
                  bufferlist* body_bl, std::string method, const std::string& content_type="") override;
};

inline void get_ip_port_from_url(std::string & url, std::string & host, std::string & port) {
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

class RGWHttpConnect {
public:
  int http_connect(const req_state* s, std::string& uri, std::string method,
                   const std::string& request_body, bufferlist& response_bl) const;

private:
  static ConnectionPool _async_conn_pool;
};

#endif
