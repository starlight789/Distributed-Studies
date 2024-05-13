#include <errno.h>
#include <vector>
#include <algorithm>
#include <string>
#include <boost/tokenizer.hpp>

#include "json_spirit/json_spirit.h"
#include "common/ceph_json.h"

#include "rgw_string.h"
#include "rgw_rados.h"
#include "rgw_http_errors.h"

#include "rgw_http.h"
#include "common/ceph_crypto.h"
#include "common/armor.h"
#include "common/errno.h"
#include "common/Clock.h"
#include "common/Formatter.h"
#include "common/perf_counters.h"
#include "common/convenience.h"
#include "common/strtol.h"
#include "include/str_list.h"

#include <sstream>

#define dout_context g_ceph_context
#define dout_subsys ceph_subsys_rgw

#define HTTPV2 11
#define BCE_REQID "x-bce-request-id"
#define ABCS_AGENT "abcstorage_agent"

void RgwAsyncHttpClient::send() {
  if (is_ssl) {
    http::async_write(*_stream, req,
        std::bind(
          &RgwAsyncHttpClient::on_write,
          shared_from_this(),
          std::placeholders::_1,
          std::placeholders::_2));
  } else {
    http::async_write(_stream->next_layer(), req,
        std::bind(
          &RgwAsyncHttpClient::on_write,
          shared_from_this(),
          std::placeholders::_1,
          std::placeholders::_2));
  }
}

void RgwAsyncHttpClient::on_write(boost::system::error_code ec, std::size_t bytes_sent) {
  if (ec) {
    dout(0) << __func__ << "(): send request error:" << ec.message()
            << ", uri:" << _uri
            << ", request_id:" << _req_id << dendl;
    _fp(_sync_pt, -EIO);
    return;
  }

  if (is_ssl) {
    _stream->handshake(ssl::stream_base::client);
    http::async_read(*_stream, buffer, resp,
      std::bind(
        &RgwAsyncHttpClient::on_read,
        shared_from_this(),
        std::placeholders::_1,
        std::placeholders::_2));
  } else {
    http::async_read(_stream->next_layer(), buffer, resp,
      std::bind(
        &RgwAsyncHttpClient::on_read,
        shared_from_this(),
        std::placeholders::_1,
        std::placeholders::_2));
  }
}

void RgwAsyncHttpClient::on_read(boost::system::error_code ec, std::size_t bytes_received) {
  boost::ignore_unused(bytes_received);
  if (ec) {
    dout(0) << __func__ << "(): receive response error:" << ec.message()
            << ", uri:" << _uri
            << ", request_id:" << _req_id << dendl;
    _fp(_sync_pt, -EIO);
    return;
  }
  int ret = 0;
  if (resp.get().result_int() >= 300) {
    dout(0) <<  __func__ << "(): ERROR response code:"<< resp.get().result_int()
            << ", uri:" << _uri
            << ", request_id:" << _req_id << dendl;
    dout(30) <<  __func__ << "(): ERROR response body:"
             << resp.get().body().c_str() << dendl;
    ret = -EBADRQC;
  }
  uint64_t resp_len = resp.get().body().size();
  try {
    uint64_t content_length = boost::lexical_cast<uint64_t>(resp.get().base().at(http::field::content_length));
    if (resp_len != content_length) {
      dout(0) << __func__ << "(): ERROR got response, while content_length:"
              << content_length << "not equal to body.size():"<< resp_len
              << ", uri:" << _uri
              << ", request_id:" << _req_id << dendl;
    }
  } catch(std::exception const& e) {
    dout(0) << __func__ << " ERROR exception: " << e.what()
            << ". get content_length failed." << dendl;
  }
  if (_body_bl) {
    _body_bl->append(resp.get().body().c_str(), resp_len);
  }
  _fp(_sync_pt, ret);
}

int RgwAsyncHttpClient::send_request(const string& host, const string& request_body,
                                    bufferlist* body_bl, string method, const string& content_type) {
  try {
    _body_bl = body_bl;
    req.version(HTTPV2);
    std::transform(method.begin(), method.end(), method.begin(), ::tolower);
    if (method.compare("put") == 0) {
      req.method(http::verb::put);
    } else {
      req.method(http::verb::post);
    }
    req.target(_uri);
    if (!host.empty()) {
      req.set(http::field::host, host);
    }
    req.set(http::field::user_agent, ABCS_AGENT);

    if (!_req_id.empty()) {
      boost::beast::string_view stv = BCE_REQID;
      req.set(stv, _req_id);
    }
    if (content_type != "") {
      req.set(http::field::content_type, content_type);
    }
    if (!request_body.empty()) {
      req.body() = std::move(request_body);
      req.prepare_payload();
    }
    this->send();
    return 0;
  } catch (std::exception& e) {
    dout(5) << __func__ << "(): Exception:" << e.what()
            << ", errno:" << errno
            << ", uri:" << _uri
            << ", request_id:" << _req_id << dendl;
  }
  return -errno;
}

int RgwSyncHttpClient::send_request(const string& host, const string& request_body,
                                   bufferlist* body_bl, string method, const string& content_type) {
  try {
    req.version(HTTPV2);
    std::transform(method.begin(), method.end(), method.begin(), ::tolower);

    if (method.compare("put") == 0) {
      req.method(http::verb::put);
    } else if (method.compare("get") == 0) {
      req.method(http::verb::get);
    } else {
      req.method(http::verb::post);
    }

    req.target(_uri);
    if (!host.empty()) {
      req.set(http::field::host, host);
    }
    req.set(http::field::user_agent, ABCS_AGENT);
    if (!_req_id.empty()) {
      boost::beast::string_view stv = BCE_REQID;
      req.set(stv, _req_id);
    }
    if (content_type != "") {
      req.set(http::field::content_type, content_type);
    }
    if (!request_body.empty()) {
      req.body() = std::move(request_body);
      req.prepare_payload();
    }

    if (!_stream) {
      dout(0) << __func__ << "(): ERROR stream is nullptr" << dendl;
      return -EINVAL;
    }

    // next_layer() work for http request
    // *_stream work for https request
    if (is_ssl) {
      _stream->handshake(ssl::stream_base::client);
      http::write(*_stream, req);
      http::read(*_stream, buffer, resp);
    } else {
      http::write(_stream->next_layer(), req);
      http::read(_stream->next_layer(), buffer, resp);
    }

    uint64_t resp_len = resp.get().body().size();
    try {
      uint64_t content_length = boost::lexical_cast<uint64_t>(resp.get().base().at(http::field::content_length));
      if (resp_len != content_length) {
        dout(0) << "ERROR: get response from abcstore_proxy, while content_length:"
                << content_length << "not equal to body.size():"<< resp_len
                << ", uri:" << _uri
                << ", request_id:" << _req_id << dendl;
      }
    } catch(std::exception const& e) {
      dout(0) << __func__ << " ERROR exception: " << e.what()
              << ". get content_length failed." << dendl;
    }

    if (body_bl) {
      body_bl->append(resp.get().body().c_str(), resp_len);
    }
    if (resp.get().result_int() >= 300) {
      dout(0) << __func__ << "(): ERROR abcstore_proxy response code:"<< resp.get().result_int()
              << ", uri:" << _uri
              << ", request_id:" << _req_id << dendl;
      dout(30) << __func__ << "(): ERROR abcstore_proxy response body:" 
               << resp.get().body().c_str() << dendl;
      return resp.get().result_int();
    }
    return 0;
  } catch (std::exception const& e) {
    dout(5) << __func__ << "(): ERROR exception:"<< e.what()
            << ", errno:" << errno
            << ", uri:" << _uri
            << ", request_id:" << _req_id << dendl;
  }
  return -errno;
}

#ifdef WITH_RADOSGW_BEAST_FRONTEND
static void asio_send_http_cb(void *arg, int ret) {
  auto sync = (SyncPoint *) arg;
  sync->put(ret);
}
#endif

int RGWHttpConnect::http_connect(const req_state* s, std::string& uri, std::string method,
                                 const std::string& request_body, bufferlist& response_bl) const {
  std::string host, port;
  std::string proxy_address = s->cct->_conf->rgw_abcstore_proxy_address;
  get_ip_port_from_url(proxy_address, host, port);
  void **asio_ctx = (void **) s->asio_ctx;
#ifdef WITH_RADOSGW_BEAST_FRONTEND
  if (asio_ctx != NULL) {
    static ConnectionPool _async_conn_pool = ConnectionPool(
        *((boost::asio::io_service *) asio_ctx[0]), host, port,
        s->cct->_conf->rgw_abcstore_proxy_connect_number,
        s->cct->_conf->rgw_abcstore_proxy_connect_retry, true);

    std::shared_ptr<ssl::stream<tcp::socket> > stream_ptr;

    int idx = _async_conn_pool.fetch_socket(stream_ptr, asio_ctx);

    if (idx < 0 || idx >= s->cct->_conf->rgw_abcstore_proxy_connect_number) {
      ldout(s->cct, 0) << "ConnectionPool fetch_socket return error idx:" << idx << dendl;
      return -1;
    }

    SyncPoint sync(*((boost::asio::io_service *) asio_ctx[0]), *((boost::asio::yield_context *) asio_ctx[1]));

    auto client = std::make_shared<RgwAsyncHttpClient>(stream_ptr, uri);
    client->set_reqid(s->trans_id);

    client->set_cb(&sync, asio_send_http_cb);

    // call send async http request
    int op_ret = 0;
    retry_send_request_by_connection_pool(s, op_ret, _async_conn_pool, idx, [&] {
          return client->send_request(host, request_body, &response_bl, method);
        });

    if (op_ret != 0) {
      ldout(s->cct, 0) << "send request to abcstore_proxy error:" << op_ret << dendl;
      _async_conn_pool.free_socket(idx);
      return op_ret;
    }
    // wait for response
    op_ret = sync.get();

    _async_conn_pool.free_socket(idx);
  } else
#endif
  {
    static boost::asio::io_context ioc;

    static ConnectionPool _sync_conn_pool = ConnectionPool(ioc, host, port,
        s->cct->_conf->rgw_abcstore_proxy_connect_number,
        s->cct->_conf->rgw_abcstore_proxy_connect_retry, false);

    std::shared_ptr<ssl::stream<tcp::socket> > stream_ptr;
    int idx = _sync_conn_pool.fetch_socket(stream_ptr);
    if (idx < 0 || idx >= s->cct->_conf->rgw_abcstore_proxy_connect_number) {
      ldout(s->cct, 0) << "ConnectionPool fetch_socket return error idx:" << idx << dendl;
      return -1;
    }
    RgwSyncHttpClient client = RgwSyncHttpClient(stream_ptr, uri);

    client.set_reqid(s->trans_id);

    int op_ret = 0;
    retry_send_request_by_connection_pool(s, op_ret, _sync_conn_pool, idx, [&] {
          return client.send_request(host, request_body, &response_bl, method);
        });

    if (op_ret != 0) {
      ldout(s->cct, 0) << "send request error:" << op_ret << dendl;
      _sync_conn_pool.free_socket(idx);
      return op_ret;
    }

    _sync_conn_pool.free_socket(idx);
  }
  return 0;
}

