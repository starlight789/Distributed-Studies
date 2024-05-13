#include "rgw_bhttp_client.h"
#include "bhttp/http_connection.h"

int RGWBhttpClient::init_env(CephContext *cct) {
  _env.init(cct);
  perfcounter->inc(l_rgw_qlen);
  perfcounter->inc(l_rgw_qactive);

  std::string key = "HTTP_";
  auto &headers = _conn->headers();
  for (auto it = headers.begin(); it != headers.end(); ++it) {
    auto& name = it->first;
    auto& value = it->second;

    key.resize(5 + name.size());
    auto dest = key.begin() + 5;
    for (auto src = name.begin(); src != name.end(); ++src, ++dest) {
      if (*src == '-') {
        *dest = '_';
      } else if (*src == '_') {
        *dest = '-';
      } else {
        *dest = std::toupper(*src);
      }
    }
    if (key.compare(5, name.size(), "CONTENT_LENGTH") == 0) {
        _env.set("CONTENT_LENGTH", value);
    } else if (key.compare(5, name.size(), "CONTENT_TYPE") == 0) {
        _env.set("CONTENT_TYPE", value);
    } else {
        _env.set(key, value);
    }
  }

  _env.set("HTTP_VERSION", std::to_string(_conn->http_major()) + '.'
      + std::to_string(_conn->http_minor()));
  _env.set("REQUEST_METHOD", _conn->http_method());

  auto url = _conn->url();
  auto pos = url.find('?');
  if (pos != std::string::npos) {
    auto query = url.substr(pos + 1);
    _env.set("QUERY_STRING", query);
    url = url.substr(0, pos);
  }
  _env.set("REQUEST_URI", url);
  _env.set("SCRIPT_URI", url);

  _env.set("SERVER_PORT", std::to_string(_conn->local_port()));
  _env.set("REMOTE_ADDR", _conn->remote_addr());
  return 0;
}

size_t RGWBhttpClient::send_status(int status, const char *status_name) {
  auto s = _oss.tellp();
  _oss << "HTTP/" << _conn->http_major() << '.' << _conn->http_minor() << ' '
    << status << ' ' << status_name << "\r\n";
  return _oss.tellp() - s;
}
size_t RGWBhttpClient::send_100_continue() {
  auto s = _oss.tellp();
  _oss << "HTTP/" << _conn->http_major() << '.' << _conn->http_minor() << " 100 CONTINUE\r\n\r\n";
  auto size = _oss.tellp() - s;
  flush();
  return size;
}
size_t RGWBhttpClient::send_header(const boost::string_ref& name, const boost::string_ref& value) {
  auto s = _oss.tellp();
  _oss << name << ": " << value << "\r\n";
  return _oss.tellp() - s;
}
size_t RGWBhttpClient::send_content_length(uint64_t len) {
  auto s = _oss.tellp();
  _oss << "Content-Length: " << len << "\r\n";
  return _oss.tellp() - s;
}

size_t RGWBhttpClient::complete_header() {
  auto s = _oss.tellp();

  char timestr[128];
  const time_t gtime = time(nullptr);
  struct tm result;
  gmtime_r(&gtime, &result);
  strftime(timestr, sizeof(timestr), "%a, %d %b %Y %H:%M:%S %Z", &result);
  _oss << "Date: " << timestr << "\r\n";

  if (_conn->is_keep_alive()) {
    _oss << "Connection: Keep-Alive\r\n";
  } else {
    _oss << "Connection: Close\r\n";
  }
  _oss << "\r\n";
  size_t sent = _oss.tellp() - s;

  flush();
  return sent;
}

size_t RGWBhttpClient::recv_body(char* buf, size_t max) {
  int n = _conn->read_body(buf, max);
  if (n < 0) {
    throw rgw::io::Exception(EIO, std::system_category());
  }
  return n;
}

size_t RGWBhttpClient::write_data(const char* buf, size_t len) {
  int n = _conn->send_data(buf, len);
  if (n < 0) {
    throw rgw::io::Exception(EIO, std::system_category());
  }
  return n;
}

void RGWBhttpClient::flush() {
  _oss.flush();
}

void RGWBhttpClient::get_throttle_token(int num, shared_ptr<TokenBucketThrottle> token_bucket) {
  if (!token_bucket) {
    return;
  }
  ThrottleRequest throttle_request;
  bool waited = token_bucket->get<RGWBhttpClient, ThrottleRequest,
       &RGWBhttpClient::get_throttle_token_callback>(num, this, &throttle_request);
  if (waited == true) {
    ScopedMutex<Butex> lock(throttle_request.butex);
    while (throttle_request.ready == false) {
      throttle_request.ready_cond.wait(throttle_request.butex);
    }
  }
}

