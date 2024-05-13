#ifndef BAIDU_CEPH_CEPH_RGW_BHTTP_HTTP_CONNECTION_H
#define BAIDU_CEPH_CEPH_RGW_BHTTP_HTTP_CONNECTION_H

#include "http_parser.h"

#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <memory>

class Socket;
class HttpConnection;

class HttpRequestHandler {
public:
  virtual ~HttpRequestHandler() {}
  virtual void do_request(HttpConnection *) = 0;
};

class HttpConnection {
public:
  static int on_url(http_parser *parser, const char *at, size_t length);
  static int on_header_field(http_parser *parser, const char *at, size_t length);
  static int on_header_value(http_parser *parser, const char *at, size_t length);
  static int on_headers_complete(http_parser *parser);
  static int on_body(http_parser *parser, const char *at, size_t length);
  static int on_message_complete(http_parser *parser);
public:
  HttpConnection(std::shared_ptr<Socket> s);
  void set_handler(HttpRequestHandler *h) {
    _handler = h;
  }

  void do_session();

  int read_headers();
  int read_body(char *buf, size_t max);

  int send_data(const char *buf, size_t size);

  int http_major() const {
    return _parser.http_major;
  }
  int http_minor() const {
    return _parser.http_minor;
  }
  const char *http_method() const {
    return http_method_str((enum http_method) _parser.method);
  }

  const std::string &url() const {
    return _url;
  }

  std::map<std::string, std::string> &headers() {
    return _headers;
  }

  bool is_keep_alive() const {
    return _is_keep_alive;
  }

  int local_port() const;
  std::string remote_addr() const;

private:
  void finish_request_header();
  void reset_parser();
private:
  std::shared_ptr<Socket> _s;
  std::vector<char> _recv_buf;
  std::vector<char> _send_buf;
  size_t _send_off = 0;

  http_parser _parser;
  http_parser_settings _parser_conf;

  bool _is_keep_alive = false;
  std::string _url;
  bool _is_header_done = false;
  bool _is_body_done = false;
  std::string _current_key;
  std::string _current_value;
  std::map<std::string, std::string> _headers;
  char *_current_body = NULL;
  size_t _parsed_body_size = 0;
  size_t _recv_body_off = 0;
  size_t _recv_body_read_off = 0;

  HttpRequestHandler *_handler = NULL;
};

#endif
