#include "http_connection.h"
#include "net.h"
#include "common/debug.h"

#define dout_context g_ceph_context
#define dout_subsys ceph_subsys_rgw

int HttpConnection::on_url(http_parser *parser, const char *at, size_t length) {
  auto c = (HttpConnection *) parser->data;
  c->_url.append(at, length);
  return 0;
}

int HttpConnection::on_header_field(http_parser *parser, const char *at, size_t length) {
  auto c = (HttpConnection *) parser->data;
  if (!c->_current_value.empty()) {
    c->finish_request_header();
  }
  c->_current_key.append(at, length);
  return 0;
}
int HttpConnection::on_header_value(http_parser *parser, const char *at, size_t length) {
  auto c = (HttpConnection *) parser->data;
  c->_current_value.append(at, length);
  return 0;
}
int HttpConnection::on_headers_complete(http_parser *parser) {
  auto c = (HttpConnection *) parser->data;
  if (!c->_current_value.empty()) {
    c->finish_request_header();
  }
  c->_is_header_done = true;
  c->_is_keep_alive = http_should_keep_alive(parser);
  return 0;
}
int HttpConnection::on_body(http_parser *parser, const char *at, size_t length) {
  auto c = (HttpConnection *) parser->data;
  if (c->_current_body != NULL) {
    memmove(c->_current_body + c->_parsed_body_size, at, length);
  }
  c->_parsed_body_size += length;
  return 0;
}
int HttpConnection::on_message_complete(http_parser *parser) {
  auto c = (HttpConnection *) parser->data;
  c->_is_body_done = true;
  return 0;
}

HttpConnection::HttpConnection(std::shared_ptr<Socket> s) : _s(s) {
  http_parser_settings_init(&_parser_conf);
  _parser_conf.on_url = on_url;
  _parser_conf.on_header_field = on_header_field;
  _parser_conf.on_header_value = on_header_value;
  _parser_conf.on_headers_complete = on_headers_complete;
  _parser_conf.on_body = on_body;
  _parser_conf.on_message_complete = on_message_complete;
  _parser.data = this;
  http_parser_init(&_parser, HTTP_REQUEST);
  _recv_buf.resize(512);
}

int HttpConnection::local_port() const {
  return _s->local_side().port;
}
std::string HttpConnection::remote_addr() const {
  return butil::endpoint2str(_s->remote_side()).c_str();
}

void HttpConnection::do_session() {
  while (true) {
    int ret = read_headers();
    if (ret <= 0) {
      if (ret < 0) {
        dout(0) << "socket failure during read header, error:(" << -ret << ")" << strerror(-ret) << dendl;
      }
      _s->shutdown();
      return;
    }
    if (_handler != NULL) {
      _handler->do_request(this);
    } else {
      // send 501
      _s->shutdown();
      return;
    }

    if (!is_keep_alive()) {
      _s->shutdown();
      return;
    }

    while (!_is_body_done) {
      int n = read_body(_recv_buf.data(), _recv_buf.size());
      if (n < 0) {
        _s->shutdown();
        return;
      }
    }
    reset_parser();
  }
}
int HttpConnection::read_headers() {
  _current_body = _recv_buf.data();
  _parsed_body_size = 0;
  while (true) {
    ssize_t n = _s->recv_some(_recv_buf.data(), _recv_buf.size());
    if (n > 0) {
      size_t np = http_parser_execute(&_parser, &_parser_conf, _recv_buf.data(), n);
      if (n != (ssize_t) np) {
        return -EINVAL;
      }
      if (_is_header_done) {
        _recv_body_off = _parsed_body_size;
        return n;
      }
    } else {
      return n;
    }
  }
}

int HttpConnection::read_body(char *buf, size_t max) {
  size_t offset = 0;
  if (_recv_body_off > _recv_body_read_off) {
    offset = std::min(_recv_body_off - _recv_body_read_off, max);
    memcpy(buf, _recv_buf.data() + _recv_body_read_off, offset);
    _recv_body_read_off += offset;
  }
  while (!_is_body_done && offset < max) {
    ssize_t n = _s->recv_some(_recv_buf.data(), std::min(_recv_buf.size(), max - offset));
    if (n <= 0) {
      if (n == 0) {
        return -ECONNRESET;
      }
      return -n;
    }
    _current_body = buf + offset;
    _parsed_body_size = 0;
    size_t nparsed = http_parser_execute(&_parser, &_parser_conf, _recv_buf.data(), n);
    if (nparsed != (size_t) n) {
      dout(-1) << "http parse body failed, " << http_errno_name((http_errno) _parser.http_errno) << dendl;
      return -EINVAL;
    }
    offset += _parsed_body_size;
  }
  return offset;
}

void HttpConnection::finish_request_header() {
  _headers.emplace(std::make_pair(std::move(_current_key), std::move(_current_value)));
  _current_key.resize(0);
  _current_value.resize(0);
}

void HttpConnection::reset_parser() {
  http_parser_init(&_parser, HTTP_REQUEST);
  _is_keep_alive = false;
  _is_header_done = false;
  _is_body_done = false;
  _url.resize(0);
  _current_key.resize(0);
  _current_value.resize(0);
  _headers.clear();
  _current_body = NULL;
  _recv_body_off = 0;
  _recv_body_read_off = 0;
}

int HttpConnection::send_data(const char *buf, size_t size) {
  return _s->send(buf, size);
} 
