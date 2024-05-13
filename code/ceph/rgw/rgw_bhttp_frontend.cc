#include "bhttp/http_connection.h"
#include "bhttp/net.h"
#include "rgw_bhttp_frontend.h"
#include "rgw_bhttp_client.h"
#include <openssl/ssl.h>
#include <openssl/err.h>

#define dout_subsys ceph_subsys_rgw

static void *new_connection_func(void *p) {
    std::unique_ptr<HttpConnection> c((HttpConnection *) p);
    c->do_session();
    return NULL;
}

class HttpProtocol : public Protocol {
public:
    HttpProtocol(HttpRequestHandler *h) : _handler(h) {}
    ~HttpProtocol() {}
    void start_session(SocketPtr s) {
        auto c = new HttpConnection(s);
        c->set_handler(_handler);

        bthread_t tid;
        if (bthread_start_background(&tid, NULL, new_connection_func, c) != 0) {
            delete c;
        }
    }
private:
    HttpRequestHandler *_handler = NULL;
};

class HttpsProtocol : public Protocol {
public:
  HttpsProtocol(HttpRequestHandler *h) : _handler(h) {}
  ~HttpsProtocol() {
    if (_ssl_ctx != NULL) {
      SSL_CTX_free(_ssl_ctx);
    }
  }
  int init_ssl(const std::string &cert_path, const std::string &key_path) {
    _ssl_ctx = SSL_CTX_new(SSLv23_server_method());
    if (_ssl_ctx == NULL) {
      dout(0) << "Fail to new SSL_CTX, error:" << ERR_reason_error_string(ERR_get_error()) << dendl;
      return ERR_get_error();
    }
    if (!SSL_CTX_use_certificate_chain_file(_ssl_ctx, cert_path.c_str())) {
      dout(0) << "Fail to load certificate " << cert_path << ", error:" << ERR_reason_error_string(ERR_get_error()) << dendl;
      return ERR_get_error();
    }
    if (!SSL_CTX_use_PrivateKey_file(_ssl_ctx, key_path.c_str(), SSL_FILETYPE_PEM)) {
      dout(0) << "Fail to load key " << key_path << ", error:" << ERR_reason_error_string(ERR_get_error()) << dendl;
      return ERR_get_error();
    }
    if (!SSL_CTX_check_private_key(_ssl_ctx)) {
      dout(0) << "key:" << key_path << " and cert:" << cert_path << " not match, error:"
        << ERR_reason_error_string(ERR_get_error()) << dendl;
      return ERR_get_error();
    }
    return 0;
  }
  void start_session(SocketPtr s) {
    if (_ssl_ctx == NULL) {
      s->shutdown();
      return;
    }
    SSL *ssl = SSL_new(_ssl_ctx);
    if (ssl == NULL) {
      s->shutdown();
      return;
    }
    SSL_set_fd(ssl, s->fd());
    SSL_set_accept_state(ssl);
    while (true) {
      int rc = SSL_do_handshake(ssl);
      if (rc == 1) {
        break;
      }
      int ssl_error = SSL_get_error(ssl, rc);
      if (ssl_error == SSL_ERROR_WANT_READ) {
        s->wait_in();
      } else if (ssl_error == SSL_ERROR_WANT_WRITE) {
        s->wait_out();
      } else {
        SSL_free(ssl);
        s->shutdown();
        dout(0) << "SSL handshake failed, error:" << ERR_reason_error_string(ERR_get_error()) << dendl;
        return;
      }
    }
    s->bind_ssl(ssl);

    auto c = new HttpConnection(s);
    c->set_handler(_handler);

    bthread_t tid;
    if (bthread_start_background(&tid, NULL, new_connection_func, c) != 0) {
      delete c;
    }
  }
private:
  HttpRequestHandler *_handler = NULL;
  SSL_CTX *_ssl_ctx = NULL;
};

class BhttpFrontend : public HttpRequestHandler {
public:
  BhttpFrontend(const RGWProcessEnv& env, RGWFrontendConfig* conf)
    : env(env), conf(conf), _http(this), _https(this) {
  }
  ~BhttpFrontend() {}
  int init() {
    int thread_num = env.store->ctx()->_conf->rgw_thread_pool_size;
    bthread_setconcurrency(thread_num);
    int ret = NetReactor::global().start();
    if (ret != 0) {
      return 1;
    }
    return 0;
  }
  int run() {
    return start_serving();
  }
  void stop() {
    NetReactor::global().stop();
  }
  void join() {
    NetReactor::global().join();
  }

  int start_serving() {
    auto& config = conf->get_config_map();
    auto ports = config.equal_range("port");
    for (auto i = ports.first; i != ports.second; ++i) {
      auto acceptor = std::make_shared<Acceptor>(&_http);
      auto port = atoi(i->second.c_str());
      int ret = acceptor->listen("0.0.0.0", port);
      if (ret != 0) {
        return 1;
      }
      ret = NetReactor::global().associate(acceptor);
      if (ret != 0) {
        return -1;
      }
    }
    ports = config.equal_range("ssl_port");
    if (ports.first != ports.second) {
      std::string cert_path;
      std::string key_path;
      auto it = config.find("ssl_certificate");
      if (it != config.end()) {
        cert_path = it->second;
      }
      it = config.find("ssl_private_key");
      if (it != config.end()) {
        key_path = it->second;
      }
      if (cert_path.empty() && key_path.empty()) {
        dout(0) << "no certificate or private key specified" << dendl;
        return -1;
      }
      if (cert_path.empty()) {
        cert_path = key_path;
      } else if (key_path.empty()) {
        key_path = cert_path;
      }
      int ret = _https.init_ssl(cert_path, key_path);
      if (ret != 0) {
        return -1;
      }
    }
    for (auto i = ports.first; i != ports.second; ++i) {
      auto acceptor = std::make_shared<Acceptor>(&_https);
      auto port = atoi(i->second.c_str());
      int ret = acceptor->listen("0.0.0.0", port);
      if (ret != 0) {
        return 1;
      }
      ret = NetReactor::global().associate(acceptor);
      if (ret != 0) {
        return -1;
      }
    }
    return 0;
  }

  void do_request(HttpConnection *conn) {
    auto cct = env.store->ctx();
    RGWBhttpClient real_client(conn); 
    auto real_client_io = rgw::io::add_reordering(
                            rgw::io::add_buffering(cct,
                              rgw::io::add_chunking(
                                rgw::io::add_conlen_controlling(
                                  &real_client))));
    RGWRequest req{env.store->get_new_req_id()};
    RGWRestfulIO client(cct, &real_client_io);
    process_request(env.store, env.rest, &req, env.uri_prefix,
                    *env.auth_registry, &client, env.olog);
  }
private:
  RGWProcessEnv env;
  RGWFrontendConfig* conf;

  HttpProtocol _http;
  HttpsProtocol _https;
};

class RGWBhttpFrontend::Impl : public BhttpFrontend {
 public:
  Impl(const RGWProcessEnv& env, RGWFrontendConfig* conf) : BhttpFrontend(env, conf) {}
};

RGWBhttpFrontend::RGWBhttpFrontend(const RGWProcessEnv& env, RGWFrontendConfig* conf)
  : impl(new Impl(env, conf)) {
}

RGWBhttpFrontend::~RGWBhttpFrontend() = default;

int RGWBhttpFrontend::init() {
  return impl->init();
}

int RGWBhttpFrontend::run() {
  return impl->run();
}

void RGWBhttpFrontend::stop() {
  impl->stop();
}

void RGWBhttpFrontend::join() {
  impl->join();
}
