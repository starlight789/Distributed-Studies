#ifndef BAIDU_CEPH_CEPH_RGW_BHTTP_NET_H
#define BAIDU_CEPH_CEPH_RGW_BHTTP_NET_H

#include "common/bthread.hpp"
#include <butil/endpoint.h>
#include <memory>
#include <functional>
#include <mutex>
#include <map>

typedef struct ssl_st SSL;

class Socket {
public:
  Socket() {}
  Socket(int fd) : _fd(fd) {
    if (butil::get_local_side(fd, &_local_side) != 0) {
      _local_side = butil::EndPoint();
    }
  }
  virtual ~Socket();

  int fd() const {
    return _fd;
  }
  void set_fd(int fd) {
    _fd = fd;
  }

    void bind_ssl(SSL *ssl) {
        _ssl = ssl;
    }

  bool is_valid() const {
    return _state.load();
  }

  void set_remote_side(const butil::EndPoint &remote) {
    _remote_side = remote;
  }

  const butil::EndPoint &remote_side() const {
    return _remote_side;
  }

  const butil::EndPoint &local_side() const {
    return _local_side;
  }

  ssize_t recv_some(char *buf, size_t size);

  ssize_t send(const char *buf, size_t size);

  int set_nonblocking();

  int shutdown();

  int close();
  
  int associate_to_reactor();

  bool more_input_events(int *progress) {
    return !_nevent.compare_exchange_strong(*progress, 0, std::memory_order_release,
              std::memory_order_acquire);
  }

  void set_input_callback(std::function<void()> cb) {
      _cb_input_event = cb;
  }

    void wait_in() {
        _io_in.wait();
    }
  void on_input_event() {
    _io_in.notify();
    if (_cb_input_event != nullptr) {
      if (_nevent.fetch_add(1, std::memory_order_acq_rel) == 0) {
        _cb_input_event();
      }
    }
  }

    void wait_out() {
        _io_out.wait();
    }
  void on_output_event() {
    _io_out.notify();
  }
private:
  int _fd = -1;
  std::atomic<bool> _state = true;
  std::atomic<int> _nevent = 0;
  std::function<void()> _cb_input_event = nullptr;

  butil::EndPoint _remote_side;
  butil::EndPoint _local_side;

  IOFlag _io_in;
  IOFlag _io_out;

    SSL *_ssl = NULL;
};

typedef std::shared_ptr<Socket> SocketPtr;

class Protocol {
public:
  virtual void start_session(SocketPtr s) = 0;
  virtual ~Protocol() {}
};

class NetReactor {
public:
  static void *run_this(void *p) {
    auto reactor = (NetReactor *) p;
    reactor->run();
    return NULL;
  }
  static NetReactor &global() { return instance; }
  static NetReactor instance;
public:
  NetReactor();
  ~NetReactor();
  int associate(SocketPtr s);
  int remove(Socket *s);
  int start();
  void stop();
  void join();
  void run();

private:
  volatile bool _stop = false;
  int _epfd = -1;
  bthread_t _tid;

  std::mutex _mutex;
  std::map<int, SocketPtr> _socks;
};

class Acceptor : public Socket {
public:
  static void *accept_func(void *p);
public:
  Acceptor(Protocol *protocol) : _protocol(protocol) {
    set_input_callback([this] {
      bthread_t tid;
      bthread_start_urgent(&tid, NULL, accept_func, this);
    });
  }

  int listen(const char *ip, int port);

  void accept_util_egain();

private:
  Protocol *_protocol;
};

#endif
