#include "net.h"

#include <butil/logging.h>
#include <butil/endpoint.h>
#include <butil/fd_utility.h>
#include <sys/epoll.h>

#include <openssl/ssl.h>

Socket::~Socket() {
  //LOG(DEBUG) << "release socket, client:" << _remote_side;
    if (_ssl != NULL) {
        SSL_free(_ssl);
    }
  if (_fd >= 0) {
    ::close(_fd);
  }
}

ssize_t Socket::recv_some(char *buf, size_t size) {
  ssize_t off = 0;
  while (size > (size_t) off) {
    if (_ssl != NULL) {
        int n = SSL_read(_ssl, buf + off, size - off);
        if (n > 0) {
            off += n;
        } else {
            if (n == 0) {
                return off;
            }
            int ssl_error = SSL_get_error(_ssl, n);
            if (ssl_error == SSL_ERROR_WANT_READ
                || (ssl_error == SSL_ERROR_SYSCALL && BIO_fd_non_fatal_error(errno))) {
                if (off > 0) {
                    return off;
                }
                _io_in.wait();
            } else {
                if (ssl_error == SSL_ERROR_SYSCALL) {
                    return -errno;
                }
                return -EIO;
            }
        }
        continue;
    }
    ssize_t n = ::recv(_fd, buf + off, size - off, 0);
    if (n > 0) {
      off += n;
    } else {
      if (n == 0) {
        return off;
      } else if (errno == EAGAIN) {
        if (off > 0) {
          return off;
        }
        _io_in.wait();
      } else if (errno != EINTR) {
        return -errno;
      }
    }
  }
  return off;
}
ssize_t Socket::send(const char *buf, size_t size) {
  ssize_t total = 0;
  while (size > (size_t) total) {
    if (_ssl != NULL) {
        int n = SSL_write(_ssl, buf + total, size - total);
        if (n >= 0) {
            total += n;
        } else {
            int ssl_error = SSL_get_error(_ssl, n);
            if (ssl_error == SSL_ERROR_WANT_WRITE
                || (ssl_error == SSL_ERROR_SYSCALL && BIO_fd_non_fatal_error(errno))) {
                _io_out.wait();
            } else {
                if (ssl_error == SSL_ERROR_SYSCALL) {
                    return -errno;
                }
                return -EIO;
            }
        }
    }
    ssize_t n = ::send(_fd, buf + total, size - total, 0);
    if (n >= 0) {
      total += n;
    } else {
      if (errno == EAGAIN) {
        _io_out.wait();
      } else if (errno != EINTR) {
        return -errno;
      }
    }
  }
  return total;
}

int Socket::shutdown() {
  //LOG(DEBUG) << "shutdown socket, client:" << _remote_side;
  _state.store(false);
  return ::shutdown(_fd, SHUT_RDWR);
}

int Socket::close() {
  _state.store(false);
  ::close(_fd);
  _fd = -1;
  return 0;
}

int Socket::set_nonblocking() {
  butil::make_close_on_exec(_fd);
  butil::make_no_delay(_fd);
  if (butil::make_non_blocking(_fd) != 0) {
    PLOG(ERROR) << "Fail to set fd=" << _fd << " to non-blocking";
    return -1;
  }
  return 0;
}

void *Acceptor::accept_func(void *p) {
  auto a = (Acceptor *) p;
  a->accept_util_egain();
  return NULL;
}

int Acceptor::listen(const char *ip, int port) {
  butil::EndPoint endpoint;
  butil::str2endpoint(ip, port, &endpoint);
  int fd = butil::tcp_listen(endpoint);
  if (fd < 0) {
    return -1;
  }
  set_fd(fd);
  return 0;
}

void Acceptor::accept_util_egain() {
  struct sockaddr in_addr;
  socklen_t in_len = sizeof(in_addr);
  int progress = 1;
  for (;;) {
    int fd = accept(this->fd(), &in_addr, &in_len);
    if (fd < 0) {
      if (errno == EAGAIN) {
        if (more_input_events(&progress)) {
          continue;
        }
        return;
      } else if (errno == EINTR) {
        continue;
      }
      PLOG_EVERY_SECOND(ERROR) << "Fail to accept from listened_fd=" << this->fd();
      return;
    }
    butil::EndPoint remote((struct sockaddr_in &) in_addr);
    //LOG(DEBUG) << "new tcp connection, client:" << remote;

    auto s = std::make_shared<Socket>(fd);
    s->set_remote_side(remote);
    int ret = NetReactor::global().associate(s);
    if (ret != 0) {
      continue;
    }
    if (_protocol != NULL) {
      _protocol->start_session(s);
    }
  }
}

NetReactor NetReactor::instance;

NetReactor::NetReactor() {
  _epfd = epoll_create(1024 * 1024);
}
NetReactor::~NetReactor() {
  stop();
  join();
  if (_epfd >= 0) {
    ::close(_epfd);
    _epfd = -1;
  }
}
int NetReactor::associate(SocketPtr s) {
  int ret = s->set_nonblocking();
  if (ret != 0) {
    return ret;
  }
  epoll_event evt;
  evt.events = EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLET;
  evt.data.ptr = s.get();
  ret = epoll_ctl(_epfd, EPOLL_CTL_ADD, s->fd(), &evt);
  if (ret != 0) {
    return ret;
  }
  std::lock_guard<std::mutex> lock(_mutex);
  _socks[s->fd()] = s;
  return 0;
}
int NetReactor::remove(Socket *s) {
  int ret = epoll_ctl(_epfd, EPOLL_CTL_DEL, s->fd(), NULL);
  if (ret != 0) {
    return ret;
  }
  std::lock_guard<std::mutex> lock(_mutex);
  _socks.erase(s->fd());
  return ret;
}
int NetReactor::start() {
  if (_epfd < 0) {
    return -1;
  }
  return bthread_start_background(&_tid, NULL, run_this, this);
}
void NetReactor::stop() {
  _stop = true;
}
void NetReactor::join() {
  if (_tid) {
    bthread_join(_tid, NULL);
    _tid = 0;
  }
}
void NetReactor::run() {
  epoll_event e[32];
  while (!_stop) {
    int n = epoll_wait(_epfd, e, 32, 1000);
    if (_stop) {
      // epoll_ctl/epoll_wait should have some sort of memory fencing
      // guaranteeing that we(after epoll_wait) see _stop set before
      // epoll_ctl.
      break;
    }
    if (n < 0) {
      if (EINTR == errno) {
        // We've checked _stop, no wake-up will be missed.
        continue;
      }
      PLOG(FATAL) << "Fail to epoll_wait epfd=" << _epfd;
      break;
    }
    for (int i = 0; i < n; ++i) {
      Socket *s = (Socket *) e[i].data.ptr;
      if (!s->is_valid()) {
        remove(s);
        continue;
      }
      if (e[i].events & (EPOLLIN | EPOLLERR | EPOLLHUP)) {
        s->on_input_event();
      }
      if (e[i].events & EPOLLOUT) {
        s->on_output_event();
      }
    }
  }
}
