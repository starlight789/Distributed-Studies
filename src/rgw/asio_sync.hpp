#ifndef BAIDU_CEPH_ASIO_SYNC_H
#define BAIDU_CEPH_ASIO_SYNC_H
#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>

template<typename Handler>
boost::asio::detail::wait_op *create_wait_op(Handler &handler) {
  typedef boost::asio::detail::wait_handler<Handler> op;
  typename op::ptr p = { boost::asio::detail::addressof(handler),
    op::ptr::allocate(handler), 0 };
  p.p = new (p.v) op(handler);
  boost::asio::detail::wait_op *result = p.p;
  p.v = p.p = 0;
  return result;
}

class SyncPoint {
public:
  SyncPoint(boost::asio::io_service &io_service, boost::asio::yield_context h) : io(io_service), _init(h) {
    _op = create_wait_op(_init.completion_handler);
  }
  int get() {
    _init.result.get();
    return _rc;
  }
  void put(int rc) {
    _rc = rc;
    boost::asio::use_service<boost::asio::detail::scheduler>(io).post_immediate_completion(_op, true);
  }
private:
  boost::asio::io_service &io;
  boost::asio::async_completion<boost::asio::yield_context, void (boost::system::error_code)> _init;
  boost::asio::detail::wait_op *_op;
  int _rc;
};
#endif /* BAIDU_CEPH_ASIO_SYNC_H */
