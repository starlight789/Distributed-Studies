#ifndef BAIDU_CEPH_CEPH_RGW_BHTTP_HTTP_SERVER_H
#define BAIDU_CEPH_CEPH_RGW_BHTTP_HTTP_SERVER_H

class HttpConnection {
};

class HttpServer {
public:
  int start();
  void stop();
  void join();
private:

};

#endif

