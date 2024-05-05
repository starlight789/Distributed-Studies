#ifndef BAIDU_CEPH_CEPH_COMMON_BTHREAD_WRAPPER_HPP
#define BAIDU_CEPH_CEPH_COMMON_BTHREAD_WRAPPER_HPP
#include "common/bthread.hpp"
#include "include/Context.h"
#include <string>

class ButexWrapper : public Butex {
public:
  ButexWrapper(const std::string &) {}
  ButexWrapper(const char *, bool, bool) {}
  void Lock() {
    lock();
    _is_locked = true;
  }
  void Unlock() {
    _is_locked = false;
    unlock();
  }
  bool is_locked() const {
    return _is_locked;
  }
private:
  bool _is_locked = false;

public:
  class Locker {
  public:
    explicit Locker(ButexWrapper& m) : mutex(m) {
      mutex.Lock();
    }
    ~Locker() {
      mutex.Unlock();
    }
  private:
    ButexWrapper &mutex;
  };
};

class ButexCondWrapper : public ButexCond {
public:
  ButexCondWrapper() {}
  int Wait(ButexWrapper &t) {
    return !wait(t);
  }
  void Signal() {
    notify();
  }
};

class SafeButexCond : public Context {
  ButexWrapper *lock;    ///< Mutex to take
  ButexCondWrapper *cond;     ///< Cond to signal
  bool *done;     ///< true after finish() has been called
  int *rval;      ///< return value (optional)
public:
  SafeButexCond(ButexWrapper *l, ButexCondWrapper *c, bool *d, int *r=0) : lock(l), cond(c), done(d), rval(r) {
    *done = false;
  }
  void finish(int r) override {
    lock->Lock();
    if (rval)
      *rval = r;
    *done = true;
    cond->Signal();
    lock->Unlock();
  }
};

#endif
