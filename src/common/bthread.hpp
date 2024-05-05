/***************************************************************************
 * 
 * Copyright (c) 2018 Baidu.com, Inc. All Rights Reserved
 * 
 **************************************************************************/
/**
 * @file util/thread_sync.h
 * @author lili19(com@baidu.com)
 * @date 2018/01/22 17:06:00
 * @brief 
 *  
 **/
#ifndef BAIDU_CEPH_CEPH_COMMON_BTHREAD_HPP
#define BAIDU_CEPH_CEPH_COMMON_BTHREAD_HPP

#include <bthread/bthread.h>
#undef ARRAY_SIZE
#undef COMPILE_ASSERT
#include <memory>

class Butex {
public:
    Butex() {
        bthread_mutex_init(&_mutex, NULL);
    }
    ~Butex() {
        bthread_mutex_destroy(&_mutex);
    }

    bthread_mutex_t *get() {
        return &_mutex;
    }

    void lock() {
        bthread_mutex_lock(&_mutex);
    }

    void unlock() {
        bthread_mutex_unlock(&_mutex);
    }
private:
    bthread_mutex_t _mutex;
};

class ButexCond {
public:
    ButexCond() {
        bthread_cond_init(&_cond, NULL);
    }
    ~ButexCond() {
        bthread_cond_destroy(&_cond);
    }

    int wait(Butex &mutex) {
        return bthread_cond_wait(&_cond, mutex.get());
    }

    int wait(Butex &mutex, int timeout_ms) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += timeout_ms / 1000;
        ts.tv_nsec += (timeout_ms % 1000) * 1000000L;
        return bthread_cond_timedwait(&_cond, mutex.get(), &ts);
    }

    void notify() {
        bthread_cond_signal(&_cond);
    }

    void notify_all() {
        bthread_cond_broadcast(&_cond);
    }
private:
    bthread_cond_t _cond;
};

template<typename T>
class ScopedMutex {
public:
    ScopedMutex(T &mutex) : _mutex(mutex) {
        _mutex.lock();
    }
    ~ScopedMutex() {
        _mutex.unlock();
    }
private:
    T &_mutex;
};

class IOFlag {
public:
    bool wait() {
        ScopedMutex lock(_mutex);
        if (!_flag) {
            _cond.wait(_mutex);
        }
        if (_flag) {
          _flag = false;
          return true;
        }
        return false;
    }

    void notify() {
        ScopedMutex lock(_mutex);
        _flag = true;
        _cond.notify();
    }

private:
    bool _flag = false;
    Butex _mutex;
    ButexCond _cond;
};

template<typename T>
class FutureState {
public:
    FutureState() {}
    void set(const T &val) {
        ScopedMutex lock(_mutex);
        _val = val;
        _state = true;
        _cond.notify();
    }
    bool wait() {
        ScopedMutex lock(_mutex);
        if (!_state) {
            _cond.wait(_mutex);
        }
        return _state;
    }
    T &get() {
        wait();
        return _val;
    }
private:
    volatile bool _state = false;
    T _val;
    Butex _mutex;
    ButexCond _cond;
};

template<typename T> class Promise;

template<typename T>
class Future {
    friend Promise<T>;
    explicit Future(std::shared_ptr<FutureState<T>> state) : _state(state) {}
public:
    bool valid() const { return _state != nullptr; }
    T &get() { return _state->get(); }
private:
    std::shared_ptr<FutureState<T>> _state = nullptr;
};

template<typename T>
class Promise {
public:
    Promise() {
        _state = std::make_shared<FutureState<T>>();
    }
    Future<T> get_future() {
        return Future<T>(_state);
    }
    void set_value(const T &value) {
        _state->set(value);
    }
private:
    std::shared_ptr<FutureState<T>> _state;
};

#endif

