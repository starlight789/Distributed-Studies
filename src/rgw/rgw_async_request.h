#ifndef CEPH_RGW_ASYNC_REQUEST_H
#define CEPH_RGW_ASYNC_REQUEST_H

#include <functional>
#include <memory>
#include "common/Cond.h"
#include "rgw_async_processor.hpp"

class RGWAsyncRequest;
template class RGWAsyncProcessor<RGWAsyncRequest>;

class RGWAsyncRequest final: public RefCountedObject {
public:
    using RequestFunc = std::function<std::shared_ptr<void>(std::shared_ptr<void>)>;

    RGWAsyncRequest(RequestFunc func_ptr, void* params) = delete;
    RGWAsyncRequest(RequestFunc func_ptr, std::shared_ptr<void> params) : m_func_ptr(func_ptr), m_params(std::move(params)),
                                                          m_lock("RGWAsyncRequest::lock"){
    }
    RGWAsyncRequest(const RGWAsyncRequest&) = delete;
    RGWAsyncRequest& operator=(const RGWAsyncRequest&) = delete;
    ~RGWAsyncRequest() override = default;

    void send_request() {
        assert(m_func_ptr != nullptr);
        get();
        std::shared_ptr<void> ret = m_func_ptr(m_params);
        {
            Mutex::Locker guard(m_lock);
            m_result = std::move(ret);
            m_complete = true;
            m_cond.SignalOne();
        }
        put();
    }

    std::shared_ptr<void> get_ret_status() {
        return m_result;
    }

    bool aio_complete() {
        Mutex::Locker guard(m_lock);
        return m_complete;
    }

    void aio_wait() {
        Mutex::Locker guard(m_lock);
        if (m_complete == false) {
            m_cond.Wait(m_lock);
        }
    }

    void release() {
        put();
    }

private:
    RequestFunc             m_func_ptr;
    std::shared_ptr<void>   m_params;
    std::shared_ptr<void>   m_result{nullptr};
    Mutex                   m_lock;
    Cond                    m_cond;
    bool                    m_complete{false};
};

#endif  /* CEPH_RGW_ASYNC_REQUEST_H */