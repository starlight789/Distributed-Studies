#ifndef CEPH_RGW_ASYNC_PROCESSOR_H
#define CEPH_RGW_ASYNC_PROCESSOR_H

#include <atomic>
#include <deque>
#include <string>
#include <type_traits>
#include <boost/type_index.hpp>
#include "rgw_rados.h"
#include "common/Throttle.h"
#include "common/WorkQueue.h"

#define dout_context g_ceph_context
#define dout_subsys ceph_subsys_rgw

template <typename RequestType>
class RGWAsyncProcessor {
    static_assert(!std::is_pointer_v<RequestType>, "Pointer types are not allowed.");
    static_assert(!std::is_reference_v<RequestType>, "Reference types are not allowed.");
    std::string getRequestTypeName() const {
        return boost::typeindex::type_id_with_cvr<RequestType>().pretty_name();
    }
    std::string getRGWAsyncWQName() const {
        return "RGWAsyncWQ<" + getRequestTypeName() + ">";
    }

public:
    RGWAsyncProcessor(RGWRados *store, int num_threads);
    ~RGWAsyncProcessor() {}
    void start();
    void stop();
    void handle_request(RequestType *req);
    void queue(RequestType *req);

    bool is_going_down() {
        return m_going_down;
    }

private:
    struct RGWAsyncWQ : public ThreadPool::WorkQueue<RequestType> {
        RGWAsyncProcessor *processor;
        RGWAsyncWQ(RGWAsyncProcessor *p, time_t timeout, time_t suicide_timeout, ThreadPool *tp)
        : ThreadPool::WorkQueue<RequestType>(p->getRGWAsyncWQName(), timeout, suicide_timeout, tp), processor(p) {}

        bool _enqueue(RequestType *req) override;
        void _dequeue(RequestType *req) override {
            ceph_abort();
        }
        bool _empty() override;
        RequestType *_dequeue() override;
        using ThreadPool::WorkQueue<RequestType>::_process;
        void _process(RequestType *req, ThreadPool::TPHandle& handle) override;
        void _dump_queue();
        void _clear() override {
            assert(processor->m_req_queue.empty());
        }
    };

private:
    std::deque<RequestType *>   m_req_queue;
    std::atomic<bool>           m_going_down{false};
    RGWRados                    *m_store;
    ThreadPool                  m_tp;
    Throttle                    m_req_throttle;
    RGWAsyncWQ                  m_req_wq;
};

template <typename RequestType>
bool RGWAsyncProcessor<RequestType>::RGWAsyncWQ::_enqueue(RequestType *req) {
    if (processor->is_going_down()) {
        return false;
    }
    req->get();
    processor->m_req_queue.push_back(req);
    dout(20) << "enqueued request req=" << hex << req << dec << dendl;
    _dump_queue();
    return true;
}

template <typename RequestType>
bool RGWAsyncProcessor<RequestType>::RGWAsyncWQ::_empty() {
    return processor->m_req_queue.empty();
}

template <typename RequestType>
RequestType *RGWAsyncProcessor<RequestType>::RGWAsyncWQ::_dequeue() {
    if (processor->m_req_queue.empty())
        return nullptr;
    RequestType *req = processor->m_req_queue.front();
    processor->m_req_queue.pop_front();
    dout(20) << "dequeued request req=" << hex << req << dec << dendl;
    _dump_queue();
    return req;
}

template <typename RequestType>
void RGWAsyncProcessor<RequestType>::RGWAsyncWQ::_process(RequestType *req, ThreadPool::TPHandle& handle) {
    processor->handle_request(req);
    processor->m_req_throttle.put(1);
}

template <typename RequestType>
void RGWAsyncProcessor<RequestType>::RGWAsyncWQ::_dump_queue() {
    if (!g_conf->subsys.should_gather<ceph_subsys_rgw, 20>()) {
        return;
    }
    if (processor->m_req_queue.empty()) {
        dout(20) << (processor->getRGWAsyncWQName() + ": empty") << dendl;
        return;
    }
    dout(20) << (processor->getRGWAsyncWQName() + ":") << dendl;
    for (auto iter = processor->m_req_queue.begin(); iter != processor->m_req_queue.end(); ++iter) {
        dout(20) << "req: " << hex << *iter << dec << dendl;
    }
}

template <typename RequestType>
RGWAsyncProcessor<RequestType>::RGWAsyncProcessor(RGWRados *store, int num_threads)
  : m_store(store), m_tp(m_store->ctx(), (getRequestTypeName() +"::m_tp"), "rados_async", num_threads),
    m_req_throttle(m_store->ctx(), "rgw_async_ops", num_threads * 2),
    m_req_wq(this, g_conf->rgw_op_thread_timeout,
    g_conf->rgw_op_thread_suicide_timeout, &m_tp) {
}

template <typename RequestType>
void RGWAsyncProcessor<RequestType>::start() {
    m_tp.start();
}

template <typename RequestType>
void RGWAsyncProcessor<RequestType>::stop() {
    m_going_down = true;
    m_tp.drain(&m_req_wq);
    m_tp.stop();
    for (auto iter = m_req_queue.begin(); iter != m_req_queue.end(); ++iter) {
        (*iter)->put();
    }
}

template <typename RequestType>
void RGWAsyncProcessor<RequestType>::handle_request(RequestType *req) {
    req->send_request();
    req->put();
}

template <typename RequestType>
void RGWAsyncProcessor<RequestType>::queue(RequestType *req) {
    m_req_throttle.get(1);
    m_req_wq.queue(req);
}


#endif