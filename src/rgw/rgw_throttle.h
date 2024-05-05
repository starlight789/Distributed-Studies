#ifndef CEPH_RGW_THROTTLE_H
#define CEPH_RGW_THROTTLE_H

#include "rgw_common.h"
#include "common/Throttle.h"
#include "common/Mutex.h"
#include "common/Timer.h"
#include "common/dout.h"
#include <mutex>

#define dout_subsys ceph_subsys_rgw

#define UPDATE_RGWS_INTERVAL 120

class ThrottleManager {
private:
  ThrottleManager() {};
  ThrottleManager(const ThrottleManager&);
  ThrottleManager& operator=(const ThrottleManager&);
  ~ThrottleManager();

public:
  static ThrottleManager &instance() {
    static ThrottleManager s_instance;
    return s_instance;
  }

  void init(CephContext* cct, RGWRados* rados);

  void create_node_bandwidth_throttle(uint64_t limit);

  void create_node_qps_throttle(uint64_t limit);

  shared_ptr<TokenBucketThrottle> get_node_bandwidth_throttle();

  shared_ptr<TokenBucketThrottle> get_node_qps_throttle();

  int check_qps_limit(req_state* const s);

  shared_ptr<TokenBucketThrottle> get_bucket_bandwidth_throttle(req_state* const s);

  shared_ptr<TokenBucketThrottle> get_bucket_qps_throttle(req_state* const s);

  shared_ptr<TokenBucketThrottle> get_user_bandwidth_throttle(req_state* const s);

  shared_ptr<TokenBucketThrottle> get_user_qps_throttle(req_state* const s);

  void shutdown();

  int get_rgw_nums();

private:
  shared_ptr<TokenBucketThrottle> create_bucket_bandwidth_throttle(
      const string& bucket_name, uint64_t limit);

  shared_ptr<TokenBucketThrottle> create_bucket_qps_throttle(
      const string& bucket_name, uint64_t limit);

  shared_ptr<TokenBucketThrottle> create_user_bandwidth_throttle(
      const string& uid, uint64_t limit);

  shared_ptr<TokenBucketThrottle> create_user_qps_throttle(
      const string& uid, uint64_t limit);

  void schedule_get_rgw_nums();

  CephContext* _cct;
  Mutex* _timer_lock;
  Mutex get_num_lock{"get_rgw_nums_lock"};
  SafeTimer* _timer;
  RGWRados* _rados;
  atomic<int> _rgw_nums{1};
  RWLock _bucket_bandwidth_lock{"bucket_bandwidth_lock"};
  RWLock _bucket_qps_lock{"bucket_qps_lock"};
  RWLock _user_bandwidth_lock{"user_bandwidth_lock"};
  RWLock _user_qps_lock{"user_qps_lock"};
  FunctionContext *_token_manager_ctx = nullptr;

  shared_ptr<TokenBucketThrottle> _node_bandwidth_throttle;
  shared_ptr<TokenBucketThrottle> _node_qps_throttle;
  std::map<std::string, shared_ptr<TokenBucketThrottle>> _bucket_bandwidth_throttle_map;
  std::map<std::string, shared_ptr<TokenBucketThrottle>> _bucket_qps_throttle_map;
  std::map<std::string, shared_ptr<TokenBucketThrottle>> _user_bandwidth_throttle_map;
  std::map<std::string, shared_ptr<TokenBucketThrottle>> _user_qps_throttle_map;
};

#endif // CEPH_RGW_THROTTLE_H

