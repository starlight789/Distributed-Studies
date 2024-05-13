#include "rgw_throttle.h"
#include "rgw_rados.h"

void ThrottleManager::init(CephContext* cct, RGWRados* rados) {
  _cct = cct;
  _rados = rados;

  _timer_lock = new Mutex("timer_lock");
  _timer = new SafeTimer(_cct, *_timer_lock);
  _timer->init();

  if (_cct->_conf->rgw_node_bandwidth_limit > 0) {
    create_node_bandwidth_throttle(_cct->_conf->rgw_node_bandwidth_limit);
  }
  if (_cct->_conf->rgw_node_qps_limit > 0) {
    create_node_qps_throttle(_cct->_conf->rgw_node_qps_limit);
  }

  Mutex::Locker timer_locker(*_timer_lock);
  schedule_get_rgw_nums();
}

void ThrottleManager::create_node_bandwidth_throttle(uint64_t limit) {
  _node_bandwidth_throttle = make_shared<TokenBucketThrottle>(_cct, 1.1*limit,
      limit, _timer, _timer_lock);
}

void ThrottleManager::create_node_qps_throttle(uint64_t limit) {
  _node_qps_throttle = make_shared<TokenBucketThrottle>(_cct, 1.1*limit,
      limit, _timer, _timer_lock);
}

shared_ptr<TokenBucketThrottle> ThrottleManager::get_node_bandwidth_throttle() {
  return _node_bandwidth_throttle;
}

shared_ptr<TokenBucketThrottle> ThrottleManager::get_node_qps_throttle() {
  return _node_qps_throttle;
}

int ThrottleManager::check_qps_limit(req_state* const s) {
  if (s->bucket_name.empty() || s->system_request ||
      s->auth.identity->is_admin_of(s->user->user_id) ||
      s->object.empty()) {
    ldout(s->cct, 15) << "system operation or admin operation do not limit" << dendl;
    return 0;
  }

  // check node qps limit
  if (_node_qps_throttle) {
    bool r = _node_qps_throttle->get(1);
    if (!r) {
      ldout(s->cct, 15) << "request over node qps limit" << dendl;
      return -ERR_QPS_EXCEEDED;
    }
  }

  // check bucket qps limit
  shared_ptr<TokenBucketThrottle> user_qps_throttle = get_user_qps_throttle(s);
  if (user_qps_throttle) {
    bool r = user_qps_throttle->get(1);
    if (!r) {
      ldout(s->cct, 15) << "request over user qps limit" << dendl;
      return -ERR_QPS_EXCEEDED;
    }
  }

  // check bucket qps limit
  shared_ptr<TokenBucketThrottle> bucket_qps_throttle = get_bucket_qps_throttle(s);
  if (bucket_qps_throttle) {
    bool r = bucket_qps_throttle->get(1);
    if (!r) {
      ldout(s->cct, 15) << "request over bucket qps limit" << dendl;
      return -ERR_QPS_EXCEEDED;
    }
  }

  return 0;
}

shared_ptr<TokenBucketThrottle> ThrottleManager::get_bucket_bandwidth_throttle(req_state* const s) {
  if (s->bucket_name.empty() || s->system_request ||
      s->auth.identity->is_admin_of(s->user->user_id) ||
      s->object.empty()) {
    ldout(s->cct, 15) << "system operation or admin operation do not limit" << dendl;
    return nullptr;
  }
  int64_t bandwidth_limit = -1;
  auto aiter = s->bucket_attrs.find(RGW_ATTR_BANDWIDTH_LIMIT);
  if (aiter != s->bucket_attrs.end()) {
    bufferlist::iterator liter = aiter->second.begin();
    decode(bandwidth_limit, liter);
  }

  ldout(_cct, 20) << "bucket name " << s->bucket_name
                  << " bandwidth_limit: " << bandwidth_limit << dendl;
  if (bandwidth_limit <= 0) {
    return nullptr;
  }

  uint64_t new_limit = static_cast<uint64_t>((bandwidth_limit + _rgw_nums - 1) / _rgw_nums);
  {
    RWLock::RLocker rl(_bucket_bandwidth_lock);
    auto iter = _bucket_bandwidth_throttle_map.find(s->bucket_name);
    if (iter != _bucket_bandwidth_throttle_map.end()) {
      if (iter->second->get_avg() != new_limit) {
        ldout(_cct, 15) << "need to reset the limit, "
                        << "old limit is:  " << iter->second->get_avg()
                        << " new limit is: " << new_limit << dendl;
        // each rgw has the request approximately, 1.1 for the burst
        iter->second->set_limit(new_limit, 1.1*new_limit);
      }
      return iter->second;
    }
  }

  return create_bucket_bandwidth_throttle(s->bucket_name, new_limit);
}

shared_ptr<TokenBucketThrottle> ThrottleManager::get_user_bandwidth_throttle(req_state* const s) {
  // remove s->system_request to support synchronization-user in multisite
  if (s->bucket_name.empty() ||
      s->auth.identity->is_admin_of(s->user->user_id) ||
      s->object.empty()) {
    ldout(s->cct, 15) << "system operation or admin operation do not limit" << dendl;
    return nullptr;
  }

  ldout(_cct, 20) << "user name " << s->user->user_id << " bandwidth_limit: " << s->user->bandwidth << dendl;
  if (s->user->bandwidth <= 0) {
    return nullptr;
  }

  uint64_t new_limit = static_cast<uint64_t>((s->user->bandwidth + _rgw_nums - 1) / _rgw_nums);
  {
    RWLock::RLocker rl(_user_bandwidth_lock);
    auto iter = _user_bandwidth_throttle_map.find(s->user->user_id.to_str());
    if (iter != _user_bandwidth_throttle_map.end()) {
      if (iter->second->get_avg() != new_limit) {
        ldout(_cct, 15) << "need to reset the limit, "
                        << "old limit is:  " << iter->second->get_avg()
                        << " new limit is: " << new_limit << dendl;
        // each rgw has the request approximately, 1.1 for the burst
        iter->second->set_limit(new_limit, 1.1*new_limit);
      }
      return iter->second;
    }
  }

  return create_user_bandwidth_throttle(s->user->user_id.to_str(), new_limit);
}

shared_ptr<TokenBucketThrottle> ThrottleManager::create_user_bandwidth_throttle(
    const string& uid, uint64_t limit) {
  RWLock::WLocker wl(_user_bandwidth_lock);
  auto iter = _user_bandwidth_throttle_map.find(uid);
  if (iter != _user_bandwidth_throttle_map.end()) {
    return iter->second;
  }

  shared_ptr<TokenBucketThrottle> throttle =
      make_shared<TokenBucketThrottle>(_cct, 1.1*limit, limit, _timer, _timer_lock);

  auto ret = _user_bandwidth_throttle_map.emplace(uid, throttle);
  ldout(_cct, 20) << "create_user_bandwidth_throttle is: " << ret.second << dendl;
  return ret.first->second;
}

shared_ptr<TokenBucketThrottle> ThrottleManager::get_user_qps_throttle(req_state* const s) {
  // remove s->system_request to support synchronization-user in multisite
  if (s->bucket_name.empty() ||
      s->auth.identity->is_admin_of(s->user->user_id) ||
      s->object.empty()) {
    ldout(s->cct, 15) << "do not limit admin operation or no specific object" << dendl;
    return nullptr;
  }

  ldout(_cct, 20) << "user name " << s->user->user_id << " qps_limit: " << s->user->qps << dendl;
  if (s->user->qps <= 0) {
    return nullptr;
  }

  uint64_t new_limit = static_cast<uint64_t>((s->user->qps + _rgw_nums -1) / _rgw_nums);
  {
    RWLock::RLocker rl(_user_qps_lock);
    auto iter = _user_qps_throttle_map.find(s->user->user_id.to_str());
    if (iter != _user_qps_throttle_map.end()) {
      if (iter->second->get_avg() != new_limit) {
        ldout(_cct, 15) << "need to reset the limit, "
                        << "old limit is:  " << iter->second->get_avg()
                        << " new limit is: " << new_limit << dendl;
        // each rgw has the request approximately, 1.1 for the burst
        iter->second->set_limit(new_limit, 1.1*new_limit);
      }
      return iter->second;
    }
  }

  return create_user_qps_throttle(s->user->user_id.to_str(), new_limit);
}

shared_ptr<TokenBucketThrottle> ThrottleManager::create_user_qps_throttle(
    const string& uid, uint64_t limit) {
  RWLock::WLocker wl(_user_qps_lock);
  auto iter = _user_qps_throttle_map.find(uid);
  if (iter != _user_qps_throttle_map.end()) {
    return iter->second;
  }

  shared_ptr<TokenBucketThrottle> throttle =
      make_shared<TokenBucketThrottle>(_cct, 1.1*limit, limit, _timer, _timer_lock);

  auto ret = _user_qps_throttle_map.emplace(uid, throttle);
  ldout(_cct, 20) << "create_user_qps_throttle is: " << ret.second << dendl;
  return ret.first->second;
}

shared_ptr<TokenBucketThrottle> ThrottleManager::get_bucket_qps_throttle(req_state* const s) {
  if (s->bucket_name.empty() || s->system_request ||
      s->auth.identity->is_admin_of(s->user->user_id) ||
      s->object.empty()) {
    ldout(s->cct, 15) << "do not limit system/admin operation or no specific object" << dendl;
    return nullptr;
  }
  int64_t qps_limit = -1;
  auto aiter = s->bucket_attrs.find(RGW_ATTR_QPS_LIMIT);
  if (aiter != s->bucket_attrs.end()) {
    bufferlist::iterator liter = aiter->second.begin();
    decode(qps_limit, liter);
  }

  ldout(_cct, 20) << "bucket name " << s->bucket_name << " qps_limit: " << qps_limit << dendl;
  if (qps_limit <= 0) {
    return nullptr;
  }
  uint64_t new_limit = static_cast<uint64_t>((qps_limit + _rgw_nums -1) / _rgw_nums);
  {
    RWLock::RLocker rl(_bucket_qps_lock);
    auto iter = _bucket_qps_throttle_map.find(s->bucket_name);
    if (iter != _bucket_qps_throttle_map.end()) {
      if (iter->second->get_avg() != new_limit) {
        ldout(_cct, 15) << "need to reset the limit, "
                        << "old limit is:  " << iter->second->get_avg()
                        << " new limit is: " << new_limit << dendl;
        // each rgw has the request approximately, 1.1 for the burst
        iter->second->set_limit(new_limit, 1.1*new_limit);
      }
      return iter->second;
    }
  }

  return create_bucket_qps_throttle(s->bucket_name, new_limit);
}

shared_ptr<TokenBucketThrottle> ThrottleManager::create_bucket_bandwidth_throttle(
    const string& bucket_name, uint64_t limit) {
  RWLock::WLocker wl(_bucket_bandwidth_lock);
  auto iter = _bucket_bandwidth_throttle_map.find(bucket_name);
  if (iter != _bucket_bandwidth_throttle_map.end()) {
    return iter->second;
  }

  shared_ptr<TokenBucketThrottle> throttle =
      make_shared<TokenBucketThrottle>(_cct, 1.1*limit, limit, _timer, _timer_lock);

  auto ret = _bucket_bandwidth_throttle_map.emplace(bucket_name, throttle);
  ldout(_cct, 20) << "create_bucket_bandwidth_throttle is: " << ret.second << dendl;
  return ret.first->second;
}

shared_ptr<TokenBucketThrottle> ThrottleManager::create_bucket_qps_throttle(
    const string& bucket_name, uint64_t limit) {
  RWLock::WLocker wl(_bucket_qps_lock);
  auto iter = _bucket_qps_throttle_map.find(bucket_name);
  if (iter != _bucket_qps_throttle_map.end()) {
    return iter->second;
  }

  shared_ptr<TokenBucketThrottle> throttle =
      make_shared<TokenBucketThrottle>(_cct, 1.1*limit, limit, _timer, _timer_lock);

  auto ret = _bucket_qps_throttle_map.emplace(bucket_name, throttle);
  ldout(_cct, 20) << "create_bucket_qps_throttle is: " << ret.second << dendl;
  return ret.first->second;
}

void assign_admin_self_to_rgws() {
  rgw_client.lock.get_write();
  rgw_client.rgw_client_id = RGW_ADMIN_CLIENT_ID;
  rgw_client.rgws.insert(rgw_client.rgw_client_id);
  rgw_client.update_time = mono_clock::now();
  rgw_client.lock.unlock();
}

int ThrottleManager::get_rgw_nums() {
  Mutex::Locker l(get_num_lock);
  _rgw_nums = 1;
  if (!_rados) {
    // admin process, assign itself in rgw_client.rgws to work with check_renaming_state()
    assign_admin_self_to_rgws();
    return 0;
  }
  librados::Rados* handle = _rados->get_rados_handle();
  bufferlist inbl;
  bufferlist outbl;
  if (!handle) {
    return 0;
  }

  int ret = handle->mon_command("{\"prefix\": \"status\" ,\"format\": \"json\"}", inbl, &outbl, NULL);
  if (ret < 0) {
    _rgw_nums = 1;
    return -EAGAIN;
  }

  JSONParser parser;
  ret = parser.parse(outbl.c_str(), outbl.length());
  if (ret < 0) {
    _rgw_nums = 1;
    return -EINVAL;
  }
  JSONObjIter iter;
  JSONObj* obj = nullptr;

  do {
    iter = parser.find_first("servicemap");
    if (iter.end()) {
      break;
    }

    obj = *iter;
    iter = obj->find_first("services");
    if (iter.end()) {
      break;
    }

    obj = *iter;
    iter = obj->find_first("rgw");
    if (iter.end()) {
      break;
    }

    obj = *iter;
    iter = obj->find_first("daemons");
    if (iter.end()) {
      break;
    }

    string name = _cct->_conf->name.get_id();
    if (name.compare(0, 4, "rgw.") == 0) {
      name = name.substr(4);
    }

    ldout(_cct, 20) << __func__ << "() get_rgw_nums:" << obj->get_data() <<  dendl;
    obj = *iter;
    iter = obj->find_first();
    rgw_client.lock.get_write();
    rgw_client.rgws.clear();
    for (; !iter.end(); ++iter) {
      if ((*iter)->get_name() == "summary") {
        continue;
      }
      JSONObj* o = *iter;
      JSONObjIter i = o->find_first("start_epoch");
      if ((*iter)->get_name() == name) {
        string actual_client_id = name + RGW_CLIENT_ID_SEPARATOR + (*i)->get_data();
        if (rgw_client.rgw_client_id.empty()) {
          ldout(_cct, 0) << __func__ << "() INFO: update rgw client id:"
                         << actual_client_id << dendl;
          rgw_client.rgw_client_id = actual_client_id;
        } else if (rgw_client.rgw_client_id.compare(actual_client_id) != 0){
          ldout(_cct, 0) << __func__ << "() ERROR: rgw client id has changed, self:"
            << rgw_client.rgw_client_id << " actual in mon record:" << actual_client_id
            << dendl;
          rgw_client.rgw_client_id = actual_client_id;
        }
      }
      _rgw_nums++;
      rgw_client.rgws.insert((*iter)->get_name() + RGW_CLIENT_ID_SEPARATOR + (*i)->get_data());
      rgw_client.update_time = mono_clock::now();
    }
    rgw_client.lock.unlock();
  } while (0);

  if (_rgw_nums > 1) {
    _rgw_nums -= 1;
  }
  ldout(_cct, 20) << "rgw num " << _rgw_nums <<  dendl;
  return 0;
}

void ThrottleManager::schedule_get_rgw_nums() {
  get_rgw_nums();

  _token_manager_ctx = new FunctionContext(
      [this](int r) {
        schedule_get_rgw_nums();
      });

  // get rgw nums every two minutes
  _timer->add_event_after(UPDATE_RGWS_INTERVAL, _token_manager_ctx);
}

void ThrottleManager::shutdown() {
  if (_timer) {
    assert(_timer_lock != nullptr);
    Mutex::Locker l(*_timer_lock);
    _timer->shutdown();
    delete _timer;
    _timer = nullptr;
  }
}

ThrottleManager::~ThrottleManager() {
  if (_timer) {
      shutdown();
  }
  if (_timer_lock) {
    delete _timer_lock;
  }
};
