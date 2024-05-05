// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include <string.h>
#include <iostream>
#include <map>
#include <algorithm>
#include <tuple>
#include <functional>

#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/variant.hpp>

#include "include/scope_guard.h"
#include "common/Formatter.h"
#include "common/containers.h"
#include <common/errno.h>
#include "include/random.h"
#include "cls/rgw/cls_rgw_client.h"
#include "cls/lock/cls_lock_client.h"
#include "rgw_common.h"
#include "rgw_bucket.h"
#include "rgw_rados.h"
#include "rgw_lc.h"

#define dout_context g_ceph_context
#define dout_subsys ceph_subsys_rgw

#define ONE_DAY 86400

const char* LC_STATUS[] = {
      "UNINITIAL",
      "PROCESSING",
      "FAILED",
      "COMPLETE"
};

using namespace librados;

bool LCRule::valid() const
{
  if (id.length() > MAX_ID_LEN) {
    return false;
  }
  else if(expiration.empty() && noncur_expiration.empty() &&
          mp_expiration.empty() && !dm_expiration &&
          transitions.empty() && noncur_transitions.empty()) {
    return false;
  }
  else if (!expiration.valid() || !noncur_expiration.valid() || !mp_expiration.valid()) {
    return false;
  }
  if (!transitions.empty()) {
    for (const auto& elem : transitions) {
      if (!elem.second.valid()) {
        return false;
      }
    }
  }
  for (const auto& elem : noncur_transitions) {
    if (!elem.second.valid()) {
      return false;
    }
  }

  return true;
}

void LCRule::init_simple_days_rule(std::string_view _id, std::string_view _prefix, int num_days)
{
  id = _id;
  prefix = _prefix;
  char buf[32];
  snprintf(buf, sizeof(buf), "%d", num_days);
  expiration.set_days(buf);
  set_enabled(true);
}

void RGWLifecycleConfiguration::add_rule(const LCRule& rule)
{
  auto& id = rule.get_id(); // note that this will return false for groups, but that's ok, we won't search groups
  rule_map.insert(pair<string, LCRule>(id, rule));
}

bool RGWLifecycleConfiguration::_add_rule(const LCRule& rule)
{
  lc_op op(rule.get_id());
  op.status = rule.is_enabled();
  if (rule.get_expiration().has_days()) {
    op.expiration = rule.get_expiration().get_days();
  }
  if (rule.get_expiration().has_date()) {
    op.expiration_date = ceph::from_iso_8601(rule.get_expiration().get_date());
  }
  if (rule.get_noncur_expiration().has_days()) {
    op.noncur_expiration = rule.get_noncur_expiration().get_days();
  }
  if (rule.get_mp_expiration().has_days()) {
    op.mp_expiration = rule.get_mp_expiration().get_days();
  }
  op.dm_expiration = rule.get_dm_expiration();
  for (const auto &elem : rule.get_transitions()) {
    transition_action action;
    if (elem.second.has_days()) {
      action.days = elem.second.get_days();
    } else {
      action.date = ceph::from_iso_8601(elem.second.get_date());
    }
    action.storage_class = rgw_placement_rule::get_canonical_storage_class(elem.first);
    op.transitions.emplace(elem.first, std::move(action));
  }
  for (const auto &elem : rule.get_noncur_transitions()) {
    transition_action action;
    action.days = elem.second.get_days();
    action.date = ceph::from_iso_8601(elem.second.get_date());
    action.storage_class = elem.first;
    op.noncur_transitions.emplace(elem.first, std::move(action));
  }
  std::string prefix;
  if (rule.get_filter().has_prefix()){
    prefix = rule.get_filter().get_prefix();
  } else {
    prefix = rule.get_prefix();
  }

  if (rule.get_filter().has_tags()){
    op.obj_tags = rule.get_filter().get_tags();
  }
  if (rule.get_filter().has_suffix()){
    op.suffix = rule.get_filter().get_suffix();
  }
  prefix_map.emplace(std::move(prefix), std::move(op));
  return true;
}

int RGWLifecycleConfiguration::check_and_add_rule(const LCRule& rule)
{
  if (!rule.valid()) {
    return -EINVAL;
  }
  auto& id = rule.get_id();
  if (rule_map.find(id) != rule_map.end()) {  //id shouldn't be the same 
    return -EINVAL;
  }
  rule_map.insert(pair<string, LCRule>(id, rule));

  if (!_add_rule(rule)) {
    return -ERR_INVALID_REQUEST;
  }
  return 0;
}

bool RGWLifecycleConfiguration::has_overlap_suffix(const lc_op& first, const lc_op& second) {
  if (boost::algorithm::ends_with(first.suffix, second.suffix)) {
    return true;
  }
  return false;
}

bool RGWLifecycleConfiguration::has_same_action(const lc_op& first, const lc_op& second) {
  if ((first.expiration > 0 || first.expiration_date != boost::none) && 
    (second.expiration > 0 || second.expiration_date != boost::none)) {
    return true;
  } else if (first.noncur_expiration > 0 && second.noncur_expiration > 0) {
    return true;
  } else if (first.mp_expiration > 0 && second.mp_expiration > 0) {
    return true;
  } else if (!first.transitions.empty() && !second.transitions.empty()) {
    for (auto &elem : first.transitions) {
      if (second.transitions.find(elem.first) != second.transitions.end()) {
        return true;
      }
    }
  } else if (!first.noncur_transitions.empty() && !second.noncur_transitions.empty()) {
    for (auto &elem : first.noncur_transitions) {
      if (second.noncur_transitions.find(elem.first) != second.noncur_transitions.end()) {
        return true;
      }
    }
  }
  return false;
}

//Rules are conflicted: if one rule's prefix starts with other rule's prefix, and these two rules
//define same action.
//[TODO] prefix, suffix and tags are overlap, return false when its action is same. Now, this function is not called in anywhere.
bool RGWLifecycleConfiguration::valid()
{
  if (prefix_map.size() < 2) {
    return true;
  }
  auto cur_iter = prefix_map.begin();
  while (cur_iter != prefix_map.end()) {
    auto next_iter = cur_iter;
    ++next_iter;
    while (next_iter != prefix_map.end()) {
      string c_pre = cur_iter->first;
      string n_pre = next_iter->first;
      if (n_pre.compare(0, c_pre.length(), c_pre) == 0) {
        if (has_overlap_suffix(cur_iter->second, next_iter->second) &&
            has_same_action(cur_iter->second, next_iter->second)) {
          return false;
        } else {
          ++next_iter;
        }
      } else {
        break;
      }
    }
    ++cur_iter;
  }
  return true;
}

void *RGWLC::LCWorker::entry() {
  do {
    utime_t start = ceph_clock_now();
    if (should_work(start)) {
      ldout(cct, 2) << "life cycle: start" << dendl;
      int r = lc->process(this, false /* once */);
      if (r < 0) {
        ldout(cct, 0) << "ERROR: do life cycle process() returned error r=" << r << dendl;
      }
      ldout(cct, 2) << "life cycle: stop" << dendl;
    }
    if (lc->going_down())
      break;

    utime_t end = ceph_clock_now();
    int secs = schedule_next_start_time(start, end);
    utime_t next;
    next.set_from_double(end + secs);

    ldout(cct, 5) << "schedule life cycle next start time: " << rgw_to_asctime(next) << dendl;

    lock.Lock();
    cond.WaitInterval(lock, utime_t(secs, 0));
    lock.Unlock();
  } while (!lc->going_down());

  return NULL;
}

void RGWLC::initialize(CephContext *_cct, RGWRados *_store) {
  cct = _cct;
  store = _store;
  max_objs = cct->_conf->rgw_lc_max_objs;
  if (max_objs > HASH_PRIME)
    max_objs = HASH_PRIME;

  obj_names = new string[max_objs];

  for (int i = 0; i < max_objs; i++) {
    obj_names[i] = lc_oid_prefix;
    char buf[32];
    snprintf(buf, 32, ".%d", i);
    obj_names[i].append(buf);
  }

#define COOKIE_LEN 16
  char cookie_buf[COOKIE_LEN + 1];
  gen_rand_alphanumeric(cct, cookie_buf, sizeof(cookie_buf) - 1);
  cookie = cookie_buf;
}

void RGWLC::finalize()
{
  delete[] obj_names;
}

bool RGWLC::if_already_run_today(time_t& start_date)
{
  struct tm bdt;
  time_t begin_of_day;
  utime_t now = ceph_clock_now();
  localtime_r(&start_date, &bdt);

  if (cct->_conf->rgw_lc_debug_interval > 0) {
    if (now - start_date < cct->_conf->rgw_lc_debug_interval)
      return true;
    else
      return false;
  }

  bdt.tm_hour = 0;
  bdt.tm_min = 0;
  bdt.tm_sec = 0;
  begin_of_day = mktime(&bdt);
  if (now - begin_of_day < ONE_DAY)
    return true;
  else
    return false;
}

static inline std::ostream& operator<<(std::ostream &os, cls_rgw_lc_entry& ent) {
  os << "<ent: bucket=";
  os << ent.bucket;
  os << "; start_time=";
  os << rgw_to_asctime(utime_t(time_t(ent.start_time), 0));
  os << "; status=";
  os << ent.status;
  os << "; shard_id:";
  os << ent.shard_id;
    os << ">";
    return os;
}

/**
 * [RGWLC::reshard_bucket_lc_entry description]
 * @param  bucket_name
 * @return 0 if success
 */
int RGWLC::reshard_bucket_lc_entry(const string& bucket_name) {
  RGWObjectCtx obj_ctx(store);
  RGWBucketInfo bucket_info;

  int ret = store->get_bucket_info(obj_ctx, "", bucket_name, bucket_info, NULL, NULL);
  if (ret < 0) {
    ldout(cct, 0) << __func__ << "(): ERROR get_bucket_info for " << bucket_name
                  << " ret:" << ret
                  << dendl;
    return ret;
  }
  ret = set_lc_entries(bucket_info.bucket, 0, bucket_info.num_shards);
  if (ret != 0) {
    ldout(cct, 0) << __func__ << "(): ERROR set_lc_entries err"
                              << ", bucket:" << bucket_name
                              << ", ret:" << ret
                              << dendl;
    return ret;
  }
  // remove old version lc entry
  ret = remove_lc_entries(bucket_info.bucket, -1, 0);
  if (ret != 0) {
    ldout(cct, 0) << __func__ << "(): ERROR remove_lc_entries err"
                                << ", bucket:" << bucket_name
                                << ", ret:" << ret
                                << dendl;
    return ret;
  }
  return 0;
}

int RGWLC::bucket_lc_prepare(int index, LCWorker* worker)
{
  vector<cls_rgw_lc_entry> entries;

  string marker;

  ldout(cct, 5) << "RGWLC::bucket_lc_prepare(): PREPARE "
    << "index: " << index << " worker ix: " << worker->ix
    << dendl;

#define MAX_LC_LIST_ENTRIES 100
  do {
    int ret = cls_rgw_lc_list(store->lc_pool_ctx, obj_names[index], marker, MAX_LC_LIST_ENTRIES, entries);
    if (ret < 0) {
      ldout(cct, 0) << "ERROR RGWLC::bucket_lc_prepare() list lc entry failed on "
                    << obj_names[index] << ", ret:" << ret << dendl;
      return ret;
    }
    for (auto& entry : entries) {
      entry.start_time = ceph_clock_now();
      entry.status = lc_uninitial;
      ldout(cct, 30) << __func__ << "() update lc entry " << entry << dendl;
      ret = cls_rgw_lc_set_entry(store->lc_pool_ctx, obj_names[index], entry);
      if (ret < 0) {
        ldout(cct, 0) << __func__ << "(): ERROR failed to set entry on "
                      << obj_names[index] << dendl;
        return ret;
      }
    }

    if (!entries.empty()) {
      marker = std::move(entries.back().bucket);
    }
  } while (!entries.empty());

  return 0;
}

static bool obj_has_expired(CephContext *cct, ceph::real_time mtime, int days,
                            ceph::real_time *expire_time = nullptr)
{
  double timediff, cmp;
  utime_t base_time;
  if (cct->_conf->rgw_lc_debug_interval <= 0) {
    /* Normal case, run properly */
    cmp = double(days)*ONE_DAY;
    base_time = ceph_clock_now().round_to_day();
  } else {
    /* We're in debug mode; Treat each rgw_lc_debug_interval seconds as a day */
    cmp = double(days)*cct->_conf->rgw_lc_debug_interval;
    base_time = ceph_clock_now();
  }
  timediff = base_time - ceph::real_clock::to_time_t(mtime);

  if (expire_time) {
    *expire_time = mtime + make_timespan(cmp);
  }

  ldout(cct, 20) << __func__ << "(): mtime=" << mtime << " days=" << days
                 << " base_time=" << base_time << " timediff=" << timediff
                 << " cmp=" << cmp
                 << " is_expired=" << (timediff >= cmp)
                 << dendl;
  return (timediff >= cmp);
}

static bool pass_bos_object_lock_check(RGWRados *store, RGWBucketInfo& bucket_info,
                                       rgw_obj& obj, ceph::real_time& mtime, RGWObjectCtx& ctx)
{
  auto bos_lock_status = bucket_info.bos_obj_lock.get_lock_status(nullptr);
  if (bos_lock_status == BOS_OBJECT_LOCK_STATUS_IN_PROGRESS ||
      bos_lock_status == BOS_OBJECT_LOCK_STATUS_LOCKED) {

    int ret = bucket_info.bos_obj_lock.verify_bos_obj_lock(store->ctx()->_conf->rgw_bos_worm_expiration_time, mtime);
    if (ret < 0) {
      ldout(store->ctx(), 10) << __func__ << "() INFO: bos object locked now, obj: " << obj << dendl;
      return false;
    }
  }

  return true;
}

static bool pass_object_lock_check(RGWRados *store, RGWBucketInfo& bucket_info, rgw_obj& obj, RGWObjectCtx& ctx)
{
  if (!bucket_info.obj_lock_enabled()) {
    return true;
  }
  RGWRados::Object op_target(store, bucket_info, ctx, obj);
  RGWRados::Object::Read read_op(&op_target);
  map<string, bufferlist> attrs;
  read_op.params.attrs = &attrs;

  int ret = read_op.prepare();
  if (ret < 0) {
    if (ret == -ENOENT) {
      ldout(store->ctx(), 10) << __func__ << "(): obj not exist:" << obj << dendl;
      return true;
    } else {
      ldout(store->ctx(), 0) << __func__ << "(): ERROR failed to read obj:" << obj << dendl;
      return false;
    }
  }

  auto iter = attrs.find(RGW_ATTR_OBJECT_RETENTION);
  if (iter != attrs.end()) {
    RGWObjectRetention retention;
    try {
      decode(retention, iter->second);
    } catch (buffer::error& err) {
      ldout(store->ctx(), 0) << "ERROR: failed to decode RGWObjectRetention" << dendl;
      return false;
    }
    if (ceph::real_clock::to_time_t(retention.get_retain_until_date()) > ceph_clock_now()) {
      if (unlikely(store->ctx()->_conf->rgw_worm_debug_interval > 0)) {
        if (!satisfy_worm_debug_time(store->ctx(), *read_op.params.lastmod, retention.get_retain_until_date())) {
          return false;
        }
      } else {
        return false;
      }
    }
  }
  iter = attrs.find(RGW_ATTR_OBJECT_LEGAL_HOLD);
  if (iter != attrs.end()) {
    RGWObjectLegalHold obj_legal_hold;
    try {
      decode(obj_legal_hold, iter->second);
    } catch (buffer::error& err) {
      ldout(store->ctx(), 0) << "ERROR: failed to decode RGWObjectLegalHold" << dendl;
      return false;
    }
    if (obj_legal_hold.is_enabled()) {
      return false;
    }
  }
  return true;
}

static bool is_valid_op(const lc_op& op)
{
      return (op.status &&
              (op.expiration > 0
               || op.expiration_date != boost::none
               || op.noncur_expiration > 0
               || op.dm_expiration
               || !op.transitions.empty()
               || !op.noncur_transitions.empty()));
}


class LCObjsLister {
  RGWRados *store;
  RGWBucketInfo& bucket_info;
  RGWRados::Bucket target;
  RGWRados::Bucket::List list_op;
  bool is_truncated{false};
  rgw_obj_key next_marker;
  string prefix;
  vector<rgw_bucket_dir_entry> objs;
  vector<rgw_bucket_dir_entry>::iterator obj_iter;
  rgw_bucket_dir_entry pre_obj;
  int64_t delay_ms;

public:
  LCObjsLister(RGWRados *_store, RGWBucketInfo& _bucket_info) :
      store(_store), bucket_info(_bucket_info),
      target(store, bucket_info), list_op(&target) {
    list_op.params.list_versions = bucket_info.versioned();
    list_op.params.allow_unordered = true;
    delay_ms = store->ctx()->_conf->rgw_lc_thread_delay;
  }

  void set_prefix(const string& p) {
    prefix = p;
    list_op.params.prefix = prefix;
    list_op.params.marker.set(string{});
  }

  void set_shard_id(int shard_id) {
    target.set_shard_id(shard_id);
  }

  int init() {
    return fetch();
  }

  int fetch() {
    int ret = list_op.list_objects(1000, &objs, NULL, &is_truncated);
    if (ret < 0) {
      return ret;
    }

    obj_iter = objs.begin();

    return 0;
  }

  void delay() {
    std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
  }

  bool get_obj(rgw_bucket_dir_entry **obj,
               std::function<void(void)> fetch_barrier
               = []() { /* nada */}) {
    if (obj_iter == objs.end()) {
      if (!is_truncated) {
        delay();
        return false;
      } else {
        fetch_barrier();
        list_op.params.marker = pre_obj.key;
        int ret = fetch();
        if (ret < 0) {
          ldout(store->ctx(), 0) << "ERROR: list_op returned ret=" << ret << dendl;
          return ret;
        }
      }
      delay();
    }
    /* returning address of entry in objs */
    *obj = &(*obj_iter);
    return obj_iter != objs.end();
  }

  rgw_bucket_dir_entry get_prev_obj() {
    return pre_obj;
  }

  void next() {
    pre_obj = *obj_iter;
    ++obj_iter;
  }

  boost::optional<std::string> next_key_name() {
    if (obj_iter == objs.end() || (obj_iter + 1) == objs.end()) {
      /* this should have been called after get_obj() was called, so this should
       * only happen if is_truncated is false */
      return boost::none;
    }

    return ((obj_iter + 1)->key.name);
  }

  void set_self_shard(bool self) {
    list_op.set_self_shard(self);
  }
}; /* LCObjsLister */


struct op_env {
  using LCWorker = RGWLC::LCWorker;

  lc_op op;

  RGWRados *store;
  LCWorker* worker;

  RGWBucketInfo& bucket_info;
  LCObjsLister& ol;


  op_env(lc_op& _op, RGWRados *_store, LCWorker* _worker,
         RGWBucketInfo& _bucket_info, LCObjsLister& _ol)
    : op(_op), store(_store), worker(_worker), bucket_info(_bucket_info), ol(_ol) {}
}; /* op_env */

class WorkQ;

struct lc_op_ctx {
  CephContext *cct;
  op_env env;
  rgw_bucket_dir_entry o;
  boost::optional<std::string> next_key_name;

  ceph::real_time effective_mtime;

  RGWRados *store;
  RGWBucketInfo& bucket_info;
  lc_op& op;  // ok--refers to expanded env.op
  LCObjsLister& ol;

  rgw_obj obj;
  RGWObjectCtx rctx;
  WorkQ* wq;

  lc_op_ctx(op_env& _env, rgw_bucket_dir_entry& _o,
            boost::optional<std::string> _next_key_name,
            ceph::real_time _effective_mtime, WorkQ* _wq)
    : cct(_env.store->ctx()), env(_env), o(_o), next_key_name(_next_key_name),
      effective_mtime(_effective_mtime),
      store(env.store), bucket_info(env.bucket_info), op(env.op), ol(env.ol),
      obj(env.bucket_info.bucket, o.key), rctx(env.store), wq(_wq)
    {}

  bool next_has_same_name(const std::string& key_name) {
    return (next_key_name && key_name.compare(
        boost::get<std::string>(next_key_name)) == 0);
  }

}; /* lc_op_ctx */

static int remove_expired_obj(lc_op_ctx& oc, bool remove_indeed)
{
  auto& store = oc.store;
  auto& bucket_info = oc.bucket_info;
  auto& o = oc.o;
  auto obj_key = o.key;
  auto& meta = o.meta;
  int ret = 0;

  if (!remove_indeed) {
    obj_key.instance.clear();
  } else if (obj_key.instance.empty()) {
    obj_key.instance = "null";
  }

  rgw_obj obj(bucket_info.bucket, obj_key);
  ACLOwner obj_owner;
  obj_owner.set_id(rgw_user {meta.owner});
  obj_owner.set_name(meta.owner_display_name);

  if (!bucket_info.trash_dir.empty() && obj.key.name.find(bucket_info.trash_dir) != 0) {
    if (obj.key.instance == "null") {
      obj.key.instance.clear();
    }
    auto dst_object = rgw_obj_key(bucket_info.trash_dir + obj.key.name);
    rgw_obj dst_obj(bucket_info.bucket, dst_object);
    oc.rctx.obj.set_atomic(dst_obj);
    store->set_prefetch_data(&oc.rctx, obj);

    ret = store->rename_obj(oc.rctx, obj, dst_obj, bucket_info);
    dout(0) << "NOTICE: trash obj " << obj << " ret=" << ret << dendl;
    return ret;
  }

  RGWRados::Object del_target(store, bucket_info, oc.rctx, obj);
  RGWRados::Object::Delete del_op(&del_target);

  del_op.params.bucket_owner = bucket_info.owner;
  del_op.params.versioning_status = bucket_info.versioning_status();
  del_op.params.obj_owner = obj_owner;
  del_op.params.unmod_since = meta.mtime;

  ret = del_op.delete_obj();
  dout(0) << "NOTICE: delete obj " << obj << " ret=" << ret << dendl;
  return ret;
} /* remove_expired_obj */

class LCOpAction {
public:
  virtual ~LCOpAction() {}

  virtual bool check(lc_op_ctx& oc, ceph::real_time *exp_time) {
    return false;
  }

  virtual int process(lc_op_ctx& oc) {
    return 0;
  }

  friend class LCOpRule;
}; /* LCOpAction */

class LCOpFilter {
public:
virtual ~LCOpFilter() {}
  virtual bool check(lc_op_ctx& oc) {
    return false;
  }
}; /* LCOpFilter */

class LCOpRule {
  friend class LCOpAction;

  op_env env;
  boost::optional<std::string> next_key_name;
  ceph::real_time effective_mtime;

  std::vector<shared_ptr<LCOpFilter> > filters; // n.b., sharing ovhd
  std::vector<shared_ptr<LCOpAction> > actions;

public:
  LCOpRule(op_env& _env) : env(_env) {}

  boost::optional<std::string> get_next_key_name() {
    return next_key_name;
  }

  void build();
  void update();
  int process(rgw_bucket_dir_entry& o, WorkQ* wq);
}; /* LCOpRule */

using WorkItem =
  boost::variant<void*,
     /* out-of-line delete */
     std::tuple<LCOpRule, rgw_bucket_dir_entry>,
     /* uncompleted MPU expiration */
     std::tuple<lc_op, rgw_bucket_dir_entry>,
     rgw_bucket_dir_entry>;

class WorkQ : public Thread
{
public:
  using unique_lock = std::unique_lock<std::mutex>;
  using work_f = std::function<void(RGWLC::LCWorker*, WorkQ*, WorkItem&)>;
  using dequeue_result = boost::variant<void*, WorkItem>;

  static constexpr uint32_t FLAG_NONE =        0x0000;
  static constexpr uint32_t FLAG_EWAIT_SYNC =  0x0001;
  static constexpr uint32_t FLAG_DWAIT_SYNC =  0x0002;
  static constexpr uint32_t FLAG_EDRAIN_SYNC = 0x0004;

private:
  const work_f bsf = [](RGWLC::LCWorker* wk, WorkQ* wq, WorkItem& wi) {}; // just for init f
  RGWLC::LCWorker* wk;
  uint32_t qmax;      // max size of vector<> items
  int ix;
  std::mutex mtx;
  std::condition_variable cv;
  uint32_t flags;
  vector<WorkItem> items;
  work_f f;

public:
  WorkQ(RGWLC::LCWorker* wk, uint32_t ix, uint32_t qmax)
    : wk(wk), qmax(qmax), ix(ix), flags(FLAG_NONE), f(bsf)
    {
      create(thr_name().c_str());
      ldout(wk->cct, 10) << "WorkQ create, LCWorker ix:"<< wk->ix
                        << ", qmax:"<< qmax
                        << ", ix:"<< ix << dendl;
    }

  std::string thr_name() {
    return std::string{"wp_thrd: "}
    + std::to_string(wk->ix) + ", " + std::to_string(ix);
  }

  void setf(work_f _f) {
    f = _f;
  }

  void enqueue(WorkItem&& item) {
    unique_lock uniq(mtx);
    while ((!wk->get_lc()->going_down()) &&
     (items.size() > qmax)) {       // items full, set flags -> FLAG_EWAIT_SYNC
      flags |= FLAG_EWAIT_SYNC;
      cv.wait_for(uniq, 200ms);
    }
    items.push_back(item);
    if (flags & FLAG_DWAIT_SYNC) {
      // push items success, if flags with FLAG_DWAIT_SYNC, clear it and notify
      flags &= ~FLAG_DWAIT_SYNC;
      cv.notify_one();
    }
  }

  void drain() {
    unique_lock uniq(mtx);
    flags |= FLAG_EDRAIN_SYNC;
    while (flags & FLAG_EDRAIN_SYNC) {
      cv.wait_for(uniq, 200ms);
    }
  }

private:
  dequeue_result dequeue() {
    unique_lock uniq(mtx);
    while ((!wk->get_lc()->going_down()) &&
     (items.size() == 0)) {
      /* clear drain state, as we are NOT doing work and qlen==0 */
      if (flags & FLAG_EDRAIN_SYNC) {
        flags &= ~FLAG_EDRAIN_SYNC;
      }
      // wait to pull from items, set flags -> FLAG_DWAIT_SYNC
      flags |= FLAG_DWAIT_SYNC;
      cv.wait_for(uniq, 200ms);
    }
    if (items.size() > 0) {
      auto item = items.back();
      items.pop_back();
      if (flags & FLAG_EWAIT_SYNC) {
        // pulled one, if flags with FLAG_EWAIT_SYNC, clear it and notify.
        // Thus enqueue can push another item
        flags &= ~FLAG_EWAIT_SYNC;
        cv.notify_one();
      }
      return {item};
    }
    return nullptr;
  }

  void* entry() override {
    while (!wk->get_lc()->going_down()) {
      auto item = dequeue();
      if (item.which() == 0) {
        /* going down */
        break;
      }
      f(wk, this, boost::get<WorkItem>(item));
    }
    return nullptr;
  }
}; /* WorkQ */

class RGWLC::WorkPool
{
  // 3: just init the size, actual size: n_threads
  using TVector = ceph::containers::tiny_vector<WorkQ, 3>;
  TVector wqs;
  uint64_t ix;

public:
  WorkPool(RGWLC::LCWorker* wk, uint16_t n_threads, uint32_t qmax)
    : wqs(TVector{
            n_threads,
            [&](const size_t ix, auto emplacer) {
              emplacer.emplace(wk, ix, qmax);
            }
          }),
      ix(0)
    {}

  ~WorkPool() {
    for (auto& wq : wqs) {
      wq.join();
    }
  }

  void setf(WorkQ::work_f _f) {
    for (auto& wq : wqs) {
      wq.setf(_f);
    }
  }

  void enqueue(WorkItem item) {
    const auto tix = ix;
    ix = (ix+1) % wqs.size();
    (wqs[tix]).enqueue(std::move(item));
  }

  void drain() {
    for (auto& wq : wqs) {
      wq.drain();
    }
  }
}; /* WorkPool */

RGWLC::LCWorker::LCWorker(const DoutPrefixProvider* dpp, CephContext *cct,
                          RGWLC *lc, int ix)
  : dpp(dpp), cct(cct), lc(lc), ix(ix), lock("LCWorker")
{
  auto wpw = cct->_conf->rgw_lc_max_wp_worker;
  workpool = new WorkPool(this, wpw, 512);
}

static inline bool worker_should_stop(time_t stop_at, bool once)
{
  return !once && stop_at < time(nullptr);
}

int RGWLC::handle_multipart_expiration(RGWRados::Bucket *target, const multimap<string, lc_op>& prefix_map,
                                       LCWorker* worker, time_t stop_at, bool once)
{
  MultipartMetaFilter mp_filter;
  vector<rgw_bucket_dir_entry> objs;
  bool is_truncated;
  int ret;
  RGWBucketInfo& bucket_info = target->get_bucket_info();
  RGWRados::Bucket::List list_op(target);
  auto delay_ms = cct->_conf->rgw_lc_thread_delay;
  list_op.params.list_versions = false;
  // lifecycle processing does not depend on total order, so can
  // take advantage of unorderd listing optimizations--such as
  // operating on one shard at a time 
  list_op.params.allow_unordered = true;
  list_op.params.ns = RGW_OBJ_NS_MULTIPART;
  list_op.params.filter = &mp_filter;

  auto pf = [&](RGWLC::LCWorker* wk, WorkQ* wq, WorkItem& wi) {
    auto wt = boost::get<std::tuple<lc_op, rgw_bucket_dir_entry>>(wi);
    auto& [rule, obj] = wt;
    RGWMPObj mp_obj;
    if (!rule.suffix.empty()) {
      if (!boost::ends_with(obj.key.name, rule.suffix)) {
        ldout(cct, 20) << "NOTICE: obj not match suffix, obj=" << obj.key
                      << " suffix=" << rule.suffix << dendl;
        return;
      }
    }
    if (obj_has_expired(cct, obj.meta.mtime, rule.mp_expiration)) {
      rgw_obj_key key(obj.key);
      if (!mp_obj.from_meta(key.name)) {
        return;
      }
      RGWObjectCtx rctx(store);
      int ret = abort_multipart_upload(store, cct, &rctx, bucket_info, mp_obj);
      if (ret == 0) {
        if (perfcounter) {
          perfcounter->inc(l_rgw_lc_abort_mpu, 1);
        }
      } else {
        if (ret == -ERR_NO_SUCH_UPLOAD) {
          ldout(cct, 5) << "ERROR: abort_multipart_upload failed, ret=" << ret
                        << wq->thr_name() << ", meta:" << obj.key << dendl;
        } else {
          ldout(cct, 0) << "ERROR: abort_multipart_upload failed, ret=" << ret
            << wq->thr_name() << ", meta:" << obj.key << dendl;
        }
      } /* abort failed */
    } /* expired */
  };

  worker->workpool->setf(pf);


  for (auto prefix_iter = prefix_map.begin(); prefix_iter != prefix_map.end(); ++prefix_iter) {
    if (worker_should_stop(stop_at, once)) {
      ldout(cct, 5) << __func__ << " interval budget EXPIRED worker "
                    << worker->ix << dendl;
      return 0;
    }

    if (!prefix_iter->second.status || prefix_iter->second.mp_expiration <= 0) {
      continue;
    }
    list_op.params.prefix = prefix_iter->first;
    do {
      objs.clear();
      list_op.params.marker = list_op.get_next_marker();
      ret = list_op.list_objects(1000, &objs, NULL, &is_truncated);
      if (ret < 0) {
        if (ret == (-ENOENT))
          return 0;
        ldout(cct, 0) << "ERROR: store->list_objects(), ret:" << ret << dendl;
        return ret;
      }

      for (auto obj_iter = objs.begin(); obj_iter != objs.end(); ++obj_iter) {
        std::tuple<lc_op, rgw_bucket_dir_entry> t1 = {prefix_iter->second, *obj_iter};
        worker->workpool->enqueue(WorkItem{t1});
        if (going_down()) {
          return 0;
        }
      } // for objs 
      std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
    } while(is_truncated);
  }

  worker->workpool->drain();
  return 0;
}

static inline bool has_all_tags(const lc_op& rule_action,
                                const RGWObjTags& object_tags)
{
  if(! rule_action.obj_tags)
    return false;
  if(object_tags.count() < rule_action.obj_tags->count())
    return false;
  size_t tag_count = 0;
  for (const auto& tag : object_tags.get_tags()) {
    const auto& rule_tags = rule_action.obj_tags->get_tags();
    const auto& iter = rule_tags.find(tag.first);
    if(iter == rule_tags.end())
      continue;
    if(iter->second == tag.second)
    {
      tag_count++;
    }
  /* all tags in the rule appear in obj tags */
  }
  return tag_count == rule_action.obj_tags->count();
}

static int check_tags(lc_op_ctx& oc, bool *skip)
{
  auto& op = oc.op;

  if (!op.suffix.empty()) {
    if (!boost::ends_with(oc.obj.key.name, op.suffix)) {
      *skip = true;
      ldout(oc.cct, 20) << __func__ << "() skipping obj " << oc.obj
                        << " as key do not match suffix in rule: " << op.id
                        << " " << oc.wq->thr_name() << dendl;
      return 0;
    }
  }

  if (op.obj_tags != boost::none) {
    *skip = true;
    if (!oc.o.meta.has_tags || !oc.o.meta.tags_bl.length()) {
      ldout(oc.cct, 20) << __func__ << "() skipping obj " << oc.obj
                        << " as obj doesn't have tag in rule: " << op.id << " "
                        << oc.wq->thr_name() << dendl;
      return 0;
    }
    RGWObjTags dest_obj_tags;
    try {
      auto iter = oc.o.meta.tags_bl.begin();
      dest_obj_tags.decode(iter);
    } catch (buffer::error& err) {
      ldout(oc.cct,0) << __func__ << "() ERROR: caught buffer::error, couldn't decode TagSet "
                      << oc.wq->thr_name() << dendl;
      return -EIO;
    }
    if (!has_all_tags(op, dest_obj_tags)) {
      ldout(oc.cct, 20) << __func__ << "() skipping obj " << oc.obj
                        << " as tags do not match in rule: " << op.id << " "
                        << oc.wq->thr_name() << dendl;
      return 0;
    }
  }
  *skip = false;
  return 0;
}

// integrate suffix check in LCOpFilter_Tags
class LCOpFilter_Tags : public LCOpFilter {
public:
  bool check(lc_op_ctx& oc) override {
    auto& o = oc.o;

    if (o.is_delete_marker()) {
      return true;
    }

    bool skip;

    int ret = check_tags(oc, &skip);
    if (ret < 0) {
      if (ret == -ENOENT) {
        return false;
      }
      ldout(oc.cct, 0) << "ERROR: check_tags on obj=" << oc.obj
                       << " returned ret=" << ret << " "
                       << oc.wq->thr_name() << dendl;
      return false;
    }

    return !skip;
  };
};

class LCOpAction_CurrentExpiration : public LCOpAction {
public:

  bool check(lc_op_ctx& oc, ceph::real_time *exp_time) override {
    auto& o = oc.o;
    if (!o.is_current()) {
      ldout(oc.cct, 20) << __func__ << "(): key=" << o.key
                        << ": not current, skipping "
                        << oc.wq->thr_name() << dendl;
      return false;
    }

    if (o.is_delete_marker()) {
      std::string nkn;
      if (oc.next_key_name) nkn = *oc.next_key_name;
      if (oc.next_has_same_name(o.key.name)) {
        ldout(oc.cct, 10) << __func__ << "(): dm-check SAME: key=" << o.key
                          << " next_key_name: %%" << nkn << "%% "
                          << oc.wq->thr_name() << dendl;
        return false;
      } else {
        ldout(oc.cct, 10) << __func__ << "(): dm-check DELE: key=" << o.key
                          << " next_key_name: %%" << nkn << "%% "
                          << oc.wq->thr_name() << dendl;
        *exp_time = real_clock::now();
        return true;
      }
    }

    auto& mtime = o.meta.mtime;
    bool is_expired;
    auto& op = oc.op;
    if (op.expiration <= 0) {
      if (op.expiration_date == boost::none) {
        ldout(oc.cct, 20) << __func__ << "(): key=" << o.key
                          << ": no expiration set in rule, skipping "
                          << oc.wq->thr_name() << dendl;
        return false;
      }
      is_expired = ceph_clock_now() >= ceph::real_clock::to_time_t(*op.expiration_date);
      *exp_time = *op.expiration_date;
    } else {
      is_expired = obj_has_expired(oc.cct, mtime, op.expiration, exp_time);
    }

    ldout(oc.cct, 20) << __func__ << "(): key=" << o.key << ": is_expired="
                      << (int)is_expired << " "
                      << oc.wq->thr_name() << dendl;
    return is_expired && pass_bos_object_lock_check(oc.store, oc.bucket_info, oc.obj, mtime, oc.rctx);
  }

  int process(lc_op_ctx& oc) {
    auto& o = oc.o;
    int r;
    if (o.is_delete_marker()) {
      r = remove_expired_obj(oc, true);
      if (r < 0) {
        ldout(oc.cct, 0) << "ERROR: current is-dm remove_expired_obj "
                         << oc.bucket_info.bucket << ":" << o.key
                         << " " << cpp_strerror(r) << " "
                         << oc.wq->thr_name() << dendl;
        return r;
      }
      ldout(oc.cct, 15) << "DELETED: current is-dm "
                        << oc.bucket_info.bucket << ":" << o.key
                        << " " << oc.wq->thr_name() << dendl;
    } else {
      /* ! o.is_delete_marker() */
      r = remove_expired_obj(oc, !oc.bucket_info.versioned());
      if (r < 0) {
        ldout(oc.cct, 0) << "ERROR: remove_expired_obj "
                         << oc.bucket_info.bucket << ":" << o.key
                         << " " << cpp_strerror(r) << " "
                         << oc.wq->thr_name() << dendl;
        return r;
      }
      if (perfcounter) {
        perfcounter->inc(l_rgw_lc_expire_current, 1);
      }
      ldout(oc.cct, 15) << "DELETED:" << oc.bucket_info.bucket << ":" << o.key
           << " " << oc.wq->thr_name() << dendl;
    }
    return 0;
  }
};

class LCOpAction_NonCurrentExpiration : public LCOpAction {
public:
  bool check(lc_op_ctx& oc, ceph::real_time* exp_time) override {
    auto& o = oc.o;
    if (o.is_current()) {
      ldout(oc.cct, 20) << __func__ << "(): key=" << o.key
                        << ": current version, skipping "
                        << oc.wq->thr_name() << dendl;
      return false;
    }

    int expiration = oc.op.noncur_expiration;
    bool is_expired = obj_has_expired(oc.cct, oc.effective_mtime, expiration, exp_time);

    ldout(oc.cct, 20) << __func__ << "(): key=" << o.key << ": is_expired="
                      << is_expired << " "
                      << oc.wq->thr_name() << dendl;

    ldout(oc.cct, 20) << __func__ << "(): key=" << o.key << ": is_expired=" << is_expired << dendl;
    return is_expired && pass_object_lock_check(oc.store, oc.bucket_info, oc.obj, oc.rctx);
  }

  int process(lc_op_ctx& oc) {
    auto& o = oc.o;
    int r = remove_expired_obj(oc, true);
    if (r < 0) {
      ldout(oc.cct, 0) << "ERROR: remove_expired_obj (non-current expiration) " 
                       << oc.bucket_info.bucket << ":" << o.key 
                       << " " << cpp_strerror(r)
                       << " " << oc.wq->thr_name() << dendl;
      return r;
    }
    if (perfcounter) {
      perfcounter->inc(l_rgw_lc_expire_noncurrent, 1);
    }
    ldout(oc.cct, 2) << "DELETED:" << oc.bucket_info.bucket << ":" << o.key
                     << " (non-current expiration) "
                     << oc.wq->thr_name() << dendl;
    return 0;
  }
};

class LCOpAction_DMExpiration : public LCOpAction {
public:
  bool check(lc_op_ctx& oc, ceph::real_time *exp_time) override {
    auto& o = oc.o;
    if (!o.is_delete_marker()) {
      ldout(oc.cct, 20) << __func__ << "(): key=" << o.key
                        << ": not a delete marker, skipping "
                        << oc.wq->thr_name() << dendl;
      return false;
    }

    if (oc.next_has_same_name(o.key.name)) {
      ldout(oc.cct, 20) << __func__ << "(): key=" << o.key
                        << ": next is same object, skipping "
                        << oc.wq->thr_name() << dendl;
      return false;
    }

    *exp_time = real_clock::now();

    return true;
  }

  int process(lc_op_ctx& oc) {
    auto& o = oc.o;
    int r = remove_expired_obj(oc, true);
    if (r < 0) {
      ldout(oc.cct, 0) << "ERROR: remove_expired_obj (delete marker expiration) "
                       << oc.bucket_info.bucket << ":" << o.key
                       << " " << cpp_strerror(r)
                       << " " << oc.wq->thr_name()
                       << dendl;
      return r;
    }
    if (perfcounter) {
      perfcounter->inc(l_rgw_lc_expire_dm, 1);
    }
    ldout(oc.cct, 10) << "DELETED:" << oc.bucket_info.bucket << ":" << o.key
                      << " (delete marker expiration) "
                      << oc.wq->thr_name() << dendl;
    return 0;
  }
};

class LCOpAction_Transition : public LCOpAction {
  const transition_action& transition;
  bool need_to_process{false};

protected:
  virtual bool check_current_state(bool is_current) = 0;
  virtual ceph::real_time get_effective_mtime(lc_op_ctx& oc) = 0;
public:
  LCOpAction_Transition(const transition_action& _transition) : transition(_transition) {}

  bool check(lc_op_ctx& oc, ceph::real_time *exp_time) override {
    auto& o = oc.o;

    if (o.is_delete_marker()) {
      return false;
    }

    if (!check_current_state(o.is_current())) {
      return false;
    }

    auto mtime = get_effective_mtime(oc);
    bool is_expired;
    if (transition.days <= 0) {
      if (transition.date == boost::none) {
        ldout(oc.cct, 20) << __func__ << "(): key=" << o.key
                          << ": no transition day/date set in rule, skipping "
                          << oc.wq->thr_name() << dendl;
        return false;
      }
      is_expired = ceph_clock_now() >= ceph::real_clock::to_time_t(*transition.date);
      *exp_time = *transition.date;
    } else {
      is_expired = obj_has_expired(oc.cct, mtime, transition.days, exp_time);
    }

    ldout(oc.cct, 20) << __func__ << "(): key=" << o.key << ": is_expired="
                      << is_expired << " " << oc.wq->thr_name()
                      << dendl;

    string obj_storage_class = rgw_placement_rule::get_canonical_storage_class(o.meta.storage_class);
    if (transition.storage_class == RGWStorageClass::ARCHIVE) {
      if (obj_storage_class != RGWStorageClass::STANDARD_HP &&
          obj_storage_class != RGWStorageClass::STANDARD &&
          obj_storage_class != RGWStorageClass::STANDARD_IA) {
        is_expired = false;
      }
    } else if (transition.storage_class == RGWStorageClass::STANDARD_IA) {
      if (obj_storage_class != RGWStorageClass::STANDARD_HP &&
          obj_storage_class != RGWStorageClass::STANDARD) {
        is_expired = false;
      }
    } else if (transition.storage_class == RGWStorageClass::STANDARD) {
      if (obj_storage_class != RGWStorageClass::STANDARD_HP) {
        is_expired = false;
      }
    }

    return is_expired;
  }

  int process(lc_op_ctx& oc) {
    auto& o = oc.o;

    rgw_placement_rule target_placement;
    target_placement.inherit_from(oc.bucket_info.head_placement_rule);
    target_placement.storage_class = transition.storage_class;
    oc.rctx.obj.set_atomic(oc.obj);

    if (!oc.store->get_zone_params().valid_placement(target_placement)) {
      ldout(oc.cct, 0) << "ERROR: non existent dest placement: "
                       << target_placement
                       << " bucket="<< oc.bucket_info.bucket
                       << " rule_id=" << oc.op.id
                       << " " << oc.wq->thr_name() << dendl;
      return -EINVAL;
    }

    int r = oc.store->transition_obj(oc.rctx, oc.bucket_info, oc.obj,
                                     target_placement, o.meta.mtime,
                                     o.versioned_epoch);
    if (r < 0) {
      ldout(oc.cct, 0) << "ERROR: failed to transition obj " 
                       << oc.bucket_info.bucket << ":" << o.key 
                       << " -> " << transition.storage_class 
                       << " " << cpp_strerror(r)
                       << " " << oc.wq->thr_name() << dendl;
      return r;
    }
    ldout(oc.cct, 10) << "TRANSITIONED:" << oc.bucket_info.bucket
                      << ":" << o.key << " -> "
                      << transition.storage_class
                      << " " << oc.wq->thr_name() << dendl;
    return 0;
  }
};

class LCOpAction_CurrentTransition : public LCOpAction_Transition {
protected:
  bool check_current_state(bool is_current) override {
    return is_current;
  }

  ceph::real_time get_effective_mtime(lc_op_ctx& oc) override {
    return oc.o.meta.mtime;
  }
public:
  LCOpAction_CurrentTransition(const transition_action& _transition) : LCOpAction_Transition(_transition) {}

  int process(lc_op_ctx& oc) {
    int r = LCOpAction_Transition::process(oc);
    if (r == 0) {
      if (perfcounter) {
        perfcounter->inc(l_rgw_lc_transition_current, 1);
      }
    }
    return r;
  }
};

class LCOpAction_NonCurrentTransition : public LCOpAction_Transition {
protected:
  bool check_current_state(bool is_current) override {
    return !is_current;
  }

  ceph::real_time get_effective_mtime(lc_op_ctx& oc) override {
    return oc.effective_mtime;
  }
public:
  LCOpAction_NonCurrentTransition(const transition_action& _transition) : LCOpAction_Transition(_transition) {}

  int process(lc_op_ctx& oc) {
    int r = LCOpAction_Transition::process(oc);
    if (r == 0) {
      if (perfcounter) {
        perfcounter->inc(l_rgw_lc_transition_noncurrent, 1);
      }
    }
    return r;
  }
};

// priority order: delete > transition archive > transition ia > transition standard
void LCOpRule::build()
{
  filters.emplace_back(new LCOpFilter_Tags);

  auto& op = env.op;

  if (op.expiration > 0 ||
      op.expiration_date != boost::none) {
    actions.emplace_back(new LCOpAction_CurrentExpiration);
  }

  if (op.dm_expiration) {
    actions.emplace_back(new LCOpAction_DMExpiration);
  }

  if (op.noncur_expiration > 0) {
    actions.emplace_back(new LCOpAction_NonCurrentExpiration);
  }

  // wanghao, github process every transition, while we ignore STANDARD_HP ok?
  auto iter = op.transitions.find(RGWStorageClass::ARCHIVE);
  if (iter != op.transitions.end()) {
    actions.emplace_back(new LCOpAction_CurrentTransition(iter->second));
  }
  iter = op.transitions.find(RGWStorageClass::STANDARD_IA);
  if (iter != op.transitions.end()) {
    actions.emplace_back(new LCOpAction_CurrentTransition(iter->second));
  }
  iter = op.transitions.find(RGWStorageClass::STANDARD);
  if (iter != op.transitions.end()) {
    actions.emplace_back(new LCOpAction_CurrentTransition(iter->second));
  }

  iter = op.noncur_transitions.find(RGWStorageClass::ARCHIVE);
  if (iter != op.noncur_transitions.end()) {
    actions.emplace_back(new LCOpAction_NonCurrentTransition(iter->second));
  }
  iter = op.noncur_transitions.find(RGWStorageClass::STANDARD_IA);
  if (iter != op.noncur_transitions.end()) {
    actions.emplace_back(new LCOpAction_NonCurrentTransition(iter->second));
  }
  iter = op.noncur_transitions.find(RGWStorageClass::STANDARD);
  if (iter != op.noncur_transitions.end()) {
    actions.emplace_back(new LCOpAction_NonCurrentTransition(iter->second));
  }
}

void LCOpRule::update()
{
  next_key_name = env.ol.next_key_name();
  effective_mtime = env.ol.get_prev_obj().meta.mtime;
}

int LCOpRule::process(rgw_bucket_dir_entry& o, WorkQ* wq)
{
  lc_op_ctx ctx(env, o, next_key_name, effective_mtime, wq);
  shared_ptr<LCOpAction> *selected = nullptr; // n.b., req'd by sharing
  real_time exp;

  for (auto& a : actions) {
    // action_exp -> find the first expire action
    real_time action_exp;

    if (a->check(ctx, &action_exp)) {
      if (action_exp > exp) {
        exp = action_exp;
        selected = &a;
      }
    }
  }

  if (selected) {

    /*
     * Calling filter checks after action checks because
     * all action checks (as they are implemented now) do
     * not access the objects themselves, but return result
     * from info from bucket index listing. The current tags filter
     * check does access the objects, so we avoid unnecessary rados calls
     * having filters check later in the process.
     */

    bool cont = false;
    for (auto& f : filters) {
      if (f->check(ctx)) {
        cont = true;
        break;
      }
    }

    if (!cont) {
      ldout(env.store->ctx(), 20) << __func__ << "(): key=" << o.key
                                  << ": no rule match, skipping "
                                  << wq->thr_name() << dendl;
      return 0;
    }

    int r = (*selected)->process(ctx);
    if (r < 0) {
      ldout(ctx.cct, 0) << "ERROR: proess:"
                        << env.bucket_info.bucket << ":" << o.key
                        << " " << cpp_strerror(r)
                        << " " << wq->thr_name() << dendl;
      return r;
    }
    ldout(ctx.cct, 20) << "processed:" << env.bucket_info.bucket << ":"
                       << o.key << " " << wq->thr_name() << dendl;
  }

  return 0;

}


int RGWLC::bucket_lc_process(string& bucket, int shard_id, LCWorker* worker,
           time_t stop_at, bool once)
{

  ldout(cct, 20) << __func__ << "(): process bucket:" << bucket
                 << " shard_id:" << shard_id
                 << dendl;
  vector<std::string> result;
  boost::split(result, bucket, boost::is_any_of(":"));
  if (result.size() < 3) {
    ldout(cct, 0) << __func__ << "() ERROR: failed to decode entry bucket:"
                  << bucket << dendl;
    return -EINVAL;
  }
  string bucket_tenant = result[0];
  string bucket_name = result[1];
  string bucket_marker = result[2];

  if (shard_id < 0) {
    // update from old version, reshard bucket into lc entries
    ldout(cct, 10) << __func__ << "(): call reshard_bucket_lc_entry"
                   << " bucket:" << bucket << dendl;
    int ret = reshard_bucket_lc_entry(result[1]);
    if (ret != 0) {
      ldout(cct, 0) << __func__ << "() ERROR: failed to reshard bucket entry"
                    << ", bucket:" << bucket
                    << dendl;
      return ret;
    }
    return 1;
  }

  RGWLifecycleConfiguration config(cct);
  RGWBucketInfo bucket_info;
  map<string, bufferlist> bucket_attrs;
  string no_ns;
  string list_versions;
  vector<rgw_bucket_dir_entry> objs;
  RGWObjectCtx obj_ctx(store);

  int ret = store->get_bucket_info(obj_ctx, bucket_tenant, bucket_name, bucket_info, NULL, &bucket_attrs);
  if (ret < 0) {
    ldout(cct, 0) << __func__ << "() ERROR: get_bucket_info for "
                  << bucket_name << ", ret:" << ret
                  << dendl;
    return ret;
  }

  auto stack_guard = make_scope_guard(
      [&worker, &bucket_info] {
        worker->workpool->drain();
      }
    );

  if (bucket_info.bucket.marker != bucket_marker) {
    ldout(cct, 10) << "LC: deleting stale entry found for bucket="
                   << bucket_tenant << ":" << bucket_name
                   << " cur_marker=" << bucket_info.bucket.marker
                   << " orig_marker=" << bucket_marker << dendl;
    return -ENOENT;
  }

  RGWRados::Bucket target(store, bucket_info);

  map<string, bufferlist>::iterator aiter = bucket_attrs.find(RGW_ATTR_LC);
  if (aiter == bucket_attrs.end()) {
    ldout(cct, 10) << "can't find lc in bucket attr: " << bucket_name << dendl;
    return -ENOENT;
  }

  bufferlist::iterator iter = aiter->second.begin();
  try {
    config.decode(iter);
  } catch (const buffer::error& e) {
    ldout(cct, 0) << __func__ <<  "() ERROR: decode life cycle config failed" << dendl;
    return -EINTR;
  }

  auto pf = [](RGWLC::LCWorker* wk, WorkQ* wq, WorkItem& wi) {
    auto wt = boost::get<std::tuple<LCOpRule, rgw_bucket_dir_entry>>(wi);
    auto& [op_rule, o] = wt;

    ldpp_dout(wk->get_lc(), 20) << __func__ << "(): key=" << o.key << wq->thr_name() << dendl;
    int ret = op_rule.process(o, wq);
    if (ret < 0) {
      ldpp_dout(wk->get_lc(), 20) << "ERROR: orule.process() returned ret="
                                  << ret << wq->thr_name() << dendl;
    }
  };
  worker->workpool->setf(pf); // set every WorkQ's f

  multimap<string, lc_op>& prefix_map = config.get_prefix_map();
  ldout(cct, 10) << __func__ <<  "() prefix_map size="
                 << prefix_map.size()
                 << dendl;

  rgw_obj_key pre_marker;
  rgw_obj_key next_marker;
  for (auto prefix_iter = prefix_map.begin(); prefix_iter != prefix_map.end(); ++prefix_iter) {
    if (worker_should_stop(stop_at, once)) {
      ldout(cct, 5) << __func__ << " interval budget EXPIRED worker "
                    << worker->ix
                    << dendl;
      return 0;
    }

    auto& op = prefix_iter->second;
    if (!is_valid_op(op)) {
      ldout(cct, 10) << __func__ << "(): not invalid op, prefix:"
                     << prefix_iter->first << dendl;
      continue;
    }
    ldout(cct, 20) << __func__ << "(): prefix=" << prefix_iter->first << dendl;

    if (prefix_iter != prefix_map.begin() &&
        (prefix_iter->first.compare(0, prev(prefix_iter)->first.length(),
                                    prev(prefix_iter)->first) == 0)) {
      next_marker = pre_marker;
    } else {
      pre_marker = next_marker;
    }

    LCObjsLister ol(store, bucket_info);
    ol.set_prefix(prefix_iter->first);
    if (shard_id >= 0) {
      ol.set_shard_id(shard_id);
      ol.set_self_shard(true);
    }

    ret = ol.init();

    if (ret < 0) {
      ldout(cct, 0) << "ERROR: LCObjsLister.init -> list_objects return:"<< ret << dendl;
      if (ret == (-ENOENT)) {
        return 0;
      }
      return ret;
    }

    op_env oenv(op, store, worker, bucket_info, ol);

    LCOpRule orule(oenv);

    orule.build();  // why can't ctor do it?
    rgw_bucket_dir_entry* o{nullptr};
    for (; ol.get_obj(&o /*, fetch_barrier */); ol.next()) {
      ldout(cct, 20) << __func__ << "(): enqueue key=" << o->key << dendl;
      orule.update();
      std::tuple<LCOpRule, rgw_bucket_dir_entry> t1 = {orule, *o};
      worker->workpool->enqueue(WorkItem{t1});
    }
    worker->workpool->drain();
  }

  if (shard_id >= 0) {
    target.set_shard_id(shard_id);
  }
  ret = handle_multipart_expiration(&target, prefix_map, worker, stop_at, once);

  return ret;
}

int RGWLC::bucket_lc_post(int index, int max_lock_sec,
                          cls_rgw_lc_entry& entry, int& result,
                          LCWorker* worker)
{
  utime_t lock_duration(cct->_conf->rgw_lc_lock_max_time, 0);

  rados::cls::lock::Lock l(lc_index_lock_name);
  l.set_cookie(cookie);
  l.set_duration(lock_duration);

  ldout(cct, 5) << __func__ << "(): POST " << entry
                << " index: " << index << " worker ix: " << worker->ix
                << dendl;

  cls_rgw_lc_entry exist_entry;
  do {
    int ret = l.lock_exclusive(&store->lc_pool_ctx, obj_names[index]);
    if (ret == -EBUSY || ret == -EEXIST) { /* already locked by another lc processor */
      ldout(cct, 5) << __func__ << "(): failed to acquire lock on "
                    << obj_names[index] << ", sleep 5, try again" << dendl;
      sleep(5);
      continue;
    }
    if (ret < 0) {
      ldout(cct, 0) << __func__ << "(): failed to acquire lock on "
                    << obj_names[index] << ", ret=" << ret << dendl;
      return 0;
    }
    ldout(cct, 20) << __func__ << "() lock " << obj_names[index] << dendl;
    if (result == -ENOENT) {
      ret = cls_rgw_lc_rm_entry(store->lc_pool_ctx, obj_names[index],  entry);
      if (ret < 0) {
        ldout(cct, 0) << __func__ << "() ERROR: failed to remove entry "
                      << obj_names[index] << ", ret=" << ret << dendl;
      }
      goto clean;
    } else if (result < 0) {
      entry.status = lc_failed;
    } else {
      entry.status = lc_complete;
    }

    ret = cls_rgw_lc_get_entry(store->lc_pool_ctx, obj_names[index], entry.bucket, exist_entry);
    if (ret < 0) {
      if (ret == -ENOENT) {
        ldout(cct, 10) << __func__ << "() entry has been removed while lc process this shard" << dendl;
      }
      ldout(cct, 0) << __func__ << "() ERROR: failed to reread this entry " << entry
                    << ", ret=" << ret  << dendl;
      goto clean;
    }

    ldout(cct, 30) << __func__ << "() update lc entry " << entry << dendl;
    ret = cls_rgw_lc_set_entry(store->lc_pool_ctx, obj_names[index], entry);
    if (ret < 0) {
      ldout(cct, 0) << __func__ << "() ERROR failed to set entry on "
                    << obj_names[index] << ", ret=" << ret << dendl;
    }
clean:
    l.unlock(&store->lc_pool_ctx, obj_names[index]);
    ldout(cct, 20) << __func__ << "() unlock " << obj_names[index] << dendl;
    return 0;
  } while (true);
}

int RGWLC::list_lc_progress(string& marker, uint32_t max_entries,
                            vector<cls_rgw_lc_entry>& progress_map,
                            int& index)
{
  progress_map.clear();
  for(; index < max_objs; index++, marker = "") {
    vector<cls_rgw_lc_entry> entries;
    int ret = cls_rgw_lc_list(store->lc_pool_ctx, obj_names[index], marker, max_entries, entries);
    if (ret < 0) {
      if (ret == -ENOENT) {
        ldout(cct, 10) << __func__ << "() ignoring unfound lc object="
                       << obj_names[index] << dendl;
        continue;
      } else {
        return ret;
      }
    }

    progress_map.reserve(progress_map.size() + entries.size());
    progress_map.insert(progress_map.end(), entries.begin(), entries.end());

    /* update index, marker tuple*/
    if (progress_map.size() > 0) {
      marker = progress_map.back().bucket;
    }

    if (progress_map.size() >= max_entries) {
      break;
    }
  }
  return 0;
}

static inline vector<int> random_sequence(uint32_t n)
{
  vector<int> v(n, 0);
  std::generate(v.begin(), v.end(),
    [ix = 0]() mutable {
      return ix++;
    });
  std::random_shuffle(v.begin(), v.end());
  return v;
}

int RGWLC::process(LCWorker* worker, bool once = false)
{
  int max_secs = cct->_conf->rgw_lc_lock_max_time;

  /* generate an index-shard sequence unrelated to any other
   * that might be running in parallel */

  vector<int> shard_seq = random_sequence(max_objs);
  ldout(cct, 20) << __func__ << "() random sequence:" << shard_seq << dendl;
  for (auto index : shard_seq) {
    int ret = process(index, max_secs, worker, once);
    if (ret < 0)
      return ret;
  }

  return 0;
}

bool RGWLC::expired_session(time_t started)
{
  time_t interval = (cct->_conf->rgw_lc_debug_interval > 0)
    ? cct->_conf->rgw_lc_debug_interval
    : ONE_DAY;

  auto now = time(nullptr);

  ldout(cct, 10) << "RGWLC::expired_session"
                 << " started: " << started
                 << " interval: " << interval << "(*2==" << 2*interval << ")"
                 << " now: " << now
                 << dendl;

  return (started + 2*interval < now);
}

time_t RGWLC::thread_stop_at()
{
  uint64_t interval = (cct->_conf->rgw_lc_debug_interval > 0)
    ? cct->_conf->rgw_lc_debug_interval
    : ONE_DAY;

  return time(nullptr) + interval;
}

int RGWLC::process(int index, int max_lock_secs,
                   LCWorker* worker, bool once = false)
{
  ldout(cct, 20) << "RGWLC::process(): ENTER: " << "index: "
                << index << " worker ix: " << worker->ix << dendl;

  cls_rgw_lc_entry entry;
  rados::cls::lock::Lock l(lc_index_lock_name);
  do {
    utime_t now = ceph_clock_now();
    if (max_lock_secs <= 0)
      return -EAGAIN;

    utime_t time(max_lock_secs, 0);
    l.set_duration(time);

    int ret = l.lock_exclusive(&store->lc_pool_ctx, obj_names[index]);
    if (ret == -EBUSY || ret == -EEXIST) { /* already locked by another lc processor */
      ldout(cct, 5) << __func__ << "() failed to acquire lock on "
          << obj_names[index] << ", sleep 5, try again" << dendl;
      sleep(5);
      continue;
    }
    if (ret < 0) {
      ldout(cct, 0) << __func__ << "() ERROR: acquire lock failed on "
                    << obj_names[index] << ", ret:" << ret << dendl;
      return 0;
    }

    cls_rgw_lc_obj_head head;
    ret = cls_rgw_lc_get_head(store->lc_pool_ctx, obj_names[index], head);
    if (ret < 0) {
      ldout(cct, 0) << __func__ << "() ERROR failed to get obj head "
          << obj_names[index] << ", ret=" << ret << dendl;
      goto exit;
    }

    ldout(cct, 20) << "RGWLC::process() head start_date=" << head.start_date
                  << " on " << obj_names[index]
                  << dendl;

    /*
     * Jump this shard when:
     * case 1: this lc thread is processing this lc shard, while this lc shard 
     *         has been marked as finished by other lc thread.
     * case 2: this lc shard has been marked as finished today before i process
     *         it.
     * */
    if (head.marker.empty()) {
      if (!entry.bucket.empty() || if_already_run_today(head.start_date)) {
        ldout(cct, 10) << __func__ << " WARNING: shard has finished, start_date:"
                       << head.start_date << " just jump this shard:"
                       << obj_names[index] << " entry:"
                       << entry << dendl;
        goto exit;
      } else {
        // new day, init start_data and status for each entry in this lc shard
        head.start_date = now;
        ret = bucket_lc_prepare(index, worker);
        if (ret < 0) {
          ldout(cct, 0) << __func__ << "() ERROR: failed to update lc object "
                        << obj_names[index] << ", ret=" << ret << dendl;
          goto exit;
        }
      }
    }

    // called by admin lc run -> clear marker, trigger new cycle
    if(!head.marker.empty() && once) {
      ldout(cct, 20) << "RGWLC::process(): admin lc run trigger clear lc head marker on "
                     << obj_names[index]
                     << dendl;
      head.start_date = now;
      head.marker.clear();
      ret = bucket_lc_prepare(index, worker);
      if (ret < 0) {
        ldout(cct, 0) << __func__ << "() ERROR: failed to update lc object "
                      << obj_names[index] << ", ret=" << ret << dendl;
        goto exit;
      }
    }

    ldout(cct, 20) << "RGWLC::process(): get next entry on " << obj_names[index]
                   << " marker:" << head.marker
                   << dendl;
    ret = cls_rgw_lc_get_next_entry(store->lc_pool_ctx, obj_names[index], head.marker, entry);
    if (ret < 0) {
      ldout(cct, 0) << __func__ << "() ERROR: failed to get obj entry "
                    << obj_names[index] << " ret=" << ret << dendl;
      goto exit;
    }

    /* termination condition (eof)*/
    if (entry.bucket.empty()) {
      ldout(cct, 20) << "RGWLC::process() list entrys empty on " << obj_names[index] << dendl;
      // clear head marker when processed this lc shard
      ldout(cct, 0) << __func__ << " finish this lc shard, clear its marker "
                    << obj_names[index]
                    << ", start_date:" << head.start_date
                    << dendl;
      head.marker.clear();
      ret = cls_rgw_lc_put_head(store->lc_pool_ctx, obj_names[index], head);
      if (ret < 0) {
        ldout(cct, 0) << __func__ << "() ERROR: failed to put head on "
                      << obj_names[index] << " ret=" << ret << dendl;
      }
      goto exit;
    }

    ldout(cct, 20) << "RGWLC::process(): START entry 1: " << entry
                  << " index: " << index << " worker ix: " << worker->ix << dendl;
    entry.status = lc_processing;
    ret = cls_rgw_lc_set_entry(store->lc_pool_ctx, obj_names[index], entry);
    if (ret < 0) {
      ldout(cct, 0) << __func__ << "() ERROR: failed to set obj entry " << obj_names[index]
                    << " (" << entry.bucket << "," << entry.status << ")"
                    << " ret=" << ret << dendl;
      goto exit;
    }

    head.marker = entry.bucket;
    ret = cls_rgw_lc_put_head(store->lc_pool_ctx, obj_names[index], head);
    if (ret < 0) {
      ldout(cct, 0) << __func__ << "() ERROR: failed to put head on "
                    << obj_names[index] << " ret=" << ret << dendl;
      goto exit;
    }
    l.unlock(&store->lc_pool_ctx, obj_names[index]);
    ret = bucket_lc_process(entry.bucket, entry.shard_id, worker, thread_stop_at(), once);
    if (ret == -ENOENT) {
      // this shard info is older or newer than its bucket info, ignore update it 
      // in this period
      continue;
    }
    if (1 == ret) {
      // jump bucket_lc_post (update old entry status)
      continue;
    }
    bucket_lc_post(index, max_lock_secs, entry, ret, worker);
  } while(1 && !once);

  return 0;

exit:
  l.unlock(&store->lc_pool_ctx, obj_names[index]);
  return 0;
}

void RGWLC::start_processor()
{
  auto maxw = cct->_conf->rgw_lc_max_worker;
  workers.reserve(maxw);
  for (int ix = 0; ix < maxw; ++ix) {
    auto worker = std::make_unique<RGWLC::LCWorker>(this /* dpp */, cct, this, ix);
    worker->create((string{"lc_thr_"} + to_string(ix)).c_str());
    ldout(cct, 5) << "RGWLC start lc thread:" << ix << dendl;
    workers.emplace_back(std::move(worker));
  }
}

void RGWLC::stop_processor()
{
  down_flag = true;
  for (auto& worker : workers) {
    worker->stop();
    worker->join();
  }
  workers.clear();
}

unsigned RGWLC::get_subsys() const
{
  return dout_subsys;
}

std::ostream& RGWLC::gen_prefix(std::ostream& out) const
{
  return out << "lifecycle: ";
}

void RGWLC::LCWorker::stop()
{
  Mutex::Locker l(lock);
  cond.Signal();
}

bool RGWLC::going_down()
{
  return down_flag;
}

bool RGWLC::LCWorker::should_work(utime_t& now)
{
  int start_hour;
  int start_minute;
  int end_hour;
  int end_minute;
  string worktime = cct->_conf->rgw_lifecycle_work_time;
  sscanf(worktime.c_str(),"%d:%d-%d:%d",&start_hour, &start_minute, &end_hour, &end_minute);
  struct tm bdt;
  time_t tt = now.sec();
  localtime_r(&tt, &bdt);

  if (cct->_conf->rgw_lc_debug_interval > 0) {
    /* We're debugging, so say we can run */
    return true;
  } else if ((bdt.tm_hour*60 + bdt.tm_min >= start_hour*60 + start_minute) &&
             (bdt.tm_hour*60 + bdt.tm_min <= end_hour*60 + end_minute)) {
    return true;
  } else {
    return false;
  }
}

int RGWLC::LCWorker::schedule_next_start_time(utime_t &start, utime_t& now)
{
  int secs;

  if (cct->_conf->rgw_lc_debug_interval > 0) {
    secs = start + cct->_conf->rgw_lc_debug_interval - now;
  if (secs < 0)
    secs = 0;
  return (secs);
  }

  int start_hour;
  int start_minute;
  int end_hour;
  int end_minute;
  string worktime = cct->_conf->rgw_lifecycle_work_time;
  sscanf(worktime.c_str(),"%d:%d-%d:%d",&start_hour, &start_minute, &end_hour, &end_minute);
  struct tm bdt;
  time_t tt = now.sec();
  time_t nt;
  localtime_r(&tt, &bdt);
  bdt.tm_hour = start_hour;
  bdt.tm_min = start_minute;
  bdt.tm_sec = 0;
  nt = mktime(&bdt);
  secs = nt - tt;

  return secs>0 ? secs : secs + ONE_DAY;
}

RGWLC::LCWorker::~LCWorker()
{
  delete workpool;
} /* ~LCWorker */

void RGWLifecycleConfiguration::generate_test_instances(list<RGWLifecycleConfiguration*>& o)
{
  o.push_back(new RGWLifecycleConfiguration);
}

static void get_lc_oid(CephContext *cct, const string& key, int shard_id, string *oid)
{
  int max_objs = (cct->_conf->rgw_lc_max_objs > HASH_PRIME ? HASH_PRIME : cct->_conf->rgw_lc_max_objs);
  int shard_shift = (shard_id > 0 ? shard_id : 0);
  int index = (ceph_str_hash_linux(key.c_str(), key.size()) + shard_shift) % HASH_PRIME % max_objs;
  *oid = lc_oid_prefix;
  char buf[32];
  snprintf(buf, 32, ".%d", index);
  oid->append(buf);
  return;
}

static std::string get_lc_shard_name(const rgw_bucket& bucket, int shard_id) {
  if (shard_id == -1)
    return string_join_reserve(':', bucket.tenant, bucket.name, bucket.marker);
  else 
    return string_join_reserve(':', bucket.tenant, bucket.name, bucket.marker, to_string(shard_id));
}

template<typename F>
static int guard_lc_modify(RGWRados* store, const rgw_bucket& bucket, const string& cookie, string& oid, vector<cls_rgw_lc_entry>& entries, const F& f) {
  CephContext *cct = store->ctx();
  int max_lock_secs = cct->_conf->rgw_lc_lock_max_time;

  rados::cls::lock::Lock l(lc_index_lock_name); 
  utime_t time(max_lock_secs, 0);
  l.set_duration(time);
  l.set_cookie(cookie);

  librados::IoCtx *ctx = store->get_lc_pool_ctx();
  int ret;

  do {
    ret = l.lock_exclusive(ctx, oid);
    if (ret == -EBUSY || ret == -EEXIST) {
      ldout(cct, 5) << __func__ << "() ERROR: failed to acquire lock on "
                    << oid << ", sleep 5, try again"
                    << dendl;
      sleep(5); // XXX: return retryable error
      continue;
    }
    if (ret < 0) {
      ldout(cct, 0) << __func__ << "() ERROR: failed to acquire lock on "
                    << oid << ", ret=" << ret
                    << dendl;
      return ret;
    }
    ret = f(ctx, oid, entries);
    if (ret < 0) {
      ldout(cct, 0) << __func__ << "() ERROR: failed to set entry on "
                    << oid << ", ret=" << ret << dendl;
    }
    break;
  } while (true);
  l.unlock(ctx, oid);
  return ret;
}

void split_lc_entry_by_shard(CephContext* cct, rgw_bucket& bucket, int begin_shard_id, int end_shard_id, map<string, vector<cls_rgw_lc_entry>>& total_entries) {
  for (int i = begin_shard_id; i < end_shard_id; ++i) {
    string key = get_lc_shard_name(bucket, i);
    string oid;
    get_lc_oid(cct, key, i, &oid);

    cls_rgw_lc_entry entry;
    entry.bucket = key;
    entry.shard_id = i;
    entry.status = lc_uninitial;

    total_entries[oid].push_back(entry);
  }
}

int RGWLC::set_lc_entries(rgw_bucket& bucket, int begin_shard_id, int end_shard_id) {
  map<string, vector<cls_rgw_lc_entry>> total_entries;
  split_lc_entry_by_shard(cct, bucket, begin_shard_id, end_shard_id, total_entries);
  int ret = 0;
  for (auto iter = total_entries.begin(); iter != total_entries.end(); ++iter) {
    string oid = iter->first;
    ret = guard_lc_modify(store, bucket, cookie, oid, iter->second,
      [&](librados::IoCtx *ctx, string& oid, vector<cls_rgw_lc_entry>& entries) {
        return cls_rgw_lc_set_entries(*ctx, oid, entries);
    });
    if (ret < 0) {
      ldout(cct, 5) << __func__ << "() ERROR: failed to set lc entries "
                    << iter->first << " ret:" << ret << dendl;
      return ret;
    }
  }

  return ret;
}

int RGWLC::remove_lc_entries(rgw_bucket& bucket, int begin_shard_id, int end_shard_id) {
  map<string, vector<cls_rgw_lc_entry>> total_entries;
  split_lc_entry_by_shard(cct, bucket, begin_shard_id, end_shard_id, total_entries);
  int ret = 0;
  for (auto iter = total_entries.begin(); iter != total_entries.end(); ++iter) {
    string oid = iter->first;
    ldout(cct, 30) << __func__ << "() remove lc entries on " << oid << ", entries:";
    for (auto e : iter->second) {
      *_dout << e << " ";
    }
    *_dout << dendl;
    ret = guard_lc_modify(store, bucket, cookie, oid, iter->second,
      [&](librados::IoCtx *ctx, string& oid, vector<cls_rgw_lc_entry>& entries) {
        return cls_rgw_lc_rm_entries(*ctx, oid, entries);
    });
    if (ret < 0) {
      ldout(cct, 5) << __func__ << "() ERROR: failed to set lc entries "
                    << iter->first << " ret:" << ret << dendl;
      return ret;
    }
  }

  return ret;
}

int RGWLC::set_bucket_config(RGWBucketInfo& bucket_info,
                         const map<string, bufferlist>& bucket_attrs,
                         RGWLifecycleConfiguration *config)
{
  map<string, bufferlist> attrs = bucket_attrs;
  bufferlist bl;
  config->encode(bl);
  attrs[RGW_ATTR_LC] = bl;
  int ret = rgw_bucket_set_attrs(store, bucket_info, attrs, &bucket_info.objv_tracker);
  if (ret < 0)
    return ret;

  rgw_bucket& bucket = bucket_info.bucket;

  ret = set_lc_entries(bucket, 0, bucket_info.num_shards);
  return ret;
}

int RGWLC::remove_bucket_config(RGWBucketInfo& bucket_info,
                                const map<string, bufferlist>& bucket_attrs)
{
  map<string, bufferlist> attrs = bucket_attrs;
  attrs.erase(RGW_ATTR_LC);
  int ret = rgw_bucket_set_attrs(store, bucket_info, attrs, &bucket_info.objv_tracker);

  rgw_bucket& bucket = bucket_info.bucket;

  if (ret < 0) {
    ldout(cct, 0) << __func__ << "() ERROR: failed to set attrs on bucket="
                  << bucket.name << " returned err=" << ret << dendl;
    return ret;
  }

  ret = remove_lc_entries(bucket, 0, bucket_info.num_shards);
  if (ret < 0) {
    ldout(cct, 0) << __func__ << "() ERROR: failed to delete lc entry"
                  << ", bucket_name:" << bucket_info.bucket.name
                  << ", ret=" << ret << dendl;
    return ret;
  }
  return ret;
  
}

namespace rgw::lc {

std::string s3_expiration_header(
  struct req_state* s,
  const rgw_obj_key& obj_key,
  const RGWObjTags& obj_tagset,
  const ceph::real_time& mtime,
  std::map<std::string, buffer::list>& bucket_attrs)
{
  CephContext* cct = s->cct;
  RGWLifecycleConfiguration config(cct);
  std::string hdr{""};

  map<string, bufferlist>::iterator aiter = bucket_attrs.find(RGW_ATTR_LC);
  if (aiter == bucket_attrs.end())
    return hdr;

  bufferlist::iterator iter = aiter->second.begin();
  try {
    config.decode(iter);
  } catch (const buffer::error& e) {
    ldout(cct, 0) << __func__ <<  "() ERROR: decode life cycle config failed"
                  << dendl;
    return hdr;
  } /* catch */

  RGWObjTags::tag_map_t obj_tag_map = obj_tagset.get_tags();
  if (cct->_conf->subsys.should_gather(ceph_subsys_rgw, 16)) {
    for (const auto& elt : obj_tag_map) {
      ldout(cct, 15) << __func__ << "() key=" << elt.first << " val=" << elt.second
                     << dendl;
    }
  }

  boost::optional<ceph::real_time> expiration_date;
  boost::optional<std::string> rule_id;

  const auto& rule_map = config.get_rule_map();
  for (const auto& ri : rule_map) {
    const auto& rule = ri.second;
    auto& id = rule.get_id();
    auto& filter = rule.get_filter();
    auto& prefix = filter.has_prefix() ? filter.get_prefix(): rule.get_prefix();
    auto& expiration = rule.get_expiration();
    auto& noncur_expiration = rule.get_noncur_expiration();

    ldout(cct, 10) << __func__ << "rule: " << ri.first
                   << " prefix: " << prefix
                   << " expiration: "
                   << " date: " << expiration.get_date()
                   << " days: " << expiration.get_days()
                   << " noncur_expiration: "
                   << " date: " << noncur_expiration.get_date()
                   << " days: " << noncur_expiration.get_days()
                   << dendl;

    /* skip if rule !enabled
     * if rule has prefix, skip iff object !match prefix
     * if rule has tags, skip iff object !match tags
     * note if object is current or non-current, compare accordingly
     * if rule has days, construct date expression and save iff older
     * than last saved
     * if rule has date, convert date expression and save iff older
     * than last saved
     * if the date accum has a value, format it into hdr
     */

    if (! rule.is_enabled())
      continue;

    if(! prefix.empty()) {
      if (! boost::starts_with(obj_key.name, prefix))
        continue;
    }

    if (filter.has_suffix()) {
      if (!boost::ends_with(obj_key.name, filter.get_suffix()))
        continue;
    }

    if (filter.has_tags()) {
      bool tag_match = false;
      const RGWObjTags& rule_tagset = filter.get_tags();
      for (auto& tag : rule_tagset.get_tags()) {
        /* remember, S3 tags are {key,value} tuples */
        tag_match = true;
        auto obj_tag = obj_tag_map.find(tag.first);
        if (obj_tag == obj_tag_map.end() || obj_tag->second != tag.second) {
          ldout(cct, 10) << "tag does not match obj_key=" << obj_key
                         << " rule_id=" << id
                         << " tag=" << tag
                         << dendl;
          tag_match = false;
          break;
        }
      }
      if (! tag_match)
        continue;
    }

    // compute a uniform expiration date
    boost::optional<ceph::real_time> rule_expiration_date;
    const LCExpiration& rule_expiration =
      (obj_key.instance.empty()) ? expiration : noncur_expiration;

    if (rule_expiration.has_date()) {
      rule_expiration_date =
        boost::optional<ceph::real_time>(
          ceph::from_iso_8601(rule.get_expiration().get_date()));
    } else {
      if (rule_expiration.has_days()) {
        rule_expiration_date =
          boost::optional<ceph::real_time>(
            mtime + make_timespan(double(rule_expiration.get_days())*ONE_DAY - ceph::real_clock::to_time_t(mtime)%ONE_DAY + ONE_DAY));
      }
    }

    // update earliest expiration
    if (rule_expiration_date) {
      if ((! expiration_date) ||
          (*expiration_date > *rule_expiration_date)) {
      expiration_date = boost::optional<ceph::real_time>(rule_expiration_date);
      rule_id = boost::optional<std::string>(id);
      }
    }
  }

  // cond format header
  if (expiration_date && rule_id) {
    // Fri, 23 Dec 2012 00:00:00 GMT
    char exp_buf[100];
    time_t exp = ceph::real_clock::to_time_t(*expiration_date);
    if (std::strftime(exp_buf, sizeof(exp_buf),
          "%a, %d %b %Y %T %Z", std::gmtime(&exp))) {
      char buf[sizeof(exp_buf) + (*rule_id).length() + 30];
      snprintf(buf, sizeof(buf), "expiry-date=\"%s\", rule-id=\"%s\"",
               exp_buf, (*rule_id).c_str());
      hdr = string(buf);
    } else {
      ldout(cct, 0) << __func__
                    << "() ERROR: strftime of life cycle expiration header failed"
                    << dendl;
    }
  }

  return hdr;

} /* rgwlc_s3_expiration_header */

bool s3_multipart_abort_header(
  struct req_state* s,
  const rgw_obj_key& obj_key,
  const ceph::real_time& mtime,
  std::map<std::string, buffer::list>& bucket_attrs,
  ceph::real_time& abort_date,
  std::string& rule_id)
{
  CephContext* cct = s->cct;
  RGWLifecycleConfiguration config(cct);

  auto aiter = bucket_attrs.find(RGW_ATTR_LC);
  if (aiter == bucket_attrs.end())
    return false;

  bufferlist::iterator iter = aiter->second.begin();
  try {
    config.decode(iter);
  } catch (const buffer::error& e) {
    ldout(cct, 0) << __func__ <<  "() ERROR: decode life cycle config failed"
                  << dendl;
    return false;
  } /* catch */

  std::optional<ceph::real_time> abort_date_tmp;
  std::optional<std::string_view> rule_id_tmp;
  const auto& rule_map = config.get_rule_map();
  for (const auto& ri : rule_map) {
    const auto& rule = ri.second;
    const auto& id = rule.get_id();
    const auto& filter = rule.get_filter();
    const auto& prefix = filter.has_prefix()?filter.get_prefix():rule.get_prefix();
    const auto& mp_expiration = rule.get_mp_expiration();
    if (!rule.is_enabled()) {
      continue;
    }
    if(!prefix.empty() && !boost::starts_with(obj_key.name, prefix)) {
      continue;
    }

    std::optional<ceph::real_time> rule_abort_date;
    if (mp_expiration.has_days()) {
      rule_abort_date = std::optional<ceph::real_time>(
              mtime + make_timespan(mp_expiration.get_days()*ONE_DAY - ceph::real_clock::to_time_t(mtime)%ONE_DAY + ONE_DAY));
    }

    // update earliest abort date
    if (rule_abort_date) {
      if ((! abort_date_tmp) ||
          (*abort_date_tmp > *rule_abort_date)) {
        abort_date_tmp =
                std::optional<ceph::real_time>(rule_abort_date);
        rule_id_tmp = std::optional<std::string_view>(id);
      }
    }
  }
  if (abort_date_tmp && rule_id_tmp) {
    abort_date = *abort_date_tmp;
    rule_id = *rule_id_tmp;
    return true;
  } else {
    return false;
  }
}

} /* namespace rgw::lc */