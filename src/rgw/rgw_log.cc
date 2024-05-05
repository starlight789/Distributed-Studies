// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/trim_all.hpp>
#include <math.h>

#include "common/Clock.h"
#include "common/Timer.h"
#include "common/utf8.h"
#include "common/OutputDataSocket.h"
#include "common/Formatter.h"

#include "rgw_bucket.h"
#include "rgw_log.h"
#include "rgw_acl.h"
#include "rgw_rados.h"
#include "rgw_client_io.h"
#include "rgw_rest.h"

#define dout_subsys ceph_subsys_rgw

ceph::logging::Log* g_access_log = NULL;

static void set_param_str(struct req_state *s, const char *name, string& str)
{
  const char *p = s->info.env->get(name);
  if (p)
    str = p;
}

string render_log_object_name(const string& format,
			      struct tm *dt, string& bucket_id,
			      const string& bucket_name)
{
  string o;
  for (unsigned i=0; i<format.size(); i++) {
    if (format[i] == '%' && i+1 < format.size()) {
      i++;
      char buf[32];
      switch (format[i]) {
      case '%':
	strcpy(buf, "%");
	break;
      case 'Y':
	sprintf(buf, "%.4d", dt->tm_year + 1900);
	break;
      case 'y':
	sprintf(buf, "%.2d", dt->tm_year % 100);
	break;
      case 'm':
	sprintf(buf, "%.2d", dt->tm_mon + 1);
	break;
      case 'd':
	sprintf(buf, "%.2d", dt->tm_mday);
	break;
      case 'H':
	sprintf(buf, "%.2d", dt->tm_hour);
	break;
      case 'I':
	sprintf(buf, "%.2d", (dt->tm_hour % 12) + 1);
	break;
      case 'k':
	sprintf(buf, "%d", dt->tm_hour);
	break;
      case 'l':
	sprintf(buf, "%d", (dt->tm_hour % 12) + 1);
	break;
      case 'M':
	sprintf(buf, "%.2d", dt->tm_min);
	break;

      case 'i':
	o += bucket_id;
	continue;
      case 'n':
	o += bucket_name;
	continue;
      default:
	// unknown code
	sprintf(buf, "%%%c", format[i]);
	break;
      }
      o += buf;
      continue;
    }
    o += format[i];
  }
  return o;
}

/* usage logger */
class UsageLogger {
  CephContext *cct;
  RGWRados *store;
  map<rgw_user_bucket, RGWUsageBatch> usage_map;
  Mutex lock;
  int32_t num_entries;
  Mutex timer_lock;
  SafeTimer timer;
  utime_t round_timestamp;
  set<string> whitelist_ip;
  map<string, pair<uint64_t, uint64_t> > whitelist_segment;

  class C_UsageLogTimeout : public Context {
    UsageLogger *logger;
  public:
    explicit C_UsageLogTimeout(UsageLogger *_l) : logger(_l) {}
    void finish(int r) override {
      logger->flush();
      logger->set_timer();
    }
  };

  class C_UsageLogTrimTimeout : public Context {
    UsageLogger *logger;
  public:
    explicit C_UsageLogTrimTimeout(UsageLogger *_l) : logger(_l) {}
    void finish(int r) override {
      logger->trim();
      logger->set_trim_timer();
    }
  };

  void set_timer() {
    timer.add_event_after(cct->_conf->rgw_usage_log_tick_interval, new C_UsageLogTimeout(this));
  }
  void set_trim_timer() {
    timer.add_event_after(cct->_conf->rgw_usage_log_tick_trim_interval, new C_UsageLogTrimTimeout(this));
  }
public:

  UsageLogger(CephContext *_cct, RGWRados *_store) : cct(_cct), store(_store), lock("UsageLogger"), num_entries(0), timer_lock("UsageLogger::timer_lock"), timer(cct, timer_lock) {
    timer.init();
    Mutex::Locker l(timer_lock);
    set_timer();
    set_trim_timer();
    utime_t ts = ceph_clock_now();
    recalc_round_timestamp(ts);
    init_whitelist();
  }

  ~UsageLogger() {
    Mutex::Locker l(timer_lock);
    flush();
    timer.cancel_all_events();
    timer.shutdown();
  }

  void recalc_round_timestamp(utime_t& ts) {
    round_timestamp = ts.round_to_minute();
  }

  void insert_user(utime_t& timestamp, const rgw_user& user, rgw_usage_log_entry& entry, bool is_intranet_addr = false) {
    lock.Lock();
    if (timestamp.sec() > round_timestamp + cct->_conf->rgw_usage_entry_add_threshold)
      recalc_round_timestamp(timestamp);
    entry.epoch = round_timestamp.sec();
    bool account;
    string u = user.to_str();
    rgw_user_bucket ub(u, entry.bucket);
    real_time rt = round_timestamp.to_real_time();
    usage_map[ub].insert(rt, entry, &account, is_intranet_addr);
    if (account)
      num_entries++;
    bool need_flush = (num_entries > cct->_conf->rgw_usage_log_flush_threshold);
    lock.Unlock();
    if (need_flush) {
      Mutex::Locker l(timer_lock);
      flush();
    }
  }

  void insert(utime_t& timestamp, rgw_usage_log_entry& entry, bool is_intranet_addr = false) {
    if (entry.payer.empty()) {
      insert_user(timestamp, entry.owner, entry, is_intranet_addr);
    } else {
      insert_user(timestamp, entry.payer, entry, is_intranet_addr);
    }
  }

  void flush() {
    map<rgw_user_bucket, RGWUsageBatch> old_map;
    lock.Lock();
    old_map.swap(usage_map);
    num_entries = 0;
    lock.Unlock();

    store->log_usage(old_map);
  }

  void trim() {
    set<string> user_list;
    get_user_list(store, user_list);
    utime_t ts = ceph_clock_now().round_to_minute();
    uint64_t cur_epoch = ts.sec();

    set<string>::iterator it;
    for (it = user_list.begin(); it != user_list.end(); ++it) {
      rgw_user user("", *it);
      trim_usage(user, cur_epoch);
      trim_readop_usage(user, cur_epoch);
    }
  }

  void trim_usage(rgw_user& user, uint64_t cur_epoch) {
    uint64_t end_epoch = cur_epoch - cct->_conf->rgw_usage_log_trim_time_wait; // trim log 7 days before
    store->trim_usage(user, 0, end_epoch);
  }

  void trim_readop_usage(rgw_user& user, uint64_t cur_epoch) {
    uint64_t end_epoch = cur_epoch - cct->_conf->rgw_usage_log_readop_trim_time_wait; // trim log 30 days before
    store->trim_readop_usage(user, 0, end_epoch);
  }

  void init_whitelist() {
    whitelist_ip.clear();
    whitelist_segment.clear();

    string whitelist_config_value = cct->_conf->rgw_readop_usage_whitelist;
    boost::trim_all(whitelist_config_value);
    if (whitelist_config_value == "")
      return;

    vector<string> white_list;
    vector<string>::iterator wl_iter;
    boost::split(white_list, whitelist_config_value, boost::is_any_of(","));
    for (wl_iter = white_list.begin(); wl_iter != white_list.end(); ++wl_iter) {
      boost::trim_all(*wl_iter);
      string::size_type idx;
      idx = (*wl_iter).find('/');
      if (idx == string::npos) {
        whitelist_ip.insert(*wl_iter);
      } else {
        int mask = stoi((*wl_iter).substr(idx+1, (*wl_iter).size()-idx));
        string wl_string = (*wl_iter).substr(0, idx);
        uint64_t ip = change_ip_to_int(wl_string);
        uint64_t mask_num = change_mask_to_int(mask);
        whitelist_segment[*wl_iter] = pair<uint64_t, uint64_t>(ip, mask_num);
      }
    }
  }

  // check whitelist(for readop usage only)
  void check_remote_addr_in_whilelist(const struct req_state *s, bool& is_intranet_addr)
  {
    // get client ip
    const map<string, string, ltstr_nocase>& m = s->info.env->get_map();
    const auto remote_addr_param = s->cct->_conf->rgw_remote_addr_param;
    string remote_addr = "";
    if (remote_addr_param.length()) {
      map<string, string, ltstr_nocase>::const_iterator iter = m.find(remote_addr_param);
      if (iter != m.end()) {
        remote_addr = iter->second;
      }
    } else {
      map<string, string, ltstr_nocase>::const_iterator iter = m.find("REMOTE_ADDR");
      if (iter != m.end()) {
        remote_addr = iter->second;
      }
    }

    // check ip
    if (whitelist_ip.find(remote_addr) != whitelist_ip.end()) {
      is_intranet_addr = true;
      return;
    }

    // check segment
    pair<uint64_t, uint64_t> ip_mask_pair;
    map<string, pair<uint64_t, uint64_t> >::iterator seg_iter;
    for (seg_iter = whitelist_segment.begin(); seg_iter != whitelist_segment.end(); ++seg_iter) {
      ip_mask_pair = seg_iter->second;
      if (is_in_network_segment(remote_addr, ip_mask_pair)) {
        is_intranet_addr = true;
        return;
      }
    }
    is_intranet_addr = false;
  }
};

static UsageLogger *usage_logger = NULL;

void rgw_log_usage_init(CephContext *cct, RGWRados *store)
{
  usage_logger = new UsageLogger(cct, store);
}

void rgw_log_usage_finalize()
{
  delete usage_logger;
  usage_logger = NULL;
}

static void log_usage(struct req_state *s, const string& op_name)
{
  string user_name = s->user->user_id.to_str();
  if (s->system_request && MULTISITE_SYNC_USER != user_name) /* don't log system user operations */
    return;

  if (!usage_logger)
    return;

  rgw_user user;
  rgw_user payer;
  string bucket_name;

  bucket_name = s->bucket_name;

  if (MULTISITE_SYNC_USER == user_name) {
    user = s->user->user_id;
  } else if (!bucket_name.empty()) {
    user = s->bucket_owner.get_id();
    if (s->bucket_info.requester_pays) {
      payer = s->user->user_id;
    }
  } else {
      user = s->user->user_id;
  }

  bool error = s->err.is_err();
  if (error && s->err.http_ret == 404) {
    bucket_name = "-"; /* bucket not found, use the invalid '-' as bucket name */
  }

  string u = user.to_str();
  string p = payer.to_str();
  rgw_usage_log_entry entry(u, p, bucket_name);

  uint64_t bytes_sent = ACCOUNTING_IO(s)->get_bytes_sent();
  uint64_t bytes_received = ACCOUNTING_IO(s)->get_bytes_received();

  rgw_usage_data data(bytes_sent, bytes_received);

  data.ops = 1;
  if (!s->is_err())
    data.successful_ops = 1;

  ldout(s->cct, 30) << "log_usage: bucket_name=" << bucket_name
	<< " tenant=" << s->bucket_tenant
	<< ", bytes_sent=" << bytes_sent << ", bytes_received="
	<< bytes_received << ", success=" << data.successful_ops << dendl;

  entry.add(op_name, data);

  utime_t ts = ceph_clock_now();

  bool is_intranet_addr = false;

  if (MULTISITE_SYNC_USER != u) {
    usage_logger->check_remote_addr_in_whilelist(s, is_intranet_addr);
  }
  usage_logger->insert(ts, entry, is_intranet_addr);
}

bool is_in_network_segment(string& r_addr, pair<uint64_t, uint64_t>& ip_mask)
{
  uint64_t remote_ip = change_ip_to_int(r_addr);
  if ((remote_ip ^ ip_mask.first) & ip_mask.second) {
    return false;
  }
  return true;
}

uint64_t change_ip_to_int(string ip_addr) {
  uint64_t num = 0;
  uint64_t ip_num = 0;
  int j = 0;
  for(int i=0; i<3; ++i){
    int index = ip_addr.find('.', j);
    num = stoi(ip_addr.substr(j, index-j));
    ip_num = ip_num*256 + num;
    j = index + 1;
  }
  num = stoi(ip_addr.substr(j, ip_addr.size()-j));
  ip_num = ip_num*256 + num;
  return ip_num;
}

uint64_t change_mask_to_int(int mask) {
  uint64_t binary = 0;
  for (int i=0; i != mask; ++i) {
    binary += pow(2, 31-i);
  }
  return binary;
}

void rgw_format_ops_log_entry(struct rgw_log_entry& entry, Formatter *formatter)
{
  formatter->open_object_section("log_entry");
  formatter->dump_string("bucket", entry.bucket);
  {
    auto t = utime_t{entry.time};
    t.gmtime(formatter->dump_stream("time"));      // UTC
    t.localtime(formatter->dump_stream("time_local"));
  }
  formatter->dump_string("remote_addr", entry.remote_addr);
  string obj_owner = entry.object_owner.to_str();
  if (obj_owner.length())
    formatter->dump_string("object_owner", obj_owner);
  formatter->dump_string("user", entry.user);
  formatter->dump_string("operation", entry.op);
  formatter->dump_string("uri", entry.uri);
  formatter->dump_string("http_status", entry.http_status);
  formatter->dump_string("error_code", entry.error_code);
  formatter->dump_int("bytes_sent", entry.bytes_sent);
  formatter->dump_int("bytes_received", entry.bytes_received);
  formatter->dump_int("object_size", entry.obj_size);
  {
    using namespace std::chrono;
    uint64_t total_time = duration_cast<milliseconds>(entry.total_time).count();
    formatter->dump_int("total_time", total_time);
  }
  formatter->dump_string("user_agent",  entry.user_agent);
  formatter->dump_string("referrer",  entry.referrer);
  if (entry.x_headers.size() > 0) {
    formatter->open_array_section("http_x_headers");
    for (const auto& iter: entry.x_headers) {
      formatter->open_object_section(iter.first.c_str());
      formatter->dump_string(iter.first.c_str(), iter.second);
      formatter->close_section();
    }
    formatter->close_section();
  }
  formatter->close_section();
}

void OpsLogSocket::formatter_to_bl(bufferlist& bl)
{
  stringstream ss;
  formatter->flush(ss);
  const string& s = ss.str();

  bl.append(s);
}

void OpsLogSocket::init_connection(bufferlist& bl)
{
  bl.append("[");
}

OpsLogSocket::OpsLogSocket(CephContext *cct, uint64_t _backlog) : OutputDataSocket(cct, _backlog), lock("OpsLogSocket")
{
  formatter = new JSONFormatter;
  delim.append(",\n");
}

OpsLogSocket::~OpsLogSocket()
{
  delete formatter;
}

void OpsLogSocket::log(struct rgw_log_entry& entry)
{
  bufferlist bl;

  lock.Lock();
  rgw_format_ops_log_entry(entry, formatter);
  formatter_to_bl(bl);
  lock.Unlock();

  append_output(bl);
}

int rgw_log_op(RGWRados *store, RGWREST* const rest, struct req_state *s,
	       const string& op_name, OpsLogSocket *olog)
{
  struct rgw_log_entry entry;
  string bucket_id;

  if (s->enable_usage_log)
    log_usage(s, op_name);

  if (!s->enable_ops_log && !g_access_log)
    return 0;

  if (s->bucket_name.empty()) {
    ldout(s->cct, 5) << "nothing to log for operation" << dendl;
    return -EINVAL;
  }
  if (s->err.ret == -ERR_NO_SUCH_BUCKET) {
    if (!s->cct->_conf->rgw_log_nonexistent_bucket) {
      ldout(s->cct, 5) << "bucket " << s->bucket << " doesn't exist, not logging" << dendl;
      return 0;
    }
    bucket_id = "";
  } else {
    bucket_id = s->bucket.bucket_id;
  }
  rgw_make_bucket_entry_name(s->bucket_tenant, s->bucket_name, entry.bucket);

  if (check_utf8(entry.bucket.c_str(), entry.bucket.size()) != 0) {
    ldout(s->cct, 5) << "not logging op on bucket with non-utf8 name" << dendl;
    return 0;
  }

  if (!s->object.empty()) {
    entry.obj = s->object;
  } else {
    entry.obj = rgw_obj_key("-"sv);
  }

  entry.obj_size = s->obj_size;

  if (s->cct->_conf->rgw_remote_addr_param.length())
    set_param_str(s, s->cct->_conf->rgw_remote_addr_param.c_str(),
		  entry.remote_addr);
  else
    set_param_str(s, "REMOTE_ADDR", entry.remote_addr);
  set_param_str(s, "HTTP_USER_AGENT", entry.user_agent);
  // legacy apps are still using misspelling referer, such as curl -e option
  if (s->info.env->exists("HTTP_REFERRER"))
    set_param_str(s, "HTTP_REFERRER", entry.referrer);
  else
    set_param_str(s, "HTTP_REFERER", entry.referrer);

  std::string uri;
  if (s->info.env->exists("REQUEST_METHOD")) {
    uri.append(s->info.env->get("REQUEST_METHOD"));
    uri.append(" ");
  }

  if (s->info.env->exists("REQUEST_URI")) {
    uri.append(s->info.env->get("REQUEST_URI"));
  }

  if (s->info.env->exists("QUERY_STRING")) {
    const char* qs = s->info.env->get("QUERY_STRING");
    if(qs && (*qs != '\0')) {
      uri.append("?");
      uri.append(qs);
    }
  }

  if (s->info.env->exists("HTTP_VERSION")) {
    uri.append(" ");
    uri.append("HTTP/");
    uri.append(s->info.env->get("HTTP_VERSION"));
  }

  entry.uri = std::move(uri);

  set_param_str(s, "REQUEST_METHOD", entry.op);

  /* custom header logging */
  if (rest) {
    if (rest->log_x_headers()) {
      for (const auto& iter : s->info.env->get_map()) {
	if (rest->log_x_header(iter.first)) {
	  entry.x_headers.insert(
	    rgw_log_entry::headers_map::value_type(iter.first, iter.second));
	}
      }
    }
  }

  entry.user = s->user->user_id.to_str();
  if (s->object_acl)
    entry.object_owner = s->object_acl->get_owner().get_id();
  entry.bucket_owner = s->bucket_owner.get_id();

  uint64_t bytes_sent = ACCOUNTING_IO(s)->get_bytes_sent()  + s->symlink_size_out;
  uint64_t bytes_received = ACCOUNTING_IO(s)->get_bytes_received()  + s->symlink_size_in;

  entry.time = s->time;
  entry.total_time = s->time_elapsed();
  entry.bytes_sent = bytes_sent;
  entry.bytes_received = bytes_received;
  if (s->err.http_ret) {
    char buf[16];
    snprintf(buf, sizeof(buf), "%d", s->err.http_ret);
    entry.http_status = buf;
  } else
    entry.http_status = "200"; // default

  entry.error_code = s->err.err_code;
  entry.bucket_id = bucket_id;

  // print rgw access log
  if (g_access_log) {

#if defined(WITH_BCEBOS) && defined(WITH_BCEIAM)
    if (s->cct->_conf->rgw_bos_format_access_log) {
      static map<int, string> bos_cmd = {
        {RGW_OP_GET_OBJ, "API_OBJECT_GET"},
        {RGW_OP_LIST_BUCKETS, "API_BUCKET_LIST"},
        {RGW_OP_STAT_ACCOUNT, "RGW_OP_STAT_ACCOUNT"},
        {RGW_OP_LIST_BUCKET, "API_BUCKET_GET"},
        {RGW_OP_GET_BUCKET_LOGGING, "API_BUCKET_GET_LOGGING"},
        {RGW_OP_PUT_BUCKET_LOGGING, "API_BUCKET_PUT_LOGGING"},
        {RGW_OP_DELETE_BUCKET_LOGGING, "API_BUCKET_DELETE_LOGGING"},
        {RGW_OP_GET_BUCKET_LOCATION, "API_BUCKET_GET_LOCATION"},
        {RGW_OP_GET_BUCKET_VERSIONING, "API_BUCKET_VERSIONING_GET"},
        {RGW_OP_SET_BUCKET_VERSIONING, "API_BUCKET_VERSIONING_PUT"},
        {RGW_OP_GET_BUCKET_WEBSITE, "API_BUCKET_STATIC_WEB_SITE_GET"},
        {RGW_OP_SET_BUCKET_WEBSITE, "API_BUCKET_STATIC_WEB_SITE_PUT"},
        {RGW_OP_STAT_BUCKET, "API_BUCKET_HEAD"},
        {RGW_OP_CREATE_BUCKET, "API_BUCKET_PUT"},
        {RGW_OP_DELETE_BUCKET, "API_BUCKET_DELETE"},
        {RGW_OP_PUT_OBJ, "API_OBJECT_PUT"},
        {RGW_OP_STAT_OBJ, "API_OBJECT_HEAD"},
        {RGW_OP_POST_OBJ, "API_OBJECT_POST"},
        {RGW_OP_DELETE_OBJ, "API_OBJECT_DELETE"},
        {RGW_OP_COPY_OBJ, "API_OBJECT_COPY"},
        {RGW_OP_RENAME_OBJ, "API_OBJECT_RENAME"},
        {RGW_OP_GET_ACLS, "BOSS_API_OBJECT_ACL_GET"},
        {RGW_OP_PUT_ACLS, "BOSS_API_OBJECT_ACL_PUT"},
        {RGW_OP_DELETE_ACLS, "BOSS_API_OBJECT_ACL_DELETE"},
        {RGW_OP_PUT_BUCKET_POLICY, "API_BUCKET_ACL_PUT"},
        {RGW_OP_GET_BUCKET_POLICY, "API_BUCKET_ACL_GET"},
        {RGW_OP_GET_CORS, "API_BUCKET_CORS_GET"},
        {RGW_OP_PUT_CORS, "API_BUCKET_CORS_PUT"},
        {RGW_OP_DELETE_CORS, "API_BUCKET_CORS_DELETE"},
        {RGW_OP_OPTIONS_CORS, "API_BUCKET_CORS_OPTIONS"},
        {RGW_OP_GET_REQUEST_PAYMENT, "API_BUCKET_REQUEST_PAYMENT_GET"},
        {RGW_OP_SET_REQUEST_PAYMENT, "API_BUCKET_REQUEST_PAYMENT_PUT"},
        {RGW_OP_INIT_MULTIPART, "API_OBJECT_MULTI_INIT"},
        {RGW_OP_COMPLETE_MULTIPART, "API_OBJECT_MULTI_COMPLETE"},
        {RGW_OP_ABORT_MULTIPART, "API_OBJECT_MULTI_ABORT"},
        {RGW_OP_LIST_MULTIPART, "API_OBJECT_LIST_PART"},
        {RGW_OP_LIST_BUCKET_MULTIPARTS, "API_OBJECT_LIST_MULTI"},
        {RGW_OP_DELETE_MULTI_OBJ, "API_OBJECT_MULTIPLE_DELETE"},
        {RGW_OP_PUT_LC, "API_BUCKET_LIFECYCLE_PUT"},
        {RGW_OP_GET_LC, "API_BUCKET_LIFECYCLE_GET"},
        {RGW_OP_DELETE_LC, "API_BUCKET_LIFECYCLE_DELETE"},
        {RGW_OP_PUT_BUCKET_MIRRORING, "API_BUCKET_MIRRORING_PUT"},
        {RGW_OP_GET_BUCKET_MIRRORING, "API_BUCKET_MIRRORING_GET"},
        {RGW_OP_GET_BUCKET_OBJ_LOCK, "API_BUCKET_OBJECT_LOCK_GET"},
        {RGW_OP_INIT_BUCKET_OBJ_LOCK, "API_BUCKET_OBJECT_LOCK_INIT"},
        {RGW_OP_DELETE_BUCKET_OBJ_LOCK, "API_BUCKET_OBJECT_LOCK_DELETE"},
        {RGW_OP_COMPLETE_BUCKET_OBJ_LOCK, "API_BUCKET_OBJECT_LOCK_COMPLETE"},
        {RGW_OP_EXTEND_BUCKET_OBJ_LOCK, "API_BUCKET_OBJECT_LOCK_EXTEND"},
        {RGW_OP_GET_BUCKET_TRASH, "API_BUCKET_TRASH_GET"},
        {RGW_OP_PUT_BUCKET_TRASH, "API_BUCKET_TRASH_PUT"},
        {RGW_OP_DELETE_BUCKET_TRASH, "API_BUCKET_TRASH_DELETE"},
        {RGW_OP_PUT_SYMLINK_OBJ, "API_OBJECT_SYMLINK_PUT"},
        {RGW_OP_GET_SYMLINK_OBJ, "API_OBJECT_SYMLINK_GET"}
      };
      if (s->dest_placement.storage_class == "STANDARD") {
        entry.storage_class = "bos";
      } else if (s->dest_placement.storage_class == "STANDARD_IA") {
        entry.storage_class = "bosIA";
      } else {
        entry.storage_class = s->dest_placement.storage_class;
      }

      auto cmd_iter = bos_cmd.find(s->op_type);
      if (cmd_iter != bos_cmd.end()) {
        entry.bos_op = cmd_iter->second;
      } else {
        entry.bos_op = "API_UNDEFINED";
      }

      string bos_time;
      double bos_cost = entry.total_time.count() / 1e9;
      ceph::real_time real_time = ceph::real_clock::now() + chrono::hours(8);
      rgw_to_iso8601(real_time, &bos_time);
      ceph::logging::Entry *_dout_bos_e = g_access_log->create_entry(0, dout_subsys, nullptr, false);
      std::ostream* _dout_bos = &_dout_bos_e->get_ostream();
      *_dout_bos << "[NOTICE] " << string_view(bos_time).substr(0, bos_time.size() -1)
           << "+08:00" << " remote_addr=" << entry.remote_addr
           << " status=" << entry.http_status << " owner_id=" << entry.bucket_owner
           << " user_id=" << entry.user << " bucket=" << entry.bucket
           << " client=" << entry.remote_addr << " bytes_in=" << bytes_received
           << " bytes_out=" << bytes_sent << " method=" << entry.op
           << " request_id=" << s->trans_id << " request=\"" << entry.uri
           << "\" errmsg=\"" << entry.error_code << "\" user_agent=\"" << entry.user_agent
           << "\" referer=\"" << entry.referrer << "\" bucket_id=" << entry.bucket_id
           << " service=" << entry.storage_class << " turn_around_time="  << bos_cost
           << " time_gap=" << bos_cost << " object=\"" << entry.obj << "\""
           << " object_size=" << (entry.obj_size != 0 ? std::to_string(entry.obj_size) : string_view("-"))
           << " cmd=" << entry.bos_op << std::flush;
      g_access_log->submit_entry(_dout_bos_e);
    }
#else
    {
      static size_t _log_exp_length = 80;
      ceph::logging::Entry *_dout_e = g_access_log->create_entry(0, dout_subsys, &_log_exp_length);
      std::ostream* _dout = &_dout_e->get_ostream();
      *_dout << " remote_addr=" << entry.remote_addr << " req=" << s->trans_id
             << " method=" << entry.op << " status=" <<  entry.http_status
             << " user_id=" << entry.user << " bucket=" << entry.bucket
             << " bucket_id=" << entry.bucket_id << " bucket_owner=" << entry.bucket_owner
             << " object=" << entry.obj << " obj_size=" << entry.obj_size
             << " request=\"" << entry.uri << "\" bytes_out=" << bytes_sent
             << " bytes_in=" << bytes_received << " cost=" << entry.total_time
             << " code=\""  << entry.error_code << "\" user_agent=\"" << entry.user_agent
             << "\" referrer=\"" << entry.referrer << "\""
             << std::flush;
      g_access_log->submit_entry(_dout_e);
    }
#endif
  }

  if (!s->enable_ops_log)
    return 0;

  bufferlist bl;
  encode(entry, bl);

  struct tm bdt;
  time_t t = req_state::Clock::to_time_t(entry.time);
  if (s->cct->_conf->rgw_log_object_name_utc)
    gmtime_r(&t, &bdt);
  else
    localtime_r(&t, &bdt);

  int ret = 0;

  if (s->cct->_conf->rgw_ops_log_rados) {
    string oid = render_log_object_name(s->cct->_conf->rgw_log_object_name, &bdt,
				        s->bucket.bucket_id, entry.bucket);

    rgw_raw_obj obj(store->get_zone_params().log_pool, oid);

    ret = store->append_async(obj, bl.length(), bl);
    if (ret == -ENOENT) {
      ret = store->create_pool(store->get_zone_params().log_pool);
      if (ret < 0)
        goto done;
      // retry
      ret = store->append_async(obj, bl.length(), bl);
    }
  }

  if (olog) {
    olog->log(entry);
  }
done:
  if (ret < 0)
    ldout(s->cct, 0) << "ERROR: failed to log entry" << dendl;

  return ret;
}

