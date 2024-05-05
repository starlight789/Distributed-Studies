// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include "include/compat.h"
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <boost/algorithm/string.hpp>

#include <boost/format.hpp>
#include <boost/optional.hpp>
#include <boost/utility/in_place_factory.hpp>
#ifdef WITH_RADOSGW_BEAST_FRONTEND
#include "asio_sync.hpp"
#endif

#include "common/ceph_json.h"
#include "common/utf8.h"

#include "common/errno.h"
#include "common/Formatter.h"
#include "common/Throttle.h"
#include "common/Finisher.h"

#include "rgw_rados.h"
#include "rgw_cache.h"
#include "rgw_acl.h"
#include "rgw_acl_s3.h" /* for dumping s3policy in debug log */
#include "rgw_metadata.h"
#include "rgw_bucket.h"
#include "rgw_rest_conn.h"
#include "rgw_cr_rados.h"
#include "rgw_cr_rest.h"
#include "rgw_async_request.h"

#include "cls/rgw/cls_rgw_ops.h"
#include "cls/rgw/cls_rgw_types.h"
#include "cls/rgw/cls_rgw_client.h"
#include "cls/rgw/cls_rgw_const.h"
#include "cls/refcount/cls_refcount_client.h"
#include "cls/version/cls_version_client.h"
#include "cls/log/cls_log_client.h"
#include "cls/statelog/cls_statelog_client.h"
#include "cls/timeindex/cls_timeindex_client.h"
#include "cls/lock/cls_lock_client.h"
#include "cls/user/cls_user_client.h"
#include "cls/otp/cls_otp_client.h"
#include "osd/osd_types.h"

#include "rgw_tools.h"
#include "rgw_coroutine.h"
#include "rgw_compression.h"

#undef fork // fails to compile RGWPeriod::fork() below

#include "common/Clock.h"

#include "include/rados/librados.hpp"
using namespace librados;

#include <string>
#include <iostream>
#include <vector>
#include <atomic>
#include <list>
#include <map>
#include "include/random.h"

#include "rgw_log.h"

#include "rgw_gc.h"
#include "rgw_lc.h"

#include "rgw_object_expirer_core.h"
#include "rgw_sync.h"
#include "rgw_sync_trace.h"
#include "rgw_data_sync.h"
#include "rgw_realm_watcher.h"
#include "rgw_reshard.h"
#include "rgw/rgw_crypt.h"

#include "compressor/Compressor.h"

#ifdef WITH_LTTNG
#define TRACEPOINT_DEFINE
#define TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#include "tracing/rgw_rados.h"
#undef TRACEPOINT_PROBE_DYNAMIC_LINKAGE
#undef TRACEPOINT_DEFINE
#else
#define tracepoint(...)
#endif

#define dout_context g_ceph_context
#define dout_subsys ceph_subsys_rgw


static string notify_oid_prefix = "notify";
static string *notify_oids = NULL;
static string shadow_ns = "shadow";
static string dir_oid_prefix = ".dir.";
static string default_storage_pool_suffix = "rgw.buckets.data";
static string default_bucket_index_pool_suffix = "rgw.buckets.index";
static string default_storage_extra_pool_suffix = "rgw.buckets.non-ec";
static string avail_pools = ".pools.avail";

static string zone_info_oid_prefix = "zone_info.";
static string zone_names_oid_prefix = "zone_names.";
static string region_info_oid_prefix = "region_info.";
static string zone_group_info_oid_prefix = "zonegroup_info.";
static string realm_names_oid_prefix = "realms_names.";
static string realm_info_oid_prefix = "realms.";
static string default_region_info_oid = "default.region";
static string default_zone_group_info_oid = "default.zonegroup";
static string period_info_oid_prefix = "periods.";
static string period_latest_epoch_info_oid = ".latest_epoch";
static string region_map_oid = "region_map";
static string zonegroup_map_oid = "zonegroup_map";
static string log_lock_name = "rgw_log_lock";
static string default_realm_info_oid = "default.realm";
const string default_zonegroup_name = "default";
const string default_zone_name = "default";
static string zonegroup_names_oid_prefix = "zonegroups_names.";
static string todelete_bucket_instance_oid_prefix = "todelete_info.";
static RGWObjCategory main_category = RGW_OBJ_CATEGORY_MAIN;
#define RGW_USAGE_OBJ_PREFIX "usage."
#define FIRST_EPOCH 1
static string RGW_DEFAULT_ZONE_ROOT_POOL = "rgw.root";
static string RGW_DEFAULT_ZONEGROUP_ROOT_POOL = "rgw.root";
static string RGW_DEFAULT_REALM_ROOT_POOL = "rgw.root";
static string RGW_DEFAULT_PERIOD_ROOT_POOL = "rgw.root";


#define RGW_STATELOG_OBJ_PREFIX "statelog."

#define dout_subsys ceph_subsys_rgw

// split filepath by '/'
// /a : {a}
//  a : {a}
// /a/b/c : {a, b, c}
static int namespace_split_filepath(const string& name, vector<string_extent>& names)
{
  size_t extent_index = 0;
  size_t pos = 0;
  size_t last_pos = 0;

  names.clear();

  while (last_pos < name.length() &&
        (pos = name.find(S3_PATH_DELIMITER, last_pos)) != string::npos) {

    // like path /a/b
    if (pos == 0) {
      last_pos = pos + 1;
      continue;
    }

    size_t dir_len = pos - last_pos;
    if (dir_len > 0) {
      if (names.size() <= extent_index) {
          names.resize(extent_index + 2);
      }
      names[extent_index].offset = last_pos;
      names[extent_index].length = dir_len;
      ++extent_index;
    }
    last_pos = pos + 1;
  }

  // like path /a/b/c
  if (last_pos < name.length()) {
    size_t dir_len = name.length() - last_pos;
    if (dir_len > 0) {
      if (names.size() <= extent_index) {
          names.resize(extent_index + 2);
      }
      names[extent_index].offset = last_pos;
      names[extent_index].length = dir_len;
      ++extent_index;
    }
  }

  return extent_index;
}

// get dir oid
static inline string namespace_get_parent_oid(const string& bucket_marker,
                                              const string& parent_name, int level) {
  return "nesp." + bucket_marker + "|" + std::to_string(level) + "|" + parent_name;
}

// get the parent name of level
static inline string namespace_cut_parent_path(const string& name,
                                               vector<string_extent> &names, size_t level) {
  assert(level <= names.size());
  string parent_name = "";
  size_t i = 0;
  while (i < level) {
    parent_name.append(name, names[i].offset, names[i].length);
    ++i;
    if (i < level) {
      parent_name.append(S3_PATH_DELIMITER);
    }
  }
  return parent_name;
}

static bool rgw_get_obj_data_pool(const RGWZoneGroup& zonegroup, const RGWZoneParams& zone_params,
                                  const rgw_placement_rule& placement_rule, const rgw_obj& obj, rgw_pool *pool)
{
  if (!zone_params.get_data_pool(placement_rule, obj, pool)) {
    RGWZonePlacementInfo placement;
    if (!zone_params.get_placement(zonegroup.default_placement.name, &placement)) {
      return false;
    }

    if (!obj.in_extra_data) {
      *pool = placement.get_data_pool(zonegroup.default_placement.storage_class);
    } else {
      *pool = placement.get_data_extra_pool();
    }
  }

  return true;
}

static bool rgw_obj_to_raw(const RGWZoneGroup& zonegroup, const RGWZoneParams& zone_params,
                           const rgw_placement_rule& placement_rule, const rgw_obj& obj, rgw_raw_obj *raw_obj)
{
  get_obj_bucket_and_oid_loc(obj, raw_obj->oid, raw_obj->loc);

  return rgw_get_obj_data_pool(zonegroup, zone_params, placement_rule, obj, &raw_obj->pool);
}

rgw_raw_obj rgw_obj_select::get_raw_obj(const RGWZoneGroup& zonegroup, const RGWZoneParams& zone_params) const
{
  if (!is_raw) {
    rgw_raw_obj r;
    rgw_obj_to_raw(zonegroup, zone_params, placement_rule, obj, &r);
    return r;
  }
  return raw_obj;
}

rgw_raw_obj rgw_obj_select::get_raw_obj(RGWRados *store) const
{
  if (!is_raw) {
    rgw_raw_obj r;
    store->obj_to_raw(placement_rule, obj, &r);
    return r;
  }
  return raw_obj;
}

int rgw_init_ioctx(librados::Rados *rados, const rgw_pool& pool, IoCtx& ioctx, bool create)
{
  int r = rados->ioctx_create(pool.name.c_str(), ioctx);
  if (r == -ENOENT && create) {
    r = rados->pool_create(pool.name.c_str());
    if (r == -ERANGE) {
      dout(0)
        << __func__
        << " ERROR: librados::Rados::pool_create returned " << cpp_strerror(-r)
        << " (this can be due to a pool or placement group misconfiguration, e.g."
        << " pg_num < pgp_num or mon_max_pg_per_osd exceeded)"
        << dendl;
    }
    if (r < 0 && r != -EEXIST) {
      return r;
    }

    r = rados->ioctx_create(pool.name.c_str(), ioctx);
    if (r < 0) {
      return r;
    }

    r = ioctx.application_enable(pg_pool_t::APPLICATION_NAME_RGW, false);
    if (r < 0 && r != -EOPNOTSUPP) {
      return r;
    }
  } else if (r < 0) {
    return r;
  }
  if (!pool.ns.empty()) {
    ioctx.set_namespace(pool.ns);
  }
  return 0;
}

template<>
void RGWObjectCtxImpl<rgw_obj, RGWObjState>::invalidate(rgw_obj& obj) {
  dout(20) << __func__ << "() invalidate obj from objs_state:" << obj << dendl;
  RWLock::WLocker wl(lock);
  auto iter = objs_state.find(obj);
  if (iter == objs_state.end()) {
    return;
  }
  bool is_atomic = iter->second.is_atomic;
  bool prefetch_data = iter->second.prefetch_data;

  objs_state.erase(iter);

  if (is_atomic || prefetch_data) {
    auto& s = objs_state[obj];
    s.is_atomic = is_atomic;
    s.prefetch_data = prefetch_data;
  }
}

template<>
void RGWObjectCtxImpl<rgw_raw_obj, RGWRawObjState>::invalidate(rgw_raw_obj& obj) {
  RWLock::WLocker wl(lock);
  auto iter = objs_state.find(obj);
  if (iter == objs_state.end()) {
    return;
  }

  objs_state.erase(iter);
}

void RGWDefaultZoneGroupInfo::dump(Formatter *f) const {
  encode_json("default_zonegroup", default_zonegroup, f);
}

void RGWDefaultZoneGroupInfo::decode_json(JSONObj *obj) {

  JSONDecoder::decode_json("default_zonegroup", default_zonegroup, obj);
  /* backward compatability with region */
  if (default_zonegroup.empty()) {
    JSONDecoder::decode_json("default_region", default_zonegroup, obj);
  }
}

rgw_pool RGWZoneGroup::get_pool(CephContext *cct_)
{
  if (cct_->_conf->rgw_zonegroup_root_pool.empty()) {
    return rgw_pool(RGW_DEFAULT_ZONEGROUP_ROOT_POOL);
  }

  return rgw_pool(cct_->_conf->rgw_zonegroup_root_pool);
}

int RGWZoneGroup::create_default(bool old_format)
{
  name = default_zonegroup_name;
  is_master = true;

  RGWZoneGroupPlacementTarget placement_target;
  placement_target.name = "default-placement";
  placement_targets[placement_target.name] = placement_target;
  default_placement.name = "default-placement";

  RGWZoneParams zone_params(default_zone_name);

  int r = zone_params.init(cct, store, false);
  if (r < 0) {
    ldout(cct, 0) << "create_default: error initializing zone params: " << cpp_strerror(-r) << dendl;
    return r;
  }

  r = zone_params.create_default();
  if (r < 0 && r != -EEXIST) {
    ldout(cct, 0) << "create_default: error in create_default  zone params: " << cpp_strerror(-r) << dendl;
    return r;
  } else if (r == -EEXIST) {
    ldout(cct, 10) << "zone_params::create_default() returned -EEXIST, we raced with another default zone_params creation" << dendl;
    zone_params.clear_id();
    r = zone_params.init(cct, store);
    if (r < 0) {
      ldout(cct, 0) << "create_default: error in init existing zone params: " << cpp_strerror(-r) << dendl;
      return r;
    }
    ldout(cct, 20) << "zone_params::create_default() " << zone_params.get_name() << " id " << zone_params.get_id()
		   << dendl;
  }
  
  RGWZone& default_zone = zones[zone_params.get_id()];
  default_zone.name = zone_params.get_name();
  default_zone.id = zone_params.get_id();
  master_zone = default_zone.id;
  
  r = create();
  if (r < 0 && r != -EEXIST) {
    ldout(cct, 0) << "error storing zone group info: " << cpp_strerror(-r) << dendl;
    return r;
  }

  if (r == -EEXIST) {
    ldout(cct, 10) << "create_default() returned -EEXIST, we raced with another zonegroup creation" << dendl;
    id.clear();
    r = init(cct, store);
    if (r < 0) {
      return r;
    }
  }

  if (old_format) {
    name = id;
  }

  post_process_params();

  return 0;
}

const string RGWZoneGroup::get_default_oid(bool old_region_format)
{
  if (old_region_format) {
    if (cct->_conf->rgw_default_region_info_oid.empty()) {
      return default_region_info_oid;
    }
    return cct->_conf->rgw_default_region_info_oid;
  }

  string default_oid = cct->_conf->rgw_default_zonegroup_info_oid;

  if (cct->_conf->rgw_default_zonegroup_info_oid.empty()) {
    default_oid = default_zone_group_info_oid;
  }

  default_oid += "." + realm_id;

  return default_oid;
}

const string& RGWZoneGroup::get_info_oid_prefix(bool old_region_format)
{
  if (old_region_format) {
    return region_info_oid_prefix;
  }
  return zone_group_info_oid_prefix;
}

const string& RGWZoneGroup::get_names_oid_prefix()
{
  return zonegroup_names_oid_prefix;
}

const string& RGWZoneGroup::get_predefined_name(CephContext *cct) {
  return cct->_conf->rgw_zonegroup;
}

int RGWZoneGroup::equals(const string& other_zonegroup) const
{
  if (is_master && other_zonegroup.empty())
    return true;

  return (id  == other_zonegroup);
}

int RGWZoneGroup::add_zone(const RGWZoneParams& zone_params, bool *is_master, bool *read_only,
                           const list<string>& endpoints, const string *ptier_type,
                           bool *psync_from_all, list<string>& sync_from, list<string>& sync_from_rm,
                           string *predirect_zone)
{
  auto& zone_id = zone_params.get_id();
  auto& zone_name = zone_params.get_name();

  // check for duplicate zone name on insert
  if (!zones.count(zone_id)) {
    for (const auto& zone : zones) {
      if (zone.second.name == zone_name) {
        ldout(cct, 0) << "ERROR: found existing zone name " << zone_name
            << " (" << zone.first << ") in zonegroup " << get_name() << dendl;
        return -EEXIST;
      }
    }
  }

  if (is_master) {
    if (*is_master) {
      if (!master_zone.empty() && master_zone != zone_id) {
        ldout(cct, 0) << "NOTICE: overriding master zone: " << master_zone << dendl;
      }
      master_zone = zone_id;
    } else if (master_zone == zone_id) {
      master_zone.clear();
    }
  }

  RGWZone& zone = zones[zone_id];
  zone.name = zone_name;
  zone.id = zone_id;
  if (!endpoints.empty()) {
    zone.endpoints = endpoints;
  }
  if (read_only) {
    zone.read_only = *read_only;
  }
  if (ptier_type) {
    zone.tier_type = *ptier_type;
    if (!store->get_sync_modules_manager()->get_module(*ptier_type, nullptr)) {
      ldout(cct, 0) << "ERROR: could not found sync module: " << *ptier_type 
                    << ",  valid sync modules: " 
                    << store->get_sync_modules_manager()->get_registered_module_names()
                    << dendl;
      return -ENOENT;
    }
  }

  if (psync_from_all) {
    zone.sync_from_all = *psync_from_all;
  }

  if (predirect_zone) {
    zone.redirect_zone = *predirect_zone;
  }

  for (auto add : sync_from) {
    zone.sync_from.insert(add);
  }

  for (auto rm : sync_from_rm) {
    zone.sync_from.erase(rm);
  }

  post_process_params();

  return update();
}


int RGWZoneGroup::rename_zone(const RGWZoneParams& zone_params)
{ 
  RGWZone& zone = zones[zone_params.get_id()];
  zone.name = zone_params.get_name();
  
  return update();
}

void RGWZoneGroup::post_process_params()
{
  bool log_data = zones.size() > 1;

  if (master_zone.empty()) {
    map<string, RGWZone>::iterator iter = zones.begin();
    if (iter != zones.end()) {
      master_zone = iter->first;
    }
  }
  
  for (map<string, RGWZone>::iterator iter = zones.begin(); iter != zones.end(); ++iter) {
    RGWZone& zone = iter->second;
    zone.log_data = log_data;

    RGWZoneParams zone_params(zone.id, zone.name);
    int ret = zone_params.init(cct, store);
    if (ret < 0) {
      ldout(cct, 0) << "WARNING: could not read zone params for zone id=" << zone.id << " name=" << zone.name << dendl;
      continue;
    }

    for (map<string, RGWZonePlacementInfo>::iterator iter = zone_params.placement_pools.begin(); 
         iter != zone_params.placement_pools.end(); ++iter) {
      const string& placement_name = iter->first;
      if (placement_targets.find(placement_name) == placement_targets.end()) {
        RGWZoneGroupPlacementTarget placement_target;
        placement_target.name = placement_name;
        placement_targets[placement_name] = placement_target;
      }
    }
  }

  if (default_placement.empty() && !placement_targets.empty()) {
    default_placement.name = placement_targets.begin()->first;
  }
}

int RGWZoneGroup::remove_zone(const std::string& zone_id)
{
  map<string, RGWZone>::iterator iter = zones.find(zone_id);
  if (iter == zones.end()) {
    ldout(cct, 0) << "zone id " << zone_id << " is not a part of zonegroup "
        << name << dendl;
    return -ENOENT;
  }

  zones.erase(iter);

  post_process_params();

  return update();
}

int RGWZoneGroup::read_default_id(string& default_id, bool old_format)
{
  if (realm_id.empty()) {
    /* try using default realm */
    RGWRealm realm;
    int ret = realm.init(cct, store);
    // no default realm exist
    if (ret < 0) {
      return read_id(default_zonegroup_name, default_id);
    }
    realm_id = realm.get_id();
  }

  return RGWSystemMetaObj::read_default_id(default_id, old_format);
}

int RGWZoneGroup::set_as_default(bool exclusive)
{
  if (realm_id.empty()) {
    /* try using default realm */
    RGWRealm realm;
    int ret = realm.init(cct, store);
    if (ret < 0) {
      ldout(cct, 10) << "could not read realm id: " << cpp_strerror(-ret) << dendl;
      return -EINVAL;
    }
    realm_id = realm.get_id();
  }

  return RGWSystemMetaObj::set_as_default(exclusive);
}

int RGWSystemMetaObj::init(CephContext *_cct, RGWRados *_store, bool setup_obj, bool old_format)
{
  cct = _cct;
  store = _store;

  if (!setup_obj)
    return 0;

  if (old_format && id.empty()) {
    id = name;
  }

  if (id.empty()) {
    int r;
    if (name.empty()) {
      name = get_predefined_name(cct);
    }
    if (name.empty()) {
      r = use_default(old_format);
      if (r < 0) {
	return r;
      }
    } else if (!old_format) {
      r = read_id(name, id);
      if (r < 0) {
        if (r != -ENOENT) {
          ldout(cct, 0) << "error in read_id for object name: " << name << " : " << cpp_strerror(-r) << dendl;
        }
        return r;
      }
    }
  }

  return read_info(id, old_format);
}

int RGWSystemMetaObj::read_default(RGWDefaultSystemMetaObjInfo& default_info, const string& oid)
{
  using ceph::decode;
  auto pool = get_pool(cct);
  bufferlist bl;
  RGWObjectCtx obj_ctx(store);
  int ret = rgw_get_system_obj(store, obj_ctx, pool, oid, bl, NULL, NULL);
  if (ret < 0)
    return ret;

  try {
    bufferlist::iterator iter = bl.begin();
    decode(default_info, iter);
  } catch (buffer::error& err) {
    ldout(cct, 0) << "error decoding data from " << pool << ":" << oid << dendl;
    return -EIO;
  }

  return 0;
}

int RGWSystemMetaObj::read_default_id(string& default_id, bool old_format)
{
  RGWDefaultSystemMetaObjInfo default_info;

  int ret = read_default(default_info, get_default_oid(old_format));
  if (ret < 0) {
    return ret;
  }

  default_id = default_info.default_id;

  return 0;
}

int RGWSystemMetaObj::use_default(bool old_format)
{
  return read_default_id(id, old_format);
}

int RGWSystemMetaObj::set_as_default(bool exclusive)
{
  using ceph::encode;
  string oid  = get_default_oid();

  rgw_pool pool(get_pool(cct));
  bufferlist bl;

  RGWDefaultSystemMetaObjInfo default_info;
  default_info.default_id = id;

  encode(default_info, bl);

  int ret = rgw_put_system_obj(store, pool, oid, bl,
                               exclusive, NULL, real_time(), NULL);
  if (ret < 0)
    return ret;

  return 0;
}

int RGWSystemMetaObj::read_id(const string& obj_name, string& object_id)
{
  using ceph::decode;
  rgw_pool pool(get_pool(cct));
  bufferlist bl;

  string oid = get_names_oid_prefix() + obj_name;

  RGWObjectCtx obj_ctx(store);
  int ret = rgw_get_system_obj(store, obj_ctx, pool, oid, bl, NULL, NULL);
  if (ret < 0) {
    return ret;
  }

  RGWNameToId nameToId;
  try {
    bufferlist::iterator iter = bl.begin();
    decode(nameToId, iter);
  } catch (buffer::error& err) {
    ldout(cct, 0) << "ERROR: failed to decode obj from " << pool << ":" << oid << dendl;
    return -EIO;
  }
  object_id = nameToId.obj_id;
  return 0;
}

int RGWSystemMetaObj::delete_obj(bool old_format)
{
  rgw_pool pool(get_pool(cct));

  /* check to see if obj is the default */
  RGWDefaultSystemMetaObjInfo default_info;
  int ret = read_default(default_info, get_default_oid(old_format));
  if (ret < 0 && ret != -ENOENT)
    return ret;
  if (default_info.default_id == id || (old_format && default_info.default_id == name)) {
    string oid = get_default_oid(old_format);
    rgw_raw_obj default_named_obj(pool, oid);
    ret = store->delete_system_obj(default_named_obj);
    if (ret < 0) {
      ldout(cct, 0) << "Error delete default obj name  " << name << ": " << cpp_strerror(-ret) << dendl;
      return ret;
    }
  }
  if (!old_format) {
    string oid  = get_names_oid_prefix() + name;
    rgw_raw_obj object_name(pool, oid);
    ret = store->delete_system_obj(object_name);
    if (ret < 0) {
      ldout(cct, 0) << "Error delete obj name  " << name << ": " << cpp_strerror(-ret) << dendl;
      return ret;
    }
  }

  string oid = get_info_oid_prefix(old_format);
  if (old_format) {
    oid += name;
  } else {
    oid += id;
  }

  rgw_raw_obj object_id(pool, oid);
  ret = store->delete_system_obj(object_id);
  if (ret < 0) {
    ldout(cct, 0) << "Error delete object id " << id << ": " << cpp_strerror(-ret) << dendl;
  }

  return ret;
}

int RGWSystemMetaObj::store_name(bool exclusive)
{
  rgw_pool pool(get_pool(cct));
  string oid = get_names_oid_prefix() + name;

  RGWNameToId nameToId;
  nameToId.obj_id = id;

  bufferlist bl;
  using ceph::encode;
  encode(nameToId, bl);
  return rgw_put_system_obj(store, pool, oid, bl, exclusive, NULL, real_time(), NULL);
}

int RGWSystemMetaObj::rename(const string& new_name)
{
  string new_id;
  int ret = read_id(new_name, new_id);
  if (!ret) {
    return -EEXIST;
  }
  if (ret < 0 && ret != -ENOENT) {
    ldout(cct, 0) << "Error read_id " << new_name << ": " << cpp_strerror(-ret) << dendl;
    return ret;
  }
  string old_name = name;
  name = new_name;
  ret = update();
  if (ret < 0) {
    ldout(cct, 0) << "Error storing new obj info " << new_name << ": " << cpp_strerror(-ret) << dendl;
    return ret;
  }
  ret = store_name(true);
  if (ret < 0) {
    ldout(cct, 0) << "Error storing new name " << new_name << ": " << cpp_strerror(-ret) << dendl;
    return ret;
  }
  /* delete old name */
  rgw_pool pool(get_pool(cct));
  string oid = get_names_oid_prefix() + old_name;
  rgw_raw_obj old_name_obj(pool, oid);
  ret = store->delete_system_obj(old_name_obj);
  if (ret < 0) {
    ldout(cct, 0) << "Error delete old obj name  " << old_name << ": " << cpp_strerror(-ret) << dendl;
    return ret;
  }

  return ret;
}

int RGWSystemMetaObj::read_info(const string& obj_id, bool old_format)
{
  rgw_pool pool(get_pool(cct));

  bufferlist bl;

  string oid = get_info_oid_prefix(old_format) + obj_id;

  RGWObjectCtx obj_ctx(store);
  int ret = rgw_get_system_obj(store, obj_ctx, pool, oid, bl, NULL, NULL);
  if (ret < 0) {
    ldout(cct, 0) << "failed reading obj info from " << pool << ":" << oid << ": " << cpp_strerror(-ret) << dendl;
    return ret;
  }
  using ceph::decode;

  try {
    bufferlist::iterator iter = bl.begin();
    decode(*this, iter);
  } catch (buffer::error& err) {
    ldout(cct, 0) << "ERROR: failed to decode obj from " << pool << ":" << oid << dendl;
    return -EIO;
  }

  return 0;
}

int RGWSystemMetaObj::read()
{
  int ret = read_id(name, id);
  if (ret < 0) {
    return ret;
  }

  return read_info(id);
}

int RGWSystemMetaObj::create(bool exclusive)
{
  int ret;
  
  /* check to see the name is not used */
  ret = read_id(name, id);
  if (exclusive && ret == 0) {
    ldout(cct, 10) << "ERROR: name " << name << " already in use for obj id " << id << dendl;
    return -EEXIST;
  } else if ( ret < 0 && ret != -ENOENT) {
    ldout(cct, 0) << "failed reading obj id  " << id << ": " << cpp_strerror(-ret) << dendl;
    return ret;
  }

  if (id.empty()) {
    /* create unique id */
    uuid_d new_uuid;
    char uuid_str[37];
    new_uuid.generate_random();
    new_uuid.print(uuid_str);
    id = uuid_str;
  }

  ret = store_info(exclusive);
  if (ret < 0) {
    ldout(cct, 0) << "ERROR:  storing info for " << id << ": " << cpp_strerror(-ret) << dendl;
    return ret;
  }

  return store_name(exclusive);
}

int RGWSystemMetaObj::store_info(bool exclusive)
{
  rgw_pool pool(get_pool(cct));

  string oid = get_info_oid_prefix() + id;

  bufferlist bl;
  using ceph::encode;
  encode(*this, bl);
  return rgw_put_system_obj(store, pool, oid, bl, exclusive, NULL, real_time(), NULL);
}

int RGWSystemMetaObj::write(bool exclusive)
{
  int ret = store_info(exclusive);
  if (ret < 0) {
    ldout(cct, 20) << __func__ << "(): store_info() returned ret=" << ret << dendl;
    return ret;
  }
  ret = store_name(exclusive);
  if (ret < 0) {
    ldout(cct, 20) << __func__ << "(): store_name() returned ret=" << ret << dendl;
    return ret;
  }
  return 0;
}


const string& RGWRealm::get_predefined_name(CephContext *cct) {
  return cct->_conf->rgw_realm;
}

int RGWRealm::create(bool exclusive)
{
  int ret = RGWSystemMetaObj::create(exclusive);
  if (ret < 0) {
    ldout(cct, 0) << "ERROR creating new realm object " << name << ": " << cpp_strerror(-ret) << dendl;
    return ret;
  }
  // create the control object for watch/notify
  ret = create_control(exclusive);
  if (ret < 0) {
    ldout(cct, 0) << "ERROR creating control for new realm " << name << ": " << cpp_strerror(-ret) << dendl;
    return ret;
  }
  RGWPeriod period;
  if (current_period.empty()) {
    /* create new period for the realm */
    ret = period.init(cct, store, id, name, false);
    if (ret < 0 ) {
      return ret;
    }
    ret = period.create(true);
    if (ret < 0) {
      ldout(cct, 0) << "ERROR: creating new period for realm " << name << ": " << cpp_strerror(-ret) << dendl;
      return ret;
    }
  } else {
    period = RGWPeriod(current_period, 0);
    int ret = period.init(cct, store, id, name);
    if (ret < 0) {
      ldout(cct, 0) << "ERROR: failed to init period " << current_period << dendl;
      return ret;
    }
  }
  ret = set_current_period(period);
  if (ret < 0) {
    ldout(cct, 0) << "ERROR: failed set current period " << current_period << dendl;
    return ret;
  }
  // try to set as default. may race with another create, so pass exclusive=true
  // so we don't override an existing default
  ret = set_as_default(true);
  if (ret < 0 && ret != -EEXIST) {
    ldout(cct, 0) << "WARNING: failed to set realm as default realm, ret=" << ret << dendl;
  }

  return 0;
}

int RGWRealm::delete_obj()
{
  int ret = RGWSystemMetaObj::delete_obj();
  if (ret < 0) {
    return ret;
  }
  return delete_control();
}

int RGWRealm::create_control(bool exclusive)
{
  auto pool = rgw_pool{get_pool(cct)};
  auto oid = get_control_oid();
  bufferlist bl;
  return rgw_put_system_obj(store, pool, oid, bl, exclusive,
                            nullptr, real_time(), nullptr);
}

int RGWRealm::delete_control()
{
  auto pool = rgw_pool{get_pool(cct)};
  auto obj = rgw_raw_obj{pool, get_control_oid()};
  return store->delete_system_obj(obj);
}

rgw_pool RGWRealm::get_pool(CephContext *cct)
{
  if (cct->_conf->rgw_realm_root_pool.empty()) {
    return rgw_pool(RGW_DEFAULT_REALM_ROOT_POOL);
  }
  return rgw_pool(cct->_conf->rgw_realm_root_pool);
}

const string RGWRealm::get_default_oid(bool old_format)
{
  if (cct->_conf->rgw_default_realm_info_oid.empty()) {
    return default_realm_info_oid;
  }
  return cct->_conf->rgw_default_realm_info_oid;
}

const string& RGWRealm::get_names_oid_prefix()
{
  return realm_names_oid_prefix;
}

const string& RGWRealm::get_info_oid_prefix(bool old_format)
{
  return realm_info_oid_prefix;
}

int RGWRealm::set_current_period(RGWPeriod& period)
{
  // update realm epoch to match the period's
  if (epoch > period.get_realm_epoch()) {
    ldout(cct, 0) << "ERROR: set_current_period with old realm epoch "
        << period.get_realm_epoch() << ", current epoch=" << epoch << dendl;
    return -EINVAL;
  }
  if (epoch == period.get_realm_epoch() && current_period != period.get_id()) {
    ldout(cct, 0) << "ERROR: set_current_period with same realm epoch "
        << period.get_realm_epoch() << ", but different period id "
        << period.get_id() << " != " << current_period << dendl;
    return -EINVAL;
  }

  epoch = period.get_realm_epoch();
  current_period = period.get_id();

  int ret = update();
  if (ret < 0) {
    ldout(cct, 0) << "ERROR: period update: " << cpp_strerror(-ret) << dendl;
    return ret;
  }

  ret = period.reflect();
  if (ret < 0) {
    ldout(cct, 0) << "ERROR: period.reflect(): " << cpp_strerror(-ret) << dendl;
    return ret;
  }

  return 0;
}

string RGWRealm::get_control_oid()
{
  return get_info_oid_prefix() + id + ".control";
}

int RGWRealm::notify_zone(bufferlist& bl)
{
  // open a context on the realm's pool
  rgw_pool pool{get_pool(cct)};
  librados::IoCtx ctx;
  int r = rgw_init_ioctx(store->get_rados_handle(), pool, ctx);
  if (r < 0) {
    ldout(cct, 0) << "Failed to open pool " << pool << dendl;
    return r;
  }
  // send a notify on the realm object
  r = ctx.notify2(get_control_oid(), bl, 0, nullptr);
  if (r < 0) {
    ldout(cct, 0) << "Realm notify failed with " << r << dendl;
    return r;
  }
  return 0;
}

int RGWRealm::notify_new_period(const RGWPeriod& period)
{
  bufferlist bl;
  using ceph::encode;
  // push the period to dependent zonegroups/zones
  encode(RGWRealmNotify::ZonesNeedPeriod, bl);
  encode(period, bl);
  // reload the gateway with the new period
  encode(RGWRealmNotify::Reload, bl);

  return notify_zone(bl);
}

std::string RGWPeriodConfig::get_oid(const std::string& realm_id)
{
  if (realm_id.empty()) {
    return "period_config.default";
  }
  return "period_config." + realm_id;
}

rgw_pool RGWPeriodConfig::get_pool(CephContext *cct)
{
  const auto& pool_name = cct->_conf->rgw_period_root_pool;
  if (pool_name.empty()) {
    return {RGW_DEFAULT_PERIOD_ROOT_POOL};
  }
  return {pool_name};
}

int RGWPeriodConfig::read(RGWRados *store, const std::string& realm_id)
{
  RGWObjectCtx obj_ctx(store);
  const auto& pool = get_pool(store->ctx());
  const auto& oid = get_oid(realm_id);
  bufferlist bl;

  int ret = rgw_get_system_obj(store, obj_ctx, pool, oid, bl, nullptr, nullptr);
  if (ret < 0) {
    return ret;
  }
  using ceph::decode;
  try {
    bufferlist::iterator iter = bl.begin();
    decode(*this, iter);
  } catch (buffer::error& err) {
    return -EIO;
  }
  return 0;
}

int RGWPeriodConfig::write(RGWRados *store, const std::string& realm_id)
{
  const auto& pool = get_pool(store->ctx());
  const auto& oid = get_oid(realm_id);
  bufferlist bl;
  using ceph::encode;
  encode(*this, bl);
  return rgw_put_system_obj(store, pool, oid, bl,
                            false, nullptr, real_time(), nullptr);
}

int RGWPeriod::init(CephContext *_cct, RGWRados *_store, const string& period_realm_id,
		    const string& period_realm_name, bool setup_obj)
{
  cct = _cct;
  store = _store;
  realm_id = period_realm_id;
  realm_name = period_realm_name;

  if (!setup_obj)
    return 0;

  return init(_cct, _store, setup_obj);
}


int RGWPeriod::init(CephContext *_cct, RGWRados *_store, bool setup_obj)
{
  cct = _cct;
  store = _store;

  if (!setup_obj)
    return 0;

  if (id.empty()) {
    RGWRealm realm(realm_id, realm_name);
    int ret = realm.init(cct, store);
    if (ret < 0) {
      ldout(cct, 0) << "RGWPeriod::init failed to init realm " << realm_name  << " id " << realm_id << " : " <<
	cpp_strerror(-ret) << dendl;
      return ret;
    }
    id = realm.get_current_period();
    realm_id = realm.get_id();
  }

  if (!epoch) {
    int ret = use_latest_epoch();
    if (ret < 0) {
      ldout(cct, 0) << "failed to use_latest_epoch period id " << id << " realm " << realm_name  << " id " << realm_id
	   << " : " << cpp_strerror(-ret) << dendl;
      return ret;
    }
  }

  return read_info();
}


int RGWPeriod::get_zonegroup(RGWZoneGroup& zonegroup, const string& zonegroup_id) {
  map<string, RGWZoneGroup>::const_iterator iter;
  if (!zonegroup_id.empty()) {
    iter = period_map.zonegroups.find(zonegroup_id);
  } else {
    iter = period_map.zonegroups.find("default");
  }
  if (iter != period_map.zonegroups.end()) {
    zonegroup = iter->second;
    return 0;
  }

  return -ENOENT;
}

bool RGWRados::get_redirect_zone_endpoint(string *endpoint)
{
  if (zone_public_config.redirect_zone.empty()) {
    return false;
  }

  auto iter = zone_conn_map.find(zone_public_config.redirect_zone);
  if (iter == zone_conn_map.end()) {
    ldout(cct, 0) << "ERROR: cannot find entry for redirect zone: " << zone_public_config.redirect_zone << dendl;
    return false;
  }

  RGWRESTConn *conn = iter->second;

  int ret = conn->get_url(*endpoint);
  if (ret < 0) {
    ldout(cct, 0) << "ERROR: redirect zone, conn->get_endpoint() returned ret=" << ret << dendl;
    return false;
  }

  return true;
}

const string& RGWPeriod::get_latest_epoch_oid()
{
  if (cct->_conf->rgw_period_latest_epoch_info_oid.empty()) {
    return period_latest_epoch_info_oid;
  }
  return cct->_conf->rgw_period_latest_epoch_info_oid;
}

const string& RGWPeriod::get_info_oid_prefix()
{
  return period_info_oid_prefix;
}

const string RGWPeriod::get_period_oid_prefix()
{
  return get_info_oid_prefix() + id;
}

const string RGWPeriod::get_period_oid()
{
  std::ostringstream oss;
  oss << get_period_oid_prefix();
  // skip the epoch for the staging period
  if (id != get_staging_id(realm_id))
    oss << "." << epoch;
  return oss.str();
}

int RGWPeriod::read_latest_epoch(RGWPeriodLatestEpochInfo& info,
                                 RGWObjVersionTracker *objv)
{
  string oid = get_period_oid_prefix() + get_latest_epoch_oid();

  rgw_pool pool(get_pool(cct));
  bufferlist bl;
  RGWObjectCtx obj_ctx(store);
  int ret = rgw_get_system_obj(store, obj_ctx, pool, oid, bl, objv, nullptr);
  if (ret < 0) {
    ldout(cct, 1) << "error read_lastest_epoch " << pool << ":" << oid << dendl;
    return ret;
  }
  try {
    bufferlist::iterator iter = bl.begin();
    using ceph::decode;
    decode(info, iter);
  } catch (buffer::error& err) {
    ldout(cct, 0) << "error decoding data from " << pool << ":" << oid << dendl;
    return -EIO;
  }

  return 0;
}

int RGWPeriod::get_latest_epoch(epoch_t& latest_epoch)
{
  RGWPeriodLatestEpochInfo info;

  int ret = read_latest_epoch(info);
  if (ret < 0) {
    return ret;
  }

  latest_epoch = info.epoch;

  return 0;
}

int RGWPeriod::use_latest_epoch()
{
  RGWPeriodLatestEpochInfo info;
  int ret = read_latest_epoch(info);
  if (ret < 0) {
    return ret;
  }

  epoch = info.epoch;

  return 0;
}

int RGWPeriod::set_latest_epoch(epoch_t epoch, bool exclusive,
                                RGWObjVersionTracker *objv)
{
  string oid = get_period_oid_prefix() + get_latest_epoch_oid();

  rgw_pool pool(get_pool(cct));
  bufferlist bl;

  RGWPeriodLatestEpochInfo info;
  info.epoch = epoch;

  using ceph::encode;
  encode(info, bl);

  return rgw_put_system_obj(store, pool, oid, bl,
                            exclusive, objv, real_time(), nullptr);
}

int RGWPeriod::update_latest_epoch(epoch_t epoch)
{
  static constexpr int MAX_RETRIES = 20;

  for (int i = 0; i < MAX_RETRIES; i++) {
    RGWPeriodLatestEpochInfo info;
    RGWObjVersionTracker objv;
    bool exclusive = false;

    // read existing epoch
    int r = read_latest_epoch(info, &objv);
    if (r == -ENOENT) {
      // use an exclusive create to set the epoch atomically
      exclusive = true;
      ldout(cct, 20) << "creating initial latest_epoch=" << epoch
          << " for period=" << id << dendl;
    } else if (r < 0) {
      ldout(cct, 0) << "ERROR: failed to read latest_epoch" << dendl;
      return r;
    } else if (epoch <= info.epoch) {
      r = -EEXIST; // fail with EEXIST if epoch is not newer
      ldout(cct, 1) << "found existing latest_epoch " << info.epoch
          << " >= given epoch " << epoch << ", returning r=" << r << dendl;
      return r;
    } else {
      ldout(cct, 20) << "updating latest_epoch from " << info.epoch
          << " -> " << epoch << " on period=" << id << dendl;
    }

    r = set_latest_epoch(epoch, exclusive, &objv);
    if (r == -EEXIST) {
      continue; // exclusive create raced with another update, retry
    } else if (r == -ECANCELED) {
      continue; // write raced with a conflicting version, retry
    }
    if (r < 0) {
      ldout(cct, 0) << "ERROR: failed to write latest_epoch" << dendl;
      return r;
    }
    return 0; // return success
  }

  return -ECANCELED; // fail after max retries
}

int RGWPeriod::delete_obj()
{
  rgw_pool pool(get_pool(cct));

  // delete the object for each period epoch
  for (epoch_t e = 1; e <= epoch; e++) {
    RGWPeriod p{get_id(), e};
    rgw_raw_obj oid{pool, p.get_period_oid()};
    int ret = store->delete_system_obj(oid);
    if (ret < 0) {
      ldout(cct, 0) << "WARNING: failed to delete period object " << oid
          << ": " << cpp_strerror(-ret) << dendl;
    }
  }

  // delete the .latest_epoch object
  rgw_raw_obj oid{pool, get_period_oid_prefix() + get_latest_epoch_oid()};
  int ret = store->delete_system_obj(oid);
  if (ret < 0) {
    ldout(cct, 0) << "WARNING: failed to delete period object " << oid
        << ": " << cpp_strerror(-ret) << dendl;
  }
  return ret;
}

int RGWPeriod::read_info()
{
  rgw_pool pool(get_pool(cct));

  bufferlist bl;

  RGWObjectCtx obj_ctx(store);
  int ret = rgw_get_system_obj(store, obj_ctx, pool, get_period_oid(), bl, NULL, NULL);
  if (ret < 0) {
    ldout(cct, 0) << "failed reading obj info from " << pool << ":" << get_period_oid() << ": " << cpp_strerror(-ret) << dendl;
    return ret;
  }

  try {
    using ceph::decode;
    bufferlist::iterator iter = bl.begin();
    decode(*this, iter);
  } catch (buffer::error& err) {
    ldout(cct, 0) << "ERROR: failed to decode obj from " << pool << ":" << get_period_oid() << dendl;
    return -EIO;
  }

  return 0;
}

int RGWPeriod::create(bool exclusive)
{
  int ret;
  
  /* create unique id */
  uuid_d new_uuid;
  char uuid_str[37];
  new_uuid.generate_random();
  new_uuid.print(uuid_str);
  id = uuid_str;

  epoch = FIRST_EPOCH;

  period_map.id = id;
  
  ret = store_info(exclusive);
  if (ret < 0) {
    ldout(cct, 0) << "ERROR:  storing info for " << id << ": " << cpp_strerror(-ret) << dendl;
    return ret;
  }

  ret = set_latest_epoch(epoch);
  if (ret < 0) {
    ldout(cct, 0) << "ERROR: setting latest epoch " << id << ": " << cpp_strerror(-ret) << dendl;
  }

  return ret;
}

int RGWPeriod::store_info(bool exclusive)
{
  rgw_pool pool(get_pool(cct));

  string oid = get_period_oid();
  bufferlist bl;
  using ceph::encode;
  encode(*this, bl);

  return rgw_put_system_obj(store, pool, oid, bl,
                            exclusive, NULL, real_time(), NULL);
}

rgw_pool RGWPeriod::get_pool(CephContext *cct)
{
  if (cct->_conf->rgw_period_root_pool.empty()) {
    return rgw_pool(RGW_DEFAULT_PERIOD_ROOT_POOL);
  }
  return rgw_pool(cct->_conf->rgw_period_root_pool);
}

int RGWPeriod::add_zonegroup(const RGWZoneGroup& zonegroup)
{
  if (zonegroup.realm_id != realm_id) {
    return 0;
  }
  int ret = period_map.update(zonegroup, cct);
  if (ret < 0) {
    ldout(cct, 0) << "ERROR: updating period map: " << cpp_strerror(-ret) << dendl;
    return ret;
  }

  return store_info(false);
}

int RGWPeriod::update()
{
  ldout(cct, 20) << __func__ << " realm " << realm_id << " period " << get_id() << dendl;
  list<string> zonegroups;
  int ret = store->list_zonegroups(zonegroups);
  if (ret < 0) {
    ldout(cct, 0) << "ERROR: failed to list zonegroups: " << cpp_strerror(-ret) << dendl;
    return ret;
  }

  // clear zone short ids of removed zones. period_map.update() will add the
  // remaining zones back
  period_map.short_zone_ids.clear();

  for (auto& iter : zonegroups) {
    RGWZoneGroup zg(string(), iter);
    ret = zg.init(cct, store);
    if (ret < 0) {
      ldout(cct, 0) << "WARNING: zg.init() failed: " << cpp_strerror(-ret) << dendl;
      continue;
    }

    if (zg.realm_id != realm_id) {
      ldout(cct, 20) << "skipping zonegroup " << zg.get_name() << " zone realm id " << zg.realm_id << ", not on our realm " << realm_id << dendl;
      continue;
    }

    if (zg.master_zone.empty()) {
      ldout(cct, 0) << "ERROR: zonegroup " << zg.get_name() << " should have a master zone " << dendl;
      return -EINVAL;
    }  
    
    if (zg.zones.find(zg.master_zone) == zg.zones.end()) {
      ldout(cct,0) << "ERROR: zonegroup " << zg.get_name()
                   << " has a non existent master zone "<< dendl;
      return -EINVAL;
    }

    if (zg.is_master_zonegroup()) {
      master_zonegroup = zg.get_id();
      master_zone = zg.master_zone;
    }

    int ret = period_map.update(zg, cct);
    if (ret < 0) {
      return ret;
    }
  }

  ret = period_config.read(store, realm_id);
  if (ret < 0 && ret != -ENOENT) {
    ldout(cct, 0) << "ERROR: failed to read period config: "
        << cpp_strerror(ret) << dendl;
    return ret;
  }
  return 0;
}

int RGWPeriod::reflect()
{
  for (auto& iter : period_map.zonegroups) {
    RGWZoneGroup& zg = iter.second;
    zg.reinit_instance(cct, store);
    int r = zg.write(false);
    if (r < 0) {
      ldout(cct, 0) << "ERROR: failed to store zonegroup info for zonegroup=" << iter.first << ": " << cpp_strerror(-r) << dendl;
      return r;
    }
    if (zg.is_master_zonegroup()) {
      // set master as default if no default exists
      r = zg.set_as_default(true);
      if (r == 0) {
        ldout(cct, 1) << "Set the period's master zonegroup " << zg.get_id()
            << " as the default" << dendl;
      }
    }
  }

  int r = period_config.write(store, realm_id);
  if (r < 0) {
    ldout(cct, 0) << "ERROR: failed to store period config: "
        << cpp_strerror(-r) << dendl;
    return r;
  }
  return 0;
}

void RGWPeriod::fork()
{
  ldout(cct, 20) << __func__ << " realm " << realm_id << " period " << id << dendl;
  predecessor_uuid = id;
  id = get_staging_id(realm_id);
  period_map.reset();
  realm_epoch++;
}

static int read_sync_status(RGWRados *store, rgw_meta_sync_status *sync_status)
{
  // initialize a sync status manager to read the status
  RGWMetaSyncStatusManager mgr(store, store->get_async_rados());
  int r = mgr.init();
  if (r < 0) {
    return r;
  }
  r = mgr.read_sync_status(sync_status);
  mgr.stop();
  return r;
}

int RGWPeriod::update_sync_status(const RGWPeriod &current_period,
                                  std::ostream& error_stream,
                                  bool force_if_stale)
{
  rgw_meta_sync_status status;
  int r = read_sync_status(store, &status);
  if (r < 0) {
    ldout(cct, 0) << "period failed to read sync status: "
        << cpp_strerror(-r) << dendl;
    return r;
  }

  std::vector<std::string> markers;

  const auto current_epoch = current_period.get_realm_epoch();
  if (current_epoch != status.sync_info.realm_epoch) {
    // no sync status markers for the current period
    assert(current_epoch > status.sync_info.realm_epoch);
    const int behind = current_epoch - status.sync_info.realm_epoch;
    if (!force_if_stale && current_epoch > 1) {
      error_stream << "ERROR: This zone is " << behind << " period(s) behind "
          "the current master zone in metadata sync. If this zone is promoted "
          "to master, any metadata changes during that time are likely to "
          "be lost.\n"
          "Waiting for this zone to catch up on metadata sync (see "
          "'radosgw-admin sync status') is recommended.\n"
          "To promote this zone to master anyway, add the flag "
          "--yes-i-really-mean-it." << std::endl;
      return -EINVAL;
    }
    // empty sync status markers - other zones will skip this period during
    // incremental metadata sync
    markers.resize(status.sync_info.num_shards);
  } else {
    markers.reserve(status.sync_info.num_shards);
    for (auto& i : status.sync_markers) {
      auto& marker = i.second;
      // filter out markers from other periods
      if (marker.realm_epoch != current_epoch) {
        marker.marker.clear();
      }
      markers.emplace_back(std::move(marker.marker));
    }
  }

  std::swap(sync_status, markers);
  return 0;
}

int RGWPeriod::commit(RGWRealm& realm, const RGWPeriod& current_period,
                      std::ostream& error_stream, bool force_if_stale)
{
  ldout(cct, 20) << __func__ << " realm " << realm.get_id() << " period " << current_period.get_id() << dendl;
  // gateway must be in the master zone to commit
  if (master_zone != store->get_zone_params().get_id()) {
    error_stream << "Cannot commit period on zone "
        << store->get_zone_params().get_id() << ", it must be sent to "
        "the period's master zone " << master_zone << '.' << std::endl;
    return -EINVAL;
  }
  // period predecessor must match current period
  if (predecessor_uuid != current_period.get_id()) {
    error_stream << "Period predecessor " << predecessor_uuid
        << " does not match current period " << current_period.get_id()
        << ". Use 'period pull' to get the latest period from the master, "
        "reapply your changes, and try again." << std::endl;
    return -EINVAL;
  }
  // realm epoch must be 1 greater than current period
  if (realm_epoch != current_period.get_realm_epoch() + 1) {
    error_stream << "Period's realm epoch " << realm_epoch
        << " does not come directly after current realm epoch "
        << current_period.get_realm_epoch() << ". Use 'realm pull' to get the "
        "latest realm and period from the master zone, reapply your changes, "
        "and try again." << std::endl;
    return -EINVAL;
  }
  // did the master zone change?
  if (master_zone != current_period.get_master_zone()) {
    // store the current metadata sync status in the period
    int r = update_sync_status(current_period, error_stream, force_if_stale);
    if (r < 0) {
      ldout(cct, 0) << "failed to update metadata sync status: "
          << cpp_strerror(-r) << dendl;
      return r;
    }
    // create an object with a new period id
    r = create(true);
    if (r < 0) {
      ldout(cct, 0) << "failed to create new period: " << cpp_strerror(-r) << dendl;
      return r;
    }
    // set as current period
    r = realm.set_current_period(*this);
    if (r < 0) {
      ldout(cct, 0) << "failed to update realm's current period: "
          << cpp_strerror(-r) << dendl;
      return r;
    }
    ldout(cct, 4) << "Promoted to master zone and committed new period "
        << id << dendl;
    realm.notify_new_period(*this);
    return 0;
  }
  // period must be based on current epoch
  if (epoch != current_period.get_epoch()) {
    error_stream << "Period epoch " << epoch << " does not match "
        "predecessor epoch " << current_period.get_epoch()
        << ". Use 'period pull' to get the latest epoch from the master zone, "
        "reapply your changes, and try again." << std::endl;
    return -EINVAL;
  }
  // set period as next epoch
  set_id(current_period.get_id());
  set_epoch(current_period.get_epoch() + 1);
  set_predecessor(current_period.get_predecessor());
  realm_epoch = current_period.get_realm_epoch();
  // write the period to rados
  int r = store_info(false);
  if (r < 0) {
    ldout(cct, 0) << "failed to store period: " << cpp_strerror(-r) << dendl;
    return r;
  }
  // set as latest epoch
  r = update_latest_epoch(epoch);
  if (r == -EEXIST) {
    // already have this epoch (or a more recent one)
    return 0;
  }
  if (r < 0) {
    ldout(cct, 0) << "failed to set latest epoch: " << cpp_strerror(-r) << dendl;
    return r;
  }
  r = reflect();
  if (r < 0) {
    ldout(cct, 0) << "failed to update local objects: " << cpp_strerror(-r) << dendl;
    return r;
  }
  ldout(cct, 4) << "Committed new epoch " << epoch
      << " for period " << id << dendl;
  realm.notify_new_period(*this);
  return 0;
}

int RGWZoneParams::create_default(bool old_format)
{
  name = default_zone_name;

  int r = create();
  if (r < 0) {
    return r;
  }

  if (old_format) {
    name = id;
  }

  return r;
}


int get_zones_pool_set(CephContext* cct,
                       RGWRados* store,
                       const list<string>& zones,
                       const string& my_zone_id,
                       set<rgw_pool>& pool_names)
{
  for(auto const& iter : zones) {
    RGWZoneParams zone(iter);
    int r = zone.init(cct, store);
    if (r < 0) {
      ldout(cct, 0) << "Error: init zone " << iter << ":" << cpp_strerror(-r) << dendl;
      return r;
    }
    if (zone.get_id() != my_zone_id) {
      pool_names.insert(zone.domain_root);
      pool_names.insert(zone.metadata_heap);
      pool_names.insert(zone.control_pool);
      pool_names.insert(zone.gc_pool);
      pool_names.insert(zone.log_pool);
      pool_names.insert(zone.intent_log_pool);
      pool_names.insert(zone.usage_log_pool);
      pool_names.insert(zone.user_keys_pool);
      pool_names.insert(zone.user_email_pool);
      pool_names.insert(zone.user_swift_pool);
      pool_names.insert(zone.user_uid_pool);
      pool_names.insert(zone.otp_pool);
      pool_names.insert(zone.roles_pool);
      pool_names.insert(zone.reshard_pool);
      for(auto& iter : zone.placement_pools) {
        pool_names.insert(iter.second.index_pool);
        for (auto& pi : iter.second.storage_classes.get_all()) {
          if (!(pi.second.data_pool.empty())) {
            pool_names.insert(pi.second.data_pool);
          }
        }
        pool_names.insert(iter.second.data_extra_pool);
      }
    }
  }
  return 0;
}

rgw_pool fix_zone_pool_dup(set<rgw_pool> pools,
                           const string& default_prefix,
                           const string& default_suffix,
                           const rgw_pool& suggested_pool)
{
  string suggested_name = suggested_pool.to_str();

  string prefix = default_prefix;
  string suffix = default_suffix;

  if (!suggested_pool.empty()) {
    prefix = suggested_name.substr(0, suggested_name.find("."));
    suffix = suggested_name.substr(prefix.length());
  }

  rgw_pool pool(prefix + suffix);
  
  if (pools.find(pool) == pools.end()) {
    return pool;
  } else {
    while(true) {
      pool =  prefix + "_" + std::to_string(std::rand()) + suffix;
      if (pools.find(pool) == pools.end()) {
	return pool;
      }
    }
  }  
}

int RGWZoneParams::fix_pool_names()
{

  list<string> zones;
  int r = store->list_zones(zones);
  if (r < 0) {
    ldout(cct, 10) << "WARNING: store->list_zones() returned r=" << r << dendl;
  }

  set<rgw_pool> pools;
  r = get_zones_pool_set(cct, store, zones, id, pools);
  if (r < 0) {
    ldout(cct, 0) << "Error: get_zones_pool_names" << r << dendl;
    return r;
  }

  domain_root = fix_zone_pool_dup(pools, name, ".rgw.meta:root", domain_root);
  if (!metadata_heap.name.empty()) {
    metadata_heap = fix_zone_pool_dup(pools, name, ".rgw.meta:heap", metadata_heap);
  }
  control_pool = fix_zone_pool_dup(pools, name, ".rgw.control", control_pool);
  gc_pool = fix_zone_pool_dup(pools, name ,".rgw.log:gc", gc_pool);
  lc_pool = fix_zone_pool_dup(pools, name ,".rgw.log:lc", lc_pool);
  log_pool = fix_zone_pool_dup(pools, name, ".rgw.log", log_pool);
  intent_log_pool = fix_zone_pool_dup(pools, name, ".rgw.log:intent", intent_log_pool);
  usage_log_pool = fix_zone_pool_dup(pools, name, ".rgw.log:usage", usage_log_pool);
  user_keys_pool = fix_zone_pool_dup(pools, name, ".rgw.meta:users.keys", user_keys_pool);
  user_email_pool = fix_zone_pool_dup(pools, name, ".rgw.meta:users.email", user_email_pool);
  user_swift_pool = fix_zone_pool_dup(pools, name, ".rgw.meta:users.swift", user_swift_pool);
  user_uid_pool = fix_zone_pool_dup(pools, name, ".rgw.meta:users.uid", user_uid_pool);
  roles_pool = fix_zone_pool_dup(pools, name, ".rgw.meta:roles", roles_pool);
  reshard_pool = fix_zone_pool_dup(pools, name, ".rgw.log:reshard", reshard_pool);
  otp_pool = fix_zone_pool_dup(pools, name, ".rgw.otp", otp_pool);

  for(auto& iter : placement_pools) {
    iter.second.index_pool = fix_zone_pool_dup(pools, name, "." + default_bucket_index_pool_suffix,
                                               iter.second.index_pool);
    for (auto& pi : iter.second.storage_classes.get_all()) {
      if (!(pi.second.data_pool.empty())) {
        rgw_pool& pool = pi.second.data_pool;
        pool = fix_zone_pool_dup(pools, name, "." + default_storage_pool_suffix,
                                 pool);
      }
    }
    iter.second.data_extra_pool= fix_zone_pool_dup(pools, name, "." + default_storage_extra_pool_suffix,
                                                   iter.second.data_extra_pool);
  }

  return 0;
}

int RGWZoneParams::create(bool exclusive)
{
  /* check for old pools config */
  rgw_raw_obj obj(domain_root, avail_pools);
  int r = store->raw_obj_stat(obj, NULL, NULL, NULL, NULL, NULL, NULL);
  if (r < 0) {
    ldout(store->ctx(), 10) << "couldn't find old data placement pools config, setting up new ones for the zone" << dendl;
    /* a new system, let's set new placement info */
    RGWZonePlacementInfo default_placement;
    default_placement.index_pool = name + "." + default_bucket_index_pool_suffix;
    rgw_pool pool = name + "." + default_storage_pool_suffix;
    default_placement.storage_classes.set_storage_class(RGWStorageClass::STANDARD, &pool, nullptr);
    default_placement.data_extra_pool = name + "." + default_storage_extra_pool_suffix;
    placement_pools["default-placement"] = default_placement;
  }

  r = fix_pool_names();
  if (r < 0) {
    ldout(cct, 0) << "ERROR: fix_pool_names returned r=" << r << dendl;
    return r;
  }

  r = RGWSystemMetaObj::create(exclusive);
  if (r < 0) {
    return r;
  }

  // try to set as default. may race with another create, so pass exclusive=true
  // so we don't override an existing default
  r = set_as_default(true);
  if (r < 0 && r != -EEXIST) {
    ldout(cct, 10) << "WARNING: failed to set zone as default, r=" << r << dendl;
  }

  return 0;
}

rgw_pool RGWZoneParams::get_pool(CephContext *cct)
{
  if (cct->_conf->rgw_zone_root_pool.empty()) {
    return rgw_pool(RGW_DEFAULT_ZONE_ROOT_POOL);
  }

  return rgw_pool(cct->_conf->rgw_zone_root_pool);
}

const string RGWZoneParams::get_default_oid(bool old_format)
{
  if (old_format) {
    return cct->_conf->rgw_default_zone_info_oid;
  }

  return cct->_conf->rgw_default_zone_info_oid + "." + realm_id;
}

const string& RGWZoneParams::get_names_oid_prefix()
{
  return zone_names_oid_prefix;
}

const string& RGWZoneParams::get_info_oid_prefix(bool old_format)
{
  return zone_info_oid_prefix;
}

const string& RGWZoneParams::get_predefined_name(CephContext *cct) {
  return cct->_conf->rgw_zone;
}

int RGWZoneParams::init(CephContext *cct, RGWRados *store, bool setup_obj, bool old_format)
{
  if (name.empty()) {
    name = cct->_conf->rgw_zone;
  }

  return RGWSystemMetaObj::init(cct, store, setup_obj, old_format);
}

int RGWZoneParams::read_default_id(string& default_id, bool old_format)
{
  if (realm_id.empty()) {
    /* try using default realm */
    RGWRealm realm;
    int ret = realm.init(cct, store);
    //no default realm exist
    if (ret < 0) {
      return read_id(default_zone_name, default_id);
    }
    realm_id = realm.get_id();
  }

  return RGWSystemMetaObj::read_default_id(default_id, old_format);
}


int RGWZoneParams::set_as_default(bool exclusive)
{
  if (realm_id.empty()) {
    /* try using default realm */
    RGWRealm realm;
    int ret = realm.init(cct, store);
    if (ret < 0) {
      ldout(cct, 10) << "could not read realm id: " << cpp_strerror(-ret) << dendl;
      return -EINVAL;
    }
    realm_id = realm.get_id();
  }

  return RGWSystemMetaObj::set_as_default(exclusive);
}

const string& RGWZoneParams::get_compression_type(const rgw_placement_rule& placement_rule) const
{
  static const std::string NONE{"none"};
  auto p = placement_pools.find(placement_rule.name);
  if (p == placement_pools.end()) {
    return NONE;
  }
  const auto& type = p->second.get_compression_type(placement_rule.storage_class);
  return !type.empty() ? type : NONE;
}

void RGWPeriodMap::encode(bufferlist& bl) const {
  ENCODE_START(2, 1, bl);
  encode(id, bl);
  encode(zonegroups, bl);
  encode(master_zonegroup, bl);
  encode(short_zone_ids, bl);
  ENCODE_FINISH(bl);
}

void RGWPeriodMap::decode(bufferlist::iterator& bl) {
  DECODE_START(2, bl);
  decode(id, bl);
  decode(zonegroups, bl);
  decode(master_zonegroup, bl);
  if (struct_v >= 2) {
    decode(short_zone_ids, bl);
  }
  DECODE_FINISH(bl);

  zonegroups_by_api.clear();
  for (map<string, RGWZoneGroup>::iterator iter = zonegroups.begin();
       iter != zonegroups.end(); ++iter) {
    RGWZoneGroup& zonegroup = iter->second;
    zonegroups_by_api[zonegroup.api_name] = zonegroup;
    if (zonegroup.is_master_zonegroup()) {
      master_zonegroup = zonegroup.get_id();
    }
  }
}

// run an MD5 hash on the zone_id and return the first 32 bits
static uint32_t gen_short_zone_id(const std::string zone_id)
{
  unsigned char md5[CEPH_CRYPTO_MD5_DIGESTSIZE];
  MD5 hash;
  hash.Update((const unsigned char *)zone_id.c_str(), zone_id.size());
  hash.Final(md5);

  uint32_t short_id;
  memcpy((char *)&short_id, md5, sizeof(short_id));
  return std::max(short_id, 1u);
}

int RGWPeriodMap::update(const RGWZoneGroup& zonegroup, CephContext *cct)
{
  if (zonegroup.is_master_zonegroup() && (!master_zonegroup.empty() && zonegroup.get_id() != master_zonegroup)) {
    ldout(cct,0) << "Error updating periodmap, multiple master zonegroups configured "<< dendl;
    ldout(cct,0) << "master zonegroup: " << master_zonegroup << " and  " << zonegroup.get_id() <<dendl;
    return -EINVAL;
  }
  map<string, RGWZoneGroup>::iterator iter = zonegroups.find(zonegroup.get_id());
  if (iter != zonegroups.end()) {
    RGWZoneGroup& old_zonegroup = iter->second;
    if (!old_zonegroup.api_name.empty()) {
      zonegroups_by_api.erase(old_zonegroup.api_name);
    }
  }
  zonegroups[zonegroup.get_id()] = zonegroup;

  if (!zonegroup.api_name.empty()) {
    zonegroups_by_api[zonegroup.api_name] = zonegroup;
  }

  if (zonegroup.is_master_zonegroup()) {
    master_zonegroup = zonegroup.get_id();
  } else if (master_zonegroup == zonegroup.get_id()) {
    master_zonegroup = "";
  }

  for (auto& i : zonegroup.zones) {
    auto& zone = i.second;
    if (short_zone_ids.find(zone.id) != short_zone_ids.end()) {
      continue;
    }
    // calculate the zone's short id
    uint32_t short_id = gen_short_zone_id(zone.id);

    // search for an existing zone with the same short id
    for (auto& s : short_zone_ids) {
      if (s.second == short_id) {
        ldout(cct, 0) << "New zone '" << zone.name << "' (" << zone.id
            << ") generates the same short_zone_id " << short_id
            << " as existing zone id " << s.first << dendl;
        return -EEXIST;
      }
    }

    short_zone_ids[zone.id] = short_id;
  }

  return 0;
}

uint32_t RGWPeriodMap::get_zone_short_id(const string& zone_id) const
{
  auto i = short_zone_ids.find(zone_id);
  if (i == short_zone_ids.end()) {
    return 0;
  }
  return i->second;
}

int RGWZoneGroupMap::read(CephContext *cct, RGWRados *store)
{

  RGWPeriod period;
  int ret = period.init(cct, store);
  if (ret < 0) {
    cerr << "failed to read current period info: " << cpp_strerror(ret);
    return ret;
  }
	
  bucket_quota = period.get_config().bucket_quota;
  user_quota = period.get_config().user_quota;
  zonegroups = period.get_map().zonegroups;
  zonegroups_by_api = period.get_map().zonegroups_by_api;
  master_zonegroup = period.get_map().master_zonegroup;

  return 0;
}

void RGWRegionMap::encode(bufferlist& bl) const {
  ENCODE_START( 3, 1, bl);
  encode(regions, bl);
  encode(master_region, bl);
  encode(bucket_quota, bl);
  encode(user_quota, bl);
  ENCODE_FINISH(bl);
}

void RGWRegionMap::decode(bufferlist::iterator& bl) {
  DECODE_START(3, bl);
  decode(regions, bl);
  decode(master_region, bl);
  if (struct_v >= 2)
    decode(bucket_quota, bl);
  if (struct_v >= 3)
    decode(user_quota, bl);
  DECODE_FINISH(bl);
}

void RGWZoneGroupMap::encode(bufferlist& bl) const {
  ENCODE_START( 3, 1, bl);
  encode(zonegroups, bl);
  encode(master_zonegroup, bl);
  encode(bucket_quota, bl);
  encode(user_quota, bl);
  ENCODE_FINISH(bl);
}

void RGWZoneGroupMap::decode(bufferlist::iterator& bl) {
  DECODE_START(3, bl);
  decode(zonegroups, bl);
  decode(master_zonegroup, bl);
  if (struct_v >= 2)
    decode(bucket_quota, bl);
  if (struct_v >= 3)
    decode(user_quota, bl);
  DECODE_FINISH(bl);

  zonegroups_by_api.clear();
  for (map<string, RGWZoneGroup>::iterator iter = zonegroups.begin();
       iter != zonegroups.end(); ++iter) {
    RGWZoneGroup& zonegroup = iter->second;
    zonegroups_by_api[zonegroup.api_name] = zonegroup;
    if (zonegroup.is_master_zonegroup()) {
      master_zonegroup = zonegroup.get_name();
    }
  }
}

void RGWObjVersionTracker::prepare_op_for_read(ObjectReadOperation *op)
{
  obj_version *check_objv = version_for_check();

  if (check_objv) {
    cls_version_check(*op, *check_objv, VER_COND_EQ);
  }

  cls_version_read(*op, &read_version);
}

void RGWObjVersionTracker::prepare_op_for_write(ObjectWriteOperation *op)
{
  obj_version *check_objv = version_for_check();
  obj_version *modify_version = version_for_write();

  if (check_objv) {
    cls_version_check(*op, *check_objv, VER_COND_EQ);
  }

  if (modify_version) {
    cls_version_set(*op, *modify_version);
  } else {
    cls_version_inc(*op);
  }
}

void RGWObjManifest::obj_iterator::operator++()
{
  if (manifest->explicit_objs) {
    ++explicit_iter;

    if (explicit_iter == manifest->objs.end()) {
      ofs = manifest->obj_size;
      return;
    }

    update_explicit_pos();

    update_location();
    return;
  }

  uint64_t obj_size = manifest->get_obj_size();
  uint64_t head_size = manifest->get_head_size();

  if (ofs == obj_size) {
    return;
  }

  if (manifest->rules.empty()) {
    return;
  }

  /* are we still pointing at the head? */
  if (ofs < head_size) {
    rule_iter = manifest->rules.begin();
    RGWObjManifestRule *rule = &rule_iter->second;
    ofs = std::min(head_size, obj_size);
    stripe_ofs = ofs;
    cur_stripe = 1;
    stripe_size = std::min(obj_size - ofs, rule->stripe_max_size);
    if (rule->part_size > 0) {
      stripe_size = std::min(stripe_size, rule->part_size);
    }
    update_location();
    return;
  }

  RGWObjManifestRule *rule = &rule_iter->second;

  stripe_ofs += rule->stripe_max_size;
  cur_stripe++;
  dout(20) << "RGWObjManifest::operator++(): rule->part_size=" << rule->part_size << " rules.size()=" << manifest->rules.size() << dendl;

  if (rule->part_size > 0) {
    /* multi part, multi stripes object */

    dout(20) << "RGWObjManifest::operator++(): stripe_ofs=" << stripe_ofs << " part_ofs=" << part_ofs << " rule->part_size=" << rule->part_size << dendl;

    if (stripe_ofs >= part_ofs + rule->part_size) {
      /* moved to the next part */
      cur_stripe = 0;
      part_ofs += rule->part_size;
      stripe_ofs = part_ofs;

      bool last_rule = (next_rule_iter == manifest->rules.end());
      /* move to the next rule? */
      if (!last_rule && stripe_ofs >= next_rule_iter->second.start_ofs) {
        rule_iter = next_rule_iter;
        last_rule = (next_rule_iter == manifest->rules.end());
        if (!last_rule) {
          ++next_rule_iter;
        }
        cur_part_id = rule_iter->second.start_part_num;
      } else {
        cur_part_id++;
      }

      rule = &rule_iter->second;
    }

    stripe_size = std::min(rule->part_size - (stripe_ofs - part_ofs), rule->stripe_max_size);
  }

  cur_override_prefix = rule->override_prefix;

  ofs = stripe_ofs;
  if (ofs > obj_size) {
    ofs = obj_size;
    stripe_ofs = ofs;
    stripe_size = 0;
  }

  dout(20) << "RGWObjManifest::operator++(): result: ofs=" << ofs << " stripe_ofs=" << stripe_ofs << " part_ofs=" << part_ofs << " rule->part_size=" << rule->part_size << dendl;
  update_location();
}

int RGWObjManifest::generator::restore_env(RGWObjManifest *_m,
                     const rgw_placement_rule& head_placement_rule) {
  manifest = _m;
  manifest->set_head_placement_rule(head_placement_rule);
  last_ofs = 0;

  if (manifest->get_prefix().empty()) {
    derr << "ERROR: manifest->prefix should not be empty" << dendl;
    return -EIO;
  }

  bool found = manifest->get_rule(manifest->obj_size, &rule);
  if (!found) {
    derr << "ERROR: manifest->get_rule() could not find rule for offset:" << manifest->obj_size << dendl;
    return -EIO;
  }
  cur_stripe_size = rule.stripe_max_size;
  cur_part_id = rule.start_part_num;

  if (manifest->obj_size >= manifest->max_head_size) {
    cur_stripe = ((manifest->obj_size - manifest->max_head_size) / cur_stripe_size);
    if (manifest->max_head_size > 0) {
      cur_stripe++;
    }
  }
  manifest->get_implicit_location(cur_part_id, cur_stripe, manifest->obj_size, NULL, &cur_obj);

  manifest->update_iterators();

  return 0;
}

int RGWObjManifest::generator::create_begin(CephContext *cct, RGWObjManifest *_m,
                                            const rgw_placement_rule& head_placement_rule,
                                            const rgw_placement_rule& tail_placement_rule,
                                            const rgw_bucket& _b, const rgw_obj& _obj)
{
  manifest = _m;

  if (!tail_placement_rule.empty()) {
    manifest->set_tail_placement(tail_placement_rule, _b);
  } else {
    manifest->set_tail_placement(head_placement_rule, _b);
  }
  manifest->set_head(head_placement_rule, _obj, 0);
  last_ofs = 0;

  if (manifest->get_prefix().empty()) {
    char buf[33];
    gen_rand_alphanumeric(cct, buf, sizeof(buf) - 1);

    string oid_prefix = ".";
    oid_prefix.append(buf);
    oid_prefix.append("_");

    manifest->set_prefix(oid_prefix);
  }

  bool found = manifest->get_rule(0, &rule);
  if (!found) {
    derr << "ERROR: manifest->get_rule() could not find rule" << dendl;
    return -EIO;
  }

  uint64_t head_size = manifest->get_head_size();

  if (head_size > 0) {
    cur_stripe_size = head_size;
  } else {
    cur_stripe_size = rule.stripe_max_size;
  }
  
  cur_part_id = rule.start_part_num;

  manifest->get_implicit_location(cur_part_id, cur_stripe, 0, NULL, &cur_obj);

  // Normal object which not generated through copy operation 
  manifest->set_tail_instance(_obj.key.instance);

  manifest->update_iterators();

  return 0;
}

int RGWObjManifest::generator::create_next(uint64_t ofs)
{
  if (ofs < last_ofs) /* only going forward */
    return -EINVAL;

  uint64_t max_head_size = manifest->get_max_head_size();

  if (ofs < max_head_size) {
    manifest->set_head_size(ofs);
  }

  if (ofs >= max_head_size) {
    manifest->set_head_size(max_head_size);
    cur_stripe = (ofs - max_head_size) / rule.stripe_max_size;
    cur_stripe_size = rule.stripe_max_size;

    if (cur_part_id == 0 && max_head_size > 0) {
      cur_stripe++;
    }
  }

  last_ofs = ofs;
  manifest->set_obj_size(ofs);

  manifest->get_implicit_location(cur_part_id, cur_stripe, ofs, NULL, &cur_obj);

  manifest->update_iterators();

  return 0;
}

const RGWObjManifest::obj_iterator& RGWObjManifest::obj_begin()
{
  return begin_iter;
}

const RGWObjManifest::obj_iterator& RGWObjManifest::obj_end()
{
  return end_iter;
}

RGWObjManifest::obj_iterator RGWObjManifest::obj_find(uint64_t ofs)
{
  if (ofs > obj_size) {
    ofs = obj_size;
  }
  RGWObjManifest::obj_iterator iter(this);
  iter.seek(ofs);
  return iter;
}

int RGWObjManifest::append(RGWObjManifest& m, RGWZoneGroup& zonegroup, RGWZoneParams& zone_params)
{
  if (explicit_objs || m.explicit_objs) {
    return append_explicit(m, zonegroup, zone_params);
  }

  if (rules.empty()) {
    *this = m;
    return 0;
  }

  string override_prefix;

  if (prefix.empty()) {
    prefix = m.prefix;
  }

  if (prefix != m.prefix) {
    override_prefix = m.prefix;
  }

  map<uint64_t, RGWObjManifestRule>::iterator miter = m.rules.begin();
  if (miter == m.rules.end()) {
    return append_explicit(m, zonegroup, zone_params);
  }

  for (; miter != m.rules.end(); ++miter) {
    map<uint64_t, RGWObjManifestRule>::reverse_iterator last_rule = rules.rbegin();

    RGWObjManifestRule& rule = last_rule->second;

    if (rule.part_size == 0) {
      rule.part_size = obj_size - rule.start_ofs;
    }

    RGWObjManifestRule& next_rule = miter->second;
    if (!next_rule.part_size) {
      next_rule.part_size = m.obj_size - next_rule.start_ofs;
    }

    string rule_prefix = prefix;
    if (!rule.override_prefix.empty()) {
      rule_prefix = rule.override_prefix;
    }

    string next_rule_prefix = m.prefix;
    if (!next_rule.override_prefix.empty()) {
      next_rule_prefix = next_rule.override_prefix;
    }

    if (rule.part_size != next_rule.part_size ||
        rule.stripe_max_size != next_rule.stripe_max_size ||
        rule_prefix != next_rule_prefix) {
      if (next_rule_prefix != prefix) {
        append_rules(m, miter, &next_rule_prefix);
      } else {
        append_rules(m, miter, NULL);
      }
      break;
    }

    uint64_t expected_part_num = rule.start_part_num + 1;
    if (rule.part_size > 0) {
      expected_part_num = rule.start_part_num + (obj_size + next_rule.start_ofs - rule.start_ofs) / rule.part_size;
    }

    if (expected_part_num != next_rule.start_part_num) {
      append_rules(m, miter, NULL);
      break;
    }
  }

  set_obj_size(obj_size + m.obj_size);

  return 0;
}

int RGWObjManifest::append(RGWObjManifest& m, RGWRados *store)
{
  return append(m, store->get_zonegroup(), store->get_zone_params());
}

void RGWObjManifest::append_rules(RGWObjManifest& m, map<uint64_t, RGWObjManifestRule>::iterator& miter,
                                  string *override_prefix)
{
  for (; miter != m.rules.end(); ++miter) {
    RGWObjManifestRule rule = miter->second;
    rule.start_ofs += obj_size;
    if (override_prefix)
      rule.override_prefix = *override_prefix;
    rules[rule.start_ofs] = rule;
  }
}

void RGWObjManifest::convert_to_explicit(const RGWZoneGroup& zonegroup, const RGWZoneParams& zone_params)
{
  if (explicit_objs) {
    return;
  }
  obj_iterator iter = obj_begin();

  while (iter != obj_end()) {
    RGWObjManifestPart& part = objs[iter.get_stripe_ofs()];
    const rgw_obj_select& os = iter.get_location();
    const rgw_raw_obj& raw_loc = os.get_raw_obj(zonegroup, zone_params);
    part.loc_ofs = 0;

    uint64_t ofs = iter.get_stripe_ofs();

    if (ofs == 0) {
      part.loc = obj;
    } else {
      rgw_raw_obj_to_obj(tail_placement.bucket, raw_loc, &part.loc);
    }
    ++iter;
    uint64_t next_ofs = iter.get_stripe_ofs();

    part.size = next_ofs - ofs;
  }

  explicit_objs = true;
  rules.clear();
  prefix.clear();
}

int RGWObjManifest::append_explicit(RGWObjManifest& m, const RGWZoneGroup& zonegroup, const RGWZoneParams& zone_params)
{
  if (!explicit_objs) {
    convert_to_explicit(zonegroup, zone_params);
  }
  if (!m.explicit_objs) {
    m.convert_to_explicit(zonegroup, zone_params);
  }
  map<uint64_t, RGWObjManifestPart>::iterator iter;
  uint64_t base = obj_size;
  for (iter = m.objs.begin(); iter != m.objs.end(); ++iter) {
    RGWObjManifestPart& part = iter->second;
    objs[base + iter->first] = part;
  }
  obj_size += m.obj_size;

  return 0;
}

bool RGWObjManifest::get_rule(uint64_t ofs, RGWObjManifestRule *rule)
{
  if (rules.empty()) {
    return false;
  }

  map<uint64_t, RGWObjManifestRule>::iterator iter = rules.upper_bound(ofs);
  if (iter != rules.begin()) {
    --iter;
  }

  *rule = iter->second;

  return true;
}

void RGWObjVersionTracker::generate_new_write_ver(CephContext *cct)
{
  write_version.ver = 1;
#define TAG_LEN 24

  write_version.tag.clear();
  append_rand_alpha(cct, write_version.tag, write_version.tag, TAG_LEN);
}

int RGWPutObjProcessor::complete(size_t accounted_size, const string& etag,
                                 real_time *mtime, real_time set_mtime,
                                 map<string, bufferlist>& attrs, real_time delete_at,
                                 const char *if_match, const char *if_nomatch, const string *user_data,
                                 rgw_zone_set *zones_trace)
{
  int r = do_complete(accounted_size, etag, mtime, set_mtime, attrs, delete_at, if_match, if_nomatch, user_data, zones_trace);
  if (r < 0)
    return r;

  is_complete = !canceled;
  return 0;
}

CephContext *RGWPutObjProcessor::ctx()
{
  return store->ctx();
}

RGWPutObjProcessor_Aio::~RGWPutObjProcessor_Aio()
{
  drain_pending();

  if (is_complete) {
    return;
  }

  set<rgw_raw_obj>::iterator iter;
  bool need_to_remove_head = false;
  rgw_raw_obj raw_head;

  if (!head_obj.empty()) {
    store->obj_to_raw(bucket_info.head_placement_rule, head_obj, &raw_head);
  }

  /** 
   * We should delete the object in the "multipart" namespace to avoid race condition. 
   * Such race condition is caused by the fact that the multipart object is the gatekeeper of a multipart 
   * upload, when it is deleted, a second upload would start with the same suffix("2/"), therefore, objects
   * written by the second upload may be deleted by the first upload.
   * details is describled on #11749
   *
   * The above comment still stands, but instead of searching for a specific object in the multipart
   * namespace, we just make sure that we remove the object that is marked as the head object after
   * we remove all the other raw objects. Note that we use different call to remove the head object,
   * as this one needs to go via the bucket index prepare/complete 2-phase commit scheme.
   */
  for (iter = written_objs.begin(); iter != written_objs.end(); ++iter) {
    const rgw_raw_obj& obj = *iter;
    if (!head_obj.empty() && obj == raw_head) {
      ldout(store->ctx(), 5) << "NOTE: we should not process the head object (" << obj << ") here" << dendl;
      need_to_remove_head = true;
      continue;
    }

    int r = store->delete_raw_obj(obj, enable_skip_cache);
    if (r < 0 && r != -ENOENT) {
      ldout(store->ctx(), 5) << "WARNING: failed to remove obj (" << obj << "), leaked" << dendl;
    }
  }

  if (need_to_remove_head) {
    ldout(store->ctx(), 5) << "NOTE: we are going to process the head obj (" << raw_head << ")" << dendl;
    int r = store->delete_obj(obj_ctx, bucket_info, head_obj, 0, true, 0);
    if (r < 0 && r != -ENOENT) {
      ldout(store->ctx(), 0) << "WARNING: failed to remove obj (" << raw_head << "), leaked" << dendl;
    }
  }
}

int RGWPutObjProcessor_Aio::handle_obj_data(rgw_raw_obj& obj, bufferlist& bl, off_t ofs, off_t abs_ofs, void **phandle, bool exclusive)
{
  if ((uint64_t)abs_ofs + bl.length() > obj_len)
    obj_len = abs_ofs + bl.length();

  if (!(obj == last_written_obj)) {
    last_written_obj = obj;
  }

  // For the first call pass -1 as the offset to
  // do a write_full.
  return store->aio_put_obj_data(NULL, obj, bl, ((ofs != 0) ? ofs : -1), exclusive, phandle, enable_skip_cache);
}

struct put_obj_aio_info RGWPutObjProcessor_Aio::pop_pending()
{
  struct put_obj_aio_info info;
  info = pending.front();
  pending.pop_front();
  pending_size -= info.size;
  return info;
}

int RGWPutObjProcessor_Aio::wait_pending_front()
{
  if (pending.empty()) {
    return 0;
  }
  struct put_obj_aio_info info = pop_pending();
  int ret = store->aio_wait(info.handle);

  if (ret >= 0) {
    add_written_obj(info.obj);
  }

  return ret;
}

bool RGWPutObjProcessor_Aio::pending_has_completed()
{
  if (pending.empty())
    return false;

  struct put_obj_aio_info& info = pending.front();
  return store->aio_completed(info.handle);
}

int RGWPutObjProcessor_Aio::drain_pending()
{
  int ret = 0;
  while (!pending.empty()) {
    int r = wait_pending_front();
    if (r < 0)
      ret = r;
  }
  return ret;
}

int RGWPutObjProcessor_Aio::throttle_data(void *handle, const rgw_raw_obj& obj, uint64_t size, bool need_to_wait)
{
  bool _wait = need_to_wait;

  if (handle) {
    struct put_obj_aio_info info;
    info.handle = handle;
    info.obj = obj;
    info.size = size;
    pending_size += size;
    pending.push_back(info);
  }
  size_t orig_size = pending_size;

  /* first drain complete IOs */
  while (pending_has_completed()) {
    int r = wait_pending_front();
    if (r < 0)
      return r;

    _wait = false;
  }

  /* resize window in case messages are draining too fast */
  if (orig_size - pending_size >= window_size) {
    window_size += store->ctx()->_conf->rgw_max_chunk_size;
    uint64_t max_window_size = store->ctx()->_conf->rgw_put_obj_max_window_size;
    if (window_size > max_window_size) {
      window_size = max_window_size;
    }
  }

  /* now throttle. Note that need_to_wait should only affect the first IO operation */
  if (pending_size > window_size || _wait) {
    int r = wait_pending_front();
    if (r < 0)
      return r;
  }
  return 0;
}

int RGWPutObjProcessor_Atomic::write_data(bufferlist& bl, off_t ofs, void **phandle, rgw_raw_obj *pobj, bool exclusive)
{
  if (ofs >= next_part_ofs) {
    int r = prepare_next_part(ofs);
    if (r < 0) {
      return r;
    }
  }

  *pobj = cur_obj;

  if (!bl.length()) {
    *phandle = nullptr;
    return 0;
  }

  return RGWPutObjProcessor_Aio::handle_obj_data(cur_obj, bl, ofs - cur_part_ofs, ofs, phandle, exclusive);
}

int RGWPutObjProcessor_Aio::prepare(RGWRados *store, string *oid_rand)
{
  RGWPutObjProcessor::prepare(store, oid_rand);

  window_size = store->ctx()->_conf->rgw_put_obj_min_window_size;

  return 0;
}

int RGWPutObjProcessor_Atomic::handle_data(bufferlist& bl, off_t ofs, void **phandle, rgw_raw_obj *pobj, bool *again)
{
  *phandle = NULL;
  uint64_t max_write_size = std::min(max_chunk_size, (uint64_t)next_part_ofs - data_ofs);

  pending_data_bl.claim_append(bl);

  if (!data_ofs && !immutable_head() && is_first_chunk) {
    uint64_t max_head_size = manifest.get_max_head_size();
    max_write_size = std::min(max_write_size, max_head_size);
    if (pending_data_bl.length() < max_write_size) {
      *again = false;
      return 0;
    }
    pending_data_bl.splice(0, max_write_size, &bl);
    *again = (pending_data_bl.length() >= max_write_size);
    first_chunk.claim(bl);
    is_first_chunk = false;
    obj_len = (uint64_t)first_chunk.length();
    int r = prepare_next_part(obj_len);
    if (r < 0) {
      return r;
    }
    data_ofs = obj_len;
    return 0;
  }

  if (pending_data_bl.length() < max_write_size) {
    *again = false;
    return 0;
  }
  pending_data_bl.splice(0, max_write_size, &bl);

  /* do we have enough data pending accumulated that needs to be written? */
  *again = (pending_data_bl.length() >= max_chunk_size);
  off_t write_ofs = data_ofs;
  data_ofs = write_ofs + bl.length();
  bool exclusive = (!write_ofs && immutable_head()); /* immutable head object, need to verify nothing exists there
                                                        we could be racing with another upload, to the same
                                                        object and cleanup can be messy */
  int ret = write_data(bl, write_ofs, phandle, pobj, exclusive);
  if (ret >= 0) { /* we might return, need to clear bl as it was already sent */
    if (immutable_head() && is_first_chunk && !write_ofs) {
      // pass back the whole data after store first chunk
      is_first_chunk = false;
      bl.append(pending_data_bl);
    } else {
      bl.clear();
    }
  }
  return ret;
}

int RGWPutObjProcessor_Atomic::prepare_init(RGWRados *store, string *oid_rand)
{
  RGWPutObjProcessor_Aio::prepare(store, oid_rand);

  int r = store->get_max_chunk_size(bucket_info.head_placement_rule, head_obj, &max_chunk_size);
  if (r < 0) {
    return r;
  }

  return 0;
}

void RGWPutObjProcessor_Atomic::try_file_shuntflow()
{
  rgw_pool tail_pool;
  if (store->get_obj_tail_pool(tail_placement_rule, &tail_pool)) {
    // if target storage class have tail pool, check file length is compatible with file_shuntflow_size
    if (content_length > file_shuntflow_size || unknown_actual_size) {
      tail_placement_rule.is_tail_rule = true;
    }
  }
}

int RGWPutObjProcessor_Atomic::prepare(RGWRados *store, string *oid_rand)
{
  RGWPutObjProcessor_Aio::prepare(store, oid_rand);
  head_obj.init(bucket, obj_str);
  // when versioning suspened, transition also need to be done
  if (versioned_object || is_transition) {
    if (!version_id.empty()) {
      head_obj.key.set_instance(version_id);
    } else if (!is_transition) {
      store->gen_rand_obj_instance_name(&head_obj);
      version_id = head_obj.key.get_instance();
    }
  }

  rgw_pool head_pool;
  if (!store->get_obj_data_pool(bucket_info.head_placement_rule, head_obj, &head_pool)) {
    return -EIO;
  }

  int r = store->get_max_chunk_size(head_pool, &max_chunk_size);
  if (r < 0) {
    return r;
  }
  uint64_t max_head_size = max_chunk_size;
  if (bucket_info.head_placement_rule != tail_placement_rule) {
    rgw_pool tail_pool;
    if (!store->get_obj_data_pool(tail_placement_rule, head_obj, &tail_pool)) {
      return -EIO;
    }

    if (tail_pool != head_pool) {
      r = store->get_max_chunk_size(tail_pool, &max_chunk_size);
      if (r < 0) {
        return r;
      }
      max_head_size = 0;
    }
  } else if (get_skip_cache_flag()) {
    if (content_length > file_shuntflow_size) {
      uint64_t temp_size = content_length % max_chunk_size;
      if (temp_size > file_shuntflow_size) {
        max_head_size = temp_size % file_shuntflow_size;
      } else {
        max_head_size = temp_size;
      }
    }
    if (unknown_actual_size) {
      max_head_size = file_shuntflow_size;
    }
  }
  try_file_shuntflow();
  manifest.set_skip_cache(get_skip_cache_flag());
  manifest.set_trivial_rule(max_head_size, store->ctx()->_conf->rgw_obj_stripe_size);
  r = manifest_gen.create_begin(store->ctx(), &manifest,
                                bucket_info.head_placement_rule,
                                tail_placement_rule,
                                head_obj.bucket, head_obj);
  if (r < 0) {
    return r;
  }

  return 0;
}

int RGWPutObjProcessor_Atomic::prepare_next_part(off_t ofs) {

  int ret = manifest_gen.create_next(ofs);
  if (ret < 0) {
    lderr(store->ctx()) << "ERROR: manifest_gen.create_next() returned ret=" << ret << dendl;
    return ret;
  }
  cur_part_ofs = ofs;
  next_part_ofs = ofs + manifest_gen.cur_stripe_max_size();
  cur_obj = manifest_gen.get_cur_obj(store);

  return 0;
}

int RGWPutObjProcessor_Atomic::complete_parts()
{
  if (obj_len > (uint64_t)cur_part_ofs) {
    return prepare_next_part(obj_len);
  }
  return 0;
}

int RGWPutObjProcessor_Atomic::complete_writing_data(bool need_append_head_obj)
{
  if ((!data_ofs && !immutable_head() && is_first_chunk) || need_append_head_obj) {
    /* only claim if pending_data_bl() is not empty. This is needed because we might be called twice
     * (e.g., when a retry due to race happens). So a second call to first_chunk.claim() would
     * clobber first_chunk
     */
    if (pending_data_bl.length() > 0) {
      first_chunk.claim(pending_data_bl);
    }
    obj_len = (uint64_t)first_chunk.length();
    is_first_chunk = false;
  }
  while (pending_data_bl.length()) {
    void *handle = nullptr;
    rgw_raw_obj obj;
    uint64_t max_write_size = std::min(max_chunk_size, (uint64_t)next_part_ofs - data_ofs);
    if (max_write_size > pending_data_bl.length()) {
      max_write_size = pending_data_bl.length();
    }
    bufferlist bl;
    pending_data_bl.splice(0, max_write_size, &bl);
    uint64_t write_len = bl.length();
    int r = write_data(bl, data_ofs, &handle, &obj, false);
    if (r < 0) {
      ldout(store->ctx(), 0) << "ERROR: write_data() returned " << r << dendl;
      return r;
    }
    data_ofs += write_len;
    r = throttle_data(handle, obj, write_len, false);
    if (r < 0) {
      ldout(store->ctx(), 0) << "ERROR: throttle_data() returned " << r << dendl;
      return r;
    }

    if (data_ofs >= next_part_ofs) {
      r = prepare_next_part(data_ofs);
      if (r < 0) {
        ldout(store->ctx(), 0) << "ERROR: prepare_next_part() returned " << r << dendl;
        return r;
      }
    }
  }
  int r = complete_parts();
  if (r < 0) {
    return r;
  }

  r = drain_pending();
  if (r < 0)
    return r;

  return 0;
}

int RGWPutObjProcessor_Atomic::do_complete(size_t accounted_size, const string& etag,
                                           real_time *mtime, real_time set_mtime,
                                           map<string, bufferlist>& attrs,
                                           real_time delete_at,
                                           const char *if_match,
                                           const char *if_nomatch, const string *user_data,
                                           rgw_zone_set *zones_trace) {
  int r = complete_writing_data();
  if (r < 0)
    return r;

  obj_ctx.obj.set_atomic(head_obj);

  RGWRados::Object op_target(store, bucket_info, obj_ctx, head_obj);

  /* some object types shouldn't be versioned, e.g., multipart parts */
  op_target.set_versioning_disabled(!versioned_object);

  RGWRados::Object::Write obj_op(&op_target);

  obj_op.meta.data = &first_chunk;
  obj_op.meta.manifest = &manifest;
  obj_op.meta.ptag = &unique_tag; /* use req_id as operation tag */
  obj_op.meta.if_match = if_match;
  obj_op.meta.if_nomatch = if_nomatch;
  obj_op.meta.mtime = mtime;
  obj_op.meta.set_mtime = set_mtime;
  obj_op.meta.owner = bucket_info.owner;
  obj_op.meta.flags = PUT_OBJ_CREATE;
  obj_op.meta.olh_epoch = olh_epoch;
  obj_op.meta.delete_at = delete_at;
  obj_op.meta.user_data = user_data;
  obj_op.meta.zones_trace = zones_trace;
  obj_op.meta.modify_tail = true;
  obj_op.meta.head_placement_rule = manifest.get_head_placement_rule();
  obj_op.meta.storage_class = manifest.get_tail_placement().placement_rule.storage_class;
  obj_op.meta.is_transition = is_transition;
  auto iter = attrs.find(RGW_ATTR_TAGS);
  if (iter != attrs.end() && iter->second.length() > 0) {
    obj_op.meta.tags_bl = &(iter->second);
  }


  if (unmod_time) {
    obj_op.meta.unmod_time = unmod_time;
  }

  r = obj_op.write_meta(obj_len, accounted_size, attrs);
  if (r < 0) {
    return r;
  }

  canceled = obj_op.meta.canceled;

  return 0;
}

int RGWPutObjProcessor_Append::prepare(RGWRados *store, string *oid_rand)
{
  if (bucket_info.versioned()) {
    ldout(store->ctx(), 10) << "ERROR: Can not append object to versioned bucket" << dendl;
    return -ERR_INVALID_BUCKET_STATE;
  }

  if (supplied_request_id_exist && supplied_request_id.empty()) {
    ldout(store->ctx(), 0) << "ERROR: length of request id should not be null: "
      << supplied_request_id << dendl;
    return -ERR_INVALID_REQUEST;
  }

  RGWPutObjProcessor_Aio::prepare(store, oid_rand);
  head_obj.init(bucket, obj_str);

  int r = store->get_obj_state(&obj_ctx, bucket_info, head_obj, &astate);
  if (r < 0) {
    return r;
  }

  auto iter = astate->attrset.find(RGW_ATTR_DELETED);
  if (iter != astate->attrset.end() &&
      iter->second.to_str().compare("true") == 0 &&
      0 != supplied_offset) {
    ldout(store->ctx(), 10) << "ERROR: Append position:" << supplied_offset <<
      ", should be zero on your first append" << dendl;
    return -ENOENT;
  }

  if (!astate->exists) {
    if (0 != supplied_offset) {
      ldout(store->ctx(), 10) << "ERROR: Append position:" << supplied_offset <<
        ", should be zero on your first append" << dendl;
      return -ENOENT;
    }
    head_obj_exist = false;
  } else if (supplied_offset == 0) {
    // if offset is zero but object exist, cover this object
    head_obj_exist = false;
    cover_obj = true;
  } else {
    map<string, bufferlist>::iterator iter = astate->attrset.find(RGW_ATTR_ETAG);
    if (iter != astate->attrset.end()) {
      string s = rgw_string_unquote(iter->second.c_str());
      size_t pos = s.find("-");
      if (pos == std::string::npos) {
        cur_etag = s;
      } else {
        cur_etag = s.substr(0, pos);
        string temp_str = s.substr(pos + 1);
        append_times = uint64_t(atoll(temp_str.c_str()));
      }
    }

    data_ofs = astate->size;
    *cur_accounted_size = astate->size;

    if (astate->size + content_length > store->ctx()->_conf->rgw_max_put_size) {
      return -ERR_TOO_LARGE;
    }

    iter = astate->attrset.find(RGW_ATTR_TARGET_SIZE);
    if (iter == astate->attrset.end()) {
      ldout(store->ctx(), 10) << "ERROR: Can not append to normal object" << dendl;
      return -ERR_OBJECT_NOT_APPENDABLE;
    }

    uint64_t target_size;
    try {
      decode(target_size, iter->second);
    } catch (buffer::error& err) {
      ldout(store->ctx(), 5) << "ERROR: failed to decode " RGW_ATTR_TARGET_SIZE
        << " attr, value:" << iter->second.c_str() << dendl;
      return -EIO;
    }

    if (target_size != uint64_t(data_ofs)) {
      // set head_obj xattr first, failed to update head_obj in the end ->
      // can rewrite at the same offset after rgw_append_timeout
      iter = astate->attrset.find(RGW_ATTR_APPEND_TIMEOUT);
      if (iter != astate->attrset.end()) {
        ceph::real_time ts;
        try {
          decode(ts, iter->second);
        } catch (buffer::error& err) {
          ldout(store->ctx(), 5) << "ERROR: failed to decode " RGW_ATTR_APPEND_TIMEOUT
            << " attr, value:" << iter->second.c_str() << dendl;
          return -EIO;
        }
        if (real_clock::now() < ts + make_timespan(store->ctx()->_conf->rgw_append_timeout)) {
          return -ERR_OFFSET_INCORRECT;
        }
        need_cmpxattr = false;
      }
    }

    if (astate->accounted_size != supplied_offset) {
      // client doesn't receive success response, when client retry with same
      // request-id, we can process it again.
      bool offset_incorrect = true;
      if (target_size == astate->accounted_size &&
          (supplied_offset + content_length) == target_size) {
        iter = astate->attrset.find(RGW_ATTR_REQUEST_ID);
        if (iter != astate->attrset.end()) {
          string recorded_request_id = iter->second.c_str();
          if (supplied_request_id.compare(recorded_request_id) == 0) {
            ldout(store->ctx(), 15) << "same request, process it again" << dendl;
            offset_incorrect = false;
            data_ofs = supplied_offset;
            *cur_accounted_size = supplied_offset;
            need_cmpxattr = false;
          }
        }
      }
      if (offset_incorrect) {
        ldout(store->ctx(), 5) << "ERROR: Append position: " << supplied_offset
          << "does not equal to the obj size:" << astate->accounted_size << dendl;
        return -ERR_OFFSET_INCORRECT;
      }
    }

    if (!astate->has_manifest) {
      ldout(store->ctx(), 5) << "ERROR: manifest does not exist! head_obj:" << head_obj << dendl;
      return -EINVAL;
    }
    astate->keep_tail = true;
  }

  if (supplied_offset != 0) {
    cur_idtag = astate->attrset[RGW_ATTR_ID_TAG];
  }

  rgw_pool head_pool;
  if (!store->get_obj_data_pool(bucket_info.head_placement_rule, head_obj, &head_pool)) {
    return -EIO;
  }

  r = store->get_max_chunk_size(head_pool, &max_chunk_size);
  if (r < 0) {
    return r;
  }

  if (astate->exists && !cover_obj) {
    manifest = astate->manifest;
    r = manifest_gen.restore_env(&manifest, bucket_info.head_placement_rule);
    if (r < 0) {
      return r;
    }
  } else {
    uint64_t max_head_size = max_chunk_size;
    if (bucket_info.head_placement_rule != tail_placement_rule) {
      rgw_pool tail_pool;
      if (!store->get_obj_data_pool(tail_placement_rule, head_obj, &tail_pool)) {
        return -EIO;
      }

      if (tail_pool != head_pool) {
        r = store->get_max_chunk_size(tail_pool, &max_chunk_size);
        if (r < 0) {
          return r;
        }
        max_head_size = 0;
      }
    } else if (get_skip_cache_flag()) {
      max_head_size = file_shuntflow_size;
    }
    try_file_shuntflow();
    manifest.set_skip_cache(get_skip_cache_flag());
    manifest.set_trivial_rule(max_head_size, store->ctx()->_conf->rgw_obj_stripe_size);
    r = manifest_gen.create_begin(store->ctx(), &manifest,
                                  bucket_info.head_placement_rule,
                                  tail_placement_rule,
                                  head_obj.bucket, head_obj);
    if (r < 0) {
      return r;
    }
  }
  cur_obj = manifest_gen.get_cur_obj(store);

  return 0;
}

int RGWPutObjProcessor_Append::pre_handle_data(bufferlist& bl, bool *has_tail)
{
  pending_data_bl.claim_append(bl);

  if (crypt) {
    bufferlist cache;
    if (!(*crypt)->encrypt(pending_data_bl, 0, pending_data_bl.length(), cache, data_ofs)) {
      return -ERR_INTERNAL_ERROR;
    }
    pending_data_bl.clear();
    pending_data_bl.claim(cache);
  }

  start_time = real_clock::now();

  if (head_obj_updated) {
    return 0;
  }

  // restore manifest environment
  uint64_t max_head_size = manifest.get_max_head_size();

  if (max_head_size && uint64_t(data_ofs) < max_head_size) {
    cur_part_ofs = 0;
    next_part_ofs = max_head_size;
  } else {
    cur_part_ofs = ((data_ofs - max_head_size) / max_chunk_size) * max_chunk_size + max_head_size;
    first_obj_offset = (data_ofs - max_head_size) % max_chunk_size;
    next_part_ofs = cur_part_ofs + max_chunk_size;
  }

  if (uint64_t(data_ofs) < max_head_size) {
    first_chunk_ofs = (head_obj_exist ? data_ofs : -1);
    // only append data to head_object, update it all in complete
    if (pending_data_bl.length() + uint64_t(data_ofs) < max_head_size) {
      need_append_head_obj = true;
      *has_tail = false;
      return 0;
    }
    uint64_t max_write_size = std::min(max_chunk_size, (uint64_t)next_part_ofs - data_ofs);
    max_write_size = std::min(max_write_size, max_head_size);
    pending_data_bl.splice(0, max_write_size, &bl);
    first_chunk.claim(bl);
    obj_len = max_write_size + data_ofs;
    int ret = prepare_next_part(obj_len);
    if (ret < 0) {
      return ret;
    }
    data_ofs += max_write_size;
  }

  if (!max_head_size) {
    is_first_chunk = false;
  }
  // head obj doesn't exist, update it all in complete
  // append should work with placement, which max_head_size maybe zero
  if (!head_obj_exist) {
    head_obj_updated = true;  // restore Manifest environment only once
    return 0;
  }

  // set RGW_ATTR_TARGET_SIZE, RGW_ATTR_APPEND_TIMEOUT xattr to head_obj before write tail data
  bufferlist timeout;

  try {
    encode(start_time, timeout);
  } catch (buffer::error& err) {
    ldout(store->ctx(), 5) << "error encode real_time:" << start_time << dendl;
    return -EIO;
  }

  map<string, bufferlist> attrs = astate->attrset;
  map<string, bufferlist> cmpattrs;
  if (need_cmpxattr) {
    bufferlist cur_size_bl;
    encode(*cur_accounted_size, cur_size_bl);
    cmpattrs[RGW_ATTR_TARGET_SIZE] = cur_size_bl;
  }
  if (cur_idtag.length() > 0) {
    cmpattrs[RGW_ATTR_ID_TAG] = cur_idtag;
  }
  bufferlist target_size_bl;
  encode(*cur_accounted_size + content_length, target_size_bl);
  attrs[RGW_ATTR_TARGET_SIZE] = target_size_bl;
  attrs[RGW_ATTR_APPEND_TIMEOUT] = timeout;

  int op_ret = store->set_attrs(&obj_ctx, bucket_info, head_obj, attrs, nullptr, &cmpattrs);
  if (op_ret < 0) {
    if (op_ret == -ECANCELED) {
      ldout(store->ctx(), 10) << "ERROR: conflict with another appending to same offset" << dendl;
      return -ERR_OFFSET_INCORRECT;
    }
    ldout(store->ctx(), 1) << "error at set_attrs, " << op_ret << dendl;
    return op_ret;
  }
  head_obj_updated = true;
  return 0;
}

RGWPutObjProcessor_Append::~RGWPutObjProcessor_Append() {
  if (is_complete) {
    return;
  }

  int r = 0;

  set<rgw_raw_obj>::iterator iter;
  rgw_raw_obj raw_head;

  if (!head_obj.empty()) {
    store->obj_to_raw(bucket_info.head_placement_rule, head_obj, &raw_head);
  }

  for (iter = written_objs.begin(); iter != written_objs.end(); ++iter) {
    const rgw_raw_obj& obj = *iter;
    if (!head_obj.empty() && obj == raw_head) {
      ldout(store->ctx(), 0) << "NOTE: we should not process the head object (" << obj << ") here" << dendl;
      continue;
    }

    if (iter == written_objs.begin() && first_obj_offset > 0) {
      r = store->truncate_raw_obj(obj, first_obj_offset, enable_skip_cache);
      if (r < 0 && r != -ENOENT) {
        ldout(store->ctx(), 5) << "WARNING: failed to truncate obj (" << obj << "), leaked" << dendl;
      }
    } else {
      r = store->delete_raw_obj(obj, enable_skip_cache);
      if (r < 0 && r != -ENOENT) {
        ldout(store->ctx(), 5) << "WARNING: failed to remove obj (" << obj << "), leaked" << dendl;
      }
    }
  }

  if (!head_obj_updated || !head_obj_exist) {
    dout(20) << "NOTE: jump restore target_size head_obj_updated:"
             << head_obj_updated << " head_obj_exist:" << head_obj_exist
             << dendl;
    return;
  }

  bufferlist cur_size_bl;
  if (!astate) {
    r = store->get_obj_state(&obj_ctx, bucket_info, head_obj, &astate);
    if (r < 0) {
      ldout(store->ctx(), 10) << __func__ << "() ERROR: get_obj_state "<< head_obj
                              << " ret:" << r << dendl;
      return;
    }
  }

  encode(*cur_accounted_size, cur_size_bl);
  astate->attrset[RGW_ATTR_TARGET_SIZE] = cur_size_bl;

  // restore targe_size, so other append request can process
  r = store->set_attrs(&obj_ctx, bucket_info, head_obj, astate->attrset, nullptr, nullptr);
  if (r < 0) {
    ldout(store->ctx(), 1) << "error at set_attrs, " << r << dendl;
  }

  is_complete = true;
}

int RGWPutObjProcessor_Append::handle_data(bufferlist& bl, off_t ofs, void **phandle, rgw_raw_obj *pobj, bool *again)
{
  // already append data into pending_data_bl in pre_handle_data()
  *phandle = NULL;
  uint64_t max_write_size = std::min(max_chunk_size, (uint64_t)next_part_ofs - data_ofs);
  // write tail data in do_complete()
  if (pending_data_bl.length() < max_write_size) {
    *again = false;
    return 0;
  }
  pending_data_bl.splice(0, max_write_size, &bl);

  /* do we have enough data pending accumulated that needs to be written? */
  *again = (pending_data_bl.length() >= max_chunk_size);
  off_t write_ofs = data_ofs;
  data_ofs = write_ofs + bl.length();
  bool exclusive = (!write_ofs && immutable_head()); /* immutable head object, need to verify nothing exists there
                                                        we could be racing with another upload, to the same
                                                        object and cleanup can be messy */

  // if append data to tail rados object after rgw_append_timeout, result from
  // huge stress in osd, abandon this slow append operation. Avoid new request
  // append to the same offset has successfully been operated, this slow append
  // operation rewrite it inappropriately.
  if (real_clock::now() > start_time + make_timespan(store->ctx()->_conf->rgw_append_timeout)) {
    return -ERR_OFFSET_INCORRECT;
  }

  int ret = write_data(bl, write_ofs, phandle, pobj, exclusive);
  if (ret >= 0) { /* we might return, need to clear bl as it was already sent */
    bl.clear();
  }
  return ret;
}

int RGWPutObjProcessor_Append::do_complete(size_t accounted_size, const string& etag,
                                           real_time *mtime, real_time set_mtime,
                                           map<string, bufferlist>& attrs,
                                           real_time delete_at,
                                           const char *if_match,
                                           const char *if_nomatch, const string *user_data,
                                           rgw_zone_set *zones_trace) {
  int r = complete_writing_data(need_append_head_obj);
  if (r < 0)
    return r;

  if (real_clock::now() > start_time + make_timespan(store->ctx()->_conf->rgw_append_timeout)) {
    return -ERR_OFFSET_INCORRECT;
  }

  obj_ctx.obj.set_atomic(head_obj);

  RGWRados::Object op_target(store, bucket_info, obj_ctx, head_obj);

  /* some object types shouldn't be versioned, e.g., multipart parts */
  op_target.set_versioning_disabled(!versioned_object);

  RGWRados::Object::Write obj_op(&op_target);

  obj_op.meta.data = &first_chunk;
  manifest.set_obj_size(accounted_size + *cur_accounted_size);
  obj_op.meta.manifest = &manifest;
  obj_op.meta.ptag = &unique_tag; /* use req_id as operation tag */
  obj_op.meta.if_match = if_match;
  obj_op.meta.if_nomatch = if_nomatch;
  obj_op.meta.mtime = mtime;
  obj_op.meta.set_mtime = set_mtime;
  obj_op.meta.owner = bucket_info.owner;
  if (!head_obj_exist) {
    obj_op.meta.flags = PUT_OBJ_CREATE;
  }
  obj_op.meta.olh_epoch = olh_epoch;
  obj_op.meta.delete_at = delete_at;
  obj_op.meta.user_data = user_data;
  obj_op.meta.zones_trace = zones_trace;
  obj_op.meta.modify_tail = true;
  obj_op.meta.head_placement_rule = manifest.get_head_placement_rule();
  obj_op.meta.storage_class = manifest.get_tail_placement().placement_rule.storage_class;
  obj_op.meta.is_transition = is_transition;
  obj_op.meta.appendable = true;

  auto iter = attrs.find(RGW_ATTR_TAGS);
  if (iter != attrs.end() && iter->second.length() > 0) {
    obj_op.meta.tags_bl = &(iter->second);
  } else {
    iter = astate->attrset.find(RGW_ATTR_TAGS);
    if (iter != astate->attrset.end() && iter->second.length() > 0) {
      obj_op.meta.tags_bl = &(iter->second);
    }
  }

  if (!cur_etag.empty()) {
    MD5 hash;
    char petag[CEPH_CRYPTO_MD5_DIGESTSIZE];
    char final_etag[CEPH_CRYPTO_MD5_DIGESTSIZE];
    char final_etag_str[CEPH_CRYPTO_MD5_DIGESTSIZE * 2 + 16];
    hex_to_buf(cur_etag.c_str(), petag, CEPH_CRYPTO_MD5_DIGESTSIZE);
    hash.Update((const unsigned char *)petag, sizeof(petag));
    hex_to_buf(etag.c_str(), petag, CEPH_CRYPTO_MD5_DIGESTSIZE);
    hash.Update((const unsigned char *)petag, sizeof(petag));
    hash.Final((unsigned char *)final_etag);
    buf_to_hex((unsigned char *)final_etag, sizeof(final_etag), final_etag_str);
    snprintf(&final_etag_str[CEPH_CRYPTO_MD5_DIGESTSIZE * 2],  sizeof(final_etag_str) 
      - CEPH_CRYPTO_MD5_DIGESTSIZE * 2, "-%lld", (long long)append_times + 1);
    bufferlist etag_bl;
    etag_bl.append(final_etag_str, strlen(final_etag_str) + 1);
    const_cast<string&>(etag) = string(final_etag_str);
    attrs[RGW_ATTR_ETAG] = etag_bl;
  }
  bufferlist bl;
  encode(accounted_size + *cur_accounted_size, bl);
  attrs[RGW_ATTR_TARGET_SIZE] = bl;
  r = obj_op.write_meta(*cur_accounted_size + obj_len, *cur_accounted_size + accounted_size, attrs, first_chunk_ofs);
  if (r < 0) {
    return r;
  }
  *cur_accounted_size += accounted_size;
  canceled = obj_op.meta.canceled;

  return 0;
}

int RGWRados::watch(const string& oid, uint64_t *watch_handle, librados::WatchCtx2 *ctx) {
  int r = control_pool_ctx.watch2(oid, watch_handle, ctx);
  if (r < 0)
    return r;
  return 0;
}

int RGWRados::unwatch(uint64_t watch_handle)
{
  int r = control_pool_ctx.unwatch2(watch_handle);
  if (r < 0) {
    ldout(cct, 0) << "ERROR: rados->unwatch2() returned r=" << r << dendl;
    return r;
  }
  r = rados[0].watch_flush();
  if (r < 0) {
    ldout(cct, 0) << "ERROR: rados->watch_flush() returned r=" << r << dendl;
    return r;
  }
  return 0;
}

void RGWRados::add_watcher(int i)
{
  ldout(cct, 20) << "add_watcher() i=" << i << dendl;
  Mutex::Locker l(watchers_lock);
  watchers_set.insert(i);
  if (watchers_set.size() ==  (size_t)num_watchers) {
    ldout(cct, 2) << "all " << num_watchers << " watchers are set, enabling cache" << dendl;
    set_cache_enabled(true);
  }
}

void RGWRados::remove_watcher(int i)
{
  ldout(cct, 20) << "remove_watcher() i=" << i << dendl;
  Mutex::Locker l(watchers_lock);
  size_t orig_size = watchers_set.size();
  watchers_set.erase(i);
  if (orig_size == (size_t)num_watchers &&
      watchers_set.size() < orig_size) { /* actually removed */
    ldout(cct, 2) << "removed watcher, disabling cache" << dendl;
    set_cache_enabled(false);
  }
}

class RGWWatcher : public librados::WatchCtx2 {
  RGWRados *rados;
  int index;
  string oid;
  uint64_t watch_handle;

  class C_ReinitWatch : public Context {
    RGWWatcher *watcher;
    public:
      explicit C_ReinitWatch(RGWWatcher *_watcher) : watcher(_watcher) {}
      void finish(int r) override {
        watcher->reinit();
      }
  };
public:
  RGWWatcher(RGWRados *r, int i, const string& o) : rados(r), index(i), oid(o), watch_handle(0) {}
  void handle_notify(uint64_t notify_id,
		     uint64_t cookie,
		     uint64_t notifier_id,
		     bufferlist& bl) override {
    ldout(rados->ctx(), 10) << "RGWWatcher::handle_notify() "
			    << " notify_id " << notify_id
			    << " cookie " << cookie
			    << " notifier " << notifier_id
			    << " bl.length()=" << bl.length() << dendl;
    rados->watch_cb(notify_id, cookie, notifier_id, bl);

    bufferlist reply_bl; // empty reply payload
    rados->control_pool_ctx.notify_ack(oid, notify_id, cookie, reply_bl);
  }
  void handle_error(uint64_t cookie, int err) override {
    lderr(rados->ctx()) << "RGWWatcher::handle_error cookie " << cookie
			<< " err " << cpp_strerror(err) << dendl;
    rados->remove_watcher(index);
    rados->schedule_context(new C_ReinitWatch(this));
  }

  void reinit() {
    int ret = unregister_watch();
    if (ret < 0) {
      ldout(rados->ctx(), 0) << "ERROR: unregister_watch() returned ret=" << ret << dendl;
      return;
    }
    ret = register_watch();
    if (ret < 0) {
      ldout(rados->ctx(), 0) << "ERROR: register_watch() returned ret=" << ret << dendl;
      return;
    }
  }

  int unregister_watch() {
    int r = rados->unwatch(watch_handle);
    if (r < 0) {
      return r;
    }
    rados->remove_watcher(index);
    return 0;
  }

  int register_watch() {
    int r = rados->watch(oid, &watch_handle, this);
    if (r < 0) {
      return r;
    }
    rados->add_watcher(index);
    return 0;
  }
};

class RGWMetaNotifierManager : public RGWCoroutinesManager {
  RGWRados *store;
  RGWHTTPManager http_manager;

public:
  RGWMetaNotifierManager(RGWRados *_store) : RGWCoroutinesManager(_store->ctx(), _store->get_cr_registry()), store(_store),
                                             http_manager(store->ctx(), completion_mgr) {
    http_manager.start();
  }

  int notify_all(map<string, RGWRESTConn *>& conn_map, set<int>& shards) {
    rgw_http_param_pair pairs[] = { { "type", "metadata" },
                                    { "notify", NULL },
                                    { NULL, NULL } };

    list<RGWCoroutinesStack *> stacks;
    for (map<string, RGWRESTConn *>::iterator iter = conn_map.begin(); iter != conn_map.end(); ++iter) {
      RGWRESTConn *conn = iter->second;
      RGWCoroutinesStack *stack = new RGWCoroutinesStack(store->ctx(), this);
      stack->call(new RGWPostRESTResourceCR<set<int>, int>(store->ctx(), conn, &http_manager, "/admin/log", pairs, shards, NULL));

      stacks.push_back(stack);
    }
    return run(stacks);
  }
};

class RGWDataNotifierManager : public RGWCoroutinesManager {
  RGWRados *store;
  RGWHTTPManager http_manager;

public:
  RGWDataNotifierManager(RGWRados *_store) : RGWCoroutinesManager(_store->ctx(), _store->get_cr_registry()), store(_store),
                                             http_manager(store->ctx(), completion_mgr) {
    http_manager.start();
  }

  int notify_all(map<string, RGWRESTConn *>& conn_map, map<int, set<string> >& shards) {
    rgw_http_param_pair pairs[] = { { "type", "data" },
                                    { "notify", NULL },
                                    { "source-zone", store->get_zone_params().get_id().c_str() },
                                    { NULL, NULL } };

    list<RGWCoroutinesStack *> stacks;
    for (map<string, RGWRESTConn *>::iterator iter = conn_map.begin(); iter != conn_map.end(); ++iter) {
      RGWRESTConn *conn = iter->second;
      RGWCoroutinesStack *stack = new RGWCoroutinesStack(store->ctx(), this);
      stack->call(new RGWPostRESTResourceCR<map<int, set<string> >, int>(store->ctx(), conn, &http_manager, "/admin/log", pairs, shards, NULL));

      stacks.push_back(stack);
    }
    return run(stacks);
  }
};

/* class RGWRadosThread */

void RGWRadosThread::start()
{
  worker = new Worker(cct, this);
  worker->create(thread_name.c_str());
}

void RGWRadosThread::stop()
{
  down_flag = true;
  stop_process();
  if (worker) {
    worker->signal();
    worker->join();
  }
  delete worker;
  worker = NULL;
}

void *RGWRadosThread::Worker::entry() {
  uint64_t msec = processor->interval_msec();
  utime_t interval = utime_t(msec / 1000, (msec % 1000) * 1000000);

  do {
    utime_t start = ceph_clock_now();
    int r = processor->process();
    if (r < 0) {
      dout(0) << "ERROR: processor->process() returned error r=" << r << dendl;
    }

    if (processor->going_down())
      break;

    utime_t end = ceph_clock_now();
    end -= start;

    uint64_t cur_msec = processor->interval_msec();
    if (cur_msec != msec) { /* was it reconfigured? */
      msec = cur_msec;
      interval = utime_t(msec / 1000, (msec % 1000) * 1000000);
    }

    if (cur_msec > 0) {
      if (interval <= end)
        continue; // next round

      utime_t wait_time = interval;
      wait_time -= end;

      wait_interval(wait_time);
    } else {
      wait();
    }
  } while (!processor->going_down());

  return NULL;
}

class RGWMetaNotifier : public RGWRadosThread {
  RGWMetaNotifierManager notify_mgr;
  RGWMetadataLog *const log;

  uint64_t interval_msec() override {
    return cct->_conf->rgw_md_notify_interval_msec;
  }
  void stop_process() override {
    notify_mgr.stop();
  }
public:
  RGWMetaNotifier(RGWRados *_store, RGWMetadataLog* log)
    : RGWRadosThread(_store, "meta-notifier"), notify_mgr(_store), log(log) {}

  int process() override;
};

int RGWMetaNotifier::process()
{
  set<int> shards;

  log->read_clear_modified(shards);

  if (shards.empty()) {
    return 0;
  }

  for (set<int>::iterator iter = shards.begin(); iter != shards.end(); ++iter) {
    ldout(cct, 20) << __func__ << "(): notifying mdlog change, shard_id=" << *iter << dendl;
  }

  notify_mgr.notify_all(store->zone_conn_map, shards);

  return 0;
}

class RGWDataNotifier : public RGWRadosThread {
  RGWDataNotifierManager notify_mgr;

  uint64_t interval_msec() override {
    return cct->_conf->get_val<int64_t>("rgw_data_notify_interval_msec");
  }
  void stop_process() override {
    notify_mgr.stop();
  }
public:
  RGWDataNotifier(RGWRados *_store) : RGWRadosThread(_store, "data-notifier"), notify_mgr(_store) {}

  int process() override;
};

int RGWDataNotifier::process()
{
  if (!store->data_log) {
    return 0;
  }

  map<string, map<int, set<string> > > shards;

  store->data_log->read_clear_modified(shards);

  if (shards.empty()) {
    return 0;
  }
  for (auto& z : shards) {
    for (map<int, set<string> >::iterator iter = z.second.begin(); iter != z.second.end(); ++iter) {
      ldout(cct, 20) << __func__ << "(): notifying datalog change, dest zone:" << z.first
                     << ", shard_id=" << iter->first << ": " << iter->second << dendl;
    }
    map<string, RGWRESTConn *> conn_map;
    if (store->zone_data_notify_to_map.find(z.first) == store->zone_data_notify_to_map.end()) {
      ldout(cct, 5) << __func__ << "(): zone doesn't exist in notify map:" << z.first << dendl;
      continue;
    }
    conn_map[z.first] = store->zone_data_notify_to_map[z.first];
    notify_mgr.notify_all(conn_map, z.second);
  }

  return 0;
}

class RGWAwakeDataSync : public RGWRadosThread {
  uint64_t interval_msec() override {
    return cct->_conf->get_val<int64_t>("rgw_sync_data_awake_interval_sec") * 1000;
  }
  void stop_process() override {
  }

public:
  RGWAwakeDataSync(RGWRados *_store) : RGWRadosThread(_store, "awake-data-sync") {}

  int process() override;
};

int RGWAwakeDataSync::process() {
  if (store->get_zonegroup().zones.size() <= 1) {
    return 0;
  }
  RGWAccessHandle handle = nullptr;
  string& zone = store->get_zone().name;

  if (store->list_buckets_init(&handle) >= 0) {
    rgw_bucket_dir_entry obj;
    while (store->list_buckets_next(obj, &handle) >= 0) {
      RGWObjectCtx obj_ctx(store);
      RGWBucketInfo bucket_info;
      map<string, bufferlist> attrs;
      bool need_notify = false;
      bool update_bucket = false;

      int ret = store->get_bucket_info(obj_ctx, "", obj.key.name, bucket_info, NULL, &attrs);
      if (ret < 0) {
        ldout(store->ctx(), 0) << __func__ << "() get bucket(" << obj.key.name 
          << ") info error:" << ret << dendl;
        continue;
      }

      // check if need resync/stop bilog, and change syncstopped in rgw_bucket_dir_header
      if (!bucket_info.bilog_started(zone)) {
        if (bucket_info.datasync_flag_enabled(zone) &&
            !store->datasync_all_disabled(bucket_info)) {
          ldout(store->ctx(), 10) << __func__ << "() resync bilog entries, bucket:"
            << bucket_info.bucket.name << dendl;
          ret = store->resync_bi_log_entries(bucket_info, -1);
          if (ret < 0) {
            lderr(store->ctx()) << __func__ << "() ERROR: failed writing resync bilog, bucket:"
              << bucket_info.bucket.name << dendl;
            return ret;
          }
          bucket_info.bilog_flags[zone] = true;
          update_bucket = true;
        }
      } else if (!bucket_info.datasync_flag_enabled(zone) || store->datasync_all_disabled(bucket_info)) {
        ldout(store->ctx(), 10) << __func__ << "() stop bilog entries, bucket:"
          << bucket_info.bucket.name << dendl;
        ret = store->stop_bi_log_entries(bucket_info, -1);
        if (ret < 0) {
          lderr(store->ctx()) << __func__ << "() ERROR: failed writing bilog" << dendl;
          return ret;
        }
        bucket_info.bilog_flags[zone] = false;
        update_bucket = true;
      }

      // check if bucket sync time is expire or approach(send notify meanwhile)
      for (auto& z : bucket_info.sync_config) {
        // only update is_delay for self zone
        if (z.first.compare(zone) != 0)
          continue;

        uint64_t start_time = z.second.start_sync_time;
        uint64_t stop_time = z.second.stop_sync_time;
        time_t now_t = time(nullptr);
        struct tm now_tm;
        localtime_r(&now_t, &now_tm);
        uint64_t now_minute = now_tm.tm_hour * 100 + now_tm.tm_min;

        if (stop_time > start_time ?
            now_minute < start_time || now_minute > stop_time :
            now_minute < start_time && now_minute > stop_time) {
          if (!z.second.is_delay) {
            ldout(store->ctx(), 15) << __func__ << "bucket (" << bucket_info.bucket.name
                                    << ") can't sync at present for zone:" << z.first << dendl;
            z.second.is_delay = true;
            update_bucket = true;
          }
        } else {
          if (z.second.is_delay) {
            ldout(store->ctx(), 15) << __func__ << "bucket (" << bucket_info.bucket.name
                                    << ") can sync from now for zone:" << z.first << dendl;
            need_notify = true;
            z.second.is_delay = false;
          }
        }
      }

      // update bucket info
      if (update_bucket || need_notify) {
        ret = store->put_bucket_instance_info(bucket_info, false, real_time(), &attrs);
        if (ret < 0) {
          ldout(store->ctx(), 0) << __func__ << ", put bucket (" << bucket_info.bucket.name 
            << ") info error:" << ret << dendl;
        }
      }

      if (need_notify) {
        // Don't process further in this round if bucket is resharding
        if (bucket_info.reshard_status == CLS_RGW_RESHARD_IN_PROGRESS) {
          ldout(store->ctx(), 0) << __func__ << "() bucket is resharding:" << bucket_info.bucket.name << dendl;
          continue;
        }

        librados::IoCtx index_ctx;
        map<int, string> oids;
        map<int, cls_rgw_bi_log_list_ret> bi_log_lists;
        ret = store->open_bucket_index(bucket_info, index_ctx, oids);
        if (ret < 0) {
          ldout(store->ctx(), 0) << __func__ << "() open bucket(" << bucket_info.bucket.name 
            << ") index error:" << ret << dendl;
          continue;
        }

        BucketIndexShardsManager marker_mgr;
        ret = marker_mgr.from_string("", -1);
        if (ret < 0) {
          ldout(store->ctx(), 0) << __func__ << "() BucketIndexShardsManager from_string error:" << ret << dendl;
          continue;
        }

        ret = CLSRGWIssueBILogList(index_ctx, marker_mgr, 1, oids, bi_log_lists, cct->_conf->rgw_bucket_index_max_aio)();
        if (ret < 0) {
          ldout(store->ctx(), 0) << __func__ << "() issue bilog list error:" << ret << dendl;
          continue;
        }

        map<int, cls_rgw_bi_log_list_ret>::iterator miter = bi_log_lists.begin();
        for (; miter != bi_log_lists.end(); ++miter) {
          if (miter->second.entries.size() > 0) {
            // need notify and add change log to data_log[i]
            store->data_log->add_entry(bucket_info.bucket, miter->first);
          }
        }

      }

    }

  }
  return 0;
}

class RGWSyncProcessorThread : public RGWRadosThread {
public:
  RGWSyncProcessorThread(RGWRados *_store, const string& thread_name = "radosgw") : RGWRadosThread(_store, thread_name) {}
  RGWSyncProcessorThread(RGWRados *_store) : RGWRadosThread(_store) {}
  ~RGWSyncProcessorThread() override {}
  int init() override = 0 ;
  int process() override = 0;
};

class RGWMetaSyncProcessorThread : public RGWSyncProcessorThread
{
  RGWMetaSyncStatusManager sync;

  uint64_t interval_msec() override {
    return 0; /* no interval associated, it'll run once until stopped */
  }
  void stop_process() override {
    sync.stop();
  }
public:
  RGWMetaSyncProcessorThread(RGWRados *_store, RGWAsyncRadosProcessor *async_rados)
    : RGWSyncProcessorThread(_store, "meta-sync"), sync(_store, async_rados) {}

  void wakeup_sync_shards(set<int>& shard_ids) {
    for (set<int>::iterator iter = shard_ids.begin(); iter != shard_ids.end(); ++iter) {
      sync.wakeup(*iter);
    }
  }
  RGWMetaSyncStatusManager* get_manager() { return &sync; }

  int init() override {
    int ret = sync.init();
    if (ret < 0) {
      ldout(store->ctx(), 0) << "ERROR: sync.init() returned " << ret << dendl;
      return ret;
    }
    return 0;
  }

  int process() override {
    sync.run();
    return 0;
  }
};

class RGWDataSyncProcessorThread : public RGWSyncProcessorThread
{
  RGWDataSyncStatusManager sync;
  bool initialized;

  uint64_t interval_msec() override {
    if (initialized) {
      return 0; /* no interval associated, it'll run once until stopped */
    } else {
#define DATA_SYNC_INIT_WAIT_SEC 20
      return DATA_SYNC_INIT_WAIT_SEC * 1000;
    }
  }
  void stop_process() override {
    sync.stop();
  }
public:
  RGWDataSyncProcessorThread(RGWRados *_store, RGWAsyncRadosProcessor *async_rados,
                             const string& _source_zone)
    : RGWSyncProcessorThread(_store, "data-sync"),
      sync(_store, async_rados, _source_zone),
      initialized(false) {}

  void wakeup_sync_shards(map<int, set<string> >& shard_ids) {
    for (map<int, set<string> >::iterator iter = shard_ids.begin(); iter != shard_ids.end(); ++iter) {
      sync.wakeup(iter->first, iter->second);
    }
  }
  RGWDataSyncStatusManager* get_manager() { return &sync; }

  int init() override {
    return 0;
  }

  int process() override {
    while (!initialized) {
      if (going_down()) {
        return 0;
      }
      int ret = sync.init();
      if (ret >= 0) {
        initialized = true;
        break;
      }
      /* we'll be back! */
      return 0;
    }
    sync.run();
    return 0;
  }
};

class RGWSyncLogTrimThread : public RGWSyncProcessorThread
{
  RGWCoroutinesManager crs;
  RGWRados *store;
  rgw::BucketTrimManager *bucket_trim;
  RGWHTTPManager http;
  const utime_t trim_interval;
  const utime_t bucket_clear_interval;

  uint64_t interval_msec() override { return 0; }
  void stop_process() override { crs.stop(); }
public:
  RGWSyncLogTrimThread(RGWRados *store, rgw::BucketTrimManager *bucket_trim,
                       int interval, int bc_interval)
    : RGWSyncProcessorThread(store, "sync-log-trim"),
      crs(store->ctx(), store->get_cr_registry()), store(store),
      bucket_trim(bucket_trim),
      http(store->ctx(), crs.get_completion_mgr()),
      trim_interval(interval, 0), bucket_clear_interval(bc_interval, 0)
  {}

  int init() override {
    return http.start();
  }
  int process() override {
    list<RGWCoroutinesStack*> stacks;
    auto meta = new RGWCoroutinesStack(store->ctx(), &crs);
    meta->call(create_meta_log_trim_cr(store, &http,
                                       cct->_conf->rgw_md_log_max_shards,
                                       trim_interval));
    stacks.push_back(meta);

    auto data = new RGWCoroutinesStack(store->ctx(), &crs);
    data->call(create_data_log_trim_cr(store, &http,
                                       cct->_conf->rgw_data_log_num_shards,
                                       trim_interval));
    stacks.push_back(data);

    auto bucket = new RGWCoroutinesStack(store->ctx(), &crs);
    bucket->call(bucket_trim->create_bucket_trim_cr(&http));
    stacks.push_back(bucket);

    auto bucket_data = new RGWCoroutinesStack(store->ctx(), &crs);
    bucket_data->call(bucket_trim->create_bucket_clear_cr(&http, trim_interval, bucket_clear_interval));
    stacks.push_back(bucket_data);

    crs.run(stacks);
    return 0;
  }
};

void RGWRados::wakeup_meta_sync_shards(set<int>& shard_ids)
{
  Mutex::Locker l(meta_sync_thread_lock);
  if (meta_sync_processor_thread) {
    meta_sync_processor_thread->wakeup_sync_shards(shard_ids);
  }
}

void RGWRados::wakeup_data_sync_shards(const string& source_zone, map<int, set<string> >& shard_ids)
{
  ldout(ctx(), 20) << __func__ << ": source_zone=" << source_zone << ", shard_ids=" << shard_ids << dendl;
  Mutex::Locker l(data_sync_thread_lock);
  map<string, RGWDataSyncProcessorThread *>::iterator iter = data_sync_processor_threads.find(source_zone);
  if (iter == data_sync_processor_threads.end()) {
    ldout(ctx(), 10) << __func__ << ": couldn't find sync thread for zone " << source_zone << ", skipping async data sync processing" << dendl;
    return;
  }

  RGWDataSyncProcessorThread *thread = iter->second;
  assert(thread);
  thread->wakeup_sync_shards(shard_ids);
}

RGWMetaSyncStatusManager* RGWRados::get_meta_sync_manager()
{
  Mutex::Locker l(meta_sync_thread_lock);
  if (meta_sync_processor_thread) {
    return meta_sync_processor_thread->get_manager();
  }
  return nullptr;
}

RGWDataSyncStatusManager* RGWRados::get_data_sync_manager(const std::string& source_zone)
{
  Mutex::Locker l(data_sync_thread_lock);
  auto thread = data_sync_processor_threads.find(source_zone);
  if (thread == data_sync_processor_threads.end()) {
    return nullptr;
  }
  return thread->second->get_manager();
}

int RGWRados::get_required_alignment(const rgw_pool& pool, uint64_t *alignment)
{
  IoCtx ioctx;
  int r = open_pool_ctx(pool, ioctx);
  if (r < 0) {
    ldout(cct, 0) << "ERROR: open_pool_ctx() returned " << r << dendl;
    return r;
  }

  bool requires;
  r = ioctx.pool_requires_alignment2(&requires);
  if (r < 0) {
    ldout(cct, 0) << "ERROR: ioctx.pool_requires_alignment2() returned " 
      << r << dendl;
    return r;
  }

  if (!requires) {
    *alignment = 0;
    return 0;
  }

  uint64_t align;
  r = ioctx.pool_required_alignment2(&align);
  if (r < 0) {
    ldout(cct, 0) << "ERROR: ioctx.pool_required_alignment2() returned " 
      << r << dendl;
    return r;
  }
  if (align != 0) {
    ldout(cct, 20) << "required alignment=" << align << dendl;
  }
  *alignment = align;
  return 0;
}

int RGWRados::get_max_chunk_size(const rgw_pool& pool, uint64_t *max_chunk_size)
{
  uint64_t alignment = 0;
  int r = get_required_alignment(pool, &alignment);
  if (r < 0) {
    return r;
  }

  uint64_t config_chunk_size = cct->_conf->rgw_max_chunk_size;

  if (alignment == 0) {
    *max_chunk_size = config_chunk_size;
    return 0;
  }

  if (config_chunk_size <= alignment) {
    *max_chunk_size = alignment;
    return 0;
  }

  *max_chunk_size = config_chunk_size - (config_chunk_size % alignment);

  ldout(cct, 20) << "max_chunk_size=" << *max_chunk_size << dendl;

  return 0;
}

int RGWRados::get_max_chunk_size(const rgw_placement_rule& placement_rule, const rgw_obj& obj,
                                 uint64_t *max_chunk_size)
{
   rgw_pool pool;
  if (!get_obj_data_pool(placement_rule, obj, &pool)) {
    ldout(cct, 0) << "ERROR: failed to get data pool for object " << obj << dendl;
    return -EIO;
  }
  ldout(cct, 1) << "get_max_chunk_size pool: " << pool.name << dendl;
  return get_max_chunk_size(pool, max_chunk_size);
}

class RGWIndexCompletionManager;

struct complete_op_data {
  Mutex lock{"complete_op_data"};
  AioCompletion *rados_completion{nullptr};
  int manager_shard_id{-1};
  RGWIndexCompletionManager *manager{nullptr};
  rgw_obj obj;
  RGWModifyOp op;
  string tag;
  rgw_bucket_entry_ver ver;
  cls_rgw_obj_key key;
  rgw_bucket_dir_entry_meta dir_meta;
  list<cls_rgw_obj_key> remove_objs;
  bool log_op;
  uint16_t bilog_op;
  rgw_zone_set zones_trace;

  bool stopped{false};

  void stop() {
    Mutex::Locker l(lock);
    stopped = true;
  }
};

class RGWIndexCompletionThread : public RGWRadosThread {
  RGWRados *store;

  uint64_t interval_msec() override {
    return 0;
  }

  list<complete_op_data *> completions;

  Mutex completions_lock;
public:
  RGWIndexCompletionThread(RGWRados *_store)
    : RGWRadosThread(_store, "index-complete"), store(_store), completions_lock("RGWIndexCompletionThread::completions_lock") {}

  int process() override;

  void add_completion(complete_op_data *completion) {
    {
      Mutex::Locker l(completions_lock);
      completions.push_back(completion);
    }

    signal();
  }
};

int RGWIndexCompletionThread::process()
{
  list<complete_op_data *> comps;

  {
    Mutex::Locker l(completions_lock);
    completions.swap(comps);
  }

  for (auto c : comps) {
    std::unique_ptr<complete_op_data> up{c};

    if (going_down()) {
      continue;
    }
    ldout(store->ctx(), 20) << __func__ << "(): handling completion for key=" << c->key << dendl;

    RGWRados::BucketShard bs(store);
    RGWBucketInfo bucket_info;

    int r = bs.init(c->obj.bucket, c->obj, &bucket_info);
    if (r < 0) {
      ldout(cct, 0) << "ERROR: " << __func__ << "(): failed to initialize BucketShard, obj=" << c->obj << " r=" << r << dendl;
      /* not much to do */
      continue;
    }

    r = store->guard_reshard(&bs, c->obj, bucket_info,
			     [&](RGWRados::BucketShard *bs) -> int {
			       librados::ObjectWriteOperation o;
			       cls_rgw_guard_bucket_resharding(o, -ERR_BUSY_RESHARDING);
			       cls_rgw_bucket_complete_op(o, c->op, c->tag, c->ver, c->key, c->dir_meta, &c->remove_objs,
							  c->log_op, c->bilog_op, &c->zones_trace);
			       return bs->index_ctx.operate(bs->bucket_obj, &o);
                             });
    if (r < 0) {
      ldout(cct, 0) << "ERROR: " << __func__ << "(): bucket index completion failed, obj=" << c->obj << " r=" << r << dendl;
      /* ignoring error, can't do anything about it */
      continue;
    }

    bool ignore_bucket_initial = true;
    #ifdef WITH_UNAUTO_SYNC
      ignore_bucket_initial = !(bucket_info.disable_sync.size() == 0 && bucket_info.bilog_flags.size() == 0);
    #endif
    if (bucket_info.datasync_flag_enabled(store->get_zone().id) &&
        !store->datasync_all_disabled(bucket_info) && ignore_bucket_initial) {
      r = store->data_log->add_entry(bs.bucket, bs.shard_id);
      if (r < 0) {
        lderr(store->ctx()) << __func__ << "() ERROR: failed writing data log" << dendl;
      }
    }
  }

  return 0;
}

class RGWIndexCompletionManager {
  RGWRados *store{nullptr};
  vector<Mutex *> locks;
  vector<set<complete_op_data *> > completions;

  RGWIndexCompletionThread *completion_thread{nullptr};

  int num_shards;

  std::atomic<int> cur_shard {0};


public:
  RGWIndexCompletionManager(RGWRados *_store) : store(_store) {
    num_shards = store->ctx()->_conf->rgw_thread_pool_size;

    for (int i = 0; i < num_shards; i++) {
      char buf[64];
      snprintf(buf, sizeof(buf), "RGWIndexCompletionManager::lock::%d", i);
      locks.push_back(new Mutex(buf));
    }

    completions.resize(num_shards);
  }
  ~RGWIndexCompletionManager() {
    stop();

    for (auto l : locks) {
      delete l;
    }
  }

  int next_shard() {
    int result = cur_shard % num_shards;
    cur_shard++;
    return result;
  }

  void create_completion(const rgw_obj& obj,
                         RGWModifyOp op, string& tag,
                         rgw_bucket_entry_ver& ver,
                         const cls_rgw_obj_key& key,
                         rgw_bucket_dir_entry_meta& dir_meta,
                         list<cls_rgw_obj_key> *remove_objs, bool log_op,
                         uint16_t bilog_op,
                         rgw_zone_set *zones_trace,
                         complete_op_data **result);
  bool handle_completion(completion_t cb, complete_op_data *arg);

  int start() {
    completion_thread = new RGWIndexCompletionThread(store);
    int ret = completion_thread->init();
    if (ret < 0) {
      return ret;
    }
    completion_thread->start();
    return 0;
  }
  void stop() {
    if (completion_thread) {
      completion_thread->stop();
      delete completion_thread;
    }

    for (int i = 0; i < num_shards; ++i) {
      Mutex::Locker l(*locks[i]);
      for (auto c : completions[i]) {
        c->stop();
      }
    }
    completions.clear();
  }
};

static void obj_complete_cb(completion_t cb, void *arg)
{
  complete_op_data *completion = (complete_op_data *)arg;
  completion->lock.Lock();
  if (completion->stopped) {
    completion->lock.Unlock(); /* can drop lock, no one else is referencing us */
    delete completion;
    return;
  }
  bool need_delete = completion->manager->handle_completion(cb, completion);
  completion->lock.Unlock();
  if (need_delete) {
    delete completion;
  }
}


void RGWIndexCompletionManager::create_completion(const rgw_obj& obj,
                                                  RGWModifyOp op, string& tag,
                                                  rgw_bucket_entry_ver& ver,
                                                  const cls_rgw_obj_key& key,
                                                  rgw_bucket_dir_entry_meta& dir_meta,
                                                  list<cls_rgw_obj_key> *remove_objs, bool log_op,
                                                  uint16_t bilog_op,
                                                  rgw_zone_set *zones_trace,
                                                  complete_op_data **result)
{
  complete_op_data *entry = new complete_op_data;

  int shard_id = next_shard();

  entry->manager_shard_id = shard_id;
  entry->manager = this;
  entry->obj = obj;
  entry->op = op;
  entry->tag = tag;
  entry->ver = ver;
  entry->key = key;
  entry->dir_meta = dir_meta;
  entry->log_op = log_op;
  entry->bilog_op = bilog_op;

  if (remove_objs) {
    for (auto iter = remove_objs->begin(); iter != remove_objs->end(); ++iter) {
      entry->remove_objs.push_back(*iter);
    }
  }

  if (zones_trace) {
    entry->zones_trace = *zones_trace;
  } else {
    entry->zones_trace.insert(store->get_zone().id);
  }

  *result = entry;

  entry->rados_completion = librados::Rados::aio_create_completion(entry, NULL, obj_complete_cb);

  Mutex::Locker l(*locks[shard_id]);
  completions[shard_id].insert(entry);
}

bool RGWIndexCompletionManager::handle_completion(completion_t cb, complete_op_data *arg)
{
  int shard_id = arg->manager_shard_id;
  {
    Mutex::Locker l(*locks[shard_id]);

    auto& comps = completions[shard_id];

    auto iter = comps.find(arg);
    if (iter == comps.end()) {
      return true;
    }

    comps.erase(iter);
  }

  int r = rados_aio_get_return_value(cb);
  if (r != -ERR_BUSY_RESHARDING) {
    return true;
  }
  completion_thread->add_completion(arg);
  return false;
}

void RGWRados::finalize()
{
  auto admin_socket = cct->get_admin_socket();
  for (auto cmd : admin_commands) {
    int r = admin_socket->unregister_command(cmd[0]);
    if (r < 0) {
      lderr(cct) << "ERROR: fail to unregister admin socket command (r=" << r
                 << ")" << dendl;
    }
  }

  if (run_sync_thread) {
    Mutex::Locker l(meta_sync_thread_lock);
    meta_sync_processor_thread->stop();

    Mutex::Locker dl(data_sync_thread_lock);
    for (auto iter : data_sync_processor_threads) {
      RGWDataSyncProcessorThread *thread = iter.second;
      thread->stop();
    }
    if (sync_log_trimmer) {
      sync_log_trimmer->stop();
    }
  }
  if (async_rados) {
    async_rados->stop();
  }
  if (async_processor) {
    async_processor->stop();
  }
  if (run_sync_thread) {
    delete meta_sync_processor_thread;
    meta_sync_processor_thread = NULL;
    Mutex::Locker dl(data_sync_thread_lock);
    for (auto iter : data_sync_processor_threads) {
      RGWDataSyncProcessorThread *thread = iter.second;
      delete thread;
    }
    data_sync_processor_threads.clear();
    delete sync_log_trimmer;
    sync_log_trimmer = nullptr;
    bucket_trim = boost::none;
  }
  if (finisher) {
    finisher->stop();
  }
  if (need_watch_notify()) {
    finalize_watch();
  }
  if (finisher) {
    /* delete finisher only after cleaning up watches, as watch error path might call
     * into finisher. We stop finisher before finalizing watch to make sure we don't
     * actually handle any racing work
     */
    delete finisher;
  }
  if (meta_notifier) {
    meta_notifier->stop();
    delete meta_notifier;
  }
  if (data_notifier) {
    data_notifier->stop();
    delete data_notifier;
  }
  delete data_log;
  delete sync_tracer;
  if (async_rados) {
    delete async_rados;
  }
  if (async_processor) {
    delete async_processor;
  }

  delete lc;
  lc = NULL; 

  delete gc;
  gc = NULL;

  delete obj_expirer;
  obj_expirer = NULL;

  delete rest_master_conn;

  map<string, RGWRESTConn *>::iterator iter;
  for (iter = zone_conn_map.begin(); iter != zone_conn_map.end(); ++iter) {
    RGWRESTConn *conn = iter->second;
    delete conn;
  }

  for (iter = zonegroup_conn_map.begin(); iter != zonegroup_conn_map.end(); ++iter) {
    RGWRESTConn *conn = iter->second;
    delete conn;
  }
  RGWQuotaHandler::free_handler(quota_handler);
  if (cr_registry) {
    cr_registry->put();
  }
  delete meta_mgr;
  delete binfo_cache;
  delete obj_tombstone_cache;
  delete sync_modules_manager;

  if (reshard_wait.get()) {
    reshard_wait->stop();
    reshard_wait.reset();
  }

  if (run_reshard_thread) {
    reshard->stop_processor();
  }
  delete reshard;
  delete index_completion_manager;
}

/** 
 * Initialize the RADOS instance and prepare to do other ops
 * Returns 0 on success, -ERR# on failure.
 */
int RGWRados::init_rados()
{
  int ret = 0;
  auto admin_socket = cct->get_admin_socket();
  for (auto cmd : admin_commands) {
    int r = admin_socket->register_command(cmd[0], cmd[1], this,
                                           cmd[2]);
    if (r < 0) {
      lderr(cct) << "ERROR: fail to register admin socket command (r=" << r
                 << ")" << dendl;
      return r;
    }
  }

  auto handles = std::vector<librados::Rados>{static_cast<size_t>(cct->_conf->rgw_num_rados_handles)};

  for (auto& r : handles) {
    ret = r.init_with_context(cct);
    if (ret < 0) {
      return ret;
    }
    ret = r.connect();
    if (ret < 0) {
      return ret;
    }
  }

  sync_modules_manager = new RGWSyncModulesManager();

  rgw_register_sync_modules(sync_modules_manager);

  auto crs = std::unique_ptr<RGWCoroutinesManagerRegistry>{
    new RGWCoroutinesManagerRegistry(cct)};
  ret = crs->hook_to_admin_command("cr dump");
  if (ret < 0) {
    return ret;
  }

  meta_mgr = new RGWMetadataManager(cct, this);
  data_log = new RGWDataChangesLog(cct, this);
  cr_registry = crs.release();

  std::swap(handles, rados);
  return ret;
}


int RGWRados::register_to_service_map(const string& daemon_type, const map<string, string>& meta)
{
  map<string,string> metadata = meta;
  metadata["num_handles"] = stringify(rados.size());
  metadata["zonegroup_id"] = zonegroup.get_id();
  metadata["zonegroup_name"] = zonegroup.get_name();
  metadata["zone_name"] = zone_name();
  metadata["zone_id"] = zone_id();;
  string name = cct->_conf->name.get_id();
  if (name.compare(0, 4, "rgw.") == 0) {
    name = name.substr(4);
  }
  int ret = rados[0].service_daemon_register(daemon_type, name, metadata);
  if (ret < 0) {
    ldout(cct, 0) << "ERROR: service_daemon_register() returned ret=" << ret << ": " << cpp_strerror(-ret) << dendl;
    return ret;
  }

  return 0;
}

int RGWRados::update_service_map(std::map<std::string, std::string>&& status)
{
  int ret = rados[0].service_daemon_update_status(move(status));
  if (ret < 0) {
    ldout(cct, 0) << "ERROR: service_daemon_update_status() returned ret=" << ret << ": " << cpp_strerror(-ret) << dendl;
    return ret;
  }

  return 0;
}

/**
 * Add new connection to connections map
 * @param zonegroup_conn_map map which new connection will be added to
 * @param zonegroup zonegroup which new connection will connect to
 * @param new_connection pointer to new connection instance
 */
static void add_new_connection_to_map(map<string, RGWRESTConn *> &zonegroup_conn_map,
				      const RGWZoneGroup &zonegroup, RGWRESTConn *new_connection)
{
  // Delete if connection is already exists
  map<string, RGWRESTConn *>::iterator iterZoneGroup = zonegroup_conn_map.find(zonegroup.get_id());
  if (iterZoneGroup != zonegroup_conn_map.end()) {
    delete iterZoneGroup->second;
  }
    
  // Add new connection to connections map
  zonegroup_conn_map[zonegroup.get_id()] = new_connection;
}

int RGWRados::convert_regionmap()
{
  RGWZoneGroupMap zonegroupmap;

  string pool_name = cct->_conf->rgw_zone_root_pool;
  if (pool_name.empty()) {
    pool_name = RGW_DEFAULT_ZONE_ROOT_POOL;
  }
  string oid = region_map_oid; 

  rgw_pool pool(pool_name);
  bufferlist bl;
  RGWObjectCtx obj_ctx(this);
  int ret = rgw_get_system_obj(this, obj_ctx, pool, oid, bl, NULL, NULL);
  if (ret < 0 && ret != -ENOENT) {
    return ret;
  } else if (ret == -ENOENT) {
    return 0;
  }

  try {
    bufferlist::iterator iter = bl.begin();
    decode(zonegroupmap, iter);
  } catch (buffer::error& err) {
    ldout(cct, 0) << "error decoding regionmap from " << pool << ":" << oid << dendl;
    return -EIO;
  }
  
  for (map<string, RGWZoneGroup>::iterator iter = zonegroupmap.zonegroups.begin();
       iter != zonegroupmap.zonegroups.end(); ++iter) {
    RGWZoneGroup& zonegroup = iter->second;
    ret = zonegroup.init(cct, this, false);
    ret = zonegroup.update();
    if (ret < 0 && ret != -ENOENT) {
      ldout(cct, 0) << "Error could not update zonegroup " << zonegroup.get_name() << ": " <<
	cpp_strerror(-ret) << dendl;
      return ret;
    } else if (ret == -ENOENT) {
      ret = zonegroup.create();
      if (ret < 0) {
	ldout(cct, 0) << "Error could not create " << zonegroup.get_name() << ": " <<
	  cpp_strerror(-ret) << dendl;
	return ret;
      }
    }
  }

  current_period.set_user_quota(zonegroupmap.user_quota);
  current_period.set_bucket_quota(zonegroupmap.bucket_quota);

  // remove the region_map so we don't try to convert again
  rgw_raw_obj obj(pool, oid);
  ret = delete_system_obj(obj);
  if (ret < 0) {
    ldout(cct, 0) << "Error could not remove " << obj
        << " after upgrading to zonegroup map: " << cpp_strerror(ret) << dendl;
    return ret;
  }

  return 0;
}

/** 
 * Replace all region configuration with zonegroup for
 * backward compatability
 * Returns 0 on success, -ERR# on failure.
 */
int RGWRados::replace_region_with_zonegroup()
{
  /* copy default region */
  /* convert default region to default zonegroup */
  string default_oid = cct->_conf->rgw_default_region_info_oid;
  if (default_oid.empty()) {
    default_oid = default_region_info_oid;
  }


  RGWZoneGroup default_zonegroup;
  rgw_pool pool{default_zonegroup.get_pool(cct)};
  string oid  = "converted";
  bufferlist bl;
  RGWObjectCtx obj_ctx(this);

  int ret = rgw_get_system_obj(this, obj_ctx, pool ,oid, bl, NULL,  NULL);
  if (ret < 0 && ret !=  -ENOENT) {
    ldout(cct, 0) << __func__ << " failed to read converted: ret "<< ret << " " << cpp_strerror(-ret)
		  << dendl;
    return ret;
  } else if (ret != -ENOENT) {
    ldout(cct, 20) << "System already converted " << dendl;
    return 0;
  }

  string default_region;
  ret = default_zonegroup.init(cct, this, false, true);
  if (ret < 0) {
    ldout(cct, 0) <<  __func__ << " failed init default region: ret "<< ret << " " << cpp_strerror(-ret) << dendl;
    return ret;
  }    
  ret  = default_zonegroup.read_default_id(default_region, true);
  if (ret < 0 && ret != -ENOENT) {
    ldout(cct, 0) <<  __func__ << " failed reading old default region: ret "<< ret << " " << cpp_strerror(-ret) << dendl;
    return ret;
  }

  /* convert regions to zonegroups */
  list<string> regions;
  ret = list_regions(regions);
  if (ret < 0 && ret != -ENOENT) {
    ldout(cct, 0) <<  __func__ << " failed to list regions: ret "<< ret << " " << cpp_strerror(-ret) << dendl;
    return ret;
  } else if (ret == -ENOENT || regions.empty()) {
    RGWZoneParams zoneparams(default_zone_name);
    int ret = zoneparams.init(cct, this);
    if (ret < 0 && ret != -ENOENT) {
      ldout(cct, 0) << __func__ << ": error initializing default zone params: " << cpp_strerror(-ret) << dendl;
      return ret;
    }
    /* update master zone */
    RGWZoneGroup default_zg(default_zonegroup_name);
    ret = default_zg.init(cct, this);
    if (ret < 0 && ret != -ENOENT) {
      ldout(cct, 0) << __func__ << ": error in initializing default zonegroup: " << cpp_strerror(-ret) << dendl;
      return ret;
    }
    if (ret != -ENOENT && default_zg.master_zone.empty()) {
      default_zg.master_zone = zoneparams.get_id();
      return default_zg.update();
    }
    return 0;
  }

  string master_region, master_zone;
  for (list<string>::iterator iter = regions.begin(); iter != regions.end(); ++iter) {
    if (*iter != default_zonegroup_name){
      RGWZoneGroup region(*iter);
      int ret = region.init(cct, this, true, true);
      if (ret < 0) {
	  ldout(cct, 0) <<  __func__ << " failed init region "<< *iter << ": " << cpp_strerror(-ret) << dendl;
	  return ret;
      }
      if (region.is_master_zonegroup()) {
	master_region = region.get_id();
	master_zone = region.master_zone;
      }
    }
  }

  /* create realm if there is none.
     The realm name will be the region and zone concatenated
     realm id will be mds of its name */
  if (realm.get_id().empty() && !master_region.empty() && !master_zone.empty()) {
    string new_realm_name = master_region + "." + master_zone;
    unsigned char md5[CEPH_CRYPTO_MD5_DIGESTSIZE];
    char md5_str[CEPH_CRYPTO_MD5_DIGESTSIZE * 2 + 1];
    MD5 hash;
    hash.Update((const unsigned char *)new_realm_name.c_str(), new_realm_name.length());
    hash.Final(md5);
    buf_to_hex(md5, CEPH_CRYPTO_MD5_DIGESTSIZE, md5_str);
    string new_realm_id(md5_str);
    RGWRealm new_realm(new_realm_id,new_realm_name);
    ret = new_realm.init(cct, this, false);
    if (ret < 0) {
      ldout(cct, 0) <<  __func__ << " Error initing new realm: " << cpp_strerror(-ret)  << dendl;
      return ret;
    }
    ret = new_realm.create();
    if (ret < 0 && ret != -EEXIST) {
      ldout(cct, 0) <<  __func__ << " Error creating new realm: " << cpp_strerror(-ret)  << dendl;
      return ret;
    }
    ret = new_realm.set_as_default();
    if (ret < 0) {
      ldout(cct, 0) << __func__ << " Error setting realm as default: " << cpp_strerror(-ret)  << dendl;
      return ret;
    }
    ret = realm.init(cct, this);
    if (ret < 0) {
      ldout(cct, 0) << __func__ << " Error initing realm: " << cpp_strerror(-ret)  << dendl;
      return ret;
    }
    ret = current_period.init(cct, this, realm.get_id(), realm.get_name());
    if (ret < 0) {
      ldout(cct, 0) << __func__ << " Error initing current period: " << cpp_strerror(-ret)  << dendl;
      return ret;
    }
  }

  list<string>::iterator iter;
  /* create zonegroups */
  for (iter = regions.begin(); iter != regions.end(); ++iter)
  {
    ldout(cct, 0) << __func__ << " Converting  " << *iter << dendl;
    /* check to see if we don't have already a zonegroup with this name */
    RGWZoneGroup new_zonegroup(*iter);
    ret = new_zonegroup.init(cct , this);
    if (ret == 0 && new_zonegroup.get_id() != *iter) {
      ldout(cct, 0) << __func__ << " zonegroup  "<< *iter << " already exists id " << new_zonegroup.get_id () <<
	" skipping conversion " << dendl;
      continue;
    }
    RGWZoneGroup zonegroup(*iter);
    zonegroup.set_id(*iter);
    int ret = zonegroup.init(cct, this, true, true);
    if (ret < 0) {
      ldout(cct, 0) << __func__ << " failed init zonegroup: ret "<< ret << " " << cpp_strerror(-ret) << dendl;
      return ret;
    }
    zonegroup.realm_id = realm.get_id();
    /* fix default region master zone */
    if (*iter == default_zonegroup_name && zonegroup.master_zone.empty()) {
      ldout(cct, 0) << __func__ << " Setting default zone as master for default region" << dendl;
      zonegroup.master_zone = default_zone_name;
    }
    ret = zonegroup.update();
    if (ret < 0 && ret != -EEXIST) {
      ldout(cct, 0) << __func__ << " failed to update zonegroup " << *iter << ": ret "<< ret << " " << cpp_strerror(-ret)
        << dendl;
      return ret;
    }
    ret = zonegroup.update_name();
    if (ret < 0 && ret != -EEXIST) {
      ldout(cct, 0) << __func__ << " failed to update_name for zonegroup " << *iter << ": ret "<< ret << " " << cpp_strerror(-ret)
        << dendl;
      return ret;
    }
    if (zonegroup.get_name() == default_region) {
      ret = zonegroup.set_as_default();
      if (ret < 0) {
        ldout(cct, 0) << __func__ << " failed to set_as_default " << *iter << ": ret "<< ret << " " << cpp_strerror(-ret)
          << dendl;
        return ret;
      }
    }
    for (map<string, RGWZone>::const_iterator iter = zonegroup.zones.begin(); iter != zonegroup.zones.end();
         ++iter) {
      ldout(cct, 0) << __func__ << " Converting zone" << iter->first << dendl;
      RGWZoneParams zoneparams(iter->first, iter->first);
      zoneparams.set_id(iter->first);
      zoneparams.realm_id = realm.get_id();
      ret = zoneparams.init(cct, this);
      if (ret < 0 && ret != -ENOENT) {
        ldout(cct, 0) << __func__ << " failed to init zoneparams  " << iter->first <<  ": " << cpp_strerror(-ret) << dendl;
        return ret;
      } else if (ret == -ENOENT) {
        ldout(cct, 0) << __func__ << " zone is part of another cluster " << iter->first <<  " skipping " << dendl;
        continue;
      }
      zonegroup.realm_id = realm.get_id();
      ret = zoneparams.update();
      if (ret < 0 && ret != -EEXIST) {
        ldout(cct, 0) << __func__ << " failed to update zoneparams " << iter->first <<  ": " << cpp_strerror(-ret) << dendl;
        return ret;
      }
      ret = zoneparams.update_name();
      if (ret < 0 && ret != -EEXIST) {
        ldout(cct, 0) << __func__ << " failed to init zoneparams " << iter->first <<  ": " << cpp_strerror(-ret) << dendl;
        return ret;
      }
    }

    if (!current_period.get_id().empty()) {
      ret = current_period.add_zonegroup(zonegroup);
      if (ret < 0) {
        ldout(cct, 0) << __func__ << " failed to add zonegroup to current_period: " << cpp_strerror(-ret) << dendl;
        return ret;
      }
    }
  }

  if (!current_period.get_id().empty()) {
    ret = current_period.update();
    if (ret < 0) {
      ldout(cct, 0) << __func__ << " failed to update new period: " << cpp_strerror(-ret) << dendl;
      return ret;
    }
    ret = current_period.store_info(false);
    if (ret < 0) {
      ldout(cct, 0) << __func__ << " failed to store new period: " << cpp_strerror(-ret) << dendl;
      return ret;
    }
    ret = current_period.reflect();
    if (ret < 0) {
      ldout(cct, 0) << __func__ << " failed to update local objects: " << cpp_strerror(-ret) << dendl;
      return ret;
    }
  }

  for (auto const& iter : regions) {
    RGWZoneGroup zonegroup(iter);
    int ret = zonegroup.init(cct, this, true, true);
    if (ret < 0) {
      ldout(cct, 0) << __func__ << " failed init zonegroup" << iter << ": ret "<< ret << " " << cpp_strerror(-ret) << dendl;
      return ret;
    }
    ret = zonegroup.delete_obj(true);
    if (ret < 0 && ret != -ENOENT) {
      ldout(cct, 0) << __func__ << " failed to delete region " << iter << ": ret "<< ret << " " << cpp_strerror(-ret)
        << dendl;
      return ret;
    }
  }

  /* mark as converted */
  ret = rgw_put_system_obj(this, pool, oid, bl,
			   true, NULL, real_time(), NULL);
  if (ret < 0 ) {
    ldout(cct, 0) << __func__ << " failed to mark cluster as converted: ret "<< ret << " " << cpp_strerror(-ret)
		  << dendl;
    return ret;
  }

  return 0;
}

int RGWRados::init_zg_from_period(bool *initialized)
{
  *initialized = false;

  if (current_period.get_id().empty()) {
    return 0;
  }

  int ret = zonegroup.init(cct, this);
  ldout(cct, 20) << "period zonegroup init ret " << ret << dendl;
  if (ret == -ENOENT) {
    return 0;
  }
  if (ret < 0) {
    ldout(cct, 0) << "failed reading zonegroup info: " << cpp_strerror(-ret) << dendl;
    return ret;
  }
  ldout(cct, 20) << "period zonegroup name " << zonegroup.get_name() << dendl;

  map<string, RGWZoneGroup>::const_iterator iter =
    current_period.get_map().zonegroups.find(zonegroup.get_id());

  if (iter != current_period.get_map().zonegroups.end()) {
    ldout(cct, 20) << "using current period zonegroup " << zonegroup.get_name() << dendl;
    zonegroup = iter->second;
    ret = zonegroup.init(cct, this, false);
    if (ret < 0) {
      ldout(cct, 0) << "failed init zonegroup: " << " " << cpp_strerror(-ret) << dendl;
      return ret;
    }
    ret = zone_params.init(cct, this);
    if (ret < 0 && ret != -ENOENT) {
      ldout(cct, 0) << "failed reading zone params info: " << " " << cpp_strerror(-ret) << dendl;
      return ret;
    } if (ret ==-ENOENT && zonegroup.get_name() == default_zonegroup_name) {
      ldout(cct, 10) << " Using default name "<< default_zone_name << dendl;
      zone_params.set_name(default_zone_name);
      ret = zone_params.init(cct, this);
      if (ret < 0 && ret != -ENOENT) {
       ldout(cct, 0) << "failed reading zone params info: " << " " << cpp_strerror(-ret) << dendl;
       return ret;
      }
    }
  }
  for (iter = current_period.get_map().zonegroups.begin();
       iter != current_period.get_map().zonegroups.end(); ++iter){
    const RGWZoneGroup& zg = iter->second;
    // use endpoints from the zonegroup's master zone
    auto master = zg.zones.find(zg.master_zone);
    if (master == zg.zones.end()) {
      // Check for empty zonegroup which can happen if zone was deleted before removal
      if (zg.zones.size() == 0)
        continue;
      // fix missing master zone for a single zone zonegroup
      if (zg.master_zone.empty() && zg.zones.size() == 1) {
	master = zg.zones.begin();
	ldout(cct, 0) << "zonegroup " << zg.get_name() << " missing master_zone, setting zone " <<
	  master->second.name << " id:" << master->second.id << " as master" << dendl;
	if (zonegroup.get_id() == zg.get_id()) {
	  zonegroup.master_zone = master->second.id;
	  ret = zonegroup.update();
	  if (ret < 0) {
	    ldout(cct, 0) << "error updating zonegroup : " << cpp_strerror(-ret) << dendl;
	    return ret;
	  }
	} else {
	  RGWZoneGroup fixed_zg(zg.get_id(),zg.get_name());
	  ret = fixed_zg.init(cct, this);
	  if (ret < 0) {
	    ldout(cct, 0) << "error initializing zonegroup : " << cpp_strerror(-ret) << dendl;
	    return ret;
	  }
	  fixed_zg.master_zone = master->second.id;
	  ret = fixed_zg.update();
	  if (ret < 0) {
	    ldout(cct, 0) << "error initializing zonegroup : " << cpp_strerror(-ret) << dendl;
	    return ret;
	  }
	}
      } else {
	ldout(cct, 0) << "zonegroup " << zg.get_name() << " missing zone for master_zone=" <<
	  zg.master_zone << dendl;
	return -EINVAL;
      }
    }
    const auto& endpoints = master->second.endpoints;
    add_new_connection_to_map(zonegroup_conn_map, zg, new RGWRESTConn(cct, this, zg.get_id(), endpoints));
    if (!current_period.get_master_zonegroup().empty() &&
        zg.get_id() == current_period.get_master_zonegroup()) {
      rest_master_conn = new RGWRESTConn(cct, this, zg.get_id(), endpoints);
    }
  }

  *initialized = true;

  return 0;
}

int RGWRados::init_zg_from_local(bool *creating_defaults)
{
  int ret = zonegroup.init(cct, this);
  if ( (ret < 0 && ret != -ENOENT) || (ret == -ENOENT && !cct->_conf->rgw_zonegroup.empty())) {
    ldout(cct, 0) << "failed reading zonegroup info: ret "<< ret << " " << cpp_strerror(-ret) << dendl;
    return ret;
  } else if (ret == -ENOENT) {
    *creating_defaults = true;
    ldout(cct, 10) << "Creating default zonegroup " << dendl;
    ret = zonegroup.create_default();
    if (ret < 0) {
      ldout(cct, 0) << "failure in zonegroup create_default: ret "<< ret << " " << cpp_strerror(-ret)
        << dendl;
      return ret;
    }
    ret = zonegroup.init(cct, this);
    if (ret < 0) {
      ldout(cct, 0) << "failure in zonegroup create_default: ret "<< ret << " " << cpp_strerror(-ret)
        << dendl;
      return ret;
    }
  }
  ldout(cct, 20) << "zonegroup " << zonegroup.get_name() << dendl;
  if (zonegroup.is_master_zonegroup()) {
    // use endpoints from the zonegroup's master zone
    auto master = zonegroup.zones.find(zonegroup.master_zone);
    if (master == zonegroup.zones.end()) {
      // fix missing master zone for a single zone zonegroup
      if (zonegroup.master_zone.empty() && zonegroup.zones.size() == 1) {
	master = zonegroup.zones.begin();
	ldout(cct, 0) << "zonegroup " << zonegroup.get_name() << " missing master_zone, setting zone " <<
	  master->second.name << " id:" << master->second.id << " as master" << dendl;
	zonegroup.master_zone = master->second.id;
	ret = zonegroup.update();
	if (ret < 0) {
	  ldout(cct, 0) << "error initializing zonegroup : " << cpp_strerror(-ret) << dendl;
	  return ret;
	}
      } else {
	ldout(cct, 0) << "zonegroup " << zonegroup.get_name() << " missing zone for "
          "master_zone=" << zonegroup.master_zone << dendl;
	return -EINVAL;
      }
    }
    const auto& endpoints = master->second.endpoints;
    rest_master_conn = new RGWRESTConn(cct, this, zonegroup.get_id(), endpoints);
  }

  return 0;
}


bool RGWRados::zone_syncs_from(RGWZone& target_zone, RGWZone& source_zone)
{
  return target_zone.syncs_from(source_zone.name) &&
         sync_modules_manager->supports_data_export(source_zone.tier_type);
}

/** 
 * Initialize the RADOS instance and prepare to do other ops
 * Returns 0 on success, -ERR# on failure.
 */
int RGWRados::init_complete()
{
  int ret = realm.init(cct, this);
  if (ret < 0 && ret != -ENOENT) {
    ldout(cct, 0) << "failed reading realm info: ret "<< ret << " " << cpp_strerror(-ret) << dendl;
    return ret;
  } else if (ret != -ENOENT) {
    ldout(cct, 20) << "realm  " << realm.get_name() << " " << realm.get_id() << dendl;
    ret = current_period.init(cct, this, realm.get_id(), realm.get_name());
    if (ret < 0 && ret != -ENOENT) {
      ldout(cct, 0) << "failed reading current period info: " << " " << cpp_strerror(-ret) << dendl;
      return ret;
    }
    ldout(cct, 20) << "current period " << current_period.get_id() << dendl;  
  }

  ret = replace_region_with_zonegroup();
  if (ret < 0) {
    lderr(cct) << "failed converting region to zonegroup : ret "<< ret << " " << cpp_strerror(-ret) << dendl;
    return ret;
  }

  ret = convert_regionmap();
  if (ret < 0) {
    lderr(cct) << "failed converting regionmap: " << cpp_strerror(-ret) << dendl;
    return ret;
  }

  bool zg_initialized = false;

  if (!current_period.get_id().empty()) {
    ret = init_zg_from_period(&zg_initialized);
    if (ret < 0) {
      return ret;
    }
  }

  bool creating_defaults = false;
  bool using_local = (!zg_initialized);
  if (using_local) {
    ldout(cct, 10) << " cannot find current period zonegroup using local zonegroup" << dendl;
    ret = init_zg_from_local(&creating_defaults);
    if (ret < 0) {
      return ret;
    }
    // read period_config into current_period
    auto& period_config = current_period.get_config();
    ret = period_config.read(this, zonegroup.realm_id);
    if (ret < 0 && ret != -ENOENT) {
      ldout(cct, 0) << "ERROR: failed to read period config: "
          << cpp_strerror(ret) << dendl;
      return ret;
    }
  }

  ldout(cct, 10) << "Cannot find current period zone using local zone" << dendl;
  if (creating_defaults && cct->_conf->rgw_zone.empty()) {
    ldout(cct, 10) << " Using default name "<< default_zone_name << dendl;
    zone_params.set_name(default_zone_name);
  }

  ret = zone_params.init(cct, this);
  if (ret < 0 && ret != -ENOENT) {
    lderr(cct) << "failed reading zone info: ret "<< ret << " " << cpp_strerror(-ret) << dendl;
    return ret;
  }
  map<string, RGWZone>::iterator zone_iter = get_zonegroup().zones.find(zone_params.get_id());
  if (zone_iter == get_zonegroup().zones.end()) {
    if (using_local) {
      lderr(cct) << "Cannot find zone id=" << zone_params.get_id() << " (name=" << zone_params.get_name() << ")" << dendl;
      return -EINVAL;
    }
    ldout(cct, 1) << "Cannot find zone id=" << zone_params.get_id() << " (name=" << zone_params.get_name() << "), switching to local zonegroup configuration" << dendl;
    ret = init_zg_from_local(&creating_defaults);
    if (ret < 0) {
      return ret;
    }
    zone_iter = get_zonegroup().zones.find(zone_params.get_id());
  }
  if (zone_iter != get_zonegroup().zones.end()) {
    zone_public_config = zone_iter->second;
    ldout(cct, 20) << "zone " << zone_params.get_name() << dendl;
  } else {
    lderr(cct) << "Cannot find zone id=" << zone_params.get_id() << " (name=" << zone_params.get_name() << ")" << dendl;
    return -EINVAL;
  }

  zone_short_id = current_period.get_map().get_zone_short_id(zone_params.get_id());

  if (run_sync_thread) {
    ret = sync_modules_manager->create_instance(cct, zone_public_config.tier_type, zone_params.tier_config, &sync_module);
    if (ret < 0) {
      lderr(cct) << "ERROR: failed to init sync module instance, ret=" << ret << dendl;
      if (ret == -ENOENT) {
        lderr(cct) << "ERROR: " << zone_public_config.tier_type 
                   << " sync module does not exist. valid sync modules: " 
                   << sync_modules_manager->get_registered_module_names()
                   << dendl;
      }
      return ret;
    }
  }

  writeable_zone = (zone_public_config.tier_type.empty() || zone_public_config.tier_type == "rgw");

  if (!g_conf->public_addr.is_blank_ip()) {
    local_ip = g_conf->public_addr.ip_only_to_str();
  }

  init_unique_trans_id_deps();

  finisher = new Finisher(cct);
  finisher->start();

  period_puller.reset(new RGWPeriodPuller(this));
  period_history.reset(new RGWPeriodHistory(cct, period_puller.get(),
                                            current_period));

  if (need_watch_notify()) {
    ret = init_watch();
    if (ret < 0) {
      lderr(cct) << "ERROR: failed to initialize watch: " << cpp_strerror(-ret) << dendl;
      return ret;
    }
  }

  /* first build all zones index */
  for (auto ziter : get_zonegroup().zones) {
    const string& id = ziter.first;
    RGWZone& z = ziter.second;
    zone_id_by_name[z.name] = id;
    zone_by_id[id] = z;
  }

  if (zone_by_id.find(zone_id()) == zone_by_id.end()) {
    ldout(cct, 0) << "WARNING: could not find zone config in zonegroup for local zone (" << zone_id() << "), will use defaults" << dendl;
  }
  zone_public_config = zone_by_id[zone_id()];
  for (auto ziter : get_zonegroup().zones) {
    const string& id = ziter.first;
    RGWZone& z = ziter.second;
    if (id == zone_id()) {
      continue;
    }
    if (z.endpoints.empty()) {
      ldout(cct, 0) << "WARNING: can't generate connection for zone " << z.id << " id " << z.name << ": no endpoints defined" << dendl;
      continue;
    }
    ldout(cct, 20) << "generating connection object for zone " << z.name << " id " << z.id << dendl;
    RGWRESTConn *conn = new RGWRESTConn(cct, this, z.id, z.endpoints);
    zone_conn_map[id] = conn;
    if (zone_syncs_from(zone_public_config, z) ||
        zone_syncs_from(z, zone_public_config)) {
      if (zone_syncs_from(zone_public_config, z)) {
        zone_data_sync_from_map[id] = conn;
      }
      if (zone_syncs_from(z, zone_public_config)) {
        zone_data_notify_to_map[id] = conn;
      }
    } else {
      ldout(cct, 20) << "NOTICE: not syncing to/from zone " << z.name << " id " << z.id << dendl;
    }
  }

  ret = open_root_pool_ctx();
  if (ret < 0)
    return ret;

  ret = open_gc_pool_ctx();
  if (ret < 0)
    return ret;

  ret = open_lc_pool_ctx();
  if (ret < 0)
    return ret;

  ret = open_objexp_pool_ctx();
  if (ret < 0)
    return ret;

  ret = open_reshard_pool_ctx();
  if (ret < 0)
    return ret;

  pools_initialized = true;

  gc = new RGWGC();
  gc->initialize(cct, this);

  obj_expirer = new RGWObjectExpirer(this);

  if (use_gc_thread) {
    gc->start_processor();
    obj_expirer->start_processor();
  }

  /* no point of running sync thread if we don't have a master zone configured
    or there is no rest_master_conn */
  if (get_zonegroup().master_zone.empty() || !rest_master_conn
      || current_period.get_id().empty()) {
    run_sync_thread = false;
  }

  if (run_sync_thread) {
    // initialize the log period history
    meta_mgr->init_oldest_log_period();
  }

  async_rados = new RGWAsyncRadosProcessor(this, cct->_conf->rgw_num_async_rados_threads);
  async_rados->start();

  if(!admin_op) {
    async_processor = new RGWAsyncRequestProcessor(this, cct->_conf->rgw_num_async_request_threads);
    async_processor->start();
  }

  ret = meta_mgr->init(current_period.get_id());
  if (ret < 0) {
    lderr(cct) << "ERROR: failed to initialize metadata log: "
        << cpp_strerror(-ret) << dendl;
    return ret;
  }

  if (is_meta_master() && !admin_op) {
    auto md_log = meta_mgr->get_log(current_period.get_id());
    meta_notifier = new RGWMetaNotifier(this, md_log);
    meta_notifier->start();
  }

  /* init it anyway, might run sync through radosgw-admin explicitly */
  sync_tracer = new RGWSyncTraceManager(cct, cct->_conf->rgw_sync_trace_history_size);
  sync_tracer->init(this);
  ret = sync_tracer->hook_to_admin_command();
  if (ret < 0) {
    return ret;
  }

  if (run_sync_thread) {
    Mutex::Locker l(meta_sync_thread_lock);
    meta_sync_processor_thread = new RGWMetaSyncProcessorThread(this, async_rados);
    ret = meta_sync_processor_thread->init();
    if (ret < 0) {
      ldout(cct, 0) << "ERROR: failed to initialize meta sync thread" << dendl;
      return ret;
    }
    meta_sync_processor_thread->start();

    // configure the bucket trim manager
    rgw::BucketTrimConfig config;
    rgw::configure_bucket_trim(cct, config);

    bucket_trim.emplace(this, config);
    ret = bucket_trim->init();
    if (ret < 0) {
      ldout(cct, 0) << "ERROR: failed to start bucket trim manager" << dendl;
      return ret;
    }
    data_log->set_observer(&*bucket_trim);

    Mutex::Locker dl(data_sync_thread_lock);
    for (auto iter : zone_data_sync_from_map) {
      ldout(cct, 5) << "starting data sync thread for zone " << iter.first << dendl;
      auto *thread = new RGWDataSyncProcessorThread(this, async_rados, iter.first);
      ret = thread->init();
      if (ret < 0) {
        ldout(cct, 0) << "ERROR: failed to initialize data sync thread" << dendl;
        return ret;
      }
      thread->start();
      data_sync_processor_threads[iter.first] = thread;
    }
    auto interval = cct->_conf->rgw_sync_log_trim_interval;
    auto bucket_clear_interval = cct->_conf->rgw_sync_bucket_clear_interval_sec;
    bucket_clear_interval = max(interval, bucket_clear_interval);
    if (interval > 0) {
      sync_log_trimmer = new RGWSyncLogTrimThread(this, &*bucket_trim, interval, bucket_clear_interval);
      ret = sync_log_trimmer->init();
      if (ret < 0) {
        ldout(cct, 0) << "ERROR: failed to initialize sync log trim thread" << dendl;
        return ret;
      }
      sync_log_trimmer->start();
    }
  }
  if (!admin_op) {
    data_notifier = new RGWDataNotifier(this);
    data_notifier->start();
  }

  lc = new RGWLC();
  lc->initialize(cct, this);

  if (use_lc_thread)
    lc->start_processor();

  quota_handler = RGWQuotaHandler::generate_handler(this, quota_threads);

  bucket_index_max_shards = (cct->_conf->rgw_override_bucket_index_max_shards ? cct->_conf->rgw_override_bucket_index_max_shards :
                             get_zone().bucket_index_max_shards);
  if (bucket_index_max_shards > get_max_bucket_shards()) {
    bucket_index_max_shards = get_max_bucket_shards();
    ldout(cct, 1) << __func__ << " bucket index max shards is too large, reset to value: "
      << get_max_bucket_shards() << dendl;
  }
  ldout(cct, 20) << __func__ << " bucket index max shards: " << bucket_index_max_shards << dendl;

  if (cct->_conf->rgw_bucket_namespace_enable) {
    bucket_namespace_default_type = BUCKET_NAMESPACE_ENABLE;
  } else {
    bucket_namespace_default_type = BUCKET_NAMESPACE_DISABLE;
  }

  binfo_cache = new RGWChainedCacheImpl<bucket_info_entry>;
  binfo_cache->init(this);
  
  if (!admin_op) {
    awake_data_sync = new RGWAwakeDataSync(this);
    awake_data_sync->start();
  }

  bool need_tombstone_cache = !zone_data_notify_to_map.empty(); /* have zones syncing from us */

  if (need_tombstone_cache) {
    obj_tombstone_cache = new tombstone_cache_t(cct->_conf->rgw_obj_tombstone_cache_size);
  }

  reshard_wait = std::make_shared<RGWReshardWait>(this);

  reshard = new RGWReshard(this);

  /* only the master zone in the zonegroup reshards buckets */
  run_reshard_thread = run_reshard_thread && (get_zonegroup().master_zone == zone_public_config.id);
  if (run_reshard_thread)  {
    reshard->start_processor();
  }

  index_completion_manager = new RGWIndexCompletionManager(this);
  ret = index_completion_manager->start();

  return ret;
}

/** 
 * Initialize the RADOS instance and prepare to do other ops
 * Returns 0 on success, -ERR# on failure.
 */
int RGWRados::initialize()
{
  int ret;

  ret = init_rados();
  if (ret < 0)
    return ret;

  return init_complete();
}

void RGWRados::finalize_watch()
{
  for (int i = 0; i < num_watchers; i++) {
    RGWWatcher *watcher = watchers[i];
    watcher->unregister_watch();
    delete watcher;
  }

  delete[] notify_oids;
  delete[] watchers;
}

void RGWRados::schedule_context(Context *c) {
  finisher->queue(c);
}

int RGWRados::list_raw_prefixed_objs(const rgw_pool& pool, const string& prefix, list<string>& result)
{
  bool is_truncated;
  RGWListRawObjsCtx ctx;
  do {
    list<string> oids;
    int r = list_raw_objects(pool, prefix, 1000,
			     ctx, oids, &is_truncated);
    if (r < 0) {
      return r;
    }
    list<string>::iterator iter;
    for (iter = oids.begin(); iter != oids.end(); ++iter) {
      string& val = *iter;
      if (val.size() > prefix.size())
        result.push_back(val.substr(prefix.size()));
    }
  } while (is_truncated);

  return 0;
}

int RGWRados::list_regions(list<string>& regions)
{
  RGWZoneGroup zonegroup;

  return list_raw_prefixed_objs(zonegroup.get_pool(cct), region_info_oid_prefix, regions);
}

int RGWRados::list_zonegroups(list<string>& zonegroups)
{
  RGWZoneGroup zonegroup;

  return list_raw_prefixed_objs(zonegroup.get_pool(cct), zonegroup_names_oid_prefix, zonegroups);
}

int RGWRados::list_zones(list<string>& zones)
{
  RGWZoneParams zoneparams;

  return list_raw_prefixed_objs(zoneparams.get_pool(cct), zone_names_oid_prefix, zones);
}

int RGWRados::list_realms(list<string>& realms)
{
  RGWRealm realm(cct, this);
  return list_raw_prefixed_objs(realm.get_pool(cct), realm_names_oid_prefix, realms);
}

int RGWRados::list_periods(list<string>& periods)
{
  RGWPeriod period;
  list<string> raw_periods;
  int ret = list_raw_prefixed_objs(period.get_pool(cct), period.get_info_oid_prefix(), raw_periods);
  if (ret < 0) {
    return ret;
  }
  for (const auto& oid : raw_periods) {
    size_t pos = oid.find(".");
    if (pos != std::string::npos) {
      periods.push_back(oid.substr(0, pos));
    } else {
      periods.push_back(oid);
    }
  }
  periods.sort(); // unique() only detects duplicates if they're adjacent
  periods.unique();
  return 0;
}


int RGWRados::list_periods(const string& current_period, list<string>& periods)
{
  int ret = 0;
  string period_id = current_period;
  while(!period_id.empty()) {
    RGWPeriod period(period_id);
    ret = period.init(cct, this);
    if (ret < 0) {
      return ret;
    }
    periods.push_back(period.get_id());
    period_id = period.get_predecessor();
  }
  
  return ret;
}

int RGWRados::list_todelete_bucket(list<string>& buckets) {
  return list_raw_prefixed_objs(get_zone_params().log_pool, todelete_bucket_instance_oid_prefix, buckets);
}

/**
 * Open the pool used as root for this gateway
 * Returns: 0 on success, -ERR# otherwise.
 */
int RGWRados::open_root_pool_ctx()
{
  return rgw_init_ioctx(get_rados_handle(), get_zone_params().domain_root, root_pool_ctx, true);
}

int RGWRados::open_gc_pool_ctx()
{
  return rgw_init_ioctx(get_rados_handle(), get_zone_params().gc_pool, gc_pool_ctx, true);
}

int RGWRados::open_lc_pool_ctx()
{
  return rgw_init_ioctx(get_rados_handle(), get_zone_params().lc_pool, lc_pool_ctx, true);
}

int RGWRados::open_objexp_pool_ctx()
{
  return rgw_init_ioctx(get_rados_handle(), get_zone_params().log_pool, objexp_pool_ctx, true);
}

int RGWRados::open_reshard_pool_ctx()
{
  return rgw_init_ioctx(get_rados_handle(), get_zone_params().reshard_pool, reshard_pool_ctx, true);
}

int RGWRados::init_watch()
{
  int r = rgw_init_ioctx(&rados[0], get_zone_params().control_pool, control_pool_ctx, true);
  if (r < 0) {
    return r;
  }

  num_watchers = cct->_conf->rgw_num_control_oids;

  bool compat_oid = (num_watchers == 0);

  if (num_watchers <= 0)
    num_watchers = 1;

  notify_oids = new string[num_watchers];
  watchers = new RGWWatcher *[num_watchers];

  for (int i=0; i < num_watchers; i++) {
    string& notify_oid = notify_oids[i];
    notify_oid = notify_oid_prefix;
    if (!compat_oid) {
      char buf[16];
      snprintf(buf, sizeof(buf), ".%d", i);
      notify_oid.append(buf);
    }
    r = control_pool_ctx.create(notify_oid, false);
    if (r < 0 && r != -EEXIST)
      return r;

    RGWWatcher *watcher = new RGWWatcher(this, i, notify_oid);
    watchers[i] = watcher;

    r = watcher->register_watch();
    if (r < 0)
      return r;
  }

  watch_initialized = true;

  set_cache_enabled(true);

  return 0;
}

void RGWRados::pick_control_oid(const string& key, string& notify_oid)
{
  uint32_t r = ceph_str_hash_linux(key.c_str(), key.size());

  int i = r % num_watchers;
  char buf[16];
  snprintf(buf, sizeof(buf), ".%d", i);

  notify_oid = notify_oid_prefix;
  notify_oid.append(buf);
}

int RGWRados::open_pool_ctx(const rgw_pool& pool, librados::IoCtx& io_ctx, librados::Rados* rados_handle)
{
  constexpr bool create = true; // create the pool if it doesn't exist
  if (rados_handle == NULL) {
    return rgw_init_ioctx(get_rados_handle(), pool, io_ctx, create);
  } else {
    return rgw_init_ioctx(rados_handle, pool, io_ctx, create);
  }

}

void RGWRados::build_bucket_index_marker(const string& shard_id_str, const string& shard_marker,
      string *marker) {
  if (marker) {
    *marker = shard_id_str;
    marker->append(BucketIndexShardsManager::KEY_VALUE_SEPARATOR);
    marker->append(shard_marker);
  }
}

int RGWRados::open_bucket_index_ctx(const RGWBucketInfo& bucket_info, librados::IoCtx& index_ctx)
{
  const rgw_pool& explicit_pool = bucket_info.bucket.explicit_placement.index_pool;

  if (!explicit_pool.empty()) {
    return open_pool_ctx(explicit_pool, index_ctx);
  }

  const rgw_placement_rule *rule = &bucket_info.head_placement_rule;
  if (rule->empty()) {
    rule = &zonegroup.default_placement;
  }
  auto iter = zone_params.placement_pools.find((*rule).name);
  if (iter == zone_params.placement_pools.end()) {
    ldout(cct, 0) << "could not find placement rule " << *rule << " within zonegroup " << dendl;
    return -EINVAL;
  }

  int r = open_pool_ctx(iter->second.index_pool, index_ctx);
  if (r < 0)
    return r;

  return 0;
}

/**
 * set up a bucket listing.
 * handle is filled in.
 * Returns 0 on success, -ERR# otherwise.
 */
int RGWRados::list_buckets_init(RGWAccessHandle *handle)
{
  librados::NObjectIterator *state = new librados::NObjectIterator(root_pool_ctx.nobjects_begin());
  *handle = (RGWAccessHandle)state;
  return 0;
}

/** 
 * get the next bucket in the listing.
 * obj is filled in,
 * handle is updated.
 * returns 0 on success, -ERR# otherwise.
 */
int RGWRados::list_buckets_next(rgw_bucket_dir_entry& obj, RGWAccessHandle *handle)
{
  librados::NObjectIterator *state = (librados::NObjectIterator *)*handle;

  do {
    if (*state == root_pool_ctx.nobjects_end()) {
      delete state;
      return -ENOENT;
    }

    obj.key.name = (*state)->get_oid();
    if (obj.key.name[0] == '_') {
      obj.key.name = obj.key.name.substr(1);
    }

    (*state)++;
  } while (obj.key.name[0] == '.'); /* skip all entries starting with '.' */

  return 0;
}


/**** logs ****/

struct log_list_state {
  string prefix;
  librados::IoCtx io_ctx;
  librados::NObjectIterator obit;
};

int RGWRados::log_list_init(const string& prefix, RGWAccessHandle *handle)
{
  log_list_state *state = new log_list_state;
  int r = rgw_init_ioctx(get_rados_handle(), get_zone_params().log_pool, state->io_ctx);
  if (r < 0) {
    delete state;
    return r;
  }
  state->prefix = prefix;
  state->obit = state->io_ctx.nobjects_begin();
  *handle = (RGWAccessHandle)state;
  return 0;
}

int RGWRados::log_list_next(RGWAccessHandle handle, string *name)
{
  log_list_state *state = static_cast<log_list_state *>(handle);
  while (true) {
    if (state->obit == state->io_ctx.nobjects_end()) {
      delete state;
      return -ENOENT;
    }
    if (state->prefix.length() &&
	state->obit->get_oid().find(state->prefix) != 0) {
      state->obit++;
      continue;
    }
    *name = state->obit->get_oid();
    state->obit++;
    break;
  }
  return 0;
}

int RGWRados::log_remove(const string& name)
{
  librados::IoCtx io_ctx;
  int r = rgw_init_ioctx(get_rados_handle(), get_zone_params().log_pool, io_ctx);
  if (r < 0)
    return r;
  return io_ctx.remove(name);
}

struct log_show_state {
  librados::IoCtx io_ctx;
  bufferlist bl;
  bufferlist::iterator p;
  string name;
  uint64_t pos;
  bool eof;
  log_show_state() : pos(0), eof(false) {}
};

int RGWRados::log_show_init(const string& name, RGWAccessHandle *handle)
{
  log_show_state *state = new log_show_state;
  int r = rgw_init_ioctx(get_rados_handle(), get_zone_params().log_pool, state->io_ctx);
  if (r < 0) {
    delete state;
    return r;
  }
  state->name = name;
  *handle = (RGWAccessHandle)state;
  return 0;
}

int RGWRados::log_show_next(RGWAccessHandle handle, rgw_log_entry *entry)
{
  log_show_state *state = static_cast<log_show_state *>(handle);
  off_t off = state->p.get_off();

  ldout(cct, 10) << "log_show_next pos " << state->pos << " bl " << state->bl.length()
	   << " off " << off
	   << " eof " << (int)state->eof
	   << dendl;
  // read some?
  unsigned chunk = 1024*1024;
  if ((state->bl.length() - off) < chunk/2 && !state->eof) {
    bufferlist more;
    int r = state->io_ctx.read(state->name, more, chunk, state->pos);
    if (r < 0)
      return r;
    state->pos += r;
    bufferlist old;
    try {
      old.substr_of(state->bl, off, state->bl.length() - off);
    } catch (buffer::error& err) {
      return -EINVAL;
    }
    state->bl.clear();
    state->bl.claim(old);
    state->bl.claim_append(more);
    state->p = state->bl.begin();
    if ((unsigned)r < chunk)
      state->eof = true;
    ldout(cct, 10) << " read " << r << dendl;
  }

  if (state->p.end())
    return 0;  // end of file
  try {
    decode(*entry, state->p);
  }
  catch (const buffer::error &e) {
    return -EINVAL;
  }
  return 1;
}

/**
 * usage_log_hash: get usage log key hash, based on name and index
 *
 * Get the usage object name. Since a user may have more than 1
 * object holding that info (multiple shards), we use index to
 * specify that shard number. Once index exceeds max shards it
 * wraps.
 * If name is not being set, results for all users will be returned
 * and index will wrap only after total shards number.
 *
 * @param cct [in] ceph context
 * @param name [in] user name
 * @param hash [out] hash value
 * @param index [in] shard index number 
 */
static void usage_log_hash(CephContext *cct, const string& name, string& hash, uint32_t index)
{
  uint32_t val = index;

  if (!name.empty()) {
    int max_user_shards = cct->_conf->rgw_usage_max_user_shards;
    val %= max_user_shards;
    val += ceph_str_hash_linux(name.c_str(), name.size());
  }
  char buf[17];
  int max_shards = cct->_conf->rgw_usage_max_shards;
  snprintf(buf, sizeof(buf), RGW_USAGE_OBJ_PREFIX "%u", (unsigned)(val % max_shards));
  hash = buf;
}

int RGWRados::log_usage(map<rgw_user_bucket, RGWUsageBatch>& usage_info)
{
  uint32_t index = 0;

  map<string, rgw_usage_log_info> log_objs;

  string hash;
  string last_user;

  /* restructure usage map, zone by object hash */
  map<rgw_user_bucket, RGWUsageBatch>::iterator iter;
  for (iter = usage_info.begin(); iter != usage_info.end(); ++iter) {
    const rgw_user_bucket& ub = iter->first;
    RGWUsageBatch& info = iter->second;

    if (ub.user.empty()) {
      ldout(cct, 0) << "WARNING: RGWRados::log_usage(): user name empty (bucket=" << ub.bucket << "), skipping" << dendl;
      continue;
    }

    if (ub.user != last_user) {
      /* index *should* be random, but why waste extra cycles
         in most cases max user shards is not going to exceed 1,
         so just incrementing it */
      usage_log_hash(cct, ub.user, hash, index++);
    }
    last_user = ub.user;
    vector<rgw_usage_log_entry>& v = log_objs[hash].entries;

    for (auto miter = info.m.begin(); miter != info.m.end(); ++miter) {
      v.push_back(miter->second);
    }
  }

  map<string, rgw_usage_log_info>::iterator liter;

  for (liter = log_objs.begin(); liter != log_objs.end(); ++liter) {
    int r = cls_obj_usage_log_add(liter->first, liter->second);
    if (r < 0)
      return r;
  }
  return 0;
}

int RGWRados::read_usage(const rgw_user& user, uint64_t start_epoch, uint64_t end_epoch, uint32_t max_entries,
                         bool *is_truncated, RGWUsageIter& usage_iter, map<rgw_user_bucket, rgw_usage_log_entry>& usage)
{
  uint32_t num = max_entries;
  string hash, first_hash;
  string user_str = user.to_str();
  usage_log_hash(cct, user_str, first_hash, 0);

  if (usage_iter.index) {
    usage_log_hash(cct, user_str, hash, usage_iter.index);
  } else {
    hash = first_hash;
  }

  usage.clear();

  do {
    map<rgw_user_bucket, rgw_usage_log_entry> ret_usage;
    map<rgw_user_bucket, rgw_usage_log_entry>::iterator iter;

    int ret =  cls_obj_usage_log_read(hash, user_str, start_epoch, end_epoch, num,
                                    usage_iter.read_iter, ret_usage, is_truncated);
    if (ret == -ENOENT)
      goto next;

    if (ret < 0)
      return ret;

    num -= ret_usage.size();

    for (iter = ret_usage.begin(); iter != ret_usage.end(); ++iter) {
      usage[iter->first].aggregate(iter->second);
    }

next:
    if (!*is_truncated) {
      usage_iter.read_iter.clear();
      usage_log_hash(cct, user_str, hash, ++usage_iter.index);
    }
  } while (num && !*is_truncated && hash != first_hash);
  return 0;
}

int RGWRados::read_total_usage(const rgw_user& user, uint32_t max_entries, bool *is_truncated,
    RGWUsageIter& usage_iter, map<rgw_user_bucket, rgw_usage_log_entry>& usage)
{
  uint32_t num = max_entries;
  string hash, first_hash;
  string user_str = user.to_str();
  usage_log_hash(cct, user_str, first_hash, 0);
  if (usage_iter.index) {
    usage_log_hash(cct, user_str, hash, usage_iter.index);
  } else {
    hash = first_hash;
  }
  usage.clear();

  ldout(cct, 20) << __func__ << " start user " << user << " max entries " << max_entries
                 << " index " << usage_iter.index << "  next " << usage_iter.read_iter
                 << dendl;

  do {
    map<rgw_user_bucket, rgw_usage_log_entry> ret_usage;
    map<rgw_user_bucket, rgw_usage_log_entry>::iterator iter;

    int ret = cls_obj_usage_log_read_total(hash, user_str, num, usage_iter.read_iter,
                                           ret_usage, is_truncated);
    if (ret == -ENOENT) {
      goto next;
    }

    num -= ret_usage.size();
    for (iter = ret_usage.begin(); iter != ret_usage.end(); ++iter) {
      usage[iter->first].aggregate(iter->second);
    }

next:
    if (!*is_truncated) {
      usage_iter.read_iter.clear();
      usage_log_hash(cct, user_str, hash, ++usage_iter.index);
    }
  } while (num && !*is_truncated && hash != first_hash);

  ldout(cct, 20) << __func__ << " end user " << user_str << " num " << num
                << " is_truncated " << *is_truncated << dendl;
  return 0;
}

int RGWRados::read_usage_current_readop(set<string>& user_list, uint64_t end_epoch,
                                map<rgw_user_bucket, rgw_usage_log_entry>& usage)
{
  string hash;
  string user_name;
  uint32_t index = 0;
  end_epoch -= 120;

  usage.clear();

  set<string>::const_iterator it;
  for(it=user_list.begin(); it!=user_list.end(); ++it) {
    map<rgw_user_bucket, rgw_usage_log_entry> ret_usage;
    user_name = *it;
    usage_log_hash(cct, user_name, hash, index++);
    int ret = cls_obj_usage_log_read_current_readop(hash, user_name, end_epoch, ret_usage);
    if (ret == -ENOENT) {
      rgw_user_bucket ub(user_name, "");
      rgw_usage_log_entry& entry = ret_usage[ub];
      entry.owner = user_name;
      entry.epoch = end_epoch;
      entry.read_ops.ops = 0;
      entry.read_ops.successful_ops = 0;
      entry.write_ops.ops = 0;
      entry.write_ops.successful_ops = 0;
      entry.write_ops.bytes_received = 0;
      entry.read_ops.bytes_sent = 0;
    } else if (ret < 0) {
      ldout(cct, 0) << __func__ << " ERROR: failed to get current readop usage kv, ret: " << ret << dendl;
      return ret;
    }
    map<rgw_user_bucket, rgw_usage_log_entry>::iterator iter;
    for (iter = ret_usage.begin(); iter != ret_usage.end(); ++iter) {
      usage[iter->first].aggregate_readop(iter->second);
    }
  }
  return 0;
}

int RGWRados::read_usage_readop(rgw_user& user, uint64_t start_epoch, uint64_t end_epoch, uint32_t max_entries,
                 bool *is_truncated, RGWUsageIter& usage_iter, map<rgw_user_bucket, vector<rgw_usage_log_entry> >& usage)
{
  uint32_t num = max_entries;
  string hash, first_hash;
  string user_str = user.to_str();
  usage_log_hash(cct, user_str, first_hash, 0);
  if (usage_iter.index) {
    usage_log_hash(cct, user_str, hash, usage_iter.index);
  } else {
    hash = first_hash;
  }
  do {
    map<rgw_user_bucket, vector<rgw_usage_log_entry> > ret_usage;
    map<rgw_user_bucket, vector<rgw_usage_log_entry> >::iterator iter;

    int ret = cls_obj_usage_log_read_readop(hash, user_str, start_epoch, end_epoch, num,
                                    usage_iter.read_iter, ret_usage, is_truncated);
    if (ret == -ENOENT)
      goto next;

    if (ret < 0)
      return ret;

    num -= ret_usage.size();

    for (iter = ret_usage.begin(); iter != ret_usage.end(); ++iter) {
      for (vector<rgw_usage_log_entry>::iterator le_iter = iter->second.begin();
            le_iter != iter->second.end();
            ++le_iter) {
        rgw_usage_log_entry entry;
        entry.aggregate_readop(*le_iter);
        usage[iter->first].push_back(entry);
      }
    }
next:
    if (!*is_truncated) {
      usage_iter.read_iter.clear();
      usage_log_hash(cct, user_str, hash, ++usage_iter.index);
    }
  } while (num && !*is_truncated && hash != first_hash);
  return 0;
}

int RGWRados::trim_usage(rgw_user& user, uint64_t start_epoch, uint64_t end_epoch)
{
  uint32_t index = 0;
  string hash, first_hash;
  string user_str = user.to_str();
  usage_log_hash(cct, user_str, first_hash, index);

  hash = first_hash;
  do {
    int ret =  cls_obj_usage_log_trim(hash, user_str, start_epoch, end_epoch);

    if (ret < 0 && ret != -ENOENT)
      return ret;

    usage_log_hash(cct, user_str, hash, ++index);
  } while (hash != first_hash);

  return 0;
}

int RGWRados::trim_total_usage(rgw_user& user, string bucket)
{
  uint32_t index = 0;
  string hash, first_hash;
  string user_str = user.to_str();
  usage_log_hash(cct, user_str, first_hash, index);

  hash = first_hash;
  do {
    int ret =  cls_obj_usage_log_trim_total(hash, user_str, bucket);

    if (ret < 0 && ret != -ENOENT)
    return ret;

    usage_log_hash(cct, user_str, hash, ++index);
  } while (hash != first_hash);

  return 0;
}

int RGWRados::trim_readop_usage(rgw_user& user, uint64_t start_epoch, uint64_t end_epoch)
{
  uint32_t index = 0;
  string hash, first_hash;
  string user_str = user.to_str();
  usage_log_hash(cct, user_str, first_hash, index);

  hash = first_hash;
  do {
    int ret =  cls_obj_usage_log_trim_readop(hash, user_str, start_epoch, end_epoch);

    if (ret < 0 && ret != -ENOENT)
      return ret;

    usage_log_hash(cct, user_str, hash, ++index);
  } while (hash != first_hash);

  return 0;
}

int RGWRados::clear_usage()
{
  auto max_shards = cct->_conf->rgw_usage_max_shards;
  int ret=0;
  for (unsigned i=0; i < max_shards; i++){
    string oid = RGW_USAGE_OBJ_PREFIX + to_string(i);
    ret = cls_obj_usage_log_clear(oid);
    if (ret < 0){
      ldout(cct,0) << "usage clear on oid="<< oid << "failed with ret=" << ret << dendl;
      return ret;
    }
  }
  return ret;
}

int RGWRados::key_to_shard_id(const string& key, int max_shards)
{
  return rgw_shard_id(key, max_shards);
}

void RGWRados::shard_name(const string& prefix, unsigned max_shards, const string& key, string& name, int *shard_id)
{
  uint32_t val = ceph_str_hash_linux(key.c_str(), key.size());
  char buf[16];
  if (shard_id) {
    *shard_id = val % max_shards;
  }
  snprintf(buf, sizeof(buf), "%u", (unsigned)(val % max_shards));
  name = prefix + buf;
}

void RGWRados::shard_name(const string& prefix, unsigned max_shards, const string& section, const string& key, string& name)
{
  uint32_t val = ceph_str_hash_linux(key.c_str(), key.size());
  val ^= ceph_str_hash_linux(section.c_str(), section.size());
  char buf[16];
  snprintf(buf, sizeof(buf), "%u", (unsigned)(val % max_shards));
  name = prefix + buf;
}

void RGWRados::shard_name(const string& prefix, unsigned shard_id, string& name)
{
  char buf[16];
  snprintf(buf, sizeof(buf), "%u", shard_id);
  name = prefix + buf;

}

void RGWRados::time_log_prepare_entry(cls_log_entry& entry, const real_time& ut, const string& section, const string& key, bufferlist& bl)
{
  cls_log_add_prepare_entry(entry, utime_t(ut), section, key, bl);
}

int RGWRados::time_log_add_init(librados::IoCtx& io_ctx)
{
  return rgw_init_ioctx(get_rados_handle(), get_zone_params().log_pool, io_ctx, true);

}

int RGWRados::time_log_add(const string& oid, const real_time& ut, const string& section, const string& key, bufferlist& bl)
{
  librados::IoCtx io_ctx;

  int r = time_log_add_init(io_ctx);
  if (r < 0) {
    return r;
  }

  ObjectWriteOperation op;
  utime_t t(ut);
  cls_log_add(op, t, section, key, bl);

  return io_ctx.operate(oid, &op);
}

int RGWRados::time_log_add(const string& oid, list<cls_log_entry>& entries,
			   librados::AioCompletion *completion, bool monotonic_inc)
{
  librados::IoCtx io_ctx;

  int r = time_log_add_init(io_ctx);
  if (r < 0) {
    return r;
  }

  ObjectWriteOperation op;
  cls_log_add(op, entries, monotonic_inc);

  if (!completion) {
    r = io_ctx.operate(oid, &op);
  } else {
    r = io_ctx.aio_operate(oid, completion, &op);
  }
  return r;
}

int RGWRados::time_log_list(const string& oid, const real_time& start_time, const real_time& end_time,
                            int max_entries, list<cls_log_entry>& entries,
			    const string& marker,
			    string *out_marker,
			    bool *truncated)
{
  librados::IoCtx io_ctx;

  int r = rgw_init_ioctx(get_rados_handle(), get_zone_params().log_pool, io_ctx);
  if (r < 0)
    return r;
  librados::ObjectReadOperation op;

  utime_t st(start_time);
  utime_t et(end_time);

  cls_log_list(op, st, et, marker, max_entries, entries,
	       out_marker, truncated);

  bufferlist obl;

  int ret = io_ctx.operate(oid, &op, &obl);
  if (ret < 0)
    return ret;

  return 0;
}

int RGWRados::time_log_info(const string& oid, cls_log_header *header)
{
  librados::IoCtx io_ctx;

  int r = rgw_init_ioctx(get_rados_handle(), get_zone_params().log_pool, io_ctx);
  if (r < 0)
    return r;
  librados::ObjectReadOperation op;

  cls_log_info(op, header);

  bufferlist obl;

  int ret = io_ctx.operate(oid, &op, &obl);
  if (ret < 0)
    return ret;

  return 0;
}

int RGWRados::time_log_info_async(librados::IoCtx& io_ctx, const string& oid, cls_log_header *header, librados::AioCompletion *completion)
{
  int r = rgw_init_ioctx(get_rados_handle(), get_zone_params().log_pool, io_ctx);
  if (r < 0)
    return r;

  librados::ObjectReadOperation op;

  cls_log_info(op, header);

  int ret = io_ctx.aio_operate(oid, completion, &op, NULL);
  if (ret < 0)
    return ret;

  return 0;
}

int RGWRados::time_log_trim(const string& oid, const real_time& start_time, const real_time& end_time,
			    const string& from_marker, const string& to_marker,
                            librados::AioCompletion *completion)
{
  librados::IoCtx io_ctx;

  int r = rgw_init_ioctx(get_rados_handle(), get_zone_params().log_pool, io_ctx);
  if (r < 0)
    return r;

  utime_t st(start_time);
  utime_t et(end_time);

  ObjectWriteOperation op;
  cls_log_trim(op, st, et, from_marker, to_marker);

  if (!completion) {
    r = io_ctx.operate(oid, &op);
  } else {
    r = io_ctx.aio_operate(oid, completion, &op);
  }
  return r;
}

string RGWRados::objexp_hint_get_shardname(int shard_num)
{
  char buf[32];
  snprintf(buf, sizeof(buf), "%010u", (unsigned)shard_num);

  string objname("obj_delete_at_hint.");
  return objname + buf;
}

int RGWRados::objexp_key_shard(const rgw_obj_index_key& key)
{
  string obj_key = key.name + key.instance;
  int num_shards = cct->_conf->rgw_objexp_hints_num_shards;
  return rgw_bucket_shard_index(obj_key, num_shards);
}

static string objexp_hint_get_keyext(const string& tenant_name,
                                     const string& bucket_name,
                                     const string& bucket_id,
                                     const rgw_obj_key& obj_key)
{
  return tenant_name + (tenant_name.empty() ? "" : ":") + bucket_name + ":" + bucket_id +
      ":" + obj_key.name + ":" + obj_key.instance;
}

int RGWRados::objexp_hint_add(const ceph::real_time& delete_at,
                              const string& tenant_name,
                              const string& bucket_name,
                              const string& bucket_id,
                              const rgw_obj_index_key& obj_key)
{
  const string keyext = objexp_hint_get_keyext(tenant_name, bucket_name,
          bucket_id, obj_key);
  objexp_hint_entry he = {
      .tenant = tenant_name,
      .bucket_name = bucket_name,
      .bucket_id = bucket_id,
      .obj_key = obj_key,
      .exp_time = delete_at };
  bufferlist hebl;
  encode(he, hebl);
  ObjectWriteOperation op;
  cls_timeindex_add(op, utime_t(delete_at), keyext, hebl);

  string shard_name = objexp_hint_get_shardname(objexp_key_shard(obj_key));
  return objexp_pool_ctx.operate(shard_name, &op);
}

void  RGWRados::objexp_get_shard(int shard_num,
                                 string& shard)                       /* out */
{
  shard = objexp_hint_get_shardname(shard_num);
}

int RGWRados::objexp_hint_list(const string& oid,
                               const ceph::real_time& start_time,
                               const ceph::real_time& end_time,
                               const int max_entries,
                               const string& marker,
                               list<cls_timeindex_entry>& entries, /* out */
                               string *out_marker,                 /* out */
                               bool *truncated)                    /* out */
{
  librados::ObjectReadOperation op;
  cls_timeindex_list(op, utime_t(start_time), utime_t(end_time), marker, max_entries, entries,
        out_marker, truncated);

  bufferlist obl;
  int ret = objexp_pool_ctx.operate(oid, &op, &obl);

  if ((ret < 0 ) && (ret != -ENOENT)) {
    return ret;
  }

  if ((ret == -ENOENT) && truncated) {
    *truncated = false;
  }

  return 0;
}

int RGWRados::objexp_hint_parse(cls_timeindex_entry &ti_entry,  /* in */
                                objexp_hint_entry& hint_entry)  /* out */
{
  try {
    bufferlist::iterator iter = ti_entry.value.begin();
    decode(hint_entry, iter);
  } catch (buffer::error& err) {
    ldout(cct, 0) << "ERROR: couldn't decode avail_pools" << dendl;
  }

  return 0;
}

int RGWRados::objexp_hint_trim(const string& oid,
                               const ceph::real_time& start_time,
                               const ceph::real_time& end_time,
                               const string& from_marker,
                               const string& to_marker)
{
  int ret = cls_timeindex_trim(objexp_pool_ctx, oid, utime_t(start_time), utime_t(end_time),
          from_marker, to_marker);
  if ((ret < 0 ) && (ret != -ENOENT)) {
    return ret;
  }

  return 0;
}

int RGWRados::lock_exclusive(rgw_pool& pool, const string& oid, timespan& duration, 
                             string& zone_id, string& owner_id) {
  librados::IoCtx io_ctx;

  int r = rgw_init_ioctx(get_rados_handle(), pool, io_ctx);
  if (r < 0) {
    return r;
  }
  uint64_t msec = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
  utime_t ut(msec / 1000, msec % 1000);
  
  rados::cls::lock::Lock l(log_lock_name);
  l.set_duration(ut);
  l.set_cookie(owner_id);
  l.set_tag(zone_id);
  l.set_may_renew(true);
  
  return l.lock_exclusive(&io_ctx, oid);
}

int RGWRados::unlock(rgw_pool& pool, const string& oid, string& zone_id, string& owner_id) {
  librados::IoCtx io_ctx;

  int r = rgw_init_ioctx(get_rados_handle(), pool, io_ctx);
  if (r < 0) {
    return r;
  }
  
  rados::cls::lock::Lock l(log_lock_name);
  l.set_tag(zone_id);
  l.set_cookie(owner_id);
  
  return l.unlock(&io_ctx, oid);
}

int RGWRados::decode_policy(bufferlist& bl, ACLOwner *owner)
{
  bufferlist::iterator i = bl.begin();
  RGWAccessControlPolicy policy(cct);
  try {
    policy.decode_owner(i);
  } catch (buffer::error& err) {
    ldout(cct, 0) << "ERROR: could not decode policy, caught buffer::error" << dendl;
    return -EIO;
  }
  *owner = policy.get_owner();
  return 0;
}

int rgw_policy_from_attrset(CephContext *cct, map<string, bufferlist>& attrset, RGWAccessControlPolicy *policy)
{
  map<string, bufferlist>::iterator aiter = attrset.find(RGW_ATTR_ACL);
  if (aiter == attrset.end())
    return -EIO;

  bufferlist& bl = aiter->second;
  bufferlist::iterator iter = bl.begin();
  try {
    policy->decode(iter);
  } catch (buffer::error& err) {
    ldout(cct, 0) << "ERROR: could not decode policy, caught buffer::error" << dendl;
    return -EIO;
  }
  if (cct->_conf->subsys.should_gather<ceph_subsys_rgw, 15>()) {
    RGWAccessControlPolicy_S3 *s3policy = static_cast<RGWAccessControlPolicy_S3 *>(policy);
    ldout(cct, 15) << __func__ << " Read AccessControlPolicy";
    s3policy->to_xml(*_dout);
    *_dout << dendl;
  }
  return 0;
}


int RGWRados::Bucket::update_bucket_id(const string& new_bucket_id)
{
  rgw_bucket bucket = bucket_info.bucket;
  bucket.update_bucket_id(new_bucket_id);

  RGWObjectCtx obj_ctx(store);

  bucket_info.objv_tracker.clear();
  int ret = store->get_bucket_instance_info(obj_ctx, bucket, bucket_info, nullptr, nullptr);
  if (ret < 0) {
    return ret;
  }

  return 0;
}


/**
 * Get ordered listing of the objects in a bucket.
 *
 * max: maximum number of results to return
 * bucket: bucket to list contents of
 * prefix: only return results that match this prefix
 * delim: do not include results that match this string.
 *     Any skipped results will have the matching portion of their name
 *     inserted in common_prefixes with a "true" mark.
 * marker: if filled in, begin the listing with this object.
 * end_marker: if filled in, end the listing with this object.
 * result: the objects are put in here.
 * common_prefixes: if delim is filled in, any matching prefixes are placed here.
 * is_truncated: if number of objects in the bucket is bigger than max, then truncated.
 */
int RGWRados::Bucket::List::list_objects_ordered(int64_t max,
						 vector<rgw_bucket_dir_entry> *result,
						 map<string, bool> *common_prefixes,
						 bool *is_truncated)
{
  RGWRados *store = target->get_store();
  CephContext *cct = store->ctx();
  int shard_id = target->get_shard_id();

  int count = 0;
  bool truncated = true;
  int read_ahead = std::max(cct->_conf->rgw_list_bucket_min_readahead,max);

  result->clear();

  rgw_obj_key marker_obj(params.marker.name, params.marker.instance, params.ns);
  rgw_obj_index_key cur_marker;
  marker_obj.get_index_key(&cur_marker);

  rgw_obj_key end_marker_obj(params.end_marker.name, params.end_marker.instance,
                             params.ns);
  rgw_obj_index_key cur_end_marker;
  end_marker_obj.get_index_key(&cur_end_marker);
  const bool cur_end_marker_valid = !params.end_marker.empty();

  rgw_obj_key prefix_obj(params.prefix);
  prefix_obj.ns = params.ns;
  string cur_prefix = prefix_obj.get_index_key_name();

  bool skip_ns = list_need_skip_namespace(params.enforce_ns, params.ns, params.prefix);

  // we'll stop after this many attempts as long we return at least
  // one entry; but we will also go beyond this number of attempts
  // until we return at least one entry
  uint32_t max_attempt_times = cct->_conf->rgw_list_max_attempt_times;

  string skip_after_delim;
  string last_common_prefix;
  for (uint32_t attempt = 1; /* empty */; ++attempt) {
  //while (truncated && count <= max) {
    if (!params.delim.empty()) {
      /* if marker points at a common prefix, fast forward it into its
       * upper bound string */
      int delim_pos = cur_marker.name.find(params.delim, cur_prefix.size());
      if (delim_pos >= 0) {
        cur_marker.instance.clear();
        cur_marker.name.erase(delim_pos+1);
        cls_rgw_append_max_charater(cur_marker.name);
        ldout(cct, 20) << "setting cur_marker=" << cur_marker.name << "[" << cur_marker.instance << "]" << dendl;
      }
    }

    ldout(cct, 20) << __PRETTY_FUNCTION__ << ": starting attempt " << attempt << dendl;
    ent_map_t ent_map;
    ent_map.reserve(read_ahead);
    int r = store->cls_bucket_list_ordered(target->get_bucket_info(),
                                           shard_id,
                                           cur_marker,
                                           cur_prefix,
                                           // [TODO] transfer delimiter to cls/osd
                                           read_ahead + 1 - count,
                                           params.list_versions,
                                           skip_ns,
                                           attempt,
                                           ent_map,
                                           &truncated,
                                           &cur_marker);
    if (r < 0)
      return r;

    for (auto eiter = ent_map.begin(); eiter != ent_map.end(); ++eiter) {
      rgw_bucket_dir_entry& entry = eiter->second;
      rgw_obj_index_key index_key = entry.key;

      rgw_obj_key obj(index_key);

      ldout(cct, 20) << __PRETTY_FUNCTION__ << ": considering entry " << entry.key << dendl;

      /* note that parse_raw_oid() here will not set the correct
       * object's instance, as rgw_obj_index_key encodes that
       * separately. We don't need to set the instance because it's
       * not needed for the checks here and we end up using the raw
       * entry for the return vector
       */
      bool valid = rgw_obj_key::parse_raw_oid(index_key.name, &obj);
      if (!valid) {
        ldout(cct, 0) << __PRETTY_FUNCTION__ << "ERROR: could not parse object name: " << obj.name << dendl;
        continue;
      }
      bool check_ns = (obj.ns == params.ns);
      if (!params.list_versions && !entry.is_visible()) {
        ldout(cct, 10) << __PRETTY_FUNCTION__ <<
          ": skipping not visible entry \"" << entry.key << "\"" << dendl;
        continue;
      }

      if (params.enforce_ns && !check_ns) {
        if (!params.ns.empty()) {
          /* we've iterated past the namespace we're searching -- done now */
          truncated = false;
          ldout(cct, 10) << __PRETTY_FUNCTION__ <<
            ": finished due to getting past requested namespace \"" << params.ns << "\"" << dendl;
          goto done;
        }

        /* we're skipping past namespaced objects */
        ldout(cct, 20) << __PRETTY_FUNCTION__ <<
          ": skipping past namespaced objects, including \"" << entry.key << "\"" << dendl;
        continue;
      }

      if (cur_end_marker_valid && cur_end_marker <= index_key) {
        truncated = false;
        ldout(cct, 10) << __PRETTY_FUNCTION__ <<
          ": finished due to gitting end marker of \"" << cur_end_marker <<
          "\" with \"" << entry.key << "\"" << dendl;
        goto done;
      }

      if (count < max) {
        params.marker = index_key;
        next_marker = index_key;
      }

      if (params.filter && !params.filter->filter(obj.name, index_key.name)) {
        ldout(cct, 20) << __PRETTY_FUNCTION__ <<
          ": skipping past namespaced objects, including \"" << entry.key << "\"" << dendl;
        continue;
      }

      if (params.prefix.size() &&
	        (obj.name.compare(0, params.prefix.size(), params.prefix) != 0)) {
        ldout(cct, 20) << __PRETTY_FUNCTION__ <<
          ": skipping object \"" << entry.key <<
          "\" that doesn't match prefix \"" << params.prefix << "\"" << dendl;
        continue;
      }

      if (!params.delim.empty()) {
        int delim_pos = obj.name.find(params.delim, params.prefix.size());

        if (delim_pos >= 0) {
          std::string_view prefix_key = std::string_view(obj.name).substr(0, delim_pos + 1);
          if (common_prefixes && last_common_prefix != prefix_key) {
            if (count >= max) {
              truncated = true;
              ldout(cct, 10) << __PRETTY_FUNCTION__ <<
                  ": stopping early with common prefix \"" << entry.key <<
                  "\" because requested number (" << max <<
                  ") reached (not cls filtered)" << dendl;
              goto done;
            }
            next_marker = prefix_key;
            last_common_prefix = prefix_key;
            (*common_prefixes)[last_common_prefix] = true;
            count++;
          }
          ldout(cct, 20) << __PRETTY_FUNCTION__ <<
              ": finished entry with common prefix \"" << entry.key <<
              "\" so continuing loop (not cls filtered)" << dendl;
          continue;
        } // if a delimiter was found after prefix
      } // if a delimiter was passed in

      if (count >= max) {
        truncated = true;
        ldout(cct, 10) << __PRETTY_FUNCTION__ <<
          ": stopping early with entry \"" << entry.key <<
          "\" because requested number (" << max <<
          ") reached" << dendl;
        goto done;
      }

      ldout(cct, 20) << __PRETTY_FUNCTION__ <<
        ": adding entry " << entry.key << " to result" << dendl;

      result->emplace_back(std::move(entry));
      count++;
    } // eiter for loop

    ldout(cct, 10) << __PRETTY_FUNCTION__ <<
      ": end of outer loop, truncated=" << truncated <<
      ", count=" << count << ", attempt=" << attempt << dendl;

    //if (!truncated || count >= (max + 1) / 2) {  // github: return when get more than half entries
    if (!truncated || count > max) {
      // if we finished listing, or if we're returning at least half the
      // requested entries, that's enough; S3 and swift protocols allow
      // returning fewer than max entries
      ldout(cct, 10) << __PRETTY_FUNCTION__ <<
        ": exiting attempt loop because we reached end (" << truncated <<
        ") or we're returning the requested entries (" << count <<
        " of " << max << ")" << dendl;
      break;
    } else if (max_attempt_times != 0 && attempt >= max_attempt_times && count >= 1) {
      // if we've made at least 8 attempts and we have some, but very
      // few, results, return with what we have
      ldout(cct, 10) << __PRETTY_FUNCTION__ <<
        ": exiting attempt loop because we made " << attempt <<
        " attempts and we're returning " << count << " entries" << dendl;
      break;
    }
  }

done:
  if (is_truncated)
    *is_truncated = truncated;

  return 0;
} // list_objects_ordered


/**
 * Get listing of the objects in a bucket and allow the results to be out
 * of order.
 *
 * Even though there are key differences with the ordered counterpart,
 * the parameters are the same to maintain some compatability.
 *
 * max: maximum number of results to return
 * bucket: bucket to list contents of
 * prefix: only return results that match this prefix
 * delim: should not be set; if it is we should have indicated an error
 * marker: if filled in, begin the listing with this object.
 * end_marker: if filled in, end the listing with this object.
 * result: the objects are put in here.
 * common_prefixes: this is never filled with an unordered list; the param
 *                  is maintained for compatibility
 * is_truncated: if number of objects in the bucket is bigger than max, then
 *               truncated.
 */
int RGWRados::Bucket::List::list_objects_unordered(int64_t max,
						   vector<rgw_bucket_dir_entry> *result,
						   map<string, bool> *common_prefixes,
						   bool *is_truncated)
{
  RGWRados *store = target->get_store();
  CephContext *cct = store->ctx();
  int shard_id = target->get_shard_id();

  int count = 0;
  bool truncated = true;

  // read a few extra in each call to cls_bucket_list_unordered in
  // case some are filtered out due to namespace matching, versioning,
  // filtering, etc.
  const int64_t max_read_ahead = 100;
  const uint32_t read_ahead = uint32_t(max + std::min(max, max_read_ahead));

  result->clear();

  rgw_obj_key marker_obj(params.marker.name, params.marker.instance, params.ns);
  rgw_obj_index_key cur_marker;
  marker_obj.get_index_key(&cur_marker);

  rgw_obj_key end_marker_obj(params.end_marker.name, params.end_marker.instance,
                             params.ns);
  rgw_obj_index_key cur_end_marker;
  end_marker_obj.get_index_key(&cur_end_marker);
  const bool cur_end_marker_valid = !params.end_marker.empty();

  rgw_obj_key prefix_obj(params.prefix);
  prefix_obj.ns = params.ns;
  string cur_prefix = prefix_obj.get_index_key_name();

  while (truncated && count <= max) {
    std::vector<rgw_bucket_dir_entry> ent_list;
    int r = store->cls_bucket_list_unordered(target->get_bucket_info(),
                                             shard_id,
                                             cur_marker,
                                             cur_prefix,
                                             read_ahead,
                                             params.list_versions,
                                             ent_list,
                                             &truncated,
                                             &cur_marker,
                                             shard_id,
                                             nullptr,
                                             self_shard);
    if (r < 0)
      return r;

    // NB: while regions of ent_list will be sorted, we have no
    // guarantee that all items will be sorted since they can cross
    // shard boundaries

    for (auto& entry : ent_list) {
      rgw_obj_index_key index_key = entry.key;
      rgw_obj_key obj(index_key);

      /* note that parse_raw_oid() here will not set the correct
       * object's instance, as rgw_obj_index_key encodes that
       * separately. We don't need to set the instance because it's
       * not needed for the checks here and we end up using the raw
       * entry for the return vector
       */
      bool valid = rgw_obj_key::parse_raw_oid(index_key.name, &obj);
      if (!valid) {
        ldout(cct, 0) << "ERROR: could not parse object name: " << obj.name << dendl;
        continue;
      }

      if (!params.list_versions && !entry.is_visible()) {
        continue;
      }

      if (params.enforce_ns && obj.ns != params.ns) {
        continue;
      }

      if (cur_end_marker_valid && cur_end_marker <= index_key) {
        // we're not guaranteed items will come in order, so we have
        // to loop through all
        continue;
      }

      if (count < max) {
        params.marker = index_key;
        next_marker = index_key;
      }

      if (params.filter && !params.filter->filter(obj.name, index_key.name))
        continue;

      if (params.prefix.size() &&
          (0 != obj.name.compare(0, params.prefix.size(), params.prefix)))
        continue;

      if (count >= max) {
        truncated = true;
        goto done;
      }

      result->emplace_back(std::move(entry));
      count++;
    } // for (auto& entry : ent_list)
  } // while (truncated && count <= max)

done:
  if (is_truncated)
    *is_truncated = truncated;

  return 0;
} // list_objects_unordered


/**
 * create a rados pool, associated meta info
 * returns 0 on success, -ERR# otherwise.
 */
int RGWRados::create_pool(const rgw_pool& pool)
{
  librados::IoCtx io_ctx;
  constexpr bool create = true;
  return rgw_init_ioctx(get_rados_handle(), pool, io_ctx, create);
}

int RGWRados::init_bucket_index(RGWBucketInfo& bucket_info, int num_shards)
{
  librados::IoCtx index_ctx;

  string dir_oid = dir_oid_prefix;
  int r = open_bucket_index_ctx(bucket_info, index_ctx);
  if (r < 0) {
    return r;
  }

  dir_oid.append(bucket_info.bucket.bucket_id);

  map<int, string> bucket_objs;
  get_bucket_index_objects(dir_oid, num_shards, bucket_objs);

  return CLSRGWIssueBucketIndexInit(index_ctx,
				    bucket_objs,
				    cct->_conf->rgw_bucket_index_max_aio)();
}

int RGWRados::clean_bucket_index(RGWBucketInfo& bucket_info, int num_shards)
{
  librados::IoCtx index_ctx;

  std::string dir_oid = dir_oid_prefix;
  int r = open_bucket_index_ctx(bucket_info, index_ctx);
  if (r < 0) {
    return r;
  }

  dir_oid.append(bucket_info.bucket.bucket_id);

  std::map<int, std::string> bucket_objs;
  get_bucket_index_objects(dir_oid, num_shards, bucket_objs);

  return CLSRGWIssueBucketIndexClean(index_ctx,
				     bucket_objs,
				     cct->_conf->rgw_bucket_index_max_aio)();
}

void RGWRados::create_bucket_id(string *bucket_id)
{
  uint64_t iid = instance_id();
  uint64_t bid = next_bucket_id();
  char buf[get_zone_params().get_id().size() + 48];
  snprintf(buf, sizeof(buf), "%s.%" PRIu64 ".%" PRIu64,
           get_zone_params().get_id().c_str(), iid, bid);
  *bucket_id = buf;
}

int RGWRados::create_bucket(RGWUserInfo& owner, rgw_bucket& bucket,
                            const string& zonegroup_id,
                            const rgw_placement_rule& placement_rule,
                            const string& swift_ver_location,
                            const RGWQuotaInfo * pquota_info,
                            map<std::string, bufferlist>& attrs,
                            RGWBucketInfo& info,
                            obj_version *pobjv,
                            obj_version *pep_objv,
                            real_time creation_time,
                            rgw_bucket *pmaster_bucket,
                            uint32_t *pmaster_num_shards,
                            bool exclusive)
{
#define MAX_CREATE_RETRIES 20 /* need to bound retries */
  rgw_placement_rule selected_placement_rule_name;
  RGWZonePlacementInfo rule_info;

  for (int i = 0; i < MAX_CREATE_RETRIES; i++) {
    int ret = 0;
    ret = select_bucket_placement(owner, zonegroup_id, placement_rule,
                                  &selected_placement_rule_name, &rule_info);
    if (ret < 0)
      return ret;

    if (!pmaster_bucket) {
      create_bucket_id(&bucket.marker);
      bucket.bucket_id = bucket.marker;
    } else {
      bucket.marker = pmaster_bucket->marker;
      bucket.bucket_id = pmaster_bucket->bucket_id;
    }

    RGWObjVersionTracker& objv_tracker = info.objv_tracker;

    if (pobjv) {
      objv_tracker.write_version = *pobjv;
    } else {
      objv_tracker.generate_new_write_ver(cct);
    }

    info.bucket = bucket;
    info.owner = owner.user_id;
    info.zonegroup = zonegroup_id;
    info.head_placement_rule = selected_placement_rule_name;
    info.index_type = rule_info.index_type;

    // set namespace type
    RGWBucketNamespaceType new_namespace_type = bucket_namespace_default_type;
    if (cct->_conf->rgw_bucket_namespace_disable_force) {
      new_namespace_type = BUCKET_NAMESPACE_DISABLE;
    }
    info.namespace_type = new_namespace_type;

    info.swift_ver_location = swift_ver_location;
    info.swift_versioning = (!swift_ver_location.empty());
    if (pmaster_num_shards) {
      info.num_shards = *pmaster_num_shards;
    } else {
      info.num_shards = bucket_index_max_shards;
    }
    info.bucket_index_shard_hash_type = RGWBucketInfo::MOD;
    info.requester_pays = false;
    info.creation_time = creation_time;
    if (pquota_info) {
      info.quota = *pquota_info;
    }

    int r = init_bucket_index(info, info.num_shards);
    if (r < 0) {
      return r;
    }

    ret = put_linked_bucket_info(info, exclusive, ceph::real_time(), pep_objv, &attrs, true);
    if (ret == -EEXIST) {
      librados::IoCtx index_ctx;
      map<int, string> bucket_objs;
      int r = open_bucket_index(info, index_ctx, bucket_objs);
      if (r < 0)
        return r;

       /* we need to reread the info and return it, caller will have a use for it */
      RGWObjVersionTracker instance_ver = info.objv_tracker;
      info.objv_tracker.clear();
      RGWObjectCtx obj_ctx(this);
      r = get_bucket_info(obj_ctx, bucket.tenant, bucket.name, info, NULL, NULL);
      if (r < 0) {
        if (r == -ENOENT) {
          continue;
        }
        ldout(cct, 0) << "get_bucket_info returned " << r << dendl;
        return r;
      }

      /* only remove it if it's a different bucket instance */
      if (info.bucket.bucket_id != bucket.bucket_id) {
        /* remove bucket meta instance */
        r = rgw_bucket_instance_remove_entry(this,
					     bucket.get_key(),
					     &instance_ver);
        if (r < 0)
          return r;

	/* remove bucket index objects asynchronously by best effort */
	(void) CLSRGWIssueBucketIndexClean(index_ctx,
					   bucket_objs,
					   cct->_conf->rgw_bucket_index_max_aio)();
      }
      /* ret == -ENOENT here */
    }

    /* disable multisite sync at the creation of a bucket */
    #ifdef WITH_UNAUTO_SYNC
      ret = stop_bi_log_entries(info, -1);
      if (ret < 0) {
        ldout(cct, 0) << "disable bilog returned " << r << dendl;
        return ret;
      }
    #endif

    return ret;
  }

  /* this is highly unlikely */
  ldout(cct, 0) << "ERROR: could not create bucket, continuously raced with bucket creation and removal" << dendl;
  return -ENOENT;
}

int RGWRados::select_new_bucket_location(RGWUserInfo& user_info, const string& zonegroup_id, const rgw_placement_rule& request_rule,
                                         rgw_placement_rule *pselected_rule_name, RGWZonePlacementInfo *rule_info)

{
  /* first check that zonegroup exists within current period. */
  RGWZoneGroup zonegroup;
  int ret = get_zonegroup(zonegroup_id, zonegroup);
  if (ret < 0) {
    ldout(cct, 0) << "could not find zonegroup " << zonegroup_id << " in current period" << dendl;
    return ret;
  }

  /* find placement rule. Hierarchy: request rule > user default rule > zonegroup default rule */
  std::map<std::string, RGWZoneGroupPlacementTarget>::const_iterator titer;

  if (!request_rule.name.empty()) {
    titer = zonegroup.placement_targets.find(request_rule.name);
    if (titer == zonegroup.placement_targets.end()) {
      ldout(cct, 0) << "could not find requested placement id " << request_rule 
                    << " within zonegroup " << dendl;
      return -ERR_INVALID_LOCATION_CONSTRAINT;
    }
  } else if (!user_info.default_placement.name.empty()) {
    titer = zonegroup.placement_targets.find(user_info.default_placement.name);
    if (titer == zonegroup.placement_targets.end()) {
      ldout(cct, 0) << "could not find user default placement id " << user_info.default_placement
                    << " within zonegroup " << dendl;
      return -ERR_INVALID_LOCATION_CONSTRAINT;
    }
  } else {
    if (zonegroup.default_placement.name.empty()) { // zonegroup default rule as fallback, it should not be empty.
      ldout(cct, 0) << "misconfiguration, zonegroup default placement id should not be empty." << dendl;
      return -ERR_ZONEGROUP_DEFAULT_PLACEMENT_MISCONFIGURATION;
    } else {
      titer = zonegroup.placement_targets.find(zonegroup.default_placement.name);
      if (titer == zonegroup.placement_targets.end()) {
        ldout(cct, 0) << "could not find zonegroup default placement id " << zonegroup.default_placement
                      << " within zonegroup " << dendl;
        return -ERR_INVALID_LOCATION_CONSTRAINT;
      }
    }
  }

  /* now check tag for the rule, whether user is permitted to use rule */
  const auto& target_rule = titer->second;
  if (!target_rule.user_permitted(user_info.placement_tags)) {
    ldout(cct, 0) << "user not permitted to use placement rule " << titer->first  << dendl;
    return -EPERM;
  }

  RGWZonePlacementInfo placement_info;
  ret = select_bucket_location_by_rule(titer->first, &placement_info);
  if (ret < 0) {
    return ret;
  }

  string storage_class = request_rule.storage_class;

  // default head placement rule order: STANDARD_HP > STANDARD
  if (storage_class.empty()) {
    if (placement_info.storage_class_exists(RGWStorageClass::STANDARD_HP)) {
      storage_class = RGWStorageClass::STANDARD_HP;
    } else {
      storage_class = RGWStorageClass::STANDARD;
    }
  } else {
    if (!placement_info.storage_class_exists(storage_class)) {
      ldout(cct, 2) << "the specified storage class does not exist: " << storage_class << dendl;
      return -ERR_INVALID_STORAGE_CLASS;
    }
  }

  rgw_placement_rule rule(titer->first, storage_class);

  if (pselected_rule_name) {
    *pselected_rule_name = rule;
  }

  return 0;
}

int RGWRados::select_bucket_location_by_rule(const string& location_rule, RGWZonePlacementInfo *rule_info)
{
  if (location_rule.empty()) {
    /* we can only reach here if we're trying to set a bucket location from a bucket
     * created on a different zone, using a legacy / default pool configuration
     */
    if (rule_info) {
      return select_legacy_bucket_placement(rule_info);
    }

    return 0;
  }

  /*
   * make sure that zone has this rule configured. We're
   * checking it for the local zone, because that's where this bucket object is going to
   * reside.
   */
  map<string, RGWZonePlacementInfo>::iterator piter = get_zone_params().placement_pools.find(location_rule);
  if (piter == get_zone_params().placement_pools.end()) {
    /* couldn't find, means we cannot really place data for this bucket in this zone */
    if (get_zonegroup().equals(zonegroup.get_id())) {
      /* that's a configuration error, zone should have that rule, as we're within the requested
       * zonegroup */
      return -EINVAL;
    } else {
      /* oh, well, data is not going to be placed here, bucket object is just a placeholder */
      return 0;
    }
  }

  RGWZonePlacementInfo& placement_info = piter->second;

  if (rule_info) {
    *rule_info = placement_info;
  }

  return 0;
}

int RGWRados::select_bucket_placement(RGWUserInfo& user_info, const string& zonegroup_id,
                                      const rgw_placement_rule& placement_rule,
                                      rgw_placement_rule *pselected_rule, RGWZonePlacementInfo *rule_info)
{
  if (!get_zone_params().placement_pools.empty()) {
    return select_new_bucket_location(user_info, zonegroup_id, placement_rule,
                                      pselected_rule, rule_info);
  }

  if (pselected_rule) {
    pselected_rule->clear();
  }

  if (rule_info) {
    return select_legacy_bucket_placement(rule_info);
  }

  return 0;
}

int RGWRados::select_legacy_bucket_placement(RGWZonePlacementInfo *rule_info)
{
  bufferlist map_bl;
  map<string, bufferlist> m;
  string pool_name;
  bool write_map = false;

  rgw_raw_obj obj(get_zone_params().domain_root, avail_pools);

  RGWObjectCtx obj_ctx(this);
  int ret = rgw_get_system_obj(this, obj_ctx, get_zone_params().domain_root, avail_pools, map_bl, NULL, NULL);
  if (ret < 0) {
    goto read_omap;
  }

  try {
    bufferlist::iterator iter = map_bl.begin();
    decode(m, iter);
  } catch (buffer::error& err) {
    ldout(cct, 0) << "ERROR: couldn't decode avail_pools" << dendl;
  }

read_omap:
  if (m.empty()) {
    bufferlist header;
    ret = omap_get_all(obj, header, m);

    write_map = true;
  }

  if (ret < 0 || m.empty()) {
    vector<rgw_pool> pools;
    string s = string("default.") + default_storage_pool_suffix;
    pools.push_back(rgw_pool(s));
    vector<int> retcodes;
    bufferlist bl;
    ret = create_pools(pools, retcodes);
    if (ret < 0)
      return ret;
    ret = omap_set(obj, s, bl);
    if (ret < 0)
      return ret;
    m[s] = bl;
  }

  if (write_map) {
    bufferlist new_bl;
    encode(m, new_bl);
    ret = put_system_obj_data(NULL, obj, new_bl, -1, false);
    if (ret < 0) {
      ldout(cct, 0) << "WARNING: could not save avail pools map info ret=" << ret << dendl;
    }
  }

  auto miter = m.begin();
  if (m.size() > 1) {
    // choose a pool at random
    auto r = ceph::util::generate_random_number<size_t>(0, m.size() - 1);
    std::advance(miter, r);
  }
  pool_name = miter->first;

  rgw_pool pool(pool_name);
  rule_info->storage_classes.set_storage_class(RGWStorageClass::STANDARD, &pool, nullptr);
  rule_info->data_extra_pool = pool_name;
  rule_info->index_pool = pool_name;
  rule_info->index_type = RGWBIType_Normal;

  return 0;
}

bool RGWRados::get_obj_data_pool(const rgw_placement_rule& placement_rule, const rgw_obj& obj, rgw_pool *pool)
{
  if (!zone_params.get_data_pool(placement_rule, obj, pool)) {
    RGWZonePlacementInfo placement;
    if (!zone_params.get_placement(zonegroup.default_placement.name, &placement)) {
      return false;
    }

    if (!obj.in_extra_data) {
      *pool = placement.get_data_pool(zonegroup.default_placement.storage_class);
    } else {
      *pool = placement.get_data_extra_pool();
    }
  }

  return true;
}

bool RGWRados::get_obj_tail_pool(const rgw_placement_rule& placement_rule, rgw_pool *pool)
{
  return zone_params.get_tail_pool(placement_rule, pool);
}

bool RGWRados::obj_to_raw(const rgw_placement_rule& placement_rule, const rgw_obj& obj, rgw_raw_obj *raw_obj) {
  get_obj_bucket_and_oid_loc(obj, raw_obj->oid, raw_obj->loc);
  return get_obj_data_pool(placement_rule, obj, &raw_obj->pool);
}

int RGWRados::update_placement_map() {
  bufferlist header;
  map<string, bufferlist> m;
  rgw_raw_obj obj(get_zone_params().domain_root, avail_pools);
  int ret = omap_get_all(obj, header, m);
  if (ret < 0)
    return ret;

  bufferlist new_bl;
  encode(m, new_bl);
  ret = put_system_obj_data(NULL, obj, new_bl, -1, false);
  if (ret < 0) {
    ldout(cct, 0) << "WARNING: could not save avail pools map info ret=" << ret << dendl;
  }

  return ret;
}

int RGWRados::add_bucket_placement(const rgw_pool& new_pool)
{
  librados::Rados *rad = get_rados_handle();
  int ret = rad->pool_lookup(new_pool.name.c_str());
  if (ret < 0) // DNE, or something
    return ret;

  rgw_raw_obj obj(get_zone_params().domain_root, avail_pools);
  bufferlist empty_bl;
  ret = omap_set(obj, new_pool.to_str(), empty_bl);

  // don't care about return value
  update_placement_map();

  return ret;
}

int RGWRados::remove_bucket_placement(const rgw_pool& old_pool)
{
  rgw_raw_obj obj(get_zone_params().domain_root, avail_pools);
  int ret = omap_del(obj, old_pool.to_str());

  // don't care about return value
  update_placement_map();

  return ret;
}

int RGWRados::list_placement_set(set<rgw_pool>& names)
{
  bufferlist header;
  map<string, bufferlist> m;

  rgw_raw_obj obj(get_zone_params().domain_root, avail_pools);
  int ret = omap_get_all(obj, header, m);
  if (ret < 0)
    return ret;

  names.clear();
  map<string, bufferlist>::iterator miter;
  for (miter = m.begin(); miter != m.end(); ++miter) {
    names.insert(rgw_pool(miter->first));
  }

  return names.size();
}

int RGWRados::create_pools(vector<rgw_pool>& pools, vector<int>& retcodes)
{
  vector<librados::PoolAsyncCompletion *> completions;
  vector<int> rets;

  librados::Rados *rad = get_rados_handle();
  for (auto iter = pools.begin(); iter != pools.end(); ++iter) {
    librados::PoolAsyncCompletion *c = librados::Rados::pool_async_create_completion();
    completions.push_back(c);
    rgw_pool& pool = *iter;
    int ret = rad->pool_create_async(pool.name.c_str(), c);
    rets.push_back(ret);
  }

  vector<int>::iterator riter;
  vector<librados::PoolAsyncCompletion *>::iterator citer;

  bool error = false;
  assert(rets.size() == completions.size());
  for (riter = rets.begin(), citer = completions.begin(); riter != rets.end(); ++riter, ++citer) {
    int r = *riter;
    PoolAsyncCompletion *c = *citer;
    if (r == 0) {
      c->wait();
      r = c->get_return_value();
      if (r < 0) {
        ldout(cct, 0) << "WARNING: async pool_create returned " << r << dendl;
        error = true;
      }
    }
    c->release();
    retcodes.push_back(r);
  }
  if (error) {
    return 0;
  }

  std::vector<librados::IoCtx> io_ctxs;
  retcodes.clear();
  for (auto pool : pools) {
    io_ctxs.emplace_back();
    int ret = rad->ioctx_create(pool.name.c_str(), io_ctxs.back());
    if (ret < 0) {
      ldout(cct, 0) << "WARNING: ioctx_create returned " << ret << dendl;
      error = true;
    }
    retcodes.push_back(ret);
  }
  if (error) {
    return 0;
  }

  completions.clear();
  for (auto &io_ctx : io_ctxs) {
    librados::PoolAsyncCompletion *c =
      librados::Rados::pool_async_create_completion();
    completions.push_back(c);
    int ret = io_ctx.application_enable_async(pg_pool_t::APPLICATION_NAME_RGW,
                                              false, c);
    assert(ret == 0);
  }

  retcodes.clear();
  for (auto c : completions) {
    c->wait();
    int ret = c->get_return_value();
    if (ret == -EOPNOTSUPP) {
      ret = 0;
    } else if (ret < 0) {
      ldout(cct, 0) << "WARNING: async application_enable returned " << ret
                    << dendl;
      error = true;
    }
    c->release();
    retcodes.push_back(ret);
  }
  return 0;
}

int RGWRados::get_obj_head_ioctx(const RGWBucketInfo& bucket_info, const rgw_obj& obj, librados::IoCtx *ioctx) {
  string oid, key;
  get_obj_bucket_and_oid_loc(obj, oid, key);

  rgw_pool pool;
  if (!get_obj_data_pool(bucket_info.head_placement_rule, obj, &pool)) {
    ldout(cct, 0) << "ERROR: cannot get data pool for obj=" << obj << ", probably misconfiguration" << dendl;
    return -EIO;
  }

  int r = open_pool_ctx(pool, *ioctx);
  if (r < 0) {
    return r;
  }

  ioctx->locator_set_key(key);

  return 0;
}

int RGWRados::get_obj_head_ref(const RGWBucketInfo& bucket_info, const rgw_obj& obj, rgw_rados_ref *ref)
{
  get_obj_bucket_and_oid_loc(obj, ref->oid, ref->key);

  rgw_pool pool;
  if (!get_obj_data_pool(bucket_info.head_placement_rule, obj, &pool)) {
    ldout(cct, 0) << "ERROR: cannot get data pool for obj=" << obj << ", probably misconfiguration" << dendl;
    return -EIO;
  }

  ldout(cct, 20) << "get obj head ref, the pool is: " << pool.name << dendl;
  int r = open_pool_ctx(pool, ref->ioctx);
  if (r < 0) {
    return r;
  }

  ref->ioctx.locator_set_key(ref->key);

  return 0;
}

int RGWRados::get_obj_head_ref(const rgw_placement_rule& placement_rule, const rgw_obj& obj, rgw_rados_ref *ref)
{
  get_obj_bucket_and_oid_loc(obj, ref->oid, ref->key);

  rgw_pool pool;
  if (!get_obj_data_pool(placement_rule, obj, &pool)) {
    ldout(cct, 0) << "ERROR: cannot get data pool for obj=" << obj << ", probably misconfiguration" << dendl;
    return -EIO;
  }

  ldout(cct, 20) << "get obj head ref, the pool is: " << pool.name << dendl;
  int r = open_pool_ctx(pool, ref->ioctx);
  if (r < 0) {
    return r;
  }

  ref->ioctx.locator_set_key(ref->key);

  return 0;
}

int RGWRados::get_raw_obj_ref(const rgw_raw_obj& obj, rgw_rados_ref *ref, librados::Rados* rados_handle)
{
  ref->oid = obj.oid;
  ref->key = obj.loc;

  int r;

  if (ref->oid.empty()) {
    ref->oid = obj.pool.to_str();
    ref->pool = get_zone_params().domain_root;
  } else {
    ref->pool = obj.pool;
  }
  r = open_pool_ctx(ref->pool, ref->ioctx, rados_handle);
  if (r < 0)
    return r;

  ref->ioctx.locator_set_key(ref->key);

  return 0;
}

int RGWRados::get_system_obj_ref(const rgw_raw_obj& obj, rgw_rados_ref *ref)
{
  return get_raw_obj_ref(obj, ref);
}

/*
 * fixes an issue where head objects were supposed to have a locator created, but ended
 * up without one
 */
int RGWRados::fix_head_obj_locator(const RGWBucketInfo& bucket_info, bool copy_obj, bool remove_bad, rgw_obj_key& key)
{
  const rgw_bucket& bucket = bucket_info.bucket;
  string oid;
  string locator;

  rgw_obj obj(bucket, key);

  get_obj_bucket_and_oid_loc(obj, oid, locator);

  if (locator.empty()) {
    ldout(cct, 20) << "object does not have a locator, nothing to fix" << dendl;
    return 0;
  }

  librados::IoCtx ioctx;

  int ret = get_obj_head_ioctx(bucket_info, obj, &ioctx);
  if (ret < 0) {
    cerr << "ERROR: get_obj_head_ioctx() returned ret=" << ret << std::endl;
    return ret;
  }
  ioctx.locator_set_key(string()); /* override locator for this object, use empty locator */

  uint64_t size;
  bufferlist data;

  struct timespec mtime_ts;
  map<string, bufferlist> attrs;
  librados::ObjectReadOperation op;
  op.getxattrs(&attrs, NULL);
  op.stat2(&size, &mtime_ts, NULL);
#define HEAD_SIZE 512 * 1024
  op.read(0, HEAD_SIZE, &data, NULL);

  ret = ioctx.operate(oid, &op, NULL);
  if (ret < 0) {
    lderr(cct) << "ERROR: ioctx.operate(oid=" << oid << ") returned ret=" << ret << dendl;
    return ret;
  }

  if (size > HEAD_SIZE) {
    lderr(cct) << "ERROR: returned object size (" << size << ") > HEAD_SIZE (" << HEAD_SIZE << ")" << dendl;
    return -EIO;
  }

  if (size != data.length()) {
    lderr(cct) << "ERROR: returned object size (" << size << ") != data.length() (" << data.length() << ")" << dendl;
    return -EIO;
  }

  if (copy_obj) {
    librados::ObjectWriteOperation wop;

    wop.mtime2(&mtime_ts);

    map<string, bufferlist>::iterator iter;
    for (iter = attrs.begin(); iter != attrs.end(); ++iter) {
      wop.setxattr(iter->first.c_str(), iter->second);
    }

    wop.write(0, data);

    ioctx.locator_set_key(locator);
    ioctx.operate(oid, &wop);
  }

  if (remove_bad) {
    ioctx.locator_set_key(string());

    ret = ioctx.remove(oid);
    if (ret < 0) {
      lderr(cct) << "ERROR: failed to remove original bad object" << dendl;
      return ret;
    }
  }

  return 0;
}

int RGWRados::move_rados_obj(librados::IoCtx& src_ioctx,
			     const string& src_oid, const string& src_locator,
		             librados::IoCtx& dst_ioctx,
			     const string& dst_oid, const string& dst_locator)
{

#define COPY_BUF_SIZE (4 * 1024 * 1024)
  bool done = false;
  uint64_t chunk_size = COPY_BUF_SIZE;
  uint64_t ofs = 0;
  int ret = 0;
  real_time mtime;
  struct timespec mtime_ts;
  uint64_t size;

  if (src_oid == dst_oid && src_locator == dst_locator) {
    return 0;
  }

  src_ioctx.locator_set_key(src_locator);
  dst_ioctx.locator_set_key(dst_locator);

  do {
    bufferlist data;
    ObjectReadOperation rop;
    ObjectWriteOperation wop;

    if (ofs == 0) {
      rop.stat2(&size, &mtime_ts, NULL);
      mtime = real_clock::from_timespec(mtime_ts);
    }
    rop.read(ofs, chunk_size, &data, NULL);
    ret = src_ioctx.operate(src_oid, &rop, NULL);
    if (ret < 0) {
      goto done_err;
    }

    if (data.length() == 0) {
      break;
    }

    if (ofs == 0) {
      wop.create(true); /* make it exclusive */
      wop.mtime2(&mtime_ts);
      mtime = real_clock::from_timespec(mtime_ts);
    }
    wop.write(ofs, data);
    ret = dst_ioctx.operate(dst_oid, &wop);
    if (ret < 0) {
      goto done_err;
    }
    ofs += data.length();
    done = data.length() != chunk_size;
  } while (!done);

  if (ofs != size) {
    lderr(cct) << "ERROR: " << __func__ << ": copying " << src_oid << " -> " << dst_oid
               << ": expected " << size << " bytes to copy, ended up with " << ofs << dendl;
    ret = -EIO;
    goto done_err;
  }

  src_ioctx.remove(src_oid);

  return 0;

done_err:
  // TODO: clean up dst_oid if we created it
  lderr(cct) << "ERROR: failed to copy " << src_oid << " -> " << dst_oid << dendl;
  return ret;
}

/*
 * fixes an issue where head objects were supposed to have a locator created, but ended
 * up without one
 */
int RGWRados::fix_tail_obj_locator(const RGWBucketInfo& bucket_info, rgw_obj_key& key, bool fix, bool *need_fix)
{
  const rgw_bucket& bucket = bucket_info.bucket;
  rgw_obj obj(bucket, key);

  if (need_fix) {
    *need_fix = false;
  }

  rgw_rados_ref ref;
  int r = get_obj_head_ref(bucket_info, obj, &ref);
  if (r < 0) {
    return r;
  }

  RGWObjState *astate = NULL;
  RGWObjectCtx rctx(this);
  r = get_obj_state(&rctx, bucket_info, obj, &astate, false);
  if (r < 0)
    return r;

  if (astate->has_manifest) {
    RGWObjManifest::obj_iterator miter;
    RGWObjManifest& manifest = astate->manifest;
    for (miter = manifest.obj_begin(); miter != manifest.obj_end(); ++miter) {
      rgw_raw_obj raw_loc = miter.get_location().get_raw_obj(this);
      rgw_obj loc;
      string oid;
      string locator;

      rgw_raw_obj_to_obj(manifest.get_tail_placement().bucket, raw_loc, &loc);

      if (loc.key.ns.empty()) {
	/* continue, we're only interested in tail objects */
	continue;
      }

      get_obj_bucket_and_oid_loc(loc, oid, locator);
      ref.ioctx.locator_set_key(locator);

      ldout(cct, 20) << __func__ << ": key=" << key << " oid=" << oid << " locator=" << locator << dendl;

      r = ref.ioctx.stat(oid, NULL, NULL);
      if (r != -ENOENT) {
	continue;
      }

      string bad_loc;
      prepend_bucket_marker(bucket, loc.key.name, bad_loc);

      /* create a new ioctx with the bad locator */
      librados::IoCtx src_ioctx;
      src_ioctx.dup(ref.ioctx);
      src_ioctx.locator_set_key(bad_loc);

      r = src_ioctx.stat(oid, NULL, NULL);
      if (r != 0) {
	/* cannot find a broken part */
	continue;
      }
      ldout(cct, 20) << __func__ << ": found bad object part: " << loc << dendl;
      if (need_fix) {
        *need_fix = true;
      }
      if (fix) {
        r = move_rados_obj(src_ioctx, oid, bad_loc, ref.ioctx, oid, locator);
        if (r < 0) {
          lderr(cct) << "ERROR: copy_rados_obj() on oid=" << oid << " returned r=" << r << dendl;
        }
      }
    }
  }

  return 0;
}

int RGWRados::BucketShard::init(const rgw_bucket& _bucket,
				const rgw_obj& obj,
				RGWBucketInfo* bucket_info_out)
{
  bucket = _bucket;

  RGWObjectCtx obj_ctx(store);

  RGWBucketInfo bucket_info;
  RGWBucketInfo* bucket_info_p =
    bucket_info_out ? bucket_info_out : &bucket_info;
  
  int ret = store->get_bucket_instance_info(obj_ctx, bucket, *bucket_info_p, NULL, NULL);
  if (ret < 0) {
    return ret;
  }

  ret = store->open_bucket_index_shard(*bucket_info_p, index_ctx, obj.get_hash_object(), &bucket_obj, &shard_id);
  if (ret < 0) {
    ldout(store->ctx(), 0) << "ERROR: open_bucket_index_shard() returned ret=" << ret << dendl;
    return ret;
  }
  ldout(store->ctx(), 20) << " bucket index object: " << bucket_obj << dendl;

  return 0;
}

int RGWRados::BucketShard::init(const rgw_bucket& _bucket,
				int sid,
				RGWBucketInfo* bucket_info_out)
{
  bucket = _bucket;
  shard_id = sid;

  RGWObjectCtx obj_ctx(store);

  RGWBucketInfo bucket_info;
  RGWBucketInfo* bucket_info_p =
    bucket_info_out ? bucket_info_out : &bucket_info;
  int ret = store->get_bucket_instance_info(obj_ctx, bucket, *bucket_info_p, NULL, NULL);
  if (ret < 0) {
    return ret;
  }

  ret = store->open_bucket_index_shard(*bucket_info_p, index_ctx, shard_id, &bucket_obj);
  if (ret < 0) {
    ldout(store->ctx(), 0) << "ERROR: open_bucket_index_shard() returned ret=" << ret << dendl;
    return ret;
  }
  ldout(store->ctx(), 20) << " bucket index object: " << bucket_obj << dendl;

  return 0;
}

int RGWRados::BucketShard::init(const RGWBucketInfo& bucket_info, int sid)
{
  bucket = bucket_info.bucket;
  shard_id = sid;

  int ret = store->open_bucket_index_shard(bucket_info, index_ctx, shard_id, &bucket_obj);
  if (ret < 0) {
    ldout(store->ctx(), 0) << "ERROR: open_bucket_index_shard() returned ret=" << ret << dendl;
    return ret;
  }
  ldout(store->ctx(), 20) << " bucket index object: " << bucket_obj << dendl;

  return 0;
}


/* Execute @handler on last item in bucket listing for bucket specified
 * in @bucket_info. @obj_prefix and @obj_delim narrow down the listing
 * to objects matching these criterias. */
int RGWRados::on_last_entry_in_listing(RGWBucketInfo& bucket_info,
                                       const std::string& obj_prefix,
                                       const std::string& obj_delim,
                                       std::function<int(const rgw_bucket_dir_entry&)> handler)
{
  RGWRados::Bucket target(this, bucket_info);
  RGWRados::Bucket::List list_op(&target);

  list_op.params.prefix = obj_prefix;
  list_op.params.delim = obj_delim;

  ldout(cct, 20) << "iterating listing for bucket=" << bucket_info.bucket.name
                 << ", obj_prefix=" << obj_prefix
                 << ", obj_delim=" << obj_delim
                 << dendl;

  bool is_truncated = false;

  boost::optional<rgw_bucket_dir_entry> last_entry;
  /* We need to rewind to the last object in a listing. */
  do {
    /* List bucket entries in chunks. */
    static constexpr int MAX_LIST_OBJS = 100;
    std::vector<rgw_bucket_dir_entry> entries(MAX_LIST_OBJS);

    int ret = list_op.list_objects(MAX_LIST_OBJS, &entries, nullptr,
                                   &is_truncated);
    if (ret < 0) {
      return ret;
    } else if (!entries.empty()) {
      last_entry = entries.back();
    }
  } while (is_truncated);

  if (last_entry) {
    return handler(*last_entry);
  }

  /* Empty listing - no items we can run handler on. */
  return 0;
}


int RGWRados::swift_versioning_copy(RGWObjectCtx& obj_ctx,
                                    const rgw_user& user,
                                    RGWBucketInfo& bucket_info,
                                    rgw_obj& obj,
                                    RGWQuotaInfo& user_quota,
                                    RGWQuotaInfo& bucket_quota)
{
  if (! swift_versioning_enabled(bucket_info)) {
    return 0;
  }

  ldout(cct, 10) << "enable swift versioning" << dendl;
  obj_ctx.obj.set_atomic(obj);

  RGWObjState * state = nullptr;
  int r = get_obj_state(&obj_ctx, bucket_info, obj, &state, false);
  if (r < 0) {
    return r;
  }

  if (!state->exists) {
    return 0;
  }

  string client_id;
  string op_id;

  const string& src_name = obj.get_oid();
  char buf[src_name.size() + 32];
  struct timespec ts = ceph::real_clock::to_timespec(state->mtime);
  snprintf(buf, sizeof(buf), "%03x%s/%lld.%06ld", (int)src_name.size(),
           src_name.c_str(), (long long)ts.tv_sec, ts.tv_nsec / 1000);

  RGWBucketInfo dest_bucket_info;

  r = get_bucket_info(obj_ctx, bucket_info.bucket.tenant, bucket_info.swift_ver_location, dest_bucket_info, NULL, NULL);
  if (r < 0) {
    ldout(cct, 10) << "failed to read dest bucket info: r=" << r << dendl;
    if (r == -ENOENT) {
      return -ERR_PRECONDITION_FAILED;
    }
    return r;
  }

  if (dest_bucket_info.owner != bucket_info.owner) {
    return -ERR_PRECONDITION_FAILED;
  }

  rgw_obj dest_obj(dest_bucket_info.bucket, buf);

  if (dest_bucket_info.versioning_enabled()){
    gen_rand_obj_instance_name(&dest_obj);
  }

  obj_ctx.obj.set_atomic(dest_obj);

  string no_zone;

  r = copy_obj(obj_ctx,
               user,
               client_id,
               op_id,
               NULL, /* req_info *info */
               no_zone,
               dest_obj,
               obj,
               dest_bucket_info,
               bucket_info,
               bucket_info.head_placement_rule,
               NULL, /* time_t *src_mtime */
               NULL, /* time_t *mtime */
               NULL, /* const time_t *mod_ptr */
               NULL, /* const time_t *unmod_ptr */
               false, /* bool high_precision_time */
               NULL, /* const char *if_match */
               NULL, /* const char *if_nomatch */
               NULL, /*const char *md_directive */
               RGWRados::ATTRSMOD_NONE,
               true, /* bool copy_if_newer */
               state->attrset,
               RGW_OBJ_CATEGORY_MAIN,
               0, /* uint64_t olh_epoch */
               real_time(), /* time_t delete_at */
               NULL, /* string *version_id */
               NULL, /* string *ptag */
               NULL, /* string *petag */
               NULL, /* void (*progress_cb)(off_t, void *) */
               NULL, /* void *progress_data */
               user_quota,
               bucket_quota);
  if (r == -ECANCELED || r == -ENOENT) {
    /* Has already been overwritten, meaning another rgw process already
     * copied it out */
    return 0;
  }

  return r;
}

int RGWRados::swift_versioning_restore(RGWObjectCtx& obj_ctx,
                                       const rgw_user& user,
                                       RGWBucketInfo& bucket_info,
                                       rgw_obj& obj,
                                       bool& restored,             /* out */
                                       RGWQuotaInfo& user_quota,
                                       RGWQuotaInfo& bucket_quota)
{
  if (! swift_versioning_enabled(bucket_info)) {
    return 0;
  }

  /* Bucket info of the bucket that stores previous versions of our object. */
  RGWBucketInfo archive_binfo;

  int ret = get_bucket_info(obj_ctx, bucket_info.bucket.tenant,
                            bucket_info.swift_ver_location, archive_binfo,
                            nullptr, nullptr);
  if (ret < 0) {
    return ret;
  }

  /* Abort the operation if the bucket storing our archive belongs to someone
   * else. This is a limitation in comparison to Swift as we aren't taking ACLs
   * into consideration. For we can live with that.
   *
   * TODO: delegate this check to un upper layer and compare with ACLs. */
  if (bucket_info.owner != archive_binfo.owner) {
    return -EPERM;
  }

  /* This code will be executed on latest version of the object. */
  const auto handler = [&](const rgw_bucket_dir_entry& entry) -> int {
    std::string no_client_id;
    std::string no_op_id;
    std::string no_zone;

    /* We don't support object versioning of Swift API on those buckets that
     * are already versioned using the S3 mechanism. This affects also bucket
     * storing archived objects. Otherwise the delete operation would create
     * a deletion marker. */
    if (archive_binfo.versioned()) {
      restored = false;
      return -ERR_PRECONDITION_FAILED;
    }

    /* We are requesting ATTRSMOD_NONE so the attr attribute is perfectly
     * irrelevant and may be safely skipped. */
    std::map<std::string, ceph::bufferlist> no_attrs;

    rgw_obj archive_obj(archive_binfo.bucket, entry.key);

    if (bucket_info.versioning_enabled()){
      gen_rand_obj_instance_name(&obj);
    }

    obj_ctx.obj.set_atomic(archive_obj);
    obj_ctx.obj.set_atomic(obj);

    int ret = copy_obj(obj_ctx,
                       user,
                       no_client_id,
                       no_op_id,
                       nullptr,       /* req_info *info */
                       no_zone,
                       obj,           /* dest obj */
                       archive_obj,   /* src obj */
                       bucket_info,   /* dest bucket info */
                       archive_binfo, /* src bucket info */
                       bucket_info.head_placement_rule,
                       nullptr,       /* time_t *src_mtime */
                       nullptr,       /* time_t *mtime */
                       nullptr,       /* const time_t *mod_ptr */
                       nullptr,       /* const time_t *unmod_ptr */
                       false,         /* bool high_precision_time */
                       nullptr,       /* const char *if_match */
                       nullptr,       /* const char *if_nomatch */
                       nullptr,       /*const char *md_directive */
                       RGWRados::ATTRSMOD_NONE,
                       true,          /* bool copy_if_newer */
                       no_attrs,
                       RGW_OBJ_CATEGORY_MAIN,
                       0,             /* uint64_t olh_epoch */
                       real_time(),   /* time_t delete_at */
                       nullptr,       /* string *version_id */
                       nullptr,       /* string *ptag */
                       nullptr,       /* string *petag */
                       nullptr,       /* void (*progress_cb)(off_t, void *) */
                       nullptr,      /* void *progress_data */
                       user_quota,
                       bucket_quota);
    if (ret == -ECANCELED || ret == -ENOENT) {
      /* Has already been overwritten, meaning another rgw process already
       * copied it out */
      return 0;
    } else if (ret < 0) {
      return ret;
    } else {
      restored = true;
    }

    /* Need to remove the archived copy. */
    ret = delete_obj(obj_ctx, archive_binfo, archive_obj,
                     archive_binfo.versioning_status(), false);

    return ret;
  };

  const std::string& obj_name = obj.get_oid();
  const auto prefix = boost::str(boost::format("%03x%s") % obj_name.size()
                                                         % obj_name);

  return on_last_entry_in_listing(archive_binfo, prefix, std::string(),
                                  handler);
}

int RGWRados::Object::Write::_do_write_meta(uint64_t size, uint64_t accounted_size,
                                           map<string, bufferlist>& attrs,
                                           bool assume_noent, bool modify_tail,
                                           void *_index_op, void *_namespace_op, off_t ofs)
{

  RGWRados::Bucket::UpdateIndex *index_op = static_cast<RGWRados::Bucket::UpdateIndex *>(_index_op);
  RGWRados::Bucket::Namespace *namespace_op = nullptr;
  if (_namespace_op != nullptr) {
      namespace_op = static_cast<RGWRados::Bucket::Namespace *>(_namespace_op);
  }

  RGWRados *store = target->get_store();

  ObjectWriteOperation op;
  const struct req_state* s = get_req_state();
#ifdef WITH_LTTNG
  string req_id;
  if (!s) {
    // fake req_id
    req_id = store->unique_id(store->get_new_req_id());
  } else {
    req_id = s->req_id;
  }
#endif

  RGWObjState *state;
  int r = target->get_state(&state, false, assume_noent);
  if (r < 0)
    return r;

  rgw_obj& obj = target->get_obj();

  if (obj.get_oid().empty()) {
    ldout(store->ctx(), 0) << "ERROR: " << __func__ << "(): cannot write object with empty name" << dendl;
    return -EIO;
  }

  // head data pool should be same as tail data pool for upload part
  rgw_rados_ref ref;
  r = store->get_obj_head_ref(meta.head_placement_rule, obj, &ref);
  if (r < 0)
    return r;

  bool is_olh = state->is_olh;

  bool reset_obj = (meta.flags & PUT_OBJ_CREATE) != 0;

  const string *ptag = meta.ptag;
  if (!ptag && !index_op->get_optag()->empty()) {
    ptag = index_op->get_optag();
  }
  r = target->prepare_atomic_modification(op, reset_obj, ptag, meta.if_match, meta.if_nomatch, false, modify_tail);
  if (r < 0) {
    return r;
  }

  if (real_clock::is_zero(meta.set_mtime)) {
    meta.set_mtime = real_clock::now();
  }

  if (target->bucket_info.obj_lock_enabled() && target->bucket_info.obj_lock.has_rule() && meta.flags == PUT_OBJ_CREATE) {
    auto iter = attrs.find(RGW_ATTR_OBJECT_RETENTION);
    if (iter == attrs.end()) {
      real_time lock_until_date = target->bucket_info.obj_lock.get_lock_until_date(meta.set_mtime);
      string mode = target->bucket_info.obj_lock.get_mode();
      RGWObjectRetention obj_retention(mode, lock_until_date);
      bufferlist bl;
      obj_retention.encode(bl);
      op.setxattr(RGW_ATTR_OBJECT_RETENTION, bl);
    }
  }

  if (state->is_olh) {
    op.setxattr(RGW_ATTR_OLH_ID_TAG, state->olh_tag);
  }

  struct timespec mtime_ts = real_clock::to_timespec(meta.set_mtime);
  op.mtime2(&mtime_ts);

  if (meta.unmod_time) {
    store->cls_obj_check_mtime(op, *meta.unmod_time, true, CLS_RGW_CHECK_TIME_MTIME_LE);
  }

  if (meta.data) {
    if (ofs == -1) {
      /* if we want to overwrite the data, we also want to overwrite the
         xattrs, so just remove the object */
      op.write_full(*meta.data);
    } else if (ofs >= 0) {
      op.write(uint64_t(ofs), *meta.data);
    }
  }

  string etag;
  string content_type;
  bufferlist acl_bl;

  map<string, bufferlist>::iterator iter;
  if (meta.rmattrs) {
    for (iter = meta.rmattrs->begin(); iter != meta.rmattrs->end(); ++iter) {
      const string& name = iter->first;
      op.rmxattr(name.c_str());
    }
  }

  if (meta.manifest) {
    /* remove existing manifest attr */
    iter = attrs.find(RGW_ATTR_MANIFEST);
    if (iter != attrs.end())
      attrs.erase(iter);

    bufferlist bl;
    encode(*meta.manifest, bl);
    op.setxattr(RGW_ATTR_MANIFEST, bl);
  }

  for (iter = attrs.begin(); iter != attrs.end(); ++iter) {
    const string& name = iter->first;
    bufferlist& bl = iter->second;

    if (!bl.length())
      continue;
    op.setxattr(name.c_str(), bl);

    if (name.compare(RGW_ATTR_ETAG) == 0) {
      etag = rgw_bl_to_str(bl);
    } else if (name.compare(RGW_ATTR_CONTENT_TYPE) == 0) {
      content_type = rgw_bl_to_str(bl);
    } else if (name.compare(RGW_ATTR_ACL) == 0) {
      acl_bl = bl;
    }
  }
  if (attrs.find(RGW_ATTR_PG_VER) == attrs.end()) {
    cls_rgw_obj_store_pg_ver(op, RGW_ATTR_PG_VER);
  }

  if (attrs.find(RGW_ATTR_SOURCE_ZONE) == attrs.end()) {
    bufferlist bl;
    encode(store->get_zone_short_id(), bl);
    op.setxattr(RGW_ATTR_SOURCE_ZONE, bl);
  }

  if (!meta.storage_class.empty()) {
    bufferlist bl;
    bl.append(meta.storage_class);
    op.setxattr(RGW_ATTR_STORAGE_CLASS, bl);
  }

  if (!op.size())
    return 0;

  uint64_t epoch;
  int64_t poolid;
  bool orig_exists;
  uint64_t orig_size;

  if (!reset_obj) {    //Multipart upload, it has immutable head. 
    orig_exists = false;
    orig_size = 0;
  } else {
    orig_exists = state->exists;
    orig_size = state->accounted_size;
  }

  bool versioned_target = (meta.olh_epoch && *meta.olh_epoch > 0) ||
                          !obj.key.instance.empty();

  bool versioned_op = (target->versioning_enabled() || is_olh || versioned_target);

  if (versioned_op) {
    index_op->set_bilog_flags(RGW_BILOG_FLAG_VERSIONED_OP);
  }

  if (!index_op->is_prepared()) {
    tracepoint(rgw_rados, prepare_enter, req_id.c_str());
    r = index_op->prepare(CLS_RGW_OP_ADD, &state->write_tag);
    tracepoint(rgw_rados, prepare_exit, req_id.c_str());
    if (s) {
      perfcounter->tinc(l_rgw_put_prepare_index, s->time_elapsed());
    }
    if (r < 0) {
      return r;
    }
  }

  if (namespace_op && !namespace_op->is_prepared()) {
    r = namespace_op->prepare(s, CLS_RGW_OP_ADD, &state->write_tag, meta.set_mtime);
    if (s) {
      perfcounter->tinc(l_rgw_put_prepare_namespace, s->time_elapsed());
    }
    if (r < 0) {
      ldout(store->ctx(), 0) << __func__ << " ERROR: namespace prepare ret =" << r
                             << " " << namespace_op->get_obj() << dendl;
      if (r == -EEXIST) {
        // have the same name directory
        r = -ERR_KEY_EXIST;
      }
      return r;
    }
  }

  tracepoint(rgw_rados, operate_enter, req_id.c_str());
  r = ref.ioctx.operate(ref.oid, &op, skip_cache);
  tracepoint(rgw_rados, operate_exit, req_id.c_str());
  if (s) {
    perfcounter->tinc(l_rgw_put_head_meta, s->time_elapsed());
  }

  if (r < 0) { /* we can expect to get -ECANCELED if object was replaced under,
                or -ENOENT if was removed, or -EEXIST if it did not exist
                before and now it does */
    if (r == -EEXIST && assume_noent) {
      target->invalidate_state();
      return r;
    }
    goto done_cancel;
  }
  epoch = ref.ioctx.get_last_version();
  poolid = ref.ioctx.get_id();

  r = target->complete_atomic_modification();
  if (r < 0) {
    ldout(store->ctx(), 0) << "ERROR: complete_atomic_modification returned r=" << r << dendl;
  }

  if (namespace_op) {
    r = namespace_op->complete(poolid, epoch, size, meta.set_mtime, meta.appendable);
    if (s) {
      perfcounter->tinc(l_rgw_put_complete_namespce, s->time_elapsed());
    }
    if (r < 0) {
      ldout(store->ctx(), 0) << __func__ << " ERROR: namespace complete "
                             << namespace_op->get_obj() << " ret=" << r << dendl;
      if (r == -EEXIST) {
        // have the same name directory
        r = -ERR_KEY_EXIST;
      }
      perfcounter->inc(l_rgw_put_complete_namespce_cancel);
      goto done_cancel;
    }
  }

  tracepoint(rgw_rados, complete_enter, req_id.c_str());
  r = index_op->complete(poolid, epoch, size, accounted_size,
                         meta.set_mtime, etag, content_type, &acl_bl,
                         meta.category, meta.remove_objs,
                         meta.storage_class, meta.user_data, meta.accounted_entry,
                         meta.appendable, meta.tags_bl);
  tracepoint(rgw_rados, complete_exit, req_id.c_str());
  if (s) {
    perfcounter->tinc(l_rgw_put_complete_index, s->time_elapsed());
  }
  if (r < 0) {
    goto done_cancel;
  }

  if (meta.mtime) {
    *meta.mtime = meta.set_mtime;
  }
  /* note that index_op was using state so we couldn't invalidate it earlier */
  target->invalidate_state();
  state = NULL;
  if (versioned_op && meta.olh_epoch) {
    r = store->set_olh(target->get_ctx(), target->get_bucket_info(), obj, false,
                       NULL, *meta.olh_epoch, real_time(), false, meta.zones_trace,
                       false, meta.is_transition);
    if (r < 0) {
      return r;
    }
  }
  if (!real_clock::is_zero(meta.delete_at)) {
    rgw_obj_index_key obj_key;
    obj.key.get_index_key(&obj_key);

    r = store->objexp_hint_add(meta.delete_at,
            obj.bucket.tenant, obj.bucket.name, obj.bucket.bucket_id, obj_key);
    if (r < 0) {
      ldout(store->ctx(), 0) << "ERROR: objexp_hint_add() returned r=" << r << ", object will not get removed" << dendl;
      /* ignoring error, nothing we can do at this point */
    }
  }
  meta.canceled = false;
  /* update quota cache */
  if (meta.completeMultipart) {
  	store->quota_handler->update_stats(meta.owner, obj.bucket, (orig_exists ? 0 : 1), 0, orig_size);
  }
  else {
    if (meta.accounted_entry) {
      store->quota_handler->update_stats(meta.owner, obj.bucket, (orig_exists ? 0 : 1), accounted_size, orig_size);
    } else {
        store->quota_handler->update_stats(meta.owner, obj.bucket, 0, accounted_size, orig_size);
    }
  }
  return 0;

done_cancel:
  ldout(store->ctx(), 20) << __func__ << " start do cancel" << dendl;
  int ret = index_op->cancel();
  if (ret < 0) {
    ldout(store->ctx(), 0) << "ERROR: index_op.cancel()() returned ret=" << ret << dendl;
  }

  if (namespace_op) {
    ret = namespace_op->cancel();
    if (ret < 0) {
      ldout(store->ctx(), 0) << "ERROR: namespace_op.cancel()() returned ret=" << ret << dendl;
    }
  }

  meta.canceled = true;
  /* we lost in a race. There are a few options:
   * - existing object was rewritten (ECANCELED)
   * - non existing object was created (EEXIST)
   * - object was removed (ENOENT)
   * should treat it as a success
   */
  if (meta.if_match == NULL && meta.if_nomatch == NULL) {
    if (r == -ECANCELED || r == -ENOENT || r == -EEXIST) {
      r = 0;
    }
  } else {
    if (meta.if_match != NULL) {
      // only overwrite existing object
      if (strcmp(meta.if_match, "*") == 0) {
        if (r == -ENOENT) {
          r = -ERR_PRECONDITION_FAILED;
        } else if (r == -ECANCELED) {
          r = 0;
        }
      }
    }
    if (meta.if_nomatch != NULL) {
      // only create a new object
      if (strcmp(meta.if_nomatch, "*") == 0) {
        if (r == -EEXIST) {
          r = -ERR_PRECONDITION_FAILED;
        } else if (r == -ENOENT) {
          r = 0;
        }
      }
    }
  }
  return r;
}

int RGWRados::Object::Write::write_meta(uint64_t size, uint64_t accounted_size,
                                        map<string, bufferlist>& attrs, off_t ofs)
{
  RGWBucketInfo& bucket_info = target->get_bucket_info();

  RGWRados::Bucket bop(target->get_store(), bucket_info);
  RGWRados::Bucket::UpdateIndex index_op(&bop, target->get_obj());
  index_op.set_zones_trace(meta.zones_trace);
  RGWRados::Bucket::Namespace namespace_op(&bop, target->get_obj());

  bool assume_noent = (ofs == -1 && meta.if_match == NULL && meta.if_nomatch == NULL);
  int r = 0;
  if (assume_noent) {
    r = _do_write_meta(size, accounted_size, attrs, assume_noent, meta.modify_tail,
                       (void *)&index_op, (void *)&namespace_op);
    if (r == -EEXIST) {
      assume_noent = false;
    }
  }
  if (!assume_noent) {
    r = _do_write_meta(size, accounted_size, attrs, assume_noent, meta.modify_tail,
                       (void *)&index_op, (void *)&namespace_op, ofs);
  }
  return r;
}

int RGWRados::Object::Write::write_meta_without_namespace(uint64_t size, uint64_t accounted_size,
                                           map<string, bufferlist>& attrs, off_t ofs)
{
  RGWBucketInfo& bucket_info = target->get_bucket_info();

  RGWRados::Bucket bop(target->get_store(), bucket_info);
  RGWRados::Bucket::UpdateIndex index_op(&bop, target->get_obj());
  index_op.set_zones_trace(meta.zones_trace);
  index_op.set_bilog_write_enable(target->get_bilog_write_enable());
  index_op.set_bilog_delete_enable(target->get_bilog_delete_enable());

  bool assume_noent = (ofs == -1 && meta.if_match == NULL && meta.if_nomatch == NULL);
  int r = 0;
  if (assume_noent) {
    r = _do_write_meta(size, accounted_size, attrs, assume_noent, meta.modify_tail,
                       (void *)&index_op, nullptr);
    if (r == -EEXIST) {
      assume_noent = false;
    }
  }
  if (!assume_noent) {
    r = _do_write_meta(size, accounted_size, attrs, assume_noent, meta.modify_tail,
                       (void *)&index_op, nullptr, ofs);
  }
  return r;
}

/** Write/overwrite a system object. */
int RGWRados::put_system_obj_impl(rgw_raw_obj& obj, uint64_t size, real_time *mtime,
              map<std::string, bufferlist>& attrs, int flags,
              const bufferlist& data,
              RGWObjVersionTracker *objv_tracker,
              real_time set_mtime /* 0 for don't set */)
{
  rgw_rados_ref ref;
  int r = get_system_obj_ref(obj, &ref);
  if (r < 0)
    return r;

  ObjectWriteOperation op;

  if (flags & PUT_OBJ_EXCL) {
    if (!(flags & PUT_OBJ_CREATE))
	return -EINVAL;
    op.create(true); // exclusive create
  } else {
    op.remove();
    op.set_op_flags2(LIBRADOS_OP_FLAG_FAILOK);
    op.create(false);
  }

  if (objv_tracker) {
    objv_tracker->prepare_op_for_write(&op);
  }

  if (real_clock::is_zero(set_mtime)) {
    set_mtime = real_clock::now();
  }

  struct timespec mtime_ts = real_clock::to_timespec(set_mtime);
  op.mtime2(&mtime_ts);
  op.write_full(data);

  bufferlist acl_bl;

  for (map<string, bufferlist>::iterator iter = attrs.begin(); iter != attrs.end(); ++iter) {
    const string& name = iter->first;
    bufferlist& bl = iter->second;

    if (!bl.length())
      continue;

    op.setxattr(name.c_str(), bl);
  }

  r = ref.ioctx.operate(ref.oid, &op);
  if (r < 0) {
    return r;
  }

  if (objv_tracker) {
    objv_tracker->apply_write();
  }

  if (mtime) {
    *mtime = set_mtime;
  }

  return 0;
}

int RGWRados::put_system_obj_data(void *ctx, rgw_raw_obj& obj, const bufferlist& bl,
                                  off_t ofs, bool exclusive,
                                  RGWObjVersionTracker *objv_tracker)
{
  rgw_rados_ref ref;
  int r = get_system_obj_ref(obj, &ref);
  if (r < 0) {
    return r;
  }

  ObjectWriteOperation op;

  if (exclusive)
    op.create(true);

  if (objv_tracker) {
    objv_tracker->prepare_op_for_write(&op);
  }
  if (ofs == -1) {
    op.write_full(bl);
  } else {
    op.write(ofs, bl);
  }
  r = ref.ioctx.operate(ref.oid, &op);
  if (r < 0)
    return r;

  if (objv_tracker) {
    objv_tracker->apply_write();
  }
  return 0;
}

/**
 * Write/overwrite an object to the bucket storage.
 * bucket: the bucket to store the object in
 * obj: the object name/key
 * data: the object contents/value
 * offset: the offet to write to in the object
 *         If this is -1, we will overwrite the whole object.
 * size: the amount of data to write (data must be this long)
 * attrs: all the given attrs are written to bucket storage for the given object
 * Returns: 0 on success, -ERR# otherwise.
 */

int RGWRados::aio_put_obj_data(void *ctx, rgw_raw_obj& obj, bufferlist& bl,
                               off_t ofs, bool exclusive,
                               void **handle, bool skip_cache)
{
  rgw_rados_ref ref;
  int r = get_raw_obj_ref(obj, &ref);
  if (r < 0) {
    return r;
  }

  AioCompletion *c = librados::Rados::aio_create_completion(NULL, NULL, NULL);
  *handle = c;
  
  ObjectWriteOperation op;

  if (exclusive)
    op.create(true);

  if (ofs == -1) {
    op.write_full(bl);
  } else {
    op.write(ofs, bl);
  }

  r = ref.ioctx.aio_operate(ref.oid, c, &op, skip_cache ? librados::OPERATION_SKIP_CACHE:0);
  if (r < 0)
    return r;

  return 0;
}

int RGWRados::aio_wait(void *handle)
{
  AioCompletion *c = (AioCompletion *)handle;
  c->wait_for_safe();
  int ret = c->get_return_value();
  c->release();
  return ret;
}

bool RGWRados::aio_completed(void *handle)
{
  AioCompletion *c = (AioCompletion *)handle;
  return c->is_safe();
}

// PutObj filter that buffers data so we don't try to compress tiny blocks.
// libcurl reads in 16k at a time, and we need at least 64k to get a good
// compression ratio
class RGWPutObj_Buffer : public RGWPutObj_Filter {
  const unsigned buffer_size;
  bufferlist buffer;
 public:
  RGWPutObj_Buffer(RGWPutObjDataProcessor* next, unsigned buffer_size)
    : RGWPutObj_Filter(next), buffer_size(buffer_size) {
    assert(isp2(buffer_size)); // must be power of 2
  }

  int handle_data(bufferlist& bl, off_t ofs, void **phandle, rgw_raw_obj *pobj,
                  bool *again) override {
    if (*again || !bl.length()) {
      // flush buffered data
      return RGWPutObj_Filter::handle_data(buffer, ofs, phandle, pobj, again);
    }
    // transform offset to the beginning of the buffer
    ofs = ofs - buffer.length();
    buffer.claim_append(bl);
    if (buffer.length() < buffer_size) {
      *again = false; // don't come back until there's more data
      return 0;
    }
    const auto count = p2align(buffer.length(), buffer_size);
    buffer.splice(0, count, &bl);
    return RGWPutObj_Filter::handle_data(bl, ofs, phandle, pobj, again);
  }
};

class RGWRadosPutObj : public RGWHTTPStreamRWRequest::ReceiveCB
{
  CephContext* cct;
  rgw_obj obj;
  RGWPutObjDataProcessor *filter;
  boost::optional<RGWPutObj_Compress>& compressor;
  boost::optional<RGWPutObj_Buffer> buffering;
  CompressorRef& plugin;
  RGWPutObjProcessor_Atomic *processor;
  RGWOpStateSingleOp *opstate;
  void (*progress_cb)(off_t, void *);
  void *progress_data;
  bufferlist extra_data_bl;
  uint64_t extra_data_left;
  uint64_t data_len;
  map<string, bufferlist> src_attrs;
  off_t ofs{0};
  off_t lofs{0}; /* logical ofs */
  bool need_to_process_attrs{true};
  std::function<int(const map<string, bufferlist>&)> attrs_handler;
public:
  RGWRadosPutObj(CephContext* cct,
                 CompressorRef& plugin,
                 boost::optional<RGWPutObj_Compress>& compressor,
                 RGWPutObjProcessor_Atomic *p,
                 RGWOpStateSingleOp *_ops,
                 void (*_progress_cb)(off_t, void *),
                 void *_progress_data,
                 std::function<int(const map<string, bufferlist>&)> _attrs_handler) :
                       cct(cct),
                       filter(p),
                       compressor(compressor),
                       plugin(plugin),
                       processor(p),
                       opstate(_ops),
                       progress_cb(_progress_cb),
                       progress_data(_progress_data),
                       extra_data_left(0),
                       data_len(0),
                       attrs_handler(_attrs_handler) {}

  int process_attrs(void) {
    if (extra_data_bl.length()) {
      JSONParser jp;
      if (!jp.parse(extra_data_bl.c_str(), extra_data_bl.length())) {
        ldout(cct, 0) << "failed to parse response extra data. len=" << extra_data_bl.length() << " data=" << extra_data_bl.c_str() << dendl;
        return -EIO;
      }

      JSONDecoder::decode_json("attrs", src_attrs, &jp);

      src_attrs.erase(RGW_ATTR_COMPRESSION);
      src_attrs.erase(RGW_ATTR_MANIFEST); // not interested in original object layout

      // filter out olh attributes
      auto iter = src_attrs.lower_bound(RGW_ATTR_OLH_PREFIX);
      while (iter != src_attrs.end()) {
        if (!boost::algorithm::starts_with(iter->first, RGW_ATTR_OLH_PREFIX)) {
          break;
        }
        iter = src_attrs.erase(iter);
      }
    }

    int ret = attrs_handler(src_attrs);
    if (ret < 0) {
      return ret;
    }

    src_attrs.erase(RGW_ATTR_STORAGE_CLASS);
    if (plugin && src_attrs.find(RGW_ATTR_CRYPT_MODE) == src_attrs.end()) {
      //do not compress if object is encrypted
      compressor = boost::in_place(cct, plugin, filter);
      constexpr unsigned buffer_size = 512 * 1024;
      buffering = boost::in_place(&*compressor, buffer_size);
      filter = &*buffering;
    }

    need_to_process_attrs = false;

    return 0;
  }

  int handle_data(bufferlist& bl, bool *pause) override {
    if (progress_cb) {
      progress_cb(lofs, progress_data);
    }
    if (extra_data_left) {
      size_t extra_len = bl.length();
      if (extra_len > extra_data_left)
        extra_len = extra_data_left;

      bufferlist extra;
      bl.splice(0, extra_len, &extra);
      extra_data_bl.append(extra);

      extra_data_left -= extra_len;
      if (extra_data_left == 0) {
        int res = process_attrs();
        if (res < 0)
          return res;
      }
      ofs += extra_len;
      if (bl.length() == 0) {
        return 0;
      }
    }

    if (need_to_process_attrs) {
      /* need to call process_attrs() even if we don't get any attrs,
       * need it to call attrs_handler().
       */
      int res = process_attrs();
      if (res < 0) {
        return res;
      }
    }

    assert(uint64_t(ofs) >= extra_data_len);

    lofs = ofs - extra_data_len;

    data_len += bl.length();
    bool again = false;

    bool need_opstate = true;

    do {
      void *handle = NULL;
      rgw_raw_obj obj;
      uint64_t size = bl.length();
      int ret = filter->handle_data(bl, lofs, &handle, &obj, &again);
      if (ret < 0)
        return ret;

      ofs += size;

      if (need_opstate && opstate) {
        /* need to update opstate repository with new state. This is ratelimited, so we're not
         * really doing it every time
         */
        ret = opstate->renew_state();
        if (ret < 0) {
          ldout(cct, 0) << "ERROR: RGWRadosPutObj::handle_data(): failed to renew op state ret=" << ret << dendl;
          int r = filter->throttle_data(handle, obj, size, false);
          if (r < 0) {
            ldout(cct, 0) << "ERROR: RGWRadosPutObj::handle_data(): processor->throttle_data() returned " << r << dendl;
          }
          /* could not renew state! might have been marked as cancelled */
          return ret;
        }
        need_opstate = false;
      }

      ret = filter->throttle_data(handle, obj, size, false);
      if (ret < 0)
        return ret;
    } while (again);

    return 0;
  }

  int flush() {
    bufferlist bl;
    bool need_to_wait = false;
    return put_data_and_throttle(filter, bl, ofs, need_to_wait);
  }

  bufferlist& get_extra_data() { return extra_data_bl; }

  map<string, bufferlist>& get_attrs() { return src_attrs; }

  void set_extra_data_len(uint64_t len) override {
    extra_data_left = len;
    RGWHTTPStreamRWRequest::ReceiveCB::set_extra_data_len(len);
  }

  uint64_t get_data_len() {
    return data_len;
  }

  int complete(const string& etag, real_time *mtime, real_time set_mtime,
               map<string, bufferlist>& attrs, real_time delete_at, rgw_zone_set *zones_trace) {
    return processor->complete(data_len, etag, mtime, set_mtime, attrs, delete_at, NULL, NULL, NULL, zones_trace);
  }

  bool is_canceled() {
    return processor->is_canceled();
  }
};

class RGWRadosMirrorObj : public RGWHTTPStreamRWRequest::ReceiveCB
{
  req_state* s = nullptr;
  CephContext* cct = nullptr;
  rgw_obj obj;
  RGWPutObjDataProcessor *filter = nullptr;
  boost::optional<RGWPutObj_Buffer> buffering;
  RGWPutObjProcessor_Atomic *processor = nullptr;
  MD5* hash = nullptr;
  RGWGetDataCB* cb = nullptr;
  RGWRESTStreamRWRequest **req;
  bufferlist extra_data_bl;
  uint64_t extra_data_left{0};
  uint64_t data_len{0}; // response body length
  off_t ofs{0};
  bool header_processed{false};

  bufferlist data;
  bool paused = false;
  SyncPoint* sync = nullptr;
public:
  RGWRadosMirrorObj(req_state* s,
                    CephContext* cct,
                    RGWPutObjProcessor_Atomic *p,
                    MD5* hash,
                    RGWGetDataCB* cb,
                    RGWRESTStreamRWRequest **req) :
                       s(s),
                       cct(cct),
                       filter(p),
                       processor(p),
                       hash(hash),
                       cb(cb),
                       req(req) {
    data.clear();
#ifdef WITH_RADOSGW_BEAST_FRONTEND
    void **asio_ctx = (void **) s->asio_ctx;
    // with beast fronted
    if (asio_ctx) {
      sync = new SyncPoint(*((boost::asio::io_service *) asio_ctx[0]), *((boost::asio::yield_context *) asio_ctx[1]));
    }
#endif
  }

  ~RGWRadosMirrorObj() {
    if (sync)
      delete sync;
    // Now that don't call RGWRESTConn::complete_request, we need clear req self
    if (*req)
      delete *req;
  }

  void notify_async() override {
#ifdef WITH_RADOSGW_BEAST_FRONTEND
    // with beast fronted
    if (sync) {
      ldout(cct, 30) << __func__ << "() call notify finish" << dendl;
      sync->put(1);
    }
#endif
  }


  int handle_data(bufferlist& bl, bool *pause) override {
    ldout(cct, 30) << __func__ << "() receive source bl len:" << bl.length() << dendl;

    (*req)->inner_lock();
    data.append(bl);

    uint64_t len = data.length();
    ldout(cct, 30) << __func__ << "() total cache data len:" << len << dendl;

    if (!paused && len >= uint64_t(cct->_conf->rgw_mirror_data_window_size)) {
      *pause = true;
      paused = true;
      ldout(cct, 30) << __func__ << "() call notify data, data len:" << len << dendl;
#ifdef WITH_RADOSGW_BEAST_FRONTEND
      if (sync) {
        sync->put(0);
      } else
#endif
      {
        (*req)->notify_data();
      }
    }
    (*req)->unlock();
    return 0;
  }

  void unpause_recv() {
    bool need_to_unpause = false;
    (*req)->inner_lock();
    need_to_unpause = (paused && data.length() < cct->_conf->rgw_mirror_data_window_size);
    (*req)->unlock();
    if (need_to_unpause) {
      paused = false;
      (*req)->unpause_receive();
      ldout(cct, 30) << __func__ << "() unpause_receive" << dendl;
    }
  }

  void claim_data(bufferlist* dest, uint64_t max) {
    (*req)->inner_lock();
    if (data.length() == 0) {
      (*req)->unlock();
      return;
    }

    if (data.length() < max) {
      max = data.length();
    }

    data.splice(0, max, dest);
    (*req)->unlock();
  }

  int mirror_data() {
    int ret = 0;

    while (!(*req)->is_done()) {
#ifdef WITH_RADOSGW_BEAST_FRONTEND
      // with beast fronted
      if (sync) {
        while (data.length() < cct->_conf->rgw_mirror_data_window_size && !(*req)->is_done()) {
          ldout(cct, 30) << __func__ << "() data.length no enough, call sync get:" << data.length() << dendl;
          unpause_recv();
          int ret = sync->get();
          ldout(cct, 30) << __func__ << "() asio notified, sync get " << ret
                         << " data len:" << data.length()
                         << " req is_done:" << (*req)->is_done()
                         << dendl;
          void **asio_ctx = (void **) s->asio_ctx;
          // SyncPoint call only be used once, next time create new SyncPoint
          (*req)->inner_lock();
          delete sync;
          sync = nullptr;
          sync = new SyncPoint(*((boost::asio::io_service *) asio_ctx[0]), *((boost::asio::yield_context *) asio_ctx[1]));
          (*req)->unlock();
        }
      } else
#endif
      {
        (*req)->inner_lock();
        //_is_done doesn't call lock again
        while (data.length() < cct->_conf->rgw_mirror_data_window_size && !(*req)->_is_done()) {
          ldout(cct, 30) << __func__ << "() data.length no enough, wait_for_data_or_done:" << data.length()  << dendl;
          (*req)->wait_for_data_or_done();
          ldout(cct, 30) << __func__ << "() cond_wait notified"
                         << " data len:" << data.length()
                         << " req is_done:" << (*req)->_is_done()
                         << dendl;
        }
        (*req)->unlock();
      }

      if (!header_processed) {
        if (!(*req)) {
          return -EINTR;
        }
        if ((*req)->get_http_status() >= 400) {
          ldout(cct, 30) << __func__ << "() ERROR: mirror source http status:"
                         << (*req)->get_http_status() << dendl;
          if ((*req)->get_http_status() == 403) {
            ret = -ERR_MIRROR_SOURCE_DENY;
          } else if ((*req)->get_http_status() == 404) {
            ret = -ENOENT;
          } else {
            ret = -ERR_MIRROR_FAILED;
          }
          static_cast<RGWGetObj_CB*>(cb)->send_response_error(ret);
          return ret;
        }
        header_processed = true;
      }

      bufferlist bl;
      claim_data(&bl, cct->_conf->rgw_mirror_data_window_size);
      ldout(cct, 30) << __func__ << "() claimed data len:" << bl.length()   << dendl;

      // TODO: wanghao72
      // After chase beast fronted to github, make read_ahead before send to client
      // and store local for beast. Nowadays, unpause before sync->get().
#ifdef WITH_RADOSGW_BEAST_FRONTEND
      // with beast fronted
      if (!sync) {
        unpause_recv();
      }
#else
      {
        unpause_recv();
      }
#endif

      if (!bl.length()) {
        continue;
      }
      ret = process_data(bl);
      if (ret < 0) {
        return ret;
      }
    }
    // consume remain data, which length less than cct->_conf->rgw_mirror_data_window_size
    if (data.length()) {
      ret = process_data(data);
      if (ret < 0)
        return ret;
    }
    ret = (*req)->get_req_retcode();
    return ret;
  }

  int process_data(bufferlist& bl) {
    int ret = 0;
    if (hash)
      hash->Update(reinterpret_cast<const unsigned char*>(bl.c_str()), bl.length());

    ret = cb->handle_data(bl, 0, bl.length());    // send to client
    if (ret < 0) {
      ldout(cct, 0) << __func__ << " send to client err:" << ret << dendl;
      (*req)->cancel();
      return ret;
    }

    data_len += bl.length();

    /**
     * Range request, no need store local this time.
     * Async store total data in next RGWRESTConn::get_obj()
     */
    if (!filter)
      return 0;

    bool again = false;

    do {
      void *handle = NULL;
      rgw_raw_obj obj;
      uint64_t size = bl.length();
      ldout(cct, 20) << __func__ << " call filter handle_data bl len:" << bl.length()
                     << ", ofs:" << ofs << dendl;
      ret = filter->handle_data(bl, ofs, &handle, &obj, &again);
      if (ret < 0) {
        ldout(cct, 10) << __func__ << " store data to local err:" << ret << dendl;
        return ret;
      }

      ofs += size;

      ret = filter->throttle_data(handle, obj, size, false);
      if (ret < 0) {
        ldout(cct, 10) << __func__ << " throttle_data err:" << ret << dendl;
        return ret;
      }
    } while (again);
    return 0;
  }

  int flush() {
    bufferlist bl;
    bool bool_false = false;
    return put_data_and_throttle(filter, bl, ofs, bool_false);
  }

  bufferlist& get_extra_data() { return extra_data_bl; }

  map<string, bufferlist>& get_attrs() {
    return static_cast<RGWGetObj_CB*>(cb)->get_attrs();
  }

  void set_extra_data_len(uint64_t len) override {
    extra_data_left = len;
    RGWHTTPStreamRWRequest::ReceiveCB::set_extra_data_len(len);
    static_cast<RGWGetObj_CB*>(cb)->set_content_length(len);
  }

  uint64_t get_data_len() {
    return data_len;
  }

  int complete(const string& etag, real_time *mtime, real_time set_mtime,
               map<string, bufferlist>& attrs, real_time delete_at, rgw_zone_set *zones_trace) {
    if (extra_data_len != data_len) {
      ldout(cct, 10) << __func__ << " supplied_content_length:" << extra_data_len
                     << " not equal to actual data len:" << data_len
                     << dendl;
    }
    if (processor)
      return processor->complete(data_len, etag, mtime, set_mtime, attrs, delete_at, NULL, NULL, NULL, zones_trace);
    else
      return 0;
  }

  void set_attr(const string& key, const string& val) override {
    static_cast<RGWGetObj_CB*>(cb)->set_attr(key, val);
  }
  void set_chunk() override {
    static_cast<RGWGetObj_CB*>(cb)->set_chunk();
  }
};

/*
 * prepare attrset depending on attrs_mod.
 */
static void set_copy_attrs(map<string, bufferlist>& src_attrs,
                           map<string, bufferlist>& attrs,
                           RGWRados::AttrsMod attrs_mod)
{
  switch (attrs_mod) {
  case RGWRados::ATTRSMOD_NONE:
    attrs = src_attrs;
    break;
  case RGWRados::ATTRSMOD_REPLACE:
    if (!attrs[RGW_ATTR_ETAG].length()) {
      attrs[RGW_ATTR_ETAG] = src_attrs[RGW_ATTR_ETAG];
    }
    if (!attrs[RGW_ATTR_TAIL_TAG].length()) {
      auto ttiter = src_attrs.find(RGW_ATTR_TAIL_TAG);
      if (ttiter != src_attrs.end()) {
        attrs[RGW_ATTR_TAIL_TAG] = src_attrs[RGW_ATTR_TAIL_TAG];
      }
    }
    break;
  case RGWRados::ATTRSMOD_MERGE:
    for (map<string, bufferlist>::iterator it = src_attrs.begin(); it != src_attrs.end(); ++it) {
      if (attrs.find(it->first) == attrs.end()) {
       attrs[it->first] = it->second;
      }
    }
    break;
  }
}

int RGWRados::rewrite_obj(RGWBucketInfo& dest_bucket_info, rgw_obj& obj)
{
  map<string, bufferlist> attrset;

  real_time mtime;
  uint64_t obj_size;
  RGWObjectCtx rctx(this);

  RGWRados::Object op_target(this, dest_bucket_info, rctx, obj);
  RGWRados::Object::Read read_op(&op_target);

  read_op.params.attrs = &attrset;
  read_op.params.lastmod = &mtime;
  read_op.params.obj_size = &obj_size;

  int ret = read_op.prepare();
  if (ret < 0)
    return ret;

  attrset.erase(RGW_ATTR_ID_TAG);
  attrset.erase(RGW_ATTR_TAIL_TAG);

  return copy_obj_data(rctx, dest_bucket_info, dest_bucket_info.head_placement_rule,
                       read_op, obj_size - 1, obj, NULL, mtime, attrset,
                       0, real_time(),
                       (obj.key.instance.empty() ? NULL : &(obj.key.instance)),
                       NULL);
}

struct obj_time_weight {
  real_time mtime;
  uint32_t zone_short_id;
  uint64_t pg_ver;
  bool high_precision;

  obj_time_weight() : zone_short_id(0), pg_ver(0), high_precision(false) {}

  bool compare_low_precision(const obj_time_weight& rhs) {
    struct timespec l = ceph::real_clock::to_timespec(mtime);
    struct timespec r = ceph::real_clock::to_timespec(rhs.mtime);
    l.tv_nsec = 0;
    r.tv_nsec = 0;
    if (l > r) {
      return false;
    }
    if (l < r) {
      return true;
    }
    if (!zone_short_id || !rhs.zone_short_id) {
      /* don't compare zone ids, if one wasn't provided */
      return false;
    }
    if (zone_short_id != rhs.zone_short_id) {
      return (zone_short_id < rhs.zone_short_id);
    }
    return (pg_ver < rhs.pg_ver);

  }

  bool operator<(const obj_time_weight& rhs) {
    if (!high_precision || !rhs.high_precision) {
      return compare_low_precision(rhs);
    }
    if (mtime > rhs.mtime) {
      return false;
    }
    if (mtime < rhs.mtime) {
      return true;
    }
    if (!zone_short_id || !rhs.zone_short_id) {
      /* don't compare zone ids, if one wasn't provided */
      return false;
    }
    if (zone_short_id != rhs.zone_short_id) {
      return (zone_short_id < rhs.zone_short_id);
    }
    return (pg_ver < rhs.pg_ver);
  }

  void init(const real_time& _mtime, uint32_t _short_id, uint64_t _pg_ver) {
    mtime = _mtime;
    zone_short_id = _short_id;
    pg_ver = _pg_ver;
  }

  void init(RGWObjState *state) {
    mtime = state->mtime;
    zone_short_id = state->zone_short_id;
    pg_ver = state->pg_ver;
  }
};

inline ostream& operator<<(ostream& out, const obj_time_weight &o) {
  out << o.mtime;

  if (o.zone_short_id != 0 || o.pg_ver != 0) {
    out << "[zid=" << o.zone_short_id << ", pgv=" << o.pg_ver << "]";
  }

  return out;
}

class RGWGetExtraDataCB : public RGWHTTPStreamRWRequest::ReceiveCB {
  bufferlist extra_data;
public:
  RGWGetExtraDataCB() {}
  int handle_data(bufferlist& bl, bool *pause) override {
    int bl_len = (int)bl.length();
    if (extra_data.length() < extra_data_len) {
      off_t max = extra_data_len - extra_data.length();
      if (max > bl_len) {
        max = bl_len;
      }
      bl.splice(0, max, &extra_data);
    }
    return bl_len;
  }

  bufferlist& get_extra_data() {
    return extra_data;
  }
};

int RGWRados::stat_remote_obj(RGWObjectCtx& obj_ctx,
               const rgw_user& user_id,
               const string& client_id,
               req_info *info,
               const string& source_zone,
               rgw_obj& src_obj,
               RGWBucketInfo& src_bucket_info,
               real_time *src_mtime,
               uint64_t *psize,
               const real_time *mod_ptr,
               const real_time *unmod_ptr,
               bool high_precision_time,
               const char *if_match,
               const char *if_nomatch,
               map<string, bufferlist> *pattrs,
               map<string, string> *pheaders,
               string *version_id,
               string *ptag,
               string *petag)
{
  /* source is in a different zonegroup, copy from there */

  RGWRESTStreamRWRequest *in_stream_req;
  string tag;
  map<string, bufferlist> src_attrs;
  append_rand_alpha(cct, tag, tag, 32);
  obj_time_weight set_mtime_weight;
  set_mtime_weight.high_precision = high_precision_time;

  RGWRESTConn *conn;
  if (source_zone.empty()) {
    if (src_bucket_info.zonegroup.empty()) {
      /* source is in the master zonegroup */
      conn = rest_master_conn;
    } else {
      map<string, RGWRESTConn *>::iterator iter = zonegroup_conn_map.find(src_bucket_info.zonegroup);
      if (iter == zonegroup_conn_map.end()) {
        ldout(cct, 0) << "could not find zonegroup connection to zonegroup: " << source_zone << dendl;
        return -ENOENT;
      }
      conn = iter->second;
    }
  } else {
    map<string, RGWRESTConn *>::iterator iter = zone_conn_map.find(source_zone);
    if (iter == zone_conn_map.end()) {
      ldout(cct, 0) << "could not find zone connection to zone: " << source_zone << dendl;
      return -ENOENT;
    }
    conn = iter->second;
  }

  RGWGetExtraDataCB cb;
  map<string, string> req_headers;
  real_time set_mtime;

  const real_time *pmod = mod_ptr;

  obj_time_weight dest_mtime_weight;

  constexpr bool prepend_meta = true;
  constexpr bool get_op = true;
  constexpr bool rgwx_stat = true;
  constexpr bool sync_manifest = true;
  constexpr bool skip_decrypt = true;
  int ret = conn->get_obj(user_id, info, src_obj, pmod, unmod_ptr,
                      dest_mtime_weight.zone_short_id, dest_mtime_weight.pg_ver,
                      prepend_meta, get_op, rgwx_stat,
                      sync_manifest, skip_decrypt,
                      true, &cb, &in_stream_req);
  if (ret < 0) {
    return ret;
  }

  ret = conn->complete_request(in_stream_req, nullptr, &set_mtime, psize, nullptr, pheaders);
  if (ret < 0) {
    return ret;
  }

  bufferlist& extra_data_bl = cb.get_extra_data();
  if (extra_data_bl.length()) {
    JSONParser jp;
    if (!jp.parse(extra_data_bl.c_str(), extra_data_bl.length())) {
      ldout(cct, 0) << "failed to parse response extra data. len=" << extra_data_bl.length() << " data=" << extra_data_bl.c_str() << dendl;
      return -EIO;
    }

    JSONDecoder::decode_json("attrs", src_attrs, &jp);

    src_attrs.erase(RGW_ATTR_MANIFEST); // not interested in original object layout
  }

  if (src_mtime) {
    *src_mtime = set_mtime;
  }

  if (petag) {
    map<string, bufferlist>::iterator iter = src_attrs.find(RGW_ATTR_ETAG);
    if (iter != src_attrs.end()) {
      bufferlist& etagbl = iter->second;
      *petag = etagbl.to_str();
      while (petag->size() > 0 && (*petag)[petag->size() - 1] == '\0') {
        *petag = petag->substr(0, petag->size() - 1);
      }
    }
  }

  if (pattrs) {
    *pattrs = std::move(src_attrs);
  }

  return 0;
}

int RGWRados::fetch_remote_obj(RGWObjectCtx& obj_ctx,
               const rgw_user& user_id,
               const string& client_id,
               const string& op_id,
               bool record_op_state,
               req_info *info,
               const string& source_zone,
               rgw_obj& dest_obj,
               rgw_obj& src_obj,
               RGWBucketInfo& dest_bucket_info,
               RGWBucketInfo& src_bucket_info,
               std::optional<rgw_placement_rule> dest_placement_rule,
               real_time *src_mtime,
               real_time *mtime,
               const real_time *mod_ptr,
               const real_time *unmod_ptr,
               bool high_precision_time,
               const char *if_match,
               const char *if_nomatch,
               AttrsMod attrs_mod,
               bool copy_if_newer,
               map<string, bufferlist>& attrs,
               RGWObjCategory category,
               std::optional<uint64_t> olh_epoch,
	       real_time delete_at,
               string *version_id,
               string *ptag,
               string *petag,
               void (*progress_cb)(off_t, void *),
               void *progress_data,
               rgw_zone_set *zones_trace,
               bool *not_modified)
{
  /* source is in a different zonegroup, copy from there */

  RGWRESTStreamRWRequest *in_stream_req;
  string tag;
  int i;
  int ret = 0;
  append_rand_alpha(cct, tag, tag, 32);
  obj_time_weight set_mtime_weight;
  set_mtime_weight.high_precision = high_precision_time;

  RGWPutObjProcessor_Atomic processor(obj_ctx,
                                      dest_bucket_info, dest_obj.bucket, dest_obj.key.name,
                                      cct->_conf->rgw_obj_stripe_size, tag, dest_bucket_info.versioning_enabled());
  processor.set_content_length(cct->_conf->rgw_file_shuntflow_size);
  processor.set_unknown_actual_size(true);
  processor.set_skip_cache_flag(cct->_conf->rgw_enable_skip_cachepool);
  processor.set_file_shuntflow_size(cct->_conf->rgw_file_shuntflow_size);
  if (version_id && *version_id != "null") {
    processor.set_version_id(*version_id);
  }
  if (olh_epoch) {
    processor.set_olh_epoch(*olh_epoch);
  }

  RGWRESTConn *conn;
  if (source_zone.empty()) {
    if (dest_bucket_info.zonegroup.empty()) {
      /* source is in the master zonegroup */
      conn = rest_master_conn;
    } else {
      map<string, RGWRESTConn *>::iterator iter = zonegroup_conn_map.find(src_bucket_info.zonegroup);
      if (iter == zonegroup_conn_map.end()) {
        ldout(cct, 0) << "could not find zonegroup connection to zonegroup: " << source_zone << dendl;
        return -ENOENT;
      }
      conn = iter->second;
    }
  } else {
    map<string, RGWRESTConn *>::iterator iter = zone_conn_map.find(source_zone);
    if (iter == zone_conn_map.end()) {
      ldout(cct, 0) << "could not find zone connection to zone: " << source_zone << dendl;
      return -ENOENT;
    }
    conn = iter->second;
  }

  string obj_name = dest_obj.bucket.name + "/" + dest_obj.get_oid();

  RGWOpStateSingleOp *opstate = NULL;

  if (record_op_state) {
    opstate = new RGWOpStateSingleOp(this, client_id, op_id, obj_name);

    ret = opstate->set_state(RGWOpState::OPSTATE_IN_PROGRESS);
    if (ret < 0) {
      ldout(cct, 0) << "ERROR: failed to set opstate ret=" << ret << dendl;
      delete opstate;
      return ret;
    }
  }

  boost::optional<RGWPutObj_Compress> compressor;
  CompressorRef plugin;

  const rgw_placement_rule *ptail_rule = (dest_placement_rule ? &(*dest_placement_rule) : nullptr);
  rgw_placement_rule dest_rule;
  RGWRadosPutObj cb(cct, plugin, compressor, &processor, opstate, progress_cb, progress_data,
                    [&](const map<string, bufferlist>& obj_attrs) {
                      if (!ptail_rule) {
                        auto iter = obj_attrs.find(RGW_ATTR_STORAGE_CLASS);
                        if (iter != obj_attrs.end()) {
                          dest_rule.storage_class = iter->second.to_str();
                          dest_rule.inherit_from(dest_bucket_info.head_placement_rule);
                          ptail_rule = &dest_rule;
                        } else {
                          ptail_rule = &dest_bucket_info.head_placement_rule;
                        }
                      }
                      processor.set_placement_rule(*ptail_rule);
                      const auto& compression_type = zone_params.get_compression_type(*ptail_rule);
                      if (compression_type != "none") {
                        plugin = Compressor::create(cct, compression_type);
                        if (!plugin) {
                          ldout(cct, 1) << "Cannot load plugin for compression type "
                                        << compression_type << dendl;
                        }
                      }
                      int ret = processor.prepare(this, NULL);
                      if (ret < 0) {
                        ldout(cct, 10) << __func__ << "() ERROR: processor prepare, ret:"
                                       << ret << dendl;
                        return ret;
                      }
                      return 0;
                    });

  string etag;
  real_time set_mtime;

  RGWObjState *dest_state = NULL;

  const real_time *pmod = mod_ptr;

  obj_time_weight dest_mtime_weight;

  if (copy_if_newer) {
    /* need to get mtime for destination */
    ret = get_obj_state(&obj_ctx, dest_bucket_info, dest_obj, &dest_state, false);
    if (ret < 0) {
      ldout(cct, 10) << __func__ << "() ERROR: get_obj_state ret:" << ret << dendl;
      goto set_err_state;
    }
    if (!real_clock::is_zero(dest_state->mtime)) {
      dest_mtime_weight.init(dest_state);
      pmod = &dest_mtime_weight.mtime;
    }
  }

  // in multisite, copy remote object unless local mtime less than mtime of remote object
  // don't compare umod_time in versioning situation, meanwhile don't compare unmod_time
  // when fetch remote object.
  if (not_modified) {
    if (!(dest_bucket_info.versioning_status() & (BUCKET_VERSIONED | BUCKET_VERSIONS_SUSPENDED))) {
      if (unmod_ptr) {
        processor.set_unmod_time(unmod_ptr);
      }
    } else {
      unmod_ptr = nullptr;
    }
  }

  static constexpr bool prepend_meta = true;
  static constexpr bool get_op = true;
  static constexpr bool rgwx_stat = false;
  static constexpr bool sync_manifest = true;
  static constexpr bool skip_decrypt = true;
  ret = conn->get_obj(user_id, info, src_obj, pmod, unmod_ptr,
                      dest_mtime_weight.zone_short_id, dest_mtime_weight.pg_ver,
                      prepend_meta, get_op, rgwx_stat,
                      sync_manifest, skip_decrypt,
                      true,
                      &cb, &in_stream_req);
  if (ret < 0) {
    ldout(cct, 10) << "ERROR: RGWRESTConn::get_obj() ret:" << ret << dendl;
    goto set_err_state;
  }

  ret = conn->complete_request(in_stream_req, &etag, &set_mtime, nullptr, nullptr, nullptr);
  if (ret < 0) {
    ldout(cct, 10) << "ERROR: RGWRESTConn::complete_request() ret:" << ret << dendl;
    goto set_err_state;
  }
  ret = cb.flush();
  if (ret < 0) {
    ldout(cct, 10) << "ERROR: RGWRadosPutObj::flush() ret:" << ret << dendl;
    goto set_err_state;
  }
  if (compressor && compressor->is_compressed()) {
    bufferlist tmp;
    RGWCompressionInfo cs_info;
    cs_info.compression_type = plugin->get_type_name();
    cs_info.orig_size = cb.get_data_len();
    cs_info.blocks = move(compressor->get_compression_blocks());
    encode(cs_info, tmp);
    cb.get_attrs()[RGW_ATTR_COMPRESSION] = tmp;
  }

  if (source_zone.empty()) { /* need to preserve expiration if copy in the same zonegroup */
    cb.get_attrs().erase(RGW_ATTR_DELETE_AT);
  } else {
    map<string, bufferlist>::iterator iter = cb.get_attrs().find(RGW_ATTR_DELETE_AT);
    if (iter != cb.get_attrs().end()) {
      try {
        decode(delete_at, iter->second);
      } catch (buffer::error& err) {
        ldout(cct, 0) << "ERROR: failed to decode delete_at field in intra zone copy" << dendl;
      }
    }
  }

  if (src_mtime) {
    *src_mtime = set_mtime;
  }

  if (petag) {
    const auto iter = cb.get_attrs().find(RGW_ATTR_ETAG);
    if (iter != cb.get_attrs().end()) {
      *petag = iter->second.to_str();
    }
  }

  if (source_zone.empty()) {
    set_copy_attrs(cb.get_attrs(), attrs, attrs_mod);
  } else {
    attrs = cb.get_attrs();
  }

  if (copy_if_newer) {
    uint64_t pg_ver = 0;
    auto i = attrs.find(RGW_ATTR_PG_VER);
    if (i != attrs.end() && i->second.length() > 0) {
      bufferlist::iterator iter = i->second.begin();
      try {
        decode(pg_ver, iter);
      } catch (buffer::error& err) {
        ldout(ctx(), 0) << "ERROR: failed to decode pg ver attribute, ignoring" << dendl;
        /* non critical error */
      }
    }
    set_mtime_weight.init(set_mtime, get_zone_short_id(), pg_ver);
  }

#define MAX_COMPLETE_RETRY 100
  for (i = 0; i < MAX_COMPLETE_RETRY; i++) {
    ret = cb.complete(etag, mtime, set_mtime, attrs, delete_at, zones_trace);
    if (ret < 0) {
      ldout(cct, 10) << "ERROR: RGWRadosPutObj::complete() ret:" << ret << dendl;
      goto set_err_state;
    }
    if (copy_if_newer && cb.is_canceled()) {
      ldout(cct, 20) << "raced with another write of obj: " << dest_obj << dendl;
      obj_ctx.obj.invalidate(dest_obj); /* object was overwritten */
      ret = get_obj_state(&obj_ctx, dest_bucket_info, dest_obj, &dest_state, false);
      if (ret < 0) {
        ldout(cct, 10) << "ERROR: " << __func__ << ": get_err_state() returned ret=" << ret << dendl;
        goto set_err_state;
      }
      dest_mtime_weight.init(dest_state);
      dest_mtime_weight.high_precision = high_precision_time;
      if (!dest_state->exists ||
        dest_mtime_weight < set_mtime_weight) {
        ldout(cct, 20) << "retrying writing object mtime=" << set_mtime << " dest_state->mtime=" << dest_state->mtime << " dest_state->exists=" << dest_state->exists << dendl;
        continue;
      } else {
        ldout(cct, 20) << "not retrying writing object mtime=" << set_mtime << " dest_state->mtime=" << dest_state->mtime << " dest_state->exists=" << dest_state->exists << dendl;
      }
    }
    break;
  }

  if (i == MAX_COMPLETE_RETRY) {
    ldout(cct, 0) << "ERROR: retried object completion too many times, something is wrong!" << dendl;
    ret = -EIO;
    goto set_err_state;
  }

  if (opstate) {
    ret = opstate->set_state(RGWOpState::OPSTATE_COMPLETE);
    if (ret < 0) {
      ldout(cct, 0) << "ERROR: failed to set opstate ret=" << ret << dendl;
    }
    delete opstate;
  }

  return 0;
set_err_state:
  if (copy_if_newer && ret == -ERR_NOT_MODIFIED) {
    // we may have already fetched during sync of OP_ADD, but were waiting
    // for OP_LINK_OLH to call set_olh() with a real olh_epoch
    if (olh_epoch && *olh_epoch > 0) {
      constexpr bool log_data_change = true;
      ret = set_olh(obj_ctx, dest_bucket_info, dest_obj, false, nullptr,
                    *olh_epoch, real_time(), false, zones_trace, log_data_change);
      ldout(cct, 20) << "ERROR: " << __func__ << ": set_olh() ret=" << ret << dendl;
    } else {
      // we already have the latest copy
      if (not_modified) {
        *not_modified = true;
      }
      ret = 0;
    }
  }
  if (opstate) {
    RGWOpState::OpState state;
    if (ret < 0) {
      state = RGWOpState::OPSTATE_ERROR;
    } else {
      state = RGWOpState::OPSTATE_COMPLETE;
    }
    int r = opstate->set_state(state);
    if (r < 0) {
      ldout(cct, 0) << "ERROR: failed to set opstate r=" << ret << dendl;
    }
    delete opstate;
  }
  return ret;
}

int RGWRados::async_fetch_mirror_obj(req_state* s,
                                     MirroringConfiguration& config,
                                     RGWGetDataCB* get_data_cb) {
  RGWRESTStreamRWRequest *in_stream_req;

  list<string> endpoint;
  endpoint.push_back(config.source_url);
  std::unique_ptr<RGWRESTConn> conn = std::unique_ptr<RGWRESTConn>(
      new RGWRESTConn(cct, this, zonegroup.get_id(), endpoint, PathStyle, true));

  // add prefix to bucket name, adapt to RGWRESTConn
  rgw_bucket temp_bucket;
  temp_bucket.name = config.prefix;
  rgw_obj src_obj(temp_bucket, s->object);
  static rgw_user empty_user;

  map<string, string>& params = s->info.args.get_params();
  map<string, string> headers;
  rgw::mirror::generate_mirror_headers(s, config, headers);
  headers["HTTP_RANGE"] = s->info.env->get("HTTP_RANGE", "");
  ldout(s->cct, 20) << __func__ << "() fetch range data, range:"
                    << headers["HTTP_RANGE"] << dendl;

  RGWRadosMirrorObj cb(s, cct, nullptr, nullptr, get_data_cb, &in_stream_req);

  // register range fetch request
  int ret = conn->get_obj(empty_user, &s->info, src_obj,
                          nullptr,    // pmod
                          nullptr,    // unmod_ptr
                          0,          // dest_mtime_weight.zone_short_id
                          0,          // dest_mtime_weight.pg_ver,
                          false,      // prepend_meta
                          true,       // get_op
                          false,      // rgwx_stat
                          false,      // sync_manifest
                          false,      // skip_decrypt
                          true,       // send
                          &cb,        // cb
                          &in_stream_req,
                          &headers,
                          (config.pass_querystring ? &params : nullptr));
  if (ret < 0) {
    ldout(s->cct, 0) << __func__ << "() ERROR: conn get_obj err:" << ret << dendl;
    return ret;
  }

  // process response data, return when request is done
  ret = cb.mirror_data();
  if (ret < 0) {
    ldout(s->cct, 10) << __func__ << "() mirror_data err:" << ret << dendl;
    if (ret == -EAGAIN) {  // cann't connect to dest
      return -ERR_MIRROR_SOURCE_INVALID;
    }
    return -ERR_MIRROR_FAILED;
  }

  RGWRESTStreamRWRequest *async_stream_req;

  conn->set_range_explicited(true);

  auto iter = headers.find("HTTP_RANGE");
  if (iter != headers.end()) {
    headers.erase(iter);
  }
  ldout(s->cct, 20) << __func__ << "() try to fetch total data" << dendl;

  // register async fetch total object, http_manager will handle store local
  ret = conn->get_obj(empty_user, &s->info, src_obj,
                      nullptr,        // pmod
                      nullptr,        // unmod_ptr
                      0,              // dest_mtime_weight.zone_short_id
                      0,              // dest_mtime_weight.pg_ver,
                      false,          // prepend_meta
                      true,           // get_op
                      false,          // rgwx_stat
                      false,          // sync_manifest
                      false,          // skip_decrypt
                      false,          // send
                      nullptr,        // cb
                      &async_stream_req,
                      &headers,
                      (config.pass_querystring ? &params : nullptr));
  if (ret < 0) {
    ldout(s->cct, 0) << __func__ << "() ERROR: conn get_obj err:" << ret << dendl;
    return ret;
  }

  if (!config.storage_class.empty()) {
    rgw_placement_rule dest_rule;
    dest_rule.storage_class = config.storage_class;
    dest_rule.inherit_from(s->bucket_info.head_placement_rule);
    static_cast<RGWRESTStreamAsyncMirrorReadRequest*>(async_stream_req)->set_placement_rule(dest_rule);
  } else {
    static_cast<RGWRESTStreamAsyncMirrorReadRequest*>(async_stream_req)->set_placement_rule(s->bucket_info.head_placement_rule);
  }

  static_cast<RGWRESTStreamAsyncMirrorReadRequest*>(async_stream_req)->prepare(s->bucket_info, s->bucket, s->object.name);

  ret = async_stream_req->send(nullptr);
  if (ret < 0) {
    if (async_stream_req) {
      delete async_stream_req;
      async_stream_req = nullptr;
    }
    ldout(s->cct, 0) << __func__ << "() ERROR: send async mirror read request err:" << ret << dendl;
    return ret;
  }
  return 0;
}

int RGWRados::fetch_mirror_obj(req_state* s,
                               real_time* mtime, // &lastmod, send to client
                               map<string, bufferlist>& attrs,
                               string *version_id,
                               RGWGetDataCB* get_data_cb)
{
  map<string, bufferlist>::iterator aiter = s->bucket_attrs.find(RGW_ATTR_MIRRORING);
  if (aiter == s->bucket_attrs.end()) {
    ldout(s->cct, 30) << "no mirroring configuration attr found" << dendl;
    return -ENOENT;
  }

  int ret = verify_object_permission(s, this, s->bucket.name, s->object.name,
                                     rgw::IAM::s3PutObject, RGW_PERM_WRITE, true);
  if (ret < 0) {
    dout(10) << __func__ << "() no permission to put mirror obj:" << s->object << dendl;
    return -EACCES;
  }

  const char * user_agent = s->info.env->get("HTTP_USER_AGENT");
  if (user_agent && boost::algorithm::starts_with(boost::string_view(user_agent), "bcebos-spider")) {
    // this GetObject request is send by mirror, dirently return -ENOENT to
    // avoid a cycle loop of fetching.
    ldout(s->cct, 20) << "obj no exists, don't trigger fetch for mirror request" << dendl;
    return -ENOENT;
  }

  RGWMirroringConfiguration configs;
  try {
    bufferlist::iterator iter = aiter->second.begin();
    configs.decode(iter);
  } catch (buffer::error& err) {
    ldout(s->cct, 0) << "ERROR: could not decode mirroring, caught error:" << err << dendl;
    return -EINTR;
  }
  if (configs.configurations.size() != 1) {
    return -ERR_MIRROR_FAILED;
  }
  MirroringConfiguration& config = configs.configurations.front();

  bool range_explicted = false;

  if (s->info.env->exists("HTTP_RANGE")) {
    range_explicted = true;
  }

  //real_time set_mtime;
  *mtime = real_clock::now();

  if (range_explicted) {
    return async_fetch_mirror_obj(s, config, get_data_cb);
  }

  RGWRESTStreamRWRequest *in_stream_req;

  RGWObjectCtx& obj_ctx = *static_cast<RGWObjectCtx *>(s->obj_ctx);
  string tag;
  append_rand_alpha(cct, tag, tag, 32);


  RGWPutObjProcessor_Atomic processor(obj_ctx,
                                      s->bucket_info, s->bucket, s->object.name,
                                      cct->_conf->rgw_obj_stripe_size, tag,
                                      s->bucket_info.versioning_enabled());
  ceph::bufferlist& bl_sc = attrs[RGW_ATTR_STORAGE_CLASS];
  if (bl_sc.length()) bl_sc.clear();

  if (!config.storage_class.empty()) {
    rgw_placement_rule dest_rule;
    dest_rule.storage_class = config.storage_class;
    dest_rule.inherit_from(s->bucket_info.head_placement_rule);
    processor.set_placement_rule(dest_rule);
    bl_sc.append(dest_rule.storage_class.c_str(), dest_rule.storage_class.length());
  } else {
    processor.set_placement_rule(s->bucket_info.head_placement_rule);
    bl_sc.append(s->bucket_info.head_placement_rule.storage_class.c_str(),
                 s->bucket_info.head_placement_rule.storage_class.length());
  }
  processor.set_content_length(s->cct->_conf->rgw_file_shuntflow_size);
  processor.set_unknown_actual_size(true);
  processor.set_skip_cache_flag(s->cct->_conf->rgw_enable_skip_cachepool);
  processor.set_file_shuntflow_size(s->cct->_conf->rgw_file_shuntflow_size);
  ret = processor.prepare(this, NULL);
  if (ret < 0) {
    ldout(s->cct, 0) << __func__ << " putobj processor prepare err:" << ret << dendl;
    return -ERR_MIRROR_FAILED;
  }

  list<string> endpoint;
  endpoint.push_back(config.source_url);
  std::unique_ptr<RGWRESTConn> conn = std::unique_ptr<RGWRESTConn>(
      new RGWRESTConn(cct, this, zonegroup.get_id(), endpoint, PathStyle, true));
  MD5 hash;
  char calc_md5[CEPH_CRYPTO_MD5_DIGESTSIZE * 2 + 1];
  unsigned char m[CEPH_CRYPTO_MD5_DIGESTSIZE];

  RGWRadosMirrorObj cb(s, cct, &processor, &hash, get_data_cb, &in_stream_req);

  string etag;

  static constexpr bool prepend_meta = false;
  static constexpr bool get_op = true;
  static constexpr bool rgwx_stat = false;
  static constexpr bool sync_manifest = false;
  static constexpr bool skip_decrypt = false;

  // add prefix to bucket name, adapt to RGWRESTConn
  rgw_bucket temp_bucket;
  temp_bucket.name = config.prefix;
  rgw_obj src_obj(temp_bucket, s->object);
  static rgw_user empty_user;

  map<string, string>& params = s->info.args.get_params();
  map<string, string> headers;
  rgw::mirror::generate_mirror_headers(s, config, headers);

  ret = conn->get_obj(empty_user, &s->info, src_obj,
                      nullptr,   // pmod
                      nullptr,   // unmod_ptr
                      0,         // dest_mtime_weight.zone_short_id
                      0,         // dest_mtime_weight.pg_ver,
                      prepend_meta, get_op, rgwx_stat,
                      sync_manifest, skip_decrypt,
                      true,
                      &cb, &in_stream_req,
                      &headers,
                      (config.pass_querystring ? &params : nullptr));
  if (ret < 0) {
    ldout(s->cct, 0) << __func__ << " conn get_obj err:" << ret << dendl;
    return ret;
  }

  // process response data, return when request is done
  ret = cb.mirror_data();
  if (ret < 0) {
    ldout(s->cct, 10) << __func__ << "() mirror_data err:" << ret << dendl;
    if (ret == -EAGAIN) {  // cann't connect to dest
      return -ERR_MIRROR_SOURCE_INVALID;
    }
    return -ERR_MIRROR_FAILED;
  }

  ret = cb.flush();
  if (ret < 0) {
    ldout(s->cct, 10) << __func__ << " cb flush err:" << ret << dendl;
    return ret;
  }


  hash.Final(m);
  buf_to_hex(m, CEPH_CRYPTO_MD5_DIGESTSIZE, calc_md5);
  etag = calc_md5;

  auto iter = attrs.find(RGW_ATTR_CONTENT_MD5);
  if (iter != attrs.end() && iter->second.length()) {
    char supplied_md5_bin[CEPH_CRYPTO_MD5_DIGESTSIZE + 1];
    char supplied_md5[CEPH_CRYPTO_MD5_DIGESTSIZE * 2 + 1];
    const char *supplied_md5_b64 = nullptr;
    supplied_md5_b64 = iter->second.c_str();

    int ret = ceph_unarmor(supplied_md5_bin, &supplied_md5_bin[CEPH_CRYPTO_MD5_DIGESTSIZE + 1],
                       supplied_md5_b64, supplied_md5_b64 + iter->second.length());
    ldout(s->cct, 15) << "ceph_unarmor ret=" << ret << dendl;
    if (ret != CEPH_CRYPTO_MD5_DIGESTSIZE) {
      return -ERR_INVALID_DIGEST;
    }

    buf_to_hex((const unsigned char *)supplied_md5_bin, CEPH_CRYPTO_MD5_DIGESTSIZE, supplied_md5);
    ldout(s->cct, 15) << "supplied_md5 from CONTENT_MD5 " << supplied_md5 << dendl;
    if (strcmp(calc_md5, supplied_md5)) {
      // auto clear written tail obj in ~RGWPutObjProcessor_Aio
      ldout(s->cct, 10) << __func__ << " source md5 not satisfy, calc_md5:"
                        << calc_md5 << ", supplied_md5:" << supplied_md5
                        << dendl;
      return -ERR_BAD_DIGEST;
    }
  }

  ceph::bufferlist& bl_etag = attrs[RGW_ATTR_ETAG];
  if (bl_etag.length()) bl_etag.clear();
  bl_etag.append(etag.c_str(), etag.length());

  // mtime: specify obj mtime
  ret = cb.complete(etag, nullptr, *mtime, attrs, real_time(), nullptr);
  if (ret < 0) {
    ldout(s->cct, 10) << __func__ << " conn complete err:" << ret << dendl;
    return ret;
  }

  return 0;
}

int RGWRados::copy_obj_to_remote_dest(RGWObjState *astate,
                                      map<string, bufferlist>& src_attrs,
                                      RGWRados::Object::Read& read_op,
                                      const rgw_user& user_id,
                                      rgw_obj& dest_obj,
                                      real_time *mtime)
{
  string etag;

  RGWRESTStreamS3PutObj *out_stream_req;

  int ret = rest_master_conn->put_obj_async(user_id, dest_obj, astate->size, src_attrs, true, &out_stream_req);
  if (ret < 0) {
    return ret;
  }

  ret = read_op.iterate(0, astate->size - 1, out_stream_req->get_out_cb());
  if (ret < 0) {
    delete out_stream_req;
    return ret;
  }

  ret = rest_master_conn->complete_request(out_stream_req, etag, mtime);
  if (ret < 0)
    return ret;

  return 0;
}

RGWClients rgw_client;

int RGWRados::is_renaming_conflict(RGWObjState* state) {
  string renaming_info_key = "";
  bufferlist bl;
  if (state->get_attr(RGW_ATTR_ID_TAG, bl)) {
    int r = 0;
    std::tie(r, renaming_info_key) = get_renaming_info(state->attrset, rgw_bl_to_str(bl));
    if (r == 0) return -ERR_RENAME_CONFLICT;
    if (r < 0) return r;
  }

  // cann't rename between appending
  auto iter = state->attrset.find(RGW_ATTR_TARGET_SIZE);
  if (iter != state->attrset.end()) {
    uint64_t target_size;
    try {
      decode(target_size, iter->second);
    } catch (buffer::error& err) {
      ldout(cct, 5) << "ERROR: failed to decode " RGW_ATTR_TARGET_SIZE
        << " attr, value:" << iter->second.c_str() << dendl;
      return -EIO;
    }
    if (target_size != uint64_t(state->size)) {
      iter = state->attrset.find(RGW_ATTR_APPEND_TIMEOUT);
      if (iter != state->attrset.end()) {
        ceph::real_time ts;
        try {
          decode(ts, iter->second);
        } catch (buffer::error& err) {
          ldout(cct, 5) << "ERROR: failed to decode " RGW_ATTR_APPEND_TIMEOUT
            << " attr, value:" << iter->second.c_str() << dendl;
          return -EIO;
        }
        if (real_clock::now() < ts + make_timespan(cct->_conf->rgw_append_timeout)) {
          return -ERR_RENAME_CONFLICT;
        }
      }
    }
  }
  return 0;
}

int RGWRados::rename_obj(RGWObjectCtx& obj_ctx,
                         const rgw_obj& src_obj,
                         const rgw_obj& dst_obj,
                         const RGWBucketInfo& bucket_info) {
  RGWRados::Bucket bop(this, bucket_info);
  RGWRados::Bucket::UpdateIndex index_src_op(&bop, src_obj);

  string src_tag, dst_tag;
  append_rand_alpha(cct, src_tag, src_tag, 32);
  append_rand_alpha(cct, dst_tag, dst_tag, 32);

  RGWObjState *state = NULL;
  int r = get_obj_state(&obj_ctx, bucket_info, src_obj, &state, false);
  if (r < 0) {
    ldout(cct, 0) << __func__ << "() ERROR get src obj state return:" << r << dendl;
    return r;
  }

  if (state->exists) {
    r = is_renaming_conflict(state);
    if (r < 0) return r;
  } else {
    return -ENOENT;
  }
  map<string, bufferlist>::iterator iter = state->attrset.find(RGW_ATTR_DELETED);
  if (iter != state->attrset.end()) {
    if (rgw_bl_to_str(iter->second).compare("true") == 0) {
      return -ENOENT;
    }
  }

  if (src_obj == dst_obj) {
    ldout(cct, 5) << __func__ << "(): src and dst obj is same for renaming" << dendl;
    return 0;
  }

  // 1. prepare src idx
  r = index_src_op.prepare(CLS_RGW_OP_DEL, &src_tag);
  if (r < 0) {
    ldout(cct, 0) << __func__ << "() ERROR: prepare src obj index return:" << r << dendl;
    return r;
  }

  RGWRados::Object source(this, bucket_info, obj_ctx, src_obj);
  RGWRados::Object target(this, bucket_info, obj_ctx, dst_obj);

  RGWRados::Object::Rename rename_op(this, &source, &target);

  // 2. set src rename xattr with fetch data
  if (rgw_client.rgw_client_id.empty()) {
    r = try_refresh_client_id();
    ldout(cct, 10) << __func__ << "() try refresh rgw_client_id ret:" << r << dendl;
    if (r < 0) return r;
  }
  ldout(cct, 30) << __func__ << "() rgw_client.rgw_client_id:" << rgw_client.rgw_client_id << dendl;

  r = rename_op.set_src_obj_rename_attr(src_tag, dst_tag);
  if (r < 0) {
    ldout(cct, 0) << __func__ << "() ERROR: set src obj attr return:" << r << dendl;
    rename_op.rename_backward_operation(dst_tag, &index_src_op);
    return r;  // if set src attr err:-ENOENT -> return client 404
  }

  // 3. prepare dst idx
  RGWRados::Bucket::UpdateIndex index_dst_op(&bop, dst_obj);

  r = index_dst_op.prepare(CLS_RGW_OP_ADD, &dst_tag);

  if (r < 0) {
    ldout(cct, 0) << __func__ << "() ERROR: prepare dst obj index return:" << r << dendl;
    rename_op.rename_backward_operation(dst_tag, &index_src_op);
    return r;
  }

  // 4. write dst obj
  ceph::real_time mtime = real_clock::now();

  rename_op.set_renaming_progress(Object::Rename::DONE_DST_IDX);

  r = rename_op.store_rename_dst_obj(mtime, src_tag, dst_tag, true);
  if (r < 0) {
    if (r == -EEXIST) {
#define RGW_RENAME_RETRY_OVERWRITE_DEST 10
      for (int i = 0; i < RGW_RENAME_RETRY_OVERWRITE_DEST; i++) {
        ldout(cct, 10) << __func__ << "() dst obj exists, try overwrite it " << dst_obj << dendl;
        r = rename_op.store_rename_dst_obj(mtime, src_tag, dst_tag, false);
        if (r != -ECANCELED) break;
        srand(time(NULL));
        std::this_thread::sleep_for(std::chrono::milliseconds(rand() % 1000));
      }
    }
    if (r < 0) {
      ldout(cct, 0) << __func__ << "() ERROR: write dst obj return:" << r << dendl;
      rename_op.rename_backward_operation(dst_tag, &index_src_op, &index_dst_op);
      if (r == -ECANCELED) return -ERR_RENAME_CONFLICT;
      return r;
    }
  }

  //5. remove src obj
  ObjectWriteOperation sop;
  list<string> prefixes;
  cls_rgw_remove_obj(sop, prefixes);

  bufferlist src_tag_bl;
  src_tag_bl.append(src_tag.c_str(), src_tag.size() + 1);
  sop.cmpxattr(RGW_ATTR_ID_TAG, LIBRADOS_CMPXATTR_OP_EQ, src_tag_bl);

  rgw_rados_ref sref;
  r = get_obj_head_ref(bucket_info, src_obj, &sref);
  if (r < 0) {
    ldout(cct, 0) << __func__ << "() ERROR: get src obj ref return:" << r << dendl;
    return r;
  }
  r = sref.ioctx.operate(sref.oid, &sop);

  if (r < 0) {
    if (r == -ECANCELED) {
      ldout(cct, 10) << __func__ << "() try remove src obj with conflict, try clear rename attr" << dendl;
      r = rename_op.clear_rename_attr(dst_tag);
      if (r < 0) {
        // if clear src rename xattr failed, abandon clear rename xattr in dst_obj
        ldout(cct, 0) << __func__ << "() ERROR: clear src rename attr failed:" << r << dendl;
        return r;
      }
    } else if (r == -ENOENT) {
      ldout(cct, 10) << "src obj not exist, continue excute remaining operation" << dendl;
    } else {
      // if clear src rename xattr failed, abandon clear rename xattr in dst_obj
      ldout(cct, 0) << __func__ << "() ERROR: remove src obj failed:" << r << dendl;
      return r;
    }
  }

  //6. clear rename attr in dst obj
  string rm_attr = RGW_ATTR_RENAME_DEST + src_tag;
  struct timespec mtime_ts = real_clock::to_timespec(mtime);
  bool jump_complete_dst = false;
  rgw_rados_ref dref;
  bufferlist dst_tag_bl;
  dst_tag_bl.append(dst_tag.c_str(), dst_tag.size() + 1);
  r = rename_op.rm_dst_rename_attr_and_keep_mtime(dref, mtime_ts, rm_attr, dst_tag_bl, jump_complete_dst);

  //7. complete src idx
  uint64_t epoch = sref.ioctx.get_last_version();
  int64_t poolid = sref.ioctx.get_id();

  real_time rtime;
  r = index_src_op.complete_del(poolid, sref.ioctx.get_last_version(), rtime, nullptr);
  if (r < 0) {
    ldout(cct, 0) << __func__ << "() ERROR: complete del src idx failed:" << r << dendl;
    return r;
  }

  if (jump_complete_dst) return 0;

  //8. complete dst idx
  state = nullptr;
  r = get_obj_state(&obj_ctx, bucket_info, src_obj, &state, false);
  if (r < 0) {
    ldout(cct, 0) << __func__ << "() ERROR get src obj state from cache return:" << r << dendl;
    return r;
  }

  bufferlist etag_bl = state->attrset[RGW_ATTR_ETAG];
  bufferlist content_type_bl = state->attrset[RGW_ATTR_CONTENT_TYPE];
  string etag(etag_bl.c_str(), etag_bl.length());
  string content_type(content_type_bl.c_str(), content_type_bl.length());
  bufferlist acl_bl = state->attrset[RGW_ATTR_ACL];
  string storage_class;
  iter = state->attrset.find(RGW_ATTR_STORAGE_CLASS);
  if (iter != state->attrset.end()) {
    storage_class = rgw_bl_to_str(iter->second);
  }
  auto tag_iter = state->attrset.find(RGW_ATTR_TAGS);

  // symlink object size == 0 but accounted_size is target resource length
  iter = state->attrset.find(RGW_ATTR_TARGET_OBJECT);
  if (iter != state->attrset.end()) {
    // modify index accounted_size
    state->accounted_size = (iter->second).to_str().size();
    ldout(cct, 0) << __func__ << "() ERROR: (iter->second).to_str().size() " << (iter->second).to_str().size() << "  (iter->second).to_str() " << (iter->second).to_str() << dendl;
    iter = state->attrset.find(RGW_ATTR_TARGET_BUCKET);
    if (iter != state->attrset.end() ) {
      std::string target_bucket = (iter->second).to_str();
      if (target_bucket.compare(bucket_info.bucket.name) != 0) {
        ldout(cct, 0) << __func__ << "() ERROR: target_bucket " << target_bucket << "  target_bucket" << bucket_info.bucket.name.c_str()<< dendl;
        state->accounted_size += target_bucket.size();
      }
    } 
  }

  epoch = dref.ioctx.get_last_version();
  r = index_dst_op.complete(poolid, epoch, state->size, state->accounted_size,
                            mtime, etag, content_type, &acl_bl,
                            RGW_OBJ_CATEGORY_MAIN, NULL, storage_class,
                            nullptr, true, false,
                            tag_iter != state->attrset.end() ? &(tag_iter->second) : nullptr);
  if (r < 0) {
    ldout(cct, 0) << __func__ << "() ERROR: complete dst idx failed:" << r << dendl;
    return r;
  }
  return 0;
}

int RGWRados::Object::Rename::clear_rename_attr(const std::string& tag)
{
  string write_tag;
  bufferlist bl;
  ObjectWriteOperation clear_op;

  clear_op.rmxattr(string_view(RGW_ATTR_RENAME_SOURCE + tag).data());

  int ret = source->operate_op(&clear_op);

  if (ret < 0) {
    ldout(store->ctx(), 0) << __func__ << "() ERROR: clear obj rename xattr ret:" << ret << dendl;
    return ret;
  }
  return 0;
}

int RGWRados::Object::Rename::set_src_obj_rename_attr(const std::string& src_tag,
                                                      const std::string& dst_tag)
{
  int ret = 0;

#define MAX_RENAME_ECANCELED_RETRY 10
  for (int i = 0; i < MAX_RENAME_ECANCELED_RETRY; i++) {
    if (ret == -ECANCELED) {
      source->invalidate_state();
    }
    ldout(store->ctx(), 20) << __func__ << "() call get src obj state:"
                            << source->get_obj()
                            << dendl;
    RGWObjState *astate;
    ret = source->get_state(&astate, true);
    if (ret < 0) {
      ldout(store->ctx(), 0) << __func__ << "() ERROR: get src obj state "
                             << source->get_obj() << " ret:" << ret << dendl;
      return ret;
    }

    if (astate->exists) {
      ret = store->is_renaming_conflict(astate);
      if (ret < 0) return ret;
    } else {
      return -ENOENT;
    }
    // check if src is deleted every time we reread src obj stat
    map<string, bufferlist>::iterator iter = astate->attrset.find(RGW_ATTR_DELETED);
    if (iter != astate->attrset.end()) {
      if (rgw_bl_to_str(iter->second).compare("true") == 0) {
        return -ENOENT;
      }
    }

    RGWObjManifest::obj_iterator oiter = astate->manifest.obj_begin();
    if (oiter != astate->manifest.obj_end()) {
      oiter.set_obj(source->get_obj());
    }

    RGWRenameSrcInfo info(rgw_client.rgw_client_id,
                          src_tag,
                          target->get_obj().key.name,
                          &(astate->manifest));

    ObjectWriteOperation op;

    op.cmpxattr(RGW_ATTR_ID_TAG, LIBRADOS_CMPXATTR_OP_EQ, astate->obj_tag);

    ldout(store->ctx(), 10) << "setting src object id_tag=" << src_tag << dendl;
    bufferlist bl;
    bl.append(src_tag.c_str(), src_tag.size() + 1);
    op.setxattr(RGW_ATTR_ID_TAG, bl);

    bufferlist rn_bl;
    encode(info, rn_bl);
    op.setxattr(string_view(RGW_ATTR_RENAME_SOURCE + dst_tag).data(), rn_bl);

    ret = source->operate_op(&op);
    if (ret < 0) {
      ldout(store->ctx(), 0) << __func__ << "() ERROR: prepare src obj"
                             << source->get_obj() << " ret:" << ret << dendl;
      if (ret == -ECANCELED)
        continue;
      return ret;
    } else {
      break;
    }
  }
  progress = DONE_SRC_ATTR;
  return 0;
}

int RGWRados::Object::Rename::reset_manifest_by_rename(ObjectWriteOperation& wop,
                                                       bufferlist& manifest_bl) {
  bufferlist::iterator miter = manifest_bl.begin();
  RGWObjManifest manifest;
  try {
    decode(manifest, miter);
  } catch (buffer::error& err) {
    ldout(store->ctx(), 0) << __func__ << "() ERROR: couldn't decode manifest, src_obj:"
                           << source->get_obj() << dendl;
    return -EIO;
  }
  ldout(store->ctx(), 20) << __func__ << "() correct manifest attr from src_obj:"
                          << source->get_obj() << " to " << target->get_obj() << dendl;
  rgw_obj& obj = manifest.get_non_const_obj();
  obj.bucket = target->get_obj().bucket;
  obj.key = target->get_obj().key;

  bufferlist bl;
  encode(manifest, bl);
  wop.setxattr(RGW_ATTR_MANIFEST, bl);
  return 0;
}

int RGWRados::Object::Rename::rm_dst_rename_attr_and_keep_mtime(
                                rgw_rados_ref& dref,
                                timespec& mtime_ts,
                                const string& rm_attr,
                                bufferlist& dst_tag_bl,
                                bool& jump_complete_dst)
{
#define MAX_RENAME_ECANCELED_RETRY 10
  for (int i = 0; i < MAX_RENAME_ECANCELED_RETRY; i++) {
    ObjectWriteOperation dop;

    dop.mtime2(&mtime_ts);
    dop.rmxattr(rm_attr.c_str());
    dop.cmpxattr(RGW_ATTR_ID_TAG, LIBRADOS_CMPXATTR_OP_EQ, dst_tag_bl);

    int r = store->get_obj_head_ref(target->get_bucket_info(), target->get_obj(), &dref);
    if (r < 0) {
      ldout(store->ctx(), 0) << __func__ << "() ERROR: get dst obj ref return:" << r
                             << " obj:" << target->get_obj() << dendl;
      return r;
    }

    r = dref.ioctx.operate(dref.oid, &dop);
    if (r < 0) {
      ldout(store->ctx(), 0) << __func__ << "() ERROR: rm rename attr in dst obj failed:"
                             << r << " obj:" << target->get_obj() << dendl;
      if (r == -ECANCELED) {
        target->invalidate_state();
        ldout(store->ctx(), 20) << __func__ << "() call get dst obj state:"
                                << target->get_obj()
                                << dendl;
        RGWObjState *astate;
        r = target->get_state(&astate, true);
        if (r < 0) {
          ldout(store->ctx(), 0) << __func__ << "() ERROR: get dst obj state "
                                 << target->get_obj() << " ret:" << r << dendl;
          return r;
        }
        mtime_ts = real_clock::to_timespec(astate->mtime);
        dst_tag_bl = astate->obj_tag;
        continue;
      }
      if (r != -ENOENT) {
        jump_complete_dst = true;
        return 0;
      }
    }
    break;
  }
  return 0;
}

int RGWRados::Object::Rename::store_rename_dst_obj(ceph::real_time& mtime,
                                                   const string& src_tag,
                                                   const string& dst_tag,
                                                   bool assume_noent)
{
  int r = 0;
  ObjectWriteOperation wop;

  struct timespec mtime_ts = real_clock::to_timespec(mtime);
  wop.mtime2(&mtime_ts);

  if (assume_noent) {
    wop.create(true);
  } else {
    target->invalidate_state(); // actually, no state of target in ctx at present

    // get data into state in target struct, for convenienc of
    // complete_atomic_modification later
    RGWObjState** dst_state = target->get_inner_state();
    r = target->get_state(dst_state, false, assume_noent);
    if (r < 0) {
      ldout(store->ctx(), 0) << "ERROR: get target " << target->get_obj()
                             << " state return:" << r << dendl;
      return r;
    }

    if ((*dst_state)->exists) {
      wop.create(false);

      list<string> prefixes;
      cls_rgw_remove_obj(wop, prefixes);

      if (((*dst_state)->has_manifest || ((*dst_state)->obj_tag.length() != 0)) && (!(*dst_state)->fake_tag)) {
        wop.cmpxattr(RGW_ATTR_ID_TAG, LIBRADOS_CMPXATTR_OP_EQ, (*dst_state)->obj_tag);
      }
    }
  }

  RGWObjState* src_state = nullptr;
  RGWObjectCtx& ctx = source->get_ctx();
  r = store->get_obj_state(&ctx, source->get_bucket_info(), source->get_obj(), &src_state, false);
  if (r < 0)
    return r;
  if (src_state->data.length() > 0) {
    wop.write_full(src_state->data);
  }

  bufferlist bl;
  bl.append(dst_tag.c_str(), dst_tag.size() + 1);
  ldout(store->ctx(), 10) << "setting dst object id_tag=" << dst_tag << dendl;
  wop.setxattr(RGW_ATTR_ID_TAG, bl);

  change_owner_in_acl(ctx.s, src_state->attrset);

  for (auto iter = src_state->attrset.begin();
       iter != src_state->attrset.end(); ++iter) {
    const string& name = iter->first;
    if (name.compare(RGW_ATTR_ID_TAG) == 0)
      continue;
    bufferlist& bl = iter->second;

    if (!bl.length())
      continue;

    if (name.compare(RGW_ATTR_MANIFEST) == 0) {
      r = reset_manifest_by_rename(wop, bl);
      if (r < 0) {
        return r;
      }
      continue;
    }
    if (name.compare(RGW_ATTR_DELETED) == 0) {
      if (rgw_bl_to_str(bl).compare("true") == 0) {
        ldout(store->ctx(), 0) << "ERROR: src attr shouldn't has deleted"
                               << source->get_obj() << dendl;
        return -ENOENT;
      }
    }

    ldout(store->ctx(), 10) << "set attr[" << name << "]:" << rgw_bl_to_str(bl) << dendl;
    wop.setxattr(name.c_str(), bl);
  }

  bl.clear();
  bl.append(source->get_obj().key.name.c_str(), source->get_obj().key.name.size() + 1);
  wop.setxattr(string_view(RGW_ATTR_RENAME_DEST + src_tag).data(), bl);


  //TODO: check ref.verison
  r = target->operate_op(&wop);

  if (r < 0) {
    return r;
  }
  if (!assume_noent) {
    r = target->complete_atomic_modification();
    if (r < 0) {
      ldout(store->ctx(), 0) << __func__ << "() ERROR: complete_atomic_modification returned ret=" << r << dendl;
    }
  }
  return 0;
}

void RGWRados::Object::Rename::change_owner_in_acl(const req_state* s, map<std::string, bufferlist>& attrs) {
  if (!s) {
    ldout(store->ctx(), 0) << __func__ << "() ERROR req_state is nullptr" << dendl;
    return;
  }
  RGWAccessControlPolicy policy;
  int ret = rgw_policy_from_attrset(s->cct, attrs, &policy);
  if (ret < 0) {
    ldout(store->ctx(), 0) << "ERROR: couldn't get policy from attrs " << source->get_obj() << dendl;
    return;
  }

  if (policy.get_owner().get_id() != s->user->user_id) {
    policy.get_owner().set_id(s->user->user_id);
    policy.get_owner().set_name(s->user->display_name);

    bufferlist new_bl;
    encode(policy, new_bl);
    attrs[RGW_ATTR_ACL] = new_bl;
  }
}


void RGWRados::Object::Rename::rename_backward_operation(
    const string& dst_tag,
    RGWRados::Bucket::UpdateIndex* src_idx,
    RGWRados::Bucket::UpdateIndex* dst_idx) {
  int ret = 0;
  switch(progress) {
    case DONE_DST_IDX:
      if (dst_idx) {
        ret = dst_idx->cancel();
        if (ret < 0) {
          ldout(store->ctx(), 0) << "ERROR: update dst index cancel() return:" << ret << dendl;
        }
      }
    case DONE_SRC_ATTR:
      clear_rename_attr(dst_tag);
    case DONE_SRC_IDX:
      if (src_idx) {
        ret = src_idx->cancel();
        if (ret < 0) {
          ldout(store->ctx(), 0) << "ERROR: update src index cancel() return:" << ret << dendl;
        }
      }
      break;
    default:
      ldout(store->ctx(), 0) << "ERROR: invalid rename progress bar:" << progress << dendl;
      break;
  }
}

bool can_replace_renaming(const RGWRenameSrcInfo& rename_info,
                          uint64_t rename_timeout_threshold) {
  if (mono_clock::now() >
      rgw_client.update_time + make_timespan(2 * UPDATE_RGWS_INTERVAL)) {
    if (try_refresh_client_id() < 0) {
      return false;
    }
  }

  rgw_client.lock.get_read();
  if (rgw_client.rgws.size() == 1 &&
      rgw_client.rgw_client_id.compare(RGW_ADMIN_CLIENT_ID) == 0) {
    // run radosgw-admin process, couldn't replace renaming
    rgw_client.lock.unlock();
    return false;
  }

  auto iter = rgw_client.rgws.find(rename_info.client_id);
  if (iter != rgw_client.rgws.end()) {
    dout(20) << __func__ << "() rgw alive:" << rename_info.client_id << dendl;
    rgw_client.lock.unlock();
    return false;
  }
  rgw_client.lock.unlock();

  // get rgws again, avoid local machine clock skew bigger than rename_timeout_threshold
  if (mono_clock::now() < rgw_client.update_time + make_timespan(rename_timeout_threshold)) {
    srand(time(NULL));
    std::this_thread::sleep_for(std::chrono::milliseconds(rand() % 3000));
  }
  if (try_refresh_client_id() < 0) {
    return false;
  }
  rgw_client.lock.get_read();
  iter = rgw_client.rgws.find(rename_info.client_id);
  if (iter != rgw_client.rgws.end()) {
    dout(20) << __func__ << "() refresh clients again, find rgw alive:" << rename_info.client_id << dendl;
    rgw_client.lock.unlock();
    return false;
  }
  rgw_client.lock.unlock();
  dout(20) << __func__ << "() couldn't find rgw in rgws:" << rename_info.client_id << dendl;
  return true;
}

int RGWRados::process_src_renaming_attr(RGWObjectCtx *obj_ctx,
                                        RGWObjState* s,
                                        const RGWBucketInfo& bucket_info,
                                        map<string, bufferlist>::iterator& iter,
                                        int& result) {
  // process rn_s_ xattr
  int ret = 0;

  bufferlist::iterator miter = iter->second.begin();
  RGWRenameSrcInfo rename_info;

  try {
    decode(rename_info, miter);
  } catch (buffer::error& err) {
    ldout(cct, 0) << "ERROR: couldn't decode rename info, object:" << s->obj << dendl;
    return -EIO;
  }

  bool can_replace = can_replace_renaming(rename_info, cct->_conf->rgw_append_timeout);

  rgw_obj dst_obj(bucket_info.bucket, rename_info.dst_object);

  RGWObjState *dst_s = obj_ctx->obj.get_state(dst_obj);
  ldout(cct, 20) << "get_obj_state obj=" << dst_obj << " state="
                 << (void *)dst_s << " dst_s->prefetch_data="
                 << dst_s->prefetch_data << dendl;

  // get dst obj state
  if (dst_s->has_attrs) {
    ldout(cct, 10) << "get_obj_state from cache obj=" << dst_obj << dendl;

  } else {

    ret = get_obj_state(obj_ctx, bucket_info, dst_obj, &dst_s, false,
                        false, true);
    if (ret < 0) {
      ldout(cct, 0) << "ERROR get_obj_state obj=" << dst_obj
                    << " return=" << ret << dendl;
      // continue process other renaming xattr, instead of break loop right now
      return 0;
    }

    if (!dst_s->exists) {
      ldout(cct, 10) << "get_obj_state obj=" << dst_obj
                     << " return=" << ret
                     << dendl;
      if (rename_info.src_idtag.compare(rgw_bl_to_str(s->attrset[RGW_ATTR_ID_TAG])) == 0) {
        // this renaming operation is newest
        result = 0;
        ldout(cct, 10) << "id_tag in rename source attr match self attr, result:" << result << dendl;
      }
      if (can_replace) {
        // clear src rn xattr, when rgw not exist and timeout

        ldout(cct, 10) << "clear rename source attr, obj:" << s->obj << dendl;
        ret = remove_attr(obj_ctx, bucket_info, s->obj, s->attrset, iter->first, true);
        if (ret < 0 && ret != -ENOENT) {
          ldout(cct, 0) << "ERROR set_attrs obj=" << dst_obj
                        << " return=" << ret << dendl;
        }
      }
      return 0;
    }
  }

  auto it_dst = dst_s->attrset.find(RGW_ATTR_RENAME_DEST + rename_info.src_idtag);
  if (it_dst != dst_s->attrset.end()) {
    // have renamed successfully
    if (rename_info.src_idtag.compare(rgw_bl_to_str(s->attrset[RGW_ATTR_ID_TAG])) == 0) {
      // remove src obj, when rgw not exist and timeout
      result = -ENOENT;
      ldout(cct, 10) << "src obj id_tag ("
                     << rgw_bl_to_str(s->attrset[RGW_ATTR_ID_TAG])
                     << ") exists in attrs of dst obj:"<< dst_obj
                     << ", get src obj result:" << result << dendl;

      if (can_replace) {
        ldout(cct, 10) << " delete obj obj=" << s->obj << dendl;

        ret = delete_obj(*obj_ctx, bucket_info, s->obj, 0, true, 0,
                         ceph::real_time(), nullptr, true, &(s->mtime));
        if (ret < 0) {
          ldout(cct, 10) << "ERROR delete obj obj=" << s->obj << " return=" << ret << dendl;
          if (ret != -ENOENT && ret != -ERR_PRECONDITION_FAILED) {
            // only clear dst rn xattr when clear src obj successfully
            return 0;
          }
        }
      }
    } else {
      // clear src rn xattr, when rgw not exist and timeout
      if (can_replace) {
        ldout(cct, 10) << "renaming timeout, clear src rn xattr obj=" << s->obj << dendl;
        ret = remove_attr(obj_ctx, bucket_info, s->obj, s->attrset, iter->first, true);
        if (ret < 0 && ret != -ENOENT) {
          ldout(cct, 0) << "ERROR set_attrs obj=" << s->obj << " return=" << ret << dendl;
          // only clear dst rn xattr when clear src rn xattr successfully
          return 0;
        }
      }
    }

    if (can_replace) {
      // clear dst rn xattr

      ldout(cct, 10) << "renaming timeout, clear dst rn xattr obj=" << dst_obj << dendl;
      ret = remove_attr(obj_ctx, bucket_info, dst_obj, dst_s->attrset, RGW_ATTR_RENAME_DEST + rename_info.src_idtag, true);
      if (ret < 0 && ret != -ENOENT) {
        ldout(cct, 0) << "ERROR set_attrs obj=" << dst_obj << " return=" << ret << dendl;
      }
    }

  } else {

    ldout(cct, 10) << "rename_info.src_idtag (" << rename_info.src_idtag
                   << ") no exists in attrs of dst obj:"<< dst_obj
                   << ") s attrset addr:"<< &(s->attrset)<<dendl;
    bufferlist bl = s->attrset[RGW_ATTR_ID_TAG];
    ldout(cct, 10) << " s attrset idtag:"<< bl.to_str() << dendl;
    if (rename_info.src_idtag.compare(s->attrset[RGW_ATTR_ID_TAG].to_str()) == 0) {
      result = 0;
      ldout(cct, 10) << "src obj id_tag (" << s->attrset[RGW_ATTR_ID_TAG].to_str() << ") no exists in attrs of dst obj:"<< dst_obj << ", get src obj result:" << result << dendl;
    }

    if (can_replace) {
      // clear src rn xattr
      ldout(cct, 10) << "renaming timeout, clear src rn xattr obj=" << s->obj << dendl;
      ret = remove_attr(obj_ctx, bucket_info, s->obj, s->attrset, iter->first, true);
      if (ret < 0 && ret != -ENOENT) {
        ldout(cct, 0) << "ERROR set_attrs obj=" << s->obj << " return=" << ret << dendl;
        return 0;
      }
      // no need cancel src idx here, because list op also call get_obj_state()
      // we return -ENOENT -> bring astate->exist to false -> cls_rgw_encode_suggestion outside
      if (rename_info.src_idtag.compare(rgw_bl_to_str(s->attrset[RGW_ATTR_ID_TAG])) != 0) {
        // clear tail obj recorded in rename_info's manifest
        ldout(cct, 10) << "renaming manifest is not newest, clear tail_obj obj=" << dst_obj << dendl;
        cls_rgw_obj_chain chain;
        update_gc_chain(s->obj, *(rename_info.manifest), &chain, s);

        if (!chain.empty()) {
          string tag = (s->tail_tag.length() > 0 ? rgw_bl_to_str(s->tail_tag) : rgw_bl_to_str(s->obj_tag));
          char buf[11];
          gen_rand_alphanumeric(cct, buf, sizeof(buf) - 1);
          tag.append("#");
          tag.append(buf);
          send_chain_to_gc(chain, tag, false);
        }
      }
    }
  }
  return 0;
}

int RGWRados::process_dst_renaming_attr(RGWObjectCtx *obj_ctx,
                                        RGWObjState* s,
                                        const RGWBucketInfo& bucket_info,
                                        map<string, bufferlist>::iterator& iter) {
  // process rn_d_ xattr
  int ret = 0;
  string src_idtag = iter->first.substr(strlen(RGW_ATTR_RENAME_DEST));
  ldout(cct, 20) << "process rename dst attr:" << iter->first
                 << ", src_idtag:" << src_idtag << dendl;
  rgw_obj src_obj(bucket_info.bucket, rgw_bl_to_str(iter->second));

  RGWObjState *src_s = obj_ctx->obj.get_state(src_obj);
  ldout(cct, 20) << "get_obj_state obj=" << src_obj << " state="
                 << (void *)src_s << " src_s->prefetch_data="
                 << src_s->prefetch_data << dendl;

  // get src obj state
  if (src_s->has_attrs) {
    ldout(cct, 10) << "get_obj_state from cache obj=" << src_obj << dendl;
  } else {
    ldout(cct, 10) << "fetch rename sourc obj state obj=" << src_obj << dendl;
    ret = get_obj_state(obj_ctx, bucket_info, src_obj, &src_s, false);
    if (ret < 0) {
      ldout(cct, 0) << "ERROR get_obj_state obj=" << src_obj << " return=" << ret << dendl;
      // continue process other renaming xattr, instead of break loop right now
      return 0;
    }

    ldout(cct, 30) << "get src obj state: ret " << ret << " src_s->exists:" << src_s->exists << dendl;
    if (!(src_s->exists)) {
      // clear dst rn xattr
      ldout(cct, 10) << "src obj no exist " << src_obj << ", clear rename dst xattr, dst obj:" << s->obj << dendl;
      ret = remove_attr(obj_ctx, bucket_info, s->obj, s->attrset, iter->first, true);
      if (ret < 0 && ret != -ENOENT) {
        ldout(cct, 0) << "ERROR set_attrs obj=" << s->obj << " return=" << ret << dendl;
      }
      return 0;
    }
  }

  if (src_idtag.compare(rgw_bl_to_str(src_s->attrset[RGW_ATTR_ID_TAG])) == 0) {
    // remove src obj

    ldout(cct, 10) << "rename success, delete src obj:" << src_obj << ", dst obj:" << s->obj << dendl;
    // have done get_obj_state(process src_obj renaming attrs)
    // here delete obj directly regardless of renaming attrs
    ret = delete_obj(*obj_ctx, bucket_info, src_obj, 0, true, 0, ceph::real_time(), nullptr, true, &(src_s->mtime));
    if (ret < 0 && ret != -ENOENT) {
      ldout(cct, 0) << "ERROR delete obj=" << src_obj << " return=" << ret << dendl;
      if (ret != -ERR_PRECONDITION_FAILED) {
        // only clear dst rn xattr when remove src obj successfully
        return 0;
      }
    }

    // clear dst rn xattr
    ldout(cct, 10) << "clear dst rn xattr obj=" << s->obj << dendl;
    ret = remove_attr(obj_ctx, bucket_info, s->obj, s->attrset, iter->first, true);
    if (ret < 0 && ret != -ENOENT) {
      ldout(cct, 0) << "ERROR clear dst rn xattr obj=" << s->obj
                    << " return=" << ret << dendl;
    }

  } else {
    // src_idtag is not newest, just clear this src_idtag instead of remove
    // src obj
    ldout(cct, 10) << "rename success, clear rename src xattr, src obj:" << src_obj
                   << ", dst obj:" << s->obj
                   << ", id_tag in dst:" << src_idtag
                   << ", id_tag of src obj:" << rgw_bl_to_str(src_s->attrset[RGW_ATTR_ID_TAG])
                   << dendl;
    string renaming_info_key = "";
    std::tie(ret, renaming_info_key) = get_renaming_info(src_s->attrset, src_idtag);
    if (ret < 0) return ret;
    if (ret == 0) {
      // clear src rn xattr
      ret = remove_attr(obj_ctx, bucket_info, src_obj, src_s->attrset, renaming_info_key, true);
      if (ret < 0 && ret != -ENOENT) {
        ldout(cct, 0) << "ERROR set_attrs obj=" << src_obj << " return=" << ret << dendl;
      } else {
        // clear dst rn xattr
        ldout(cct, 10) << "clear dst rn xattr obj=" << s->obj << dendl;
        ret = remove_attr(obj_ctx, bucket_info, s->obj, s->attrset, iter->first, true);
        if (ret < 0 && ret != -ENOENT) {
          ldout(cct, 0) << "ERROR clear dst rn xattr obj=" << s->obj
                        << " return=" << ret << dendl;
        }
      }
    } else {
      // src_idtag not exist in renaming info, just clear dst rn xattr
      ldout(cct, 10) << "src_idtag(" << src_idtag << ") not exists in renaming_info,"
                     << " just clear dst rn xattr obj=" << s->obj << dendl;
      ret = remove_attr(obj_ctx, bucket_info, s->obj, s->attrset, iter->first, true);
      if (ret < 0 && ret != -ENOENT) {
        ldout(cct, 0) << "ERROR clear dst rn xattr obj=" << s->obj
                      << " return=" << ret << dendl;
      }
    }
  } // renaming src_idtag isn't newest
  return 0;
}

int RGWRados::check_renaming_state(RGWObjectCtx *obj_ctx, RGWObjState* s, const RGWBucketInfo& bucket_info) {
  int result = 0;  // only update it when src_idtag == newest id_tag in attrs
  int ret = 0;

  if (rgw_client.rgws.empty()) {
    ret = try_refresh_client_id();
    if (ret < 0) {
      ldout(cct, 0) << __func__ << "() ERROR: try_refresh_client_id ret:" << ret << dendl;
      return ret;
    }
  }

  map<string, bufferlist> rn_attrs;

  for (auto iter = s->attrset.lower_bound(RGW_ATTR_RENAME_PREFIX);
       iter != s->attrset.end(); ++iter) {
    if (!boost::algorithm::starts_with(iter->first, RGW_ATTR_RENAME_PREFIX))
      break;
    rn_attrs[iter->first] = iter->second;
  }


  for (map<string, bufferlist>::iterator iter = rn_attrs.begin();
      iter != rn_attrs.end(); ++iter) {
    ldout(cct, 20) << __func__ << "() renaming obj:" << s->obj
                   << " attr:" << iter->first << dendl;


    if (boost::algorithm::starts_with(iter->first, RGW_ATTR_RENAME_SOURCE)) {
      ret = process_src_renaming_attr(obj_ctx, s, bucket_info, iter, result);
      if (ret < 0) {
        ldout(cct, 0) << __func__ << "() ERROR: process src rename xattr "
                      << iter->first << " error:" << ret << dendl;
        return ret;
      }

    } else if (boost::algorithm::starts_with(iter->first, RGW_ATTR_RENAME_DEST)) {
      ret = process_dst_renaming_attr(obj_ctx, s, bucket_info, iter);
      if (ret < 0) {
        ldout(cct, 0) << __func__ << "() ERROR: process dst rename xattr "
                      << iter->first << " error:" << ret << dendl;
        return ret;
      }
    }
  }
  return result;
}

/**
 * Copy an object.
 * dest_obj: the object to copy into
 * src_obj: the object to copy from
 * attrs: usage depends on attrs_mod parameter
 * attrs_mod: the modification mode of the attrs, may have the following values:
 *            ATTRSMOD_NONE - the attributes of the source object will be
 *                            copied without modifications, attrs parameter is ignored;
 *            ATTRSMOD_REPLACE - new object will have the attributes provided by attrs
 *                               parameter, source object attributes are not copied;
 *            ATTRSMOD_MERGE - any conflicting meta keys on the source object's attributes
 *                             are overwritten by values contained in attrs parameter.
 * err: stores any errors resulting from the get of the original object
 * Returns: 0 on success, -ERR# otherwise.
 */
int RGWRados::copy_obj(RGWObjectCtx& obj_ctx,
               const rgw_user& user_id,
               const string& client_id,
               const string& op_id,
               req_info *info,
               const string& source_zone,
               rgw_obj& dest_obj,
               rgw_obj& src_obj,
               RGWBucketInfo& dest_bucket_info,
               RGWBucketInfo& src_bucket_info,
               const rgw_placement_rule& dest_placement,
               real_time *src_mtime,
               real_time *mtime,
               const real_time *mod_ptr,
               const real_time *unmod_ptr,
               bool high_precision_time,
               const char *if_match,
               const char *if_nomatch,
               const char *md_directive,
               AttrsMod attrs_mod,
               bool copy_if_newer,
               map<string, bufferlist>& attrs,
               RGWObjCategory category,
               uint64_t olh_epoch,
               real_time delete_at,
               string *version_id,
               string *ptag,
               string *petag,
               void (*progress_cb)(off_t, void *),
               void *progress_data,
               RGWQuotaInfo& user_quota,
               RGWQuotaInfo& bucket_quota)
{
  int ret;
  uint64_t obj_size;
  rgw_obj shadow_obj = dest_obj;
  string shadow_oid;

  bool remote_src;
  bool remote_dest;

  append_rand_alpha(cct, dest_obj.get_oid(), shadow_oid, 32);
  shadow_obj.init_ns(dest_obj.bucket, shadow_oid, shadow_ns);

  remote_dest = !get_zonegroup().equals(dest_bucket_info.zonegroup);
  remote_src = !get_zonegroup().equals(src_bucket_info.zonegroup);

  if (remote_src && remote_dest) {
    ldout(cct, 0) << "ERROR: can't copy object when both src and dest buckets are remote" << dendl;
    return -EINVAL;
  }

  ldout(cct, 5) << "Copy object " << src_obj.bucket << ":" << src_obj.get_oid()
                << " => " << dest_obj.bucket << ":" << dest_obj.get_oid() << dendl;

  if (remote_src || !source_zone.empty()) {
    return fetch_remote_obj(obj_ctx, user_id, client_id, op_id, true, info, source_zone,
               dest_obj, src_obj, dest_bucket_info, src_bucket_info,
               dest_placement, src_mtime, mtime, mod_ptr,
               unmod_ptr, high_precision_time,
               if_match, if_nomatch, attrs_mod, copy_if_newer, attrs, category,
               olh_epoch, delete_at, version_id, ptag, petag, progress_cb, progress_data);
  }

  map<string, bufferlist> src_attrs;
  RGWRados::Object src_op_target(this, src_bucket_info, obj_ctx, src_obj);
  RGWRados::Object::Read read_op(&src_op_target);

  read_op.conds.mod_ptr = mod_ptr;
  read_op.conds.unmod_ptr = unmod_ptr;
  read_op.conds.high_precision_time = high_precision_time;
  read_op.conds.if_match = if_match;
  read_op.conds.if_nomatch = if_nomatch;
  read_op.params.attrs = &src_attrs;
  read_op.params.lastmod = src_mtime;
  read_op.params.obj_size = &obj_size;

  ret = read_op.prepare();
  if (ret < 0) {
    return ret;
  }

  if (src_attrs.count(RGW_ATTR_CRYPT_MODE) && md_directive && strcasecmp(md_directive, "REPLACE") == 0) {
    // Current implementation does not follow S3 spec and even
    // may result in data corruption silently when copying
    // multipart objects acorss pools. So reject COPY operations
    //on encrypted objects before it is fully functional.
    ldout(cct, 0) << __func__ << "(): ERROR: copy op for encrypted object " << src_obj
                  << " don't support replace mode." << dendl;
    return -EINVAL;
  }

  if (src_attrs.count(RGW_ATTR_DELETED)) {
    bufferlist deleted_bl = src_attrs[RGW_ATTR_DELETED];
    if (deleted_bl.to_str().compare("true") == 0) {
      return -ENOENT;
    }
  }

  if (src_attrs.count(RGW_ATTR_DELETED)) {
    bufferlist deleted_bl = src_attrs[RGW_ATTR_DELETED];
    if (deleted_bl.to_str().compare("true") == 0) {
      return -ENOENT;
    }
  }

  src_attrs[RGW_ATTR_ACL] = attrs[RGW_ATTR_ACL];
  src_attrs.erase(RGW_ATTR_DELETE_AT);
  src_attrs.erase(RGW_ATTR_STORAGE_CLASS);
  src_attrs.erase(RGW_ATTR_OBJECT_RETENTION);
  src_attrs.erase(RGW_ATTR_OBJECT_LEGAL_HOLD);
  auto iter = attrs.find(RGW_ATTR_OBJECT_RETENTION);
  if (iter != attrs.end()) {
    src_attrs[RGW_ATTR_OBJECT_RETENTION] = iter->second;
  }
  iter = attrs.find(RGW_ATTR_OBJECT_LEGAL_HOLD);
  if (iter != attrs.end()) {
    src_attrs[RGW_ATTR_OBJECT_LEGAL_HOLD] = attrs[RGW_ATTR_OBJECT_LEGAL_HOLD];
  }

  set_copy_attrs(src_attrs, attrs, attrs_mod);
  attrs.erase(RGW_ATTR_ID_TAG);
  attrs.erase(RGW_ATTR_PG_VER);
  attrs.erase(RGW_ATTR_SOURCE_ZONE);
  map<string, bufferlist>::iterator cmp = src_attrs.find(RGW_ATTR_COMPRESSION);
  if (cmp != src_attrs.end())
    attrs[RGW_ATTR_COMPRESSION] = cmp->second;

  RGWObjManifest manifest;
  RGWObjState *astate = NULL;

  ret = get_obj_state(&obj_ctx, src_bucket_info, src_obj, &astate);
  if (ret < 0) {
    return ret;
  }

  vector<rgw_raw_obj> ref_objs;

  if (remote_dest) {
    /* dest is in a different zonegroup, copy it there */
    return copy_obj_to_remote_dest(astate, attrs, read_op, user_id, dest_obj, mtime);
  }
  uint64_t max_chunk_size;

  for (auto& kv: attrs) {
    ldout(cct, 10) << "attr:" <<  kv.first << ": " << kv.second.c_str() << dendl;
  }

  ret = get_max_chunk_size(dest_bucket_info.head_placement_rule, dest_obj, &max_chunk_size);
  if (ret < 0) {
    ldout(cct, 0) << "ERROR: failed to get max_chunk_size() for bucket " << dest_obj.bucket << dendl;
    return ret;
  }

  rgw_pool src_pool;
  rgw_pool dest_pool;

  const rgw_placement_rule *src_rule{nullptr};

  if (astate->has_manifest) {
    src_rule = &astate->manifest.get_tail_placement().placement_rule;
    ldout(cct, 20) << __func__ << "(): manifest src_rule=" << src_rule->to_str() << dendl;
  }

  if (!src_rule || src_rule->empty()) {
    src_rule = &src_bucket_info.head_placement_rule;
  }

  if (!get_obj_data_pool(*src_rule, src_obj, &src_pool)) {
    ldout(cct, 0) << "ERROR: failed to locate data pool for " << src_obj << dendl;
    return -EIO;
  }

  if (!get_obj_data_pool(dest_placement, dest_obj, &dest_pool)) {
    ldout(cct, 0) << "ERROR: failed to locate data pool for " << dest_obj << dendl;
    return -EIO;
  }

  ldout(cct, 20) << " src_rule=" << src_rule->to_str() << " src_pool=" << src_pool
                 << " dest_rule=" << dest_placement.to_str() << " dest_pool=" << dest_pool << dendl;

  bool copy_data = !astate->has_manifest || (*src_rule != dest_placement) || (src_pool != dest_pool);
  bool copy_first = false;
  if (astate->has_manifest) {
    if (!astate->manifest.has_tail()) {
      copy_data = true;
    } else {
      uint64_t head_size = astate->manifest.get_head_size();

      if (head_size > 0) {
        if (head_size > max_chunk_size) {
          copy_data = true;
        } else {
          copy_first = true;
        }
      }
    }
  }

  if (petag) {
    const auto iter = attrs.find(RGW_ATTR_ETAG);
    if (iter != attrs.end()) {
      *petag = iter->second.to_str();
    }
  }

  ret = check_quota(user_id, dest_bucket_info.bucket, user_quota,  bucket_quota, obj_size);
  if (ret < 0) {
    return ret;
  }
  if (copy_data) { /* refcounting tail wouldn't work here, just copy the data */
    attrs.erase(RGW_ATTR_TAIL_TAG);
    return copy_obj_data(obj_ctx, dest_bucket_info, dest_placement, read_op, obj_size - 1, dest_obj,
                         mtime, real_time(), attrs, olh_epoch, delete_at, version_id, petag);
  }

  RGWObjManifest::obj_iterator miter = astate->manifest.obj_begin();

  if (copy_first) { // we need to copy first chunk, not increase refcount
    ++miter;
  }

  rgw_rados_ref ref;
  ret = get_raw_obj_ref(miter.get_location().get_raw_obj(this), &ref);
  if (ret < 0) {
    return ret;
  }

  if (version_id && !version_id->empty()) {
    dest_obj.key.set_instance(*version_id);
  } else if (dest_bucket_info.versioning_enabled()) {
    gen_rand_obj_instance_name(&dest_obj);
  }

  bufferlist first_chunk;

  bool copy_itself = (dest_obj == src_obj);
  RGWObjManifest *pmanifest; 
  ldout(cct, 20) << "dest_obj=" << dest_obj << " src_obj=" << src_obj << " copy_itself=" << (int)copy_itself << dendl;

  RGWRados::Object dest_op_target(this, dest_bucket_info, obj_ctx, dest_obj);
  RGWRados::Object::Write write_op(&dest_op_target);

  string tag;

  if (ptag) {
    tag = *ptag;
  }

  if (tag.empty()) {
    append_rand_alpha(cct, tag, tag, 32);
  }

  RGWIOManager<rgw_raw_obj> io_manager(cct, &ref_objs, cct->_conf->rgw_max_copy_obj_concurrent_io);
  if (!copy_itself) {
    attrs.erase(RGW_ATTR_TAIL_TAG);
    manifest = astate->manifest;
    const rgw_bucket_placement& tail_placement = manifest.get_tail_placement();
    if (tail_placement.bucket.name.empty()) {
      manifest.set_tail_placement(tail_placement.placement_rule, src_obj.bucket);
    }
    
    string ref_tag;
    for (; miter != astate->manifest.obj_end(); ++miter) {
      ObjectWriteOperation op;
      bool is_head_obj = false;
      ref_tag = tag + '\0';
      cls_refcount_get(op, ref_tag, true);
      const rgw_raw_obj& loc = miter.get_location().get_raw_obj(this);
      ref.ioctx.locator_set_key(loc.loc);

      /* should check whether raw_obj is head_obj */
      if (!is_tail_obj_key(loc.oid)) {
        is_head_obj = true;
        ldout(cct, 0) << "ERROR: copy obj couldnot set head_obj refcount, oid=" << loc.oid << dendl;
      }

      ret = io_manager.schedule_io(&ref.ioctx, loc.oid, &op, loc, is_head_obj, astate->manifest.is_enable_skip_cache());
      if (ret < 0) {
        ldout(cct, 0) << "ERROR: failed to schedule_io on obj=" << loc.oid << ", the error code = " << ret << dendl;
        goto done_ret;
      }
    }

    ret = io_manager.drain_ios();
    if (ret < 0) {
      ldout(cct, 0) << "ERROR: failed to drain_ios, the error code = " << ret <<dendl;
      goto done_ret;
    }

    pmanifest = &manifest;
  } else {
    pmanifest = &astate->manifest;
    /* don't send the object's tail for garbage collection */
    astate->keep_tail = true;
  }

  if (copy_first) {
    ret = read_op.read(0, max_chunk_size, first_chunk);
    if (ret < 0) {
      goto done_ret;
    }

    pmanifest->set_head(dest_bucket_info.head_placement_rule, dest_obj, first_chunk.length());
  } else {
    pmanifest->set_head(dest_bucket_info.head_placement_rule, dest_obj, 0);
  }

  write_op.meta.data = &first_chunk;
  write_op.meta.manifest = pmanifest;
  write_op.meta.ptag = &tag;
  write_op.meta.owner = dest_bucket_info.owner;
  write_op.meta.mtime = mtime;
  write_op.meta.flags = PUT_OBJ_CREATE;
  write_op.meta.category = category;
  write_op.meta.olh_epoch = olh_epoch;
  write_op.meta.delete_at = delete_at;
  write_op.meta.modify_tail = !copy_itself;
  write_op.meta.storage_class = dest_placement.storage_class;
  write_op.meta.head_placement_rule = dest_bucket_info.head_placement_rule;
  iter = attrs.find(RGW_ATTR_TAGS);
  if (iter != attrs.end() && iter->second.length() > 0) {
    write_op.meta.tags_bl = &(iter->second);
  }

  ret = write_op.write_meta(obj_size, astate->accounted_size, attrs);
  if (ret < 0) {
    goto done_ret;
  }

  return 0;

done_ret:
  io_manager.drain_ios();
  if (!copy_itself) {
    vector<rgw_raw_obj>::iterator riter;

    /* rollback reference */
    string ref_tag = tag + '\0';
    for (riter = ref_objs.begin(); riter != ref_objs.end(); ++riter) {
      ObjectWriteOperation op;
      cls_refcount_put(op, ref_tag, true);

      ref.ioctx.locator_set_key(riter->loc);

      int r = ref.ioctx.operate(riter->oid, &op);
      if (r < 0) {
        ldout(cct, 0) << "ERROR: cleanup after error failed to drop reference on obj=" << *riter << dendl;
      }
    }
  }
  return ret;
}


int RGWRados::copy_obj_data(RGWObjectCtx& obj_ctx,
               RGWBucketInfo& dest_bucket_info,
               const rgw_placement_rule& dest_placement,
               RGWRados::Object::Read& read_op, off_t end,
               rgw_obj& dest_obj,
               real_time *mtime,
               real_time set_mtime,
               map<string, bufferlist>& attrs,
               uint64_t olh_epoch,
               real_time delete_at,
               const string *version_id,
               string *petag)
{
  string tag;
  append_rand_alpha(cct, tag, tag, 32);

  RGWPutObjProcessor_Atomic processor(obj_ctx,
                                      dest_bucket_info, dest_obj.bucket, dest_obj.key.name,
                                      cct->_conf->rgw_obj_stripe_size, tag, dest_bucket_info.versioning_enabled());
  if (version_id) {
    processor.set_version_id(*version_id);
  }
  processor.set_placement_rule(dest_placement);
  processor.set_olh_epoch(olh_epoch);
  processor.set_unknown_actual_size(true);
  processor.set_content_length(cct->_conf->rgw_file_shuntflow_size);
  processor.set_skip_cache_flag(cct->_conf->rgw_enable_skip_cachepool);
  processor.set_file_shuntflow_size(cct->_conf->rgw_file_shuntflow_size);

  int ret = processor.prepare(this, NULL);
  if (ret < 0)
    return ret;

  dest_obj.key.set_instance(processor.get_version_id());

  off_t ofs = 0;

  do {
    bufferlist bl;
    ret = read_op.read(ofs, end, bl);
    if (ret < 0) {
      ldout(cct, 0) << "ERROR: fail to read object data, ret = " << ret << dendl;
      return ret;
    }

    uint64_t read_len = ret;
    bool again;

    do {
      void *handle;
      rgw_raw_obj obj;

      ret = processor.handle_data(bl, ofs, &handle, &obj, &again);
      if (ret < 0) {
        return ret;
      }
      ret = processor.throttle_data(handle, obj, read_len, false);
      if (ret < 0)
        return ret;
    } while (again);

    ofs += read_len;
  } while (ofs <= end);

  string etag;
  auto iter = attrs.find(RGW_ATTR_ETAG);
  if (iter != attrs.end()) {
    bufferlist& bl = iter->second;
    etag = bl.to_str();
    if (petag) {
      *petag = etag;
    }
  }

  uint64_t accounted_size;
  {
    bool compressed{false};
    RGWCompressionInfo cs_info;
    ret = rgw_compression_info_from_attrset(attrs, compressed, cs_info);
    if (ret < 0) {
      ldout(cct, 0) << "ERROR: failed to read compression info" << dendl;
      return ret;
    }
    // pass original size if compressed
    accounted_size = compressed ? cs_info.orig_size : ofs;
  }

  return processor.complete(accounted_size, etag, mtime, set_mtime, attrs, delete_at);
}

int RGWRados::transition_obj(RGWObjectCtx& obj_ctx,
                             RGWBucketInfo& bucket_info,
                             rgw_obj& obj,
                             const rgw_placement_rule& placement_rule,
                             const real_time& mtime,
                             uint64_t olh_epoch) {
  map<string, bufferlist> attrs;
  real_time read_mtime;
  uint64_t obj_size;

  RGWRados::Object op_target(this, bucket_info, obj_ctx, obj);
  RGWRados::Object::Read read_op(&op_target);

  read_op.params.attrs = &attrs;
  read_op.params.lastmod = &read_mtime;
  read_op.params.obj_size = &obj_size;

  int ret = read_op.prepare();
  if (ret < 0) {
    return ret;
  }

  if (read_mtime != mtime) {
    ldout(cct, 20) << __func__ << "() INFO read_mtime=" << read_mtime
                   << " not match mtime=" << mtime << dendl;
    /* raced */
    return -ECANCELED;
  }

  string tag;
  append_rand_alpha(cct, tag, tag, 32);

  RGWPutObjProcessor_Atomic processor(obj_ctx,
                                      bucket_info, obj.bucket, obj.key.name,
                                      cct->_conf->rgw_obj_stripe_size, tag, 
                                      bucket_info.versioning_enabled());
  processor.set_version_id(obj.key.get_instance());
  processor.set_placement_rule(placement_rule);
  processor.set_olh_epoch(olh_epoch);
  processor.set_is_transition(true);
  processor.set_unknown_actual_size(true);
  processor.set_content_length(cct->_conf->rgw_file_shuntflow_size);
  processor.set_skip_cache_flag(cct->_conf->rgw_enable_skip_cachepool);
  processor.set_file_shuntflow_size(cct->_conf->rgw_file_shuntflow_size);
  ret = processor.prepare(this, NULL);
  if (ret < 0)
    return ret;

  off_t ofs = 0;
  off_t end = obj_size - 1;

  do {
    bufferlist bl;
    ret = read_op.read(ofs, end, bl);
    if (ret < 0) {
      ldout(cct, 0) << "ERROR: fail to read object data, ret = " << ret << dendl;
      return ret;
    }

    uint64_t read_len = ret;
    bool again;

    do {
      void *handle;
      rgw_raw_obj obj;

      ret = processor.handle_data(bl, ofs, &handle, &obj, &again);
      if (ret < 0) {
        ldout(cct, 10) << "ERROR: fail to handle data, ret = " << ret << dendl;
        return ret;
      }
      ret = processor.throttle_data(handle, obj, read_len, false);
      if (ret < 0) {
        ldout(cct, 10) << "ERROR: fail to throttle data, ret = " << ret << dendl;
        return ret;
      }
    } while (again);

    ofs += read_len;
  } while (ofs <= end);

  string etag;
  auto iter = attrs.find(RGW_ATTR_ETAG);
  if (iter != attrs.end()) {
    bufferlist& bl = iter->second;
    etag = bl.to_str();
  }

  uint64_t accounted_size;
  {
    bool compressed{false};
    RGWCompressionInfo cs_info;
    ret = rgw_compression_info_from_attrset(attrs, compressed, cs_info);
    if (ret < 0) {
      ldout(cct, 0) << "ERROR: failed to read compression info" << dendl;
      return ret;
    }
    // pass original size if compressed
    accounted_size = compressed ? cs_info.orig_size : ofs;
  }

  return processor.complete(accounted_size, etag, nullptr, mtime, attrs, real_time());
}

bool RGWRados::is_meta_master()
{
  if (!get_zonegroup().is_master_zonegroup()) {
    return false;
  }

  return (get_zonegroup().master_zone == zone_public_config.id);
}

/**
  * Check to see if the bucket metadata could be synced
  * bucket: the bucket to check
  * Returns false is the bucket is not synced
  */
bool RGWRados::is_syncing_bucket_meta(const rgw_bucket& bucket)
{
  /* ignore sync if bucket meta clear flag is set */
  if (cct->_conf->rgw_multisite_bucket_clear_flag) {
    return false;
  }

  /* no current period  */
  if (current_period.get_id().empty()) {
    return false;
  }

  /* zonegroup is not master zonegroup */
  if (!get_zonegroup().is_master_zonegroup()) {
    return false;
  }

  /* single zonegroup and a single zone */
  if (current_period.is_single_zonegroup() && get_zonegroup().zones.size() == 1) {
    return false;
  }

  /* zone is not master */
  if (get_zonegroup().master_zone.compare(zone_public_config.id) != 0) {
    return false;
  }

  return true;
}

int RGWRados::check_bucket_empty(RGWBucketInfo& bucket_info)
{
  std::vector<rgw_bucket_dir_entry> ent_list;
  rgw_obj_index_key marker;
  string prefix;
  bool is_truncated;
  int last_shard_id = RGW_NO_SHARD;

  do {
    constexpr uint NUM_ENTRIES = 1000u;
    int r = cls_bucket_list_unordered(bucket_info,
				      last_shard_id,
				      marker,
				      prefix,
				      NUM_ENTRIES,
				      true,
				      ent_list,
				      &is_truncated,
                                      &marker,
                                      last_shard_id);
    if (r < 0)
      return r;

    string ns;
    for (auto const& dirent : ent_list) {
      rgw_obj_key obj;

      if (rgw_obj_key::oid_to_key_in_ns(dirent.key.name, &obj, ns))
        return -ENOTEMPTY;
    }
  } while (is_truncated);

  return 0;
}

int RGWRados::bucket_namespace_delete_root(RGWBucketInfo& bucket_info)
{
  librados::IoCtx io_ctx;
  int r = open_bucket_index_ctx(bucket_info, io_ctx);
  if (r < 0) {
    return r;
  }

  string root_oid = std::move(namespace_get_parent_oid(bucket_info.bucket.marker, "", 0));
  return cls_namespace_dir_del(io_ctx, root_oid);
}

/**
 * Delete a bucket.
 * bucket: the name of the bucket to delete
 * Returns 0 on success, -ERR# otherwise.
 */
int RGWRados::delete_bucket(RGWBucketInfo& bucket_info, RGWObjVersionTracker& objv_tracker,
                            bool check_empty)
{
  const rgw_bucket& bucket = bucket_info.bucket;
  librados::IoCtx index_ctx;
  map<int, string> bucket_objs;
  int r = open_bucket_index(bucket_info, index_ctx, bucket_objs);
  if (r < 0)
    return r;
  
  if (check_empty) {
    r = check_bucket_empty(bucket_info);
    if (r < 0) {
      return r;
    }
  }

  // try to remove root dir "/"
  if (bucket_info.namespace_type == BUCKET_NAMESPACE_ENABLE &&
      !cct->_conf->rgw_bucket_namespace_disable_force) {
    r = bucket_namespace_delete_root(bucket_info);
    if (r < 0 && r != -ENOENT) {
      ldout(cct, 0) << __func__ <<  " WARNING: failed remove namespace root dir ret="
                    << r << dendl;
      return r;
    }
  }

  r = rgw_bucket_delete_bucket_obj(this, bucket.tenant, bucket.name, objv_tracker);
  if (r < 0)
    return r;

  /* if the bucket is not synced we can remove the meta file */
  if (!is_syncing_bucket_meta(bucket)) {
    RGWObjVersionTracker objv_tracker;
    r = rgw_bucket_instance_remove_entry(this, bucket.get_key(), &objv_tracker);
    if (r < 0) {
      return r;
    }

   /* remove bucket index objects asynchronously by best effort */
    (void) CLSRGWIssueBucketIndexClean(index_ctx,
				       bucket_objs,
				       cct->_conf->rgw_bucket_index_max_aio)();
  }

  return 0;
}

int RGWRados::set_bucket_owner(rgw_bucket& bucket, ACLOwner& owner)
{
  RGWBucketInfo info;
  map<string, bufferlist> attrs;
  RGWObjectCtx obj_ctx(this);
  int r;
  if (bucket.bucket_id.empty()) {
    r = get_bucket_info(obj_ctx, bucket.tenant, bucket.name, info, NULL, &attrs);
  } else {
    r = get_bucket_instance_info(obj_ctx, bucket, info, nullptr, &attrs);
  }
  if (r < 0) {
    ldout(cct, 0) << "NOTICE: get_bucket_info on bucket=" << bucket.name << " returned err=" << r << dendl;
    return r;
  }

  info.owner = owner.get_id();

  r = put_bucket_instance_info(info, false, real_time(), &attrs);
  if (r < 0) {
    ldout(cct, 0) << "NOTICE: put_bucket_info on bucket=" << bucket.name << " returned err=" << r << dendl;
    return r;
  }

  return 0;
}


int RGWRados::set_buckets_enabled(vector<rgw_bucket>& buckets, bool enabled)
{
  int ret = 0;

  vector<rgw_bucket>::iterator iter;

  for (iter = buckets.begin(); iter != buckets.end(); ++iter) {
    rgw_bucket& bucket = *iter;
    if (enabled)
      ldout(cct, 20) << "enabling bucket name=" << bucket.name << dendl;
    else
      ldout(cct, 20) << "disabling bucket name=" << bucket.name << dendl;

    RGWBucketInfo info;
    map<string, bufferlist> attrs;
    RGWObjectCtx obj_ctx(this);
    int r = get_bucket_info(obj_ctx, bucket.tenant, bucket.name, info, NULL, &attrs);
    if (r < 0) {
      ldout(cct, 0) << "NOTICE: get_bucket_info on bucket=" << bucket.name << " returned err=" << r << ", skipping bucket" << dendl;
      ret = r;
      continue;
    }
    if (enabled) {
      info.flags &= ~BUCKET_SUSPENDED;
    } else {
      info.flags |= BUCKET_SUSPENDED;
    }

    r = put_bucket_instance_info(info, false, real_time(), &attrs);
    if (r < 0) {
      ldout(cct, 0) << "NOTICE: put_bucket_info on bucket=" << bucket.name << " returned err=" << r << ", skipping bucket" << dendl;
      ret = r;
      continue;
    }
  }
  return ret;
}

int RGWRados::bucket_suspended(rgw_bucket& bucket, bool *suspended)
{
  RGWBucketInfo bucket_info;
  RGWObjectCtx obj_ctx(this);
  int ret = get_bucket_info(obj_ctx, bucket.tenant, bucket.name, bucket_info, NULL);
  if (ret < 0) {
    return ret;
  }

  *suspended = ((bucket_info.flags & BUCKET_SUSPENDED) != 0);
  return 0;
}

int RGWRados::Object::complete_atomic_modification(bool delay_remove_head_obj)
{
  if (!state->has_manifest || state->keep_tail)
    return 0;
  auto iter = state->attrset.find(RGW_ATTR_DELETED);
  if (iter != state->attrset.end()) {
    if (iter->second.to_str().compare("true") == 0) {
      return 0;
    }
  }

  string renaming_info_key = "";
  bufferlist bl;
  int r;
  if (state->get_attr(RGW_ATTR_ID_TAG, bl)) {
    std::tie(r, renaming_info_key) = store->get_renaming_info(state->attrset, rgw_bl_to_str(bl));
    if (r < 0) return r;
    if (r == 0) {
      ldout(store->ctx(), 10) << __func__ << " tail obj is occupied by renaming_info_key:"
                              << renaming_info_key  << " id_tag:" << rgw_bl_to_str(bl) << dendl;
      return 0;
    }
  }

  cls_rgw_obj_chain chain;
  store->update_gc_chain(obj, state->manifest, &chain, state, delay_remove_head_obj);

  if (chain.empty()) {
    return 0;
  }

  string tag = (state->tail_tag.length() > 0 ? rgw_bl_to_str(state->tail_tag) : rgw_bl_to_str(state->obj_tag));
  char buf[11];
  gen_rand_alphanumeric(store->ctx(), buf, sizeof(buf) - 1);
  tag.append("#");
  tag.append(buf);

  return store->gc->send_chain(chain, tag, false);  // do it async
}


void RGWRados::update_gc_chain(rgw_obj& head_obj, RGWObjManifest& manifest, cls_rgw_obj_chain *chain,
    RGWObjState *s, bool delay_remove_head_obj)
{
  RGWObjManifest::obj_iterator iter;
  rgw_raw_obj raw_head;
  obj_to_raw(manifest.get_head_placement_rule(), head_obj, &raw_head);
  chain->enable_delay_remove_head_obj = 
    (delay_remove_head_obj ? DELAY_REMOVE_HEAD_ENABLE : DELAY_REMOVE_HEAD_DISABLE);
  chain->skip_cache = manifest.is_enable_skip_cache();
  bool head_added = false;
  iter = manifest.obj_begin();
  bool handled_first_raw_obj = false;
  do {
    const rgw_raw_obj& mobj = iter.get_location().get_raw_obj(this);
    ldout(cct, 20) << "gc object pool is: " << mobj.pool.name
                   << ", oid is: " << mobj.oid
                   << ", loc is: " << mobj.loc
                   << ", raw_head.oid: " << raw_head.oid
                   << dendl;
    if (mobj == raw_head) {
      handled_first_raw_obj = true;
      head_added = true;
      if (!delay_remove_head_obj) {
        ++iter;
        continue;
      }
    }
    if (!handled_first_raw_obj) {
      handled_first_raw_obj = true;
      if (!is_tail_obj_key(mobj.oid)) {
        ldout(cct, 0) << __func__ << "() WARNING: first raw object shouldn't exist"
                      << " for this object: " << head_obj
                      << ", oid is: " << mobj.oid << ", loc is: " << mobj.loc
                      << ". just skip it" << dendl;
        ++iter;
        continue;
      }
    }
    // multipart object, iter doesn't contain head_obj, need add it to gc specifically
    // enable bucket version, need skip head_obj which contain the olh xattr
    if (delay_remove_head_obj && !head_added && s != nullptr) {
      map<string, bufferlist>::iterator aiter = s->attrset.lower_bound(RGW_ATTR_OLH_PREFIX);
      if (aiter != s->attrset.end()) {
        if (boost::algorithm::starts_with(aiter->first, RGW_ATTR_OLH_PREFIX)) {
          head_added = true;
        }
      }
      // iter doesn't include raw_head: work with normal object, whose head obj doesn't contain data
      if (!head_added) {
        cls_rgw_obj_key key(raw_head.oid);
        chain->push_obj(raw_head.pool.to_str(), key, raw_head.loc);
        head_added = true;
      }
    }
    if (manifest.get_obj_size() == 0) {
      // if object is empty, no need add tail obj in gc.
      // head obj should be added to chain with delay_remove_head_obj condition
      
      // mobj == raw_head: work with normal object, whose head obj contains data
      if (delay_remove_head_obj && mobj == raw_head) {
        cls_rgw_obj_key key(raw_head.oid);
        chain->push_obj(raw_head.pool.to_str(), key, raw_head.loc);
        head_added = true;
      }
      // else -> no nedd add tail obj in gc
      ++iter;
      continue;
    }
    cls_rgw_obj_key key(mobj.oid);
    chain->push_obj(mobj.pool.to_str(), key, mobj.loc);
    ++iter;
  } while(iter != manifest.obj_end());
}

int RGWRados::send_chain_to_gc(cls_rgw_obj_chain& chain, const string& tag, bool sync)
{
  return gc->send_chain(chain, tag, sync);
}

int RGWRados::open_bucket_index(const RGWBucketInfo& bucket_info,
				librados::IoCtx& index_ctx,
				string& bucket_oid)
{
  const rgw_bucket& bucket = bucket_info.bucket;
  int r = open_bucket_index_ctx(bucket_info, index_ctx);
  if (r < 0)
    return r;

  if (bucket.bucket_id.empty()) {
    ldout(cct, 0) << "ERROR: empty bucket id for bucket operation" << dendl;
    return -EIO;
  }

  bucket_oid = dir_oid_prefix;
  bucket_oid.append(bucket.bucket_id);

  return 0;
}

int RGWRados::open_bucket_index_base(const RGWBucketInfo& bucket_info,
				     librados::IoCtx& index_ctx,
				     string& bucket_oid_base) {
  const rgw_bucket& bucket = bucket_info.bucket;
  int r = open_bucket_index_ctx(bucket_info, index_ctx);
  if (r < 0)
    return r;

  if (bucket.bucket_id.empty()) {
    ldout(cct, 0) << "ERROR: empty bucket_id for bucket operation" << dendl;
    return -EIO;
  }

  bucket_oid_base = dir_oid_prefix;
  bucket_oid_base.append(bucket.bucket_id);

  return 0;

}

int RGWRados::open_bucket_index(const RGWBucketInfo& bucket_info,
				librados::IoCtx& index_ctx,
				map<int, string>& bucket_objs,
				int shard_id,
				map<int, string> *bucket_instance_ids) {
  string bucket_oid_base;
  int ret = open_bucket_index_base(bucket_info, index_ctx, bucket_oid_base);
  if (ret < 0) {
    return ret;
  }

  get_bucket_index_objects(bucket_oid_base, bucket_info.num_shards, bucket_objs, shard_id);
  if (bucket_instance_ids) {
    get_bucket_instance_ids(bucket_info, shard_id, bucket_instance_ids);
  }
  return 0;
}

template<typename T>
int RGWRados::open_bucket_index(const RGWBucketInfo& bucket_info, librados::IoCtx& index_ctx,
                                map<int, string>& oids, map<int, T>& bucket_objs,
                                int shard_id, map<int, string> *bucket_instance_ids)
{
  int ret = open_bucket_index(bucket_info, index_ctx, oids, shard_id, bucket_instance_ids);
  if (ret < 0)
    return ret;

  map<int, string>::const_iterator iter = oids.begin();
  for (; iter != oids.end(); ++iter) {
    bucket_objs[iter->first] = T();
  }
  return 0;
}

int RGWRados::open_bucket_index_shard(const RGWBucketInfo& bucket_info, librados::IoCtx& index_ctx,
    const string& obj_key, string *bucket_obj, int *shard_id)
{
  string bucket_oid_base;
  int ret = open_bucket_index_base(bucket_info, index_ctx, bucket_oid_base);
  if (ret < 0)
    return ret;

  RGWObjectCtx obj_ctx(this);

  ret = get_bucket_index_object(bucket_oid_base, obj_key, bucket_info.num_shards,
        (RGWBucketInfo::BIShardsHashType)bucket_info.bucket_index_shard_hash_type, bucket_obj, shard_id);
  if (ret < 0) {
    ldout(cct, 10) << "get_bucket_index_object() returned ret=" << ret << dendl;
    return ret;
  }
  return 0;
}

int RGWRados::open_bucket_index_shard(const RGWBucketInfo& bucket_info, librados::IoCtx& index_ctx,
                                      int shard_id, string *bucket_obj)
{
  string bucket_oid_base;
  int ret = open_bucket_index_base(bucket_info, index_ctx, bucket_oid_base);
  if (ret < 0)
    return ret;

  RGWObjectCtx obj_ctx(this);

  get_bucket_index_object(bucket_oid_base, bucket_info.num_shards,
                          shard_id, bucket_obj);
  return 0;
}

static void accumulate_raw_stats(const rgw_bucket_dir_header& header,
                                 map<RGWObjCategory, RGWStorageStats>& stats)
{
  for (const auto& pair : header.stats) {
    const RGWObjCategory category = static_cast<RGWObjCategory>(pair.first);
    const rgw_bucket_category_stats& header_stats = pair.second;

    RGWStorageStats& s = stats[category];

    s.size += header_stats.total_size;
    s.size_rounded += header_stats.total_size_rounded;
    s.size_utilized += header_stats.actual_size;
    s.num_objects += header_stats.num_entries;
  }
}

static void accumulate_storageclass_stats(const rgw_bucket_dir_header& header,
                                 map<std::string, RGWStorageStats>* storageclass_stats)
{
  for (const auto& pair : header.storageclass_stats) {
    const std::string storage_class = static_cast<std::string>(pair.first);

    RGWStorageStats& cs = (*storageclass_stats)[storage_class];

    cs.size += pair.second.total_size;
    cs.size_rounded += pair.second.total_size_rounded;
    cs.size_utilized += pair.second.actual_size;
    cs.num_objects += pair.second.num_entries;
  }
}

int RGWRados::bucket_check_index(RGWBucketInfo& bucket_info,
				 map<RGWObjCategory, RGWStorageStats> *existing_stats,
				 map<RGWObjCategory, RGWStorageStats> *calculated_stats)
{
  librados::IoCtx index_ctx;
  // key - bucket index object id
  // value - bucket index check OP returned result with the given bucket index object (shard)
  map<int, string> oids;
  map<int, struct rgw_cls_check_index_ret> bucket_objs_ret;

  int ret = open_bucket_index(bucket_info, index_ctx, oids, bucket_objs_ret);
  if (ret < 0) {
      return ret;
  }

  ret = CLSRGWIssueBucketCheck(index_ctx, oids, bucket_objs_ret, cct->_conf->rgw_bucket_index_max_aio)();
  if (ret < 0) {
      return ret;
  }

  // Aggregate results (from different shards if there is any)
  map<int, struct rgw_cls_check_index_ret>::iterator iter;
  for (iter = bucket_objs_ret.begin(); iter != bucket_objs_ret.end(); ++iter) {
    accumulate_raw_stats(iter->second.existing_header, *existing_stats);
    accumulate_raw_stats(iter->second.calculated_header, *calculated_stats);
  }

  return 0;
}

int RGWRados::bucket_rebuild_index(RGWBucketInfo& bucket_info)
{
  librados::IoCtx index_ctx;
  map<int, string> bucket_objs;

  int r = open_bucket_index(bucket_info, index_ctx, bucket_objs);
  if (r < 0) {
    return r;
  }

  return CLSRGWIssueBucketRebuild(index_ctx, bucket_objs, cct->_conf->rgw_bucket_index_max_aio)();
}

int RGWRados::bucket_set_reshard(const RGWBucketInfo& bucket_info, const cls_rgw_bucket_instance_entry& entry)
{
  librados::IoCtx index_ctx;
  map<int, string> bucket_objs;

  int r = open_bucket_index(bucket_info, index_ctx, bucket_objs);
  if (r < 0) {
    return r;
  }

  return CLSRGWIssueSetBucketResharding(index_ctx, bucket_objs, entry, cct->_conf->rgw_bucket_index_max_aio)();
}

int RGWRados::defer_gc(void *ctx, const RGWBucketInfo& bucket_info, const rgw_obj& obj)
{
  RGWObjectCtx *rctx = static_cast<RGWObjectCtx *>(ctx);
  std::string oid, key;
  get_obj_bucket_and_oid_loc(obj, oid, key);
  if (!rctx)
    return 0;

  RGWObjState *state = NULL;

  int r = get_obj_state(rctx, bucket_info, obj, &state, false);
  if (r < 0)
    return r;

  if (!state->is_atomic) {
    ldout(cct, 20) << "state for obj=" << obj << " is not atomic, not deferring gc operation" << dendl;
    return -EINVAL;
  }

  string tag;

  if (state->tail_tag.length() > 0) {
    tag = state->tail_tag.c_str();
  } else if (state->obj_tag.length() > 0) {
    tag = state->obj_tag.c_str();
  } else {
    ldout(cct, 20) << "state->obj_tag is empty, not deferring gc operation" << dendl;
    return -EINVAL;
  }

  ldout(cct, 0) << "defer chain tag=" << tag << dendl;

  return gc->defer_chain(tag, false);
}

void RGWRados::remove_rgw_head_obj(ObjectWriteOperation& op)
{
  list<string> prefixes;
  prefixes.push_back(RGW_ATTR_OLH_PREFIX);
  cls_rgw_remove_obj(op, prefixes);
}

void RGWRados::cls_obj_check_prefix_exist(ObjectOperation& op, const string& prefix, bool fail_if_exist)
{
  cls_rgw_obj_check_attrs_prefix(op, prefix, fail_if_exist);
}

void RGWRados::cls_obj_check_mtime(ObjectOperation& op, const real_time& mtime, bool high_precision_time, RGWCheckMTimeType type)
{
  cls_rgw_obj_check_mtime(op, mtime, high_precision_time, type);
}


/**
 * Delete an object.
 * bucket: name of the bucket storing the object
 * obj: name of the object to delete
 * Returns: 0 on success, -ERR# otherwise.
 */
int RGWRados::Object::Delete::delete_obj(bool delete_directly)
{

  RGWRados *store = target->get_store();
  if (!without_bucket_namespace && is_namespace_dir(store->ctx())) {
    return delete_namespace_dir();
  };
  rgw_obj& src_obj = target->get_obj();
  const string& instance = src_obj.key.instance;
  rgw_obj obj = src_obj;
  real_time mtime = real_clock::now();

  if (instance == "null") {
    obj.key.instance.clear();
  }

  bool explicit_marker_version = (!params.marker_version_id.empty());

  if (params.versioning_status & BUCKET_VERSIONED || explicit_marker_version) {
    if (instance.empty() || explicit_marker_version) {
      rgw_obj marker = obj;

      if (!params.marker_version_id.empty()) {
        if (params.marker_version_id != "null") {
          marker.key.set_instance(params.marker_version_id);
        }
      } else if ((params.versioning_status & BUCKET_VERSIONS_SUSPENDED) == 0) {
        store->gen_rand_obj_instance_name(&marker);
      }

      result.version_id = marker.key.instance;
      if (result.version_id.empty())
        result.version_id = "null";
      result.delete_marker = true;

      struct rgw_bucket_dir_entry_meta meta;

      meta.owner = params.obj_owner.get_id().to_str();
      meta.owner_display_name = params.obj_owner.get_display_name();

      if (real_clock::is_zero(params.mtime)) {
        meta.mtime = mtime;
      } else {
        meta.mtime = params.mtime;
      }

      int r = store->set_olh(target->get_ctx(), target->get_bucket_info(), marker, true, &meta, params.olh_epoch, params.unmod_since, params.high_precision_time, params.zones_trace);
      if (r < 0) {
        return r;
      }
    } else {
      rgw_bucket_dir_entry dirent;

      int r = store->bi_get_instance(target->get_bucket_info(), obj, &dirent);
      if (r < 0) {
        return r;
      }
      result.delete_marker = dirent.is_delete_marker();
      r = store->unlink_obj_instance(target->get_ctx(), target->get_bucket_info(), obj, params.olh_epoch, params.zones_trace);
      if (r < 0) {
        return r;
      }
      result.version_id = instance;
    }

    BucketShard *bs;
    int r = target->get_bucket_shard(&bs);
    if (r < 0) {
      ldout(store->ctx(), 5) << "failed to get BucketShard object: r=" << r << dendl;
      return r;
    }

    bool ignore_bucket_initial = true;
    #ifdef WITH_UNAUTO_SYNC
      ignore_bucket_initial = !(target->bucket_info.disable_sync.size() == 0 &&
                                target->bucket_info.bilog_flags.size() == 0);
    #endif
    if (target->bucket_info.datasync_flag_enabled(store->get_zone().id) &&
        !store->datasync_all_disabled(target->bucket_info) && ignore_bucket_initial) {
      r = store->data_log->add_entry(bs->bucket, bs->shard_id);
      if (r < 0) {
        lderr(store->ctx()) << "ERROR: failed writing data log" << dendl;
        return r;
      }
    }

    return 0;
  }

  rgw_rados_ref ref;
  int r = store->get_obj_head_ref(target->get_bucket_info(), obj, &ref);
  if (r < 0) {
    ldout(store->ctx(), 5) << "get obj head ref: r=" << r << dendl;
    return r;
  }

  RGWObjState *state;
  r = target->get_state(&state, false);
  if (r < 0) {
    ldout(store->ctx(), 5) << "get obj state: r=" << r << dendl;
    return r;
  }

  bufferlist deleted_bl;
  if (state->get_attr(RGW_ATTR_DELETED, deleted_bl)) {
    if (deleted_bl.to_str().compare("true") == 0) {
      return -ENOENT;
    }
  }

  bufferlist target_size_bl;
  if (state->get_attr(RGW_ATTR_TARGET_SIZE, target_size_bl)) {
    // appendable object
    uint64_t target_size;
    bufferlist::iterator iter = target_size_bl.begin();
    try {
      decode(target_size, iter);
    } catch (buffer::error& err) {
      ldout(store->ctx(), 5) << "ERROR: failed to decode " << RGW_ATTR_TARGET_SIZE
        << " attr, value:" << target_size_bl.c_str() << dendl;
      return -EIO;
    }

    if (target_size != state->accounted_size) {
      bufferlist ts_bl;
      if (state->get_attr(RGW_ATTR_APPEND_TIMEOUT, ts_bl)) {
        ceph::real_time ts;
        bufferlist::iterator iter = ts_bl.begin();
        try {
          decode(ts, iter);
        } catch (buffer::error& err) {
          ldout(store->ctx(), 5) << "ERROR: failed to decode " << RGW_ATTR_APPEND_TIMEOUT
                                 << " attr, value:" << ts_bl.c_str() << dendl;
          return -EIO;
        }
        if (real_clock::now() < ts + make_timespan(store->ctx()->_conf->rgw_append_timeout)) {
          ldout(store->ctx(), 10) << "ERROR: can't delete appending object before timeout" << dendl;
          return -ERR_DELETE_CONFLICT;
        }
      }
    }
  }

  if (!delete_directly) {
    RGWObjectCtx obj_ctx(store);
    r = store->waiting_for_renaming(&obj_ctx, &state, target->get_bucket_info(), obj, true);
    if (r < 0) {
      ldout(store->ctx(), 10) << __func__ << "() ERROR: waiting_for_renaming ret:" << r << dendl;
      return r;
    }
  }

  ObjectWriteOperation op;

  if (!real_clock::is_zero(params.unmod_since)) {
    struct timespec ctime = ceph::real_clock::to_timespec(state->mtime);
    struct timespec unmod = ceph::real_clock::to_timespec(params.unmod_since);
    if (!params.high_precision_time) {
      ctime.tv_nsec = 0;
      unmod.tv_nsec = 0;
    }

    ldout(store->ctx(), 10) << "If-UnModified-Since: " << params.unmod_since << " Last-Modified: " << ctime << dendl;
    if (ctime > unmod) {
      return -ERR_PRECONDITION_FAILED;
    }

    /* only delete object if mtime is less than or equal to params.unmod_since */
    store->cls_obj_check_mtime(op, params.unmod_since, params.high_precision_time, CLS_RGW_CHECK_TIME_MTIME_LE);
  }
  uint64_t obj_accounted_size = state->accounted_size;

  if (!real_clock::is_zero(params.expiration_time)) {
    bufferlist bl;
    real_time delete_at;

    if (state->get_attr(RGW_ATTR_DELETE_AT, bl)) {
      try {
        bufferlist::iterator iter = bl.begin();
        decode(delete_at, iter);
      } catch (buffer::error& err) {
        ldout(store->ctx(), 0) << "ERROR: couldn't decode RGW_ATTR_DELETE_AT" << dendl;
	return -EIO;
      }

      if (params.expiration_time != delete_at) {
        return -ERR_PRECONDITION_FAILED;
      }
    } else {
      return -ERR_PRECONDITION_FAILED;
    }
  }

  if (!state->exists) {
    target->invalidate_state();
    ldout(store->ctx(), 5) << "obj no exist"  << dendl;
    return -ENOENT;
  }

  CephContext *cct = store->ctx();
  bool delay_remove_head_obj = cct->_conf->rgw_delay_remove_head_obj;
  // if delay_remove_head_obj is true, need to update RGW_ATTR_ID_TAG
  r = target->prepare_atomic_modification(op, false, NULL, NULL, NULL, !delay_remove_head_obj, false);
  if (r < 0) {
    ldout(store->ctx(), 5) << "prepare atomic modification: r=" << r << dendl;
    return r;
  }

  RGWBucketInfo& bucket_info = target->get_bucket_info();

  RGWRados::Bucket bop(store, bucket_info);
  RGWRados::Bucket::UpdateIndex index_op(&bop, obj);
  RGWRados::Bucket::Namespace namespace_op(&bop, obj);

  index_op.set_bilog_write_enable(target->get_bilog_write_enable());
  index_op.set_zones_trace(params.zones_trace);
  index_op.set_bilog_flags(params.bilog_flags);

  r = index_op.prepare(CLS_RGW_OP_DEL, &state->write_tag);
  if (r < 0)
    return r;

  // prepare delete namespace
  if (!without_bucket_namespace) {
    r = namespace_op.prepare(nullptr, CLS_RGW_OP_DEL, &state->write_tag, mtime);
    if (r < 0)
      return r;
  }

  if (delete_directly || !delay_remove_head_obj) {
    store->remove_rgw_head_obj(op);
    r = ref.ioctx.operate(ref.oid, &op);
  } else {
    bufferlist bl;
    string is_deleted = "true";
    bl.append(is_deleted.c_str(), is_deleted.size());
    op.setxattr(RGW_ATTR_DELETED, bl);
    if (!real_clock::is_zero(params.mtime)) {
      struct timespec mtime_ts = real_clock::to_timespec(params.mtime);
      op.mtime2(&mtime_ts);
    } else {
      // ensure deleted head_obj mtime equals to mtime in data_log entry
      struct timespec mtime_ts = real_clock::to_timespec(mtime);
      op.mtime2(&mtime_ts);
    }
    r = ref.ioctx.operate(ref.oid, &op);
  }

  /* raced with another operation, object state is indeterminate */
  const bool need_invalidate = (r == -ECANCELED);

  int64_t poolid = ref.ioctx.get_id();
  if (r >= 0) {
    tombstone_cache_t *obj_tombstone_cache = store->get_tombstone_cache();
    if (obj_tombstone_cache) {
      tombstone_entry entry{*state};
      obj_tombstone_cache->add(obj, entry);
    }

    if (!real_clock::is_zero(params.mtime)) {
      mtime = params.mtime;
    }

    // delete namespace
    if (!without_bucket_namespace) {
      r = namespace_op.complete_del(poolid, ref.ioctx.get_last_version(), &mtime);
      if (r < 0) {
        ldout(store->ctx(), 0) << "ERROR: Namespace::complete_del returned ret=" << r << dendl;
      }
    }

    r = index_op.complete_del(poolid, ref.ioctx.get_last_version(), mtime, params.remove_objs);
    int ret = target->complete_atomic_modification(delay_remove_head_obj);
    if (ret < 0) {
      ldout(store->ctx(), 0) << "ERROR: complete_atomic_modification returned ret=" << ret << dendl;
    }
    /* other than that, no need to propagate error */
  } else {
    int ret = index_op.cancel();
    if (ret < 0) {
      ldout(store->ctx(), 0) << "ERROR: index_op.cancel() returned ret=" << ret << dendl;
    }

    if (!without_bucket_namespace) {
      ret = namespace_op.cancel();
      if (ret < 0) {
        ldout(store->ctx(), 0) << "ERROR: namespace_op.cancel() returned ret=" << ret << dendl;
      }
    }
  }

  if (need_invalidate) {
    target->invalidate_state();
  }

  if (r < 0)
    return r;

  /* update quota cache */
  store->quota_handler->update_stats(params.bucket_owner, obj.bucket, -1, 0, obj_accounted_size);

  return 0;
}

int RGWRados::Object::Delete::delete_namespace_dir() {
  RGWRados *store = target->get_store();
  rgw_obj& src_obj = target->get_obj();
  string& obj_name = src_obj.key.name;

  ldout(store->ctx(), 5) << "Object::Delete::delete_namespace_dir() delete "
                         << obj_name << dendl;

  // prepare delete namespace
  int r = RGWRados::Bucket::Namespace::delete_dir(target, obj_name);
  if (r == -ENOTEMPTY) {
    return -ERROR_BUCKET_DIR_NOT_EMPTY;
  }
  return r;
}

int RGWRados::delete_obj(RGWObjectCtx& obj_ctx,
                         const RGWBucketInfo& bucket_info,
                         const rgw_obj& obj,
                         int versioning_status,
                         bool without_bucket_namespace,
                         uint16_t bilog_flags,
                         const real_time& expiration_time,
                         rgw_zone_set *zones_trace,
                         bool delete_directly,
                         ceph::real_time* unmod_since,
                         bool bilog_write_enable)
{
  RGWRados::Object del_target(this, bucket_info, obj_ctx, obj);
  del_target.set_bilog_write_enable(bilog_write_enable);
  RGWRados::Object::Delete del_op(&del_target);

  del_op.params.bucket_owner = bucket_info.owner;
  del_op.params.versioning_status = versioning_status;
  del_op.params.bilog_flags = bilog_flags;
  del_op.params.expiration_time = expiration_time;
  del_op.params.zones_trace = zones_trace;
  if (unmod_since) {
    del_op.params.unmod_since = *unmod_since;
  }
  del_op.without_bucket_namespace = without_bucket_namespace;

  return del_op.delete_obj(delete_directly);
}

int RGWRados::truncate_raw_obj(const rgw_raw_obj& obj, uint64_t offset, bool skip_cache)
{
  rgw_rados_ref ref;
  int r = get_raw_obj_ref(obj, &ref);
  if (r < 0) {
    return r;
  }

  ObjectWriteOperation op;

  op.truncate(offset);
  r = ref.ioctx.operate(ref.oid, &op, skip_cache);
  if (r < 0)
    return r;

  return 0;
}

int RGWRados::delete_raw_obj(const rgw_raw_obj& obj, bool skip_cache)
{
  rgw_rados_ref ref;
  int r = get_raw_obj_ref(obj, &ref);
  if (r < 0) {
    return r;
  }

  ObjectWriteOperation op;

  op.remove();
  r = ref.ioctx.operate(ref.oid, &op, skip_cache);
  if (r < 0)
    return r;

  return 0;
}

int RGWRados::delete_system_obj(rgw_raw_obj& obj, RGWObjVersionTracker *objv_tracker)
{
  if (obj.empty()) {
    ldout(cct, 1) << "delete_system_obj got empty object name "
        << obj << ", returning EINVAL" << dendl;
    return -EINVAL;
  }
  rgw_rados_ref ref;
  int r = get_raw_obj_ref(obj, &ref);
  if (r < 0) {
    return r;
  }

  ObjectWriteOperation op;

  if (objv_tracker) {
    objv_tracker->prepare_op_for_write(&op);
  }

  op.remove();
  r = ref.ioctx.operate(ref.oid, &op);
  if (r < 0)
    return r;

  return 0;
}

int RGWRados::delete_obj_index(const rgw_obj& obj)
{
  std::string oid, key;
  get_obj_bucket_and_oid_loc(obj, oid, key);

  RGWObjectCtx obj_ctx(this);

  RGWBucketInfo bucket_info;
  int ret = get_bucket_instance_info(obj_ctx, obj.bucket, bucket_info, NULL, NULL);
  if (ret < 0) {
    ldout(cct, 0) << "ERROR: " << __func__ << "() get_bucket_instance_info(bucket=" << obj.bucket << ") returned ret=" << ret << dendl;
    return ret;
  }

  RGWRados::Bucket bop(this, bucket_info);
  RGWRados::Bucket::UpdateIndex index_op(&bop, obj);
  RGWRados::Bucket::Namespace namespace_op(&bop, obj);

  ceph::real_time removed_mtime = ceph::real_clock::now();

  // delete namespace
  int r = namespace_op.complete_del(-1, 0, &removed_mtime);
  if (r < 0) {
    ldout(cct, 0) << __func__ << " ERROR: " << obj.key.name
                  << " namepsace op complete_del() ret=" << ret << dendl;
  }

  // delete index
  r = index_op.complete_del(-1 /* pool */, 0, removed_mtime, NULL);
  return r;
}

static void generate_fake_tag(RGWRados *store, map<string, bufferlist>& attrset, RGWObjManifest& manifest, bufferlist& manifest_bl, bufferlist& tag_bl)
{
  string tag;

  RGWObjManifest::obj_iterator mi = manifest.obj_begin();
  if (mi != manifest.obj_end()) {
    if (manifest.has_tail()) // first object usually points at the head, let's skip to a more unique part
      ++mi;
    tag = mi.get_location().get_raw_obj(store).oid;
    tag.append("_");
  }

  unsigned char md5[CEPH_CRYPTO_MD5_DIGESTSIZE];
  char md5_str[CEPH_CRYPTO_MD5_DIGESTSIZE * 2 + 1];
  MD5 hash;
  hash.Update((const unsigned char *)manifest_bl.c_str(), manifest_bl.length());

  map<string, bufferlist>::iterator iter = attrset.find(RGW_ATTR_ETAG);
  if (iter != attrset.end()) {
    bufferlist& bl = iter->second;
    hash.Update((const unsigned char *)bl.c_str(), bl.length());
  }

  hash.Final(md5);
  buf_to_hex(md5, CEPH_CRYPTO_MD5_DIGESTSIZE, md5_str);
  tag.append(md5_str);

  ldout(store->ctx(), 10) << "generate_fake_tag new tag=" << tag << dendl;

  tag_bl.append(tag.c_str(), tag.size() + 1);
}

static bool is_olh(map<string, bufferlist>& attrs)
{
  map<string, bufferlist>::iterator iter = attrs.find(RGW_ATTR_OLH_INFO);
  return (iter != attrs.end());
}

static bool has_olh_tag(map<string, bufferlist>& attrs)
{
  map<string, bufferlist>::iterator iter = attrs.find(RGW_ATTR_OLH_ID_TAG);
  return (iter != attrs.end());
}

int RGWRados::get_olh_target_state(RGWObjectCtx& obj_ctx, const RGWBucketInfo& bucket_info, const rgw_obj& obj,
                                   RGWObjState *olh_state, RGWObjState **target_state)
{
  assert(olh_state->is_olh);

  rgw_obj target;
  int r = RGWRados::follow_olh(bucket_info, obj_ctx, olh_state, obj, &target); /* might return -EAGAIN */
  if (r < 0) {
    return r;
  }
  r = get_obj_state(&obj_ctx, bucket_info, target, target_state, false);
  if (r < 0) {
    return r;
  }

  return 0;
}

int RGWRados::get_system_obj_state_impl(RGWObjectCtx *rctx, rgw_raw_obj& obj, RGWRawObjState **state, RGWObjVersionTracker *objv_tracker)
{
  if (obj.empty()) {
    return -EINVAL;
  }

  RGWRawObjState *s = rctx->raw.get_state(obj);
  ldout(cct, 20) << "get_system_obj_state: rctx=" << (void *)rctx << " obj=" << obj << " state=" << (void *)s << " s->prefetch_data=" << s->prefetch_data << dendl;
  *state = s;
  if (s->has_attrs) {
    return 0;
  }

  s->obj = obj;

  int r = raw_obj_stat(obj, &s->size, &s->mtime, &s->epoch, &s->attrset, (s->prefetch_data ? &s->data : NULL), objv_tracker);
  if (r == -ENOENT) {
    s->exists = false;
    s->has_attrs = true;
    s->mtime = real_time();
    return 0;
  }
  if (r < 0)
    return r;

  s->exists = true;
  s->has_attrs = true;
  s->obj_tag = s->attrset[RGW_ATTR_ID_TAG];

  if (s->obj_tag.length())
    ldout(cct, 20) << "get_system_obj_state: setting s->obj_tag to "
                   << s->obj_tag.c_str() << dendl;
  else
    ldout(cct, 20) << "get_system_obj_state: s->obj_tag was set empty" << dendl;

  return 0;
}

int RGWRados::get_system_obj_state(RGWObjectCtx *rctx, rgw_raw_obj& obj, RGWRawObjState **state, RGWObjVersionTracker *objv_tracker)
{
  int ret;

  do {
    ret = get_system_obj_state_impl(rctx, obj, state, objv_tracker);
  } while (ret == -EAGAIN);

  return ret;
}

int RGWRados::get_obj_state_impl(RGWObjectCtx *rctx,
                                 const RGWBucketInfo& bucket_info,
                                 const rgw_obj& obj,
                                 RGWObjState **state,
                                 bool follow_olh,
                                 bool assume_noent,
                                 bool ignore_rename)
{
  if (obj.empty()) {
    return -EINVAL;
  }

  bool need_follow_olh = follow_olh && obj.key.instance.empty();

  RGWObjState *s = rctx->obj.get_state(obj);
  ldout(cct, 20) << "get_obj_state: rctx=" << (void *)rctx << " obj=" << obj << " state=" << (void *)s << " s->prefetch_data=" << s->prefetch_data<< " s->has_attrs:" << s->has_attrs << " assume_noent:" << assume_noent<< dendl;
  *state = s;
  if (s->has_attrs) {
    if (s->is_olh && need_follow_olh) {
      return get_olh_target_state(*rctx, bucket_info, obj, s, state);
    }
    return 0;
  }

  s->obj = obj;

  rgw_raw_obj raw_obj;
  obj_to_raw(bucket_info.head_placement_rule, obj, &raw_obj);

  int r = -ENOENT;

  if (!assume_noent) {
    r = RGWRados::raw_obj_stat_with_ctx(rctx, raw_obj, s, NULL);
  }

  if (r == -ENOENT) {
    ldout(cct, 30) << "get_obj_state ENOENT set exists = false obj=" << obj << dendl;
    s->exists = false;
    s->has_attrs = true;
    tombstone_entry entry;
    if (obj_tombstone_cache && obj_tombstone_cache->find(obj, entry)) {
      s->mtime = entry.mtime;
      s->zone_short_id = entry.zone_short_id;
      s->pg_ver = entry.pg_ver;
      ldout(cct, 20) << __func__ << "(): found obj in tombstone cache: obj=" << obj
          << " mtime=" << s->mtime << " pgv=" << s->pg_ver << dendl;
    } else {
      s->mtime = real_time();
    }
    return 0;
  }
  if (r < 0)
    return r;

  s->has_attrs = true;
  s->exists = true;
  s->accounted_size = s->size;

  if (!ignore_rename) {
    // trigger need_guard in prepare_atomic_modification()
    s->obj_tag = s->attrset[RGW_ATTR_ID_TAG];
    r = check_renaming_state(rctx, s, bucket_info);
    if (r == -ENOENT) {
      s->exists = false;
      return 0;
    }
    if (r < 0) return r;
  }

  auto iter = s->attrset.find(RGW_ATTR_ETAG);
  if (iter != s->attrset.end()) {
    /* get rid of extra null character at the end of the etag, as we used to store it like that */
    bufferlist& bletag = iter->second;
    if (bletag.length() > 0 && bletag[bletag.length() - 1] == '\0') {
      bufferlist newbl;
      bletag.splice(0, bletag.length() - 1, &newbl);
      bletag.claim(newbl);
    }
  }

  iter = s->attrset.find(RGW_ATTR_COMPRESSION);
  const bool compressed = (iter != s->attrset.end());
  if (compressed) {
    // use uncompressed size for accounted_size
    try {
      RGWCompressionInfo info;
      auto p = iter->second.begin();
      decode(info, p);
      s->accounted_size = info.orig_size; 
    } catch (buffer::error&) {
      dout(0) << "ERROR: could not decode compression info for object: " << obj << dendl;
      return -EIO;
    }
  }

  iter = s->attrset.find(RGW_ATTR_SHADOW_OBJ);
  if (iter != s->attrset.end()) {
    bufferlist bl = iter->second;
    bufferlist::iterator it = bl.begin();
    it.copy(bl.length(), s->shadow_obj);
    s->shadow_obj[bl.length()] = '\0';
  }
  s->obj_tag = s->attrset[RGW_ATTR_ID_TAG];
  auto ttiter = s->attrset.find(RGW_ATTR_TAIL_TAG);
  if (ttiter != s->attrset.end()) {
    s->tail_tag = s->attrset[RGW_ATTR_TAIL_TAG];
  }

  bufferlist manifest_bl = s->attrset[RGW_ATTR_MANIFEST];
  if (manifest_bl.length()) {
    bufferlist::iterator miter = manifest_bl.begin();
    try {
      decode(s->manifest, miter);
      s->has_manifest = true;

      // patch manifest to reflect the head we just read, some manifests might be broken due to old bugs 
      s->manifest.set_head(bucket_info.head_placement_rule, obj, s->size);
      s->size = s->manifest.get_obj_size();

      if (!compressed)
        s->accounted_size = s->size;
    } catch (buffer::error& err) {
      ldout(cct, 0) << "ERROR: couldn't decode manifest" << dendl;
      return -EIO;
    }
    ldout(cct, 10) << "manifest: total_size = " << s->manifest.get_obj_size() << dendl;
    if (cct->_conf->subsys.should_gather<ceph_subsys_rgw, 20>() && \
	s->manifest.has_explicit_objs()) {
      RGWObjManifest::obj_iterator mi;
      for (mi = s->manifest.obj_begin(); mi != s->manifest.obj_end(); ++mi) {
        ldout(cct, 20) << "manifest: ofs=" << mi.get_ofs() << " loc=" << mi.get_location().get_raw_obj(this) << dendl;
      }
    }

    if (!s->obj_tag.length()) {
      /*
       * Uh oh, something's wrong, object with manifest should have tag. Let's
       * create one out of the manifest, would be unique
       */
      generate_fake_tag(this, s->attrset, s->manifest, manifest_bl, s->obj_tag);
      s->fake_tag = true;
    }
  }
  map<string, bufferlist>::iterator aiter = s->attrset.find(RGW_ATTR_PG_VER);
  if (aiter != s->attrset.end()) {
    bufferlist& pg_ver_bl = aiter->second;
    if (pg_ver_bl.length()) {
      bufferlist::iterator pgbl = pg_ver_bl.begin();
      try {
        decode(s->pg_ver, pgbl);
      } catch (buffer::error& err) {
        ldout(cct, 0) << "ERROR: couldn't decode pg ver attr for object " << s->obj << ", non-critical error, ignoring" << dendl;
      }
    }
  }
  aiter = s->attrset.find(RGW_ATTR_SOURCE_ZONE);
  if (aiter != s->attrset.end()) {
    bufferlist& zone_short_id_bl = aiter->second;
    if (zone_short_id_bl.length()) {
      bufferlist::iterator zbl = zone_short_id_bl.begin();
      try {
        decode(s->zone_short_id, zbl);
      } catch (buffer::error& err) {
        ldout(cct, 0) << "ERROR: couldn't decode zone short id attr for object " << s->obj << ", non-critical error, ignoring" << dendl;
      }
    }
  }
  if (s->obj_tag.length())
    ldout(cct, 20) << "get_obj_state: setting s->obj_tag to " << s->obj_tag.c_str() << dendl;
  else
    ldout(cct, 20) << "get_obj_state: s->obj_tag was set empty" << dendl;

  /* an object might not be olh yet, but could have olh id tag, so we should set it anyway if
   * it exist, and not only if is_olh() returns true
   */
  iter = s->attrset.find(RGW_ATTR_OLH_ID_TAG);
  if (iter != s->attrset.end()) {
    s->olh_tag = iter->second;
  }

  if (is_olh(s->attrset)) {
    s->is_olh = true;

    ldout(cct, 20) << __func__ << ": setting s->olh_tag to " << string(s->olh_tag.c_str(), s->olh_tag.length()) << dendl;

    if (need_follow_olh) {
      return get_olh_target_state(*rctx, bucket_info, obj, s, state);
    }
  }

  return 0;
}

int RGWRados::get_obj_state(RGWObjectCtx *rctx, const RGWBucketInfo& bucket_info,
                            const rgw_obj& obj, RGWObjState **state, bool follow_olh,
                            bool assume_noent, bool ignore_rename)
{
  int ret;

  do {
    ret = get_obj_state_impl(rctx, bucket_info, obj, state, follow_olh,
                             assume_noent, ignore_rename);
  } while (ret == -EAGAIN);

  return ret;
}

int RGWRados::Object::get_manifest(RGWObjManifest **pmanifest)
{
  RGWObjState *astate;
  int r = get_state(&astate, true);
  if (r < 0) {
    return r;
  }

  *pmanifest = &astate->manifest;

  return 0;
}

int RGWRados::Object::Read::get_attr(const char *name, bufferlist& dest)
{
  RGWObjState *state;
  int r = source->get_state(&state, true);
  if (r < 0)
    return r;
  if (!state->exists)
    return -ENOENT;
  if (!state->get_attr(name, dest))
    return -ENODATA;

  return 0;
}


int RGWRados::Object::Stat::stat_async()
{
  RGWObjectCtx& ctx = source->get_ctx();
  rgw_obj& obj = source->get_obj();
  RGWRados *store = source->get_store();

  RGWObjState *s = ctx.obj.get_state(obj); /* calling this one directly because otherwise a sync request will be sent */
  result.obj = obj;
  if (s->has_attrs) {
    state.ret = 0;
    result.size = s->size;
    result.mtime = ceph::real_clock::to_timespec(s->mtime);
    result.attrs = s->attrset;
    result.has_manifest = s->has_manifest;
    result.manifest = s->manifest;
    return 0;
  }

  string oid;
  string loc;
  get_obj_bucket_and_oid_loc(obj, oid, loc);

  int r = store->get_obj_head_ioctx(source->get_bucket_info(), obj, &state.io_ctx);
  if (r < 0) {
    return r;
  }

  librados::ObjectReadOperation op;
  op.stat2(&result.size, &result.mtime, NULL);
  op.getxattrs(&result.attrs, NULL);
  state.completion = librados::Rados::aio_create_completion(NULL, NULL, NULL);
  state.io_ctx.locator_set_key(loc);
  r = state.io_ctx.aio_operate(oid, state.completion, &op, NULL);
  if (r < 0) {
    ldout(store->ctx(), 5) << __func__
						   << ": ERROR: aio_operate() returned ret=" << r
						   << dendl;
    return r;
  }

  return 0;
}


int RGWRados::Object::Stat::wait()
{
  if (!state.completion) {
    return state.ret;
  }

  state.completion->wait_for_safe();
  state.ret = state.completion->get_return_value();
  state.completion->release();

  if (state.ret != 0) {
    return state.ret;
  }

  return finish();
}

int RGWRados::Object::Stat::finish()
{
  map<string, bufferlist>::iterator iter = result.attrs.find(RGW_ATTR_MANIFEST);
  if (iter != result.attrs.end()) {
    bufferlist& bl = iter->second;
    bufferlist::iterator biter = bl.begin();
    try {
      decode(result.manifest, biter);
    } catch (buffer::error& err) {
      RGWRados *store = source->get_store();
      ldout(store->ctx(), 0) << "ERROR: " << __func__ << ": failed to decode manifest"  << dendl;
      return -EIO;
    }
    result.has_manifest = true;
  }

  return 0;
}

/**
 * Get an attribute for a system object.
 * obj: the object to get attr
 * name: name of the attr to retrieve
 * dest: bufferlist to store the result in
 * Returns: 0 on success, -ERR# otherwise.
 */
int RGWRados::system_obj_get_attr(rgw_raw_obj& obj, const char *name, bufferlist& dest)
{
  rgw_rados_ref ref;
  int r = get_system_obj_ref(obj, &ref);
  if (r < 0) {
    return r;
  }

  ObjectReadOperation op;

  int rval;
  op.getxattr(name, &dest, &rval);
  
  r = ref.ioctx.operate(ref.oid, &op, NULL);
  if (r < 0)
    return r;

  return 0;
}

int RGWRados::append_atomic_test(RGWObjectCtx *rctx,
                                 const RGWBucketInfo& bucket_info, const rgw_obj& obj,
                                 ObjectOperation& op, RGWObjState **pstate)
{
  if (!rctx)
    return 0;

  int r = get_obj_state(rctx, bucket_info, obj, pstate, false);
  if (r < 0)
    return r;

  RGWObjState *state = *pstate;

  if (!state->is_atomic) {
    ldout(cct, 20) << "state for obj=" << obj << " is not atomic, not appending atomic test" << dendl;
    return 0;
  }

  if (state->obj_tag.length() > 0 && !state->fake_tag) {// check for backward compatibility
    op.cmpxattr(RGW_ATTR_ID_TAG, LIBRADOS_CMPXATTR_OP_EQ, state->obj_tag);
  } else {
    ldout(cct, 20) << "state->obj_tag is empty, not appending atomic test" << dendl;
  }
  return 0;
}

int RGWRados::Object::get_state(RGWObjState **pstate, bool follow_olh, bool assume_noent)
{
  return store->get_obj_state(&ctx, bucket_info, obj, pstate, follow_olh, assume_noent);
}

void RGWRados::Object::invalidate_state()
{
  ctx.obj.invalidate(obj);
}

void RGWRados::SystemObject::invalidate_state()
{
  ctx.raw.invalidate(obj);
}

int RGWRados::Object::prepare_atomic_modification(ObjectWriteOperation& op, bool reset_obj, const string *ptag,
                                                  const char *if_match, const char *if_nomatch, bool removal_op,
                                                  bool modify_tail)
{
  int r = get_state(&state, false);
  if (r < 0)
    return r;

  // retain rename xattrs
  bool need_guard = (state->has_manifest || (state->obj_tag.length() != 0) ||
                     if_match != NULL || if_nomatch != NULL) &&
                     (!state->fake_tag);

  if (!removal_op) {
    for (auto iter = state->attrset.lower_bound(RGW_ATTR_RENAME_PREFIX);
         iter != state->attrset.end(); ++iter) {
      if (!boost::algorithm::starts_with(iter->first, RGW_ATTR_RENAME_PREFIX))
        break;

      op.setxattr(iter->first.c_str(), iter->second);
    }
  }

  if (!state->is_atomic) {
    ldout(store->ctx(), 20) << "prepare_atomic_modification: state is not atomic. state=" << (void *)state << dendl;

    if (reset_obj) {
      op.create(false);
      store->remove_rgw_head_obj(op); // we're not dropping reference here, actually removing object
    }

    return 0;
  }

  if (need_guard) {
    /* first verify that the object wasn't replaced under */
    if (if_nomatch == NULL || strcmp(if_nomatch, "*") != 0) {
      op.cmpxattr(RGW_ATTR_ID_TAG, LIBRADOS_CMPXATTR_OP_EQ, state->obj_tag);
      // FIXME: need to add FAIL_NOTEXIST_OK for racing deletion
    }

    if (if_match) {
      if (strcmp(if_match, "*") == 0) {
        // test the object is existing
        if (!state->exists) {
          return -ERR_PRECONDITION_FAILED;
        }
      } else {
        bufferlist bl;
        if (!state->get_attr(RGW_ATTR_ETAG, bl) ||
            strncmp(if_match, bl.c_str(), bl.length()) != 0) {
          return -ERR_PRECONDITION_FAILED;
        }
      }
    }

    if (if_nomatch) {
      if (strcmp(if_nomatch, "*") == 0) {
        // test the object is NOT existing
        if (state->exists) {
          return -ERR_PRECONDITION_FAILED;
        }
      } else {
        bufferlist bl;
        if (!state->get_attr(RGW_ATTR_ETAG, bl) ||
            strncmp(if_nomatch, bl.c_str(), bl.length()) == 0) {
          return -ERR_PRECONDITION_FAILED;
        }
      }
    }
  }

  if (reset_obj) {
    if (state->exists) {
      op.create(false);
      store->remove_rgw_head_obj(op);
    } else {
      op.create(true);
    }
  }

  if (removal_op) {
    /* the object is being removed, no need to update its tag */
    return 0;
  }

  if (ptag) {
    state->write_tag = *ptag;
  } else {
    append_rand_alpha(store->ctx(), state->write_tag, state->write_tag, 32);
  }
  bufferlist bl;
  bl.append(state->write_tag.c_str(), state->write_tag.size() + 1);

  ldout(store->ctx(), 10) << "setting object id_tag=" << state->write_tag << dendl;

  op.setxattr(RGW_ATTR_ID_TAG, bl);
  if (modify_tail) {
    op.setxattr(RGW_ATTR_TAIL_TAG, bl);
  }

  return 0;
}

int RGWRados::system_obj_set_attr(void *ctx, rgw_raw_obj& obj, const char *name, bufferlist& bl,
				  RGWObjVersionTracker *objv_tracker)
{
  map<string, bufferlist> attrs;
  attrs[name] = bl;
  return system_obj_set_attrs(ctx, obj, attrs, NULL, objv_tracker);
}

int RGWRados::system_obj_set_attrs(void *ctx, rgw_raw_obj& obj,
                        map<string, bufferlist>& attrs,
                        map<string, bufferlist>* rmattrs,
                        RGWObjVersionTracker *objv_tracker)
{
  rgw_rados_ref ref;
  int r = get_system_obj_ref(obj, &ref);
  if (r < 0) {
    return r;
  }
  ObjectWriteOperation op;

  if (objv_tracker) {
    objv_tracker->prepare_op_for_write(&op);
  }

  map<string, bufferlist>::iterator iter;
  if (rmattrs) {
    for (iter = rmattrs->begin(); iter != rmattrs->end(); ++iter) {
      const string& name = iter->first;
      op.rmxattr(name.c_str());
    }
  }

  for (iter = attrs.begin(); iter != attrs.end(); ++iter) {
    const string& name = iter->first;
    bufferlist& bl = iter->second;

    if (!bl.length())
      continue;

    op.setxattr(name.c_str(), bl);
  }

  if (!op.size())
    return 0;

  bufferlist bl;

  r = ref.ioctx.operate(ref.oid, &op);
  if (r < 0)
    return r;

  return 0;
}

/**
 * Set an attr on an object.
 * bucket: name of the bucket holding the object
 * obj: name of the object to set the attr on
 * name: the attr to set
 * bl: the contents of the attr
 * Returns: 0 on success, -ERR# otherwise.
 */
int RGWRados::set_attr(void *ctx, const RGWBucketInfo& bucket_info, rgw_obj& obj, const char *name, bufferlist& bl)
{
  map<string, bufferlist> attrs;
  attrs[name] = bl;
  return set_attrs(ctx, bucket_info, obj, attrs, NULL);
}

int RGWRados::remove_attr(void *ctx, const RGWBucketInfo& bucket_info, rgw_obj& obj, map<string, bufferlist>& attrs, const string& name, bool ignore_rename)
{
  map<string, bufferlist> rmattrs;
  bufferlist bl;
  rmattrs[name] = bl;
  return set_attrs(ctx, bucket_info, obj, attrs, &rmattrs, nullptr, ignore_rename);
}

#define WAITING_RENAMING_MAX_RETRY 180
int RGWRados::waiting_for_renaming(RGWObjectCtx* obj_ctx, RGWObjState** astate,
                                   const RGWBucketInfo& bucket_info, rgw_obj& obj,
                                   bool wait_short)
{
  bool need_wait = false;
  uint32_t retry = 1;
  do {
    RGWObjState* state = *astate;
    if (!state->exists) {
      ldout(cct, 10) << __func__ << "() obj state exists is false " << obj << dendl;
      return -ENOENT;
    }

    string renaming_info_key = "";
    int ret;
    std::tie(ret, renaming_info_key) =
      get_renaming_info(state->attrset, rgw_bl_to_str(state->attrset[RGW_ATTR_ID_TAG]));
    if (ret == 0) need_wait = true;
    if (ret < 0) {
      ldout(cct, 0) << __func__ << "() ERROR: get_renaming_info ret:" << ret << dendl;
      return ret;
    }

    if (need_wait) {
      if (retry % 10 == 0) {
        if (wait_short) {
          ldout(cct, 10) << __func__ << "() return early by wait_short, obj:" << obj << dendl;
          return 0;
        }
        try_refresh_client_id();
      }
      obj_ctx->obj.invalidate(obj);
      std::this_thread::sleep_for(std::chrono::seconds(1));

      int ret = get_obj_state(obj_ctx, bucket_info, obj, astate, false); /* don't follow olh */
      if (ret < 0) {
        ldout(cct, 0) << "ERROR: get obj state error obj:" << obj << dendl;
        return ret;
      }
    }

    ++retry;
    if (retry > WAITING_RENAMING_MAX_RETRY) {
      ldout(cct, 0) << __func__ << "() ERROR: retry too much refuse request:" << obj << dendl;
      return -ERR_RENAME_CONFLICT;
    }
  } while (need_wait);
  return 0;
}


/*
 * WARNING: attrs must contain whole attrs, xattrs in rados object can retain
 * other attrs without specified in xattrs. While, this function will complete
 * index, which need whole attrs.
 * */
int RGWRados::set_attrs(void *ctx, const RGWBucketInfo& bucket_info, rgw_obj& obj,
                        map<string, bufferlist>& attrs,
                        map<string, bufferlist>* rmattrs,
                        map<string, bufferlist>* cmpattrs,
                        bool ignore_rename)
{
  rgw_rados_ref ref;
  int r = get_obj_head_ref(bucket_info, obj, &ref);
  if (r < 0) {
    return r;
  }
  RGWObjectCtx *rctx = static_cast<RGWObjectCtx *>(ctx);

  ObjectWriteOperation op;
  RGWObjState *state = NULL;

  r = append_atomic_test(rctx, bucket_info, obj, op, &state);
  if (r < 0)
    return r;

  if (!ignore_rename) {
    r = waiting_for_renaming(rctx, &state, bucket_info, obj);
    if (r < 0) {
      ldout(cct, 10) << __func__ << "() ERROR: waiting_for_renaming ret:" << r << dendl;
      return r;
    }
    
  }

  map<string, bufferlist>::iterator iter;

  if (cmpattrs) {
    for (iter = cmpattrs->begin(); iter != cmpattrs->end(); ++iter) {
      const string& name = iter->first;
      bufferlist& bl = iter->second;
      if (!bl.length())
        continue;
      op.cmpxattr(name.c_str(), LIBRADOS_CMPXATTR_OP_EQ, bl);
    }
  }

  if (rmattrs) {
    for (iter = rmattrs->begin(); iter != rmattrs->end(); ++iter) {
      const string& name = iter->first;
      op.rmxattr(name.c_str());
    }
  }

  const rgw_bucket& bucket = obj.bucket;

  bufferlist* tags_bl = nullptr;

  for (iter = attrs.begin(); iter != attrs.end(); ++iter) {
    const string& name = iter->first;
    bufferlist& bl = iter->second;

    if (!bl.length())
      continue;

    if (rmattrs && rmattrs->find(name) != rmattrs->end()) {
      continue;
    }

    op.setxattr(name.c_str(), bl);

    if (name.compare(RGW_ATTR_DELETE_AT) == 0) {
      real_time ts;
      try {
        decode(ts, bl);

        rgw_obj_index_key obj_key;
        obj.key.get_index_key(&obj_key);

        objexp_hint_add(ts, bucket.tenant, bucket.name, bucket.bucket_id, obj_key);
      } catch (buffer::error& err) {
        ldout(cct, 0) << "ERROR: failed to decode " RGW_ATTR_DELETE_AT << " attr" << dendl;
        return -EIO;
      }
    } else if (name.compare(RGW_ATTR_TAGS) == 0) {
      tags_bl = &(iter->second);
    }
  }

  if (!op.size())
    return 0;

  RGWObjectCtx obj_ctx(this);

  bufferlist bl;
  RGWRados::Bucket bop(this, bucket_info);
  RGWRados::Bucket::UpdateIndex index_op(&bop, obj);

  if (state) {
    string tag;
    append_rand_alpha(cct, tag, tag, 32);
    state->write_tag = tag;
    r = index_op.prepare(CLS_RGW_OP_ADD, &state->write_tag);

    if (r < 0)
      return r;

    bl.append(tag.c_str(), tag.size() + 1);
    ldout(cct, 10) << "setting object id_tag=" << tag << dendl;
    op.setxattr(RGW_ATTR_ID_TAG,  bl);
  }


  real_time mtime = real_clock::now();
  struct timespec mtime_ts = real_clock::to_timespec(mtime);
  op.mtime2(&mtime_ts);
  r = ref.ioctx.operate(ref.oid, &op);
  if (state) {
    if (r >= 0) {
      bufferlist acl_bl = attrs[RGW_ATTR_ACL];
      bufferlist etag_bl = attrs[RGW_ATTR_ETAG];
      bufferlist content_type_bl = attrs[RGW_ATTR_CONTENT_TYPE];
      string etag = rgw_bl_to_str(etag_bl);
      string content_type = rgw_bl_to_str(content_type_bl);
      string storage_class;
      auto iter = attrs.find(RGW_ATTR_STORAGE_CLASS);
      if (iter != attrs.end()) {
        storage_class = rgw_bl_to_str(iter->second);
      }
      uint64_t epoch = ref.ioctx.get_last_version();
      int64_t poolid = ref.ioctx.get_id();
      r = index_op.complete(poolid, epoch, state->size, state->accounted_size,
                            mtime, etag, content_type, &acl_bl,
                            RGW_OBJ_CATEGORY_MAIN, NULL, storage_class,
                            nullptr, true, false, tags_bl);
    } else {
      int ret = index_op.cancel();
      if (ret < 0) {
        ldout(cct, 0) << "ERROR: complete_update_index_cancel() returned ret=" << ret << dendl;
      }
    }
  }
  if (r < 0)
    return r;

  if (state) {
    state->obj_tag.swap(bl);

    for (iter = attrs.begin(); iter != attrs.end(); ++iter) {
      state->attrset[iter->first] = iter->second;
    }

    if (rmattrs) {
      for (iter = rmattrs->begin(); iter != rmattrs->end(); ++iter) {
        state->attrset.erase(iter->first);
      }
    }

    auto iter = state->attrset.find(RGW_ATTR_ID_TAG);
    if (iter != state->attrset.end()) {
      iter->second = state->obj_tag;
    }
  }

  return 0;
}

int RGWRados::Object::Read::prepare()
{
  RGWRados *store = source->get_store();
  CephContext *cct = store->ctx();

  bufferlist etag;

  map<string, bufferlist>::iterator iter;

  RGWObjState *astate;
  int r = source->get_state(&astate, true);
  if (r < 0)
    return r;

  if (!astate->exists) {
    return -ENOENT;
  }

  const RGWBucketInfo& bucket_info = source->get_bucket_info();

  state.obj = astate->obj;
  store->obj_to_raw(bucket_info.head_placement_rule, state.obj, &state.head_obj);

  state.cur_pool = state.head_obj.pool;
  state.cur_ioctx = &state.io_ctxs[state.cur_pool];

  r = store->get_obj_head_ioctx(bucket_info, state.obj, state.cur_ioctx);
  if (r < 0) {
    return r;
  }
  if (params.attrs) {
    *params.attrs = astate->attrset;
    if (cct->_conf->subsys.should_gather<ceph_subsys_rgw, 20>()) {
      for (iter = params.attrs->begin(); iter != params.attrs->end(); ++iter) {
        ldout(cct, 30) << "Read xattr:" << iter->first
                       << ", value:" << rgw_bl_to_str(iter->second) << dendl;
      }
    }
  }

  /* Convert all times go GMT to make them compatible */
  if (conds.mod_ptr || conds.unmod_ptr) {
    obj_time_weight src_weight;
    src_weight.init(astate);
    src_weight.high_precision = conds.high_precision_time;

    obj_time_weight dest_weight;
    dest_weight.high_precision = conds.high_precision_time;

    if (conds.mod_ptr) {
      dest_weight.init(*conds.mod_ptr, conds.mod_zone_id, conds.mod_pg_ver);
      ldout(cct, 10) << "If-Modified-Since: " << dest_weight << " Last-Modified: " << src_weight << dendl;
      if (!(dest_weight < src_weight)) {
        return -ERR_NOT_MODIFIED;
      }
    }

    if (conds.unmod_ptr) {
      dest_weight.init(*conds.unmod_ptr, conds.mod_zone_id, conds.mod_pg_ver);
      ldout(cct, 10) << "If-UnModified-Since: " << dest_weight << " Last-Modified: " << src_weight << dendl;
      if (dest_weight < src_weight) {
        return -ERR_PRECONDITION_FAILED;
      }
    }
  }
  if (conds.if_match || conds.if_nomatch) {
    r = get_attr(RGW_ATTR_ETAG, etag);
    if (r < 0)
      return r;



    if (conds.if_match) {
      string if_match_str = rgw_string_unquote(conds.if_match);
      ldout(cct, 10) << "ETag: " << string(etag.c_str(), etag.length()) << " " << " If-Match: " << if_match_str << dendl;
      if (if_match_str.compare(0, etag.length(), etag.c_str(), etag.length()) != 0) {
        return -ERR_PRECONDITION_FAILED;
      }
    }

    if (conds.if_nomatch) {
      string if_nomatch_str = rgw_string_unquote(conds.if_nomatch);
      ldout(cct, 10) << "ETag: " << string(etag.c_str(), etag.length()) << " " << " If-NoMatch: " << if_nomatch_str << dendl;
      if (if_nomatch_str.compare(0, etag.length(), etag.c_str(), etag.length()) == 0) {
        return -ERR_NOT_MODIFIED;
      }
    }
  }

  if (params.obj_size)
    *params.obj_size = astate->size;
  if (params.lastmod)
    *params.lastmod = astate->mtime;

  return 0;
}

int RGWRados::Object::Read::range_to_ofs(uint64_t obj_size, int64_t &ofs, int64_t &end)
{
  if (ofs < 0) {
    ofs += obj_size;
    if (ofs < 0)
      ofs = 0;
    end = obj_size - 1;
  } else if (end < 0) {
    end = obj_size - 1;
  }

  if (obj_size > 0) {
    if (ofs >= (off_t)obj_size) {
      return -ERANGE;
    }
    if (end >= (off_t)obj_size) {
      end = obj_size - 1;
    }
  }
  return 0;
}

int RGWRados::stat_system_obj(RGWObjectCtx& obj_ctx,
                              RGWRados::SystemObject::Read::GetObjState& state,
                              rgw_raw_obj& obj,
                              map<string, bufferlist> *attrs,
                              real_time *lastmod,
                              uint64_t *obj_size,
                              RGWObjVersionTracker *objv_tracker)
{
  RGWRawObjState *astate = NULL;

  int r = get_system_obj_state(&obj_ctx, obj, &astate, objv_tracker);
  if (r < 0)
    return r;

  if (!astate->exists) {
    return -ENOENT;
  }

  if (attrs) {
    *attrs = astate->attrset;
    if (cct->_conf->subsys.should_gather<ceph_subsys_rgw, 20>()) {
      map<string, bufferlist>::iterator iter;
      for (iter = attrs->begin(); iter != attrs->end(); ++iter) {
        ldout(cct, 20) << "Read xattr: " << iter->first << dendl;
      }
    }
  }

  if (obj_size)
    *obj_size = astate->size;
  if (lastmod)
    *lastmod = astate->mtime;

  return 0;
}


int RGWRados::Bucket::UpdateIndex::guard_reshard(BucketShard **pbs, std::function<int(BucketShard *)> call)
{
  RGWRados *store = target->get_store();
  BucketShard *bs;
  int r;

#define NUM_RESHARD_RETRIES 10
  for (int i = 0; i < NUM_RESHARD_RETRIES; ++i) {
    int ret = get_bucket_shard(&bs);
    if (ret < 0) {
      ldout(store->ctx(), 5) << "failed to get BucketShard object: ret=" << ret << dendl;
      return ret;
    }
    r = call(bs);
    if (r != -ERR_BUSY_RESHARDING) {
      break;
    }
    ldout(store->ctx(), 0) << "NOTICE: resharding operation on bucket index detected, blocking" << dendl;
    string new_bucket_id;
    r = store->block_while_resharding(bs, &new_bucket_id, target->bucket_info);
    if (r == -ERR_BUSY_RESHARDING) {
      continue;
    }
    if (r < 0) {
      return r;
    }
    ldout(store->ctx(), 20) << "reshard completion identified, new_bucket_id=" << new_bucket_id << dendl;
    i = 0; /* resharding is finished, make sure we can retry */
    r = target->update_bucket_id(new_bucket_id);
    if (r < 0) {
      ldout(store->ctx(), 0) << "ERROR: update_bucket_id() new_bucket_id=" << new_bucket_id << " returned r=" << r << dendl;
      return r;
    }
    invalidate_bs();
  }

  if (r < 0) {
    return r;
  }

  if (pbs) {
    *pbs = bs;
  }

  return 0;
}

int RGWRados::SystemObject::Read::stat(RGWObjVersionTracker *objv_tracker)
{
  RGWRados *store = source->get_store();
  rgw_raw_obj& obj = source->get_obj();

  return store->stat_system_obj(source->get_ctx(), state, obj, stat_params.attrs,
                                stat_params.lastmod, stat_params.obj_size, objv_tracker);
}

int RGWRados::Bucket::UpdateIndex::prepare(RGWModifyOp op, const string *write_tag)
{
  if (blind) {
    return 0;
  }
  RGWRados *store = target->get_store();

  if (write_tag && write_tag->length()) {
    optag = string(write_tag->c_str(), write_tag->length());
  } else {
    if (optag.empty()) {
      append_rand_alpha(store->ctx(), optag, optag, 32);
    }
  }

  int r = guard_reshard(nullptr, [&](BucketShard *bs) -> int {
				   return store->cls_obj_prepare_op(*bs, op, optag, obj, bilog_flags, zones_trace);
				 });

  if (r < 0) {
    return r;
  }
  prepared = true;

  return 0;
}

int RGWRados::Bucket::UpdateIndex::complete(int64_t poolid, uint64_t epoch,
                                            uint64_t size, uint64_t accounted_size,
                                            ceph::real_time& ut, const string& etag,
                                            const string& content_type,
                                            bufferlist *acl_bl,
                                            RGWObjCategory category,
                                            list<rgw_obj_index_key> *remove_objs,
                                            const string& storage_class,
                                            const string *user_data,
                                            bool accounted_entry,
                                            bool appendable,
                                            bufferlist* tags_bl)
{
  if (blind) {
    return 0;
  }
  RGWRados *store = target->get_store();
  BucketShard *bs;

  int ret = get_bucket_shard(&bs);
  if (ret < 0) {
    ldout(store->ctx(), 5) << "failed to get BucketShard object: ret=" << ret << dendl;
    return ret;
  }

  rgw_bucket_dir_entry ent;
  obj.key.get_index_key(&ent.key);
  ent.meta.size = size;
  ent.meta.accounted_size = accounted_size;
  ent.meta.mtime = ut;
  ent.meta.etag = etag;
  ent.meta.appendable = appendable;
  if (user_data)
    ent.meta.user_data = *user_data;
  ent.meta.storage_class = storage_class;
  ent.meta.accounted_entry = accounted_entry;
  if (tags_bl && tags_bl->length() > 0) {
    ent.meta.has_tags = true;
    ent.meta.tags_bl = *tags_bl;
  }

  ACLOwner owner;
  if (acl_bl && acl_bl->length()) {
    int ret = store->decode_policy(*acl_bl, &owner);
    if (ret < 0) {
      ldout(store->ctx(), 0) << "WARNING: could not decode policy ret=" << ret << dendl;
    }
  }
  ent.meta.owner = owner.get_id().to_str();
  ent.meta.owner_display_name = owner.get_display_name();
  ent.meta.content_type = content_type;

  ret = store->cls_obj_complete_add(*bs, obj, optag, poolid, epoch, ent, category, remove_objs,
                                    bilog_flags, zones_trace, bilog_write_enable, bilog_delete_enable);

  bool ignore_bucket_initial = true;
  #ifdef WITH_UNAUTO_SYNC
    ignore_bucket_initial = !(target->bucket_info.disable_sync.size() == 0 &&
                              target->bucket_info.bilog_flags.size() == 0);
  #endif
  if (target->bucket_info.datasync_flag_enabled(store->get_zone().id) &&
      !store->datasync_all_disabled(target->bucket_info) && ignore_bucket_initial) {
    int r = store->data_log->add_entry(bs->bucket, bs->shard_id);
    if (r < 0) {
      lderr(store->ctx()) << "ERROR: failed writing data log" << dendl;
    }
  }

  return ret;
}

int RGWRados::Bucket::UpdateIndex::complete_del(int64_t poolid, uint64_t epoch,
                                                real_time& removed_mtime,
                                                list<rgw_obj_index_key> *remove_objs)
{
  if (blind) {
    return 0;
  }
  RGWRados *store = target->get_store();
  BucketShard *bs;

  int ret = get_bucket_shard(&bs);
  if (ret < 0) {
    ldout(store->ctx(), 5) << "failed to get BucketShard object: ret=" << ret << dendl;
    return ret;
  }

  ret = store->cls_obj_complete_del(*bs, optag, poolid, epoch, obj, removed_mtime, remove_objs,
                                     bilog_flags, zones_trace, bilog_write_enable);
  
  bool ignore_bucket_initial = true;
  #ifdef WITH_UNAUTO_SYNC
    ignore_bucket_initial = !(target->bucket_info.disable_sync.size() == 0 &&
                              target->bucket_info.bilog_flags.size() == 0);
  #endif
  if (target->bucket_info.datasync_flag_enabled(store->get_zone().id) &&
      !store->datasync_all_disabled(target->bucket_info) && ignore_bucket_initial) {
    int r = store->data_log->add_entry(bs->bucket, bs->shard_id);
    if (r < 0) {
      lderr(store->ctx()) << "ERROR: failed writing data log" << dendl;
    }
  }

  return ret;
}


int RGWRados::Bucket::UpdateIndex::cancel()
{
  if (blind) {
    return 0;
  }
  RGWRados *store = target->get_store();
  BucketShard *bs;

  int ret = guard_reshard(&bs, [&](BucketShard *bs) -> int {
				 return store->cls_obj_complete_cancel(*bs, optag, obj, bilog_flags, zones_trace);
			       });

  /*
   * need to update data log anyhow, so that whoever follows needs to update its internal markers
   * for following the specific bucket shard log. Otherwise they end up staying behind, and users
   * have no way to tell that they're all caught up
   */
  bool ignore_bucket_initial = true;
  #ifdef WITH_UNAUTO_SYNC
    ignore_bucket_initial = !(target->bucket_info.disable_sync.size() == 0 &&
                              target->bucket_info.bilog_flags.size() == 0);
  #endif
  if (target->bucket_info.datasync_flag_enabled(store->get_zone().id) &&
      !store->datasync_all_disabled(target->bucket_info) && ignore_bucket_initial) {
    int r = store->data_log->add_entry(bs->bucket, bs->shard_id);
    if (r < 0) {
      lderr(store->ctx()) << "ERROR: failed writing data log" << dendl;
    }
  }

  return ret;
}


int RGWRados::Bucket::Namespace::init()
{
  if (inited) {
    return 0;
  }

  level = namespace_split_filepath(obj_name, parents);
  complete_bottom_level = level;
  complete_top_level = 0;

  if (level > 0) {
    int c_index = level -1;
    string parent_name = namespace_cut_parent_path(obj_name, parents, c_index);
    file_name = obj_name.substr(parents[c_index].offset, parents[c_index].length);
    parent_oid = namespace_get_parent_oid(target->bucket.marker, parent_name, c_index);
    parent_versions.reserve(level);
  }


  int r = store->open_bucket_index_ctx(target->get_bucket_info(), io_ctx);
  if (r < 0) {
    return r;
  }

  inited = true;
  return 0;
}

/**
 * prepare: from top to bottom
 * complete: from top to bottom
 * cancel: from bottom to top
 *
 *     fast  prepare complete  cancel
 *    prepare  +        +        ^   <-- complete_top_level
 *             |        |        |
 *   /         |        |        |
 *   a         |        |        |
 *   /         |        |        |
 *   b   ^     |        |        |
 *   /   |     |        |        |
 *   c   |     |        |        |
 *       +     v        v        +   <-- complete_bottom_level
 */
int RGWRados::Bucket::Namespace::prepare(const req_state* s, RGWModifyOp op,
                                         const string *write_tag, ceph::real_time& ut)
{
  if (without_namespace) {
    return 0;
  }

  ldout(store->ctx(), 10) << __func__ << " start prepare for object " << obj_name << dendl;

  // init Namespace
  if (!inited) {
    int r = init();
    if (r < 0) {
      ldout(store->ctx(), 0) << __func__ <<  " ERROR: failed init " << obj_name
                             << " ret=" << r << dendl;
      return r;
    }
  }

  assert(level > 0);

  // generate optag
  if (write_tag && write_tag->length()) {
    optag = string(write_tag->c_str(), write_tag->length());
  } else {
    if (optag.empty()) {
      append_rand_alpha(store->ctx(), optag, optag, 32);
    }
  }

  int level_of_file = level -1;
  int c_index =  level_of_file;
  int r = 0;
  int op_num = 1;

  // reset the val
  complete_top_level = level;
  complete_bottom_level = -1;

  ldout(store->ctx(), 20) << __func__ << " prepare file "
                          << obj_name << " optag=" << optag << dendl;

  // try to fast prepare this file
  if ( level == 1) { // parent directory is root "/", don't need root be completed
    r = store->cls_namespace_prepare_op(io_ctx, op, optag, obj_name, parent_oid, file_name);
  } else { // parent must be completed, prepare op with exclusive flag
    r = store->cls_namespace_prepare_op_excl(io_ctx, op, optag, obj_name, parent_oid, file_name);
  }

  if (r == -ENOENT) {
    ldout(store->ctx(), 20) << __func__ << " failed to quick namespace prepare "
                            << obj_name <<  dendl;
  } else if (r < 0) {
    ldout(store->ctx(), 0) << __func__ << " ERROR:: failed namespace prepare " << obj_name
                           << " ret= " << r << " " << obj_name << dendl;
    return r;
  } else {
    ldout(store->ctx(), 20) << __func__ << " success quick namespace prepare "
                            << obj_name << dendl;
    complete_top_level = c_index;
    complete_bottom_level = c_index;
    prepared = true;

    if (s != nullptr) {
      perfcounter->tinc(l_rgw_put_quick_prepare_namespace_lat, s->time_elapsed());
      perfcounter->inc(l_rgw_put_prepare_namespace_cls_op, op_num);
    }
    return r;
  }

  string dir_name;
  string parent_name;
  string pparent_oid;

  --c_index;

  // try to prepare dir bottom-up with flag EXCLUDE
  // prepare dir with flag EXCLUDE
  for (; c_index >= 0; --c_index) {
    dir_name = std::move(obj_name.substr(parents[c_index].offset, parents[c_index].length));
    parent_name = std::move(namespace_cut_parent_path(obj_name, parents, c_index));
    pparent_oid = std::move(namespace_get_parent_oid(target->bucket.marker, parent_name,
                                                     c_index));
    if ( c_index == 0) {
      r = store->cls_namespace_dir_prepare_op(io_ctx, CLS_RGW_OP_ADD, optag, pparent_oid,
                                              dir_name, ut);
    } else {
      r = store->cls_namespace_dir_prepare_op_excl(io_ctx, CLS_RGW_OP_ADD, optag, pparent_oid,
                                                   dir_name, ut);
    }
    ++ op_num;

    // if error code is EEXIST (have the same name file), we need to cacel prepare op which
    // has been prepared.
    if (r == -ENOENT) {
      ldout(store->ctx(), 20) << __func__ << " bottom-up prepare "
                              << dir_name << " not compelete ["
                              << obj_name << ", level " << c_index
                              << ", " << pparent_oid
                              << ", optag=" << optag << "]" << dendl;
      continue;
    } else if (r < 0) {
      ldout(store->ctx(), 0) << __func__ << " ERROR: failed to prepare " << dir_name
                             << "[" << obj_name << ", level " << c_index
                             << ", " << pparent_oid
                             << ", optag=" << optag << ", ret=" << r << "]" << dendl;
      return r;
    }

    complete_top_level = c_index;
    complete_bottom_level = c_index;
    parent_versions[c_index] = io_ctx.get_last_version();

    ldout(store->ctx(), 20) <<  __func__ << " bottom-up prepare compelete "
                            << dir_name << " compelete ["
                            << obj_name << ", level " << c_index
                            << ", " << pparent_oid
                            << ", optag=" << optag
                            << ", epoch=" << parent_versions[c_index] << "]" << dendl;
    // parent exist
    break;
  }

  ++ c_index;

  // all parent directory are uncompleted
  if (complete_top_level == level) {
    complete_top_level = c_index;
  }

  // prepare dir from top to bottom, without flag EXCLUDE
  for (; c_index < level_of_file; ++c_index) {
    dir_name = std::move(obj_name.substr(parents[c_index].offset, parents[c_index].length));
    parent_name = std::move(namespace_cut_parent_path(obj_name, parents, c_index));
    pparent_oid = std::move(namespace_get_parent_oid(target->bucket.marker, parent_name,
                                                     c_index));
    ++ op_num;
    r = store->cls_namespace_dir_prepare_op(io_ctx, CLS_RGW_OP_ADD, optag, pparent_oid,
                                            dir_name, ut);
    // we need to cacel prepare op which has been prepared.
    if (r < 0) {
      ldout(store->ctx(), 0) << __func__ << " ERROR: failed to prepare "
                             << dir_name << " ["  << obj_name << ", level " << c_index
                             << ", ret=" << r << "]" << dendl;
     goto done_cancel;
    }

    complete_bottom_level = c_index;
    // the last version of parent
    parent_versions[c_index] = io_ctx.get_last_version();

    ldout(store->ctx(), 20) <<  __func__ << " up-bottom prepare "
                            << dir_name << " success ["
                            << obj_name << ", level " << c_index
                            << ", " << pparent_oid
                            << ", epoch=" << parent_versions[c_index]
                            << ", optag=" << optag << "]" << dendl;
  }

  ++ op_num;
  // prepare file
  r = store->cls_namespace_prepare_op(io_ctx, op, optag, obj_name, parent_oid, file_name);
  if (r < 0) {
    ldout(store->ctx(), 0) << __func__ << " ERROR: failed namespace prepare " << obj_name
                           << " ret=" << r  << dendl;

    // the parent of this file maybe delete, maybe timeout
    goto done_cancel;
  }

  complete_bottom_level = level_of_file;
  parent_versions[level_of_file] = io_ctx.get_last_version();
  prepared = true;
  if (s != nullptr) {
    perfcounter->tinc(l_rgw_put_slow_prepare_namespace_lat, s->time_elapsed());
    perfcounter->inc(l_rgw_put_prepare_namespace_cls_op, op_num);
  }

  return 0;

done_cancel:
  if (s != nullptr) {
    perfcounter->inc(l_rgw_put_prepare_namespace_cancel);
  }

  // call cancel
  cancel(true);
  return r;
}

int RGWRados::Bucket::Namespace::complete(int64_t poolid, uint64_t epoch, uint64_t size,
                                          ceph::real_time& ut, bool appendable)
{
  if (without_namespace) {
    return 0;
  }

  assert(level > 0);

  ldout(store->ctx(), 10) << __func__ << " do complete for " << obj_name << dendl;
  // init Namespace
  if (!inited) {
    int r = init();
    if (r < 0) {
      ldout(store->ctx(), 0) << __func__ <<  "ERROR: failed init Namespace ret="
                             << r << dendl;
      return r;
    }
  }

  // complete dir
  int bottom = complete_bottom_level;
  if (complete_bottom_level == level - 1) {
    -- bottom;
  }

  ldout(store->ctx(), 20) << __func__ << " complete " << obj_name
                          << " top=" << complete_top_level
                          << " bottom=" << complete_bottom_level << dendl;

  // from top to bottom
  while (complete_top_level <= bottom) {
    string dir_name = std::move(obj_name.substr(parents[complete_top_level].offset,
                                                parents[complete_top_level].length));
    string parent_name = std::move(namespace_cut_parent_path(obj_name, parents,
                                                             complete_top_level));
    string pparent_oid = std::move(namespace_get_parent_oid(target->bucket.marker, parent_name,
                                                            complete_top_level));

    uint64_t p_epoch = parent_versions[complete_top_level + 1];
    ldout(store->ctx(), 20) << __func__ << " start complete " << dir_name
                            << " [dir, " << obj_name << ", epoolid=" << namespace_poolid
                            << ", pparent_oid=" << pparent_oid
                            << ", optag=" << optag
                            << ", epoch=" << p_epoch
                            << ", level=" << complete_top_level << "]" << dendl;
    int r = store->cls_namespace_dir_complete_add(io_ctx, poolid, p_epoch, optag, pparent_oid,
        dir_name, ut);
    // if failed to complete dir, don't need to cancel this op
    if (r < 0) {
      ldout(store->ctx(), 0) << __func__ << " ERROR: failed to complete " << dir_name
                             << " [" << obj_name
                             << ", level " << complete_top_level
                             << ", pparent_oid=" << pparent_oid
                             << ", optag=" << optag
                             << ", epoch=" << p_epoch
                             << "] ret=" << r << dendl;
      return r;
    }
    ++ complete_top_level;
  }

  // complete obj
  int r = store->cls_namespace_complete_add(io_ctx, optag, parent_oid, file_name, poolid, epoch,
                                           size, &ut, appendable);
  if (r < 0) {
      ldout(store->ctx(), 0) << __func__ << " ERROR: failed to complete " << obj_name
                             << " [" << parent_oid
                             << ", " << file_name
                             << ", optag=" << optag
                             << ", optag=" << optag
                             << ", epoch=" << epoch
                             << ", appendable=" << appendable
                             << "] ret=" << r << dendl;
  }

  complete_top_level = level;
  complete_bottom_level = -1;

  return r;
}

int RGWRados::Bucket::Namespace::complete_del(int64_t poolid, uint64_t epoch,
                                              ceph::real_time* remove_time)
{
  if (without_namespace) {
    return 0;
  }
  assert(level > 0);

  ldout(store->ctx(), 10) << __func__ << " complete del "
                          << obj_name << " optag=" << optag << dendl;
  // init Namespace
  if (!inited) {
    int r = init();
    if (r < 0) {
      ldout(store->ctx(), 0) << __func__ <<  "ERROR: failed init namespace "
                             << obj_name << " ret=" << r << dendl;
      return r;
    }
  }

  return store->cls_namespace_complete_del(io_ctx, optag, parent_oid, file_name, poolid, epoch,
      remove_time);
}

int RGWRados::Bucket::Namespace::cancel(bool force_delete)
{
  if (without_namespace) {
    return 0;
  }

  assert(level > 0);

  ldout(store->ctx(), 10) << __func__ << " bucket namespace cancel "
                         << obj_name << " top " << complete_top_level
                         << " bottom " << complete_bottom_level << dendl;
  // init Namespace
  if (!inited) {
    int r = init();
    if (r < 0) {
      ldout(store->ctx(), 0) << __func__ <<  "ERROR: failed namespace init "
                             << obj_name << " ret=" << r << dendl;
      return r;
    }
  }

  ceph::real_time ut = ceph::real_clock::now();
  int c_index = complete_bottom_level;

  // cancel file
  if (complete_bottom_level == level - 1) {
    ldout(store->ctx(), 20) << __func__ << " Namespace::cancel "
                            << file_name << " [file, " << obj_name
                            << ", optag " << optag << "]" << dendl;

    int r = store->cls_namespace_complete_cancel(io_ctx, optag, parent_oid, file_name, force_delete);
    if (r < 0) {
      ldout(store->ctx(), 0) << __func__
                             << " ERROR: failed namespace cancel " << file_name
                             << " [file, " << obj_name
                             << ", parent_oid=" << parent_oid
                             << ", optag=" << optag
                             << ", ret=" << r << "]" << dendl;
      return r;
    }
    -- c_index;
  }

  // cancel dir, from bottom to top
  for (; c_index >= complete_top_level; --c_index) {
    string dir_name = std::move(obj_name.substr(parents[c_index].offset, parents[c_index].length));
    string parent_name = std::move(namespace_cut_parent_path(obj_name, parents, c_index));
    string pparent_oid = std::move(namespace_get_parent_oid(target->bucket.marker, parent_name, c_index));

    ldout(store->ctx(), 20) << __func__ << " Namespace::cancel " << dir_name
                            << "[dir, " << obj_name << ", level=" << c_index
                            << ", " << pparent_oid << ", optag " << optag << "]" << dendl;

    int r = store->cls_namespace_dir_complete_cancel(io_ctx, optag, pparent_oid, dir_name, ut,
        force_delete);
    if (r < 0) {
       ldout(store->ctx(), 0) << __func__
                              << " ERROR: namespace failed cancel " << dir_name
                              << " [file, " << obj_name
                              << ", parent_oid=" << pparent_oid
                              << ", optag=" << optag
                              << ", ret=" << r << "]" << dendl;
      return r;
    }
  }

  return 0;
}

int RGWRados::Bucket::Namespace::make_dir(RGWRados *store, const req_state *s)
{
  const RGWBucketInfo& bucket_info = s->bucket_info;
  const string& obj_name = s->object.name;
  vector<string_extent> parents;

  // split object name
  int level = namespace_split_filepath(obj_name, parents);
  // it's not neccessary to make root directory
  if (level == 0) {
    ldout(store->ctx(), 0) << __func__ << " ERROR: dir_name is /" << dendl;
    return -EINVAL;
  }

  ldout(store->ctx(), 10) << __func__ << " start make dir " << obj_name << dendl;

  // get new IoCtx
  librados::IoCtx io_ctx;
  int r = store->open_bucket_index_ctx(bucket_info, io_ctx);
  if (r < 0) {
    ldout(store->ctx(), 0) << __func__ << " Error: failed open bucket index ctx ret="
                           << r << dendl;
    return r;
  }

  // init optag
  string optag;
  append_rand_alpha(store->ctx(), optag, optag, 32);

  ceph::real_time ut = ceph::real_clock::now();

  int c_index = level - 1;
  string parent_name = namespace_cut_parent_path(obj_name, parents, c_index);
  string parent_oid = namespace_get_parent_oid(bucket_info.bucket.marker, parent_name, c_index);
  string dir_name = std::move(obj_name.substr(parents[c_index].offset, parents[c_index].length));

  ldout(store->ctx(), 20) << __func__ << " try prepare dir " << obj_name
                          << " " << parent_oid << " " << dir_name
                          << " optag=" << optag << dendl;

  // TODO: need to check if the directory already exists
  // try to prepare directory
  if ( level == 1) { // parent directory is root "/", don't need root be completed
    r = store->cls_namespace_dir_prepare_op(io_ctx, CLS_RGW_OP_ADD, optag, parent_oid,
                                                   dir_name, ut);
  } else { // parent must be completed, prepare this directory with exclusive flag
    r = store->cls_namespace_dir_prepare_op_excl(io_ctx, CLS_RGW_OP_ADD, optag, parent_oid,
                                                   dir_name, ut);
  }
  if (r < 0) {
    // parent not exist, fail!
    if (r == -ENOENT) {
      r = -ERROR_BUCKET_NAMESPACE_PARENT_NOEXIST;
    }

    ldout(store->ctx(), 0) << __func__ << " Error: failed prepare dir " << obj_name
                           << " ret=" << r << dendl;
    return r;
  }

  parent_name = namespace_cut_parent_path(obj_name, parents, level);
  string dir_oid =  namespace_get_parent_oid(bucket_info.bucket.marker, parent_name, level);

  // start create directory
  // create empty oid in rados, the status of this directory is uncompleted
  r = store->cls_namespace_dir_make_complete(io_ctx, dir_oid);
  if (r >= 0) {
    // get pool id and last version
    int64_t poolid = io_ctx.get_id();
    uint64_t epoch = io_ctx.get_last_version();
    r = store->cls_namespace_dir_complete_add(io_ctx, poolid, epoch, optag, parent_oid,
                                              dir_name, ut);
  } else {
    ldout(store->ctx(), 0) << __func__ <<  " ERROR: failed to prepare make directory "
                           << obj_name << " " << parent_oid << " " << dir_name
                           << " ret=" << r << dendl;
    if (r == -EEXIST) {
      r = -ERROR_BUCKET_NAMESPACE_DIR_EXIST;
    }
    store->cls_namespace_dir_complete_cancel(io_ctx, optag, parent_oid, dir_name,
                                             ut, true);
  }

  return r;
}

int RGWRados::Bucket::Namespace::delete_dir(RGWRados::Object *target, const string& obj_name)
{
  // split object name
  vector<string_extent> parents;
  RGWBucketInfo& bucket_info = target->get_bucket_info();
  int level = namespace_split_filepath(obj_name, parents);

  // get new IoCtx
  librados::IoCtx io_ctx;
  RGWRados *store = target->get_store();

  ldout(store->ctx(), 10) << __func__ << " namespace delete_dir " << obj_name << dendl;

  int r = store->open_bucket_index_ctx(target->get_bucket_info(), io_ctx);
  if (r < 0) {
    ldout(store->ctx(), 0) << __func__ << " Error: failed open bucket index ctx ret="
                           << r << dendl;
    return r;
  }

  // delete root directory "/"
  if (level == 0) {
    string dir_oid = namespace_get_parent_oid(bucket_info.bucket.marker, "", 0);
    r = store->cls_namespace_dir_del(io_ctx, dir_oid);
    if (r == -EEXIST) {
      ldout(store->ctx(), 1) << __func__ << "WARNING: have the same name file with dir "
                             << dir_oid << dendl;
      r = -ENOENT;
    } else if (r == -ENOTEMPTY) {
      ldout(store->ctx(), 1) << __func__ << "WARNING: dir " << dir_oid
                             << " is not empty" << dendl;
    } else if (r < 0) {
      ldout(store->ctx(), 0) << __func__ << "ERROR: failed delete dir "
                             << dir_oid << " ret=" << r << dendl;
    }
    return r;
  }

  // delete middle directory
  // get the oid of self
  string parent_name = namespace_cut_parent_path(obj_name, parents, level);
  string dir_oid =  namespace_get_parent_oid(bucket_info.bucket.marker, parent_name, level);

  // get parent oid
  int c_i =  level-1; // current index
  parent_name = namespace_cut_parent_path(obj_name, parents, c_i);
  string parent_oid = namespace_get_parent_oid(bucket_info.bucket.marker, parent_name, c_i);
  string child_name = std::move(obj_name.substr(parents[c_i].offset, parents[c_i].length));

  // get optag
  string optag;
  append_rand_alpha(store->ctx(), optag, optag, 32);

  // prepare delete middle directory
  ceph::real_time ut = ceph::real_clock::now();
  r = store->cls_namespace_dir_prepare_op(io_ctx, CLS_RGW_OP_DEL, optag, parent_oid,
                                          child_name, ut);
  if (r == -EEXIST) {
    ldout(store->ctx(), 1) << __func__ << "WARNING: have the same name file with dir "
                           << dir_oid << dendl;
    r = -ENOENT;
  } else if (r < 0) {
    return r;
  }

  // delete directory
  r = store->cls_namespace_dir_del(io_ctx, dir_oid);
  if (r >=0) {
    int64_t poolid = io_ctx.get_id();
    uint64_t epoch = io_ctx.get_last_version();

    // update parent
    r = store->cls_namespace_dir_complete_del(io_ctx, poolid, epoch, optag, parent_oid,
        child_name, ut);
  } else {
    // cancel op
    ldout(store->ctx(), 10) << __func__ << " start cancel dir complete "
                            << parent_oid << dendl;
    store->cls_namespace_dir_complete_cancel(io_ctx, optag, parent_oid, child_name, ut, false);
  }

  return r;
}

int RGWRados::Bucket::Namespace::list_dir(req_state* s, RGWRados::Bucket *target,
                                         const string& prefix, const string& marker,
                                         const string& end_marker, int64_t max,
                                         vector<rgw_bucket_dir_entry>* objs,
                                         map<string, bool>* common_prefixes, bool* is_truncated,
                                         rgw_obj_key* next_marker)
{
  // get parent oid
  vector<string_extent> parents;
  string parent_oid;
  string parent_name;
  int count = 0;
  bool truncated = true;
  RGWRados* store = target->get_store();

  // get oid
  int level = namespace_split_filepath(prefix, parents);
  if (level == 0) {
    parent_oid = namespace_get_parent_oid(target->bucket.marker, "", 0);
  } else {
    parent_name = namespace_cut_parent_path(prefix, parents, level);
    parent_oid =  namespace_get_parent_oid(target->bucket.marker, parent_name, level);
  }

  // TODO: now, we don't support end_marker
  // get marker, trim delimter
  string cur_marker = marker;
  if (cur_marker.length()) {
    level = namespace_split_filepath(cur_marker, parents);
    if (level > 1) {
      ldout(store->ctx(), 0) << __func__ << " ERROR: invalid marker "
                             << marker << dendl;
      return -EINVAL;
    }
    cur_marker = namespace_cut_parent_path(cur_marker, parents, level);
  }

  // list children
  while (truncated && count < max) {
    int r = store->cls_bucket_namespace_list(s, target->get_bucket_info(), parent_oid,
                                             parent_name, level, cur_marker, end_marker,
                                             common_prefixes, objs, max - count,
                                             cur_marker, &truncated);
    if (r < 0) {
      return r;
    }
    count = common_prefixes->size() + objs->size();
  }

  *is_truncated = truncated;
  *next_marker = cur_marker;

  perfcounter->tinc(l_rgw_list_namespace_lat, s->time_elapsed());

  return 0;
}

int RGWRados::Bucket::Namespace::head_obj(RGWRados* store, RGWBucketInfo& bucket_info,
                                          const string& obj_name, uint64_t& obj_size,
                                          ceph::real_time& lastmod, bool& is_dir,
                                          bool& is_appendable)
{
  // get parent oid
  vector<string_extent> parents;
  string parent_oid;
  string child_name;
  string parent_name;
  bool need_dir = obj_name.size() ?
                  (obj_name[obj_name.size() - 1] == S3_PATH_DELIMITER_CHAR) : false;
  int level = namespace_split_filepath(obj_name, parents);

  // get parent oid and the name of file or directory
  if (level == 0) {
    parent_oid = namespace_get_parent_oid(bucket_info.bucket.marker, "", 0);
  } else {
    int c_index = level - 1;
    parent_name = namespace_cut_parent_path(obj_name, parents, c_index);
    parent_oid =  namespace_get_parent_oid(bucket_info.bucket.marker, parent_name, c_index);
    child_name = obj_name.substr(parents[c_index].offset, parents[c_index].length);
  }

  // get the info of object from rados
  int ret = store->cls_bucket_namespace_head_op(bucket_info, parent_oid, parent_name, level,
                                                child_name, obj_size, lastmod, is_dir,
                                                is_appendable);
  if (ret < 0) {
    return ret;
  }

  // object_name endwith '/', so, it should be a directory
  if (need_dir && !is_dir) {
    return -ENOENT;
  }

  return ret;
}

int RGWRados::Object::Read::read(int64_t ofs, int64_t end, bufferlist& bl)
{
  RGWRados *store = source->get_store();
  CephContext *cct = store->ctx();

  rgw_raw_obj read_obj;
  uint64_t read_ofs = ofs;
  uint64_t len, read_len;
  bool reading_from_head = true;
  ObjectReadOperation op;

  bool merge_bl = false;
  bufferlist *pbl = &bl;
  bufferlist read_bl;
  uint64_t max_chunk_size;

  RGWObjState *astate;
  int r = source->get_state(&astate, true);
  if (r < 0)
    return r;

  if (astate->size == 0) {
    end = 0;
  } else if (end >= (int64_t)astate->size) {
    end = astate->size - 1;
  }

  if (end < 0)
    len = 0;
  else
    len = end - ofs + 1;

  if (astate->has_manifest && astate->manifest.has_tail()) {
    /* now get the relevant object part */
    RGWObjManifest::obj_iterator iter = astate->manifest.obj_find(ofs);

    uint64_t stripe_ofs = iter.get_stripe_ofs();
    read_obj = iter.get_location().get_raw_obj(store);
    len = std::min(len, iter.get_stripe_size() - (ofs - stripe_ofs));
    read_ofs = iter.location_ofs() + (ofs - stripe_ofs);
    reading_from_head = (read_obj == state.head_obj);
  } else {
    read_obj = state.head_obj;
  }

  r = store->get_max_chunk_size(read_obj.pool, &max_chunk_size);
  if (r < 0) {
    ldout(cct, 0) << "ERROR: failed to get max_chunk_size() for pool " << read_obj.pool << dendl;
    return r;
  }

  if (len > max_chunk_size)
    len = max_chunk_size;

  read_len = len;

  if (reading_from_head) {
    /* only when reading from the head object do we need to do the atomic test */
    r = store->append_atomic_test(&source->get_ctx(), source->get_bucket_info(), state.obj, op, &astate);
    if (r < 0)
      return r;

    if (astate && astate->prefetch_data) {
      if (!ofs && astate->data.length() >= len) {
        bl = astate->data;
        return bl.length();
      }

      if (ofs < astate->data.length()) {
        unsigned copy_len = std::min((uint64_t)astate->data.length() - ofs, len);
        astate->data.copy(ofs, copy_len, bl);
        read_len -= copy_len;
        read_ofs += copy_len;
        if (!read_len)
	  return bl.length();

        merge_bl = true;
        pbl = &read_bl;
      }
    }
  }

  ldout(cct, 20) << "rados->read obj-ofs=" << ofs << " read_ofs=" << read_ofs << " read_len=" << read_len << dendl;
  op.read(read_ofs, read_len, pbl, NULL);

  if (state.cur_pool != read_obj.pool) {
    auto iter = state.io_ctxs.find(read_obj.pool);
    if (iter == state.io_ctxs.end()) {
      state.cur_ioctx = &state.io_ctxs[read_obj.pool];
      r = store->open_pool_ctx(read_obj.pool, *state.cur_ioctx);
      if (r < 0) {
        ldout(cct, 20) << "ERROR: failed to open pool context for pool=" << read_obj.pool << " r=" << r << dendl;
        return r;
      }
    } else {
      state.cur_ioctx = &iter->second;
    }
    state.cur_pool = read_obj.pool;
  }

  state.cur_ioctx->locator_set_key(read_obj.loc);

  r = state.cur_ioctx->operate(read_obj.oid, &op, NULL);
  ldout(cct, 20) << "rados->read r=" << r << " bl.length=" << bl.length() << dendl;

  if (r < 0) {
    return r;
  }

  if (merge_bl) {
    bl.append(read_bl);
  }

  return bl.length();
}

int RGWRados::SystemObject::Read::GetObjState::get_ref(RGWRados *store, rgw_raw_obj& obj, rgw_rados_ref **pref)
{
  if (!has_ref) {
    int r = store->get_raw_obj_ref(obj, &ref);
    if (r < 0) {
      return r;
    }
    has_ref = true;
  }
  *pref = &ref;
  return 0;

}

int RGWRados::get_system_obj(RGWObjectCtx& obj_ctx, RGWRados::SystemObject::Read::GetObjState& read_state,
                             RGWObjVersionTracker *objv_tracker, rgw_raw_obj& obj,
                             bufferlist& bl, off_t ofs, off_t end,
                             map<string, bufferlist> *attrs,
                             rgw_cache_entry_info *cache_info,
			     boost::optional<obj_version>)
{
  uint64_t len;
  ObjectReadOperation op;

  if (end < 0)
    len = 0;
  else
    len = end - ofs + 1;

  if (objv_tracker) {
    objv_tracker->prepare_op_for_read(&op);
  }

  ldout(cct, 20) << "rados->read ofs=" << ofs << " len=" << len << dendl;
  op.read(ofs, len, &bl, NULL);

  if (attrs) {
    op.getxattrs(attrs, NULL);
  }

  rgw_rados_ref *ref;
  int r = read_state.get_ref(this, obj, &ref);
  if (r < 0) {
    ldout(cct, 20) << "read_state.get_ref() on obj=" << obj << " returned " << r << dendl;
    return r;
  }
  r = ref->ioctx.operate(ref->oid, &op, NULL);
  if (r < 0) {
    ldout(cct, 20) << "rados->read r=" << r << " bl.length=" << bl.length() << dendl;
    return r;
  }
  ldout(cct, 20) << "rados->read r=" << r << " bl.length=" << bl.length() << dendl;

  uint64_t op_ver = ref->ioctx.get_last_version();

  if (read_state.last_ver > 0 &&
      read_state.last_ver != op_ver) {
    ldout(cct, 5) << "raced with an object write, abort" << dendl;
    return -ECANCELED;
  }

  read_state.last_ver = op_ver;

  return bl.length();
}

int RGWRados::SystemObject::Read::read(int64_t ofs, int64_t end, bufferlist& bl,
				       RGWObjVersionTracker *objv_tracker,
				       boost::optional<obj_version> refresh_version)
{
  RGWRados *store = source->get_store();
  rgw_raw_obj& obj = source->get_obj();

  return store->get_system_obj(source->get_ctx(), state, objv_tracker, obj, bl,
			       ofs, end, read_params.attrs,
			       read_params.cache_info, refresh_version);
}

int RGWRados::SystemObject::Read::get_attr(const char *name, bufferlist& dest)
{
  RGWRados *store = source->get_store();
  rgw_raw_obj& obj = source->get_obj();

  return store->system_obj_get_attr(obj, name, dest);
}

struct get_obj_data;

struct get_obj_aio_data {
  struct get_obj_data *op_data;
  off_t ofs;
  off_t len;
};

struct get_obj_io {
  off_t len;
  bufferlist bl;
};

static void _get_obj_aio_completion_cb(completion_t cb, void *arg);

struct get_obj_data : public RefCountedObject {
  CephContext *cct;
  RGWRados *rados;
  RGWObjectCtx *ctx;
  map<rgw_pool, librados::IoCtx> io_ctxs;
  rgw_pool cur_pool;
  IoCtx *cur_ioctx{nullptr};
  map<off_t, get_obj_io> io_map;
  map<off_t, librados::AioCompletion *> completion_map;
  uint64_t total_read;
  Mutex lock;
  Mutex data_lock;
  list<get_obj_aio_data> aio_data;
  RGWGetDataCB *client_cb;
  std::atomic<bool> cancelled = { false };
  std::atomic<int64_t> err_code = { 0 };
  Throttle throttle;
  list<bufferlist> read_list;

  explicit get_obj_data(CephContext *_cct)
    : cct(_cct),
      rados(NULL), ctx(NULL),
      total_read(0), lock("get_obj_data"), data_lock("get_obj_data::data_lock"),
      client_cb(NULL),
      throttle(cct, "get_obj_data", cct->_conf->rgw_get_obj_window_size, false) {}
  ~get_obj_data() override { } 
  void set_cancelled(int r) {
    cancelled = true;
    err_code = r;
  }

  bool is_cancelled() {
    return cancelled;
  }

  int get_err_code() {
    return err_code;
  }

  int wait_next_io(bool *done) {
    lock.Lock();
    map<off_t, librados::AioCompletion *>::iterator iter = completion_map.begin();
    if (iter == completion_map.end()) {
      *done = true;
      lock.Unlock();
      return 0;
    }
    off_t cur_ofs = iter->first;
    librados::AioCompletion *c = iter->second;
    lock.Unlock();

    c->wait_for_safe_and_cb();
    int r = c->get_return_value();

    lock.Lock();
    completion_map.erase(cur_ofs);

    if (completion_map.empty()) {
      *done = true;
    }
    lock.Unlock();

    c->release();
    
    return r;
  }

  void add_io(off_t ofs, off_t len, bufferlist **pbl, AioCompletion **pc) {
    Mutex::Locker l(lock);

    const auto& io_iter = io_map.insert(
      map<off_t, get_obj_io>::value_type(ofs, get_obj_io()));

    assert(io_iter.second); // assert new insertion

    get_obj_io& io = (io_iter.first)->second;
    *pbl = &io.bl;

    struct get_obj_aio_data aio;
    aio.ofs = ofs;
    aio.len = len;
    aio.op_data = this;

    aio_data.push_back(aio);

    struct get_obj_aio_data *paio_data =  &aio_data.back(); /* last element */

    librados::AioCompletion *c = librados::Rados::aio_create_completion((void *)paio_data, NULL, _get_obj_aio_completion_cb);
    completion_map[ofs] = c;

    *pc = c;

    /* we have a reference per IO, plus one reference for the calling function.
     * reference is dropped for each callback, plus when we're done iterating
     * over the parts */
    get();
  }

  void cancel_io(off_t ofs) {
    ldout(cct, 20) << "get_obj_data::cancel_io() ofs=" << ofs << dendl;
    lock.Lock();
    map<off_t, AioCompletion *>::iterator iter = completion_map.find(ofs);
    if (iter != completion_map.end()) {
      AioCompletion *c = iter->second;
      c->release();
      completion_map.erase(ofs);
      io_map.erase(ofs);
    }
    lock.Unlock();

    /* we don't drop a reference here -- e.g., not calling d->put(), because we still
     * need IoCtx to live, as io callback may still be called
     */
  }

  void cancel_all_io() {
    ldout(cct, 20) << "get_obj_data::cancel_all_io()" << dendl;
    Mutex::Locker l(lock);
    for (map<off_t, librados::AioCompletion *>::iterator iter = completion_map.begin();
         iter != completion_map.end(); ++iter) {
      librados::AioCompletion  *c = iter->second;
      c->release();
    }
  }

  int get_complete_ios(off_t ofs, list<bufferlist>& bl_list) {
    Mutex::Locker l(lock);

    map<off_t, get_obj_io>::iterator liter = io_map.begin();

    if (liter == io_map.end() ||
        liter->first != ofs) {
      return 0;
    }

    map<off_t, librados::AioCompletion *>::iterator aiter;
    aiter = completion_map.find(ofs);
    if (aiter == completion_map.end()) {
    /* completion map does not hold this io, it was cancelled */
      return 0;
    }

    AioCompletion *completion = aiter->second;
    int r = completion->get_return_value();
    if (r < 0)
      return r;

    for (; aiter != completion_map.end(); ++aiter) {
      completion = aiter->second;
      if (!completion->is_safe()) {
        /* reached a request that is not yet complete, stop */
        break;
      }

      r = completion->get_return_value();
      if (r < 0) {
        set_cancelled(r); /* mark it as cancelled, so that we don't continue processing next operations */
        return r;
      }

      total_read += r;

      map<off_t, get_obj_io>::iterator old_liter = liter++;
      bl_list.push_back(old_liter->second.bl);
      io_map.erase(old_liter);
    }

    return 0;
  }
};

static void _get_obj_aio_completion_cb(completion_t cb, void *arg)
{
  struct get_obj_aio_data *aio_data = (struct get_obj_aio_data *)arg;
  struct get_obj_data *d = aio_data->op_data;

  d->rados->get_obj_aio_completion_cb(cb, arg);
}


void RGWRados::get_obj_aio_completion_cb(completion_t c, void *arg)
{
  struct get_obj_aio_data *aio_data = (struct get_obj_aio_data *)arg;
  struct get_obj_data *d = aio_data->op_data;
  off_t ofs = aio_data->ofs;
  off_t len = aio_data->len;

  list<bufferlist> bl_list;
  list<bufferlist>::iterator iter;
  int r;

  ldout(cct, 20) << "get_obj_aio_completion_cb: io completion ofs=" << ofs << " len=" << len << dendl;
  d->throttle.put(len);

  r = rados_aio_get_return_value(c);
  if (r < 0) {
    ldout(cct, 0) << "ERROR: got unexpected error when trying to read object: " << r << dendl;
    d->set_cancelled(r);
    goto done;
  }

  if (d->is_cancelled()) {
    goto done;
  }

  d->data_lock.Lock();

  r = d->get_complete_ios(ofs, bl_list);
  if (r < 0) {
    goto done_unlock;
  }

  d->read_list.splice(d->read_list.end(), bl_list);

done_unlock:
  d->data_lock.Unlock();
done:
  d->put();
  return;
}

int RGWRados::flush_read_list(struct get_obj_data *d)
{
  d->data_lock.Lock();
  list<bufferlist> l;
  l.swap(d->read_list);
  d->get();
  d->read_list.clear();

  d->data_lock.Unlock();

  int r = 0;

  list<bufferlist>::iterator iter;
  for (iter = l.begin(); iter != l.end(); ++iter) {
    bufferlist& bl = *iter;
    r = d->client_cb->handle_data(bl, 0, bl.length());
    if (r < 0) {
      dout(0) << "ERROR: flush_read_list(): d->client_cb->handle_data() returned " << r << dendl;
      break;
    }
  }

  d->data_lock.Lock();
  d->put();
  if (r < 0) {
    d->set_cancelled(r);
  }
  d->data_lock.Unlock();
  return r;
}

int RGWRados::get_obj_iterate_cb(RGWObjectCtx *ctx, RGWObjState *astate,
                                 const RGWBucketInfo& bucket_info,
                                 const rgw_obj& obj,
                                 const rgw_raw_obj& read_obj,
                                 off_t obj_ofs,
                                 off_t read_ofs, off_t len,
                                 bool is_head_obj, void *arg)
{
  RGWObjectCtx *rctx = static_cast<RGWObjectCtx *>(ctx);
  ObjectReadOperation op;
  struct get_obj_data *d = (struct get_obj_data *)arg;
  string oid, key;
  bufferlist *pbl;
  AioCompletion *c;

  int r;

  if (is_head_obj && !d->client_cb->is_crypt()) {
    /* only when reading from the head object do we need to do the atomic test */
    r = append_atomic_test(rctx, bucket_info, obj, op, &astate);
    if (r < 0)
      return r;

  ldout(cct, 20) << "rados->get_obj_iterate_cb oid=" << read_obj.oid
                 << " obj-ofs=" << obj_ofs << " read_ofs=" << read_ofs
                 << " len=" << len
                 << " astate->data.length:"<< astate->data.length()
                 << dendl;
    if (astate && astate->data.length() > 0) {
      unsigned chunk_len = (uint64_t)astate->data.length();

      r = d->client_cb->handle_data(astate->data, 0, chunk_len);
      if (r < 0)
        return r;

      d->lock.Lock();
      d->total_read += chunk_len;
      d->lock.Unlock();

      len -= chunk_len;
      read_ofs += chunk_len;
      obj_ofs += chunk_len;
      if (!len)
        return 0;
    }
  }

  d->throttle.get(len);
  if (d->is_cancelled()) {
    return d->get_err_code();
  }

  /* add io after we check that we're not cancelled, otherwise we're going to have trouble
   * cleaning up
   */
  d->add_io(obj_ofs, len, &pbl, &c);

  ldout(cct, 20) << "rados->get_obj_iterate_cb oid=" << read_obj.oid
                 << " obj-ofs=" << obj_ofs << " read_ofs=" << read_ofs
                 << " len=" << len 
                 << " read_obj.pool=" << read_obj.pool << dendl;
  op.read(read_ofs, len, pbl, NULL);

  if (d->cur_pool != read_obj.pool) {
    auto iter = d->io_ctxs.find(read_obj.pool);
    if (iter == d->io_ctxs.end()) {
      d->cur_ioctx = &d->io_ctxs[read_obj.pool];
      r = d->rados->open_pool_ctx(read_obj.pool, *d->cur_ioctx);
      if (r < 0) {
        ldout(cct, 20) << "ERROR: failed to open pool context for pool=" << read_obj.pool << " r=" << r << dendl;
        return r;
      }
    } else {
      d->cur_ioctx = &iter->second;
    }
    d->cur_pool = read_obj.pool;
  }

  d->cur_ioctx->locator_set_key(read_obj.loc);
  int read_flag = cct->_conf->rgw_rados_read_flag;
  if (astate->manifest.is_enable_skip_cache()) {
    read_flag = read_flag | librados::OPERATION_SKIP_CACHE;
  }

  r = d->cur_ioctx->aio_operate(read_obj.oid, c, &op, read_flag, NULL);
  if (r < 0) {
    ldout(cct, 0) << "rados->aio_operate r=" << r << dendl;
    goto done_err;
  }

  // Flush data to client if there is any
  r = flush_read_list(d);
  if (r < 0)
    return r;

  return 0;

done_err:
  ldout(cct, 20) << "cancelling io r=" << r << " obj_ofs=" << obj_ofs << dendl;
  d->set_cancelled(r);
  d->cancel_io(obj_ofs);

  return r;
}

int RGWRados::Object::Read::iterate(int64_t ofs, int64_t end, RGWGetDataCB *cb)
{
  RGWRados *store = source->get_store();
  CephContext *cct = store->ctx();

  struct get_obj_data *data = new get_obj_data(cct);
  bool done = false;

  RGWObjectCtx& obj_ctx = source->get_ctx();

  data->rados = store;
  data->cur_pool = state.cur_pool;
  data->io_ctxs[data->cur_pool].dup(*state.cur_ioctx);
  data->cur_ioctx = &data->io_ctxs[data->cur_pool];

  data->client_cb = cb;

  int r = store->iterate_obj(obj_ctx, source->get_bucket_info(), state.obj, ofs, end, cct->_conf->rgw_get_obj_max_req_size, (void *)data);
  if (r < 0) {
    data->cancel_all_io();
    goto done;
  }

  while (!done) {
    r = data->wait_next_io(&done);
    if (r < 0) {
      dout(10) << __func__ << " r=" << r << ", canceling all io" << dendl;
      data->cancel_all_io();
      break;
    }
    r = store->flush_read_list(data);
    if (r < 0) {
      dout(10) << __func__ << " r=" << r << ", canceling all io" << dendl;
      data->cancel_all_io();
      break;
    }
  }

done:
  data->put();
  return r;
}

int RGWRados::iterate_obj(RGWObjectCtx& obj_ctx,
                          const RGWBucketInfo& bucket_info, const rgw_obj& obj,
                          off_t ofs, off_t end,
                          uint64_t max_chunk_size,
                          void *arg)
{
  rgw_raw_obj head_obj;
  rgw_raw_obj read_obj;
  uint64_t read_ofs = ofs;
  uint64_t len;
  bool reading_from_head = true;
  RGWObjState *astate = NULL;
  struct get_obj_data *d = (struct get_obj_data *)arg;

  obj_to_raw(bucket_info.head_placement_rule, obj, &head_obj);

  int r = get_obj_state(&obj_ctx, bucket_info, obj, &astate, false);
  if (r < 0) {
    return r;
  }

  if (end < 0)
    len = 0;
  else
    len = end - ofs + 1;

  if (astate->has_manifest) {
    /* now get the relevant object stripe */
    RGWObjManifest::obj_iterator iter = astate->manifest.obj_find(ofs);

    RGWObjManifest::obj_iterator obj_end = astate->manifest.obj_end();

    for (; iter != obj_end && ofs <= end; ++iter) {
      off_t stripe_ofs = iter.get_stripe_ofs();
      off_t next_stripe_ofs = stripe_ofs + iter.get_stripe_size();

      while (ofs < next_stripe_ofs && ofs <= end) {
        read_obj = iter.get_location().get_raw_obj(this);
        uint64_t read_len = std::min(len, iter.get_stripe_size() - (ofs - stripe_ofs));
        read_ofs = iter.location_ofs() + (ofs - stripe_ofs);

        if (read_len > max_chunk_size) {
          read_len = max_chunk_size;
        }

        reading_from_head = (read_obj == head_obj);
        r = get_obj_iterate_cb(d->ctx, astate, bucket_info, obj, read_obj, ofs, read_ofs, read_len, reading_from_head, arg);
        if (r < 0) {
          return r;
        }

        len -= read_len;
        ofs += read_len;
      }
    }
  } else {
    while (ofs <= end) {
      read_obj = head_obj;
      uint64_t read_len = std::min(len, max_chunk_size);

      r = get_obj_iterate_cb(d->ctx, astate, bucket_info, obj, read_obj, ofs, read_ofs, read_len, reading_from_head, arg);
      if (r < 0) {
        return r;
      }

      len -= read_len;
      ofs += read_len;
    }
  }

  return 0;
}

int RGWRados::obj_operate(const RGWBucketInfo& bucket_info, const rgw_obj& obj, ObjectWriteOperation *op)
{
  rgw_rados_ref ref;
  int r = get_obj_head_ref(bucket_info, obj, &ref);
  if (r < 0) {
    return r;
  }

  return ref.ioctx.operate(ref.oid, op);
}

int RGWRados::obj_operate(const RGWBucketInfo& bucket_info, const rgw_obj& obj, ObjectReadOperation *op)
{
  rgw_rados_ref ref;
  int r = get_obj_head_ref(bucket_info, obj, &ref);
  if (r < 0) {
    return r;
  }

  bufferlist outbl;

  return ref.ioctx.operate(ref.oid, op, &outbl);
}

int RGWRados::olh_init_modification_impl(const RGWBucketInfo& bucket_info, RGWObjState& state, const rgw_obj& olh_obj, string *op_tag)
{
  ObjectWriteOperation op;

  assert(olh_obj.key.instance.empty());

  bool has_tag = (state.exists && has_olh_tag(state.attrset));

  if (!state.exists) {
    op.create(true);
  } else {
    op.assert_exists();
    struct timespec mtime_ts = real_clock::to_timespec(state.mtime);
    op.mtime2(&mtime_ts);
  }

  /*
   * 3 possible cases: olh object doesn't exist, it exists as an olh, it exists as a regular object.
   * If it exists as a regular object we'll need to transform it into an olh. We'll do it in two
   * steps, first change its tag and set the olh pending attrs. Once write is done we'll need to
   * truncate it, remove extra attrs, and send it to the garbage collection. The bucket index olh
   * log will reflect that.
   *
   * Need to generate separate olh and obj tags, as olh can be colocated with object data. obj_tag
   * is used for object data instance, olh_tag for olh instance.
   */
  if (has_tag) {
    /* guard against racing writes */
    bucket_index_guard_olh_op(state, op);
  }

  if (!has_tag) {
    /* obj tag */
    string obj_tag;
    gen_rand_alphanumeric_lower(cct, &obj_tag, 32);

    bufferlist bl;
    bl.append(obj_tag.c_str(), obj_tag.size());
    ldout(cct, 10) << "setting object id_tag=" << obj_tag << dendl;
    op.setxattr(RGW_ATTR_ID_TAG, bl);

    state.attrset[RGW_ATTR_ID_TAG] = bl;
    state.obj_tag = bl;

    /* olh tag */
    string olh_tag;
    gen_rand_alphanumeric_lower(cct, &olh_tag, 32);

    bufferlist olh_bl;
    olh_bl.append(olh_tag.c_str(), olh_tag.size());
    op.setxattr(RGW_ATTR_OLH_ID_TAG, olh_bl);

    state.attrset[RGW_ATTR_OLH_ID_TAG] = olh_bl;
    state.olh_tag = olh_bl;
    state.is_olh = true;

    bufferlist verbl;
    op.setxattr(RGW_ATTR_OLH_VER, verbl);
  }

  bufferlist bl;
  RGWOLHPendingInfo pending_info;
  pending_info.time = real_clock::now();
  encode(pending_info, bl);

#define OLH_PENDING_TAG_LEN 32
  /* tag will start with current time epoch, this so that entries are sorted by time */
  char buf[32];
  utime_t ut(pending_info.time);
  snprintf(buf, sizeof(buf), "%016llx", (unsigned long long)ut.sec());
  *op_tag = buf;

  string s;
  gen_rand_alphanumeric_lower(cct, &s, OLH_PENDING_TAG_LEN - op_tag->size());

  op_tag->append(s);

  string attr_name = RGW_ATTR_OLH_PENDING_PREFIX;
  attr_name.append(*op_tag);

  op.setxattr(attr_name.c_str(), bl);

  int ret = obj_operate(bucket_info, olh_obj, &op);
  if (ret < 0) {
    return ret;
  }

  state.exists = true;
  state.attrset[attr_name] = bl;

  return 0;
}

int RGWRados::olh_init_modification(const RGWBucketInfo& bucket_info, RGWObjState& state, const rgw_obj& obj, string *op_tag)
{
  int ret;

  ret = olh_init_modification_impl(bucket_info, state, obj, op_tag);
  if (ret == -EEXIST) {
    ret = -ECANCELED;
  }

  return ret;
}

int RGWRados::guard_reshard(BucketShard *bs,
			    const rgw_obj& obj_instance,
			    const RGWBucketInfo& bucket_info,
			    std::function<int(BucketShard *)> call)
{
  rgw_obj obj;
  const rgw_obj *pobj = &obj_instance;
  int r;

  for (int i = 0; i < NUM_RESHARD_RETRIES; ++i) {
    r = bs->init(pobj->bucket, *pobj, nullptr /* no RGWBucketInfo */);
    if (r < 0) {
      ldout(cct, 5) << "bs.init() returned ret=" << r << dendl;
      return r;
    }
    r = call(bs);
    if (r != -ERR_BUSY_RESHARDING) {
      break;
    }
    ldout(cct, 0) << "NOTICE: resharding operation on bucket index detected, blocking" << dendl;
    string new_bucket_id;
    r = block_while_resharding(bs, &new_bucket_id, bucket_info);
    if (r == -ERR_BUSY_RESHARDING) {
      continue;
    }
    if (r < 0) {
      return r;
    }
    ldout(cct, 20) << "reshard completion identified, new_bucket_id=" << new_bucket_id << dendl;
    i = 0; /* resharding is finished, make sure we can retry */

    obj = *pobj;
    obj.bucket.update_bucket_id(new_bucket_id);
    pobj = &obj;
  }

  if (r < 0) {
    return r;
  }

  return 0;
}

int RGWRados::block_while_resharding(RGWRados::BucketShard *bs,
				     string *new_bucket_id,
				     const RGWBucketInfo& bucket_info)
{
  std::shared_ptr<RGWReshardWait> waiter = reshard_wait;

  return waiter->block_while_resharding(bs, new_bucket_id, bucket_info);
}

int RGWRados::bucket_index_link_olh(const RGWBucketInfo& bucket_info, RGWObjState& olh_state, const rgw_obj& obj_instance,
                                    bool delete_marker,
                                    const string& op_tag,
                                    struct rgw_bucket_dir_entry_meta *meta,
                                    uint64_t olh_epoch,
                                    real_time unmod_since, bool high_precision_time,
                                    rgw_zone_set *_zones_trace, bool log_data_change)
{
  rgw_rados_ref ref;
  int r = get_obj_head_ref(bucket_info, obj_instance, &ref);
  if (r < 0) {
    return r;
  }

  rgw_zone_set zones_trace;
  if (_zones_trace) {
    zones_trace = *_zones_trace;
  }
  zones_trace.insert(get_zone().id);

  BucketShard bs(this);

  cls_rgw_obj_key key(obj_instance.key.get_index_key_name(), obj_instance.key.instance);
  r = guard_reshard(&bs, obj_instance, bucket_info,
		    [&](BucketShard *bs) -> int {
		      librados::ObjectWriteOperation op;
		      cls_rgw_guard_bucket_resharding(op, -ERR_BUSY_RESHARDING);
		      return cls_rgw_bucket_link_olh(bs->index_ctx, op,
						     bs->bucket_obj, key, olh_state.olh_tag, delete_marker, op_tag, meta, olh_epoch,
						     unmod_since, high_precision_time,
						     get_zone().log_data, zones_trace);
                    });
  if (r < 0) {
    ldout(cct, 20) << "cls_rgw_bucket_link_olh() returned r=" << r << dendl;
    return r;
  }

  if (log_data_change && (bucket_info.datasync_flag_enabled(zone_public_config.id) &&
      !datasync_all_disabled(bucket_info)) &&
      !(bucket_info.disable_sync.size() == 0 && bucket_info.bilog_flags.size() == 0)) {
    data_log->add_entry(bs.bucket, bs.shard_id);
  }

  return 0;
}

void RGWRados::bucket_index_guard_olh_op(RGWObjState& olh_state, ObjectOperation& op)
{
  ldout(cct, 20) << __func__ << "(): olh_state.olh_tag=" << string(olh_state.olh_tag.c_str(), olh_state.olh_tag.length()) << dendl;
  op.cmpxattr(RGW_ATTR_OLH_ID_TAG, CEPH_OSD_CMPXATTR_OP_EQ, olh_state.olh_tag);
}

int RGWRados::bucket_index_unlink_instance(const RGWBucketInfo& bucket_info, const rgw_obj& obj_instance,
                                           const string& op_tag, const string& olh_tag, uint64_t olh_epoch, rgw_zone_set *_zones_trace)
{
  rgw_rados_ref ref;
  int r = get_obj_head_ref(bucket_info, obj_instance, &ref);
  if (r < 0) {
    return r;
  }

  rgw_zone_set zones_trace;
  if (_zones_trace) {
    zones_trace = *_zones_trace;
  }
  zones_trace.insert(get_zone().id);

  BucketShard bs(this);

  cls_rgw_obj_key key(obj_instance.key.get_index_key_name(), obj_instance.key.instance);
  r = guard_reshard(&bs, obj_instance, bucket_info,
		    [&](BucketShard *bs) -> int {
		      librados::ObjectWriteOperation op;
		      cls_rgw_guard_bucket_resharding(op, -ERR_BUSY_RESHARDING);
		      return cls_rgw_bucket_unlink_instance(bs->index_ctx, op, bs->bucket_obj, key, op_tag,
							    olh_tag, olh_epoch, get_zone().log_data, zones_trace);
                    });
  if (r < 0) {
    ldout(cct, 20) << "cls_rgw_bucket_link_olh() returned r=" << r << dendl;
    return r;
  }

  return 0;
}

int RGWRados::bucket_index_read_olh_log(const RGWBucketInfo& bucket_info, RGWObjState& state,
                                        const rgw_obj& obj_instance, uint64_t ver_marker,
                                        map<uint64_t, vector<rgw_bucket_olh_log_entry> > *log,
                                        bool *is_truncated)
{
  rgw_rados_ref ref;
  int r = get_obj_head_ref(bucket_info, obj_instance, &ref);
  if (r < 0) {
    return r;
  }

  BucketShard bs(this);
  int ret =
    bs.init(obj_instance.bucket, obj_instance, nullptr /* no RGWBucketInfo */);
  if (ret < 0) {
    ldout(cct, 5) << "bs.init() returned ret=" << ret << dendl;
    return ret;
  }

  string olh_tag(state.olh_tag.c_str(), state.olh_tag.length());

  cls_rgw_obj_key key(obj_instance.key.get_index_key_name(), string());

  ret = guard_reshard(&bs, obj_instance, bucket_info,
		      [&](BucketShard *bs) -> int {
			ObjectReadOperation op;
			cls_rgw_guard_bucket_resharding(op, -ERR_BUSY_RESHARDING);
			return cls_rgw_get_olh_log(bs->index_ctx, bs->bucket_obj, op,
						   key, ver_marker, olh_tag, log, is_truncated);
		      });
  if (ret < 0) {
    ldout(cct, 20) << "cls_rgw_get_olh_log() returned r=" << r << dendl;
    return ret;
  }

  return 0;
}

int RGWRados::bucket_index_trim_olh_log(const RGWBucketInfo& bucket_info, RGWObjState& state, const rgw_obj& obj_instance, uint64_t ver)
{
  rgw_rados_ref ref;
  int r = get_obj_head_ref(bucket_info, obj_instance, &ref);
  if (r < 0) {
    return r;
  }

  BucketShard bs(this);
  int ret =
    bs.init(obj_instance.bucket, obj_instance, nullptr /* no RGWBucketInfo */);
  if (ret < 0) {
    ldout(cct, 5) << "bs.init() returned ret=" << ret << dendl;
    return ret;
  }

  string olh_tag(state.olh_tag.c_str(), state.olh_tag.length());

  cls_rgw_obj_key key(obj_instance.key.get_index_key_name(), string());

  ret = guard_reshard(&bs, obj_instance, bucket_info,
		      [&](BucketShard *pbs) -> int {
			ObjectWriteOperation op;
			cls_rgw_guard_bucket_resharding(op, -ERR_BUSY_RESHARDING);
			cls_rgw_trim_olh_log(op, key, ver, olh_tag);
			return pbs->index_ctx.operate(pbs->bucket_obj, &op);
                      });
  if (ret < 0) {
    ldout(cct, 20) << "cls_rgw_trim_olh_log() returned r=" << ret << dendl;
    return ret;
  }

  return 0;
}

int RGWRados::bucket_index_clear_olh(const RGWBucketInfo& bucket_info, RGWObjState& state, const rgw_obj& obj_instance)
{
  rgw_rados_ref ref;
  int r = get_obj_head_ref(bucket_info, obj_instance, &ref);
  if (r < 0) {
    return r;
  }

  BucketShard bs(this);

  string olh_tag(state.olh_tag.c_str(), state.olh_tag.length());

  cls_rgw_obj_key key(obj_instance.key.get_index_key_name(), string());

  int ret = guard_reshard(&bs, obj_instance, bucket_info,
			  [&](BucketShard *pbs) -> int {
			    ObjectWriteOperation op;
			    cls_rgw_guard_bucket_resharding(op, -ERR_BUSY_RESHARDING);
			    return cls_rgw_clear_olh(pbs->index_ctx, op, pbs->bucket_obj, key, olh_tag);
                          });
  if (ret < 0) {
    ldout(cct, 5) << "cls_rgw_clear_olh() returned ret=" << ret << dendl;
    return ret;
  }

  return 0;
}

static int decode_olh_info(CephContext* cct, bufferlist& bl, RGWOLHInfo *olh)
{
  try {
    auto biter = bl.begin();
    decode(*olh, biter);
    return 0;
  } catch (buffer::error& err) {
    ldout(cct, 0) << "ERROR: failed to decode olh info" << dendl;
    return -EIO;
  }
}

int RGWRados::apply_olh_log(RGWObjectCtx& obj_ctx, RGWObjState& state, const RGWBucketInfo& bucket_info, const rgw_obj& obj,
                            bufferlist& olh_tag, map<uint64_t, vector<rgw_bucket_olh_log_entry> >& log,
                            uint64_t *plast_ver, rgw_zone_set* zones_trace)
{
  if (log.empty()) {
    return 0;
  }

  librados::ObjectWriteOperation op;

  uint64_t last_ver = log.rbegin()->first;
  *plast_ver = last_ver;

  map<uint64_t, vector<rgw_bucket_olh_log_entry> >::iterator iter = log.begin();

  op.cmpxattr(RGW_ATTR_OLH_ID_TAG, CEPH_OSD_CMPXATTR_OP_EQ, olh_tag);
  op.cmpxattr(RGW_ATTR_OLH_VER, CEPH_OSD_CMPXATTR_OP_GTE, last_ver);

  // ensure olh_log is newest
  bufferlist ver_bl;
  string last_ver_s = to_string(last_ver);
  ver_bl.append(last_ver_s.c_str(), last_ver_s.size());
  op.setxattr(RGW_ATTR_OLH_VER, ver_bl);

  struct timespec mtime_ts = real_clock::to_timespec(state.mtime);
  op.mtime2(&mtime_ts);

  bool need_to_link = false;
  uint64_t link_epoch = 0;
  cls_rgw_obj_key key;
  bool delete_marker = false;
  list<cls_rgw_obj_key> remove_instances;
  bool need_to_remove = false;

  // decode current epoch and instance
  auto olh_ver = state.attrset.find(RGW_ATTR_OLH_VER);
  if (olh_ver != state.attrset.end()) {
    std::string str = olh_ver->second.to_str();
    std::string err;
    link_epoch = strict_strtoll(str.c_str(), 10, &err);
  }
  auto olh_info = state.attrset.find(RGW_ATTR_OLH_INFO);
  if (olh_info != state.attrset.end()) {
    RGWOLHInfo info;
    int r = decode_olh_info(cct, olh_info->second, &info);
    if (r < 0) {
      return r;
    }
    info.target.key.get_index_key(&key);
    delete_marker = info.removed;
  }

  for (iter = log.begin(); iter != log.end(); ++iter) {
    vector<rgw_bucket_olh_log_entry>::iterator viter = iter->second.begin();
    for (; viter != iter->second.end(); ++viter) {
      rgw_bucket_olh_log_entry& entry = *viter;

      ldout(cct, 20) << "olh_log_entry: epoch=" << iter->first << " op=" << (int)entry.op
                     << " key=" << entry.key.name << "[" << entry.key.instance << "] "
                     << (entry.delete_marker ? "(delete)" : "") << dendl;
      switch (entry.op) {
      case CLS_RGW_OLH_OP_REMOVE_INSTANCE:
        remove_instances.push_back(entry.key);
        break;
      case CLS_RGW_OLH_OP_LINK_OLH:
        // only overwrite a link of the same epoch if its key sorts before
        if (link_epoch < iter->first || key.instance.empty() ||
            key.instance > entry.key.instance) {
          ldout(cct, 20) << "apply_olh_log applying key=" << entry.key << " epoch=" << iter->first << " delete_marker=" << entry.delete_marker
              << " over current=" << key << " epoch=" << link_epoch << " delete_marker=" << delete_marker << dendl;
          need_to_link = true;
          need_to_remove = false;
          key = entry.key;
          delete_marker = entry.delete_marker;
        } else {
          ldout(cct, 20) << "apply_olh skipping key=" << entry.key<< " epoch=" << iter->first << " delete_marker=" << entry.delete_marker
              << " before current=" << key << " epoch=" << link_epoch << " delete_marker=" << delete_marker << dendl;
        }
        break;
      case CLS_RGW_OLH_OP_UNLINK_OLH:
        need_to_remove = true;
        need_to_link = false;
        break;
      default:
        ldout(cct, 0) << "ERROR: apply_olh_log: invalid op: " << (int)entry.op << dendl;
        return -EIO;
      }
      string attr_name = RGW_ATTR_OLH_PENDING_PREFIX;
      attr_name.append(entry.op_tag);
      op.rmxattr(attr_name.c_str());
    }
  }

  rgw_rados_ref ref;
  int r = get_obj_head_ref(bucket_info, obj, &ref);
  if (r < 0) {
    return r;
  }

  const rgw_bucket& bucket = obj.bucket;

  if (need_to_link) {
    rgw_obj target(bucket, key);
    RGWOLHInfo info;
    info.target = target;
    info.removed = delete_marker;
    bufferlist bl;
    encode(info, bl);
    op.setxattr(RGW_ATTR_OLH_INFO, bl);
  }

  /* first remove object instances */
  for (list<cls_rgw_obj_key>::iterator liter = remove_instances.begin();
       liter != remove_instances.end(); ++liter) {
    cls_rgw_obj_key& key = *liter;
    rgw_obj obj_instance(bucket, key);
    int ret = delete_obj(obj_ctx, bucket_info, obj_instance, 0, false, RGW_BILOG_FLAG_VERSIONED_OP, ceph::real_time(), zones_trace);
    if (ret < 0 && ret != -ENOENT) {
      ldout(cct, 0) << "ERROR: delete_obj() returned " << ret << " obj_instance=" << obj_instance << dendl;
      return ret;
    }
  }

  /* update olh object */
  r = ref.ioctx.operate(ref.oid, &op);
  if (r == -ECANCELED) {
    r = 0;
  }
  if (r < 0) {
    ldout(cct, 0) << "ERROR: could not apply olh update, r=" << r << dendl;
    return r;
  }

  r = bucket_index_trim_olh_log(bucket_info, state, obj, last_ver);
  if (r < 0) {
    ldout(cct, 0) << "ERROR: could not trim olh log, r=" << r << dendl;
    return r;
  }

  if (need_to_remove) {
    ObjectWriteOperation rm_op;

    rm_op.cmpxattr(RGW_ATTR_OLH_ID_TAG, CEPH_OSD_CMPXATTR_OP_EQ, olh_tag);
    rm_op.cmpxattr(RGW_ATTR_OLH_VER, CEPH_OSD_CMPXATTR_OP_EQ, last_ver);
    cls_obj_check_prefix_exist(rm_op, RGW_ATTR_OLH_PENDING_PREFIX, true); /* fail if found one of these, pending modification */
    rm_op.remove();

    r = ref.ioctx.operate(ref.oid, &rm_op);
    if (r == -ECANCELED) {
      return 0; /* someone else won this race */
    } else {
      /* 
       * only clear if was successful, otherwise we might clobber pending operations on this object
       */
      r = bucket_index_clear_olh(bucket_info, state, obj);
      if (r < 0) {
        ldout(cct, 0) << "ERROR: could not clear bucket index olh entries r=" << r << dendl;
        return r;
      }
    }
  }

  return 0;
}

/*
 * read olh log and apply it
 */
int RGWRados::update_olh(RGWObjectCtx& obj_ctx, RGWObjState *state, const RGWBucketInfo& bucket_info, const rgw_obj& obj, rgw_zone_set *zones_trace)
{
  map<uint64_t, vector<rgw_bucket_olh_log_entry> > log;
  bool is_truncated;
  uint64_t ver_marker = 0;

  do {
    int ret = bucket_index_read_olh_log(bucket_info, *state, obj, ver_marker, &log, &is_truncated);
    if (ret < 0) {
      return ret;
    }
    ret = apply_olh_log(obj_ctx, *state, bucket_info, obj, state->olh_tag, log, &ver_marker, zones_trace);
    if (ret < 0) {
      return ret;
    }
  } while (is_truncated);

  return 0;
}

int RGWRados::set_olh(RGWObjectCtx& obj_ctx, RGWBucketInfo& bucket_info, const rgw_obj& target_obj, bool delete_marker, rgw_bucket_dir_entry_meta *meta,
                      uint64_t olh_epoch, real_time unmod_since, bool high_precision_time,
                      rgw_zone_set *zones_trace, bool log_data_change, bool is_transition)
{
  string op_tag;

  rgw_obj olh_obj = target_obj;
  olh_obj.key.instance.clear();

  RGWObjState *state = NULL;

  int ret = 0;
  int i;
  
#define MAX_ECANCELED_RETRY 100
  for (i = 0; i < MAX_ECANCELED_RETRY; i++) {
    if (ret == -ECANCELED) {
      obj_ctx.obj.invalidate(olh_obj);
    }

    ret = get_obj_state(&obj_ctx, bucket_info, olh_obj, &state, false); /* don't follow olh */
    if (ret < 0) {
      return ret;
    }

    // do not write olh pending log when transition
    if (!is_transition) {
      ret = olh_init_modification(bucket_info, *state, olh_obj, &op_tag);
      if (ret < 0) {
        ldout(cct, 20) << "olh_init_modification() target_obj=" << target_obj 
                       << " delete_marker=" << (int)delete_marker 
                       << " returned " << ret << dendl;
        if (ret == -ECANCELED) {
          continue;
        }
        return ret;
      }
    }
    ret = bucket_index_link_olh(bucket_info, *state, target_obj, delete_marker,
                                op_tag, meta, olh_epoch, unmod_since, high_precision_time,
                                zones_trace, log_data_change);
    if (ret < 0) {
      ldout(cct, 20) << "bucket_index_link_olh() target_obj=" << target_obj << " delete_marker=" << (int)delete_marker << " returned " << ret << dendl;
      if (ret == -ECANCELED) {
        continue;
      }
      return ret;
    }
    break;
  }

  if (i == MAX_ECANCELED_RETRY) {
    ldout(cct, 0) << "ERROR: exceeded max ECANCELED retries, aborting (EIO)" << dendl;
    return -EIO;
  }

  ret = update_olh(obj_ctx, state, bucket_info, olh_obj);
  if (ret == -ECANCELED) { /* already did what we needed, no need to retry, raced with another user */
    ret = 0;
  }
  if (ret < 0) {
    ldout(cct, 20) << "update_olh() target_obj=" << target_obj << " returned " << ret << dendl;
    return ret;
  }

  return 0;
}

int RGWRados::unlink_obj_instance(RGWObjectCtx& obj_ctx, RGWBucketInfo& bucket_info, const rgw_obj& target_obj,
                                  uint64_t olh_epoch, rgw_zone_set *zones_trace)
{
  string op_tag;

  rgw_obj olh_obj = target_obj;
  olh_obj.key.instance.clear();

  RGWObjState *state = NULL;

  int ret = 0;
  int i;

  for (i = 0; i < MAX_ECANCELED_RETRY; i++) {
    if (ret == -ECANCELED) {
      obj_ctx.obj.invalidate(olh_obj);
    }

    ret = get_obj_state(&obj_ctx, bucket_info, olh_obj, &state, false); /* don't follow olh */
    if (ret < 0)
      return ret;

    ret = olh_init_modification(bucket_info, *state, olh_obj, &op_tag);
    if (ret < 0) {
      ldout(cct, 20) << "olh_init_modification() target_obj=" << target_obj << " returned " << ret << dendl;
      if (ret == -ECANCELED) {
        continue;
      }
      return ret;
    }

    string olh_tag(state->olh_tag.c_str(), state->olh_tag.length());

    ret = bucket_index_unlink_instance(bucket_info, target_obj, op_tag, olh_tag, olh_epoch, zones_trace);
    if (ret < 0) {
      ldout(cct, 20) << "bucket_index_unlink_instance() target_obj=" << target_obj << " returned " << ret << dendl;
      if (ret == -ECANCELED) {
        continue;
      }
      return ret;
    }
    break;
  }

  if (i == MAX_ECANCELED_RETRY) {
    ldout(cct, 0) << "ERROR: exceeded max ECANCELED retries, aborting (EIO)" << dendl;
    return -EIO;
  }

  ret = update_olh(obj_ctx, state, bucket_info, olh_obj, zones_trace);
  if (ret == -ECANCELED) { /* already did what we needed, no need to retry, raced with another user */
    return 0;
  }
  if (ret < 0) {
    ldout(cct, 20) << "update_olh() target_obj=" << target_obj << " returned " << ret << dendl;
    return ret;
  }

  return 0;
}

void RGWRados::gen_rand_obj_instance_name(rgw_obj *target_obj)
{
#define OBJ_INSTANCE_LEN 32
  char buf[OBJ_INSTANCE_LEN + 1];

  gen_rand_alphanumeric_no_underscore(cct, buf, OBJ_INSTANCE_LEN); /* don't want it to get url escaped,
                                                                      no underscore for instance name due to the way we encode the raw keys */

  target_obj->key.set_instance(buf);
}

static void filter_attrset(map<string, bufferlist>& unfiltered_attrset, string check_prefix,
                           map<string, bufferlist> *attrset)
{
  attrset->clear();
  map<string, bufferlist>::iterator iter;
  for (iter = unfiltered_attrset.lower_bound(check_prefix);
       iter != unfiltered_attrset.end(); ++iter) {
    if (!boost::algorithm::starts_with(iter->first, check_prefix))
      break;
    (*attrset)[iter->first] = iter->second;
  }
}

int RGWRados::get_olh(const RGWBucketInfo& bucket_info, const rgw_obj& obj, RGWOLHInfo *olh)
{
  map<string, bufferlist> attrset;

  ObjectReadOperation op;
  op.getxattrs(&attrset, NULL);

  int r = obj_operate(bucket_info, obj, &op);
  if (r < 0) {
    return r;
  }

  auto iter = attrset.find(RGW_ATTR_OLH_INFO);
  if (iter == attrset.end()) { /* not an olh */
    return -EINVAL;
  }

  return decode_olh_info(cct, iter->second, olh);
}

void RGWRados::check_pending_olh_entries(map<string, bufferlist>& pending_entries, 
                                         map<string, bufferlist> *rm_pending_entries)
{
  map<string, bufferlist>::iterator iter = pending_entries.begin();

  real_time now = real_clock::now();

  while (iter != pending_entries.end()) {
    bufferlist::iterator biter = iter->second.begin();
    RGWOLHPendingInfo pending_info;
    try {
      decode(pending_info, biter);
    } catch (buffer::error& err) {
      /* skipping bad entry, we could remove it but it might hide a bug */
      ldout(cct, 0) << "ERROR: failed to decode pending entry " << iter->first << dendl;
      ++iter;
      continue;
    }

    map<string, bufferlist>::iterator cur_iter = iter;
    ++iter;
    if (now - pending_info.time >= make_timespan(cct->_conf->rgw_olh_pending_timeout_sec)) {
      (*rm_pending_entries)[cur_iter->first] = cur_iter->second;
      pending_entries.erase(cur_iter);
    } else {
      /* entries names are sorted by time (rounded to a second) */
      break;
    }
  }
}

int RGWRados::remove_olh_pending_entries(const RGWBucketInfo& bucket_info, RGWObjState& state, const rgw_obj& olh_obj, map<string, bufferlist>& pending_attrs)
{
  ObjectWriteOperation op;

  bucket_index_guard_olh_op(state, op);

  for (map<string, bufferlist>::iterator iter = pending_attrs.begin(); iter != pending_attrs.end(); ++iter) {
    op.rmxattr(iter->first.c_str());
  }

  rgw_rados_ref ref;
  int r = get_obj_head_ref(bucket_info, olh_obj, &ref);
  if (r < 0) {
    return r;
  }

  /* update olh object */
  r = ref.ioctx.operate(ref.oid, &op);
  if (r == -ENOENT || r == -ECANCELED) {
    /* raced with some other change, shouldn't sweat about it */
    r = 0;
  }
  if (r < 0) {
    ldout(cct, 0) << "ERROR: could not apply olh update, r=" << r << dendl;
    return r;
  }

  return 0;
}

int RGWRados::follow_olh(const RGWBucketInfo& bucket_info, RGWObjectCtx& obj_ctx, RGWObjState *state, const rgw_obj& olh_obj, rgw_obj *target)
{
  map<string, bufferlist> pending_entries;
  filter_attrset(state->attrset, RGW_ATTR_OLH_PENDING_PREFIX, &pending_entries);

  map<string, bufferlist> rm_pending_entries;
  check_pending_olh_entries(pending_entries, &rm_pending_entries);

  if (!rm_pending_entries.empty()) {
    int ret = remove_olh_pending_entries(bucket_info, *state, olh_obj, rm_pending_entries);
    if (ret < 0) {
      ldout(cct, 20) << "ERROR: rm_pending_entries returned ret=" << ret << dendl;
      return ret;
    }
  }
  if (!pending_entries.empty()) {
    ldout(cct, 20) << __func__ << "(): found pending entries, need to update_olh() on bucket=" << olh_obj.bucket << dendl;

    int ret = update_olh(obj_ctx, state, bucket_info, olh_obj);
    if (ret < 0) {
      return ret;
    }
  }

  auto iter = state->attrset.find(RGW_ATTR_OLH_INFO);
  if (iter == state->attrset.end()) {
    return -EINVAL;
  }
  RGWOLHInfo olh;
  int ret = decode_olh_info(cct, iter->second, &olh);
  if (ret < 0) {
    return ret;
  }

  if (olh.removed) {
    return -ENOENT;
  }

  *target = olh.target;

  return 0;
}

int RGWRados::raw_obj_stat(rgw_raw_obj& obj, uint64_t *psize, real_time *pmtime, uint64_t *epoch,
                           map<string, bufferlist> *attrs, bufferlist *first_chunk,
                           RGWObjVersionTracker *objv_tracker, bool filter_system_attr)
{
  rgw_rados_ref ref;
  int r = get_raw_obj_ref(obj, &ref);
  if (r < 0) {
    return r;
  }

  map<string, bufferlist> unfiltered_attrset;
  uint64_t size = 0;
  struct timespec mtime_ts;

  ObjectReadOperation op;
  if (objv_tracker) {
    objv_tracker->prepare_op_for_read(&op);
  }
  if (attrs) {
    op.getxattrs(&unfiltered_attrset, NULL);
  }
  if (psize || pmtime) {
    op.stat2(&size, &mtime_ts, NULL);
  }
  if (first_chunk) {
    op.read(0, cct->_conf->rgw_max_chunk_size, first_chunk, NULL);
  }
  bufferlist outbl;
  r = ref.ioctx.operate(ref.oid, &op, &outbl);

  if (epoch) {
    *epoch = ref.ioctx.get_last_version();
  }

  if (r < 0)
    return r;

  if (psize)
    *psize = size;
  if (pmtime)
    *pmtime = ceph::real_clock::from_timespec(mtime_ts);
  if (attrs) {
    if (filter_system_attr) {
      filter_attrset(unfiltered_attrset, RGW_ATTR_PREFIX, attrs);
    } else {
      attrs->clear();
      for (auto& u : unfiltered_attrset) {
        (*attrs)[u.first] = u.second;
      }
    }
  }

  return 0;
}

#ifdef WITH_RADOSGW_BEAST_FRONTEND
static void obj_stat_asio_cb(librados::completion_t cb, void *arg) {
  auto sync = (SyncPoint *) arg;
  sync->put(rados_aio_get_return_value(cb));
}
#endif

int RGWRados::raw_obj_stat_with_ctx(RGWObjectCtx *ctx, rgw_raw_obj& obj, RGWObjState *s, RGWObjVersionTracker *objv_tracker) {
  rgw_rados_ref ref;
  int r = get_raw_obj_ref(obj, &ref);
  if (r < 0) {
    return r;
  }

  map<string, bufferlist> unfiltered_attrset;
  uint64_t size = 0;
  struct timespec mtime_ts;

  ObjectReadOperation op;
  if (objv_tracker) {
    objv_tracker->prepare_op_for_read(&op);
  }
  op.getxattrs(&unfiltered_attrset, NULL);
  op.stat2(&size, &mtime_ts, NULL);
  if (s->prefetch_data) {
    if (ctx->s != NULL && ctx->s->obj_end >= 0) {
      off_t size = std::min(cct->_conf->rgw_max_chunk_size, ctx->s->obj_end + 1) - ctx->s->obj_ofs;
      op.read(ctx->s->obj_ofs, size, &s->data, NULL);
    } else if (ctx->s != NULL && ctx->s->obj_ofs > 0) {
      off_t size = cct->_conf->rgw_max_chunk_size - ctx->s->obj_ofs;
      op.read(ctx->s->obj_ofs, size, &s->data, NULL);
    } else {
      op.read(0, cct->_conf->rgw_max_chunk_size, &s->data, NULL);
    }
  }
  void **asio_ctx = NULL;
  if (ctx->s != NULL) {
    asio_ctx = (void **) ctx->s->asio_ctx;
  }
#ifdef WITH_RADOSGW_BEAST_FRONTEND
  if (asio_ctx != NULL) {
    SyncPoint sync(*((boost::asio::io_service *) asio_ctx[0]), *((boost::asio::yield_context *) asio_ctx[1]));
    auto cb = Rados::aio_create_completion(&sync, NULL, obj_stat_asio_cb);
    r = ref.ioctx.aio_operate(ref.oid, cb, &op, NULL);
    cb->release();
    if (r >= 0) {
      r = sync.get();
    }
  } else
#endif
  {
    r = ref.ioctx.operate(ref.oid, &op, cct->_conf->rgw_rados_read_flag, NULL);
  }

  s->epoch = ref.ioctx.get_last_version();

  if (r < 0) {
    return r;
  }

  s->size = size;
  s->mtime = ceph::real_clock::from_timespec(mtime_ts);
  filter_attrset(unfiltered_attrset, RGW_ATTR_PREFIX, &s->attrset);

  return 0;
}

int RGWRados::get_bucket_stats(RGWBucketInfo& bucket_info, int shard_id, string *bucket_ver, string *master_ver,
    map<RGWObjCategory, RGWStorageStats>& stats, string *max_marker, bool *syncstopped, 
    map<std::string, RGWStorageStats>* storageclass_stats)
{
  vector<rgw_bucket_dir_header> headers;
  map<int, string> bucket_instance_ids;
  int r = cls_bucket_head(bucket_info, shard_id, headers, &bucket_instance_ids);
  if (r < 0) {
    return r;
  }

  assert(headers.size() == bucket_instance_ids.size());

  auto iter = headers.begin();
  map<int, string>::iterator viter = bucket_instance_ids.begin();
  BucketIndexShardsManager ver_mgr;
  BucketIndexShardsManager master_ver_mgr;
  BucketIndexShardsManager marker_mgr;
  char buf[64];
  for(; iter != headers.end(); ++iter, ++viter) {
    accumulate_raw_stats(*iter, stats);
    if (storageclass_stats){
      accumulate_storageclass_stats(*iter, storageclass_stats);
    }
    snprintf(buf, sizeof(buf), "%lu", (unsigned long)iter->ver);
    ver_mgr.add(viter->first, string(buf));
    snprintf(buf, sizeof(buf), "%lu", (unsigned long)iter->master_ver);
    master_ver_mgr.add(viter->first, string(buf));
    if (shard_id >= 0) {
      *max_marker = iter->max_marker;
    } else {
      marker_mgr.add(viter->first, iter->max_marker);
    }
    if (syncstopped != NULL) {
      ldout(cct, 20) << "bucket: "<< bucket_info.bucket.name <<", master_ver:"<< iter->master_ver  <<  ", syncstopped:"<< iter->syncstopped  << dendl;
      *syncstopped = iter->syncstopped;
    }
  }
  ver_mgr.to_string(bucket_ver);
  master_ver_mgr.to_string(master_ver);
  if (shard_id < 0) {
    marker_mgr.to_string(max_marker);
  }
  return 0;
}

int RGWRados::get_bi_log_status(RGWBucketInfo& bucket_info, int shard_id,
    map<int, string>& markers)
{
  vector<rgw_bucket_dir_header> headers;
  map<int, string> bucket_instance_ids;
  int r = cls_bucket_head(bucket_info, shard_id, headers, &bucket_instance_ids);
  if (r < 0)
    return r;

  assert(headers.size() == bucket_instance_ids.size());

  auto iter = headers.begin();
  map<int, string>::iterator viter = bucket_instance_ids.begin();

  for(; iter != headers.end(); ++iter, ++viter) {
    if (shard_id >= 0) {
      markers[shard_id] = iter->max_marker;
    } else {
      markers[viter->first] = iter->max_marker;
    }
  }
  return 0;
}

class RGWGetBucketStatsContext : public RGWGetDirHeader_CB {
  RGWGetBucketStats_CB *cb;
  uint32_t pendings;
  map<RGWObjCategory, RGWStorageStats> stats;
  int ret_code;
  bool should_cb;
  Mutex lock;

public:
  RGWGetBucketStatsContext(RGWGetBucketStats_CB *_cb, uint32_t _pendings)
    : cb(_cb), pendings(_pendings), stats(), ret_code(0), should_cb(true),
    lock("RGWGetBucketStatsContext") {}

  void handle_response(int r, rgw_bucket_dir_header& header) override {
    Mutex::Locker l(lock);
    if (should_cb) {
      if ( r >= 0) {
        accumulate_raw_stats(header, stats);
      } else {
        ret_code = r;
      }

      // Are we all done?
      if (--pendings == 0) {
        if (!ret_code) {
          cb->set_response(&stats);
        }
        cb->handle_response(ret_code);
        cb->put();
      }
    }
  }

  void unset_cb() {
    Mutex::Locker l(lock);
    should_cb = false;
  }
};

int RGWRados::get_bucket_stats_async(RGWBucketInfo& bucket_info, int shard_id, RGWGetBucketStats_CB *ctx)
{
  int num_aio = 0;
  RGWGetBucketStatsContext *get_ctx = new RGWGetBucketStatsContext(ctx, bucket_info.num_shards ? : 1);
  assert(get_ctx);
  int r = cls_bucket_head_async(bucket_info, shard_id, get_ctx, &num_aio);
  if (r < 0) {
    ctx->put();
    if (num_aio) {
      get_ctx->unset_cb();
    }
  }
  get_ctx->put();
  return r;
}

class RGWGetUserStatsContext : public RGWGetUserHeader_CB {
  RGWGetUserStats_CB *cb;

public:
  explicit RGWGetUserStatsContext(RGWGetUserStats_CB * const cb)
    : cb(cb) {}

  void handle_response(int r, cls_user_header& header) override {
    const cls_user_stats& hs = header.stats;
    if (r >= 0) {
      RGWStorageStats stats;

      stats.size = hs.total_bytes;
      stats.size_rounded = hs.total_bytes_rounded;
      stats.num_objects = hs.total_entries;

      cb->set_response(stats);
    }

    cb->handle_response(r);

    cb->put();
  }
};

int RGWRados::get_user_stats(const rgw_user& user, RGWStorageStats& stats)
{
  string user_str = user.to_str();

  cls_user_header header;
  int r = cls_user_get_header(user_str, &header);
  if (r < 0)
    return r;

  const cls_user_stats& hs = header.stats;

  stats.size = hs.total_bytes;
  stats.size_rounded = hs.total_bytes_rounded;
  stats.num_objects = hs.total_entries;

  return 0;
}

int RGWRados::get_user_stats_async(const rgw_user& user, RGWGetUserStats_CB *ctx)
{
  string user_str = user.to_str();

  RGWGetUserStatsContext *get_ctx = new RGWGetUserStatsContext(ctx);
  int r = cls_user_get_header_async(user_str, get_ctx);
  if (r < 0) {
    ctx->put();
    delete get_ctx;
    return r;
  }

  return 0;
}

void RGWRados::get_bucket_meta_oid(const rgw_bucket& bucket, string& oid)
{
  oid = RGW_BUCKET_INSTANCE_MD_PREFIX + bucket.get_key(':');
}

void RGWRados::get_bucket_instance_obj(const rgw_bucket& bucket, rgw_raw_obj& obj)
{
  if (!bucket.oid.empty()) {
    obj.init(get_zone_params().domain_root, bucket.oid);
  } else {
    string oid;
    get_bucket_meta_oid(bucket, oid);
    obj.init(get_zone_params().domain_root, oid);
  }
}

int RGWRados::get_bucket_instance_info(RGWObjectCtx& obj_ctx, const string& meta_key, RGWBucketInfo& info,
                                       real_time *pmtime, map<string, bufferlist> *pattrs)
{
  size_t pos = meta_key.find(':');
  if (pos == string::npos) {
    return -EINVAL;
  }
  string oid = RGW_BUCKET_INSTANCE_MD_PREFIX + meta_key;
  rgw_bucket_instance_key_to_oid(oid);

  return get_bucket_instance_from_oid(obj_ctx, oid, info, pmtime, pattrs);
}

int RGWRados::get_bucket_instance_info(RGWObjectCtx& obj_ctx, const rgw_bucket& bucket, RGWBucketInfo& info,
                                       real_time *pmtime, map<string, bufferlist> *pattrs)
{
  string oid;
  if (bucket.oid.empty()) {
    get_bucket_meta_oid(bucket, oid);
  } else {
    oid = bucket.oid;
  }

  return get_bucket_instance_from_oid(obj_ctx, oid, info, pmtime, pattrs);
}

int RGWRados::get_bucket_instance_from_oid(RGWObjectCtx& obj_ctx, const string& oid, RGWBucketInfo& info,
                                           real_time *pmtime, map<string, bufferlist> *pattrs,
                                           rgw_cache_entry_info *cache_info,
					   boost::optional<obj_version> refresh_version)
{
  ldout(cct, 20) << "reading from " << get_zone_params().domain_root << ":" << oid << dendl;

  bufferlist epbl;

  int ret = rgw_get_system_obj(this, obj_ctx, get_zone_params().domain_root,
			       oid, epbl, &info.objv_tracker, pmtime, pattrs,
			       cache_info, refresh_version);
  if (ret < 0) {
    return ret;
  }

  bufferlist::iterator iter = epbl.begin();
  try {
    decode(info, iter);
  } catch (buffer::error& err) {
    ldout(cct, 0) << "ERROR: could not decode buffer info, caught buffer::error:" << oid << dendl;
    return -EIO;
  }
  info.bucket.oid = oid;
  return 0;
}

int RGWRados::get_bucket_entrypoint_info(RGWObjectCtx& obj_ctx,
                                         const string& tenant_name,
                                         const string& bucket_name,
                                         RGWBucketEntryPoint& entry_point,
                                         RGWObjVersionTracker *objv_tracker,
                                         real_time *pmtime,
                                         map<string, bufferlist> *pattrs,
                                         rgw_cache_entry_info *cache_info,
					 boost::optional<obj_version> refresh_version)
{
  bufferlist bl;
  string bucket_entry;

  rgw_make_bucket_entry_name(tenant_name, bucket_name, bucket_entry);
  int ret = rgw_get_system_obj(this, obj_ctx, get_zone_params().domain_root,
			       bucket_entry, bl, objv_tracker, pmtime, pattrs,
			       cache_info, refresh_version);
  if (ret < 0) {
    return ret;
  }

  bufferlist::iterator iter = bl.begin();
  try {
    decode(entry_point, iter);
  } catch (buffer::error& err) {
    ldout(cct, 0) << "ERROR: could not decode buffer info, caught buffer::error" << dendl;
    return -EIO;
  }
  return 0;
}

int RGWRados::convert_old_bucket_info(RGWObjectCtx& obj_ctx,
                                      const string& tenant_name,
                                      const string& bucket_name)
{
  RGWBucketEntryPoint entry_point;
  real_time ep_mtime;
  RGWObjVersionTracker ot;
  map<string, bufferlist> attrs;
  RGWBucketInfo info;

  ldout(cct, 10) << "RGWRados::convert_old_bucket_info(): bucket=" << bucket_name << dendl;

  int ret = get_bucket_entrypoint_info(obj_ctx, tenant_name, bucket_name, entry_point, &ot, &ep_mtime, &attrs);
  if (ret < 0) {
    ldout(cct, 0) << "ERROR: get_bucket_entrypoint_info() returned " << ret << " bucket=" << bucket_name << dendl;
    return ret;
  }

  if (!entry_point.has_bucket_info) {
    /* already converted! */
    return 0;
  }

  info = entry_point.old_bucket_info;
  info.bucket.oid = bucket_name;
  info.ep_objv = ot.read_version;

  ot.generate_new_write_ver(cct);

  ret = put_linked_bucket_info(info, false, ep_mtime, &ot.write_version, &attrs, true);
  if (ret < 0) {
    ldout(cct, 0) << "ERROR: failed to put_linked_bucket_info(): " << ret << dendl;
    return ret;
  }

  return 0;
}

int RGWRados::_get_bucket_info(RGWObjectCtx& obj_ctx,
                               const string& tenant,
                               const string& bucket_name,
                               RGWBucketInfo& info,
                               real_time *pmtime,
                               map<string, bufferlist> *pattrs,
                               boost::optional<obj_version> refresh_version)
{
  string bucket_entry;
  rgw_make_bucket_entry_name(tenant, bucket_name, bucket_entry);


  if (auto e = binfo_cache->find(bucket_entry)) {
    if (refresh_version &&
        e->info.objv_tracker.read_version.compare(&(*refresh_version))) {
      lderr(cct) << "WARNING: The bucket info cache is inconsistent. This is "
                 << "a failure that should be debugged. I am a nice machine, "
                 << "so I will try to recover." << dendl;
      binfo_cache->invalidate(bucket_entry);
    } else {
      info = e->info;
      if (pattrs)
	*pattrs = e->attrs;
      if (pmtime)
	*pmtime = e->mtime;
      return 0;
    }
  }

  bucket_info_entry e;
  RGWBucketEntryPoint entry_point;
  real_time ep_mtime;
  RGWObjVersionTracker ot;
  rgw_cache_entry_info entry_cache_info;
  int ret = get_bucket_entrypoint_info(obj_ctx, tenant, bucket_name,
				       entry_point, &ot, &ep_mtime, pattrs,
				       &entry_cache_info, refresh_version);
  if (ret < 0) {
    /* only init these fields */
    info.bucket.tenant = tenant;
    info.bucket.name = bucket_name;
    return ret;
  }

  if (entry_point.has_bucket_info) {
    info = entry_point.old_bucket_info;
    info.bucket.oid = bucket_name;
    info.bucket.tenant = tenant;
    info.ep_objv = ot.read_version;
    ldout(cct, 20) << "rgw_get_bucket_info: old bucket info, bucket=" << info.bucket << " owner " << info.owner << dendl;
    return 0;
  }

  /* data is in the bucket instance object, we need to get attributes from there, clear everything
   * that we got
   */
  if (pattrs) {
    pattrs->clear();
  }

  ldout(cct, 20) << "rgw_get_bucket_info: bucket instance: " << entry_point.bucket << dendl;


  /* read bucket instance info */

  string oid;
  get_bucket_meta_oid(entry_point.bucket, oid);

  rgw_cache_entry_info cache_info;

  ret = get_bucket_instance_from_oid(obj_ctx, oid, e.info, &e.mtime, &e.attrs,
				     &cache_info, refresh_version);
  e.info.ep_objv = ot.read_version;
  info = e.info;
  if (ret < 0) {
    lderr(cct) << "ERROR: get_bucket_instance_from_oid failed: " << ret
               << ", bucket:" << oid << dendl;
    info.bucket.tenant = tenant;
    info.bucket.name = bucket_name;
    // XXX and why return anything in case of an error anyway?
    return ret;
  }

  if (pmtime)
    *pmtime = e.mtime;
  if (pattrs)
    *pattrs = e.attrs;

  /* chain to both bucket entry point and bucket instance */
  if (!binfo_cache->put(this, bucket_entry, &e, {&entry_cache_info, &cache_info})) {
    ldout(cct, 20) << "couldn't put binfo cache entry, might have raced with data changes" << dendl;
  }

  if (refresh_version &&
      refresh_version->compare(&info.objv_tracker.read_version)) {
    lderr(cct) << "WARNING: The OSD has the same version I have. Something may "
               << "have gone squirrelly. An administrator may have forced a "
               << "change; otherwise there is a problem somewhere." << dendl;
  }

  return 0;
}

int RGWRados::get_bucket_info(RGWObjectCtx& obj_ctx,
                              const string& tenant, const string& bucket_name,
                              RGWBucketInfo& info,
                              real_time *pmtime, map<string, bufferlist> *pattrs)
{
  return _get_bucket_info(obj_ctx, tenant, bucket_name, info, pmtime,
                          pattrs, boost::none);
}

int RGWRados::try_refresh_bucket_info(RGWBucketInfo& info,
                                      ceph::real_time *pmtime,
                                      map<string, bufferlist> *pattrs)
{
  RGWObjectCtx obj_ctx(this);

  return _get_bucket_info(obj_ctx, info.bucket.tenant, info.bucket.name,
                          info, pmtime, pattrs, info.objv_tracker.read_version);
}

int RGWRados::put_bucket_entrypoint_info(const string& tenant_name, const string& bucket_name, RGWBucketEntryPoint& entry_point,
                                         bool exclusive, RGWObjVersionTracker& objv_tracker, real_time mtime,
                                         map<string, bufferlist> *pattrs)
{
  bufferlist epbl;
  encode(entry_point, epbl);
  string bucket_entry;
  rgw_make_bucket_entry_name(tenant_name, bucket_name, bucket_entry);
  return rgw_bucket_store_info(this, bucket_entry, epbl, exclusive, pattrs, &objv_tracker, mtime);
}

int RGWRados::put_bucket_instance_info(RGWBucketInfo& info, bool exclusive,
                              real_time mtime, map<string, bufferlist> *pattrs)
{
  info.has_instance_obj = true;
  bufferlist bl;

  encode(info, bl);

  string key = info.bucket.get_key(); /* when we go through meta api, we don't use oid directly */
  int ret = rgw_bucket_instance_store_info(this, key, bl, exclusive, pattrs, &info.objv_tracker, mtime);
  if (ret == -EEXIST) {
    /* well, if it's exclusive we shouldn't overwrite it, because we might race with another
     * bucket operation on this specific bucket (e.g., being synced from the master), but
     * since bucket instace meta object is unique for this specific bucket instace, we don't
     * need to return an error.
     * A scenario where we'd get -EEXIST here, is in a multi-zone config, we're not on the
     * master, creating a bucket, sending bucket creation to the master, we create the bucket
     * locally, while in the sync thread we sync the new bucket.
     */
    ret = 0;
  }
  return ret;
}

int RGWRados::put_linked_bucket_info(RGWBucketInfo& info, bool exclusive, real_time mtime, obj_version *pep_objv,
                                     map<string, bufferlist> *pattrs, bool create_entry_point)
{
  bool create_head = !info.has_instance_obj || create_entry_point;

  int ret = put_bucket_instance_info(info, exclusive, mtime, pattrs);
  if (ret < 0) {
    return ret;
  }

  if (!create_head)
    return 0; /* done! */

  RGWBucketEntryPoint entry_point;
  entry_point.bucket = info.bucket;
  entry_point.owner = info.owner;
  entry_point.creation_time = info.creation_time;
  entry_point.linked = true;
  RGWObjVersionTracker ot;
  if (pep_objv && !pep_objv->tag.empty()) {
    ot.write_version = *pep_objv;
  } else {
    ot.generate_new_write_ver(cct);
    if (pep_objv) {
      *pep_objv = ot.write_version;
    }
  }
  ret = put_bucket_entrypoint_info(info.bucket.tenant, info.bucket.name, entry_point, exclusive, ot, mtime, NULL); 
  if (ret < 0)
    return ret;

  return 0;
}

int RGWRados::omap_get_vals(rgw_raw_obj& obj, bufferlist& header, const string& marker, uint64_t count, std::map<string, bufferlist>& m)
{
  rgw_rados_ref ref;
  int r = get_raw_obj_ref(obj, &ref);
  if (r < 0) {
    return r;
  }

  r = ref.ioctx.omap_get_vals(ref.oid, marker, count, &m);
  if (r < 0)
    return r;

  return 0;
 
}

int RGWRados::omap_get_all(rgw_raw_obj& obj, bufferlist& header,
			   std::map<string, bufferlist>& m)
{
  rgw_rados_ref ref;
  int r = get_raw_obj_ref(obj, &ref);
  if (r < 0) {
    return r;
  }

#define MAX_OMAP_GET_ENTRIES 1024
  const int count = MAX_OMAP_GET_ENTRIES;
  string start_after;

  while (true) {
    std::map<string, bufferlist> t;
    r = ref.ioctx.omap_get_vals(ref.oid, start_after, count, &t);
    if (r < 0) {
      return r;
    }
    if (t.empty()) {
      break;
    }
    start_after = t.rbegin()->first;
    m.insert(t.begin(), t.end());
  }
  return 0;
}

int RGWRados::omap_set(rgw_raw_obj& obj, const std::string& key, bufferlist& bl, bool must_exist)
{
  rgw_rados_ref ref;
  int r = get_raw_obj_ref(obj, &ref);
  if (r < 0) {
    return r;
  }
  ldout(cct, 15) << "omap_set obj=" << obj << " key=" << key << dendl;

  map<string, bufferlist> m;
  m[key] = bl;
  ObjectWriteOperation op;
  if (must_exist)
    op.assert_exists();
  op.omap_set(m);
  r = ref.ioctx.operate(ref.oid, &op);
  return r;
}

int RGWRados::omap_set(rgw_raw_obj& obj, std::map<std::string, bufferlist>& m, bool must_exist)
{
  rgw_rados_ref ref;
  int r = get_raw_obj_ref(obj, &ref);
  if (r < 0) {
    return r;
  }

  ObjectWriteOperation op;
  if (must_exist)
    op.assert_exists();
  op.omap_set(m);
  r = ref.ioctx.operate(ref.oid, &op);
  return r;
}

int RGWRados::omap_del(rgw_raw_obj& obj, const std::string& key)
{
  rgw_rados_ref ref;
  int r = get_raw_obj_ref(obj, &ref);
  if (r < 0) {
    return r;
  }

  set<string> k;
  k.insert(key);

  r = ref.ioctx.omap_rm_keys(ref.oid, k);
  return r;
}

int RGWRados::update_containers_stats(map<string, RGWBucketEnt>& m)
{
  RGWObjectCtx obj_ctx(this);

  map<string, RGWBucketEnt>::iterator iter;
  for (iter = m.begin(); iter != m.end(); ++iter) {
    RGWBucketEnt& ent = iter->second;
    rgw_bucket& bucket = ent.bucket;
    ent.count = 0;
    ent.size = 0;
    ent.size_rounded = 0;

    vector<rgw_bucket_dir_header> headers;

    RGWBucketInfo bucket_info;
    map<string, bufferlist> bucket_attrs;
    int ret = get_bucket_instance_info(obj_ctx, bucket, bucket_info, NULL, &bucket_attrs);
    if (ret < 0) {
      return ret;
    }

    int r = cls_bucket_head(bucket_info, RGW_NO_SHARD, headers);
    if (r < 0)
      return r;

    auto hiter = headers.begin();
    for (; hiter != headers.end(); ++hiter) {
      RGWObjCategory category = main_category;
      map<uint8_t, struct rgw_bucket_category_stats>::iterator iter = (hiter->stats).find((uint8_t)category);
      if (iter != hiter->stats.end()) {
        struct rgw_bucket_category_stats& stats = iter->second;
        ent.count += stats.num_entries;
        ent.size += stats.total_size;
        ent.size_rounded += stats.total_size_rounded;
      }
    }

    // fill in placement_rule from the bucket instance for use in swift's
    // per-storage policy statistics
    auto iter_didecated = bucket_attrs.find(RGW_ATTR_DEDICATED);
    if (iter_didecated != bucket_attrs.end()) {
      ent.enable_dedicated = (rgw_bl_to_str(iter_didecated->second) == "true") ? true : false;
    }
    ent.placement_rule = std::move(bucket_info.head_placement_rule);
  }

  return m.size();
}

int RGWRados::append_async(rgw_raw_obj& obj, size_t size, bufferlist& bl)
{
  rgw_rados_ref ref;
  int r = get_raw_obj_ref(obj, &ref);
  if (r < 0) {
    return r;
  }
  librados::Rados *rad = get_rados_handle();
  librados::AioCompletion *completion = rad->aio_create_completion(NULL, NULL, NULL);

  r = ref.ioctx.aio_append(ref.oid, completion, bl, size);
  completion->release();
  return r;
}

int RGWRados::distribute(const string& key, bufferlist& bl)
{
  /*
   * we were called before watch was initialized. This can only happen if we're updating some system
   * config object (e.g., zone info) during init. Don't try to distribute the cache info for these
   * objects, they're currently only read on startup anyway.
   */
  if (!watch_initialized)
    return 0;

  string notify_oid;
  pick_control_oid(key, notify_oid);

  ldout(cct, 10) << "distributing notification oid=" << notify_oid << " bl.length()=" << bl.length() << dendl;
  return control_pool_ctx.notify2(notify_oid, bl, 0, NULL);
}

int RGWRados::pool_iterate_begin(const rgw_pool& pool, RGWPoolIterCtx& ctx)
{
  librados::IoCtx& io_ctx = ctx.io_ctx;
  librados::NObjectIterator& iter = ctx.iter;

  int r = open_pool_ctx(pool, io_ctx);
  if (r < 0)
    return r;

  iter = io_ctx.nobjects_begin();

  return 0;
}

int RGWRados::pool_iterate_begin(const rgw_pool& pool, const string& cursor, RGWPoolIterCtx& ctx)
{
  librados::IoCtx& io_ctx = ctx.io_ctx;
  librados::NObjectIterator& iter = ctx.iter;

  int r = open_pool_ctx(pool, io_ctx);
  if (r < 0)
    return r;

  librados::ObjectCursor oc;
  if (!oc.from_str(cursor)) {
    ldout(cct, 10) << "failed to parse cursor: " << cursor << dendl;
    return -EINVAL;
  }

  iter = io_ctx.nobjects_begin(oc);

  return 0;
}

string RGWRados::pool_iterate_get_cursor(RGWPoolIterCtx& ctx)
{
  return ctx.iter.get_cursor().to_str();
}

int RGWRados::pool_iterate(RGWPoolIterCtx& ctx, uint32_t num, vector<rgw_bucket_dir_entry>& objs,
                           bool *is_truncated, RGWAccessListFilter *filter)
{
  librados::IoCtx& io_ctx = ctx.io_ctx;
  librados::NObjectIterator& iter = ctx.iter;

  if (iter == io_ctx.nobjects_end())
    return -ENOENT;

  uint32_t i;

  for (i = 0; i < num && iter != io_ctx.nobjects_end(); ++i, ++iter) {
    rgw_bucket_dir_entry e;

    string oid = iter->get_oid();
    ldout(cct, 20) << "RGWRados::pool_iterate: got " << oid << dendl;

    // fill it in with initial values; we may correct later
    if (filter && !filter->filter(oid, oid))
      continue;

    e.key = oid;
    objs.push_back(e);
  }

  if (is_truncated)
    *is_truncated = (iter != io_ctx.nobjects_end());

  return objs.size();
}
struct RGWAccessListFilterPrefix : public RGWAccessListFilter {
  string prefix;

  explicit RGWAccessListFilterPrefix(const string& _prefix) : prefix(_prefix) {}
  bool filter(string& name, string& key) override {
    return (prefix.compare(key.substr(0, prefix.size())) == 0);
  }
};

int RGWRados::list_raw_objects_init(const rgw_pool& pool, const string& marker, RGWListRawObjsCtx *ctx)
{
  if (!ctx->initialized) {
    int r = pool_iterate_begin(pool, marker, ctx->iter_ctx);
    if (r < 0) {
      ldout(cct, 10) << "failed to list objects pool_iterate_begin() returned r=" << r << dendl;
      return r;
    }
    ctx->initialized = true;
  }
  return 0;
}

int RGWRados::list_raw_objects_next(const string& prefix_filter, int max,
                                    RGWListRawObjsCtx& ctx, list<string>& oids,
                                    bool *is_truncated)
{
  if (!ctx.initialized) {
    return -EINVAL;
  }
  RGWAccessListFilterPrefix filter(prefix_filter);
  vector<rgw_bucket_dir_entry> objs;
  int r = pool_iterate(ctx.iter_ctx, max, objs, is_truncated, &filter);
  if (r < 0) {
    if(r != -ENOENT)
      ldout(cct, 10) << "failed to list objects pool_iterate returned r=" << r << dendl;
    return r;
  }

  vector<rgw_bucket_dir_entry>::iterator iter;
  for (iter = objs.begin(); iter != objs.end(); ++iter) {
    oids.push_back(iter->key.name);
  }

  return oids.size();
}

int RGWRados::list_raw_objects(const rgw_pool& pool, const string& prefix_filter,
			       int max, RGWListRawObjsCtx& ctx, list<string>& oids,
			       bool *is_truncated)
{
  if (!ctx.initialized) {
    int r = list_raw_objects_init(pool, string(), &ctx);
    if (r < 0) {
      return r;
    }
  }

  return list_raw_objects_next(prefix_filter, max, ctx, oids, is_truncated);
}

string RGWRados::list_raw_objs_get_cursor(RGWListRawObjsCtx& ctx)
{
  return pool_iterate_get_cursor(ctx.iter_ctx);
}

int RGWRados::list_bi_log_entries(RGWBucketInfo& bucket_info, int shard_id, string& marker, uint32_t max,
                                  std::list<rgw_bi_log_entry>& result, bool *truncated)
{
  ldout(cct, 19) << __func__ << ": " << bucket_info.bucket << " marker " << marker << " shard_id=" << shard_id << " max " << max << dendl;
  result.clear();

  librados::IoCtx index_ctx;
  map<int, string> oids;
  map<int, cls_rgw_bi_log_list_ret> bi_log_lists;
  int r = open_bucket_index(bucket_info, index_ctx, oids, shard_id);
  if (r < 0)
    return r;

  BucketIndexShardsManager marker_mgr;
  bool has_shards = (oids.size() > 1 || shard_id >= 0);
  // If there are multiple shards for the bucket index object, the marker
  // should have the pattern '{shard_id_1}#{shard_marker_1},{shard_id_2}#
  // {shard_marker_2}...', if there is no sharding, the bi_log_list should
  // only contain one record, and the key is the bucket instance id.
  r = marker_mgr.from_string(marker, shard_id);
  if (r < 0)
    return r;
 
  r = CLSRGWIssueBILogList(index_ctx, marker_mgr, max, oids, bi_log_lists, cct->_conf->rgw_bucket_index_max_aio)();
  if (r < 0)
    return r;

  map<int, list<rgw_bi_log_entry>::iterator> vcurrents;
  map<int, list<rgw_bi_log_entry>::iterator> vends;
  if (truncated) {
    *truncated = false;
  }
  map<int, cls_rgw_bi_log_list_ret>::iterator miter = bi_log_lists.begin();
  for (; miter != bi_log_lists.end(); ++miter) {
    int shard_id = miter->first;
    vcurrents[shard_id] = miter->second.entries.begin();
    vends[shard_id] = miter->second.entries.end();
    if (truncated) {
      *truncated = (*truncated || miter->second.truncated);
    }
  }

  size_t total = 0;
  bool has_more = true;
  map<int, list<rgw_bi_log_entry>::iterator>::iterator viter;
  map<int, list<rgw_bi_log_entry>::iterator>::iterator eiter;
  while (total < max && has_more) {
    has_more = false;

    viter = vcurrents.begin();
    eiter = vends.begin();

    for (; total < max && viter != vcurrents.end(); ++viter, ++eiter) {
      assert (eiter != vends.end());

      int shard_id = viter->first;
      list<rgw_bi_log_entry>::iterator& liter = viter->second;

      if (liter == eiter->second){
        continue;
      }
      rgw_bi_log_entry& entry = *(liter);
      if (has_shards) {
        char buf[16];
        snprintf(buf, sizeof(buf), "%d", shard_id);
        string tmp_id;
        build_bucket_index_marker(buf, entry.id, &tmp_id);
        entry.id.swap(tmp_id);
      }
      ldout(cct, 19) << __func__ << "list entry id:"<< entry.id << ", obj:"<< entry.object<< "instance:"<< entry.instance << dendl;
      marker_mgr.add(shard_id, entry.id);
      result.push_back(entry);
      total++;
      has_more = true;
      ++liter;
    }
  }

  if (truncated) {
    for (viter = vcurrents.begin(), eiter = vends.begin(); viter != vcurrents.end(); ++viter, ++eiter) {
      assert (eiter != vends.end());
      *truncated = (*truncated || (viter->second != eiter->second));
    }
  }

  // Refresh marker, if there are multiple shards, the output will look like
  // '{shard_oid_1}#{shard_marker_1},{shard_oid_2}#{shard_marker_2}...',
  // if there is no sharding, the simply marker (without oid) is returned
  if (has_shards) {
    marker_mgr.to_string(&marker);
  } else {
    if (!result.empty()) {
      marker = result.rbegin()->id;
    }
  }

  return 0;
}

int RGWRados::trim_bi_log_entries(RGWBucketInfo& bucket_info, int shard_id, string& start_marker, string& end_marker)
{
  librados::IoCtx index_ctx;
  map<int, string> bucket_objs;

  BucketIndexShardsManager start_marker_mgr;
  BucketIndexShardsManager end_marker_mgr;

  int r = open_bucket_index(bucket_info, index_ctx, bucket_objs, shard_id);
  if (r < 0) {
    return r;
  }

  r = start_marker_mgr.from_string(start_marker, shard_id);
  if (r < 0) {
    return r;
  }

  r = end_marker_mgr.from_string(end_marker, shard_id);
  if (r < 0) {
    return r;
  }

  return CLSRGWIssueBILogTrim(index_ctx, start_marker_mgr, end_marker_mgr, bucket_objs,
			      cct->_conf->rgw_bucket_index_max_aio)();
}

int RGWRados::resync_bi_log_entries(RGWBucketInfo& bucket_info, int shard_id)
{
  librados::IoCtx index_ctx;
  map<int, string> bucket_objs;
  int r = open_bucket_index(bucket_info, index_ctx, bucket_objs, shard_id);
  if (r < 0)
    return r;

  return CLSRGWIssueResyncBucketBILog(index_ctx, bucket_objs, cct->_conf->rgw_bucket_index_max_aio)();
}

int RGWRados::stop_bi_log_entries(RGWBucketInfo& bucket_info, int shard_id)
{
  librados::IoCtx index_ctx;
  map<int, string> bucket_objs;
  int r = open_bucket_index(bucket_info, index_ctx, bucket_objs, shard_id);
  if (r < 0)
    return r;

  return CLSRGWIssueBucketBILogStop(index_ctx, bucket_objs, cct->_conf->rgw_bucket_index_max_aio)();
}

int RGWRados::bi_get_instance(const RGWBucketInfo& bucket_info, rgw_obj& obj, rgw_bucket_dir_entry *dirent)
{
  rgw_rados_ref ref;
  int r = get_obj_head_ref(bucket_info, obj, &ref);
  if (r < 0) {
    return r;
  }

  rgw_cls_bi_entry bi_entry;
  r = bi_get(obj.bucket, obj, InstanceIdx, &bi_entry);
  if (r < 0 && r != -ENOENT) {
    ldout(cct, 0) << "ERROR: bi_get() returned r=" << r << dendl;
  }
  if (r < 0) {
    return r;
  }
  bufferlist::iterator iter = bi_entry.data.begin();
  try {
    decode(*dirent, iter);
  } catch (buffer::error& err) {
    ldout(cct, 0) << "ERROR: failed to decode bi_entry()" << dendl;
    return -EIO;
  }

  return 0;
}

int RGWRados::bi_get(rgw_bucket& bucket, rgw_obj& obj, BIIndexType index_type, rgw_cls_bi_entry *entry)
{
  BucketShard bs(this);
  int ret = bs.init(bucket, obj, nullptr /* no RGWBucketInfo */);
  if (ret < 0) {
    ldout(cct, 5) << "bs.init() returned ret=" << ret << dendl;
    return ret;
  }

  cls_rgw_obj_key key(obj.key.get_index_key_name(), obj.key.instance);
  
  ret = cls_rgw_bi_get(bs.index_ctx, bs.bucket_obj, index_type, key, entry);
  if (ret < 0)
    return ret;

  return 0;
}

void RGWRados::bi_put(ObjectWriteOperation& op, BucketShard& bs, rgw_cls_bi_entry& entry)
{
  cls_rgw_bi_put(op, bs.bucket_obj, entry);
}

int RGWRados::bi_put(BucketShard& bs, rgw_cls_bi_entry& entry)
{
  int ret = cls_rgw_bi_put(bs.index_ctx, bs.bucket_obj, entry);
  if (ret < 0)
    return ret;

  return 0;
}

int RGWRados::bi_put(rgw_bucket& bucket, rgw_obj& obj, rgw_cls_bi_entry& entry)
{
  BucketShard bs(this);
  int ret = bs.init(bucket, obj, nullptr /* no RGWBucketInfo */);
  if (ret < 0) {
    ldout(cct, 5) << "bs.init() returned ret=" << ret << dendl;
    return ret;
  }

  return bi_put(bs, entry);
}

int RGWRados::bi_list(rgw_bucket& bucket, const string& obj_name, const string& marker, uint32_t max, list<rgw_cls_bi_entry> *entries, bool *is_truncated)
{
  rgw_obj obj(bucket, obj_name);
  BucketShard bs(this);
  int ret = bs.init(bucket, obj, nullptr /* no RGWBucketInfo */);
  if (ret < 0) {
    ldout(cct, 5) << "bs.init() returned ret=" << ret << dendl;
    return ret;
  }

  ret = cls_rgw_bi_list(bs.index_ctx, bs.bucket_obj, obj_name, marker, max, entries, is_truncated);
  if (ret == -ENOENT) {
    *is_truncated = false;
  }
  if (ret < 0)
    return ret;

  return 0;
}

int RGWRados::bi_list(BucketShard& bs, const string& filter_obj, const string& marker, uint32_t max, list<rgw_cls_bi_entry> *entries, bool *is_truncated)
{
  int ret = cls_rgw_bi_list(bs.index_ctx, bs.bucket_obj, filter_obj, marker, max, entries, is_truncated);
  if (ret < 0)
    return ret;

  return 0;
}

int RGWRados::bi_remove(BucketShard& bs)
{
  int ret = bs.index_ctx.remove(bs.bucket_obj);
  if (ret == -ENOENT) {
    ret = 0;
  }
  if (ret < 0) {
    ldout(cct, 5) << "bs.index_ctx.remove(" << bs.bucket_obj << ") returned ret=" << ret << dendl;
    return ret;
  }

  return 0;
}

int RGWRados::bi_list(rgw_bucket& bucket, int shard_id, const string& filter_obj, const string& marker, uint32_t max, list<rgw_cls_bi_entry> *entries, bool *is_truncated)
{
  BucketShard bs(this);
  int ret = bs.init(bucket, shard_id, nullptr /* no RGWBucketInfo */);
  if (ret < 0) {
    ldout(cct, 5) << "bs.init() returned ret=" << ret << dendl;
    return ret;
  }

  return bi_list(bs, filter_obj, marker, max, entries, is_truncated);
}

int RGWRados::gc_operate(string& oid, librados::ObjectWriteOperation *op)
{
  return gc_pool_ctx.operate(oid, op);
}

int RGWRados::gc_aio_operate(string& oid, librados::ObjectWriteOperation *op, AioCompletion **pc)
{
  AioCompletion *c = librados::Rados::aio_create_completion(NULL, NULL, NULL);
  int r = gc_pool_ctx.aio_operate(oid, c, op);
  if (!pc) {
    c->release();
  } else {
    *pc = c;
  }
  return r;
}

int RGWRados::gc_operate(string& oid, librados::ObjectReadOperation *op, bufferlist *pbl)
{
  return gc_pool_ctx.operate(oid, op, pbl);
}

int RGWRados::list_gc_objs(int *index, string& marker, uint32_t max, bool expired_only, std::list<cls_rgw_gc_obj_info>& result, bool *truncated)
{
  return gc->list(index, marker, max, expired_only, result, truncated);
}

int RGWRados::process_gc(bool expired_only)
{
  return gc->process(expired_only);
}

int RGWRados::list_lc_progress(string& marker,
                               uint32_t max_entries,
                               vector<cls_rgw_lc_entry>& progress_map,
                               int& index)
{
  return lc->list_lc_progress(marker, max_entries, progress_map, index);
}

int RGWRados::process_lc()
{
  RGWLC lc;
  lc.initialize(cct, this);
  RGWLC::LCWorker worker(&lc, cct, &lc, 0);
  auto ret = lc.process(&worker, true /* once */);
  lc.stop_processor(); // sets down_flag, but returns immediately
  return ret;
}

bool RGWRados::process_expire_objects()
{
  return obj_expirer->inspect_all_shards(utime_t(), ceph_clock_now());
}

int RGWRados::cls_obj_prepare_op(BucketShard& bs, RGWModifyOp op, string& tag,
                                 rgw_obj& obj, uint16_t bilog_flags, rgw_zone_set *_zones_trace)
{
  rgw_zone_set zones_trace;
  if (_zones_trace) {
    zones_trace = *_zones_trace;
  }
  zones_trace.insert(get_zone().id);

  ObjectWriteOperation o;
  cls_rgw_obj_key key(obj.key.get_index_key_name(), obj.key.instance);
  cls_rgw_guard_bucket_resharding(o, -ERR_BUSY_RESHARDING);
  cls_rgw_bucket_prepare_op(o, op, tag, key, obj.key.get_loc(), get_zone().log_data, bilog_flags, zones_trace);
  return bs.index_ctx.operate(bs.bucket_obj, &o);
}

int RGWRados::cls_obj_complete_op(BucketShard& bs, const rgw_obj& obj, RGWModifyOp op, string& tag,
                                  int64_t pool, uint64_t epoch,
                                  rgw_bucket_dir_entry& ent, RGWObjCategory category,
                                  list<rgw_obj_index_key> *remove_objs, uint16_t bilog_flags,
                                  rgw_zone_set *_zones_trace, bool bilog_write_enable, bool bilog_delete_enable)
{
  ObjectWriteOperation o;
  rgw_bucket_dir_entry_meta dir_meta;
  dir_meta = ent.meta;
  dir_meta.category = category;

  rgw_zone_set zones_trace;
  if (_zones_trace) {
    zones_trace = *_zones_trace;
  }
  zones_trace.insert(get_zone().id);

  rgw_bucket_entry_ver ver;
  ver.pool = pool;
  ver.epoch = epoch;
  cls_rgw_obj_key key(ent.key.name, ent.key.instance);
  cls_rgw_guard_bucket_resharding(o, -ERR_BUSY_RESHARDING);

  cls_rgw_bucket_complete_op(o, op, tag, ver, key, dir_meta, remove_objs,
                             get_zone().log_data, bilog_flags, &zones_trace, bilog_write_enable, bilog_delete_enable);
  complete_op_data *arg;
  index_completion_manager->create_completion(obj, op, tag, ver, key, dir_meta, remove_objs,
                                              get_zone().log_data, bilog_flags, &zones_trace, &arg);
  librados::AioCompletion *completion = arg->rados_completion;
  int ret = bs.index_ctx.aio_operate(bs.bucket_obj, arg->rados_completion, &o);
  completion->release(); /* can't reference arg here, as it might have already been released */
  return ret;
}

int RGWRados::cls_obj_complete_add(BucketShard& bs, const rgw_obj& obj, string& tag,
                                   int64_t pool, uint64_t epoch,
                                   rgw_bucket_dir_entry& ent, RGWObjCategory category,
                                   list<rgw_obj_index_key> *remove_objs, uint16_t bilog_flags,
                                   rgw_zone_set *zones_trace, bool bilog_write_enable, bool bilog_delete_enable)
{
  return cls_obj_complete_op(bs, obj, CLS_RGW_OP_ADD, tag, pool, epoch, ent, category, remove_objs, bilog_flags,
                             zones_trace, bilog_write_enable, bilog_delete_enable);
}

int RGWRados::cls_obj_complete_del(BucketShard& bs, string& tag,
                                   int64_t pool, uint64_t epoch,
                                   rgw_obj& obj,
                                   real_time& removed_mtime,
                                   list<rgw_obj_index_key> *remove_objs,
                                   uint16_t bilog_flags,
                                   rgw_zone_set *zones_trace, bool bilog_write_enable)
{
  rgw_bucket_dir_entry ent;
  ent.meta.mtime = removed_mtime;
  obj.key.get_index_key(&ent.key);
  return cls_obj_complete_op(bs, obj, CLS_RGW_OP_DEL, tag, pool, epoch, ent, RGW_OBJ_CATEGORY_NONE,
                             remove_objs, bilog_flags, zones_trace, bilog_write_enable);
}

int RGWRados::cls_obj_complete_cancel(BucketShard& bs, string& tag, rgw_obj& obj, uint16_t bilog_flags, rgw_zone_set *zones_trace)
{
  rgw_bucket_dir_entry ent;
  obj.key.get_index_key(&ent.key);
  return cls_obj_complete_op(bs, obj, CLS_RGW_OP_CANCEL, tag, -1 /* pool id */, 0, ent, RGW_OBJ_CATEGORY_NONE, NULL, bilog_flags, zones_trace);
}

int RGWRados::cls_namespace_prepare_op(librados::IoCtx& io_ctx, RGWModifyOp op, string& optag,
                                       const string& obj_name, const string& parent_oid,
                                       const string &child_name)
{

  ObjectWriteOperation o;
  cls_rgw_namespace_prepare_op(o, op, optag, obj_name, parent_oid, child_name, false);
  return io_ctx.operate(parent_oid, &o);
}

int RGWRados::cls_namespace_prepare_op_excl(librados::IoCtx& io_ctx, RGWModifyOp op,
                                            string& optag, const string& obj_name,
                                            const string& parent_oid,
                                            const string &child_name)
{

  ObjectWriteOperation o;
  cls_rgw_namespace_prepare_op(o, op, optag, obj_name, parent_oid, child_name, true);
  return io_ctx.operate(parent_oid, &o);
}


int RGWRados::cls_namespace_dir_prepare_op(librados::IoCtx& io_ctx, RGWModifyOp op,
                                           const string& optag, const string& parent_oid,
                                           const string& child_name, ceph::real_time& ut)
{

  ObjectWriteOperation o;
  cls_rgw_namespace_dir_prepare_op(o, op, optag, parent_oid, child_name, ut, false);
  return io_ctx.operate(parent_oid, &o);
}

int RGWRados::cls_namespace_dir_prepare_op_excl(librados::IoCtx& io_ctx, RGWModifyOp op,
                                                const string& optag, const string& parent_oid,
                                                const string& child_name, ceph::real_time& ut)
{
  ObjectWriteOperation o;
  cls_rgw_namespace_dir_prepare_op(o, op, optag, parent_oid, child_name, ut, true);
  return io_ctx.operate(parent_oid, &o);
}

// complete directory
int RGWRados::cls_namespace_dir_complete_add(librados::IoCtx& io_ctx, int64_t poolid,
                                             uint64_t epoch, const string& optag,
                                             const string& parent_oid,
                                             const string& child_name, ceph::real_time& ut)
{
  ObjectWriteOperation o;
  cls_rgw_namespace_dir_complete_op(o, CLS_RGW_OP_ADD, poolid, epoch, optag, child_name,
                                    ut, false);
  return io_ctx.operate(parent_oid, &o);
}

int RGWRados::cls_namespace_dir_complete_del(librados::IoCtx& io_ctx, int64_t poolid,
                                            uint64_t epoch, const string& optag,
                                            const string& parent_oid,
                                            const string& child_name, ceph::real_time& ut)
{
  ObjectWriteOperation o;
  cls_rgw_namespace_dir_complete_op(o, CLS_RGW_OP_DEL, poolid, epoch, optag, child_name,
                                    ut, false);
  return io_ctx.operate(parent_oid, &o);
}

int RGWRados::cls_namespace_dir_complete_cancel(librados::IoCtx& io_ctx, const string& optag,
                                                const string& parent_oid,
                                                const string& child_name,
                                                ceph::real_time& ut, bool force_delete)
{
  ObjectWriteOperation o;
  cls_rgw_namespace_dir_complete_op(o, CLS_RGW_OP_CANCEL, -1, 0, optag, child_name, ut,
                                    force_delete);
  return io_ctx.operate(parent_oid, &o);
}

int RGWRados::cls_namespace_complete_add(librados::IoCtx& io_ctx, const string& optag,
                                         const string& parent_oid, const string& file_name,
                                         int64_t poolid, uint64_t epoch, uint64_t size,
                                         ceph::real_time* ut, bool appendable)
{
  return cls_namespace_complete_op(io_ctx, CLS_RGW_OP_ADD, parent_oid, file_name, poolid,
                                   epoch, optag, size, ut, false, appendable);
}

int RGWRados::cls_namespace_complete_cancel(librados::IoCtx& io_ctx, const string& optag,
                                            const string& parent_oid, const string &file_name,
                                            bool force_delete)
{
  return cls_namespace_complete_op(io_ctx, CLS_RGW_OP_CANCEL, parent_oid, file_name, -1, 0,
                                   optag, 0, nullptr, force_delete);
}

int RGWRados::cls_namespace_complete_del(librados::IoCtx& io_ctx, const string& optag,
                                         const string& parent_oid, const string& file_name,
                                         int64_t poolid, uint64_t epoch,
                                         ceph::real_time* remove_time)
{
  return cls_namespace_complete_op(io_ctx, CLS_RGW_OP_DEL, parent_oid, file_name, poolid,
                                   epoch, optag, 0, remove_time, false);
}

int RGWRados::cls_namespace_complete_op(librados::IoCtx& io_ctx, RGWModifyOp op,
                                        const string& parent_oid, const string& file_name,
                                        int64_t poolid, uint64_t epoch, const string& tag,
                                        uint64_t size, ceph::real_time* ut, bool force_delete,
                                        bool appendable)
{
  ObjectWriteOperation o;
  // asynchronously send completion request to osd
  librados::AioCompletion* cp = librados::Rados::aio_create_completion(nullptr, nullptr,
                                nullptr);
  cls_rgw_namespace_complete_op(o, op, file_name, poolid, epoch, tag, size, ut, force_delete,
      appendable);
  int ret = io_ctx.aio_operate(parent_oid, cp, &o);
  cp->release();
  return ret;
}

int RGWRados::cls_namespace_dir_make_prepare(librados::IoCtx& io_ctx, const string& dir_oid)
{
  ObjectWriteOperation o;
  cls_rgw_namespace_dir_make(o, false);
  return io_ctx.operate(dir_oid, &o);
}

int RGWRados::cls_namespace_dir_make_complete(librados::IoCtx& io_ctx, const string& dir_oid)
{
  ObjectWriteOperation o;
  cls_rgw_namespace_dir_make(o, true);
  return io_ctx.operate(dir_oid, &o);
}

int RGWRados::cls_namespace_dir_del(librados::IoCtx& io_ctx, const string& dir_oid)
{
  return cls_rgw_namespace_dir_del(io_ctx, dir_oid);
}

int RGWRados::cls_bucket_namespace_list(req_state* s, const RGWBucketInfo& bucket_info,
                                        const string& parent_oid, string& parent_name,
                                        size_t level, const string& marker,
                                        const string& end_marker,
                                        map<string, bool>* common_prefixes,
                                        vector<rgw_bucket_dir_entry>* objs, uint32_t max,
                                        string& last_entry,  bool* is_truncated)
{
  ldout(cct, 20) << __func__ << " " << parent_name << " " << parent_oid
                 << " level=" << level << " marker=" << marker
                 << dendl;

  librados::IoCtx io_ctx;
  int r = open_bucket_index_ctx(bucket_info, io_ctx);
  if (r < 0) {
    return r;
  }

  utime_t start = ceph_clock_now();

  rgw_cls_namespace_list_ret list_results;
  r = cls_rgw_namespace_list(io_ctx, parent_oid, marker, end_marker, max, list_results);
  if (r < 0)
    return r;

  utime_t cls_list_end = ceph_clock_now();

  perfcounter->tinc(l_rgw_list_cls_list_namespace_lat, cls_list_end - start);

  // Create a list of iterators that are used to iterate each shard
  map<string, bufferlist>::iterator iter = list_results.dirs.begin();
  *is_truncated = list_results.is_truncated;
  bufferlist suggested_updates;
  uint32_t count = 0;

  for (; iter != list_results.dirs.end(); ++iter) {
    if (count >= max) {
      *is_truncated = true;
      break;
    }

    const string& child_name = iter->first;
    bufferlist::iterator p = iter->second.begin();

    uint64_t magic = 0;
    try {
      decode(magic, p);
    } catch (buffer::error& err) {
      ldout(cct, 0) << __func__ << " Error: failed decode magic" << dendl;
      return -EIO;
    }

    if (namespace_entry_is_file(magic)) {
      rgw_bucket_namespace_file file_ent(magic);
      // decode size
      file_ent.decode_size(p);
      if (file_ent.not_exist() || file_ent.is_pending()) {
        try {
          decode(file_ent, p);
        } catch (buffer::error& err) {
          ldout(cct, 0) << __func__ << " Error: failed decode file entry" << dendl;
          return -EIO;
        }
        ldout(cct, 5) << __func__ << " WARNING: need check namespace state parent_oid "
                       << parent_oid
                       << " obj_name " << file_ent.obj_name
                       << " exist " << file_ent.exist()
                       << " pending_map.empty() " << file_ent.pending_map.empty() << dendl;

        // need check this entry
        librados::IoCtx sub_ctx;
        sub_ctx.dup(io_ctx);
        r = check_bucket_namespace_file_state(sub_ctx, bucket_info, child_name, file_ent,
                                              suggested_updates);
        if (r == -ENOENT) {
          continue;
        } else if (r < 0) {
          return r;
        }
      }

      ldout(cct, 25) << __func__ << " result file: " << child_name << " "
                     << file_ent.mtime() << " " << file_ent.size << dendl;

      struct rgw_bucket_dir_entry dirent;
      dirent.key = cls_rgw_obj_key(std::move(child_name));
      dirent.exists = file_ent.exist();
      dirent.meta.size = file_ent.size;
      dirent.meta.accounted_size = file_ent.size;
      dirent.meta.mtime = file_ent.mtime();
      dirent.meta.appendable = file_ent.is_appendable();
      objs->emplace_back(std::move(dirent));
    } else if (namespace_entry_is_dir(magic)) {
      rgw_bucket_namespace_dir dir_ent(magic);

      if (dir_ent.not_exist() || dir_ent.is_pending()) {
        try {
          decode(dir_ent, p);
        } catch (buffer::error& err) {
          ldout(cct, 0) << __func__ << " Error: failed decode dir entry" << dendl;
          return -EIO;
        }

        ldout(cct, 5) << __func__ << " WARNING: need check namespace dir state parent_oid "
                      << parent_oid << " dir_name " << child_name
                      << " exist " << dir_ent.exist()
                      << " pending_map.empty() " << dir_ent.pending_map.empty() << dendl;

        string dir_name = (level==0) ? child_name :
                          (parent_name + S3_PATH_DELIMITER + child_name);
        string dir_oid =  namespace_get_parent_oid(bucket_info.bucket.marker, dir_name,
                                                   level+1);
        // need check this entry
        r = check_bucket_namespace_dir_state(io_ctx, child_name, dir_oid, dir_ent,
                                             suggested_updates);
        if (r == -ENOENT) {
          continue;
        } else if (r < 0) {
          return r;
        }
      }

      common_prefixes->emplace(std::move(child_name), true);
    } else {
      ldout(cct, 0) << __func__ << " Error: got unexpected oid " << child_name
                    << " magic " << hex << magic << dendl;
      assert(0 == "unexpected oid");
    }

    ++ count;
  }

  utime_t after_process_reust = ceph_clock_now();
  perfcounter->tinc(l_rgw_list_reuslt_process_namespace_lat,
                    after_process_reust - cls_list_end);

  if (suggested_updates.length()) {
    ldout(cct, 30) << "out dump: ";
    suggested_updates.hexdump(*_dout);
    *_dout << dendl;

    ObjectWriteOperation o;
    cls_rgw_namespace_suggest_changes(o, suggested_updates);
    AioCompletion *c = librados::Rados::aio_create_completion(NULL, NULL, NULL);
    io_ctx.aio_operate(parent_oid, c, &o);
    c->release();
  }

  // get last entry
  const string* last_name = nullptr;
  if (!objs->empty()) {
    last_name = &(objs->rbegin()->key.name);
  }

  if (!common_prefixes->empty()) {
    const string* last_dir = &(common_prefixes->rbegin()->first);
    if (last_name == nullptr || (*last_name) < (*last_dir)) {
      last_name = last_dir;
    }
  }

  if (last_name) {
    last_entry = (*last_name);
  }

  ldout(cct, 20) << __func__ << " parent_oid " << parent_oid
                << " parent_name" <<  parent_name
                << " marker " << marker
                << " end_marker " << end_marker
                << " max " << max
                << " count " << count
                << " is_truncated " << *is_truncated
                << dendl;

  return 0;
}

int RGWRados::cls_bucket_namespace_head_op(RGWBucketInfo& bucket_info,
                                           const string& parent_oid,
                                           const string& parent_name, size_t level,
                                           const string& child_name, uint64_t& obj_size,
                                           ceph::real_time& lastmod, bool& is_dir,
                                           bool& is_appendable)
{
  bufferlist suggested_updates;
  librados::IoCtx io_ctx;
  int r = open_bucket_index_ctx(bucket_info, io_ctx);
  if (r < 0) {
    return r;
  }

  bufferlist out;
  r = cls_rgw_namespace_head(io_ctx, parent_oid, child_name, out);
  if (r < 0) {
    return r;
  }

  bufferlist::iterator p = out.begin();
  uint64_t magic;

  try {
    decode(magic, p);
  } catch (buffer::error& err) {
    return -EIO;
  }

  if (namespace_entry_is_file(magic)) {
    rgw_bucket_namespace_file file_ent(magic);
    file_ent.decode_size(p);

    // need check this entry
    if (file_ent.not_exist() || file_ent.is_pending()) {
      try {
        decode(file_ent, p);
      } catch (buffer::error& err) {
        return -EIO;
      }

      ldout(cct, 5) << __func__ << " need check namespace state parent_oid "
                    << parent_oid << " obj_name " << file_ent.obj_name
                    << " exist " << file_ent.exist()
                    << " pending_map.empty() " << file_ent.pending_map.empty() << dendl;

      librados::IoCtx sub_ctx;
      sub_ctx.dup(io_ctx);
      r = check_bucket_namespace_file_state(sub_ctx, bucket_info, child_name, file_ent,
                                            suggested_updates);
      if (r < 0 && r != -ENOENT) {
        return r;
      }
    }

    if (r >= 0) {
      obj_size = file_ent.size;
      lastmod = file_ent.mtime();
      is_appendable = file_ent.is_appendable();
    }
    is_dir = false;
  } else if (namespace_entry_is_dir(magic)) {
    rgw_bucket_namespace_dir dir_ent(magic);

    if (dir_ent.not_exist() || dir_ent.is_pending()) {
      try {
        decode(dir_ent, p);
      } catch (buffer::error& err) {
        return -EIO;
      }

      ldout(cct, 5) << __func__ << " need check namespace dir state parent_oid "
                    << parent_oid << " dir_name " << child_name  << " exist "
                    << dir_ent.exist() << " pending_map.empty() "
                    << dir_ent.pending_map.empty() << dendl;

      string dir_name = (level==0) ? child_name :
                        (parent_name + S3_PATH_DELIMITER + child_name);
      string dir_oid = namespace_get_parent_oid(bucket_info.bucket.marker, dir_name, level);

      // need check this entry
      r = check_bucket_namespace_dir_state(io_ctx, child_name, dir_oid, dir_ent,
                                           suggested_updates);
      if (r < 0 && r != -ENOENT) {
        return r;
      }
    }

    if (r >= 0) {
      obj_size = 4096;
      lastmod = dir_ent.mtime();
    }

    is_dir = true;
  } else {
    ldout(cct, 0) << __func__ << " Error: got unexpected oid " << child_name << dendl;
    assert(0 == "unexpected oid");
  }

  // suggest to update this file
  if (suggested_updates.length()) {
    ObjectWriteOperation o;
    cls_rgw_namespace_suggest_changes(o, suggested_updates);
    AioCompletion *c = librados::Rados::aio_create_completion(NULL, NULL, NULL);
    io_ctx.aio_operate(parent_oid, c, &o);
    c->release();
  }

  return r;
}

int RGWRados::cls_obj_set_bucket_tag_timeout(RGWBucketInfo& bucket_info, uint64_t timeout)
{
  librados::IoCtx index_ctx;
  map<int, string> bucket_objs;
  int r = open_bucket_index(bucket_info, index_ctx, bucket_objs);
  if (r < 0)
    return r;

  return CLSRGWIssueSetTagTimeout(index_ctx, bucket_objs, cct->_conf->rgw_bucket_index_max_aio, timeout)();
}

uint32_t RGWRados::calc_ordered_bucket_list_per_shard(const uint32_t expansion_factor,
                                                      uint32_t num_entries,
                                                      uint32_t num_shards)
{
  uint32_t max_attempt_times = cct->_conf->rgw_list_max_attempt_times;
  if (max_attempt_times == 0 || expansion_factor > 11) {
    return num_entries;
  }
  // We want to minimize the chances that when num_shards >>
  // num_entries that we return much fewer than num_entries to the
  // client. Given all the overhead of making a cls call to the osd,
  // returning a few entries is not much more work than returning one
  // entry. This minimum might be better tuned based on future
  // experiments where num_shards >> num_entries. (Note: ">>" should
  // be interpreted as "much greater than".)
  constexpr uint32_t min_read = 8;

  // The following is based on _"Balls into Bins" -- A Simple and
  // Tight Analysis_ by Raab and Steger. We add 1 as a way to handle
  // cases when num_shards >> num_entries (it almost serves as a
  // ceiling calculation). We also assume alpha is 1.0 and extract it
  // from the calculation. Future work could involve memoizing some of
  // the transcendental functions to minimize repeatedly re-calling
  // them with the same parameters, which we expect to be the case the
  // majority of the time.
  uint32_t calc_read =
    1 +
    static_cast<uint32_t>((num_entries / num_shards) +
        sqrt((2 * num_entries) *
             log(num_shards) / num_shards));

  uint32_t max = std::max(min_read, calc_read);

  if (expansion_factor == 0) {
    return max;
  }
  // expansion_factor <= 11
  // we'll max out the exponential multiplication factor at 1024 (2<<10)
  return std::min(num_entries, (uint32_t(1 << (expansion_factor - 1)) * max));
}

int RGWRados::cls_bucket_list_ordered(RGWBucketInfo& bucket_info,
                                      int shard_id,
                                      rgw_obj_index_key& start,
                                      const string& prefix,
                                      uint32_t num_entries,
                                      bool list_versions,
                                      bool skip_ns,
                                      const uint32_t expansion_factor,
                                      ent_map_t& m,
                                      bool *is_truncated,
                                      rgw_obj_index_key *last_entry,
                                      bool (*force_check_filter)(const string& name))
{

  ldout(cct, 10) << __func__ << ": " << bucket_info.bucket
                 << " start_after=\"" << start
                 << "\", prefix=\"" << prefix
                 << "\", shard_id=" << shard_id
                 << "\", num_entries=" << num_entries
                 << ", list_versions=" << list_versions
                 << ", expansion_factor=" << expansion_factor
                 <<  ", force_check_filter is " << (force_check_filter ? "set" : "unset")
                 << dendl;

  /* expansion_factor allows the number of entries to read to grow
   * exponentially; this is used when earlier reads are producing too
   * few results, perhaps due to filtering or to a series of
   * namespaced entries */

  m.clear();

  librados::IoCtx index_ctx;
  // key   - oid (for different shards if there is any)
  // value - list result for the corresponding oid (shard), it is filled by
  //         the AIO callback
  map<int, string> oids;
  map<int, struct rgw_cls_list_ret> list_results;
  int r = open_bucket_index(bucket_info, index_ctx, oids, shard_id);
  if (r < 0) {
    ldout(cct, 0) << __func__ << ": open_bucket_index for " << bucket_info.bucket << " failed" << dendl;
    return r;
  }

  const uint32_t shard_count = oids.size();
  uint32_t num_entries_per_shard =
    calc_ordered_bucket_list_per_shard(expansion_factor, num_entries, shard_count);

  ldout(cct, 10) << __func__ << ": request from each of " << shard_count <<
    " shard(s) for " << num_entries_per_shard << " entries to get " <<
    num_entries << " total entries" << dendl;

  cls_rgw_obj_key start_key(start.name, start.instance);
  r = CLSRGWIssueBucketList(index_ctx, start_key, prefix, num_entries_per_shard,
                            list_versions, oids, list_results,
                            cct->_conf->rgw_bucket_index_max_aio, skip_ns)();
  if (r < 0) {
    ldout(cct, 0) << __func__ << ": CLSRGWIssueBucketList for " << bucket_info.bucket
                  << " failed:" << r << dendl;
    return r;
  }

  // Create a list of iterators that are used to iterate each shard
  vector<RGWRados::ent_map_t::iterator> vcurrents;
  vector<RGWRados::ent_map_t::iterator> vends;
  vector<string> vnames;
  vcurrents.reserve(list_results.size());
  vends.reserve(list_results.size());
  vnames.reserve(list_results.size());
  map<int, struct rgw_cls_list_ret>::iterator iter = list_results.begin();
  for (; iter != list_results.end(); ++iter) {
    vcurrents.push_back(iter->second.dir.m.begin());
    vends.push_back(iter->second.dir.m.end());
    vnames.push_back(oids[iter->first]);
  }

  // create a map to track the next candidate entry from each shard,
  // if the entry from a specified shard is selected/erased, the next
  // entry from that shard will be inserted for next round selection
  map<string, size_t> candidates;
  for (size_t i = 0; i < vcurrents.size(); ++i) {
    if (vcurrents[i] != vends[i]) {
      candidates[vcurrents[i]->first] = i;
    }
  }

  map<string, bufferlist> updates;
  uint32_t count = 0;
  while (count < num_entries && !candidates.empty()) {
    r = 0;
    // Select the next one
    int pos = candidates.begin()->second;
    const string& name = vcurrents[pos]->first;
    struct rgw_bucket_dir_entry& dirent = vcurrents[pos]->second;

    ldout(cct, 30) << __func__ << ": currently processing " << dirent.key
                   << " from shard " << pos << dendl;

    bool force_check = force_check_filter &&
        force_check_filter(dirent.key.name);
    if ((!dirent.exists && !dirent.is_delete_marker()) ||
        !dirent.pending_map.empty() ||
        force_check) {
      /* there are uncommitted ops. We need to check the current
       * state, and if the tags are old we need to do clean-up as
       * well. */
      librados::IoCtx sub_ctx;
      sub_ctx.dup(index_ctx);
      ldout(cct, 20) << "INFO: " << __func__ << " calling check_disk_state bucket="
                     << bucket_info.bucket << " entry=" << dirent.key
                     << dendl;
      r = check_disk_state(sub_ctx, bucket_info, dirent, dirent,
			   updates[vnames[pos]]);
      if (r < 0 && r != -ENOENT) {
        ldout(cct, 0) << __func__ << ": check_disk_state for \"" << dirent.key
                      << "\" failed with r=" << r << dendl;
        return r;
      }
    }
    if (r >= 0) {
      ldout(cct, 10) << __func__ << ": got " << dirent.key.name
                     << "[" << dirent.key.instance << "]" << dendl;
      m[name] = std::move(dirent);
      ++count;
    }

    // Refresh the candidates map
    candidates.erase(candidates.begin());
    ++vcurrents[pos];
    if (vcurrents[pos] != vends[pos]) {
      candidates[vcurrents[pos]->first] = pos;
    } else if (list_results[pos].is_truncated) {
      // once we exhaust one shard that is truncated, we need to stop,
      // as we cannot be certain that one of the next entries needs to
      // come from that shard; S3 and swift protocols allow returning
      // fewer than what was requested
      ldout(cct, 10) << __func__ << ": stopped accumulating results at count="
                     << count << ", dirent=\"" << dirent.key
                     << "\", because its shard is untruncated and exhaused"
                     << dendl;
      break;
    }
  } // while we haven't provided requested # of result entries

  // Suggest updates if there is any
  map<string, bufferlist>::iterator miter = updates.begin();
  for (; miter != updates.end(); ++miter) {
    if (miter->second.length()) {
      ldout(cct, 10) << "INFO: " << __func__ << ": doing dir_suggest on "
                     << miter->first << dendl;
      ObjectWriteOperation o;
      cls_rgw_suggest_changes(o, miter->second);
      // we don't care if we lose suggested updates, send them off blindly
      AioCompletion *c = librados::Rados::aio_create_completion(NULL, NULL, NULL);
      index_ctx.aio_operate(miter->first, c, &o);
      c->release();
    }
  } // updates loop

  *is_truncated = false;
  // check if all the returned entries are consumed or not
  for (size_t i = 0; i < vcurrents.size(); ++i) {
    if (vcurrents[i] != vends[i] || list_results[i].is_truncated) {
      *is_truncated = true;
      break;
    }
  }

  ldout(cct, 30) << __func__ << ": returning, count=" << count
                 << ", is_truncated=" << *is_truncated << dendl;

  if (*is_truncated && count < num_entries) {
    ldout(cct, 10) << __func__ << ": requested " << num_entries
                   << " entries but returning " << count
                   << ", which is truncated" << dendl;
  }

  if (!m.empty()) {
    *last_entry = m.rbegin()->first;
  }

  return 0;
}

int RGWRados::cls_bucket_list_unordered(
                RGWBucketInfo& bucket_info,
                int shard_id,
                rgw_obj_index_key& start,
                const string& prefix,
                uint32_t num_entries,
                bool list_versions,
                std::vector<rgw_bucket_dir_entry>& ent_list,
                bool *is_truncated,
                rgw_obj_index_key *last_entry,
                int &last_shard_id,
                bool (*force_check_filter)(const string& name),
                bool self_shard) {
  ldout(cct, 10) << "cls_bucket_list_unordered " << bucket_info.bucket 
                 << " start " << start.name << "[" << start.instance
                 << "] num_entries " << num_entries
                 << " shard_id:" << shard_id << dendl;

  static MultipartMetaFilter multipart_meta_filter;
  *is_truncated = false;
  librados::IoCtx index_ctx;

  map<int, string> oids;
  int r = open_bucket_index(bucket_info, index_ctx, oids, shard_id);
  if (r < 0)
    return r;
  const uint32_t num_shards = oids.size();

  rgw_obj_index_key marker = start;
  uint32_t current_shard;
  if (shard_id >= 0) {
    current_shard = shard_id;
  } else if (start.empty()) {
    current_shard = 0u;
  } else {
    // at this point we have a marker (start) that has something in
    // it, so we need to get to the bucket shard index, so we can
    // start reading from there

    std::string key;
    // test whether object name is a multipart meta name
    if(!multipart_meta_filter.filter(start.name, key)) {
      // if multipart_meta_filter fails, must be "regular" (i.e.,
      // unadorned) and the name is the key
      key = start.name;
    }

    // now convert the key (oid) to an rgw_obj_key since that will
    // separate out the namespace, name, and instance
    rgw_obj_key obj_key;
    bool parsed = rgw_obj_key::parse_raw_oid(key, &obj_key);
    if (!parsed) {
      ldout(cct, 0) << "ERROR: RGWRados::cls_bucket_list_unordered received an invalid "
          "start marker: '" << start << "'" << dendl;
      return -EINVAL;
    } else if (obj_key.name.empty()) {
      // if the name is empty that means the object name came in with
      // a namespace only, and therefore we need to start our scan at
      // the first bucket index shard
      current_shard = 0u;
    } else {
      // so now we have the key used to compute the bucket index shard
      // and can extract the specific shard from it
      current_shard = rgw_bucket_shard_index(obj_key.name, num_shards);
    }
  }

  last_shard_id = current_shard;
  uint32_t count = 0u;
  map<string, bufferlist> updates;
  rgw_obj_index_key last_added_entry;
  while (count <= num_entries &&
         ((shard_id >= 0 && current_shard == uint32_t(shard_id)) ||
           current_shard < num_shards)) {
    const std::string& oid = oids[current_shard];
    rgw_cls_list_ret result;

    ldout(cct, 25) << __func__ << " current_shard=" << current_shard
                   << " prefix=" << prefix
                   << " marker=" << marker.name << "[" << marker.instance << "]"
                   << " count " << count << " num_entries " << num_entries
                   << dendl;

    uint32_t last_count = count;
    librados::ObjectReadOperation op;
    cls_rgw_bucket_list_op(op, marker, prefix, num_entries,
                           list_versions, false, &result);
    r = index_ctx.operate(oid, &op, nullptr);
    if (r < 0) {
      ldout(cct, 10) << __func__ << "list bucket return err:" << r
                     << " oid:" << oid
                     << dendl;
      return r;
    }

    for (auto& entry : result.dir.m) {
      rgw_bucket_dir_entry& dirent = entry.second;

      bool force_check = force_check_filter &&
                         force_check_filter(dirent.key.name);
      if ((!dirent.exists && !dirent.is_delete_marker()) ||
          !dirent.pending_map.empty() ||
          force_check) {
        /* there are uncommitted ops. We need to check the current state,
         * and if the tags are old we need to do cleanup as well. */
        librados::IoCtx sub_ctx;
        sub_ctx.dup(index_ctx);
        r = check_disk_state(sub_ctx, bucket_info, dirent, dirent, updates[oid]);
        if (r < 0 && r != -ENOENT) {
          ldout(cct, 10) << __func__ << "check disk state err:" << r
                         << ", obj:" << dirent.key.name << dendl;
          return r;
        }
      }

      // at this point either r >=0 or r == -ENOENT
      if (r >= 0) { // i.e., if r != -ENOENT
        ldout(cct, 10) << "RGWRados::cls_bucket_list_unordered: got "
                       << dirent.key.name << "["
                       << dirent.key.instance << "]" << dendl;

        if (count < num_entries) {
          ent_list.emplace_back(std::move(dirent));
          ++count;
        } else {
          *is_truncated = true;
          if (count > last_count) {
            last_added_entry = ent_list.back().key;
          }
          goto check_updates;
        }
      } else { // r == -ENOENT
        // in the case of -ENOENT, make sure we're advancing marker
        // for possible next call to CLSRGWIssueBucketList
        marker = dirent.key;
      }
    } // entry for loop

    ldout(cct, 20) << "cls_bucket_list_unordered list 1000 over. oid:" << oid
                   << ", truncated:" << result.is_truncated
                   << ", self_shard:" << self_shard
                   << dendl;
    if (!result.is_truncated) {
      if (self_shard) {
        ldout(cct, 20) << "cls_bucket_list_unordered over, break. oid:" << oid << dendl;
        break;
      }
      // if we reached the end of the shard read next shard
      ++current_shard;
      last_shard_id = current_shard;
      last_added_entry = marker = rgw_obj_index_key();
    } else { // truncated
      // start new loop in this shard
      if (count > last_count) {
        last_added_entry = ent_list.back().key;
      }
      if (r >= 0) {
        marker = ent_list.back().key;
      }
    }
  } // shard loop

check_updates:
  // suggest updates if there is any
  map<string, bufferlist>::iterator miter = updates.begin();
  for (; miter != updates.end(); ++miter) {
    if (miter->second.length()) {
      ObjectWriteOperation o;
      cls_rgw_suggest_changes(o, miter->second);
      // we don't care if we lose suggested updates, send them off blindly
      AioCompletion *c = librados::Rados::aio_create_completion(NULL, NULL, NULL);
      index_ctx.aio_operate(miter->first, c, &o);
      c->release();
    }
  }

  if (last_entry && !ent_list.empty()) {
    *last_entry = last_added_entry;
    ldout(cct, 25) << " last entry " << last_added_entry
                   << " name " << last_added_entry.name << "[" << last_added_entry.instance << "]"
                   << " shard " << current_shard
                   << dendl;
  }

  return 0;
}


int RGWRados::cls_obj_usage_log_add(const string& oid,
				    rgw_usage_log_info& info)
{
  rgw_raw_obj obj(get_zone_params().usage_log_pool, oid);

  rgw_rados_ref ref;
  int r = get_raw_obj_ref(obj, &ref);
  if (r < 0) {
    return r;
  }

  ObjectWriteOperation op;
  cls_rgw_usage_log_add(op, info);

  r = ref.ioctx.operate(ref.oid, &op);
  return r;
}

int RGWRados::cls_obj_usage_log_read(string& oid, string& user, uint64_t start_epoch, uint64_t end_epoch, uint32_t max_entries,
                                     string& read_iter, map<rgw_user_bucket, rgw_usage_log_entry>& usage, bool *is_truncated)
{
  rgw_raw_obj obj(get_zone_params().usage_log_pool, oid);

  rgw_rados_ref ref;
  int r = get_raw_obj_ref(obj, &ref);
  if (r < 0) {
    return r;
  }

  *is_truncated = false;

  r = cls_rgw_usage_log_read(ref.ioctx, ref.oid, user, start_epoch, end_epoch,
			     max_entries, read_iter, usage, is_truncated);

  return r;
}

int RGWRados::cls_obj_usage_log_read_total(string& oid, string& user, uint32_t max_entries, string& read_iter,
                                           map<rgw_user_bucket, rgw_usage_log_entry>& usage, bool *is_truncated)
{
  rgw_raw_obj obj(get_zone_params().usage_log_pool, oid);

  rgw_rados_ref ref;
  int r = get_raw_obj_ref(obj, &ref);
  if (r < 0) {
    return r;
  }

  *is_truncated = false;

  r = cls_rgw_usage_log_read_total(ref.ioctx, ref.oid, user, max_entries, read_iter, usage, is_truncated);

  return r;
}

int RGWRados::cls_obj_usage_log_read_current_readop(string& oid, string& user, uint64_t end_epoch, map<rgw_user_bucket, rgw_usage_log_entry>& usage)
{
  rgw_raw_obj obj(get_zone_params().usage_log_pool, oid);

  rgw_rados_ref ref;
  int r = get_raw_obj_ref(obj, &ref);
  if (r < 0) {
    return r;
  }

  r = cls_rgw_usage_log_read_current_readop(ref.ioctx, ref.oid, user, end_epoch, usage);

  return r;
}

int RGWRados::cls_obj_usage_log_read_readop(string& oid, string& user, uint64_t start_epoch, uint64_t end_epoch, uint32_t max_entries,
                                     string& read_iter, map<rgw_user_bucket, vector<rgw_usage_log_entry> >& usage, bool *is_truncated)
{
  rgw_raw_obj obj(get_zone_params().usage_log_pool, oid);

  rgw_rados_ref ref;
  int r = get_raw_obj_ref(obj, &ref);
  if (r < 0) {
    return r;
  }

  *is_truncated = false;

  r = cls_rgw_usage_log_read_readop(ref.ioctx, ref.oid, user, start_epoch, end_epoch, max_entries,
                                 read_iter, usage, is_truncated);

  return r;
}

int RGWRados::cls_obj_usage_log_trim(string& oid, string& user, uint64_t start_epoch, uint64_t end_epoch)
{
  rgw_raw_obj obj(get_zone_params().usage_log_pool, oid);

  rgw_rados_ref ref;
  int r = get_raw_obj_ref(obj, &ref);
  if (r < 0) {
    return r;
  }

  r = cls_rgw_usage_log_trim(ref.ioctx, ref.oid, user, start_epoch, end_epoch);
  return r;
}

int RGWRados::cls_obj_usage_log_trim_total(string& oid, string& user, string& bucket)
{
  rgw_raw_obj obj(get_zone_params().usage_log_pool, oid);

  rgw_rados_ref ref;
  int r = get_raw_obj_ref(obj, &ref);
    if (r < 0) {
    return r;
  }

  r = cls_rgw_usage_log_trim_total(ref.ioctx, ref.oid, user, bucket);
  return r;
}

int RGWRados::cls_obj_usage_log_trim_readop(string& oid, string& user, uint64_t start_epoch, uint64_t end_epoch)
{
  rgw_raw_obj obj(get_zone_params().usage_log_pool, oid);

  rgw_rados_ref ref;
  int r = get_raw_obj_ref(obj, &ref);
  if (r < 0) {
    return r;
  }

  r = cls_rgw_usage_log_trim_readop(ref.ioctx, ref.oid, user, start_epoch, end_epoch);
  return r;
}

int RGWRados::cls_obj_usage_log_clear(string& oid)
{
  rgw_raw_obj obj(get_zone_params().usage_log_pool, oid);

  rgw_rados_ref ref;
  int r = get_raw_obj_ref(obj, &ref);
  if (r < 0) {
    return r;
  }
  librados::ObjectWriteOperation op;
  cls_rgw_usage_log_clear(op);
  r = ref.ioctx.operate(ref.oid, &op);
  return r;
}


int RGWRados::remove_objs_from_index(RGWBucketInfo& bucket_info, list<rgw_obj_index_key>& oid_list)
{
  librados::IoCtx index_ctx;
  string dir_oid;

  uint8_t suggest_flag = (get_zone().log_data ? CEPH_RGW_DIR_SUGGEST_LOG_OP : 0);

  int r = open_bucket_index(bucket_info, index_ctx, dir_oid);
  if (r < 0)
    return r;

  bufferlist updates;

  for (auto iter = oid_list.begin(); iter != oid_list.end(); ++iter) {
    rgw_bucket_dir_entry entry;
    entry.key = *iter;
    dout(2) << "RGWRados::remove_objs_from_index bucket=" << bucket_info.bucket << " obj=" << entry.key.name << ":" << entry.key.instance << dendl;
    entry.ver.epoch = (uint64_t)-1; // ULLONG_MAX, needed to that objclass doesn't skip out request
    updates.append(CEPH_RGW_REMOVE | suggest_flag);
    encode(entry, updates);
  }

  bufferlist out;

  r = index_ctx.exec(dir_oid, RGW_CLASS, RGW_DIR_SUGGEST_CHANGES, updates, out);

  return r;
}

int RGWRados::check_disk_state(librados::IoCtx io_ctx,
                               const RGWBucketInfo& bucket_info,
                               rgw_bucket_dir_entry& list_state,
                               rgw_bucket_dir_entry& object,
                               bufferlist& suggested_updates)
{
  const rgw_bucket& bucket = bucket_info.bucket;
  uint8_t suggest_flag = (get_zone().log_data ? CEPH_RGW_DIR_SUGGEST_LOG_OP : 0);

  std::string loc;

  rgw_obj obj(bucket, list_state.key);

  string oid;
  get_obj_bucket_and_oid_loc(obj, oid, loc);

  if (loc != list_state.locator) {
    ldout(cct, 0) << "WARNING: generated locator (" << loc << ") is different from listed locator (" << list_state.locator << ")" << dendl;
  }

  io_ctx.locator_set_key(list_state.locator);

  RGWObjState *astate = NULL;
  RGWObjectCtx rctx(this);
  int r = get_obj_state(&rctx, bucket_info, obj, &astate, false);
  if (r < 0 && r != -ENAMETOOLONG)
    return r;
  ldout(cct, 10) << __func__ << " astate addr:" << astate << dendl;

  list_state.pending_map.clear(); // we don't need this and it inflates size
  bool need_remove = false;
  map<string, bufferlist>::iterator iter = astate->attrset.find(RGW_ATTR_DELETED);
  if (iter != astate->attrset.end()) {
   if (iter->second.to_str().compare("true") == 0) {
     need_remove = true;
   }
  }

  if (!astate->exists || need_remove) {
      /* object doesn't exist right now -- hopefully because it's
       * marked as !exists and got deleted */
    if (list_state.exists) {
      /* FIXME: what should happen now? Work out if there are any
       * non-bad ways this could happen (there probably are, but annoying
       * to handle!) */
      ldout(cct, 10) << "INFO: " << __func__ << ": index list state exists without head obj="
                     << obj << dendl;
    }
    // encode a suggested removal of that key
    list_state.ver.epoch = io_ctx.get_last_version();
    list_state.ver.pool = io_ctx.get_id();
    cls_rgw_encode_suggestion(CEPH_RGW_REMOVE, list_state, suggested_updates);
    return -ENOENT;
  }

  string etag;
  string content_type;
  ACLOwner owner;
  string storage_class;

  object.meta.size = astate->size;
  object.meta.accounted_size = astate->accounted_size;
  object.meta.mtime = astate->mtime;

  iter = astate->attrset.find(RGW_ATTR_ETAG);
  if (iter != astate->attrset.end()) {
    etag = rgw_bl_to_str(iter->second);
  }
  iter = astate->attrset.find(RGW_ATTR_CONTENT_TYPE);
  if (iter != astate->attrset.end()) {
    content_type = rgw_bl_to_str(iter->second);
  }
  iter = astate->attrset.find(RGW_ATTR_ACL);
  if (iter != astate->attrset.end()) {
    r = decode_policy(iter->second, &owner);
    if (r < 0) {
      dout(0) << "WARNING: could not decode policy for object: " << obj <<", astate addr:" << astate << ",acl bl:" << iter->second << dendl;
    }
  }
  iter = astate->attrset.find(RGW_ATTR_STORAGE_CLASS);
  if (iter != astate->attrset.end()) {
    storage_class = iter->second.to_str();
  }

  iter = astate->attrset.find(RGW_ATTR_TAGS);
  if (iter != astate->attrset.end() && iter->second.length() > 0) {
    list_state.meta.tags_bl = iter->second;
  }

  if (astate->has_manifest) {
    RGWObjManifest::obj_iterator miter;
    RGWObjManifest& manifest = astate->manifest;
    for (miter = manifest.obj_begin(); miter != manifest.obj_end(); ++miter) {
      const rgw_raw_obj& raw_loc = miter.get_location().get_raw_obj(this);
      rgw_obj loc;
      rgw_raw_obj_to_obj(manifest.get_obj().bucket, raw_loc, &loc);

      if (loc.key.ns == RGW_OBJ_NS_MULTIPART) {
        dout(10) << "check_disk_state(): removing manifest part from index: " << loc << dendl;
        r = delete_obj_index(loc);
        if (r < 0) {
          dout(0) << "WARNING: delete_obj_index() returned r=" << r << dendl;
        }
      }
    }
  }

  object.meta.etag = etag;
  object.meta.content_type = content_type;
  object.meta.owner = owner.get_id().to_str();
  object.meta.owner_display_name = owner.get_display_name();

  // now convert the key (oid) to an rgw_obj_key since that will
  // separate out the namespace, name, and instance
  rgw_obj_key obj_key;
  bool parsed = rgw_obj_key::parse_raw_oid(list_state.key.name, &obj_key);
  if (!parsed) {
    ldout(cct, 0) << __func__ << "() ERROR: received an error idx:" << list_state.key << dendl;
    return 0;
  }
  if (obj_key.ns == RGW_OBJ_NS_MULTIPART) {
    list_state.meta.accounted_entry = false;
  }

  // encode suggested updates
  list_state.ver.pool = io_ctx.get_id();
  list_state.ver.epoch = astate->epoch;
  list_state.meta.size = object.meta.size;
  list_state.meta.accounted_size = object.meta.accounted_size;
  list_state.meta.mtime = object.meta.mtime;
  list_state.meta.category = main_category;
  list_state.meta.etag = etag;
  list_state.meta.content_type = content_type;
  if (astate->obj_tag.length() > 0)
    list_state.tag = astate->obj_tag.c_str();
  list_state.meta.owner = owner.get_id().to_str();
  list_state.meta.owner_display_name = owner.get_display_name();
  if (!storage_class.empty()) {
    list_state.meta.storage_class = storage_class;
  }

  list_state.exists = true;
  ldout(cct, 5) << "check_disk_state(): suggest update index of object:" << obj << dendl;
  cls_rgw_encode_suggestion(CEPH_RGW_UPDATE | suggest_flag, list_state, suggested_updates);
  return 0;
}

int RGWRados::check_bucket_namespace_file_state(librados::IoCtx io_ctx,
                                                const RGWBucketInfo& bucket_info,
                                                const string& child_name,
                                                rgw_bucket_namespace_file& list_state,
                                                bufferlist& suggested_updates)
{
  const rgw_bucket& bucket = bucket_info.bucket;
  rgw_obj obj(bucket, list_state.obj_name);
  string oid;
  std::string loc;

  get_obj_bucket_and_oid_loc(obj, oid, loc);
  io_ctx.locator_set_key(loc);

  RGWObjState *astate = NULL;
  RGWObjectCtx rctx(this);
  int r = get_obj_state(&rctx, bucket_info, obj, &astate, false);
  if (r < 0)
    return r;

  list_state.pending_map.clear(); // we don't need this and it inflates size
  list_state.clear_pending();
  bool need_remove = false;
  map<string, bufferlist>::iterator iter = astate->attrset.find(RGW_ATTR_DELETED);
  if (iter != astate->attrset.end()) {
   if (iter->second.to_str().compare("true") == 0) {
     need_remove = true;
   }
  }

  if (!astate->exists || need_remove) {
    // encode a suggested removal of that key
    ldout(cct, 5) << __func__ << " suggest remove namespace of object:" << obj
                  << " poolid=" << list_state.ver.pool
                  << " epoch=" << list_state.ver.epoch << dendl;
    cls_rgw_namespace_encode_suggestion(CEPH_RGW_REMOVE, child_name, list_state, suggested_updates);
    return -ENOENT;
  }

  // is appendable?
  auto a_iter = astate->attrset.find(RGW_ATTR_TARGET_SIZE);
  if (a_iter != astate->attrset.end()) {
    list_state.set_appendable(true);
  } else {
    list_state.set_appendable(false);
  }
  // encode suggested updates
  list_state.ver.epoch = astate->epoch;
  list_state.size = astate->size;
  list_state.set_mtime(astate->mtime);
  list_state.set_exist();

  ldout(cct, 5) << __func__ << " suggest update namespace of object:" << obj
                << " poolid=" << list_state.ver.pool
                << " epoch=" << list_state.ver.epoch << dendl;

  cls_rgw_namespace_encode_suggestion(CEPH_RGW_UPDATE, child_name, list_state, suggested_updates);
  return 0;
}

int RGWRados::check_bucket_namespace_dir_state(librados::IoCtx io_ctx,
                                               const string& child_name,
                                               const string& dir_oid,
                                               rgw_bucket_namespace_dir& dir_ent,
                                               bufferlist& suggested_updates)
{
  // we don't need this and it inflates size
  dir_ent.pending_map.clear();
  dir_ent.clear_pending();

  int r =  io_ctx.stat(dir_oid, NULL, NULL);
  if (r < 0 && r != -ENOENT) {
    ldout(cct, 0) << __func__ << " ERROR: failed stat dir_oid " << dir_oid
                  << " ret=" << r << dendl;
    return r;
  }

  if (r == -ENOENT) {
    // encode a suggested removal of that key
    cls_rgw_namespace_encode_suggestion(CEPH_RGW_REMOVE, child_name, dir_ent, suggested_updates);
    ldout(cct, 5) << __func__ << " suggest remove namespace of object:" << dir_oid
                  << " " << child_name << " epoch=" << dir_ent.ver.epoch << dendl;
    return -ENOENT;
  }

  // encode suggested updates
  dir_ent.ver.pool = io_ctx.get_id();
  dir_ent.ver.epoch = io_ctx.get_last_version();
  dir_ent.set_exist();
  ldout(cct, 5) << __func__ << " suggest update namespace of object:" << dir_oid 
                << " " << child_name << " epoch=" << dir_ent.ver.epoch << dendl;
  cls_rgw_namespace_encode_suggestion(CEPH_RGW_UPDATE, child_name, dir_ent, suggested_updates);
  return 0;
}

int RGWRados::cls_bucket_head(const RGWBucketInfo& bucket_info, int shard_id, vector<rgw_bucket_dir_header>& headers, map<int, string> *bucket_instance_ids)
{
  librados::IoCtx index_ctx;
  map<int, string> oids;
  map<int, struct rgw_cls_list_ret> list_results;
  int r = open_bucket_index(bucket_info, index_ctx, oids, list_results, shard_id, bucket_instance_ids);
  if (r < 0)
    return r;

  r = CLSRGWIssueGetDirHeader(index_ctx, oids, list_results, cct->_conf->rgw_bucket_index_max_aio)();
  if (r < 0)
    return r;

  map<int, struct rgw_cls_list_ret>::iterator iter = list_results.begin();
  for(; iter != list_results.end(); ++iter) {
    headers.push_back(std::move(iter->second.dir.header));
  }
  return 0;
}

int RGWRados::cls_bucket_head_async(const RGWBucketInfo& bucket_info, int shard_id, RGWGetDirHeader_CB *ctx, int *num_aio)
{
  librados::IoCtx index_ctx;
  map<int, string> bucket_objs;
  int r = open_bucket_index(bucket_info, index_ctx, bucket_objs, shard_id);
  if (r < 0)
    return r;

  map<int, string>::iterator iter = bucket_objs.begin();
  for (; iter != bucket_objs.end(); ++iter) {
    r = cls_rgw_get_dir_header_async(index_ctx, iter->second, static_cast<RGWGetDirHeader_CB*>(ctx->get()));
    if (r < 0) {
      ctx->put();
      break;
    } else {
      (*num_aio)++;
    }
  }
  return r;
}

int RGWRados::cls_user_get_header(const string& user_id, cls_user_header *header)
{
  string buckets_obj_id;
  rgw_get_buckets_obj(user_id, buckets_obj_id);
  rgw_raw_obj obj(get_zone_params().user_uid_pool, buckets_obj_id);

  rgw_rados_ref ref;
  int r = get_raw_obj_ref(obj, &ref);
  if (r < 0) {
    return r;
  }

  librados::ObjectReadOperation op;
  int rc;
  ::cls_user_get_header(op, header, &rc);
  bufferlist ibl;
  r = ref.ioctx.operate(ref.oid, &op, &ibl);
  if (r < 0)
    return r;
  if (rc < 0)
    return rc;

  return 0;
}

int RGWRados::cls_user_reset_stats(const string& user_id)
{
  string buckets_obj_id;
  rgw_get_buckets_obj(user_id, buckets_obj_id);
  rgw_raw_obj obj(get_zone_params().user_uid_pool, buckets_obj_id);

  rgw_rados_ref ref;
  int r = get_raw_obj_ref(obj, &ref);
  if (r < 0) {
    return r;
  }

  librados::ObjectWriteOperation op;
  ::cls_user_reset_stats(op);
  return ref.ioctx.operate(ref.oid, &op);
}

int RGWRados::cls_user_get_header_async(const string& user_id, RGWGetUserHeader_CB *ctx)
{
  string buckets_obj_id;
  rgw_get_buckets_obj(user_id, buckets_obj_id);
  rgw_raw_obj obj(get_zone_params().user_uid_pool, buckets_obj_id);

  rgw_rados_ref ref;
  int r = get_raw_obj_ref(obj, &ref);
  if (r < 0) {
    return r;
  }

  r = ::cls_user_get_header_async(ref.ioctx, ref.oid, ctx);
  if (r < 0)
    return r;

  return 0;
}

int RGWRados::cls_user_sync_bucket_stats(rgw_raw_obj& user_obj, const RGWBucketInfo& bucket_info)
{
  vector<rgw_bucket_dir_header> headers;
  int r = cls_bucket_head(bucket_info, RGW_NO_SHARD, headers);
  if (r < 0) {
    ldout(cct, 20) << "cls_bucket_header() returned " << r << dendl;
    return r;
  }

  cls_user_bucket_entry entry;

  bucket_info.bucket.convert(&entry.bucket);

  for (const auto& hiter : headers) {
    for (const auto& iter : hiter.stats) {
      const struct rgw_bucket_category_stats& header_stats = iter.second;
      entry.size += header_stats.total_size;
      entry.size_rounded += header_stats.total_size_rounded;
      entry.count += header_stats.num_entries;
    }
  }

  list<cls_user_bucket_entry> entries;
  entries.push_back(entry);

  r = cls_user_update_buckets(user_obj, entries, false);
  if (r < 0) {
    ldout(cct, 20) << "cls_user_update_buckets() returned " << r << dendl;
    return r;
  }

  return 0;
}

int RGWRados::cls_user_get_bucket_stats(const rgw_bucket& bucket, cls_user_bucket_entry& entry)
{
  vector<rgw_bucket_dir_header> headers;
  RGWBucketInfo bucket_info;
  RGWObjectCtx obj_ctx(this);
  int ret = get_bucket_instance_info(obj_ctx, bucket, bucket_info, NULL, NULL);
  if (ret < 0) {
    return ret;
  }

  ret = cls_bucket_head(bucket_info, RGW_NO_SHARD, headers);
  if (ret < 0) {
    ldout(cct, 20) << "cls_bucket_header() returned " << ret << dendl;
    return ret;
  }

  bucket.convert(&entry.bucket);

  for (const auto& hiter : headers) {
    for (const auto& iter : hiter.stats) {
      const struct rgw_bucket_category_stats& header_stats = iter.second;
      entry.size += header_stats.total_size;
      entry.size_rounded += header_stats.total_size_rounded;
      entry.count += header_stats.num_entries;
    }
  }

  return 0;
}

int RGWRados::cls_user_list_buckets(rgw_raw_obj& obj,
                                    const string& in_marker,
                                    const string& end_marker,
                                    const int max_entries,
                                    list<cls_user_bucket_entry>& entries,
                                    string * const out_marker,
                                    bool * const truncated)
{
  rgw_rados_ref ref;
  int r = get_raw_obj_ref(obj, &ref);
  if (r < 0) {
    return r;
  }

  librados::ObjectReadOperation op;
  int rc;

  cls_user_bucket_list(op, in_marker, end_marker, max_entries, entries, out_marker, truncated, &rc);
  bufferlist ibl;
  r = ref.ioctx.operate(ref.oid, &op, &ibl);
  if (r < 0)
    return r;
  if (rc < 0)
    return rc;

  return 0;
}

int RGWRados::cls_user_update_buckets(rgw_raw_obj& obj, list<cls_user_bucket_entry>& entries, bool add)
{
  rgw_rados_ref ref;
  int r = get_raw_obj_ref(obj, &ref);
  if (r < 0) {
    return r;
  }

  librados::ObjectWriteOperation op;
  cls_user_set_buckets(op, entries, add);
  r = ref.ioctx.operate(ref.oid, &op);
  if (r < 0)
    return r;

  return 0;
}

int RGWRados::complete_sync_user_stats(const rgw_user& user_id)
{
  string buckets_obj_id;
  rgw_get_buckets_obj(user_id, buckets_obj_id);
  rgw_raw_obj obj(get_zone_params().user_uid_pool, buckets_obj_id);
  return cls_user_complete_stats_sync(obj);
}

int RGWRados::cls_user_complete_stats_sync(rgw_raw_obj& obj)
{
  rgw_rados_ref ref;
  int r = get_raw_obj_ref(obj, &ref);
  if (r < 0) {
    return r;
  }

  librados::ObjectWriteOperation op;
  ::cls_user_complete_stats_sync(op);
  r = ref.ioctx.operate(ref.oid, &op);
  if (r < 0)
    return r;

  return 0;
}

int RGWRados::cls_user_add_bucket(rgw_raw_obj& obj, const cls_user_bucket_entry& entry)
{
  list<cls_user_bucket_entry> l;
  l.push_back(entry);

  return cls_user_update_buckets(obj, l, true);
}

int RGWRados::cls_user_remove_bucket(rgw_raw_obj& obj, const cls_user_bucket& bucket)
{
  rgw_rados_ref ref;
  int r = get_system_obj_ref(obj, &ref);
  if (r < 0) {
    return r;
  }

  librados::ObjectWriteOperation op;
  ::cls_user_remove_bucket(op, bucket);
  r = ref.ioctx.operate(ref.oid, &op);
  if (r < 0)
    return r;

  return 0;
}

int RGWRados::check_bucket_shards(const RGWBucketInfo& bucket_info, const rgw_bucket& bucket,
				  RGWQuotaInfo& bucket_quota)
{
  if (!cct->_conf->rgw_dynamic_resharding) {
      return 0;
  }

  bool need_resharding = false;
  int num_source_shards = (bucket_info.num_shards > 0 ? bucket_info.num_shards : 1);
  uint32_t suggested_num_shards;

  int ret =  quota_handler->check_bucket_shards((uint64_t)cct->_conf->rgw_max_objs_per_shard,
						num_source_shards,  bucket_info.owner, bucket, bucket_quota,
						1, need_resharding, &suggested_num_shards);
  if (ret < 0) {
    return ret;
  }

  if (need_resharding) {
    ldout(cct, 20) << __func__ << " bucket " << bucket.name << " need resharding " <<
      " old num shards " << bucket_info.num_shards << " new num shards " << suggested_num_shards <<
      dendl;
    return add_bucket_to_reshard(bucket_info, suggested_num_shards);
  }

  return ret;
}

int RGWRados::add_bucket_to_reshard(const RGWBucketInfo& bucket_info, uint32_t new_num_shards)
{
  RGWReshard reshard(this);

  uint32_t num_source_shards = (bucket_info.num_shards > 0 ? bucket_info.num_shards : 1);

  new_num_shards = std::min(new_num_shards, get_max_bucket_shards());
  if (new_num_shards <= num_source_shards) {
    ldout(cct, 20) << "not resharding bucket name=" << bucket_info.bucket.name << ", orig_num=" << num_source_shards << ", new_num_shards=" << new_num_shards << dendl;
    return 0;
  }

  cls_rgw_reshard_entry entry;
  entry.time = real_clock::now();
  entry.tenant = bucket_info.owner.tenant;
  entry.bucket_name = bucket_info.bucket.name;
  entry.bucket_id = bucket_info.bucket.bucket_id;
  entry.old_num_shards = num_source_shards;
  entry.new_num_shards = new_num_shards;

  return reshard.add(entry);
}

int RGWRados::check_quota(const rgw_user& bucket_owner, rgw_bucket& bucket,
                          RGWQuotaInfo& user_quota, RGWQuotaInfo& bucket_quota, uint64_t obj_size, bool check_size_only)
{
  if (check_size_only) {
    return quota_handler->check_quota(bucket_owner, bucket, user_quota, bucket_quota, 0, obj_size);
  }
  return quota_handler->check_quota(bucket_owner, bucket, user_quota, bucket_quota, 1, obj_size);
}

void RGWRados::get_bucket_index_objects(const string& bucket_oid_base,
					uint32_t num_shards,
					map<int, string>& bucket_objects,
					int shard_id) {
  if (!num_shards) {
    bucket_objects[0] = bucket_oid_base;
  } else {
    char buf[bucket_oid_base.size() + 32];
    if (shard_id < 0) {
      for (uint32_t i = 0; i < num_shards; ++i) {
        snprintf(buf, sizeof(buf), "%s.%d", bucket_oid_base.c_str(), i);
        bucket_objects[i] = buf;
      }
    } else {
      if ((uint32_t)shard_id > num_shards) {
        return;
      }
      snprintf(buf, sizeof(buf), "%s.%d", bucket_oid_base.c_str(), shard_id);
      bucket_objects[shard_id] = buf;
    }
  }
}

void RGWRados::get_bucket_instance_ids(const RGWBucketInfo& bucket_info, int shard_id, map<int, string> *result)
{
  const rgw_bucket& bucket = bucket_info.bucket;
  string plain_id = bucket.name + ":" + bucket.bucket_id;
  if (!bucket_info.num_shards) {
    (*result)[0] = plain_id;
  } else {
    char buf[16];
    if (shard_id < 0) {
      for (uint32_t i = 0; i < bucket_info.num_shards; ++i) {
        snprintf(buf, sizeof(buf), ":%d", i);
        (*result)[i] = plain_id + buf;
      }
    } else {
      if ((uint32_t)shard_id > bucket_info.num_shards) {
        return;
      }
      snprintf(buf, sizeof(buf), ":%d", shard_id);
      (*result)[shard_id] = plain_id + buf;
    }
  }
}

int RGWRados::get_target_shard_id(const RGWBucketInfo& bucket_info, const string& obj_key,
                                  int *shard_id)
{
  int r = 0;
  switch (bucket_info.bucket_index_shard_hash_type) {
    case RGWBucketInfo::MOD:
      if (!bucket_info.num_shards) {
        if (shard_id) {
          *shard_id = -1;
        }
      } else {
        uint32_t sid = rgw_bucket_shard_index(obj_key, bucket_info.num_shards);
        if (shard_id) {
          *shard_id = (int)sid;
        }
      }
      break;
    default:
      r = -ENOTSUP;
  }
  return r;
}

void RGWRados::get_bucket_index_object(const string& bucket_oid_base, uint32_t num_shards,
                                      int shard_id, string *bucket_obj)
{
  if (!num_shards) {
    // By default with no sharding, we use the bucket oid as itself
    (*bucket_obj) = bucket_oid_base;
  } else {
    char buf[bucket_oid_base.size() + 32];
    snprintf(buf, sizeof(buf), "%s.%d", bucket_oid_base.c_str(), shard_id);
    (*bucket_obj) = buf;
  }
}

int RGWRados::get_bucket_index_object(const string& bucket_oid_base, const string& obj_key,
    uint32_t num_shards, RGWBucketInfo::BIShardsHashType hash_type, string *bucket_obj, int *shard_id)
{
  int r = 0;
  switch (hash_type) {
    case RGWBucketInfo::MOD:
      if (!num_shards) {
        // By default with no sharding, we use the bucket oid as itself
        (*bucket_obj) = bucket_oid_base;
        if (shard_id) {
          *shard_id = -1;
        }
      } else {
        uint32_t sid = rgw_bucket_shard_index(obj_key, num_shards);
        char buf[bucket_oid_base.size() + 32];
        snprintf(buf, sizeof(buf), "%s.%d", bucket_oid_base.c_str(), sid);
        (*bucket_obj) = buf;
        if (shard_id) {
          *shard_id = (int)sid;
        }
      }
      break;
    default:
      r = -ENOTSUP;
  }
  return r;
}

void RGWStateLog::oid_str(int shard, string& oid) {
  oid = RGW_STATELOG_OBJ_PREFIX + module_name + ".";
  char buf[16];
  snprintf(buf, sizeof(buf), "%d", shard);
  oid += buf;
}

int RGWStateLog::get_shard_num(const string& object) {
  uint32_t val = ceph_str_hash_linux(object.c_str(), object.length());
  return val % num_shards;
}

string RGWStateLog::get_oid(const string& object) {
  int shard = get_shard_num(object);
  string oid;
  oid_str(shard, oid);
  return oid;
}

int RGWStateLog::open_ioctx(librados::IoCtx& ioctx) {
  rgw_pool pool;
  store->get_log_pool(pool);
  int r = rgw_init_ioctx(store->get_rados_handle(), pool, ioctx);
  if (r < 0) {
    lderr(store->ctx()) << "ERROR: could not open rados pool" << dendl;
    return r;
  }
  return 0;
}

int RGWStateLog::store_entry(const string& client_id, const string& op_id, const string& object,
                  uint32_t state, bufferlist *bl, uint32_t *check_state)
{
  if (client_id.empty() ||
      op_id.empty() ||
      object.empty()) {
    ldout(store->ctx(), 0) << "client_id / op_id / object is empty" << dendl;
  }

  librados::IoCtx ioctx;
  int r = open_ioctx(ioctx);
  if (r < 0)
    return r;

  string oid = get_oid(object);

  librados::ObjectWriteOperation op;
  if (check_state) {
    cls_statelog_check_state(op, client_id, op_id, object, *check_state);
  }
  utime_t ts = ceph_clock_now();
  bufferlist nobl;
  cls_statelog_add(op, client_id, op_id, object, ts, state, (bl ? *bl : nobl));
  r = ioctx.operate(oid, &op);
  if (r < 0) {
    return r;
  }

  return 0;
}

int RGWStateLog::remove_entry(const string& client_id, const string& op_id, const string& object)
{
  if (client_id.empty() ||
      op_id.empty() ||
      object.empty()) {
    ldout(store->ctx(), 0) << "client_id / op_id / object is empty" << dendl;
  }

  librados::IoCtx ioctx;
  int r = open_ioctx(ioctx);
  if (r < 0)
    return r;

  string oid = get_oid(object);

  librados::ObjectWriteOperation op;
  cls_statelog_remove_by_object(op, object, op_id);
  r = ioctx.operate(oid, &op);
  if (r < 0) {
    return r;
  }

  return 0;
}

void RGWStateLog::init_list_entries(const string& client_id, const string& op_id, const string& object,
                                    void **handle)
{
  list_state *state = new list_state;
  state->client_id = client_id;
  state->op_id = op_id;
  state->object = object;
  if (object.empty()) {
    state->cur_shard = 0;
    state->max_shard = num_shards - 1;
  } else {
    state->cur_shard = state->max_shard = get_shard_num(object);
  }
  *handle = (void *)state;
}

int RGWStateLog::list_entries(void *handle, int max_entries,
                              list<cls_statelog_entry>& entries,
                              bool *done)
{
  list_state *state = static_cast<list_state *>(handle);

  librados::IoCtx ioctx;
  int r = open_ioctx(ioctx);
  if (r < 0)
    return r;

  entries.clear();

  for (; state->cur_shard <= state->max_shard && max_entries > 0; ++state->cur_shard) {
    string oid;
    oid_str(state->cur_shard, oid);

    librados::ObjectReadOperation op;
    list<cls_statelog_entry> ents;
    bool truncated;
    cls_statelog_list(op, state->client_id, state->op_id, state->object, state->marker,
                      max_entries, ents, &state->marker, &truncated);
    bufferlist ibl;
    r = ioctx.operate(oid, &op, &ibl);
    if (r == -ENOENT) {
      truncated = false;
      r = 0;
    }
    if (r < 0) {
      ldout(store->ctx(), 0) << "cls_statelog_list returned " << r << dendl;
      return r;
    }

    if (!truncated) {
      state->marker.clear();
    }

    max_entries -= ents.size();

    entries.splice(entries.end(), ents);

    if (truncated)
      break;
  }

  *done = (state->cur_shard > state->max_shard);

  return 0;
}

void RGWStateLog::finish_list_entries(void *handle)
{
  list_state *state = static_cast<list_state *>(handle);
  delete state;
}

void RGWStateLog::dump_entry(const cls_statelog_entry& entry, Formatter *f)
{
  f->open_object_section("statelog_entry");
  f->dump_string("client_id", entry.client_id);
  f->dump_string("op_id", entry.op_id);
  f->dump_string("object", entry.object);
  entry.timestamp.gmtime_nsec(f->dump_stream("timestamp"));
  if (!dump_entry_internal(entry, f)) {
    f->dump_int("state", entry.state);
  }
  f->close_section();
}

RGWOpState::RGWOpState(RGWRados *_store) : RGWStateLog(_store, _store->ctx()->_conf->rgw_num_zone_opstate_shards, string("obj_opstate"))
{
}

bool RGWOpState::dump_entry_internal(const cls_statelog_entry& entry, Formatter *f)
{
  string s;
  switch ((OpState)entry.state) {
    case OPSTATE_UNKNOWN:
      s = "unknown";
      break;
    case OPSTATE_IN_PROGRESS:
      s = "in-progress";
      break;
    case OPSTATE_COMPLETE:
      s = "complete";
      break;
    case OPSTATE_ERROR:
      s = "error";
      break;
    case OPSTATE_ABORT:
      s = "abort";
      break;
    case OPSTATE_CANCELLED:
      s = "cancelled";
      break;
    default:
      s = "invalid";
  }
  f->dump_string("state", s);
  return true;
}

int RGWOpState::state_from_str(const string& s, OpState *state)
{
  if (s == "unknown") {
    *state = OPSTATE_UNKNOWN;
  } else if (s == "in-progress") {
    *state = OPSTATE_IN_PROGRESS;
  } else if (s == "complete") {
    *state = OPSTATE_COMPLETE;
  } else if (s == "error") {
    *state = OPSTATE_ERROR;
  } else if (s == "abort") {
    *state = OPSTATE_ABORT;
  } else if (s == "cancelled") {
    *state = OPSTATE_CANCELLED;
  } else {
    return -EINVAL;
  }

  return 0;
}

int RGWOpState::set_state(const string& client_id, const string& op_id, const string& object, OpState state)
{
  uint32_t s = (uint32_t)state;
  return store_entry(client_id, op_id, object, s, NULL, NULL);
}

int RGWOpState::renew_state(const string& client_id, const string& op_id, const string& object, OpState state)
{
  uint32_t s = (uint32_t)state;
  return store_entry(client_id, op_id, object, s, NULL, &s);
}

RGWOpStateSingleOp::RGWOpStateSingleOp(RGWRados *store, const string& cid, const string& oid,
                                       const string& obj) : os(store), client_id(cid), op_id(oid), object(obj)
{
  cct = store->ctx();
  cur_state = RGWOpState::OPSTATE_UNKNOWN;
}

int RGWOpStateSingleOp::set_state(RGWOpState::OpState state) {
  last_update = real_clock::now();
  cur_state = state;
  return os.set_state(client_id, op_id, object, state);
}

int RGWOpStateSingleOp::renew_state() {
  real_time now = real_clock::now();

  int rate_limit_sec = cct->_conf->rgw_opstate_ratelimit_sec;

  if (rate_limit_sec && now - last_update < make_timespan(rate_limit_sec)) {
    return 0;
  }

  last_update = now;
  return os.renew_state(client_id, op_id, object, cur_state);
}


uint64_t RGWRados::instance_id()
{
  return get_rados_handle()->get_instance_id();
}

uint64_t RGWRados::next_bucket_id()
{
  Mutex::Locker l(bucket_id_lock);
  return ++max_bucket_id;
}

RGWRados *RGWStoreManager::init_storage_provider(CephContext *cct, bool use_gc_thread, bool use_lc_thread,
						 bool quota_threads, bool run_sync_thread, bool run_reshard_thread, bool use_cache, bool admin_op)
{
  RGWRados *store = NULL;
  if (!use_cache) {
    store = new RGWRados;
  } else {
    store = new RGWCache<RGWRados>;
  }

  if (store->initialize(cct, use_gc_thread, use_lc_thread, quota_threads, run_sync_thread, run_reshard_thread, admin_op) < 0) {
    delete store;
    return NULL;
  }

  return store;
}

RGWRados *RGWStoreManager::init_raw_storage_provider(CephContext *cct)
{
  RGWRados *store = NULL;
  store = new RGWRados;

  store->set_context(cct);

  if (store->init_rados() < 0) {
    delete store;
    return NULL;
  }

  return store;
}

void RGWStoreManager::close_storage(RGWRados *store)
{
  if (!store)
    return;

  store->finalize();

  delete store;
}

librados::Rados* RGWRados::get_rados_handle()
{
  if (rados.size() == 1) {
    return &rados[0];
  } else {
    handle_lock.get_read();
    pthread_t id = pthread_self();
    std::map<pthread_t, int>:: iterator it = rados_map.find(id);

    if (it != rados_map.end()) {
      handle_lock.put_read();
      return &rados[it->second];
    } else {
      handle_lock.put_read();
      handle_lock.get_write();
      const uint32_t handle = next_rados_handle;
      rados_map[id] = handle;
      if (++next_rados_handle == rados.size()) {
        next_rados_handle = 0;
      }
      handle_lock.put_write();
      return &rados[handle];
    }
  }
}

int RGWRados::delete_raw_obj_aio(const rgw_raw_obj& obj, list<librados::AioCompletion *>& handles)
{
  rgw_rados_ref ref;
  int ret = get_raw_obj_ref(obj, &ref);
  if (ret < 0) {
    lderr(cct) << "ERROR: failed to get obj ref with ret=" << ret << dendl;
    return ret;
  }

  ObjectWriteOperation op;
  list<string> prefixes;
  cls_rgw_remove_obj(op, prefixes);

  AioCompletion *c = librados::Rados::aio_create_completion(NULL, NULL, NULL);
  ret = ref.ioctx.aio_operate(ref.oid, c, &op);
  if (ret < 0) {
    lderr(cct) << "ERROR: AioOperate failed with ret=" << ret << dendl;
    c->release();
    return ret;
  }

  handles.push_back(c);

  return 0;
}

int RGWRados::delete_obj_aio(const rgw_obj& obj,
                             RGWBucketInfo& bucket_info, RGWObjState *astate,
                             list<librados::AioCompletion *>& handles, bool keep_index_consistent)
{
  rgw_rados_ref ref;
  int ret = get_obj_head_ref(bucket_info, obj, &ref);
  if (ret < 0) {
    lderr(cct) << "ERROR: failed to get obj ref with ret=" << ret << dendl;
    return ret;
  }

  if (keep_index_consistent) {
    RGWRados::Bucket bop(this, bucket_info);
    RGWRados::Bucket::UpdateIndex index_op(&bop, obj);
    RGWRados::Bucket::Namespace namespace_op(&bop, obj);
    ret = index_op.prepare(CLS_RGW_OP_DEL, &astate->write_tag);
    if (ret < 0) {
      lderr(cct) << "ERROR: failed to prepare index op with ret=" << ret << dendl;
      return ret;
    }

    // prepare delete namespace
    ceph::real_time mtime;
    ret = namespace_op.prepare(nullptr, CLS_RGW_OP_DEL, &astate->write_tag, mtime);
    if (ret < 0) {
      lderr(cct) << "ERROR: failed to prepare namespace op with ret=" << ret << dendl;
      return ret;
    }
  }

  ObjectWriteOperation op;
  list<string> prefixes;
  cls_rgw_remove_obj(op, prefixes);

  AioCompletion *c = librados::Rados::aio_create_completion(NULL, NULL, NULL);
  ret = ref.ioctx.aio_operate(ref.oid, c, &op);
  if (ret < 0) {
    lderr(cct) << "ERROR: AioOperate failed with ret=" << ret << dendl;
    c->release();
    return ret;
  }

  handles.push_back(c);

  if (keep_index_consistent) {
    ret = delete_obj_index(obj);
    if (ret < 0) {
      lderr(cct) << "ERROR: failed to delete obj index with ret=" << ret << dendl;
      return ret;
    }
  }
  return ret;
}

int rgw_compression_info_from_attrset(map<string, bufferlist>& attrs, bool& need_decompress, RGWCompressionInfo& cs_info) {
  map<string, bufferlist>::iterator value = attrs.find(RGW_ATTR_COMPRESSION);
  if (value != attrs.end()) {
    bufferlist::iterator bliter = value->second.begin();
    try {
      decode(cs_info, bliter);
    } catch (buffer::error& err) {
      return -EIO;
    }
    if (cs_info.blocks.size() == 0) {
      return -EIO;
    }
    if (cs_info.compression_type != "none")
      need_decompress = true;
    else
      need_decompress = false;
    return 0;
  } else {
    need_decompress = false;
    return 0;
  }
}

bool RGWRados::call(std::string_view command, const cmdmap_t& cmdmap,
		    std::string_view format, bufferlist& out)
{
  if (command == "cache list"sv) {
    std::optional<std::string> filter;
    if (auto i = cmdmap.find("filter"); i != cmdmap.cend()) {
      filter = boost::get<std::string>(i->second);
    }
    std::unique_ptr<Formatter> f(ceph::Formatter::create(format, "table"));
    if (f) {
      f->open_array_section("cache_entries");
      call_list(filter, f.get());
      f->close_section();
      f->flush(out);
      return true;
    } else {
      out.append("Unable to create Formatter.\n");
      return false;
    }
  } else if (command == "cache inspect"sv) {
    std::unique_ptr<Formatter> f(ceph::Formatter::create(format, "json-pretty"));
    if (f) {
      const auto& target = boost::get<std::string>(cmdmap.at("target"));
      if (call_inspect(target, f.get())) {
        f->flush(out);
        return true;
      } else {
        out.append("Unable to find entry "s + target + ".\n");
        return false;
      }
    } else {
      out.append("Unable to create Formatter.\n");
      return false;
    }
  } else if (command == "cache erase"sv) {
    const auto& target = boost::get<std::string>(cmdmap.at("target"));
    if (call_erase(target)) {
      return true;
    } else {
      out.append("Unable to find entry "s + target + ".\n");
      return false;
    }
  } else if (command == "cache zap"sv) {
    call_zap();
    return true;
  }
  return false;
}

void RGWRados::call_list(const std::optional<std::string>&,
                         ceph::Formatter*)
{
  return;
}

bool RGWRados::call_inspect(const std::string&, Formatter*)
{
  return false;
}

bool RGWRados::call_erase(const std::string&) {
  return false;
}

void RGWRados::call_zap() {
  return;
}

string RGWRados::get_mfa_oid(const rgw_user& user)
{
  return string("user:") + user.to_str();
}

int RGWRados::get_mfa_ref(const rgw_user& user, rgw_rados_ref *ref)
{
  string oid = get_mfa_oid(user);
  rgw_raw_obj obj(get_zone_params().otp_pool, oid);
  return get_system_obj_ref(obj, ref);
}

int RGWRados::check_mfa(const rgw_user& user, const string& otp_id, const string& pin)
{
  rgw_rados_ref ref;

  int r = get_mfa_ref(user, &ref);
  if (r < 0) {
    return r;
  }

  rados::cls::otp::otp_check_t result;

  r = rados::cls::otp::OTP::check(cct, ref.ioctx, ref.oid, otp_id, pin, &result);
  if (r < 0)
    return r;

  ldout(cct, 20) << "OTP check, otp_id=" << otp_id << " result=" << (int)result.result << dendl;

  return (result.result == rados::cls::otp::OTP_CHECK_SUCCESS ? 0 : -EACCES);
}

void RGWRados::prepare_mfa_write(librados::ObjectWriteOperation *op,
                                 RGWObjVersionTracker *objv_tracker,
                                 const ceph::real_time& mtime)
{
  RGWObjVersionTracker ot;

  if (objv_tracker) {
    ot = *objv_tracker;
  }

  if (ot.write_version.tag.empty()) {
    if (ot.read_version.tag.empty()) {
      ot.generate_new_write_ver(cct);
    } else {
      ot.write_version = ot.read_version;
      ot.write_version.ver++;
    }
  }

  ot.prepare_op_for_write(op);
  struct timespec mtime_ts = real_clock::to_timespec(mtime);
  op->mtime2(&mtime_ts);
}

int RGWRados::create_mfa(const rgw_user& user, const rados::cls::otp::otp_info_t& config,
                         RGWObjVersionTracker *objv_tracker, const ceph::real_time& mtime)
{
  rgw_rados_ref ref;

  int r = get_mfa_ref(user, &ref);
  if (r < 0) {
    return r;
  }

  librados::ObjectWriteOperation op;
  prepare_mfa_write(&op, objv_tracker, mtime);
  rados::cls::otp::OTP::create(&op, config);
  r = ref.ioctx.operate(ref.oid, &op);
  if (r < 0) {
    ldout(cct, 20) << "OTP create, otp_id=" << config.id << " result=" << (int)r << dendl;
    return r;
  }

  return 0;
}

int RGWRados::remove_mfa(const rgw_user& user, const string& id,
                         RGWObjVersionTracker *objv_tracker,
                         const ceph::real_time& mtime)
{
  rgw_rados_ref ref;

  int r = get_mfa_ref(user, &ref);
  if (r < 0) {
    return r;
  }

  librados::ObjectWriteOperation op;
  prepare_mfa_write(&op, objv_tracker, mtime);
  rados::cls::otp::OTP::remove(&op, id);
  r = ref.ioctx.operate(ref.oid, &op);
  if (r < 0) {
    ldout(cct, 20) << "OTP remove, otp_id=" << id << " result=" << (int)r << dendl;
    return r;
  }

  return 0;
}

int RGWRados::get_mfa(const rgw_user& user, const string& id, rados::cls::otp::otp_info_t *result)
{
  rgw_rados_ref ref;

  int r = get_mfa_ref(user, &ref);
  if (r < 0) {
    return r;
  }

  r = rados::cls::otp::OTP::get(nullptr, ref.ioctx, ref.oid, id, result);
  if (r < 0) {
    return r;
  }

  return 0;
}

int RGWRados::list_mfa(const rgw_user& user, list<rados::cls::otp::otp_info_t> *result)
{
  rgw_rados_ref ref;

  int r = get_mfa_ref(user, &ref);
  if (r < 0) {
    return r;
  }

  r = rados::cls::otp::OTP::get_all(nullptr, ref.ioctx, ref.oid, result);
  if (r < 0) {
    return r;
  }

  return 0;
}

int RGWRados::otp_get_current_time(const rgw_user& user, ceph::real_time *result)
{
  rgw_rados_ref ref;

  int r = get_mfa_ref(user, &ref);
  if (r < 0) {
    return r;
  }

  r = rados::cls::otp::OTP::get_current_time(ref.ioctx, ref.oid, result);
  if (r < 0) {
    return r;
  }

  return 0;
}

int RGWRados::set_mfa(const string& oid, const list<rados::cls::otp::otp_info_t>& entries,
                      bool reset_obj, RGWObjVersionTracker *objv_tracker,
                      const real_time& mtime)
{
  rgw_raw_obj obj(get_zone_params().otp_pool, oid);
  rgw_rados_ref ref;
  int r = get_system_obj_ref(obj, &ref);
  if (r < 0) {
    return r;
  }

  librados::ObjectWriteOperation op;
  if (reset_obj) {
    op.remove();
    op.set_op_flags2(LIBRADOS_OP_FLAG_FAILOK);
    op.create(false);
  }
  prepare_mfa_write(&op, objv_tracker, mtime);
  rados::cls::otp::OTP::set(&op, entries);
  r = ref.ioctx.operate(ref.oid, &op);
  if (r < 0) {
    ldout(cct, 20) << "OTP set entries.size()=" << entries.size() << " result=" << (int)r << dendl;
    return r;
  }

  return 0;
}

int RGWRados::list_mfa(const string& oid, list<rados::cls::otp::otp_info_t> *result,
                       RGWObjVersionTracker *objv_tracker, ceph::real_time *pmtime)
{
  rgw_raw_obj obj(get_zone_params().otp_pool, oid);
  rgw_rados_ref ref;
  int r = get_system_obj_ref(obj, &ref);
  if (r < 0) {
    return r;
  }
  librados::ObjectReadOperation op;
  struct timespec mtime_ts;
  if (pmtime) {
    op.stat2(nullptr, &mtime_ts, nullptr);
  }
  objv_tracker->prepare_op_for_read(&op);
  r = rados::cls::otp::OTP::get_all(&op, ref.ioctx, ref.oid, result);
  if (r < 0) {
    return r;
  }
  if (pmtime) {
    *pmtime = ceph::real_clock::from_timespec(mtime_ts);
  }

  return 0;
}

string RGWRados::unique_trans_id() {
  static const size_t RAND_LENGTH = 8;
  static const size_t AES_128_KEYSIZE = 256 / 16;

  // 27 = 1(:) + 9(timestamp consume up to 9) + 1 + 15(ip_max_len) + 1(\n)
  char src[RAND_LENGTH + 27];
  time_t timestamp = time(NULL);

  gen_rand_alphanumeric(cct, src, RAND_LENGTH + 1);

  snprintf(src + RAND_LENGTH, sizeof(src) - RAND_LENGTH, ":%09llx:%s",
           (unsigned long long)timestamp, local_ip.c_str());

  uint32_t max_output_len = strlen(src) + AES_128_KEYSIZE - (strlen(src) % AES_128_KEYSIZE) + 1;
  char encrypted[max_output_len];
  int size = 0;

  bool result = encrypt_request_id(cct, src, encrypted, size);
  if (result == false) {
    ldout(cct, 10) << "encrypt error, src req_id:" << src << dendl;
    return string(src);
  }

  return rgw::to_base64(boost::string_view(encrypted, size));
}

bool is_tail_obj_key(const string& oid) {
  static string multipart_prefix = RGW_OBJ_NS_MULTIPART_PREFIX;
  static string shadow_prefix = RGW_OBJ_NS_SHADOW_PREFIX;

  auto first_dot_pos = oid.find(".");
  if (unlikely(first_dot_pos == std::string::npos)) {
    return false;
  }
  std::string_view trim_zoneid_sv = std::string_view(oid).substr(first_dot_pos+1);
  auto second_dot_pos = trim_zoneid_sv.find(".");
  if (unlikely(second_dot_pos == std::string::npos)) {
    return false;
  }

  for (auto pos = second_dot_pos + 1; pos < trim_zoneid_sv.length(); pos++) {
    if (!isdigit(trim_zoneid_sv[pos])) {
      std::string_view trim_bucket_marker_sv = trim_zoneid_sv.substr(pos);
      if (boost::algorithm::starts_with(trim_bucket_marker_sv, multipart_prefix) ||
          boost::algorithm::starts_with(trim_bucket_marker_sv, shadow_prefix)) {
        return true;
      }
      return false;
    }
  }
  return false;
}
