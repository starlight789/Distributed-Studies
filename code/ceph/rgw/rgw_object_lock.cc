#include "rgw_object_lock.h"
#include "rgw_common.h"

void DefaultRetention::decode_xml(XMLObj *obj) {
  RGWXMLDecoder::decode_xml("Mode", mode, obj, true);
  if (mode.compare("GOVERNANCE") != 0 && mode.compare("COMPLIANCE") != 0) {
    throw RGWXMLDecoder::err("bad Mode in lock rule");
  }
  bool days_exist = RGWXMLDecoder::decode_xml("Days", days, obj);
  bool years_exist = RGWXMLDecoder::decode_xml("Years", years, obj);
  if ((days_exist && years_exist) || (!days_exist && !years_exist)) {
    throw RGWXMLDecoder::err("either Days or Years must be specified, but not both");
  }
}

void DefaultRetention::dump_xml(Formatter *f) const {
  encode_xml("Mode", mode, f);
  if (days > 0) {
    encode_xml("Days", days, f);
  } else {
    encode_xml("Years", years, f);
  }
}

void DefaultRetention::dump(Formatter *f) const {
  encode_json("Mode", mode, f);
  if (days > 0) {
    encode_json("Days", days, f);
  } else {
    encode_json("Years", years, f);
  }
}

void DefaultRetention::decode_json(JSONObj *obj) {
  JSONDecoder::decode_json("Mode", mode, obj, true);
  if (mode.compare("GOVERNANCE") != 0 && mode.compare("COMPLIANCE") != 0) {
    throw JSONDecoder::err("bad Mode in lock rule");
  }
  bool days_exist = JSONDecoder::decode_json("Days", days, obj);
  bool years_exist = JSONDecoder::decode_json("Years", years, obj);
  if ((days_exist && years_exist) || (!days_exist && !years_exist)) {
    throw JSONDecoder::err("either Days or Years must be specified, but not both");
  }
}

void ObjectLockRule::decode_xml(XMLObj *obj) {
  RGWXMLDecoder::decode_xml("DefaultRetention", defaultRetention, obj, true);
}

void ObjectLockRule::dump_xml(Formatter *f) const {
  encode_xml("DefaultRetention", defaultRetention, f);
}

void ObjectLockRule::dump(Formatter *f) const {
  encode_json("DefaultRetention", defaultRetention, f);
}

void ObjectLockRule::decode_json(JSONObj *obj) {
  JSONDecoder::decode_json("DefaultRetention", defaultRetention, obj, true);
}

void RGWObjectLock::decode_xml(XMLObj *obj) {
  string enabled_str;
  RGWXMLDecoder::decode_xml("ObjectLockEnabled", enabled_str, obj, true);
  if (enabled_str.compare("Enabled") != 0) {
    throw RGWXMLDecoder::err("invalid ObjectLockEnabled value");
  } else {
    enabled = true;
  }
  rule_exist = RGWXMLDecoder::decode_xml("Rule", rule, obj);
}

void RGWObjectLock::dump_xml(Formatter *f) const {
  if (enabled) {
    encode_xml("ObjectLockEnabled", "Enabled", f);
  }
  if (rule_exist) {
    encode_xml("Rule", rule, f);
  }
}

void RGWObjectLock::dump(Formatter *f) const {
  if (enabled) {
    encode_json("ObjectLockEnabled", "Enabled", f);
  }
  if (rule_exist) {
    encode_json("Rule", rule, f);
  }
}

void RGWObjectLock::decode_json(JSONObj *obj) {
  string enabled_str;
  JSONDecoder::decode_json("ObjectLockEnabled", enabled_str, obj, true);
  if (enabled_str.compare("Enabled") != 0) {
    throw JSONDecoder::err("invalid ObjectLockEnabled value");
  } else {
    enabled = true;
  }
  rule_exist = JSONDecoder::decode_json("Rule", rule, obj);
}

ceph::real_time RGWObjectLock::get_lock_until_date(const ceph::real_time& mtime) const {
  if (!rule_exist) {
    return ceph::real_time();
  }
  int days = get_days();
  if (days <= 0) {
    days = get_years()*365;
  }
  return mtime + make_timespan(days*24*60*60);
}

void RGWObjectRetention::decode_xml(XMLObj *obj) {
  RGWXMLDecoder::decode_xml("Mode", mode, obj, true);
  if (mode.compare("GOVERNANCE") != 0 && mode.compare("COMPLIANCE") != 0) {
    throw RGWXMLDecoder::err("bad Mode in retention");
  }
  string date_str;
  RGWXMLDecoder::decode_xml("RetainUntilDate", date_str, obj, true);
  boost::optional<ceph::real_time> date = ceph::from_iso_8601(date_str);
  if (boost::none == date) {
    throw RGWXMLDecoder::err("invalid RetainUntilDate value");
  }
  retain_until_date = *date;
}

void RGWObjectRetention::dump_xml(Formatter *f) const {
  encode_xml("Mode", mode, f);
  string date = ceph::to_iso_8601(retain_until_date);
  encode_xml("RetainUntilDate", date, f);
}

void RGWObjectLegalHold::decode_xml(XMLObj *obj) {
  RGWXMLDecoder::decode_xml("Status", status, obj, true);
  if (status.compare("ON") != 0 && status.compare("OFF") != 0) {
    throw RGWXMLDecoder::err("bad status in legal hold");
  }
}

void RGWObjectLegalHold::dump_xml(Formatter *f) const {
  encode_xml("Status", status, f);
}

bool RGWObjectLegalHold::is_enabled() const {
  return status.compare("ON") == 0;
}

RGWBOSObjectLock::RGWBOSObjectLock() {
  lock_status = BOS_OBJECT_LOCK_STATUS_UNLOCK;
}

void RGWBOSObjectLock::dump(Formatter *f) const {
  encode_json("CreateDate", (uint32_t)create_date, f);
  encode_json("RetentionDays", retention_days, f);
  encode_json("LockStatus", (uint32_t)lock_status, f);
}

void RGWBOSObjectLock::decode_json(JSONObj *obj) {
  uint32_t cd, ls;
  JSONDecoder::decode_json("CreateDate", cd, obj, true);
  JSONDecoder::decode_json("RetentionDays", retention_days, obj, true);
  JSONDecoder::decode_json("LockStatus", ls, obj, true);
  create_date = (time_t)cd;
  lock_status = (BOSObjectLockStatus)ls;
}

int RGWBOSObjectLock::update_retention_days(int64_t days) {
  update_lock_status();
  switch (lock_status) {
    case BOS_OBJECT_LOCK_STATUS_UNLOCK:
      return -ERR_NO_SUCH_OBJECT_LOCK_CONFIGURATION;
    case BOS_OBJECT_LOCK_STATUS_IN_PROGRESS:
      return -ERR_OBJ_NOT_LOCK;
    case BOS_OBJECT_LOCK_STATUS_EXPIRED:
      return -ERR_OBJ_NOT_LOCK;
    default:
      {
        if (days < retention_days) {
          return -ERR_NOT_ALLOW_SHORTEN_RETEN;
        }
        retention_days = days;
      }
  }

  return 0;
}

int RGWBOSObjectLock::init_object_lock(int64_t days, int64_t bos_expired) {
  if (bos_expired > 0) {
    expired = bos_expired;
  }
  update_lock_status();
  switch (lock_status) {
    case BOS_OBJECT_LOCK_STATUS_IN_PROGRESS:
      return -ERR_OBJ_LOCK_PROGRESS;

    case BOS_OBJECT_LOCK_STATUS_EXPIRED:
      return -ERR_OBJ_LOCK_EXPIRED;

    case BOS_OBJECT_LOCK_STATUS_LOCKED:
      return -ERR_OBJ_LOCK_LOCKED;

    case BOS_OBJECT_LOCK_STATUS_UNLOCK:
      {
        lock_status = BOS_OBJECT_LOCK_STATUS_IN_PROGRESS;
        retention_days = days;
        create_date = ceph::real_clock::to_time_t(ceph::real_clock::now());
      }
  }
  return 0;
}

int RGWBOSObjectLock::complete_object_lock() {
  update_lock_status();
  switch (lock_status) {
    case BOS_OBJECT_LOCK_STATUS_UNLOCK:
      return -ERR_NO_SUCH_OBJECT_LOCK_CONFIGURATION;
    case BOS_OBJECT_LOCK_STATUS_EXPIRED:
      return -ERR_OBJ_LOCK_EXPIRED;
    case BOS_OBJECT_LOCK_STATUS_LOCKED:
      return -ERR_OBJ_LOCK_LOCKED;
    case BOS_OBJECT_LOCK_STATUS_IN_PROGRESS:
      lock_status = BOS_OBJECT_LOCK_STATUS_LOCKED;
  }
  return 0;
}

int RGWBOSObjectLock::delete_object_lock() {
  update_lock_status();
  switch (lock_status) {
    case BOS_OBJECT_LOCK_STATUS_UNLOCK:
      return -ERR_NO_SUCH_OBJECT_LOCK_CONFIGURATION;
    case BOS_OBJECT_LOCK_STATUS_LOCKED:
      return -ERR_OBJ_LOCK_LOCKED;
    default:
      lock_status = BOS_OBJECT_LOCK_STATUS_UNLOCK;
  }
  return 0;
}

time_t RGWBOSObjectLock::get_create_date() {
  return create_date;
}

int64_t RGWBOSObjectLock::get_retention_days() {
  return retention_days;
}

BOSObjectLockStatus RGWBOSObjectLock::get_lock_status(bool* status_update) {
  BOSObjectLockStatus old_status = lock_status;
  update_lock_status();
  if (status_update) {
    *status_update = (old_status != lock_status);
  }
  return lock_status;
}

void RGWBOSObjectLock::update_lock_status() {
  if (lock_status == BOS_OBJECT_LOCK_STATUS_IN_PROGRESS) {
    auto now = ceph::real_clock::to_time_t(ceph::real_clock::now());
    if (now > (create_date + expired)) {
      lock_status = BOS_OBJECT_LOCK_STATUS_EXPIRED;
    }
  }

  return;
}

int RGWBOSObjectLock::verify_bos_obj_lock(const int64_t bos_expiration_time, const ceph::real_time& mtime) {
  if (lock_status == BOS_OBJECT_LOCK_STATUS_UNLOCK ||
      lock_status == BOS_OBJECT_LOCK_STATUS_EXPIRED) {
    return 0;
  }

  time_t now = ceph::real_clock::to_time_t(ceph::real_clock::now());
  time_t expired_time = ceph::real_clock::to_time_t(mtime) + retention_days * bos_expiration_time;
  if (now < expired_time) {
    return -ERR_OBJ_IMMUTABLE;
  }

  return 0;
}

