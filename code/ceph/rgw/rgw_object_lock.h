/**
 * You can use S3 Object Lock to store objects using a write-once-read-many
 * (WORM) model. Object Lock can help prevent objects from being deleted or
 * overwritten for a fixed amount of time or indefinitely.
 * See more details:
 * https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock-overview.html
 * http://wiki.baidu.com/pages/viewpage.action?pageId=1155408801
 */
#ifndef CEPH_RGW_OBJECT_LOCK_H
#define CEPH_RGW_OBJECT_LOCK_H

#include <string>
#include "common/ceph_time.h"
#include "common/iso_8601.h"
#include "common/ceph_json.h"
#include "rgw_xml.h"

#define BOS_WORM_UNLOCK "UNLOCK"
#define BOS_WORM_EXPIRED "EXPIRED"
#define BOS_WORM_IN_PROGRESS "IN_PROGRESS"
#define BOS_WORM_LOCKED "LOCKED"
#define ONE_DAY 86400

// bucket granularity object lock configuration
class DefaultRetention
{
protected:
  string mode;    // GOVERNANCE or COMPLIANCE
  int days;
  int years;

public:
  DefaultRetention() : days(0), years(0) {};

  int get_days() const {
    return days;
  }

  int get_years() const {
    return years;
  }

  string get_mode() const {
    return mode;
  }

  void encode(bufferlist& bl) const {
    ENCODE_START(1, 1, bl);
    encode(mode, bl);
    encode(days, bl);
    encode(years, bl);
    ENCODE_FINISH(bl);
  }

  void decode(bufferlist::iterator& bl) {
    DECODE_START(1, bl);
    decode(mode, bl);
    decode(days, bl);
    decode(years, bl);
    DECODE_FINISH(bl);
  }

  void decode_xml(XMLObj *obj);
  void dump_xml(Formatter *f) const;
  void dump(Formatter *f) const;
  void decode_json(JSONObj *obj);
};
WRITE_CLASS_ENCODER(DefaultRetention)

class ObjectLockRule
{
protected:
  DefaultRetention defaultRetention;
public:
  int get_days() const {
    return defaultRetention.get_days();
  }

  int get_years() const {
    return defaultRetention.get_years();
  }

  string get_mode() const {
    return defaultRetention.get_mode();
  }

  void encode(bufferlist& bl) const {
    ENCODE_START(1, 1, bl);
    encode(defaultRetention, bl);
    ENCODE_FINISH(bl);
  }

  void decode(bufferlist::iterator& bl) {
    DECODE_START(1, bl);
    decode(defaultRetention, bl);
    DECODE_FINISH(bl);
  }

  void decode_xml(XMLObj *obj);
  void dump_xml(Formatter *f) const;
  void dump(Formatter *f) const;
  void decode_json(JSONObj *obj);
};
WRITE_CLASS_ENCODER(ObjectLockRule)

class RGWObjectLock
{
protected:
  bool enabled;
  bool rule_exist;
  ObjectLockRule rule;

public:
  RGWObjectLock() : enabled(true), rule_exist(false) {}

  int get_days() const {
    return rule.get_days();
  }

  int get_years() const {
    return rule.get_years();
  }

  string get_mode() const {
    return rule.get_mode();
  }

  bool retention_period_valid() const {
    // DefaultRetention requires either Days or Years.
    // You can't specify both at the same time.
    // see https://docs.aws.amazon.com/AmazonS3/latest/API/RESTBucketPUTObjectLockConfiguration.html
    return (get_years() > 0) != (get_days() > 0);
  }

  bool has_rule() const {
    return rule_exist;
  }

  void encode(bufferlist& bl) const {
    ENCODE_START(1, 1, bl);
    encode(enabled, bl);
    encode(rule_exist, bl);
    if (rule_exist) {
      encode(rule, bl);
    }
    ENCODE_FINISH(bl);
  }

  void decode(bufferlist::iterator& bl) {
    DECODE_START(1, bl);
    decode(enabled, bl);
    decode(rule_exist, bl);
    if (rule_exist) {
      decode(rule, bl);
    }
    DECODE_FINISH(bl);
  }

  void decode_xml(XMLObj *obj);
  void dump_xml(Formatter *f) const;
  ceph::real_time get_lock_until_date(const ceph::real_time& mtime) const;
  void dump(Formatter *f) const;
  void decode_json(JSONObj *obj);
};
WRITE_CLASS_ENCODER(RGWObjectLock)

// object granularity retention
class RGWObjectRetention
{
protected:
  string mode;
  ceph::real_time retain_until_date;
public:
  RGWObjectRetention() {}
  RGWObjectRetention(string _mode, ceph::real_time _date) : mode(_mode), retain_until_date(_date) {}

  void set_mode(string _mode) {
    mode = _mode;
  }

  string get_mode() const {
    return mode;
  }

  void set_retain_until_date(ceph::real_time _retain_until_date) {
    retain_until_date = _retain_until_date;
  }

  ceph::real_time get_retain_until_date() const {
    return retain_until_date;
  }

  void encode(bufferlist& bl) const {
    ENCODE_START(1, 1, bl);
    encode(mode, bl);
    encode(retain_until_date, bl);
    ENCODE_FINISH(bl);
  }

  void decode(bufferlist::iterator& bl) {
    DECODE_START(1, bl);
    decode(mode, bl);
    decode(retain_until_date, bl);
    DECODE_FINISH(bl);
  }

  void decode_xml(XMLObj *obj);
  void dump_xml(Formatter *f) const;
};
WRITE_CLASS_ENCODER(RGWObjectRetention)

// object granularity legal hold
class RGWObjectLegalHold
{
protected:
  string status;
public:
  RGWObjectLegalHold() {}
  RGWObjectLegalHold(string _status) : status(_status) {}
  void set_status(string _status) {
    status = _status;
  }

  string get_status() const {
    return status;
  }

  void encode(bufferlist& bl) const {
    ENCODE_START(1, 1, bl);
    encode(status, bl);
    ENCODE_FINISH(bl);
  }

  void decode(bufferlist::iterator& bl) {
    DECODE_START(1, bl);
    decode(status, bl);
    DECODE_FINISH(bl);
  }

  void decode_xml(XMLObj *obj);
  void dump_xml(Formatter *f) const;
  bool is_enabled() const;
};
WRITE_CLASS_ENCODER(RGWObjectLegalHold)

enum BOSObjectLockStatus {
  BOS_OBJECT_LOCK_STATUS_UNLOCK = 0,
  BOS_OBJECT_LOCK_STATUS_IN_PROGRESS,
  BOS_OBJECT_LOCK_STATUS_EXPIRED,
  BOS_OBJECT_LOCK_STATUS_LOCKED,
};

class RGWBOSObjectLock
{
protected:
  time_t create_date;
  int64_t expired{ONE_DAY};
  int64_t retention_days;
  BOSObjectLockStatus lock_status;

private:
  void update_lock_status();

public:
  RGWBOSObjectLock();

  void encode(bufferlist& bl) const {
    ENCODE_START(1, 1, bl);
    encode((uint32_t)create_date, bl);
    encode(retention_days, bl);
    encode(expired, bl);
    encode((uint32_t)lock_status, bl);
    ENCODE_FINISH(bl);
  }

  void decode(bufferlist::iterator& bl) {
    DECODE_START(1, bl);
    uint32_t cd, ls;
    decode(cd, bl);
    decode(retention_days, bl);
    decode(expired, bl);
    decode(ls, bl);
    create_date = (time_t)cd;
    lock_status = (BOSObjectLockStatus)ls;
    DECODE_FINISH(bl);
  }

  // extend bucket object lock
  int update_retention_days(int64_t days);

  // init bucket object lock
  int init_object_lock(int64_t days, int64_t bos_expired);

  // complete bucket object lock
  int complete_object_lock();

  // delete bucket object lock
  int delete_object_lock();

  // get bucket lock info: create date
  time_t get_create_date();

  // get bucket lock info: retention days
  int64_t get_retention_days();

  // get bucket lock infoL lock status
  BOSObjectLockStatus get_lock_status(bool* status_update);

  int verify_bos_obj_lock(const int64_t bos_expiration_time, const ceph::real_time& mtime);

  void dump(Formatter *f) const;
  void decode_json(JSONObj *obj);
};
WRITE_CLASS_ENCODER(RGWBOSObjectLock)
#endif //CEPH_RGW_OBJECT_LOCK_H
