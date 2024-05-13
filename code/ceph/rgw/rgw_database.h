#ifndef CEPH_RGW_DATABASE_H
#define CEPH_RGW_DATABASE_H

#include "include/buffer.h"
#include "rgw_http.h"
#include "rgw_bucket.h"
#include "rgw_common.h"

#ifdef WITH_RADOSGW_BEAST_FRONTEND
#include "asio_sync.hpp"
#endif

#define dout_context g_ceph_context
#define dout_subsys ceph_subsys_rgw

#define BEGIN_DATABASE_NAMESPACE namespace database {
#define END_DATABASE_NAMESPACE } /* namespace database */

BEGIN_DATABASE_NAMESPACE

struct db_bucket_info {
  db_bucket_info(std::string& _bucket, std::string& _user,
                 std::string& _region, time_t _create_time)
    : bucket(_bucket), user(_user), region(_region), create_time(_create_time) {}
  std::string bucket;
  std::string user;
  std::string region;
  time_t create_time;
};

class DBClient : public RGWHttpConnect {
public:
  DBClient() {};

  static DBClient& instance() {
    static DBClient db_client;
    return db_client;
  }

  boost::optional<RGWBucketEnt> query_bucket_info(const req_state* s, const std::string& bucket);

  int list_bucket_by_user(const req_state* s, const std::string user_id, RGWUserBuckets&  buckets, uint64_t read_count);

  int get_bucket_count_by_user(const req_state* s, const std::string user_id, int& count);

  int insert_bucket_info(const req_state* s, db_bucket_info& bucket_info);

  int delete_bucket_info(const req_state* s, const std::string& bucket);

};

END_DATABASE_NAMESPACE
#endif /* CEPH_RGW_DATABASE_H */
