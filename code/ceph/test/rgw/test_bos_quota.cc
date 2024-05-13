#include <iostream>
#include "global/global_init.h"
#include "rgw/rgw_rest_bos.h"
#include "rgw/rgw_common.h"

#include <errno.h>
#include <gtest/gtest.h>
#include <gmock/gmock.h>

class Mock_RGWPutBucketQuota_ObjStore_BOS : public RGWPutBucketQuota_ObjStore_BOS{
public:
  void set_max_size_mb(int64_t val){
    this->max_size_mb = val;
  }
  void set_max_objects(int64_t val){
    this->max_objects = val;
  }
  int64_t get_max_size_kb(){
    return this->max_size_kb;
  }
  int64_t get_max_objects(){
    return this->max_objects;
  }
};

TEST(Mock_RGWPutUserQuota_ObjStore_BOS, check_bucket_quota1){
  Mock_RGWPutBucketQuota_ObjStore_BOS putBucketQuota;
  putBucketQuota.set_max_size_mb(10);
  putBucketQuota.set_max_objects(10);
  int ret = putBucketQuota.check_quota_params();
  EXPECT_EQ(ret, 0);
  EXPECT_EQ(putBucketQuota.get_max_size_kb(), 10*1024*1024);
  EXPECT_EQ(putBucketQuota.get_max_objects(), 10);
}

TEST(Mock_RGWPutUserQuota_ObjStore_BOS, check_bucket_quota2){
  Mock_RGWPutBucketQuota_ObjStore_BOS putBucketQuota;
  putBucketQuota.set_max_size_mb(10);
  putBucketQuota.set_max_objects(-2);
  int ret = putBucketQuota.check_quota_params();
  EXPECT_EQ(ret, -EINVAL);
}


class Mock_RGWPutUserQuota_ObjStore_BOS : public RGWPutUserQuota_ObjStore_BOS{
public:
  void set_max_size_mb(int64_t val){
    this->max_size_mb = val;
  }
  void set_max_objects(int64_t val){
    this->max_objects = val;
  }
  void set_max_bucket_count(int32_t val){
    this->max_bucket_count = val;
  }
  int64_t get_max_size_kb(){
    return this->max_size_kb;
  }
  int64_t get_max_objects(){
    return this->max_objects;
  }
  int32_t get_max_bucket_count(){
    return this->max_bucket_count;
  }
};

TEST(Mock_RGWPutUserQuota_ObjStore_BOS, check_user_quota1){
  Mock_RGWPutUserQuota_ObjStore_BOS putUserQuota;
  putUserQuota.set_max_size_mb(10);
  putUserQuota.set_max_objects(10);
  putUserQuota.set_max_bucket_count(10);
  int ret = putUserQuota.check_quota_params();
  EXPECT_EQ(ret, 0);
  EXPECT_EQ(putUserQuota.get_max_size_kb(), 10*1024*1024);
  EXPECT_EQ(putUserQuota.get_max_objects(), 10);
  EXPECT_EQ(putUserQuota.get_max_bucket_count(), 10);
}

TEST(Mock_RGWPutUserQuota_ObjStore_BOS, check_user_quota2){
  Mock_RGWPutUserQuota_ObjStore_BOS putUserQuota;
  putUserQuota.set_max_size_mb(-2);
  putUserQuota.set_max_objects(10);
  putUserQuota.set_max_bucket_count(10);
  int ret = putUserQuota.check_quota_params();
  EXPECT_EQ(ret, -EINVAL);
}

TEST(Mock_RGWPutUserQuota_ObjStore_BOS, check_user_quota3){
  Mock_RGWPutUserQuota_ObjStore_BOS putUserQuota;
  putUserQuota.set_max_size_mb(0);
  putUserQuota.set_max_objects(0);
  putUserQuota.set_max_bucket_count(0);
  putUserQuota.check_quota_params();
  EXPECT_EQ(putUserQuota.get_max_size_kb(), -2);
  EXPECT_EQ(putUserQuota.get_max_objects(), -2);
  EXPECT_EQ(putUserQuota.get_max_bucket_count(), 0);
}


