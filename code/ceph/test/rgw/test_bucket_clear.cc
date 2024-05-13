// -*- mode:C; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#define FOR_TEST_BUILD

#include "rgw/rgw_bucket.h"
#include "rgw/rgw_rados.h"
#include "cls/rgw/cls_rgw_types.h"

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "global/global_context.h"
#include "global/global_init.h"
#include "common/common_init.h"
#include "common/ceph_argparse.h"

#include <errno.h>
#include <string>
#include <vector>
#include <iostream>



int main(int argc, char **argv) {
  std::vector<const char*> args(argv, argv+argc);
  auto cct = global_init(nullptr, args, CEPH_ENTITY_TYPE_CLIENT,
			 CODE_ENVIRONMENT_UTILITY,
			 CINIT_FLAG_NO_DEFAULT_CONFIG_FILE);
  common_init_finish(g_ceph_context);
  ::testing::InitGoogleTest(&argc, argv);
  ::testing::InitGoogleMock(&argc, argv);
  return RUN_ALL_TESTS();
}

class MockBucketList {
public:
  MockBucketList() {}
  ~MockBucketList() {}

  MOCK_METHOD4(list_objects, int(int64_t max,
                       vector<rgw_bucket_dir_entry> *result,
                       map<string, bool> *common_prefixes,
                       bool *is_truncated));
  MOCK_METHOD7(get_bucket_stats, int(RGWBucketInfo& bucket_info, int shard_id, string *bucket_ver, string *master_ver,
    map<RGWObjCategory, RGWStorageStats>& stats, string *max_marker, bool *syncstopped));
  MOCK_METHOD5(abort_bucket_multiparts, int(RGWRados *store, CephContext *cct, RGWBucketInfo& bucket_info,
				string& prefix, string& delim));
};


TEST(is_todelete_bucket_empty, empty_todelete_bucket)
{
  RGWBucketInfo info;
  rgw_bucket bucket;
  bucket.name = "bucket1";
  bool is_empty = false;

  rgw_bucket_dir_entry bd_entry;
  bd_entry.key.name = "obj1";
  std::vector<rgw_bucket_dir_entry> objs;
  objs.push_back(bd_entry);

  MockBucketList *l = new MockBucketList();
  EXPECT_CALL(*l, list_objects(::testing::_, &objs, ::testing::_, ::testing::_))
  .Times(1)
  .WillRepeatedly(::testing::Return(0));

  EXPECT_EQ(rgw_is_todelete_bucket_empty(nullptr, info, bucket, is_empty), 1);
}

TEST(remove_todelete_bucket_data, not_empty_todelete_bucket)
{
  RGWBucketInfo info;
  rgw_bucket bucket;
  bucket.name = "bucket1";
  bool is_empty = false;

  std::vector<rgw_bucket_dir_entry> objs;

  MockBucketList *l = new MockBucketList();
  EXPECT_CALL(*l, list_objects(::testing::_, &objs, ::testing::_, ::testing::_))
  .Times(1)
  .WillRepeatedly(::testing::Return(0));

  EXPECT_EQ(rgw_is_todelete_bucket_empty(nullptr, info, bucket, is_empty), 0);
}

TEST(remove_todelete_bucket_data, remove_failed)
{
  RGWRados store;
  RGWBucketInfo info;
  rgw_bucket bucket;
  bucket.name = "bucket1";

  rgw_bucket_dir_entry bd_entry;
  bd_entry.key.name = "obj1";
  std::vector<rgw_bucket_dir_entry> objs;
  objs.push_back(bd_entry);

  MockBucketList *l = new MockBucketList();
  EXPECT_CALL(*l, list_objects(::testing::_, &objs, ::testing::_, ::testing::_))
  .Times(1)
  .WillRepeatedly(::testing::Return(0));

  EXPECT_CALL(*l, get_bucket_stats(::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_))
  .Times(1)
  .WillRepeatedly(::testing::Return(-1));

  EXPECT_CALL(*l, abort_bucket_multiparts(::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_))
  .Times(2)
  .WillRepeatedly(::testing::Return(0))
  .WillRepeatedly(::testing::Return(-1));

  EXPECT_EQ(rgw_remove_todelete_bucket_data(&store, info), -1);
  EXPECT_EQ(rgw_remove_todelete_bucket_data(&store, info), -1);
}

TEST(remove_todelete_bucket_data, remove_success)
{
  RGWRados store;
  RGWBucketInfo info;
  rgw_bucket bucket;
  bucket.name = "bucket1";

  rgw_bucket_dir_entry bd_entry;
  bd_entry.key.name = "obj1";
  std::vector<rgw_bucket_dir_entry> objs;
  objs.push_back(bd_entry);

  MockBucketList *l = new MockBucketList();
  EXPECT_CALL(*l, list_objects(::testing::_, &objs, ::testing::_, ::testing::_))
  .Times(1)
  .WillRepeatedly(::testing::Return(0));

  EXPECT_CALL(*l, get_bucket_stats(::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_))
  .Times(1)
  .WillRepeatedly(::testing::Return(0));

  EXPECT_CALL(*l, abort_bucket_multiparts(::testing::_, ::testing::_, ::testing::_, ::testing::_, ::testing::_))
  .Times(1)
  .WillRepeatedly(::testing::Return(0));

  EXPECT_EQ(rgw_remove_todelete_bucket_data(&store, info), 0);
  
}

