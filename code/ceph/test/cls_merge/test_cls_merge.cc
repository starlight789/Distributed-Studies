// -*- mode:C; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#define FOR_TEST_BUILD

#include "include/types.h"
#include "objclass/merge_cls.h"
#include "cls/rgw/cls_rgw_types.h"

#include "gtest/gtest.h"
#include "global/global_context.h"
#include "global/global_init.h"
#include "common/common_init.h"
#include "common/ceph_argparse.h"

#include <errno.h>
#include <string>
#include <map>
#include <iostream>

bufferlist header;
map<string, bufferlist> omaps;

int main(int argc, char **argv) {
  std::vector<const char*> args(argv, argv+argc);
  auto cct = global_init(nullptr, args, CEPH_ENTITY_TYPE_CLIENT,
			 CODE_ENVIRONMENT_UTILITY,
			 CINIT_FLAG_NO_DEFAULT_CONFIG_FILE);
  common_init_finish(g_ceph_context);
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}

int cls_cxx_map_read_header(cls_method_context_t hctx, bufferlist *outbl, bool skip_cache)
{
    outbl->clear();
    outbl->append(header);

    return 0;
}

int cls_cxx_map_write_header(cls_method_context_t hctx, bufferlist *inbl, bool skip_cache)
{
    header.claim(*inbl);
    return 0;
}

int cls_cxx_map_set_val(cls_method_context_t hctx,
                        const std::string &key,
                        ceph::bufferlist *inbl,
                        bool skip_cache)
{
    omaps[key] = std::move(*inbl);
    return 0;
}

int cls_cxx_map_get_val(cls_method_context_t hctx,
                        const std::string &key,
                        ceph::bufferlist *outbl,
                        bool skip_cache)
{
    auto iter = omaps.find(key);
    // find in omaps
    if (iter != omaps.end()) {
        outbl->clear();
        outbl->append(iter->second);
        return 0;
    }
    return -ENOENT;
}

int cls_cxx_map_remove_key(cls_method_context_t hctx, const string &key, bool skip_cache)
{
    omaps.erase(key);
    return 0;
}

int cls_cxx_map_get_vals(cls_method_context_t hctx,
                         const string &start_after,
                         const string &filter_prefix,
                         uint64_t max_to_get,
                         std::map<string, bufferlist> *vals,
                         bool *more,
                         bool skip_cache)
{
    auto iter = omaps.upper_bound(start_after);
    for (uint64_t i=0; iter != omaps.end() && i<max_to_get; ++i, ++iter) {
      vals->insert(pair<string, bufferlist>(iter->first, iter->second));
    }
    if (iter != omaps.end()) {
      *more = true;
    } else {
      *more = false;
    }
    return 0;
}

TEST(cls_rgw_merge, empty_omap_read)
{
  header.clear();
  omaps.clear();

  rgw_bucket_dir_header bucket_shard_header;
  bucket_shard_header.encode(header);
  std::map<string, bufferlist> vals;
  bool more = false;
  CLSMergedRGWProcess m(g_ceph_context);

  int ret = m.cls_cxx_map_get_vals(nullptr, "", "", 10, &vals, &more);
  ASSERT_EQ(0, ret);
  ASSERT_EQ(0, vals.size());
}

TEST(cls_rgw_merge, empty_omap_set)
{
  header.clear();
  omaps.clear();

  // set heder
  rgw_bucket_dir_header bucket_shard_header;
  bucket_shard_header.syncstopped = false;
  bucket_shard_header.encode(header);

  CLSMergedRGWProcess m(g_ceph_context);

  // read header
  bufferlist bl;
  int r = m.cls_cxx_map_read_header(nullptr, &bl);
  ASSERT_EQ(0, r);
  ASSERT_GT(bl.length(), 0);
  bufferlist::iterator iter = bl.begin();
  try {
    decode(bucket_shard_header, iter);
  } catch (buffer::error& err) {
    ASSERT_TRUE(false);
  }
  ASSERT_EQ(false, bucket_shard_header.syncstopped);

  // get key
  r = m.cls_cxx_map_get_val(nullptr, "key1", &bl);
  ASSERT_EQ(-ENOENT, r);

  bufferlist val1, val2, val3;
  val1.append("val1");
  val2.append("val2");
  val3.append("val3");

  // set key
  r = m.cls_cxx_map_set_val(nullptr, "key1", &val1);
  ASSERT_EQ(0, r);
  r = m.cls_cxx_map_set_val(nullptr, "key2", &val2);
  ASSERT_EQ(0, r);
  r = m.cls_cxx_map_set_val(nullptr, "key3", &val3);
  ASSERT_EQ(0, r);

  auto m_iter = omaps.find("key1");
  ASSERT_EQ(true, (m_iter==omaps.end()));

  r = m.cls_cxx_map_get_val(nullptr, "key1", &bl);
  ASSERT_EQ(0, r);
  ASSERT_EQ(0, strcmp(bl.c_str(), "val1"));

  r = m.cls_cxx_map_flush(nullptr);
  ASSERT_EQ(0, r);

  m_iter = omaps.find("key1");
  ASSERT_EQ(false, (m_iter==omaps.end()));
  ASSERT_EQ(0, strcmp(m_iter->second.c_str(), "val1"));


  m.cls_cxx_map_snap();
  // set key
  val1.clear();
  val1.append("1");
  r = m.cls_cxx_map_set_val(nullptr, "key1", &val1);
  ASSERT_EQ(0, r);
  r = m.cls_cxx_map_remove_key(nullptr, "key2");
  ASSERT_EQ(0, r);
  r = m.cls_cxx_map_get_val(nullptr, "key2", &bl);
  ASSERT_EQ(-ENOENT, r);
  r = m.cls_cxx_map_get_val(nullptr, "key1", &bl);
  ASSERT_EQ(0, r);
  ASSERT_EQ(0, strcmp(bl.c_str(), "1"));

  m_iter = omaps.find("key1");
  ASSERT_EQ(false, (m_iter==omaps.end()));
  ASSERT_EQ(0, strcmp(m_iter->second.c_str(), "val1"));

  m.cls_cxx_map_rollback();
  r = m.cls_cxx_map_get_val(nullptr, "key2", &bl);
  ASSERT_EQ(0, r);
  ASSERT_EQ(0, strcmp(bl.c_str(), "val2"));
  r = m.cls_cxx_map_get_val(nullptr, "key1", &bl);
  ASSERT_EQ(0, r);
  ASSERT_EQ(0, strcmp(bl.c_str(), "val1"));

  m_iter = omaps.find("key1");
  ASSERT_EQ(false, (m_iter==omaps.end()));
  ASSERT_EQ(0, strcmp(m_iter->second.c_str(), "val1"));

  m_iter = omaps.find("key1");
  ASSERT_EQ(false, (m_iter==omaps.end()));
  ASSERT_EQ(0, strcmp(m_iter->second.c_str(), "val1"));


  m.cls_cxx_map_snap();
  // set key
  val1.clear();
  val1.append("1");
  r = m.cls_cxx_map_set_val(nullptr, "key1", &val1);
  ASSERT_EQ(0, r);
  r = m.cls_cxx_map_remove_key(nullptr, "key2");
  ASSERT_EQ(0, r);
  m.cls_cxx_map_apply();
  r = m.cls_cxx_map_flush(nullptr);
  ASSERT_EQ(0, r);

  r = m.cls_cxx_map_get_val(nullptr, "key1", &bl);
  ASSERT_EQ(0, r);
  ASSERT_EQ(0, strncmp(bl.c_str(), "1", 1));


  r = m.cls_cxx_map_get_val(nullptr, "key2", &bl);
  ASSERT_EQ(-ENOENT, r);
  r = m.cls_cxx_map_get_val(nullptr, "key3", &bl);
  ASSERT_EQ(0, r);
  ASSERT_EQ(0, strcmp(bl.c_str(), "val3"));

  m_iter = omaps.find("key1");
  ASSERT_EQ(false, (m_iter==omaps.end()));
  ASSERT_EQ(0, strncmp(m_iter->second.c_str(), "1", 1));

  m_iter = omaps.find("key2");
  ASSERT_EQ(true, (m_iter==omaps.end()));

  m_iter = omaps.find("key3");
  ASSERT_EQ(false, (m_iter==omaps.end()));
  ASSERT_EQ(0, strncmp(m_iter->second.c_str(), "val3", 4));
}
