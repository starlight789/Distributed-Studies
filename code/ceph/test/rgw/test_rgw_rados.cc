#include <iostream>
#include <boost/intrusive_ptr.hpp>
#include <boost/optional.hpp>
#include "global/global_init.h"
#include "common/ceph_json.h"
#include "common/Formatter.h"
#include "rgw/rgw_common.h"
#include "rgw/rgw_op.h"
#include "rgw/rgw_rados.h"
#include "rgw/rgw_throttle.h"

#include "include/rados/librados.hpp"
#include "test_rgw_common.h"
#include <gtest/gtest.h>
#include <gmock/gmock.h>

class MockRados : public librados::Rados {
  int mon_command(std::string cmd, const bufferlist& inbl,
        bufferlist *outbl, std::string *outs) override {
    string result = "{\"servicemap\":{\"services\":{\"rgw\":{\"daemons\":{\"summary\":\"\",\"rgw@10.190.78.14\":{\"start_epoch\":36,\"start_stamp\":\"2022-09-06 20:04:20.151673\",\"gid\":113763,\"addr\":\"10.190.78.14:0/152537101\"}}}}}}";
    outbl->append(result.c_str(), result.length());
    return 0;
  }
};

class MockRGWRados : public RGWRados {
  librados::Rados* get_rados_handle() override {
    return new MockRados();
  }
};

TEST(RGWRados, CanReplaceRenaming1) {
  // rgw exists, not timeout
  librados::Rados rados;
  char *id = getenv("CEPH_CLIENT_ID");

  int ret = rados.init(id);
  if (ret) std::cerr << "Rados.init failed with error: " << ret << std::endl;

  g_ceph_context = reinterpret_cast<CephContext*>(rados.cct());
  boost::intrusive_ptr<CephContext> cct;
  cct = new CephContext(CEPH_ENTITY_TYPE_CLIENT);

  MockRGWRados mock_store;
  ThrottleManager::instance().init(cct->get(), static_cast<RGWRados*>(&mock_store));

  RGWRenameSrcInfo rename_info1("",
                                "",
                                "",
                                nullptr);

  rgw_client.update_time = mono_clock::now();
  rgw_client.rgw_client_id = "rgw@10.190.78.14";
  rgw_client.rgw_client_id += RGW_CLIENT_ID_SEPARATOR;
  rgw_client.rgw_client_id = "36";

  EXPECT_TRUE(can_replace_renaming(rename_info1, 10));
}

TEST(RGWRados, CanReplaceRenaming2) {
  // rgw exists, timeout
  librados::Rados rados;
  char *id = getenv("CEPH_CLIENT_ID");

  int ret = rados.init(id);
  if (ret) std::cerr << "Rados.init failed with error: " << ret << std::endl;

  g_ceph_context = reinterpret_cast<CephContext*>(rados.cct());
  boost::intrusive_ptr<CephContext> cct;
  cct = new CephContext(CEPH_ENTITY_TYPE_CLIENT);

  MockRGWRados mock_store;
  ThrottleManager::instance().init(cct->get(), static_cast<RGWRados*>(&mock_store));

  RGWRenameSrcInfo rename_info1("",
                                "",
                                "",
                                nullptr);

  rgw_client.update_time = mono_clock::now();
  rgw_client.rgw_client_id = "rgw@10.190.78.14";
  rgw_client.rgw_client_id += RGW_CLIENT_ID_SEPARATOR;
  rgw_client.rgw_client_id = "36";

  EXPECT_TRUE(can_replace_renaming(rename_info1, 0));
}

class MockBadRados : public librados::Rados {
  int mon_command(std::string cmd, const bufferlist& inbl,
        bufferlist *outbl, std::string *outs) override {
    return -1;
  }
};

class MockBadRGWRados : public RGWRados {
  librados::Rados* get_rados_handle() override {
    return new MockBadRados();
  }
};

TEST(RGWRados, CanReplaceRenaming3) {
  // rgw not exists, not timeout
  librados::Rados rados;
  char *id = getenv("CEPH_CLIENT_ID");

  int ret = rados.init(id);
  if (ret) std::cerr << "Rados.init failed with error: " << ret << std::endl;

  g_ceph_context = reinterpret_cast<CephContext*>(rados.cct());
  // get mon rgws, body isn't json format
  boost::intrusive_ptr<CephContext> cct;
  cct = new CephContext(CEPH_ENTITY_TYPE_CLIENT);

  MockBadRGWRados mock_bad_store;
  ThrottleManager::instance().init(cct->get(), static_cast<RGWRados*>(&mock_bad_store));

  RGWRenameSrcInfo rename_info1("",
                                "",
                                "",
                                nullptr);

  rgw_client.rgw_client_id = "";

  rgw_client.update_time = mono_clock::now() - make_timespan(2 * UPDATE_RGWS_INTERVAL + 1);

  EXPECT_FALSE(can_replace_renaming(rename_info1, 10));
}

TEST(RGWRados, CanReplaceRenaming4) {
  // rgw not exists, timeout
  librados::Rados rados;
  char *id = getenv("CEPH_CLIENT_ID");

  int ret = rados.init(id);
  if (ret) std::cerr << "Rados.init failed with error: " << ret << std::endl;

  g_ceph_context = reinterpret_cast<CephContext*>(rados.cct());
  // get mon rgws, body isn't json format
  boost::intrusive_ptr<CephContext> cct;
  cct = new CephContext(CEPH_ENTITY_TYPE_CLIENT);

  MockBadRGWRados mock_bad_store;
  ThrottleManager::instance().init(cct->get(), static_cast<RGWRados*>(&mock_bad_store));

  RGWRenameSrcInfo rename_info1("",
                                "",
                                "",
                                nullptr);

  rgw_client.rgw_client_id = "";

  rgw_client.update_time = mono_clock::now() - make_timespan(2 * UPDATE_RGWS_INTERVAL + 1);

  EXPECT_FALSE(can_replace_renaming(rename_info1, 0));
}

TEST(RGWRados, GetRenamingInfo1) {
  librados::Rados rados;
  char *id = getenv("CEPH_CLIENT_ID");

  int ret = rados.init(id);
  if (ret) std::cerr << "Rados.init failed with error: " << ret << std::endl;
  g_ceph_context = reinterpret_cast<CephContext*>(rados.cct());

  RGWRados store;
  store.set_context(reinterpret_cast<CephContext*>(rados.cct()));

  string key = "";
  string test_key = RGW_ATTR_RENAME_SOURCE + string("123456");
  bufferlist bl1;
  map<string, bufferlist> attrs;
  attrs[test_key] = bl1;

  std::tie(ret, key) = store.get_renaming_info(attrs, test_key);
  EXPECT_EQ(ret, -EIO);
  EXPECT_EQ(key.length(), 0);
}

TEST(RGWRados, GetRenamingInfo2) {
  librados::Rados rados;
  char *id = getenv("CEPH_CLIENT_ID");

  int ret = rados.init(id);
  if (ret) std::cerr << "Rados.init failed with error: " << ret << std::endl;
  g_ceph_context = reinterpret_cast<CephContext*>(rados.cct());

  RGWRados store;
  store.set_context(reinterpret_cast<CephContext*>(rados.cct()));

  string key = "";
  string test_idtag = "asdfwerblwer";
  string test_key = RGW_ATTR_RENAME_SOURCE + string("123456");
  RGWObjManifest manifest;
  bufferlist bl1;
  RGWRenameSrcInfo info("",
                      test_idtag,
                      "",
                      &manifest);
  encode(info, bl1);
  map<string, bufferlist> attrs;
  attrs[test_key] = bl1;

  std::tie(ret, key) = store.get_renaming_info(attrs, test_idtag);
  EXPECT_EQ(ret, 0);
  EXPECT_EQ(key.length(), test_key.length());
}

TEST(RGWRados, GetRenamingInfo3) {
  librados::Rados rados;
  char *id = getenv("CEPH_CLIENT_ID");

  int ret = rados.init(id);
  if (ret) std::cerr << "Rados.init failed with error: " << ret << std::endl;
  g_ceph_context = reinterpret_cast<CephContext*>(rados.cct());

  RGWRados store;
  store.set_context(reinterpret_cast<CephContext*>(rados.cct()));

  string key = "";
  string test_idtag = "asdfwerblwer";
  string test_idtag2 = "asdfwerblwer2";
  string test_key = RGW_ATTR_RENAME_SOURCE + string("123456");
  RGWObjManifest manifest;
  bufferlist bl1;
  RGWRenameSrcInfo info("",
                      test_idtag,
                      "",
                      &manifest);
  encode(info, bl1);
  map<string, bufferlist> attrs;
  attrs[test_key] = bl1;

  std::tie(ret, key) = store.get_renaming_info(attrs, test_idtag2);
  EXPECT_EQ(ret, ENOENT);
  EXPECT_EQ(key.length(), 0);
}
