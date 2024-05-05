#include <iostream>
#include <boost/intrusive_ptr.hpp>
#include <boost/optional.hpp>
#include "global/global_init.h"
#include "common/ceph_json.h"
#include "common/Formatter.h"
#include "rgw/rgw_common.h"
#include "rgw/rgw_op.h"
#include "rgw/rgw_rados.h"
#include "test_rgw_common.h"
#include <gtest/gtest.h>
#include <gmock/gmock.h>

struct MockRGWOp : public RGWOp {
  int verify_permission() override {return 0;}
  void execute() override {}
  const string name() override { return "mock_rgwop"; }
};

TEST(RGWOp, CallbackParams1) {
  MockRGWOp op;
  RGWEnv env;
  boost::intrusive_ptr<CephContext> cct;
  cct = new CephContext(CEPH_ENTITY_TYPE_CLIENT);

  // wrong callba keyword
  string param = "callback/callbac,u_WyJodHRwOi8vMTAuMTkwLjc4LjI5Ojg3NjUvYXBpL3JhZG9zZ3cvY2FsbGJhY2siXQ==";
  req_state s1(cct->get(), &env, nullptr);
  s1.info.args.append("x-bce-process", param);
  op.init(nullptr, &s1, nullptr);
  EXPECT_EQ(op.process_callback("", ""), -ERR_INVALID_REQUEST);
}

TEST(RGWOp, CallbackParams2) {
  MockRGWOp op;
  RGWEnv env;
  boost::intrusive_ptr<CephContext> cct;
  cct = new CephContext(CEPH_ENTITY_TYPE_CLIENT);

  string param = "callback/callbac,u_WyJodHRwOi8vMTAuMTkwLjc4LjI5Ojg3NjUvYXBpL3JhZG9zZ3cvY2FsbGJhY2siXQ==";
  env.set("HTTP_X_BCE_PROCESS", param);
  req_state s2(cct->get(), &env, nullptr);
  op.init(nullptr, &s2, nullptr);
  EXPECT_EQ(op.process_callback("", ""), -ERR_INVALID_REQUEST);
}

TEST(RGWOp, CallbackParams3) {
  MockRGWOp op;
  RGWEnv env;
  boost::intrusive_ptr<CephContext> cct;
  cct = new CephContext(CEPH_ENTITY_TYPE_CLIENT);

  // wrong base64
  string param = "callback/callback,u_WyJodHRwOi8vMTAuMTkwLjc4LjI5Ojg3NjUvYXBpL3JhZG9zZ3cvY2FsbGJhY2siX==";
  req_state s1(cct->get(), &env, nullptr);
  s1.info.args.append("x-bce-process", param);
  op.init(nullptr, &s1, nullptr);
  EXPECT_EQ(op.process_callback("", ""), -ERR_INVALID_REQUEST);
}

TEST(RGWOp, CallbackParams4) {
  MockRGWOp op;
  RGWEnv env;
  RGWUserInfo user;
  boost::intrusive_ptr<CephContext> cct;
  cct = new CephContext(CEPH_ENTITY_TYPE_CLIENT);

  // vars longer than 1024
  string param = "callback/callback,u_WyJodHRwOi8vMTAuMTkwLjc4LjI5Ojg3NjUvYXBpL3JhZG9zZ3cvY2FsbGJhY2svIl0=,v_01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234";
  req_state s1(cct->get(), &env, &user);
  s1.info.args.append("x-bce-process", param);
  op.init(nullptr, &s1, nullptr);
  EXPECT_EQ(op.process_callback("", ""), -ERR_INVALID_REQUEST);
}
