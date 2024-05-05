#include <iostream>
#include <boost/intrusive_ptr.hpp>
#include <boost/optional.hpp>
#include "global/global_init.h"
#include "common/ceph_json.h"
#include "common/Formatter.h"
#include "rgw/rgw_common.h"
#include "rgw/rgw_auth.h"
#include "rgw/rgw_rados.h"
#include "test_rgw_common.h"
#include <gtest/gtest.h>
#include <gmock/gmock.h>

// # bos

// ## header
#ifdef WITH_BCEIAM
TEST(TestEnforcLocalOrder, BosHeader1) {
  RGWEnv env;
  string authorization = "bce-auth-v1/G131EFI0YVFQKS1JHEKF/2021-10-12T07:19:32Z/1800/host;x-bce-date/c795bca0a6d0a6ddb17f5ddaf146bbab81cd427097624a3e571d40e2a32cc80c";
  env.set("HTTP_AUTHORIZATION", authorization);
  boost::intrusive_ptr<CephContext> cct;
  cct = new CephContext(CEPH_ENTITY_TYPE_CLIENT);

  req_state s(cct->get(), &env, nullptr);
#ifdef WITH_BCEBOS
  s.prot_flags |= RGW_REST_BOS;
#endif
  EXPECT_EQ(enforce_local_order(&s), true);
}

TEST(TestEnforcLocalOrder, BosHeader2) {
  RGWEnv env;
  string authorization = "bce-auth-v1/G131EFI0YVFQKS1JHEKFA/2021-10-12T07:19:32Z/1800/host;x-bce-date/c795bca0a6d0a6ddb17f5ddaf146bbab81cd427097624a3e571d40e2a32cc80c";
  env.set("HTTP_AUTHORIZATION", authorization);
  boost::intrusive_ptr<CephContext> cct;
  cct = new CephContext(CEPH_ENTITY_TYPE_CLIENT);

  req_state s(cct->get(), &env, nullptr);
#ifdef WITH_BCEBOS
  s.prot_flags |= RGW_REST_BOS;
#endif
  EXPECT_EQ(enforce_local_order(&s), false);
}

// ## query string
TEST(TestEnforcLocalOrder, BosQueryString1) {
  RGWEnv env;
  boost::intrusive_ptr<CephContext> cct;
  cct = new CephContext(CEPH_ENTITY_TYPE_CLIENT);

  req_state s(cct->get(), &env, nullptr);
#ifdef WITH_BCEBOS
  s.prot_flags |= RGW_REST_BOS;
#endif
  string authorization = "bce-auth-v1/G131EFI0YVFQKS1JHEKF/2021-10-12T07:19:32Z/1800/host;x-bce-date/c795bca0a6d0a6ddb17f5ddaf146bbab81cd427097624a3e571d40e2a32cc80c";
  s.info.args.append("authorization", authorization);
  EXPECT_EQ(enforce_local_order(&s), true);
}

TEST(TestEnforcLocalOrder, BosQueryString2) {
  RGWEnv env;
  boost::intrusive_ptr<CephContext> cct;
  cct = new CephContext(CEPH_ENTITY_TYPE_CLIENT);

  req_state s(cct->get(), &env, nullptr);
#ifdef WITH_BCEBOS
  s.prot_flags |= RGW_REST_BOS;
#endif
  string authorization = "bce-auth-v1/G131EFI0YVFQKS1JHEKFA/2021-10-12T07:19:32Z/1800/host;x-bce-date/c795bca0a6d0a6ddb17f5ddaf146bbab81cd427097624a3e571d40e2a32cc80c";
  s.info.args.append("authorization", authorization);
  EXPECT_EQ(enforce_local_order(&s), false);
}

// # s3

// ## v4 header
TEST(TestEnforcLocalOrder, S3V4Header1) {
  RGWEnv env;
  string authorization = "AWS4-HMAC-SHA256 Credential=G131EFI0YVFQKS1JHEKF/20211012/cn/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=73794f085ad49717e4d5c289cf02c57fe8e30af99bcf4eb3300951271d95a9b3";
  env.set("HTTP_AUTHORIZATION", authorization);
  boost::intrusive_ptr<CephContext> cct;
  cct = new CephContext(CEPH_ENTITY_TYPE_CLIENT);

  req_state s(cct->get(), &env, nullptr);
#ifdef WITH_BCEBOS
  s.prot_flags |= RGW_REST_BOS;
#endif
  EXPECT_EQ(enforce_local_order(&s), true);
}

TEST(TestEnforcLocalOrder, S3V4Header2) {
  RGWEnv env;
  string authorization = "AWS4-HMAC-SHA256 Credential=G131EFI0YVFQKS1JHEKFA/20211012/cn/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=73794f085ad49717e4d5c289cf02c57fe8e30af99bcf4eb3300951271d95a9b3";
  env.set("HTTP_AUTHORIZATION", authorization);
  boost::intrusive_ptr<CephContext> cct;
  cct = new CephContext(CEPH_ENTITY_TYPE_CLIENT);

  req_state s(cct->get(), &env, nullptr);
#ifdef WITH_BCEBOS
  s.prot_flags |= RGW_REST_BOS;
#endif
  EXPECT_EQ(enforce_local_order(&s), false);
}

// ## v4 query string
TEST(TestEnforcLocalOrder, S3V4QueryString1) {
  RGWEnv env;
  boost::intrusive_ptr<CephContext> cct;
  cct = new CephContext(CEPH_ENTITY_TYPE_CLIENT);

  req_state s(cct->get(), &env, nullptr);
#ifdef WITH_BCEBOS
  s.prot_flags |= RGW_REST_BOS;
#endif
  s.info.args.append("X-Amz-Algorithm", "AWS4-HMAC-SHA256");
  s.info.args.append("X-Amz-Credential", "G131EFI0YVFQKS1JHEKF/20211012/cn/s3/aws4_request");
  EXPECT_EQ(enforce_local_order(&s), true);
}

TEST(TestEnforcLocalOrder, S3V4QueryString2) {
  RGWEnv env;
  boost::intrusive_ptr<CephContext> cct;
  cct = new CephContext(CEPH_ENTITY_TYPE_CLIENT);

  req_state s(cct->get(), &env, nullptr);
#ifdef WITH_BCEBOS
  s.prot_flags |= RGW_REST_BOS;
#endif
  s.info.args.append("X-Amz-Algorithm", "AWS4-HMAC-SHA256");
  s.info.args.append("X-Amz-Credential", "G131EFI0YVFQKS1JHEKFA/20211012/cn/s3/aws4_request");
  EXPECT_EQ(enforce_local_order(&s), false);
}

// ## v2 header

TEST(TestEnforcLocalOrder, S3V2Header1) {
  RGWEnv env;
  string authorization = "AWS G131EFI0YVFQKS1JHEKF:dl6cwwwIlUUzUv5QYQ6hhfdOPcM=";
  env.set("HTTP_AUTHORIZATION", authorization);
  boost::intrusive_ptr<CephContext> cct;
  cct = new CephContext(CEPH_ENTITY_TYPE_CLIENT);

  req_state s(cct->get(), &env, nullptr);
#ifdef WITH_BCEBOS
  s.prot_flags |= RGW_REST_BOS;
#endif
  EXPECT_EQ(enforce_local_order(&s), true);
}

TEST(TestEnforcLocalOrder, S3V2Header2) {
  RGWEnv env;
  string authorization = "AWS G131EFI0YVFQKS1JHEKFA:dl6cwwwIlUUzUv5QYQ6hhfdOPcM=";
  env.set("HTTP_AUTHORIZATION", authorization);
  boost::intrusive_ptr<CephContext> cct;
  cct = new CephContext(CEPH_ENTITY_TYPE_CLIENT);

  req_state s(cct->get(), &env, nullptr);
#ifdef WITH_BCEBOS
  s.prot_flags |= RGW_REST_BOS;
#endif
  EXPECT_EQ(enforce_local_order(&s), false);
}

// ## v2 query string

TEST(TestEnforcLocalOrder, S3V2QueryString1) {
  RGWEnv env;
  boost::intrusive_ptr<CephContext> cct;
  cct = new CephContext(CEPH_ENTITY_TYPE_CLIENT);

  req_state s(cct->get(), &env, nullptr);
#ifdef WITH_BCEBOS
  s.prot_flags |= RGW_REST_BOS;
#endif
  s.info.args.append("AWSAccessKeyId", "G131EFI0YVFQKS1JHEKF");
  EXPECT_EQ(enforce_local_order(&s), true);
}

TEST(TestEnforcLocalOrder, S3V2QueryString2) {
  RGWEnv env;
  boost::intrusive_ptr<CephContext> cct;
  cct = new CephContext(CEPH_ENTITY_TYPE_CLIENT);

  req_state s(cct->get(), &env, nullptr);
#ifdef WITH_BCEBOS
  s.prot_flags |= RGW_REST_BOS;
#endif
  s.info.args.append("AWSAccessKeyId", "G131EFI0YVFQKS1JHEKFA");
  EXPECT_EQ(enforce_local_order(&s), false);
}

// # anonymous
TEST(TestEnforcLocalOrder, Anonymous1) {
  RGWEnv env;
  boost::intrusive_ptr<CephContext> cct;
  cct = new CephContext(CEPH_ENTITY_TYPE_CLIENT);

  req_state s(cct->get(), &env, nullptr);
#ifdef WITH_BCEBOS
  s.prot_flags |= RGW_REST_BOS;
#endif
  EXPECT_EQ(enforce_local_order(&s), false);
}

TEST(TestEnforcLocalOrder, Anonymous2) {
  RGWEnv env;
  boost::intrusive_ptr<CephContext> cct;
  cct = new CephContext(CEPH_ENTITY_TYPE_CLIENT);

  req_state s(cct->get(), &env, nullptr);
#ifdef WITH_BCEBOS
  s.prot_flags |= RGW_REST_BOS;
#endif
  EXPECT_EQ(enforce_local_order(&s), false);
}
#endif
