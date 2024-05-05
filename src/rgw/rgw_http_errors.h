// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#ifndef RGW_HTTP_ERRORS_H_
#define RGW_HTTP_ERRORS_H_

#include "rgw_common.h"

#define dout_subsys ceph_subsys_rgw
#define dout_context g_ceph_context

typedef const std::map<int,const std::pair<int, const char*>> rgw_http_errors;

typedef const std::map<int,const std::tuple<int, const char*, const char*>> rgw_http_errors_plus_msg;

extern rgw_http_errors rgw_http_s3_errors;

extern rgw_http_errors_plus_msg rgw_http_bos_errors;

extern rgw_http_errors rgw_http_swift_errors;

static inline int rgw_http_error_to_errno(int http_err)
{
  if (http_err >= 200 && http_err <= 299)
    return 0;
  switch (http_err) {
    case 304:
      return -ERR_NOT_MODIFIED;
    case 400:
      return -EINVAL;
    case 401:
      return -EPERM;
    case 403:
        return -EACCES;
    case 404:
        return -ENOENT;
    case 409:
        return -ENOTEMPTY;
    case 412:
        return -ERR_PRECONDITION_FAILED;
    case 429:
        return -EAGAIN;
    default:
        if (http_err < 500) {
          dout(0) << "WARNING: unexpected http err code:" << http_err << dendl;
          return -EAGAIN;
        }
        dout(0) << "ERROR: http err code:" << http_err << dendl;
        return -EIO;
  }

  return 0; /* unreachable */
}


#endif
