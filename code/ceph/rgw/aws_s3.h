#ifndef BAIDU_BOS_CEPH_AWSS3_H
#define BAIDU_BOS_CEPH_AWSS3_H

#include <string>
#include "rgw_common.h"

#define BEGIN_AWSS3_NAMESPACE namespace awss3 {
#define END_AWSS3_NAMESPACE } /* namespace awss3 */

BEGIN_AWSS3_NAMESPACE

std::string get_presign_url(const req_state* const s, const std::string& host, const std::string& ak,
                            const std::string& sk, const std::string& bucket, const std::string& object);

END_AWSS3_NAMESPACE
#endif /* BAIDU_BOS_CEPH_AWSS3_H */
