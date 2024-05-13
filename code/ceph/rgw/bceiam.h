#ifndef BAIDU_BOS_CEPH_BCEIAM_H
#define BAIDU_BOS_CEPH_BCEIAM_H

#include <vector>
#include <string>
#include <sstream>
#include <map>
#include <list>
#include <algorithm>
#include <unordered_map>
#include <iostream>
#include "include/compat.h"
#include "include/buffer.h"

#include "common/ceph_json.h"
#include "common/Formatter.h"
#include "common/dout.h"
#include "rgw_http.h"
#include "rgw_common.h"

#ifdef WITH_RADOSGW_BEAST_FRONTEND
#include "asio_sync.hpp"
#endif

#define dout_context g_ceph_context
#define dout_subsys ceph_subsys_rgw

#define BEGIN_BCEIAM_NAMESPACE namespace bceiam {
#define END_BCEIAM_NAMESPACE } /* namespace bceiam */

BEGIN_BCEIAM_NAMESPACE

typedef enum {
    CODE_OK                             = 0,
    CODE_ACCESS_DENIED                  = 10,
    CODE_ACL_INTERNAL_ERROR             = 20,
    CODE_SIGNATURE_DOES_NOT_MATCH       = 30,
    CODE_INVALID_ARGUMENT               = 40,
    CODE_INTERNAL_ERROR                 = 50,
    CODE_OPT_IN_REQUIRED                = 60,
    CODE_INVALID_ACCESS_KEY             = 70,
    CODE_NEED_VERIFY                    = 80,
    CODE_NO_SUCH_BUCKET                 = 90,
    CODE_SOCKET_ERROR                   = 100,
    CODE_PARSE_ERROR                    = 110,
    CODE_BAD_AUTHORIZATION              = 2001,
    CODE_BAD_SIGNATURE                  = 2002,
    CODE_BAD_ACCESSKEY                  = 2003,
    CODE_BAD_SESSION_TOKEN              = 2007,
    CODE_NULL_SERVICE_TOKEN             = 2009
}error_code_t;

struct IamUserInfo {
    std::string name;
    std::string id;
    std::string subuser_id;
};

struct VerifyContext {
    struct Context {
        std::string        ip_address;
        std::string        referer;
        std::unordered_map<std::string, std::string> variables;
    };
    std::string            resource;
    std::string            service;
    std::string            region;
    std::list<std::string> permission;
    struct Context         request_context;
};

struct VerifyResponse {
    std::string effect;
    std::string id;
    std::string eid;
};

std::string CodeToStr(int code);
int check_user_auth_response(const std::string& verify_result);

class IamClientWrapper : public RGWHttpConnect {
    public:
        IamClientWrapper() {};
        IamClientWrapper(const IamClientWrapper& other) = delete;
        virtual ~IamClientWrapper();

        bool init();

        /** Judge the role of user. 
         * @param    ak                     [in]: user's ak 
         *
         * @return   CODE_OK: no need verify;
         *           CODE_NEED_VERIFY: subuser, need verify;
         *           others: refuse 
         * */
        int get_user_info(const req_state* s,
                          const std::string &ak,
                          IamUserInfo* iam_user_info,
                          JSONParser *parser) const;
 
        /* get sk from iam */
        std::string get_sk_from_ak(const req_state* s,
                                   const std::string &ak,
                                   JSONParser *parser);

        /** Verify permission with authorization signature.
         * @param    verify_context_list    [in]: resource need to bce verified
         * @param    subuser_id             [in]: subuser id 
         *
         * @return  result of verify ( look for reason via errorcode ).
         */
        int verify_subuser(const req_state* s,
                           std::list<VerifyContext>& verify_context_list,
                           const std::string &subuser_id,
                           JSONParser *parser) const;

        /** Verify permission by just forward request to iam.
         * @param    verify_context_list    [in]: resource need to bce verified
         * @param    iam_user_info          [out]: get user's account name and id 
         *
         * @return  result of verify ( look for reason via errorcode ).
         */
        int verify_sts_token(const req_state* s,
                             std::list<VerifyContext>& verify_context_list,
                             IamUserInfo* iam_user_info);

        int verify_batch_auth(const req_state* s,
                             std::string &req_id,
                             std::list<VerifyContext>& verify_context_list,
                             std::vector<string>& allowed_buckets);

    private:
        /* Iam Client, avoid to include client.h */
        int http_version{11};
        mutable std::string host;
        mutable std::string port;

        int transfer_http_code(int ret) const;

        string generate_sts_body(const req_state* s,
                 std::list<VerifyContext>& verify_context_list);

};

END_BCEIAM_NAMESPACE
#endif /* BAIDU_BOS_CEPH_BCEIAM_H */
// vim: et tw=100 ts=4 sw=4 cc=100:
