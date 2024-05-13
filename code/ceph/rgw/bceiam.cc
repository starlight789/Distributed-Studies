#include "include/str_list.h"

#include "bceiam.h"

BEGIN_BCEIAM_NAMESPACE

IamClientWrapper::~IamClientWrapper() {
}

bool IamClientWrapper::init() {
    // TODO: Send ack to the iam proxy
    bool ok =  true;
    return ok;
}

std::string IamClientWrapper::get_sk_from_ak(const req_state* s,
                                             const std::string &ak,
                                             JSONParser *parser) {
  std::stringstream ss;
  ss << "/iam/v1/get_sk?ak=" << ak.c_str();
  std::string target = ss.str();
  std::string request_body = "";
  bufferlist response_body;

  int ret = http_connect(s, target, "post", request_body, response_body);
  if (ret != 0 || response_body.length() == 0) {
      return "";
  }

  // parse response
  std::string sk;
  bool r = parser->parse(response_body.c_str(), response_body.length());
  if (!r)
    return "";

  try {
    JSONDecoder::decode_json("sk", sk, parser, true);
  } catch (JSONDecoder::err& e) {
    return "";
  }

  return sk;
}

int IamClientWrapper::get_user_info(const req_state* s,
                                    const std::string &ak,
                                    IamUserInfo* iam_user_info,
                                    JSONParser *parser) const {
  std::stringstream ss;
  ss << "/iam/v1/get_user_info?ak=" << ak.c_str();
  std::string target = ss.str();
  std::string request_body = "";
  bufferlist response_body;

  // send request and get response
  int ret = http_connect(s, target, "post", request_body, response_body);
  if (ret != 0 || response_body.length() == 0) {
    return -EACCES;
  }

  // paser response
  int err_code = 0;
  std::string account_type;
  std::string account_name;
  std::string account_id;
  std::string subuser_id;
  bool r = parser->parse(response_body.c_str(), response_body.length());
  if (!r)
    return -ERR_INTERNAL_ERROR;

  try {
    JSONDecoder::decode_json("errcode", err_code, parser);
    JSONDecoder::decode_json("account_type", account_type, parser);
    JSONDecoder::decode_json("account_name", account_name, parser);
    JSONDecoder::decode_json("account_id", account_id, parser);
    JSONDecoder::decode_json("subuser_id", subuser_id, parser);
  } catch (JSONDecoder::err& e) {
    return -ERR_INTERNAL_ERROR;
  }

  // diffrent account types
  if (err_code == 1000) {
    return -EACCES;
  }

  if (!account_type.compare("subuser")) {
    iam_user_info->name = account_name;
    iam_user_info->id = account_id;
    iam_user_info->subuser_id = subuser_id;
    return CODE_NEED_VERIFY;
  } else {
    iam_user_info->name = account_name;
    iam_user_info->id = account_id;
    return CODE_OK;
  }
}

int IamClientWrapper::verify_subuser(const req_state* s,
                                     std::list<VerifyContext>& verify_context_list,
                                     const std::string &subuser_id,
                                     JSONParser *parser) const {
  // create req body
  ceph::JSONFormatter f;
  f.open_object_section("Reqbody");
  f.open_array_section("verify_contexts");
  for (auto& it : verify_context_list) {
    f.open_object_section("verify_context");
    f.dump_string("resource", it.resource);
    f.dump_string("service", it.service);
    f.dump_string("region", it.region);
    f.open_array_section("permission");
    std::stringstream perm_ss;
    for (const auto& perm : it.permission) {
        perm_ss << "\"" << perm << "\", ";
    }
    std::string perm_str = perm_ss.str();
    f.write_raw_data(perm_str.substr(0, perm_str.size()-2).c_str());
    f.close_section(); // end of permission
    f.open_object_section("request_context");
    f.open_object_section("context");
    f.dump_string("ip_address", it.request_context.ip_address);
    f.dump_string("referer", it.request_context.referer);
    f.open_array_section("variables");
    f.open_object_section("variable");
    f.dump_string("organizationId", it.request_context.variables["organizationId"]);
    f.dump_string("resourceGroupId", it.request_context.variables["resourceGroupId"]);
    f.close_section(); // end of variable
    f.close_section(); // end of variables
    f.close_section(); // end of context
    f.close_section(); // end of request_context;
    f.close_section(); // end of verify_context
  }
  f.close_section(); // end of verify_contexts
  f.close_section(); // end of Reqbody

  // send req to iam proxy
  std::stringstream ss;
  ss << "/iam/v1/verify_user?user_id=" << subuser_id.c_str();
  std::string target = ss.str();
  std::string request_body = f.get_m_ss();
  bufferlist response_body;

  // send request and get response
  dout(20) << __func__ << " request_body: " << request_body << " req_id: " << s->trans_id << " target: " << target << dendl;
  int ret = http_connect(s, target, "post", request_body, response_body);
  if (ret != 0 || response_body.length() == 0) {
    return CODE_SOCKET_ERROR;
  }

  // parse and process the response
  int err_code = 0;
  std::string verify_result;
  bool r = parser->parse(response_body.c_str(), response_body.length());
  if (!r) {
    return CODE_PARSE_ERROR;
  }

  try {
    JSONDecoder::decode_json("errcode", err_code, parser);

    if (err_code == 0) {
      JSONDecoder::decode_json("verify_result", verify_result, parser);
      ret = check_user_auth_response(verify_result);
    } else {
      string err_msg;
      JSONDecoder::decode_json("errmsg", err_msg, parser);
      ldout(s->cct, 10) << "proxy return err, ret:" << ret
                        << ", errcode:" << err_code << ", errmsg:" << err_msg
                        << dendl;
      ret = err_code;
    }
  } catch (JSONDecoder::err& e) {
    return -ERR_INTERNAL_ERROR;
  }

  dout(30) << __func__ << "(): req_id=" << s->trans_id
           << ", iam result=" << CodeToStr(ret)
           << dendl;
  return transfer_http_code(ret);
}

int IamClientWrapper::transfer_http_code(int ret) const {
  if (ret == CODE_OK) {
    return 0;
  } else if (ret == CODE_NO_SUCH_BUCKET) {
    return -ERR_NO_SUCH_BUCKET;
  } else if (ret == CODE_BAD_SESSION_TOKEN || ret == CODE_NULL_SERVICE_TOKEN) {
    return -ERR_INVALID_SESSION_TOKEN;
  } else if (ret == CODE_SIGNATURE_DOES_NOT_MATCH ||
             ret == CODE_BAD_SIGNATURE ||
             ret == CODE_BAD_AUTHORIZATION ||
             ret == CODE_BAD_ACCESSKEY) {
    return -ERR_SIGNATURE_NO_MATCH;
  } else {
    return -EACCES;
  }
}

int IamClientWrapper::verify_sts_token(const req_state* s,
                                       std::list<VerifyContext>& verify_context_list,
                                       IamUserInfo* iam_user_info) {
  string body = generate_sts_body(s, verify_context_list);
  bufferlist resp_bl;

  // send req to iam proxy
  std::string target = "/iam/v1/verify_sts/";

  // send request and get response
  int ret = http_connect(s, target, "post", body, resp_bl);
  if (ret < 0 || resp_bl.length() == 0) {
    ldout(s->cct, 0) << "connect to proxy err, ret:" << ret << dendl;
    return -EACCES;
  }

  // parse and process the response
  int err_code = 0;
  JSONParser parser;
  bool r = parser.parse(resp_bl.c_str(), resp_bl.length());
  if (!r) {
    ldout(s->cct, 0) << __func__ << "(): parse response body error:"
                      << resp_bl.to_str() << dendl;
    return -ERR_INTERNAL_ERROR;
  }

  try {
    JSONDecoder::decode_json("errcode", err_code, &parser);

    ret = CODE_OK;
    if (err_code == 0) {
      string verify_result;
      JSONDecoder::decode_json("verify_result", verify_result, &parser);
      ldout(s->cct, 30) << __func__ << "(): proxy return verify_result:"
                        << verify_result << dendl;
      ret = check_user_auth_response(verify_result);
    } else {
      string err_msg;
      JSONDecoder::decode_json("errmsg", err_msg, &parser);
      ldout(s->cct, 10) << "proxy return err, ret:" << ret
                        << ", errcode:" << err_code << ", errmsg:" << err_msg
                        << dendl;
      ret = err_code;
    }

    if (ret == CODE_OK) {
      JSONDecoder::decode_json("account_name", iam_user_info->name, &parser);
      JSONDecoder::decode_json("account_id", iam_user_info->id, &parser);
      JSONDecoder::decode_json("subuser_id", iam_user_info->subuser_id, &parser);
      return 0;
    } else {
      return transfer_http_code(ret);
    }
  } catch (JSONDecoder::err& e) {
    return -ERR_INTERNAL_ERROR;
  }
}

int IamClientWrapper::verify_batch_auth(const req_state* s,
                                       std::string &req_id,
                                       std::list<VerifyContext>& verify_context_list,
                                       std::vector<string>& allowed_buckets) {
  string body = generate_sts_body(s, verify_context_list);
  bufferlist resp_bl;

  // send req to iam proxy
  std::string target = "/iam/v1/verify_batch_auth/";

  // send request and get response
    int ret = http_connect(s, target, "post", body, resp_bl);
    if (ret != 0 || resp_bl.length() == 0) {
        ldout(s->cct, 0) << "connect to proxy err, ret:" << ret << dendl;
        return -EINVAL;
    }

    // parse and process the response
    int err_code = 0;
    JSONParser parser;
    bool r = parser.parse(resp_bl.c_str(), resp_bl.length());
    if (!r) {
      ldout(s->cct, 0) << __func__ << "(): parse response body error:"
                        << resp_bl.to_str() << dendl;
      return -ERR_SERVICE_UNAVAILABLE;
    }
    JSONDecoder::decode_json("errcode", err_code, &parser);

    ret = CODE_OK;
    if (err_code == 0) {
      string verify_result;
      JSONDecoder::decode_json("verify_result", verify_result, &parser);
      ldout(s->cct, 30) << __func__ << "(): proxy return verify_result:"
                        << verify_result << dendl;
      boost::split(allowed_buckets, verify_result, boost::is_any_of(","));
    } else {
      string err_msg;
      JSONDecoder::decode_json("errmsg", err_msg, &parser);
      ldout(s->cct, 20) << "proxy return err, ret:" << ret
                        << ", errmsg:" << err_msg
                        << dendl;
      ret = CODE_ACL_INTERNAL_ERROR;
    }
    return transfer_http_code(ret);
}

string IamClientWrapper::generate_sts_body(const req_state* s,
                           std::list<VerifyContext>& verify_context_list) {
  ceph::JSONFormatter f;
  f.open_object_section("Reqbody");
  string uri = s->info.request_uri;
  size_t pos = std::string::npos;
  if (s->info.domain_trans) {
    if (uri[0] == '/' && uri.length() > 2) {
      uri = uri.substr(1);
      pos = uri.find("/");
    } else {
      ldout(s->cct, 0) << "Error: request_uri:" << s->info.request_uri << ", bucket_name:" << s->bucket_name << dendl;
    }
  }

  if (pos != std::string::npos) {
    f.dump_string("uri", url_decode(uri.substr(pos)));
  } else {
    f.dump_string("uri", url_decode(s->info.request_uri));
  }
  f.dump_string("method", s->info.method);
  const std::map<string, string, ltstr_nocase>& env_map = s->info.env->get_map();

  f.open_array_section("headers");
  for (auto m : env_map) {
    ldout(s->cct, 30) << "Header" << m.first << ":"<< m.second << dendl;
    if (!boost::algorithm::starts_with(m.first, "HTTP_") && m.first != "CONTENT_TYPE"
                                        && m.first != "CONTENT_LENGTH")
      continue;
    f.open_object_section("header");

    string header = m.first;
    if (m.first != "CONTENT_LENGTH" && m.first != "CONTENT_TYPE")
      header = m.first.substr(strlen("HTTP_"), m.first.size());
    if (header.find('-') != std::string::npos) {
      for (auto it = header.begin(); it != header.end(); ++it) {
        if (*it == '-') {
          *it = '_';
        } else if (*it == '_') {
          *it = '-';
        }
      }
    } else {
      boost::replace_all(header, "_", "-");
    }

    f.dump_string("key", header);
    f.dump_string("value", m.second);
    f.close_section();  // end of one header
  }
  f.close_section();  //end of headers


  if (s->info.request_params.length() != 0) {
    f.open_array_section("params");
    for (const auto& p : get_str_vec(s->info.request_params, "&")) {
      boost::string_view key, val;
      const auto parsed_pair = parse_key_value(p);
      if (parsed_pair) {
        std::tie(key, val) = *parsed_pair;
      } else {
        /* Handling a parameter without any value (even the empty one). That's
         * it, we've encountered something like "this_param&other_param=val"
         * which is used by S3 for subresources. */
        key = p;
        val = "";
      }
      f.open_object_section("param");
      f.dump_string("key", string(key));
      f.dump_string("value", url_decode(string(val)));
      f.close_section(); // end of param
    }
    f.close_section();  //end of params
  }

  f.open_array_section("verify_contexts");
  for (auto& it : verify_context_list) {
    f.open_object_section("context");
    f.dump_string("resource", it.resource);
    f.dump_string("service", it.service);
    f.dump_string("region", it.region);
    f.open_array_section("permission");
    std::stringstream perm_ss;
    for (const auto& perm : it.permission) {
        perm_ss << "\"" <<perm << "\", ";
    }
    std::string perm_str = perm_ss.str();
    if (perm_str.length() >= 2) {
      f.write_raw_data(perm_str.substr(0, perm_str.length()-2).c_str());
    }
    f.close_section(); // end of permission
    f.open_object_section("request_context");
    f.dump_string("ip_address", it.request_context.ip_address);
    f.dump_string("referer", it.request_context.referer);
    f.open_array_section("variables");
    f.open_object_section("v");
    //f.write_raw_data("{\n");
    if (it.request_context.variables.size() > 0) {
      f.dump_string("organizationId", it.request_context.variables["organizationId"]);
      f.dump_string("resourceGroupId", it.request_context.variables["resourceGroupId"]);
    }
    //f.write_raw_data("\n}");
    f.close_section(); // end of v
    f.close_section(); // end of variables
    f.close_section(); // end of request_context;
    f.close_section(); // end of context
  }
  f.close_section(); // end of verify_contexts

  f.close_section(); // end of Reqbody

  std::string request_body = f.get_m_ss();
  return request_body;
}


int check_user_auth_response(const std::string& verify_result) {
  if (!verify_result.compare("allow")) {
    return CODE_OK;
  } else if (!verify_result.compare("deny")) {
    return CODE_ACCESS_DENIED;
  } else if (!verify_result.compare("bad_acl_format")
              || !verify_result.compare("bad_auth_format")) {
    return CODE_SIGNATURE_DOES_NOT_MATCH;
  } else {
    return CODE_ACL_INTERNAL_ERROR;
  }
}

std::string CodeToStr(int code) {
  switch (code) {
    case CODE_OK:
      return "CODE_OK";
    case CODE_ACCESS_DENIED:
      return "CODE_ACCESS_DENIED";
    case CODE_ACL_INTERNAL_ERROR:
      return "CODE_ACL_INTERNAL_ERROR";
    case CODE_SIGNATURE_DOES_NOT_MATCH:
      return "CODE_SIGNATURE_DOES_NOT_MATCH";
    case CODE_INVALID_ACCESS_KEY:
      return "CODE_INVALID_ACCESS_KEY";
    default:
      return "UNKNOWN";
  }
}

END_BCEIAM_NAMESPACE

