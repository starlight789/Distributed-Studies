#include <string.h>

#include <iostream>
#include <map>

#include "include/ipaddr.h"
#include "include/types.h"

#include "rgw_mirroring.h"
#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string/trim_all.hpp>

#define dout_context g_ceph_context
#define dout_subsys ceph_subsys_rgw

void MirroringCustomHeader::decode_json(JSONObj* obj) {
  JSONDecoder::decode_json("headerName", name, obj);
  JSONDecoder::decode_json("headerValue", value, obj);
}

void MirroringCustomHeader::dump(Formatter *f) const {
  encode_json("headerName", name, f);
  encode_json("headerValue", value, f);
}

void MirroringConfiguration::decode_json(JSONObj* obj) {
  JSONDecoder::decode_json("prefix", prefix, obj);
  JSONDecoder::decode_json("sourceUrl", source_url, obj);
  JSONDecoder::decode_json("passQuerystring", pass_querystring, obj);
  JSONDecoder::decode_json("mode", mode, obj);
  if (mode.empty()) mode = "fetch";
  JSONDecoder::decode_json("storageClass", storage_class, obj);
  JSONDecoder::decode_json("passHeaders", pass_headers, obj);
  JSONDecoder::decode_json("ignoreHeaders", ignore_headers, obj);
  JSONDecoder::decode_json("customHeaders", custom_headers, obj);
}

void MirroringConfiguration::dump(Formatter *f) const {
  encode_json("prefix", prefix, f);
  encode_json("sourceUrl", source_url, f);
  f->dump_bool("passQuerystring", pass_querystring);
  encode_json("mode", mode, f);
  encode_json("storageClass", storage_class, f);
  encode_json("passHeaders", pass_headers, f);
  encode_json("ignoreHeaders", ignore_headers, f);
  encode_json("customHeaders", custom_headers, f);
}


map<string, bool> RGWMirroringConfiguration::unallowed_headers = {
  {"content-length", true},
  {"content-type", true},
  {"authorization", true},
  {"range", true},
  {"date", true},
  {"content-md5", true},
  {"host", true},
};

void RGWMirroringConfiguration::decode_json(JSONObj* obj) {
  decode_json_obj(configurations, obj);
}

void RGWMirroringConfiguration::dump(Formatter *f) const {
  encode_json("bucketMirroringConfiguration", configurations, f);
}

bool RGWMirroringConfiguration::is_blacklists_refused(string& endpoint, vector<string>& blacklists)
{
  auto pos = endpoint.find("://");
  if (pos == std::string::npos) {
    dout(0) << "url not starts_with http" << endpoint << dendl;
    return true;
  }
  string_view sv = string_view(endpoint.c_str(), endpoint.length()).substr(pos + strlen("://"));
  if (sv.length() == 0) {
    dout(0) << "url is illegal" << endpoint << dendl;
    return true;
  }

  pos = sv.find("/");
  if (pos != std::string::npos) {
    sv = sv.substr(0, pos);
  }
  for (auto blacklist : blacklists) {

    if (blacklist.empty()) continue;

    if (isdigit(char(blacklist[0])) && isdigit(char(sv[0]))) {
      // ip blacklist
      pos = blacklist.find("/");
      if (pos != std::string::npos) {
        // netmask
        struct sockaddr_storage net;
        unsigned int prefix_len;

        if (!parse_network(blacklist.c_str(), &net, &prefix_len)) {
          dout(0) << "ERROR: unable to parse network: " << blacklist << dendl;
          return true;
        }

        struct in_addr temp;
        struct in_addr filtered, match;

        auto port_pos = sv.find(":");
        if (port_pos != std::string::npos) {
          inet_aton(string(sv.substr(0, port_pos)).c_str(), &temp);
        } else {
          inet_aton(sv.data(), &temp);
        }

        netmask_ipv4(&temp, prefix_len, &filtered);
        netmask_ipv4(&(((struct sockaddr_in *)&net)->sin_addr), prefix_len, &match);
        if (match.s_addr == filtered.s_addr) {
          dout(0) << "ERROR: url in blacklist " << sv << ", blacklist:" << blacklist << dendl;
          return true;
        }
      } else {
        // fixed ipaddr blacklist
        if (sv.find(blacklist) != std::string::npos) {
          dout(0) << "ERROR: url in blacklist " << sv << ", blacklist:" << blacklist << dendl;
          return true;
        }
      }
    } else if (isalpha(blacklist[0]) && isalpha(sv[0])) {
      // domain blacklist
      if (sv.find(blacklist) != std::string::npos) {
        dout(0) << "ERROR: url in blacklist " << sv << ", blacklist:" << blacklist << dendl;
        return true;
      }
    }
  }
  return false;
}

int RGWMirroringConfiguration::is_valid(string url_blacklist) {
  // nowadays, bos only support single configuration
  if (configurations.size() != 1) {
    dout(0) << "ERROR: only support single mirror configuration" << dendl;
    return -ERR_INAPPROPRIATE_JSON;
  }
  MirroringConfiguration& conf = configurations.front();

#define MAX_URL_LENGTH 1024
  if (conf.prefix.length() > MAX_URL_LENGTH ||
        conf.source_url.length() > MAX_URL_LENGTH) {
    dout(0) << "ERROR: prefix or url exceed limit " << MAX_URL_LENGTH << dendl;
    return -ERR_INAPPROPRIATE_JSON;
  }

  if (conf.prefix.find(" ") != std::string::npos) {
    dout(0) << "ERROR: prefix illegal:" << conf.prefix << dendl;
    return -EINVAL;
  }

  if (conf.source_url.empty()) {
    dout(0) << "ERROR: source_url empty" << dendl;
    return -ERR_INAPPROPRIATE_JSON;
  } else if (conf.source_url.find(" ") != std::string::npos) {
    dout(0) << "ERROR: source_url illegal:" << conf.source_url << dendl;
    return -EINVAL;
  }

  std::vector<std::string> blacklists;
  boost::trim_all(url_blacklist);
  boost::split(blacklists, url_blacklist, boost::is_any_of(","));
  //string_view endpoint;

  if (!boost::algorithm::starts_with(conf.source_url, "http://") &&
      !boost::algorithm::starts_with(conf.source_url, "https://")) {
    if (conf.source_url.find("://") != std::string::npos) {
      dout(0) << "ERROR: invalid url " << conf.source_url << dendl;
      return -ERR_INAPPROPRIATE_JSON;
    } else {
      conf.source_url = "http://" + conf.source_url;
    }
  }

  if (is_blacklists_refused(conf.source_url, blacklists)) {
    dout(0) << "ERROR: source_url is refused by blacklist:" << conf.source_url << dendl;
    return -EINVAL;
  }

  boost::to_upper(conf.storage_class);
  if (!conf.storage_class.empty() &&
      conf.storage_class != RGWStorageClass::STANDARD &&
      conf.storage_class != RGWStorageClass::STANDARD_HP &&
      conf.storage_class != RGWStorageClass::STANDARD_IA &&
      conf.storage_class != RGWStorageClass::ARCHIVE) {
    dout(20) << "ERROR: invalid storage_class " << conf.storage_class << dendl;
    return -ERR_INAPPROPRIATE_JSON;
  } else if (conf.storage_class.empty()) {
    conf.storage_class = RGWStorageClass::STANDARD;
  }

  if (conf.pass_headers.size() > 10 ||
      conf.ignore_headers.size() > 10 ||
      conf.custom_headers.size() > 10) {
    dout(20) << "ERROR: number of headers exceed limit 10" << dendl;
    return -ERR_INAPPROPRIATE_JSON;
  }

  for (string h : conf.pass_headers) {
    boost::algorithm::to_lower(h);
    dout(20) << "ERROR: is empty?:" << h.empty() << ", h:"<< h << dendl;
    if (h.empty() ||
        boost::algorithm::starts_with(h, "x-amz") ||
        boost::algorithm::starts_with(h, "x-bce") ||
        unallowed_headers.find(h) != unallowed_headers.end()) {
      dout(20) << "ERROR: invalid pass_header:" << h << dendl;
      return -ERR_INAPPROPRIATE_JSON;
    }
  }

  for (string h : conf.ignore_headers) {
    boost::algorithm::to_lower(h);
    if (h.empty() ||
        boost::algorithm::starts_with(h, "x-amz") ||
        boost::algorithm::starts_with(h, "x-bce") ||
        unallowed_headers.find(h) != unallowed_headers.end()) {
      dout(20) << "ERROR: invalid ignore_header:" << h << dendl;
      return -ERR_INAPPROPRIATE_JSON;
    }
  }

  for (auto h : conf.custom_headers) {
    boost::algorithm::to_lower(h.name);
    if (h.name.empty() ||
        boost::algorithm::starts_with(h.name, "x-amz") ||
        boost::algorithm::starts_with(h.name, "x-bce") ||
        unallowed_headers.find(h.name) != unallowed_headers.end()) {
      dout(20) << "ERROR: invalid custom_header:" << h.name << dendl;
      return -ERR_INAPPROPRIATE_JSON;
    }
  }
  return 0;
}

namespace rgw::mirror {

void generate_mirror_headers(req_state* s,
                             MirroringConfiguration& config,
                             map<string, string>& headers) {
  static map<string, bool> unallowed_headers= {
    {"HTTP_CONTENT_LENGTH", true},
    {"HTTP_AUTHORIZATION", true},
    {"HTTP_RANGE", true},
    {"HTTP_DATE", true},
    {"HTTP_CONTENT_MD5", true},
    {"HTTP_HOST", true},
  };

  const auto& orig_map = s->info.env->get_map();
  bool allow_all = false;
  for (auto& h : config.pass_headers) {
    if (h.compare("*") == 0) {
      allow_all = true;
    }
  }
  for (auto iter = orig_map.begin(); iter != orig_map.end(); ++iter) {
    const string& name = iter->first;
    bool jump = false;
    if (boost::starts_with(name, "HTTP_X_AMX") ||
        boost::starts_with(name, "HTTP_X_BCE") ||
        unallowed_headers.find(name) != unallowed_headers.end() ||
        !boost::starts_with(name, "HTTP_")) {
      continue;
    }
    for (auto l_iter = config.ignore_headers.begin();
         !jump && l_iter != config.ignore_headers.end(); ++l_iter) {
      if (name.compare(strlen("HTTP_"), name.length(),
            boost::algorithm::to_upper_copy(*l_iter)) == 0) {
        jump = true;
      }
    }
    if (jump) continue;

    if (allow_all) {
      headers[iter->first] = iter->second;
      break;
    }
    for (auto& h : config.pass_headers) {
      if (name.compare(strlen("HTTP_"), name.length(),
            boost::algorithm::to_upper_copy(h)) == 0) {
        headers[iter->first] = iter->second;
        break;
      }
    }
  }
  for (auto& h : config.custom_headers) {
    headers[h.name] = h.value;
  }
  headers["HTTP_USER_AGENT"] = "bcebos-spider-1.0";
  return;
}

}  /* namespace rgw::mirror */
