// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*- 
// vim: ts=8 sw=2 smarttab
#ifndef CEPH_CEPHFS_BASIC_TYPES_H
#define CEPH_CEPHFS_BASIC_TYPES_H

#include <string>

#include "include/types.h"

#define CEPHFS_USER_NAMESPACE "cephfs_user"
#define CEPHFS_USER_OBJ "cephfs_user_index"

struct cephfs_user {
  std::string id;
  std::string email;
  time_t magic;
  uint64_t file_quota;
  uint64_t space_quota;
  uint64_t files;
  uint64_t space_used;

  cephfs_user() {}
  cephfs_user(const std::string& id, const std::string& email = "", const time_t magic = time(NULL), 
                const uint64_t file_quota = 0, const uint64_t space_quota = 0, const uint64_t files = 0, 
                const uint64_t space_used = 0) : id(id), email(email), magic(magic), 
                file_quota(file_quota), space_quota(space_quota), files(files), space_used(space_used) {}
  cephfs_user(std::string&& id, std::string&& email = "", time_t magic = time(NULL), 
                uint64_t file_quota = 0, uint64_t space_quota = 0, uint64_t files = 0, 
                uint64_t space_used = 0) : id(id),  email(email), magic(magic), file_quota(file_quota), 
                space_quota(space_quota), files(files), space_used(space_used) {}
  void encode(bufferlist& bl) const {
    ENCODE_START(1, 1, bl);
    encode(id, bl);
    encode(email, bl);
    encode(magic, bl);
    encode(file_quota, bl);
    encode(space_quota, bl);
    encode(files, bl);
    encode(space_used, bl);
    ENCODE_FINISH(bl);
  }
  void decode(bufferlist::iterator& bl) {
    DECODE_START(1, bl);
    decode(id, bl);
    decode(email, bl);
    decode(magic, bl);
    decode(file_quota, bl);
    decode(space_quota, bl);
    decode(files, bl);
    decode(space_used, bl);
    DECODE_FINISH(bl);
  }
  void to_str(string& write) {
    write.append("id = ");
    write.append(id);
    write.append("\nemail = ");
    write.append(email);
    write.append("\ncreate_time = ");
    write.append(asctime(localtime(&magic)));
  }

  const char* id_str() {
    return id.c_str(); 
  }

  const char* email_str() {
    return email.c_str();
  }

  char* magic_str() {
    return asctime(localtime(&magic));
  }
};
WRITE_CLASS_ENCODER(cephfs_user)

struct cephfs_dir {
  std::string dir_name;

  cephfs_dir() {}
  cephfs_dir(const std::string& dir_name) : dir_name(dir_name) {}
  cephfs_dir(std::string&& dir_name) : dir_name(std::move(dir_name)) {}

  void encode(bufferlist& bl) const {
    ENCODE_START(1, 1, bl);
    encode(dir_name, bl);
    ENCODE_FINISH(bl);
  }
  void decode(bufferlist::iterator& bl) { 
    DECODE_START(1, bl);
    decode(dir_name, bl);
    DECODE_FINISH(bl);
  }

  void to_str(string& write) {
    write = dir_name;
  }
};
WRITE_CLASS_ENCODER(cephfs_dir)

#endif
