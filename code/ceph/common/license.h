// -*- mode:C++; tab-width:4; c-basic-offset:4; indent-tabs-mode:t -*-
// vim: ts=4 sw=4 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Author: Liu Peng <liupeng37@baidu.com>
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation.  See file COPYING.
 *
 */

#include <string>

#include "include/Context.h"

#ifndef CEPH_LICENSE_H
#define CEPH_LICENSE_H

#define LICENSE_AES_LENGTH 32

// status
#define LICENSE_STATE_INVALID         2001
#define LICENSE_STATE_OFFLINE         2002
#define LICENSE_STATE_REJECT_OFFLINE  2003
#define LICENSE_STATE_OK_OFFLINE      2004
#define LICENSE_STATE_CREATING        2005
#define LICENSE_STATE_CONNECT         2006
#define LICENSE_STATE_REJECT          2007
#define LICENSE_STATE_REGED           2008
#define LICENSE_STATE_CLOSE           2009

class LicenseMsg {
public:
    LicenseMsg(uint8_t op,
               uint64_t body_len,
               char* body):
        op_type(op),
        crc32_val(0),
        body_length(body_len), body(body) {}
    int encode(char *buf, size_t buf_size);
    static size_t prefix_len() {return sizeof(op_type) + sizeof(body_length); }
    static size_t padding_len() {return sizeof(op_type) + sizeof(body_length) + sizeof(crc32_val); }
public:
    uint8_t op_type;
    uint32_t crc32_val;
    uint64_t body_length;
    char* body;
};

class LicenseRegMsg {
public:
    LicenseRegMsg(uint64_t disk_size,
                  uint64_t random,
                  uint32_t id,
                  const std::string& name,
                  const std::string &ip,
                  const std::string &fsid):
        disk_size(disk_size),
        random_id(random),
        module_id(id),
        module_name(name),
        host_ip(ip),
        fsid(fsid) {}

    int encode(char *buf, size_t offset, size_t buf_size);
    inline size_t get_length() {
        return sizeof(version) + sizeof(disk_size) +
               sizeof(random_id) + sizeof(module_id) +
               sizeof(uint32_t) + module_name.size() +
               sizeof(uint32_t) + host_ip.size() +
               sizeof(uint32_t) + fsid.size();
    }
    inline size_t padding_size() { return LicenseMsg::padding_len() + get_length(); }
private:
    uint8_t version = 2;
    uint64_t disk_size;
    uint64_t random_id;
    uint32_t module_id;
    std::string module_name;
    std::string host_ip;
    std::string fsid;
};

class LicenseRegReplyMsg {
public:
    LicenseRegReplyMsg(): version(0), random_id(0), date(0), expire_date(0) {}
    int decode(char *buf, size_t buf_length);

public:
    uint8_t version;
    uint64_t random_id;
    uint64_t date;
    uint64_t expire_date;
    std::string module_name;
};

class LicenseErrorMsg {
public:
    LicenseErrorMsg(): version(0), code(0) {}
    int decode(char *buf, size_t buf_length);
public:
    uint8_t version;
    uint32_t code;
    std::string error_msg;
};

class LicenseConnection {
private:
    CephContext *cct;
    int s_fd;
    uint64_t state;
public:
    LicenseConnection(CephContext *cct);
    ~LicenseConnection() { close(); }
    int connect(std::string addr, uint16_t port);
    ssize_t send(const char *buf, int len);
    ssize_t read(char *buf, int len);
    void close();
public:
    char aes_key[LICENSE_AES_LENGTH];
};

class License {
public:
    License() = delete;
    License(const License&) = delete;
    License& operator=(const License&) = delete;
    License(CephContext *cct_,
            const std::string &name,
            uint64_t disk_size,
            uint32_t module_id,
            const std::string &hostip,
            const std::string &module_name,
            const std::string &fsid,
            const std::string &platform_addr,
            uint16_t port,
            uint64_t expire,
            uint64_t last_check,
            uint64_t last_check_success,
            uint64_t last_checkpoint,
            uint64_t c_gap,
            uint64_t c_num);
    ~License() {
        if (conn != nullptr) {
            conn->close();
            delete conn;
        }
    }
    uint64_t get_last_check_succ_time() { return last_check_time_succ; }
    inline void shutdown() {
        state = LICENSE_STATE_CLOSE;
        if (conn != nullptr) {
            conn->close();
        }
    }

    int check_auth(bool is_init, double duration_sec);
    void encode(bufferlist& bl) const;
    int decode_and_check(bufferlist::iterator &p);
    uint64_t get_expire_date() { return expire; }
    std::string &get_name() { return persistent_name; }

private:
    int send_msg(LicenseMsg &op);
    int read_msg(LicenseMsg &msg);
    inline int realloc_buffer(size_t need_size) {
        buffer = (char *) realloc(buffer, need_size);
        if (buffer == nullptr)
            return -1;
        buffer_length = need_size;
        return 0;
    }
    int connect();
    bool is_two_auth_check_clock_skew(uint64_t now, uint64_t max_clock);
    bool is_ceph_relative_clock_skew(uint64_t now);
    int check(LicenseRegReplyMsg &op, uint64_t random_id);
    int offline_check();
    int register_auth();

private:
    CephContext *cct;
    std::string persistent_name;
    LicenseConnection *conn;
    uint64_t disk_size;
    uint32_t module_id;
    std::string hostip;
    std::string module_name;
    std::string fsid;
    std::string platform_ip;
    uint16_t platform_port;
    int state;
    uint64_t buffer_length;
    char *buffer;

    // license info
    uint64_t expire;
    uint64_t last_check_time;
    uint64_t last_check_time_succ;
    uint64_t last_checkpoint_time;
    uint64_t checkpoint_gap;
    uint64_t checkpoint_num;
};

#endif

