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

#include <arpa/inet.h>

#include "common/dout.h"
#include "include/crc32c.h"
#include "include/random.h"
#include "include/sock_compat.h"
#include "common/errno.h"
#include "common/license.h"

using ceph::util::generate_random_number;

#define dout_subsys ceph_subsys_license
#undef dout_prefix
#define dout_prefix *_dout << "license "

const string  license_magic_tag = "abclp";

// connection status
#define LICENSE_CONN_STATE_CONNECTING 0
#define LICENSE_CONN_STATE_OPEN       1
#define LICENSE_CONN_STATE_CLOSE      2
#define LICENSE_CONN_STATE_INVALID    3

// op type
#define LICENSE_OP_TYPE_INIT      1
#define LICENSE_OP_TYPE_REGISTER  2
#define LICENSE_OP_TYPE_REG_REPLY 3
#define LICENSE_OP_TYPE_CHECK     4
#define LICENSE_OP_TYPE_FAILED    5
#define LICENSE_OP_TYPE_CLOSE     6
#define LICENSE_OP_TYPE_ERROR     7

// error code
#define LICENSE_ERROR_OK                  0
#define LICENSE_ERROR_CEPH_CLOCK_SKEW     1001
#define LICENSE_ERROR_EXPIRED             1002
#define LICENSE_ERROR_BAD_MSG             1003
#define LICENSE_ERROR_REJECT              1003
#define LICENSE_ERROR_OFFLINE             1004
#define LICENSE_ERROR_INTER               1005
#define LICENSE_ERROR_NET                 1006
#define LICENSE_ERROR_PLATFORM_CLOCK_SKEW 1007

// config
#define LICENSE_BUFFER_SIZE             4096
#define LICENSE_MAX_CLOCK_SKEW          7200
#define LICENSE_PLATFORM_MAX_CLOCK_SKEW 3600
#define LICENSE_CHECK_CLOCK_TOLERATE    10
#define LICENSE_CHECK_MAX_CLOCK_SKEW    864000
#define LICENSE_OFFLINE_MAX_TOLERATE    864000
#define LICENSE_CONNECT_RETRY           3
#define SEND_RECV_TIMEOUT               120

char buffer[LICENSE_BUFFER_SIZE];

void random_padding_string(char *strs, int len) {
    int max_char_num = 255;
    for (int i=0; i< len; i++) {
        int ret = generate_random_number(0, max_char_num);
        strs[i] = (char)ret;
    }
}

template<typename T>
void int_to_chars(T int_val, char *buf, int& offset) {
    // encode body_length
    for (size_t i = 0; i < sizeof(T); i ++) {
        buf[offset++] = (char)(int_val >> (i*8));
    }
}

template<typename T>
void chars_to_int(T& int_val, char *buf) {
    uint64_t val = 0;
    // encode body_length
    for (int i = sizeof(T)-1; i >= 0 ; i --) {
        val = (val << 8) + (uint8_t)(buf[i]);
    }
    int_val = (T)val;
}

// use little-endian
int LicenseMsg::encode(char* buf, size_t buf_size) {
    // body is
    // |<- op type -> | <- body length -> | <- body -> | <- crc32 -> |
    int n = 0;
    size_t len = padding_len() + body_length;
    if (len > buf_size) {
        return -EINVAL;
    }
    crc32_val = ceph_crc32c(0, (unsigned char*) body, body_length);
    // encode op
    buf[n++] = (char)op_type;
    // encode body_length
    int_to_chars(body_length, buf, n);
    // TODO: need to encrypt body with aes
    // encode body
    if (body != buf+n) {
        memcpy(buf+n, body, body_length);
    }
    n += body_length;
    // crc32
    int_to_chars(crc32_val, buf, n);
    return len;
}

// use little-endian
int LicenseRegMsg::encode(char *buf, size_t offset, size_t buf_size) {
    int n = offset;
    // calc the length of msg body
    // body is | version | disk_size | random_id | module_id |name_size |
    // + | module_name | ip_size | host_ip | fsid_size | fsid
    ssize_t len =  get_length();
    if (offset + len >  buf_size) {
        return -EINVAL;
    }
    buf[n++] = (char)version;
    int_to_chars(disk_size, buf, n);
    int_to_chars(random_id, buf, n);
    int_to_chars(module_id, buf, n);
    int_to_chars((uint32_t)(module_name.length()), buf, n);
    memcpy(buf+n, module_name.c_str(), module_name.length());
    n += module_name.length();
    int_to_chars((uint32_t)(host_ip.length()), buf, n);
    memcpy(buf+n, host_ip.c_str(), host_ip.length());
    n += host_ip.length();
    int_to_chars((uint32_t)(fsid.length()), buf, n);
    memcpy(buf+n, fsid.c_str(), fsid.length());
    return len;
}

// use little-endian
int LicenseRegReplyMsg::decode(char *buf, size_t buf_length) {
    int n = 0;
    // calc the length of msg body
    size_t need_size = sizeof(version) + sizeof(random_id) + sizeof(date) + sizeof(expire_date);
    if (need_size > buf_length) {
        return -1;
    }
    // body is | version | random_id| date | expire_date | module_name |
    version = (uint8_t) buf[n++];
    chars_to_int<uint64_t>(random_id, buf+n);
    n += sizeof(random_id);
    chars_to_int<uint64_t>(date, buf+n);
    n += sizeof(date);
    chars_to_int<uint64_t>(expire_date, buf+n);
    n += sizeof(expire_date);
    module_name.assign(buf+n, buf_length-n);
    return 0;
}

// use little-endian
int LicenseErrorMsg::decode(char *buf, size_t buf_length) {
    size_t n = 0;
    // calc the length of msg body
    size_t need_size = sizeof(version) + sizeof(code);
    if (buf_length < need_size) {
        return -1;
    }
    // body is | version | code | error_msg |
    version = (uint8_t) buf[n++];
    if (version <= 1) {
        chars_to_int<uint32_t>(code, buf+n);
        n += sizeof(code);
        error_msg.assign(buf+n, buf_length-n);
    }
    return 0;
}

LicenseConnection::LicenseConnection(CephContext *cct): cct(cct), s_fd(0),
                                                        state(LICENSE_CONN_STATE_CONNECTING) {
    random_padding_string(aes_key, LICENSE_AES_LENGTH);
}

int LicenseConnection::connect(std::string addr, uint16_t port) {
    ldout(cct, 25) << __func__ << " start new connection" << dendl;

    if (state != LICENSE_CONN_STATE_CONNECTING && state != LICENSE_CONN_STATE_CLOSE) {
        ::close(s_fd);
    }
    int r = 0;
    struct sockaddr_in p_addr;
    // create socket
    if ((s_fd = socket_cloexec(AF_INET, SOCK_STREAM, 0)) == -1) {
        r = errno;
        ldout(cct, 0) << __func__ << " Error: couldn't create socket "
                      << cpp_strerror(r) << dendl;
        return -r;
    }
    // only support ipv4
    bzero(&p_addr, sizeof(sockaddr_in));
    p_addr.sin_family = AF_INET;
    p_addr.sin_port = htons(port);
    if(inet_pton(AF_INET, addr.c_str(), &p_addr.sin_addr) <= 0) {
        ldout(cct, 0) << __func__ << " Error: invalid ip" << addr << dendl;
        return -EINVAL;
    }
    if (::connect(s_fd, (struct sockaddr*) &p_addr, sizeof(sockaddr_in)) == -1) {
        r = errno;
        ldout(cct, 0) << __func__ << " Error: can't connect to platform "
                      << cpp_strerror(r) << dendl;
        return -r;
    }
    struct timeval timer;
    timer.tv_sec = SEND_RECV_TIMEOUT;
    timer.tv_usec = 0;
    // set read timeout
    if (::setsockopt(s_fd, SOL_SOCKET, SO_RCVTIMEO, &timer, sizeof(timer))) {
        r = errno;
        ldout(cct, 0) << __func__ << " Error: can't set read timeout for socket "
                      << cpp_strerror(r) << dendl;
        ::close(s_fd);
        return -r;
    }
    // set write timeout
    if (::setsockopt(s_fd, SOL_SOCKET, SO_SNDTIMEO, &timer, sizeof(timer))) {
        r = errno;
        ldout(cct, 0) << __func__ << " Error: can't set write timeout for socket "
                      << cpp_strerror(r) << dendl;
        ::close(s_fd);
        return -r;
    }
    state = LICENSE_CONN_STATE_OPEN;
    ldout(cct, 10) << __func__ << " success to create connection" << dendl;
    return 0;
}

ssize_t LicenseConnection::read(char *buf, int len) {
    if (state != LICENSE_CONN_STATE_OPEN) {
        ldout(cct, 0) << __func__ << " Error: bad status " << state << dendl;
        return -EINVAL;
    }

    ssize_t r = ::read(s_fd, buf, len);
    if (r < 0) {
        ldout(cct, 0) << __func__ << " Error: failed to read data "
                      << cpp_strerror(errno) << dendl;
        state = LICENSE_CONN_STATE_INVALID;
        r = -errno;
    } else if (len > 0 && r == 0) { // maybe closed
        close();
        ldout(cct, 5) << __func__ << " Error: license connection maybe closed " << dendl;
        return -EIO;
    }
    return r;
}

ssize_t LicenseConnection::send(const char *buf, int len) {
    ssize_t r = ::send(s_fd, buf, len, 0);
    if (r < 0) {
        ldout(cct, 0) << __func__ << " failed to send data " << cpp_strerror(errno) << dendl;
        state = LICENSE_CONN_STATE_INVALID;
        r = -errno;
    } else if (len > 0 && r == 0) {
        close();
        ldout(cct, 0) << __func__ << " license connection maybe closed " << dendl;
        return -EIO;
    }
    return r;
}

void LicenseConnection::close() {
    if (state == LICENSE_CONN_STATE_CLOSE) {
        return;
    }
    if (s_fd != 0) {
        ::close(s_fd);
        s_fd = 0;
    }
    state = LICENSE_CONN_STATE_CLOSE;
}

License::License(CephContext *cct_,
                 const std::string &name,
                 uint64_t disk_size,
                 uint32_t module_id,
                 const string &hostip,
                 const string &module_name,
                 const string &fsid,
                 const string &platform_addr,
                 uint16_t port,
                 uint64_t expire,
                 uint64_t last_check,
                 uint64_t last_check_success,
                 uint64_t last_checkpoint,
                 uint64_t c_gap,
                 uint64_t c_num) :
    cct(cct_),
    persistent_name(name),
    conn(nullptr),
    disk_size(disk_size),
    module_id(module_id),
    hostip(hostip),
    module_name(module_name),
    fsid(fsid),
    platform_ip(platform_addr),
    platform_port(port),
    state(LICENSE_STATE_CREATING),
    expire(expire),
    last_check_time(last_check),
    last_check_time_succ(last_check_success),
    last_checkpoint_time(last_checkpoint),
    checkpoint_gap(c_gap),
    checkpoint_num(c_num)
{
    buffer_length = LICENSE_BUFFER_SIZE;
    buffer = (char*) malloc(buffer_length);
    assert(buffer != nullptr);
}

int License::send_msg(LicenseMsg &op) {
    int n = op.encode(buffer, buffer_length);
    if (n < 0) {
        ldout(cct, 0) << __func__ << " failed to encode op " << (int)op.op_type
                      << " ret=" << n << dendl;
        return LICENSE_ERROR_INTER;
    }
    // send op
    ldout(cct, 20) << "send op: " <<  int(op.op_type)
                   <<  " length " << op.body_length << " crc32 " << op.crc32_val << dendl;
    int r = conn->send(buffer, n);
    if (r < 0) {
        ldout(cct, 0) << __func__ << " failed to send op " << (int)op.op_type
                      << " ret=" << r << dendl;
        return LICENSE_ERROR_NET;
    }
    return 0;
}

int License::read_msg(LicenseMsg& msg) {
    int r;
    // read op type
    r = conn->read((char*)(&msg.op_type), sizeof(msg.op_type));
    if (r < 0) {
        ldout(cct, 0) << __func__ << " failed to read op type of msg, ret=" << r << dendl;
        return LICENSE_ERROR_NET;
    }

    // read body length
    r = conn->read(buffer, sizeof(msg.body_length));
    if (r < 0) {
        ldout(cct, 0) << __func__ << " failed to read body length, ret=" << r << dendl;
        return LICENSE_ERROR_NET;
    }
    chars_to_int<uint64_t>(msg.body_length, buffer);

    // read body
    size_t need_size = msg.body_length + LicenseMsg::padding_len();
    if (need_size > buffer_length) {
        if (realloc_buffer(need_size)) {
            ldout(cct, 0) << __func__ << " failed to alloc memory for body" << dendl;
            return LICENSE_ERROR_INTER;
        }
    }
    r = conn->read(buffer, msg.body_length);
    if (r < 0) {
        ldout(cct, 0) << __func__ << " failed to read body, ret=" << r << dendl;
        return LICENSE_ERROR_NET;
    }
    msg.body = buffer;

    // read crc32 of remote
    char *crc_body = buffer + msg.body_length;
    r = conn->read(crc_body, sizeof(msg.crc32_val));
    if (r < 0) {
        ldout(cct, 0) << __func__ << " failed to read crc32, ret=" << r << dendl;
        return LICENSE_ERROR_NET;
    }
    chars_to_int<uint32_t>(msg.crc32_val, crc_body);

    // calc crc32 of body
    uint32_t crc32_val = ceph_crc32c(0, (unsigned char*)msg.body, msg.body_length);
    if (crc32_val != msg.crc32_val) {
        ldout(cct, 0) << __func__ << " bad crc32 " << msg.crc32_val << " != "
                      << crc32_val << dendl;
        return LICENSE_ERROR_NET; // crc is wrong, there is a problem with the network
    }
    return 0;
}

// build new connection
//       osd                      abcplatform
// 1.        --- magic tag  --- >
// 2.        --- send aes key -->
// 3.        <--      ack    ---
int License::connect() {
    int r = 0;
    if (conn == nullptr) {
        conn = new LicenseConnection(cct);
    }
    r = conn->connect(platform_ip, platform_port);
    if (r < 0) {
        ldout(cct, 0) << __func__ << " failed to connect to platform ret=" << r << dendl;
        return LICENSE_ERROR_NET;
    }

    // send magic tag
    r = conn->send(license_magic_tag.c_str(), license_magic_tag.length());
    if (r < 0) {
        ldout(cct, 0) << __func__ << " failed to send magic tag ret=" << r << dendl;
        return LICENSE_ERROR_NET;
    }

    // generate aes key op
    LicenseMsg op(LICENSE_OP_TYPE_INIT, LICENSE_AES_LENGTH, conn->aes_key);
    // TODO: should encrypt aes key with rsa
    r = send_msg(op);
    if (r != 0) {
        ldout(cct, 0) << __func__ << " failed to send init op ret=" << r << dendl;
        return r;
    }

    // read ack
    r = read_msg(op);
    if (r != 0) {
        ldout(cct, 0) << __func__ << " failed to read init reply msg ret=" << r << dendl;
        return r;
    }
    if (op.op_type != LICENSE_OP_TYPE_ERROR) {
        ldout(cct, 0) << __func__ << " failed to read ack reply init msg" << dendl;
        return LICENSE_ERROR_NET; // send to wrong address?
    }
    LicenseErrorMsg reply;
    r = reply.decode(op.body, op.body_length);
    if (r < 0) {
        ldout(cct, 0) << __func__ << " failed to decode error reply" << dendl;
        return LICENSE_ERROR_NET; // send to wrong address?
    } else if (reply.code != LICENSE_ERROR_OK) {
        ldout(cct, 0) << __func__ << " get bad ack" << dendl;
        return LICENSE_ERROR_NET; // send to wrong address?
    }
    ldout(cct, 20) << __func__ << " success to connect platform" << dendl;
    return 0;
}

// chect clock drift between two check_auth
bool License::is_two_auth_check_clock_skew(uint64_t now, uint64_t max_clock) {
    if (now < last_check_time && last_check_time - now > max_clock) {
        ldout(cct, 0) << __func__ << " clock shew: now is " << now
                      << " last check is " << last_check_time
                      << dendl;
        return true;
    }
    last_check_time = now;
    ldout(cct, 25) << __func__ << " last check time is " << last_check_time << dendl;
    return false;
}

// The clock shew between now and last checkpoint time cannot be too large
bool License::is_ceph_relative_clock_skew(uint64_t now) {
    uint64_t t = last_checkpoint_time + checkpoint_gap;
    if (t < now || t - now <= LICENSE_CHECK_CLOCK_TOLERATE * checkpoint_num) {
        last_checkpoint_time = now;
        checkpoint_gap = 0;
        checkpoint_num = 0;
    } else if (t > now && t - now > LICENSE_CHECK_MAX_CLOCK_SKEW) {
        ldout(cct, 0) << __func__ << " clock shew: now is " << now
                      << " last checkpoint time is " << t
                      << dendl;
        return true;
    }
    ldout(cct, 25) << __func__ << " last checkpoint time is " << last_checkpoint_time
                   << " gap is " << checkpoint_gap
                   << " number is " << checkpoint_num
                   << dendl;
    return false;
}

int License::check(LicenseRegReplyMsg &op, uint64_t random_id) {
    utime_t now = ceph_clock_now();
    uint64_t sec = (uint64_t) now.sec();
    uint64_t date_gap = 0;
    ldout(cct, 25) << __func__ << " start" << dendl;

    if (op.random_id != random_id) {
        ldout(cct, 0) << __func__ << " get invalid random id " << op.random_id
                      << " != " << random_id << dendl;
        return LICENSE_ERROR_BAD_MSG;
    }

    if (op.module_name.compare(module_name) != 0) {
        ldout(cct, 0) << __func__ << " get invalid module name "
                      << op.module_name << dendl;
        return LICENSE_ERROR_BAD_MSG;
    }

    if (op.expire_date != expire) {
        ldout(cct, 10) << __func__ << " license new expire date is "
                       << op.expire_date << dendl;
        expire = op.expire_date;
    }

    // check expire
    if (op.expire_date > 0) {
        if (is_two_auth_check_clock_skew(sec, LICENSE_MAX_CLOCK_SKEW)) {
            return LICENSE_ERROR_CEPH_CLOCK_SKEW;
        }
        // The clock shew between now and last check cannot be too large
        if (is_ceph_relative_clock_skew(sec)) {
            return LICENSE_ERROR_CEPH_CLOCK_SKEW;
        }
        if (sec > op.expire_date) {
            ldout(cct, 0) << __func__ << " license is expired, expire date is "
                          << op.expire_date << dendl;
            return LICENSE_ERROR_EXPIRED;
        }
    }
    last_check_time = now;

    // check clock drift between platform and ceph
    if (sec < op.date) {
        date_gap = op.date - sec;
    } else {
        date_gap = sec - op.date;
    }
    if (date_gap > LICENSE_PLATFORM_MAX_CLOCK_SKEW) {
        ldout(cct, 0) << __func__ << " clock skew now is " << now
                      << " the date of platform is " << op.date << dendl;
        return LICENSE_ERROR_PLATFORM_CLOCK_SKEW;
    }

    last_check_time_succ = sec;
    ldout(cct, 25) << __func__ << " success to check license reg reply" << dendl;

    return 0;
}

int License::offline_check() {
    utime_t now = ceph_clock_now();
    uint64_t sec = (uint64_t) now.sec();
    ldout(cct, 10) << __func__ << " offline check" << dendl;

     // check check time
    if (last_check_time_succ == 0) {
        // it is the first time to connect to the platform and we can't connect to it
        ldout(cct, 0) << __func__ << " license is offlise and the last check time is 0"
                      << dendl;
        return LICENSE_ERROR_OFFLINE;
    }

    if (expire != 0) {
        if (is_two_auth_check_clock_skew(sec, LICENSE_MAX_CLOCK_SKEW)) {
            return LICENSE_ERROR_CEPH_CLOCK_SKEW;
        }
        // check expire
        if (sec > expire) {
            ldout(cct, 0) << __func__ << " license is expired, expire date is "
                          << expire << dendl;
            return LICENSE_ERROR_EXPIRED;
        }
    }
    if (is_ceph_relative_clock_skew(sec)) {
        return LICENSE_ERROR_CEPH_CLOCK_SKEW;
    }
    if (now > last_check_time_succ && now - last_check_time_succ > LICENSE_OFFLINE_MAX_TOLERATE) {
        ldout(cct, 0) << __func__ << " platform is offline long time, last check is "
                      << last_check_time_succ << dendl;
        return LICENSE_ERROR_OFFLINE;
    }

    last_check_time = sec;
    ldout(cct, 10) << __func__ << " platform is offline, now is " << sec
                   << " expire is " << expire
                   << " last check success is " << last_check_time_succ
                   << dendl;
    return 0;
}

int License::register_auth() {
    if (state < LICENSE_STATE_CONNECT) {
        ldout(cct, 0) << __func__ << " invalid state" << (int)state << dendl;
        return LICENSE_ERROR_INTER;
    }
    uint64_t random_id = generate_random_number<uint64_t>();
    LicenseRegMsg reg_op(disk_size, random_id, module_id, module_name, hostip, fsid);
    size_t need_size = reg_op.padding_size();
    if (need_size > buffer_length) {
        if (realloc_buffer(need_size)) {
            ldout(cct, 0) << __func__ << " failed to alloc memory for buffer" << dendl;
            return LICENSE_ERROR_INTER;
        }
    }
    int n = reg_op.encode(buffer, LicenseMsg::prefix_len(), buffer_length);
    if (n< 0) {
        ldout(cct, 0) << __func__ << " failed to encode reg msg ret=" << n << dendl;
        return LICENSE_ERROR_INTER;
    }

    // send reg msg
    LicenseMsg op(LICENSE_OP_TYPE_REGISTER, n, buffer+LicenseMsg::prefix_len());
    int r = send_msg(op);
    if (r != 0) {
        ldout(cct, 0) << __func__ << " failed to send reg msg ret=" << r << dendl;
        return r;
    }

    // read license info
    r = read_msg(op);
    if (r != 0) {
        ldout(cct, 0) << __func__ << " failed to read reg reply msg ret=" << r << dendl;
        return r;
    }

    if (op.op_type == LICENSE_OP_TYPE_REG_REPLY) {
        LicenseRegReplyMsg reply;
        r = reply.decode(op.body, op.body_length);
        if (r != 0) {
            ldout(cct, 0) << __func__ << " failed to decode reply ret=" << r << dendl;
            return r;
        }
        r = check(reply, random_id);
        if (r != 0) {
            ldout(cct, 0) << __func__ << " failed to check reg ret=" << r << dendl;
            return r;
        }
    } else if (op.op_type == LICENSE_OP_TYPE_ERROR) {
        LicenseErrorMsg reply;
        r = reply.decode(op.body, op.body_length);
        if (r != 0) {
            ldout(cct, 0) << __func__ << " failed to decode error msg ret=" << r << dendl;
            return LICENSE_ERROR_INTER;
        }
        ldout(cct, 0) << __func__ << " get error msg, code=" << reply.code
                      << " error msg:" << reply.error_msg << dendl;
        // maybe try again
        if (reply.code == LICENSE_ERROR_INTER) {
            return LICENSE_ERROR_INTER;
        }
        return LICENSE_ERROR_REJECT;
    } else {
        ldout(cct, 0) << __func__ << " get bod op " << op.op_type << dendl;
        return LICENSE_ERROR_INTER;
    }
    ldout(cct, 25) << __func__ << " success to register auth, expire_date=" << expire
                   << " last check is " << last_check_time
                   << " last check success is " << last_check_time_succ
                   << dendl;

    return 0;
}

int License::check_auth(bool is_init, double duration_sec) {
    ldout(cct, 25) << __func__ << " start" << dendl;
    int r = 0;
    // update checktime
    if (!is_init) {
        checkpoint_gap += uint64_t(duration_sec);
        ++checkpoint_num;
    }

    // try create connection
    if (state == LICENSE_STATE_CLOSE) {
        ldout(cct, 10) << __func__ << " license is shutdown" << dendl;
        return state;
    } else if (state < LICENSE_STATE_CONNECT) {
        r = connect();
        if (r == 0) {
            state = LICENSE_STATE_CONNECT;
        } else if (r == LICENSE_ERROR_NET) {
            state = LICENSE_STATE_OFFLINE;
        } else {
            state = LICENSE_STATE_INVALID;
            return state;
        }
    }
    if (state == LICENSE_STATE_OFFLINE) {
        r = offline_check();
        if (r != 0) {
            state = LICENSE_STATE_REJECT_OFFLINE;
        } else {
            state = LICENSE_STATE_OK_OFFLINE;
        }
    } else {
        r = register_auth();
        if (r == 0) {
            state = LICENSE_STATE_REGED;
        // Treat internal errors as offline
        } else if (r == LICENSE_ERROR_INTER ||
                   r == LICENSE_ERROR_NET ||
                   r == LICENSE_ERROR_PLATFORM_CLOCK_SKEW) {
            r = offline_check();
            if (r != 0) {
                state = LICENSE_STATE_REJECT_OFFLINE;
            } else {
                state = LICENSE_STATE_OK_OFFLINE;
            }
        } else {
            state = LICENSE_STATE_REJECT;
        }
    }
    ldout(cct, 25) << __func__ << " state=" << state << dendl;

    return state;
}

void License::encode(bufferlist& bl) const {
    ENCODE_START(3, 1, bl);
    encode(module_id, bl);
    encode(module_name, bl);
    encode(expire, bl);
    encode(last_check_time_succ, bl);
    encode(last_check_time, bl);
    encode(last_checkpoint_time, bl);
    encode(checkpoint_gap, bl);
    encode(checkpoint_num, bl);
    ENCODE_FINISH(bl);
}

int License::decode_and_check(bufferlist::iterator &p) {
    string old_module_name;
    uint32_t old_module_id;
    DECODE_START_LEGACY_COMPAT_LEN(3, 1, 1, p);
    decode(old_module_id, p);
    if (old_module_id != module_id) {
        ldout(cct, 0) << __func__ << " the module id of license info changed, from "
                      << old_module_id << " to " << module_id <<  dendl;
        return -1;
    }
    decode(old_module_name, p);
    if (module_name.compare(old_module_name) != 0) {
        ldout(cct, 0) << __func__ << " the module name of license info changed, from "
                      << old_module_name << " to " << module_name <<  dendl;
        return -1;
    }
    decode(expire, p);
    decode(last_check_time_succ, p);
    if (struct_v >= 2) {
        decode(last_check_time, p);
    }
    if (struct_v >= 3) {
        decode(last_checkpoint_time, p);
        decode(checkpoint_gap, p);
        decode(checkpoint_num, p);
    }
    ldout(cct, 25) << __func__ << " get old license info id "
                   << old_module_id
                   << " name " << module_name
                   << " expire " << expire
                   << " last_check " << last_check_time
                   << " last_check_success " << last_check_time_succ
                   << " last_checkpoint_time " << last_checkpoint_time
                   << " checkpoint_gap " << checkpoint_gap
                   << " checkpoint_num " << checkpoint_num
                   <<  dendl;
    DECODE_FINISH(p);
    return 0;
}
