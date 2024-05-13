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

#ifndef CEPH_OSD_SLOW_DISK_CHECK_H
#define CEPH_OSD_SLOW_DISK_CHECK_H

#include <string>
#include <osd/osd_types.h>

typedef enum {
    TYPE_SATA_NONE = 1,
    TYPE_SATA_HDD,
    TYPE_SATA_SSD,
    TYPE_NVME_SSD
} disk_type_t;

string get_disk_type_name(disk_type_t _t);

struct io_stats {
    // read
    unsigned long rd_ios;
    unsigned long rd_merges;
    unsigned long rd_sectors;
    unsigned long rd_ticks;
    // write
    unsigned long wr_ios;
    unsigned long wr_merges;
    unsigned long wr_sectors;
    unsigned int wr_ticks;

    unsigned int in_flight;
    unsigned int io_ticks;
    unsigned int time_in_queue;

    io_stats() : rd_ios(0), rd_merges(0),  rd_sectors(0), rd_ticks(0), wr_ios(0), wr_merges(0),
                 wr_sectors(0), wr_ticks(0), in_flight(0), io_ticks(0), time_in_queue(0) {}
};

ostream& operator<<(ostream& out, const io_stats& s);

/*
 * Records the score of each tick in a period
 */
class SlowDiskAlarmScore {
public:
    SlowDiskAlarmScore() : scores(nullptr), score(0), have_ops_time(0), period(0), ticks(0) {}
    SlowDiskAlarmScore(uint64_t period) : score(0), have_ops_time(0), period(period), ticks(0) {
       scores = (int8_t*) calloc(period, sizeof(int8_t));
    }

    ~SlowDiskAlarmScore() {
        if (scores != nullptr) {
            free(scores);
            scores = nullptr;
        }
    }

    void reset_period(uint64_t period);
    void alarm_sys_insert_per_period(int8_t score);

    bool alarm_need_warn(int percent) {
        if (ticks < period) {
            return false;
        } else if (have_ops_time == 0) { // there are no requests in this period
            return last_period_need_warn;
        } else if (score * 100 >= have_ops_time * percent) {
            last_period_need_warn = true;
        } else {
            last_period_need_warn = false;
        }
        return last_period_need_warn;
    }

    bool last_period_need_warn = false;
    int8_t *scores;
    int score;
    int have_ops_time;
    uint64_t period;
    uint64_t ticks;
};

ostream& operator<<(ostream& out, const SlowDiskAlarmScore& s);

class SlowDiskAlarmDisk {
public:
    SlowDiskAlarmDisk(CephContext *_c, disk_type_t _t, const string &disk_name);
    SlowDiskAlarmDisk() = delete;
    ~SlowDiskAlarmDisk() {
        if (cct && disk_check_perf) {
            cct->get_perfcounters_collection()->remove(disk_check_perf);
            delete disk_check_perf;
        }
    }
    string get_device_name() { return device_name; }
    void try_reset();
    int check_disk();

    slow_disk_warn_t alarm_need_warn() {
        if (slow_drop.alarm_need_warn(cct->_conf->osd_slow_disk_drop_percent)) {
            return OSD_SLOW_DISK_WARN_TYPE_WARN_DROP;
        } else if (slow_long.alarm_need_warn(cct->_conf->osd_slow_disk_warn_long_percent)) {
            return OSD_SLOW_DISK_WARN_TYPE_WARN_LONG;
        } else if (slow.alarm_need_warn(cct->_conf->osd_slow_disk_warn_percent)) {
            return OSD_SLOW_DISK_WARN_TYPE_WARN;
        }
        return OSD_SLOW_DISK_WARN_TYPE_NONE;
    }

private:
    double get_level1();
    double get_level2();
    int read_sysfs_file_stat(struct io_stats &s);
    int svctm_score(struct io_stats &new_s, struct io_stats &old_s);

private:
    CephContext *cct;
    PerfCounters *disk_check_perf = nullptr;
    disk_type_t disk_type;
    double level1;
    double level2;
    uint64_t period;
    uint64_t last_check_time_ms;
    uint64_t ticks;

    string device_name;
    string sys_block_path;

    struct io_stats stats[2];
    SlowDiskAlarmScore slow;
    SlowDiskAlarmScore slow_long;
    SlowDiskAlarmScore slow_drop;
};

class SlowDiskAlarmSystem {
public:
    SlowDiskAlarmSystem(CephContext *c) : cct(c) {}
    SlowDiskAlarmSystem() = delete;

    int init(map<string, bool>& devices);
    inline void add_disk(disk_type_t _t, const string &disk_name) {
        disks.emplace_back(cct, _t, disk_name);
    }
    void set_reset() { need_reset = true; }
    int check_disk();
    uint64_t get_disk_status();
    void get_disk_status_str(uint64_t states, map<uint64_t, string> &s, map<string, string> &pm);

private:
    CephContext *cct;
    list<SlowDiskAlarmDisk> disks;
    atomic<bool> need_reset = false;
};

#endif
