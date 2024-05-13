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

#include <iostream>

#include "common/dout.h"
#include "include/random.h"
#include "SlowDiskCheck.h"

#define dout_context cct
#define dout_subsys ceph_subsys_osd

// config
#define DISK_CHECK_MIN_PERIOD 1
#define DISK_CHECK_MAX_PERIOD 86400
#define DISK_CHECK_MIN_LEVEL 0.001
#define DISK_CHECK_MAX_READ_FAIL_TIME 180
#define DISK_CHECK_STATE_GAP 8

const string SYSFS_BLOCK = "/sys/block";
const string S_STAT      = "stat";

const uint64_t slow_disk_state_mask = OSD_SLOW_DISK_WARN_TYPE_WARN |
                                      OSD_SLOW_DISK_WARN_TYPE_WARN_LONG |
                                      OSD_SLOW_DISK_WARN_TYPE_WARN_DROP;


enum {
  l_osd_slow_check_first = 15500,
  l_osd_slow_disk_check_ignore,
  l_osd_slow_disk_avg_svctm,
  l_osd_slow_disk_avg_slow_svctm,
  l_osd_slow_check_last,
};

using ceph::util::generate_random_number;

ostream &operator<<(ostream &out, const io_stats &s)
{
    out << "diskstats: " << s.rd_ios << " " << s.rd_merges <<  " " << s.rd_sectors << " "
        << s.rd_ticks << " " << s.wr_ios << " " << s.wr_merges << " " << s.wr_sectors << " "
        << s.wr_ticks << " " << s.in_flight << " " << s.io_ticks << " " << s.time_in_queue;
  return out;
}

string get_disk_type_name(disk_type_t _t) {
  if (TYPE_SATA_HDD == _t) {
    return "hdd";
  } else if (TYPE_SATA_SSD == _t) {
    return "sata ssd";
  } else if (TYPE_NVME_SSD == _t) {
    return "nvme";
  } else {
    return "none";
  }
}

void SlowDiskAlarmScore::reset_period(uint64_t new_period) {
    if (scores != nullptr) {
       free(scores);
    }
    period = new_period<1 ? 1 : new_period;
    score = 0;
    have_ops_time = 0;
    ticks = 0;
    scores = (int8_t*) calloc(period, sizeof(int8_t));
    assert(scores != nullptr);
    last_period_need_warn = false;
}

void SlowDiskAlarmScore::alarm_sys_insert_per_period(int8_t new_score) {
    int index = (ticks % period);
    if (ticks >= period) { // ticks start with 0
        if (scores[index] != -1) {
            score -= scores[index];
            --have_ops_time;
        }
    }

    scores[index] = new_score;
    ++ ticks;

    if (new_score != -1) {
        score += new_score;
        ++ have_ops_time;
    }
}

ostream &operator<<(ostream &out, const SlowDiskAlarmScore &s)
{
    out << "score: " << s.score << ", ops: " << s.have_ops_time <<  ", ticks: " << s.ticks;
    if (s.scores != nullptr) {
        out << "[" << (int) s.scores[0];
        for (uint64_t i = 1; i < s.period; i++) {
            out << ", " << (int) s.scores[i];
        }
        out << "]";
    }
  return out;
}

#undef dout_prefix
#define dout_prefix *_dout << "slow_disk_check " << device_name << " "

SlowDiskAlarmDisk::SlowDiskAlarmDisk(CephContext *_c, disk_type_t _t,
        const string &disk_name): cct(_c), disk_type(_t), last_check_time_ms(0), ticks(0),
        device_name(disk_name) {
    sys_block_path = SYSFS_BLOCK + "/" + device_name + "/" + S_STAT;
    try_reset();

    PerfCountersBuilder slow_perf(cct, "osd_slow_disk::" + device_name, l_osd_slow_check_first,
                                  l_osd_slow_check_last);
    slow_perf.add_u64_counter(l_osd_slow_disk_check_ignore, "osd_slow_disk_check_ignore",
                              "the number of times that osd ignore slow disk check");
    slow_perf.add_time_avg(l_osd_slow_disk_avg_svctm, "l_osd_svctm", "the svctm of disk");
    slow_perf.add_time_avg(l_osd_slow_disk_avg_slow_svctm, "l_osd_slow_svctm",
                          "the slow svctm of disk");
    disk_check_perf = slow_perf.create_perf_counters();
    cct->get_perfcounters_collection()->add(disk_check_perf);
}

// The configuration of slow disk check  may have changed,
// if it changes, we need to reset all statistics
void SlowDiskAlarmDisk::try_reset() {
    level1 = get_level1();
    level2 = get_level2();
    period = cct->_conf->osd_slow_disk_check_min_period;
    if (period < DISK_CHECK_MIN_PERIOD || period > DISK_CHECK_MAX_PERIOD) {
        period = 1;
    }
    last_check_time_ms = 0;
    ticks = 0;

    // reset slow
    uint64_t period_warn = cct->_conf->osd_slow_disk_check_warn_interval;
    period_warn = period_warn < 1 ? 1 : period_warn;
    slow.reset_period(period_warn);

    // reset slow long
    uint64_t period_long = cct->_conf->osd_slow_disk_check_warn_long_interval;
    period_long /= period_warn;
    slow_long.reset_period(period_long);

    // reset slow drop
    uint64_t period_drop = cct->_conf->osd_slow_disk_check_drop_interval;
    period_drop /= period_warn;
    slow_drop.reset_period(period_drop);

    ldout(cct, 0) << __func__ << " " << " reset slow disk alarm system, level1="
                  << level1 << " level2=" << level2 << " period=" << period
                  << " slow.period=" << slow.period << " long.period=" << slow_long.period
                  << " drop.period=" << slow_drop.period << dendl;
}

double SlowDiskAlarmDisk::get_level1() {
    double level_value = 0;
    switch (disk_type) {
    case TYPE_SATA_HDD:
        level_value = cct->_conf->osd_slow_disk_check_level1_hdd;
        break;
    case TYPE_SATA_SSD:
        level_value = cct->_conf->osd_slow_disk_check_level1_ssd;
        break;
    case TYPE_NVME_SSD:
        level_value = cct->_conf->osd_slow_disk_check_level1_nvme;
        break;
    default:
        level_value = cct->_conf->osd_slow_disk_check_level1_hdd;
        break;
    }
    if (level_value < DISK_CHECK_MIN_LEVEL) {
        level_value = 0;
    }
    return level_value;
}

double SlowDiskAlarmDisk::get_level2() {
    int level_value = 0;
    switch (disk_type) {
    case TYPE_SATA_HDD:
        level_value = cct->_conf->osd_slow_disk_check_level2_hdd;
        break;
    case TYPE_SATA_SSD:
        level_value = cct->_conf->osd_slow_disk_check_level2_ssd;
        break;
    case TYPE_NVME_SSD:
        level_value = cct->_conf->osd_slow_disk_check_level2_nvme;
        break;
    default:
        level_value = cct->_conf->osd_slow_disk_check_level2_hdd;
        break;
    }
    if (level_value < DISK_CHECK_MIN_LEVEL) {
        level_value = 0;
    }
    return level_value;
}

int SlowDiskAlarmDisk::read_sysfs_file_stat(struct io_stats &s)
{
    FILE *fp;
    int i;
    errno = 0;

    if ((fp = fopen(sys_block_path.c_str(), "r")) == NULL) {
        ldout(cct, 0) << __func__ << " ERROR: failed to open " << sys_block_path
                      << " ret=" << -errno << dendl;
        return -errno;
    }

    i = fscanf(fp, "%lu %lu %lu %lu %lu %lu %lu %u %u %u %u",
               &s.rd_ios, &s.rd_merges, &s.rd_sectors, &s.rd_ticks,
               &s.wr_ios, &s.wr_merges, &s.wr_sectors, &s.wr_ticks,
               &s.in_flight, &s.io_ticks, &s.time_in_queue);
    fclose(fp);
    if (i != 11) {
        ldout(cct, 0) << __func__ << " ERROR: failed to read disk stat, raeded count="
                      << i << dendl;
        return -1;
    }
    ldout(cct, 25) << __func__ << ": " << s << dendl;
    return 0;
}

// return
// -1: no ops
//  0: level0
//  1: level1
//  2: leval2
int SlowDiskAlarmDisk::svctm_score(struct io_stats &new_s, struct io_stats &old_s) {
    double svctm = 0;
    if (unlikely(cct->_conf->osd_slow_disk_debug_inject_slow_op)) { // for debug
        int ret = generate_random_number(0, 100);
        if ((uint64_t) ret < cct->_conf->osd_slow_disk_debug_inject_slow_op_percent) {
            svctm = generate_random_number(
                    cct->_conf->osd_slow_disk_debug_inject_slow_op_range_start,
                    cct->_conf->osd_slow_disk_debug_inject_slow_op_range_end);

        }
        ldout(cct, 25) << __func__ << " inject svctm " << fixed << setprecision(3) << svctm << dendl;
    } else {
        int ops = (new_s.rd_ios + new_s.wr_ios - old_s.rd_ios - old_s.wr_ios);
        if (ops <=  0) {
            return -1;
        }
        svctm = (double (new_s.io_ticks-old_s.io_ticks)) / (double) ops;
        ldout(cct, 25) << __func__ << " new.rd_ios=" << new_s.rd_ios
                       << " new.wr_ios=" << new_s.wr_ios << " new.io_ticks=" << new_s.io_ticks
                       << " old.rd_ios=" << old_s.rd_ios << " old.wr_ios=" << old_s.wr_ios
                       << " old.io_ticks=" << old_s.io_ticks << fixed << setprecision(3)
                       << " svctm=" << svctm << dendl;
    }
    disk_check_perf->tinc(l_osd_slow_disk_avg_svctm, make_timespan(svctm));
    if (svctm < level1) {
        return 0;
    } else if (svctm < level2) {
        disk_check_perf->tinc(l_osd_slow_disk_avg_slow_svctm, make_timespan(svctm));
        return 1;
    } else {
        disk_check_perf->tinc(l_osd_slow_disk_avg_slow_svctm, make_timespan(svctm));
        return 2;
    }
}

int SlowDiskAlarmDisk::check_disk() {
    uint64_t now_ms = ceph_clock_now().to_msec();
    if (last_check_time_ms + period*1000 > now_ms) {
        return 0;
    }

    int score = 0, ops = 0;
    struct io_stats &stat_new = stats[ticks%2];
    struct io_stats &stat_old = stats[(ticks+1)%2];
    int ret = read_sysfs_file_stat(stat_new);
    if (ret >= 0) {
         ++ticks;
        // the first to read disk stat
        if (ticks < 2) {
            return 0;
        }
        ops = (stat_new.rd_ios + stat_new.wr_ios - stat_old.rd_ios - stat_old.wr_ios);
        score = svctm_score(stat_new, stat_old);
    }

    // the svctm of slow disk may be very small, because its IO pressure is low
    // so, don't record the svctm of the idle disk
    if (score <= 0 && ops <= (int) cct->_conf->osd_slow_disk_min_ops_each_period) {
        disk_check_perf->inc(l_osd_slow_disk_check_ignore);
        ldout(cct, 25) << __func__ << " ignore this idle period: score=" << score
                       << " ops=" << ops << dendl;
        return 0;
    }

    slow.alarm_sys_insert_per_period(score);
    if (score > 0) {
        ldout(cct, 0) << __func__ << " WARN: abnormal score " << score << " ops " << ops
                      << " slow " << slow << dendl;
    } else {
        ldout(cct, 25) << __func__ << " insert score " << score << " ops " << ops
                       << " slow " << slow << dendl;
    }
    // slow disk check may complete one cycle
    if (slow.ticks % slow.period == 0) {
        if (slow.have_ops_time == 0) { // no ops
            score = -1;
        } else if (slow.alarm_need_warn(cct->_conf->osd_slow_disk_warn_percent)) {
            score = 1;
        } else {
            score = 0;
        }
        slow_long.alarm_sys_insert_per_period(score);
        slow_drop.alarm_sys_insert_per_period(score);
        if (score > 0) {
            ldout(cct, 0) << __func__ << " WARN: abnormal score, slow_long " << slow_long << dendl;
            ldout(cct, 0) << __func__ << " WARN: abnormal score, slow_drop " << slow_drop << dendl;
        } else {
            ldout(cct, 25) << __func__ << " slow_long " << slow_long << dendl;
            ldout(cct, 25) << __func__ << " slow_drop " << slow_drop << dendl;
        }
    }
    return ret;
}

#undef dout_prefix
#define dout_prefix *_dout << "slow_disk_check "

int SlowDiskAlarmSystem::init(map<string, bool> &devices) {
    disk_type_t _t;
    string device_name;

    for (auto iter = devices.begin(); iter != devices.end(); ++iter) {
        device_name = split_block_device_name(iter->first);
        if (iter->second) {
            _t = TYPE_SATA_HDD;
        } else if (device_name.find("nvme") != string::npos) {
            _t = TYPE_NVME_SSD;
        } else {
            _t = TYPE_SATA_SSD;
        }
        ldout(cct, 1) << __func__ << " add device " << device_name
                      << " type: " << (int) _t << dendl;
        add_disk(_t, device_name);
    }
    return 0;
}

int SlowDiskAlarmSystem::check_disk() {
    ldout(cct, 25) << __func__ << " slow disk check start" << dendl;
    if (need_reset.load()) {
        for (auto iter = disks.begin(); iter != disks.end(); ++iter) {
            iter->try_reset();
        }
        need_reset = false;
    }
    for (auto iter = disks.begin(); iter != disks.end(); ++iter) {
        iter->check_disk();
    }
    return 0;
}

uint64_t SlowDiskAlarmSystem::get_disk_status() {
    uint64_t new_state = 0;
    for (auto iter = disks.begin(); iter != disks.end(); ++iter) {
        slow_disk_warn_t state = iter->alarm_need_warn();
        new_state <<= DISK_CHECK_STATE_GAP;
        new_state |= (uint64_t) state;
        ldout(cct, 25) << __func__ << " disk " << iter->get_device_name()
                       << " state " <<  new_state << " "
                       << osd_slow_disk_alarm_warn_str(state) << dendl;
    }
    return new_state;
}

void SlowDiskAlarmSystem::get_disk_status_str(uint64_t states, map<uint64_t, string> &s,
                                              map<string, string> &pm) {
    s.clear();
    for (auto iter = disks.rbegin(); iter != disks.rend(); ++iter) {
        uint64_t state = states & slow_disk_state_mask;
        string &slow_disks = s[state];
        if (!slow_disks.empty()) {
            slow_disks.append(",");
        }
        s[state].append(iter->get_device_name());
        states >>= 8;
    }
    for (uint64_t i = OSD_SLOW_DISK_WARN_TYPE_WARN; i < OSD_SLOW_DISK_WARN_TYPE_LAST; ++i) {
        string state_key = slow_disk_state_key + to_string(i);
        auto iter = s.find(i);
        if (iter != s.end()) {
            pm[state_key] = iter->second;
            ldout(cct, 0) << __func__ << " WARN: [" << iter->second << "], "
                          << osd_slow_disk_alarm_warn_str(i) << dendl;
        } else {
            pm.erase(state_key);
        }
    }
}
