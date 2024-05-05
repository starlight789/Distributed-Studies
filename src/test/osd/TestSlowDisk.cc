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

#include "gtest/gtest.h"

#include "global/global_context.h"
#include "global/global_init.h"
#include "common/common_init.h"
#include "common/ceph_argparse.h"
#include "osd/SlowDiskCheck.h"

#include <iostream>

using namespace std;

int main(int argc, char **argv) {
    std::vector<const char*> args(argv, argv+argc);
    auto cct = global_init(nullptr, args, CEPH_ENTITY_TYPE_CLIENT,
                           CODE_ENVIRONMENT_UTILITY, CINIT_FLAG_NO_DEFAULT_CONFIG_FILE);
    common_init_finish(g_ceph_context);
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

TEST(TESTSlowDiskAlarmScore, Score) {
    SlowDiskAlarmScore scores;
    scores.reset_period(0);
    ASSERT_EQ(1, scores.period);

    scores.reset_period(10);
    std::vector<std::pair<int8_t, bool>> ops = {
        {-1, false}, // 1
        {-1, false},
        {-1, false},
        {-1, false},
        {-1, false}, // 5
        {-1, false},
        {-1, false},
        {-1, false},
        {-1, false},
        {-1, false}, // 10
        {0, false},
        {0, false},
        {0, false},
        {0, false},
        {1, true}, // 15
        {0, false},
        {1, true},
        {0, true},
        {0, true},
        {0, true}, // 20
        {0, true},
        {0, true},
        {0, true},
        {0, true},
        {0, false}, // 25
    };

    for (auto &p : ops) {
        scores.alarm_sys_insert_per_period(p.first);
        ASSERT_EQ(p.second, scores.alarm_need_warn(20));
    }
}
