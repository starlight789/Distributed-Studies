// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2004-2006 Sage Weil <sage@newdream.net>
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation.  See file COPYING.
 *
 */


/**
 * This header describes the subsystems (each one gets a "--debug-<subsystem>"
 * log verbosity setting), along with their default verbosities.
 */

DEFAULT_SUBSYS(0, 0)
SUBSYS(lockdep, 0, 0)
SUBSYS(context, 0, 0)
SUBSYS(crush, 0, 0)
SUBSYS(mds, 0, 5)
SUBSYS(mds_balancer, 1, 5)
SUBSYS(mds_locker, 1, 5)
SUBSYS(mds_log, 1, 5)
SUBSYS(mds_log_expire, 1, 5)
SUBSYS(mds_migrator, 1, 5)
SUBSYS(buffer, 0, 0)
SUBSYS(timer, 0, 0)
SUBSYS(filer, 0, 0)
SUBSYS(striper, 0, 0)
SUBSYS(objecter, 0, 0)
SUBSYS(rados, 0, 0)
SUBSYS(rbd, 0, 5)
SUBSYS(rbd_mirror, 0, 5)
SUBSYS(rbd_replay, 0, 5)
SUBSYS(journaler, 0, 5)
SUBSYS(objectcacher, 0, 0)
SUBSYS(client, 0, 0)
SUBSYS(osd, 0, 0)
SUBSYS(optracker, 0, 0)
SUBSYS(objclass, 0, 0)
SUBSYS(filestore, 1, 3)
SUBSYS(journal, 1, 3)
SUBSYS(ms, 0, 0)
SUBSYS(mon, 0, 0)
SUBSYS(monc, 0, 0)
SUBSYS(paxos, 1, 5)
SUBSYS(tp, 0, 0)
SUBSYS(auth, 0, 0)
SUBSYS(crypto, 0, 0)
SUBSYS(finisher, 0, 0)
SUBSYS(reserver, 1, 1)
SUBSYS(heartbeatmap, 0, 0)
SUBSYS(perfcounter, 0, 0)
SUBSYS(rgw, 0, 0)                 // log level for the Rados gateway
SUBSYS(rgw_sync, 0, 0)
SUBSYS(civetweb, 0, 0)
SUBSYS(javaclient, 1, 5)
SUBSYS(asok, 1, 5)
SUBSYS(throttle, 0, 0)
SUBSYS(refs, 0, 0)
SUBSYS(xio, 1, 5)
SUBSYS(compressor, 0, 0)
SUBSYS(bluestore, 0, 0)
SUBSYS(bluefs, 0, 0)
SUBSYS(bdev, 0, 0)
SUBSYS(kstore, 0, 0)
SUBSYS(rocksdb, 0, 0)
SUBSYS(leveldb, 4, 5)
SUBSYS(memdb, 4, 5)
SUBSYS(fuse, 1, 5)
SUBSYS(mgr, 1, 5)
SUBSYS(mgrc, 0, 0)
SUBSYS(dpdk, 0, 0)
SUBSYS(license, 5, 5)
SUBSYS(eventtrace, 0, 0)
