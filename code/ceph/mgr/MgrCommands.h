// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

/* no guard; may be included multiple times */

// see MonCommands.h

COMMAND("pg stat", "show placement group status.",
	"pg", "r")
COMMAND("pg getmap", "get binary pg map to -o/stdout", "pg", "r")

COMMAND("pg dump "							\
	"name=dumpcontents,type=CephChoices,strings=all|summary|sum|delta|pools|osds|pgs|pgs_brief,n=N,req=false", \
	"show human-readable versions of pg map (only 'all' valid with plain)", "pg", "r")
COMMAND("pg dump_json "							\
	"name=dumpcontents,type=CephChoices,strings=all|summary|sum|pools|osds|pgs,n=N,req=false", \
	"show human-readable version of pg map in json only",\
	"pg", "r")
COMMAND("pg dump_pools_json", "show pg pools info in json only",\
	"pg", "r")

COMMAND("pg ls-by-pool "		\
        "name=poolstr,type=CephString " \
	"name=states,type=CephString,n=N,req=false", \
	"list pg with pool = [poolname]", "pg", "r")
COMMAND("pg ls-by-primary " \
        "name=osd,type=CephOsdName " \
        "name=pool,type=CephInt,req=false " \
	"name=states,type=CephString,n=N,req=false", \
	"list pg with primary = [osd]", "pg", "r")
COMMAND("pg ls-by-osd " \
        "name=osd,type=CephOsdName " \
        "name=pool,type=CephInt,req=false " \
	"name=states,type=CephString,n=N,req=false", \
	"list pg on osd [osd]", "pg", "r")
COMMAND("pg ls " \
        "name=pool,type=CephInt,req=false " \
	"name=states,type=CephString,n=N,req=false", \
	"list pg with specific pool, osd, state", "pg", "r")
COMMAND("pg dump_stuck " \
	"name=stuckops,type=CephChoices,strings=inactive|unclean|stale|undersized|degraded,n=N,req=false " \
	"name=threshold,type=CephInt,req=false",
	"show information about stuck pgs",\
	"pg", "r")
COMMAND("pg debug " \
	"name=debugop,type=CephChoices,strings=unfound_objects_exist|degraded_pgs_exist", \
	"show debug info about pgs", "pg", "r")

COMMAND("pg scrub name=pgid,type=CephPgid", "start scrub on <pgid>", \
	"pg", "rw")
COMMAND("pg deep-scrub name=pgid,type=CephPgid", "start deep-scrub on <pgid>", \
	"pg", "rw")
COMMAND("pg repair name=pgid,type=CephPgid", "start repair on <pgid>", \
	"pg", "rw")

COMMAND("pg force-recovery name=pgid,type=CephPgid,n=N", "force recovery of <pgid> first", \
	"pg", "rw")
COMMAND("pg force-backfill name=pgid,type=CephPgid,n=N", "force backfill of <pgid> first", \
	"pg", "rw")
COMMAND("pg cancel-force-recovery name=pgid,type=CephPgid,n=N", "restore normal recovery priority of <pgid>", \
	"pg", "rw")
COMMAND("pg cancel-force-backfill name=pgid,type=CephPgid,n=N", "restore normal backfill priority of <pgid>", \
	"pg", "rw")

// stuff in osd namespace
COMMAND("osd perf", \
        "print dump of OSD perf summary stats", \
        "osd", \
        "r")
COMMAND("osd df " \
	"name=output_method,type=CephChoices,strings=plain|tree,req=false", \
	"show OSD utilization", "osd", "r")
COMMAND("osd blocked-by", \
	"print histogram of which OSDs are blocking their peers", \
	"osd", "r")
COMMAND("osd pool stats " \
        "name=pool_name,type=CephPoolname,req=false",
        "obtain stats from all pools, or from specified pool",
        "osd", "r")
COMMAND("osd reweight-by-utilization " \
	"name=oload,type=CephInt,req=false " \
	"name=max_change,type=CephFloat,req=false "			\
	"name=max_osds,type=CephInt,req=false "			\
	"name=no_increasing,type=CephChoices,strings=--no-increasing,req=false",\
	"reweight OSDs by utilization [overload-percentage-for-consideration, default 120]", \
	"osd", "rw")
COMMAND("osd test-reweight-by-utilization " \
	"name=oload,type=CephInt,req=false " \
	"name=max_change,type=CephFloat,req=false "			\
	"name=max_osds,type=CephInt,req=false "			\
	"name=no_increasing,type=CephBool,req=false",\
	"dry run of reweight OSDs by utilization [overload-percentage-for-consideration, default 120]", \
	"osd", "r")
COMMAND("osd reweight-by-pg " \
	"name=oload,type=CephInt,req=false " \
	"name=max_change,type=CephFloat,req=false "			\
	"name=max_osds,type=CephInt,req=false "			\
	"name=pools,type=CephPoolname,n=N,req=false",			\
	"reweight OSDs by PG distribution [overload-percentage-for-consideration, default 120]", \
	"osd", "rw")
COMMAND("osd test-reweight-by-pg " \
	"name=oload,type=CephInt,req=false " \
	"name=max_change,type=CephFloat,req=false "			\
	"name=max_osds,type=CephInt,req=false "			\
	"name=pools,type=CephPoolname,n=N,req=false",			\
	"dry run of reweight OSDs by PG distribution [overload-percentage-for-consideration, default 120]", \
	"osd", "r")

COMMAND("osd safe-to-destroy name=ids,type=CephString,n=N",
	"check whether osd(s) can be safely destroyed without reducing data durability",
	"osd", "r")
COMMAND("osd ok-to-stop name=ids,type=CephString,n=N",
	"check whether osd(s) can be safely stopped without reducing immediate"\
	" data availability", "osd", "r")

COMMAND("osd scrub " \
	"name=who,type=CephString", \
	"initiate scrub on osd <who>, or use <all|any> to scrub all", \
        "osd", "rw")
COMMAND("osd deep-scrub " \
	"name=who,type=CephString", \
	"initiate deep scrub on osd <who>, or use <all|any> to deep scrub all", \
        "osd", "rw")
COMMAND("osd repair " \
	"name=who,type=CephString", \
	"initiate repair on osd <who>, or use <all|any> to repair all", \
        "osd", "rw")

COMMAND("service dump",
        "dump service map", "service", "r")
COMMAND("service status",
        "dump service state", "service", "r")

COMMAND("config show " \
	"name=who,type=CephString name=key,type=CephString,req=False",
	"Show running configuration",
	"mgr", "r")
COMMAND("config show-with-defaults " \
	"name=who,type=CephString",
	"Show running configuration (including compiled-in defaults)",
	"mgr", "r")


