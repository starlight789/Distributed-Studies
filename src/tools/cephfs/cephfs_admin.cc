// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include <iostream>
#include <string>
#include <vector>

#include "common/ceph_argparse.h"
#include "common/dout.h"
#include "common/errno.h"

#include "global/global_context.h"
#include "global/global_init.h"

#include "include/util.h"
#include "include/rados/librados.hpp"

#include "include/cephfs/cephfs_basic_types.h"
#include "MDSUtility.h"

#define dout_context g_ceph_context
#define dout_subsys ceph_subsys_mds
#undef dout_prefix
#define dout_prefix *_dout << __func__ << ": "

using std::cout;
using namespace librados;

void usage() {
  cout << "usage: cephfs-admin <cmd> [options...]" <<std::endl;
  cout << "command:\n";
  cout << "  user create              create a new user\n";
  cout << "  user info                get user info\n";
  cout << "  user rm                  remove user\n";
  cout << "  user list                list users\n";
  cout << "  dir create               create a new dir\n";
  cout << "  dir rm                   remove dir\n";
  cout << "  dir list                 list dirs\n";
  cout << "options:\n";
  cout << "   --uid=<id>              user id\n";
  cout << "   --email=<email>         user's email address\n";
  cout << "   --dir-id=<dir-id>       directory id\n";
  cout << "\n";
}

enum {
  OPT_NO_CMD = 0,
  OPT_USER_CREATE,
  OPT_USER_INFO,
  OPT_USER_RM,
  OPT_USER_LIST,
  OPT_DIR_CREATE,
  OPT_DIR_RM,
  OPT_DIR_LIST,
};

unsigned default_op_size = 1 << 22;

static int get_cmd(const char *cmd, const char *prev_cmd, const char *prev_prev_cmd, bool *need_more)
{
  using ceph::util::match_str;

  *need_more = false;
  // NOTE: please keep the checks in alphabetical order !!!
  if (strcmp(cmd, "user") == 0 ||
      strcmp(cmd, "dir") == 0) {
    *need_more = true;
    return 0;
  }

  if (!prev_cmd)
    return -EINVAL;

  if (strcmp(prev_cmd, "user") == 0) {
    if (strcmp(cmd, "create") == 0)
      return OPT_USER_CREATE;
    if (strcmp(cmd, "info") == 0)
      return OPT_USER_INFO;
    if (strcmp(cmd, "rm") == 0)
      return OPT_USER_RM;
    if (strcmp(cmd, "list") == 0)
      return OPT_USER_LIST;
  } else if (strcmp(prev_cmd, "dir") == 0) {
    if (strcmp(cmd, "create") == 0)
      return OPT_DIR_CREATE;
    if (strcmp(cmd, "rm") == 0)
      return OPT_DIR_RM;
    if (strcmp(cmd, "list") == 0)
      return OPT_DIR_LIST;
  }
  return -EINVAL;
}

int main(int argc, const char **argv) {

  vector<const char*> args;
  argv_to_vec(argc, (const char **)argv, args);
  if (args.empty()) {
    std::cerr << argv[0] << ": -h or --help for usage" << std::endl;
    exit(1);
  }
  if (ceph_argparse_need_usage(args)) {
    usage();
    exit(0);
  }

  auto cct = global_init(NULL, args, CEPH_ENTITY_TYPE_CLIENT,
                         CODE_ENVIRONMENT_UTILITY, 0);
  common_init_finish(g_ceph_context);

  dout(10) << __func__ << dendl;
  
  std::string usr_id, usr_email, dir_name;

  std::string val;
  bool need_more;
  int ret;

  for (std::vector<const char*>::iterator i = args.begin(); i != args.end(); ) {
    if (ceph_argparse_double_dash(args, i)) {
      break;
    } else if (ceph_argparse_witharg(args, i, &val, "-i", "--uid", (char*)NULL)) {
      usr_id = val;
    } else if (ceph_argparse_witharg(args, i, &val, "-e", "--email", (char*)NULL)) {
      usr_email = val;
    } else if (ceph_argparse_witharg(args, i, &val, "--dir-id", (char*)NULL)) {
      dir_name = val;
    } else {
      ++i;
    }
  }

  if (args.empty()) {
    usage();
    exit(1);
  } else {
    const char *prev_cmd = NULL;
    const char *prev_prev_cmd = NULL;
    std::vector<const char *>::iterator i;
    int opt_cmd;
    for (i = args.begin(); i != args.end(); ++i) {
      opt_cmd = get_cmd(*i, prev_cmd, prev_prev_cmd, &need_more);
      if (opt_cmd < 0) {
        cerr << "unrecognized arg " << *i << std::endl;
        exit(1);
      }
      if (!need_more) {
        ++i;
        break;
      }
      prev_prev_cmd = prev_cmd;
      prev_cmd = *i;
    }

    if (opt_cmd == OPT_NO_CMD) {
      cerr << "no command" << std::endl;
      exit(1);
    }
    
    MDSUtility mt;
    mt.init();
    auto fsmap = mt.get_fsmap();
    assert(fsmap->get_epoch());
    auto fs = fsmap->get_filesystem();

    int64_t meta_pool = fs->mds_map.get_metadata_pool();

    librados::Rados rados;
    librados::IoCtx io_ctx;

    ret = rados.init_with_context(g_ceph_context);
    if (ret < 0) {
      cerr << "couldn't initialize rados: " << cpp_strerror(ret) << std::endl;
      goto out;
    }

    ret = rados.connect();
      if (ret) {
      cerr << "couldn't connect to cluster: " << cpp_strerror(ret) << std::endl;
      ret = -1;
      goto out;
    }

    ret = rados.ioctx_create2(meta_pool, io_ctx);
    if (ret < 0) {
      cerr << "error opening pool id " << meta_pool << ": "
            << cpp_strerror(ret) << std::endl;
      goto out;
    }

    io_ctx.set_namespace(CEPHFS_USER_NAMESPACE);

    switch (opt_cmd) {
    case OPT_USER_CREATE:
      {
        time_t timestamp = time(NULL);
        if(usr_id == "") {
          cerr << "input the usr name" << std::endl;
          goto out;
        }

        cephfs_user cu(usr_id, usr_email, timestamp);
        bufferlist bl;
        encode(cu, bl);
        ObjectWriteOperation op;
        op.write_full(bl);
        op.mtime(&timestamp);
        ret = io_ctx.operate(usr_id, &op);
        if (ret < 0) {
          cerr << " error create user " << usr_id << cpp_strerror(ret) << std::endl;
          goto out;
        }

        map<string, bufferlist> values;
        bl.clear();
        bl.append("");
        values[usr_id] = bl;
        ret = io_ctx.omap_set(CEPHFS_USER_OBJ, values);
        if (ret < 0) {
          cerr << " error omap_set " << usr_id << cpp_strerror(ret) << std::endl;
          goto out;
        }
      }
      break;

    case OPT_USER_INFO:
      {
        bufferlist bl;
        if(usr_id == "") {
          cerr << "input the usr name" << std::endl;
          goto out;
        }
        ret = io_ctx.read(usr_id, bl, default_op_size, 0);
        if (ret < 0) {
          cerr << " error read " << usr_id << cpp_strerror(ret) << std::endl;
          goto out;
        }

        cephfs_user out;
        decode(out, bl);
        string str;
        out.to_str(str);
        cout<< str << std::endl;
      }
      break;

    case OPT_USER_RM:
      {
        set<string> keys;
        if(usr_id == "") {
          cerr << "input the usr name" << std::endl;
          goto out;
        }
        keys.insert(usr_id);

        ret = io_ctx.omap_rm_keys(CEPHFS_USER_OBJ, keys);
        if (ret < 0) {
          cerr << "error removing omap key " << CEPHFS_USER_OBJ << cpp_strerror(ret) << std::endl;
          goto out;
        } else {
          ret = 0;
        }

        ret = io_ctx.remove(usr_id);
        if (ret < 0) {
          cerr << " error remove user " << usr_id << cpp_strerror(ret) << std::endl;
          goto out;
        }
      }
      break;

    case OPT_USER_LIST:
      {
        set<string> out_keys;
        ret = io_ctx.omap_get_keys(CEPHFS_USER_OBJ, "", LONG_MAX, &out_keys);
        if (ret < 0) {
          cerr << "error getting omap key set " << CEPHFS_USER_OBJ << cpp_strerror(ret) << std::endl;
          goto out;
        }

        for (set<string>::iterator iter = out_keys.begin();
          iter != out_keys.end(); ++iter) {
          cout << *iter << std::endl;
        }
      }
      break;

    case OPT_DIR_CREATE:
      {
        if(usr_id == "" || dir_name == "") {
          cerr << "input the usr name or dir name" << std::endl;
          goto out;
        }
        uint64_t psize;
        time_t pmtime;
        ret = io_ctx.stat(usr_id, &psize, &pmtime);
        if(ret < 0) {
          cerr << "the usr " << usr_id << " is not exist, the errno is " <<
               cpp_strerror(ret) << std::endl;
          goto out;
        } 
        map<string, bufferlist> values;
        bufferlist bl;
        bl.append("");
        values[dir_name] = bl;
        
        ret = io_ctx.omap_set(usr_id, values);
        if (ret < 0) {
          cerr << " error omap_set " << dir_name << cpp_strerror(ret) << std::endl;
          goto out;
        }
      }
      break;

    case OPT_DIR_RM:
      {
        if(usr_id == "" || dir_name == "") {
          cerr << "input the usr name or dir name" << std::endl;
          goto out;
        }
        set<string> keys;
        keys.insert(dir_name);

        ret = io_ctx.omap_rm_keys(usr_id, keys);
        if (ret < 0) {
          cerr << "error removing omap key " << dir_name << cpp_strerror(ret) << std::endl;
          goto out;
        } else {
          ret = 0;
        }
      }
      break;

    case OPT_DIR_LIST:
      {
        if(usr_id == "") {
          cerr << "input the usr name" << std::endl;
          goto out;
        }
        set<string> out_keys;
        ret = io_ctx.omap_get_keys(usr_id, "", LONG_MAX, &out_keys);
        if (ret < 0) {
          cerr << "error getting omap key set " << usr_id << cpp_strerror(ret) << std::endl;
          goto out;
        }

        for (set<string>::iterator iter = out_keys.begin();
          iter != out_keys.end(); ++iter) {
          cout << *iter << std::endl;
        }
      }
    }
  }
out:
  return (ret < 0) ? 1 : 0;
}
