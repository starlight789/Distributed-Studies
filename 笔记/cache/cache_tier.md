Ceph Cache Tiering
# 1. cache mode
## 1.1 Write Back
- Ceph客户端将数据写入缓存层并从缓存层接收ACK。随着时间的流逝，写入缓存层的数据将迁移到存储层，并从缓存层中清除。从概念上讲，缓存层覆盖在后备存储层的“前面”。当Ceph客户端需要驻留在存储层中的数据时，缓存分层代理在读取时将数据迁移到缓存层，然后将其发送到Ceph客户端。此后，Ceph客户端可以使用缓存层执行I / O，直到数据变为非活动状态为止。
- 该模式适合于大量修改数据的应用场景（例如，照片/视频编辑，交易数据等）。

## 1.2. Read Forward
- client 发起读请求，对象不在 cache pool 中，出现 cache miss 状态，就返回 redirect 信息给客户端，客户端再根据返回的信息再次直接向 base pool 发起读请求
![](/Distributed-Studies/笔记/image/cache/read-forward.png) 

## 1.3. Read Proxy
- 此模式将使用缓存层中已经存在的任何对象，但是如果一个对象不在缓存中，则请求将代理到基层。这对于将writeback模式转换为禁用的缓存非常有用，因为它允许工作负载在缓存耗尽时正常工作，而不需要向缓存添加任何新对象。
![](/Distributed-Studies/笔记/image/cache/read-proxy.png) 

## 1.4. Read Only
- 仅在读取操作时将对象提升到缓存中；写操作被转发到基本层。该种模式下，cache pool 设置成单副本，极大减少缓存空间的占用，当cache pool层失效时，也不会有数据丢失。
- 此模式适用于不需要存储系统强制一致性的只读工作负载。适合一次写入多次读取的场景(警告:当基本层中的对象更新时，Ceph不会尝试将这些更新同步到缓存中的相应对象。因为这种模式被认为是实验性的，所以必须通过一个yes-i-really-mean-it的选项来启用它。)

## 1.5 Forward
FORWARD模式表示所有到达cache tier存储池的请求都不会处理，直接将它的后端存储池的ID回复给请求方，并返回-ENOENT的错误号，具体实现比较简单。
该模式的用途是在删除WRITEBACK模式的cache tier时，需将其cache mode先设置为FORWARD，并主动调用cache tier的flush和evict操作，确保cache tier存储池的对象全部evict和flush到后端存储池，保证这个过程中不会有新的数据写入。

# 2. HitSet
- 在 write back/read forward/read proxy 模式下需要 HitSet 来记录缓存命中。read only 不需要
HitSet 用于跟踪和统计对象的访问行为，记录对象是否存在缓存中。定义了一个缓存查找到抽象接口，目前提供了三种实现方式：ExplicitHashHitSet，ExplicitObjectHitSet，BloomHitSet
ceph/src/osd/HitSet.h 定义了抽象接口，同时该头文件中包含了具体的 HitSet 实现

<details close> <summary>Impl code</summary>

```c++{.line-numbers}
  ...
  /// abstract interface for a HitSet implementation
  class Impl {
  public:
    virtual impl_type_t get_type() const = 0;
    virtual bool is_full() const = 0;
    virtual void insert(const hobject_t& o) = 0;
    virtual bool contains(const hobject_t& o) const = 0;
    virtual unsigned insert_count() const = 0;
    virtual unsigned approx_unique_insert_count() const = 0;
    virtual void encode(ceph::buffer::list &bl) const = 0;
    virtual void decode(ceph::buffer::list::const_iterator& p) = 0;
    virtual void dump(ceph::Formatter *f) const = 0;
    virtual Impl* clone() const = 0;
    virtual void seal() {}
    virtual ~Impl() {}
  };
  ...
```
</details>

## 2.1 ExplicitHashHitSet
- ceph/src/osd/HitSet.h/class ExplicitHashHitSet
- 基于对象的 32 位 HASH 值的 set 来记录对象的命中，每个对象占用 4 bytes 内存空间
- 优点：空间占用相对较少，但需要根据 HASH 进行全局的扫描遍历比较

## 2.2 ExplicitObjectHitSet
- ceph/src/osd/HitSet.h/class ExplicitObjectHitSet
- 使用一个基于 ceph/src/common/hobject 的 set 来记录对象的命中，占用的内存取决于对象的关键信息的大小
- 使用内存中缓存数据结构来进行判断带来的优点就是实现相对简单直观，但占用的内存空间相对较大。
  
## 2.3 BloomHitSet
ceph/src/osd/HitSet.h/class BloomHitSet
采用了压缩的 Bloom Filter 的方式来记录对象是否在缓存中，进一步减少了内存占用空间。

# 3. IO
![](/Distributed-Studies/笔记/image/cache/cache-process.png)  
- WriteBack 策略：
![](/Distributed-Studies/笔记/image/cache/WriteBackProcess.png)  
- 针对其中涉及到的几个封装好的方法的操作： do_cache_redirect， do_proxy_read， do_proxy_write, promote_object
![](/Distributed-Studies/笔记/image/cache/proxy-read.png)  
- do_cache_redirect ：客户端请求cache pool，cache pool告诉客户端你应该去base pool中请求，客户端收到应答后，再次发送请求到base pool中请求数据，由base pool告诉客户端请求完成。
  <details close> <summary>do_cache_redirect</summary>

  ```c++{.line-numbers}
  void PrimaryLogPG::do_cache_redirect(OpRequestRef op)
  {
    // Cast the request to MOSDOp
    auto m = op->get_req<MOSDOp>();
    int flags = m->get_flags() & (CEPH_OSD_FLAG_ACK|CEPH_OSD_FLAG_ONDISK);
    
    // 构造 MOSDOpReply 对象
    MOSDOpReply *reply = new MOSDOpReply(m, -ENOENT, get_osdmap_epoch(), flags, false);
    
    // 将请求重定向到指定的存储池 Pool     
    request_redirect_t redir(m->get_object_locator(), pool.info.tier_of);
    reply->set_redirect(redir);
    dout(10) << "sending redirect to pool " << pool.info.tier_of << " for op "
      << op << dendl;
    // 发送响应信息（包含重定向目标存储池的信息和对象的相关信息）	   
    m->get_connection()->send_message(reply);
    return;
  }
  ```
  </details>

- do_proxy_read：客户端发送读请求到cache pool，但是未命中，则cache pool自己会发送请求到base pool中，获取数据后，由cache pool将数据发送给客户端，完成读请求。但是值得注意的是，虽然cache pool读取到了该object，但不会保存在cache pool中，下次请求仍然需要重新向basepool请求。

  <details close> <summary>do_proxy_read</summary>

  ```c++{.line-numbers}
  void PrimaryLogPG::do_proxy_read(OpRequestRef op, ObjectContextRef obc)
  {
    // NOTE: non-const here because the ProxyReadOp needs mutable refs to
    // stash the result in the request's OSDOp vector
    MOSDOp *m = static_cast<MOSDOp*>(op->get_nonconst_req());
    object_locator_t oloc;
    hobject_t soid;
    /* extensible tier */
    // 获取对应的需要查询的对象的信息
    // 判断是否包含 manifest
    if (obc && obc->obs.exists && obc->obs.oi.has_manifest()) {
      switch (obc->obs.oi.manifest.type) {
        // 如果为 redirect 类型，获取对应的重定向 Target
        case object_manifest_t::TYPE_REDIRECT:
        oloc = object_locator_t(obc->obs.oi.manifest.redirect_target);
        // 获取重定向 target 对应的信息
        soid = obc->obs.oi.manifest.redirect_target;  
        break;
        default:
        ceph_abort_msg("unrecognized manifest type");
      }
    } else {
      // 不包含 manifest
      /* proxy */
      soid = m->get_hobj();
      oloc = object_locator_t(m->get_object_locator());
      oloc.pool = pool.info.tier_of;
    }
    unsigned flags = CEPH_OSD_FLAG_IGNORE_CACHE | CEPH_OSD_FLAG_IGNORE_OVERLAY;

    // pass through some original flags that make sense.
    //  - leave out redirection and balancing flags since we are
    //    already proxying through the primary
    //  - leave off read/write/exec flags that are derived from the op
    flags |= m->get_flags() & (CEPH_OSD_FLAG_RWORDERED |
            CEPH_OSD_FLAG_ORDERSNAP |
            CEPH_OSD_FLAG_ENFORCE_SNAPC |
            CEPH_OSD_FLAG_MAP_SNAP_CLONE);

    dout(10) << __func__ << " Start proxy read for " << *m << dendl;

    ProxyReadOpRef prdop(std::make_shared<ProxyReadOp>(op, soid, m->ops));

    ObjectOperation obj_op;
    obj_op.dup(prdop->ops);

    // 判断 Cache Mode 和 缓存是否已满
    // TierAgentState：用于保存 PG 相关的 agent 信息
    if (pool.info.cache_mode == pg_pool_t::CACHEMODE_WRITEBACK &&
        (agent_state && agent_state->evict_mode != TierAgentState::EVICT_MODE_FULL)) {
      for (unsigned i = 0; i < obj_op.ops.size(); i++) {
        ceph_osd_op op = obj_op.ops[i].op;
        switch (op.op) {
    case CEPH_OSD_OP_READ:
    case CEPH_OSD_OP_SYNC_READ:
    case CEPH_OSD_OP_SPARSE_READ:
    case CEPH_OSD_OP_CHECKSUM:
    case CEPH_OSD_OP_CMPEXT:
      op.flags = (op.flags | CEPH_OSD_OP_FLAG_FADVISE_SEQUENTIAL) &
            ~(CEPH_OSD_OP_FLAG_FADVISE_DONTNEED | CEPH_OSD_OP_FLAG_FADVISE_NOCACHE);
        }
      }
    }

    C_ProxyRead *fin = new C_ProxyRead(this, soid, get_last_peering_reset(),
              prdop);
    unsigned n = info.pgid.hash_to_shard(osd->m_objecter_finishers);
    
    // 调用 objecter read 方法读取对象数据
    ceph_tid_t tid = osd->objecter->read(
      soid.oid, oloc, obj_op,
      m->get_snapid(), NULL,
      flags, new C_OnFinisher(fin, osd->objecter_finishers[n]),
      &prdop->user_version,
      &prdop->data_offset,
      m->get_features());
    fin->tid = tid;
    prdop->objecter_tid = tid;
    proxyread_ops[tid] = prdop;
    in_progress_proxy_ops[soid].push_back(op);
  }
  ```
  </details>

- do_proxy_write：类似于 do_proxy_read

  <details close> <summary>do_proxy_write</summary>

  ```c++{.line-numbers}
  void PrimaryLogPG::do_proxy_write(OpRequestRef op, ObjectContextRef obc)
  ```
  </details>


- promote_object：当客户端发送请求到cache pool中，但是cache pool未命中，cache pool会选择将该object从base pool中提升到cache pool中，然后在cache pool进行读写操作，操作完成后告知客户端请求完成，在cache pool会缓存该object，下次直接在cache中处理，和proxy_read存在的区别。

  <details close> <summary>promote_object</summary>

  ```c++{.line-numbers}
  void PrimaryLogPG::promote_object(ObjectContextRef obc,
            const hobject_t& missing_oid,
            const object_locator_t& oloc,
            OpRequestRef op,
            ObjectContextRef *promote_obc)
  {
    hobject_t hoid = obc ? obc->obs.oi.soid : missing_oid;
    ceph_assert(hoid != hobject_t());
    
    // 等待 Scrub 操作完成
    if (write_blocked_by_scrub(hoid)) {
      dout(10) << __func__ << " " << hoid
        << " blocked by scrub" << dendl;
      if (op) {
        waiting_for_scrub.push_back(op);
        op->mark_delayed("waiting for scrub");
        dout(10) << __func__ << " " << hoid
          << " placing op in waiting_for_scrub" << dendl;
      } else {
        dout(10) << __func__ << " " << hoid
          << " no op, dropping on the floor" << dendl;
      }
      return;
    }
    if (op && !check_laggy_requeue(op)) {
      return;
    }
    // Context为空创建一个新的Context
    if (!obc) { // we need to create an ObjectContext
      ceph_assert(missing_oid != hobject_t());
      obc = get_object_context(missing_oid, true);
    }
    if (promote_obc)
      *promote_obc = obc;

    /*
    * Before promote complete, if there are  proxy-reads for the object,
    * for this case we don't use DONTNEED.
    */
    unsigned src_fadvise_flags = LIBRADOS_OP_FLAG_FADVISE_SEQUENTIAL;
    // 获取该对象对应的 proxy_read 等待队列的遍历器
    map<hobject_t, list<OpRequestRef>>::iterator q = in_progress_proxy_ops.find(obc->obs.oi.soid);
    if (q == in_progress_proxy_ops.end()) {
      src_fadvise_flags |= LIBRADOS_OP_FLAG_FADVISE_DONTNEED;
    }

    // 构造 PromoteCallback
    CopyCallback *cb;
    object_locator_t my_oloc;
    hobject_t src_hoid;
    
    // 判断是否有 manifest
    if (!obc->obs.oi.has_manifest()) {
      my_oloc = oloc;
      my_oloc.pool = pool.info.tier_of;
      src_hoid = obc->obs.oi.soid;
      cb = new PromoteCallback(obc, this);
    } else {
      // 有manifest，判断类型是否为 chunk_data
      if (obc->obs.oi.manifest.is_chunked()) {
        src_hoid = obc->obs.oi.soid;
        cb = new PromoteManifestCallback(obc, this);
      } else if (obc->obs.oi.manifest.is_redirect()) {
        // mainfest 类型为 redirect
        object_locator_t src_oloc(obc->obs.oi.manifest.redirect_target);
        my_oloc = src_oloc;
        src_hoid = obc->obs.oi.manifest.redirect_target;
        cb = new PromoteCallback(obc, this);
      } else {
        ceph_abort_msg("unrecognized manifest type");
      }
    }

    unsigned flags = CEPH_OSD_COPY_FROM_FLAG_IGNORE_OVERLAY |
                    CEPH_OSD_COPY_FROM_FLAG_IGNORE_CACHE |
                    CEPH_OSD_COPY_FROM_FLAG_MAP_SNAP_CLONE |
                    CEPH_OSD_COPY_FROM_FLAG_RWORDERED;
                    
    // 复制对象数据
    start_copy(cb, obc, src_hoid, my_oloc, 0, flags,
        obc->obs.oi.soid.snap == CEPH_NOSNAP,
        src_fadvise_flags, 0);

    ceph_assert(obc->is_blocked());

    if (op)
      wait_for_blocked_object(obc->obs.oi.soid, op);

    recovery_state.update_stats(
      [](auto &history, auto &stats) {
        stats.stats.sum.num_promote++;
        return false;
      });
  }

  void PrimaryLogPG::start_copy(CopyCallback *cb, ObjectContextRef obc,
              hobject_t src, object_locator_t oloc,
              version_t version, unsigned flags,
              bool mirror_snapset,
              unsigned src_obj_fadvise_flags,
              unsigned dest_obj_fadvise_flags)
  {
    const hobject_t& dest = obc->obs.oi.soid;
    dout(10) << __func__ << " " << dest
      << " from " << src << " " << oloc << " v" << version
      << " flags " << flags
      << (mirror_snapset ? " mirror_snapset" : "")
      << dendl;

    ceph_assert(!mirror_snapset || src.snap == CEPH_NOSNAP);

    // cancel a previous in-progress copy?
    if (copy_ops.count(dest)) {
      // FIXME: if the src etc match, we could avoid restarting from the
      // beginning.
      CopyOpRef cop = copy_ops[dest];
      vector<ceph_tid_t> tids;
      cancel_copy(cop, false, &tids);
      osd->objecter->op_cancel(tids, -ECANCELED);
    }

    // 封装 cop 对象
    CopyOpRef cop(std::make_shared<CopyOp>(cb, obc, src, oloc, version, flags,
          mirror_snapset, src_obj_fadvise_flags,
          dest_obj_fadvise_flags));
    copy_ops[dest] = cop;
    obc->start_block();

    if (!obc->obs.oi.has_manifest()) {
      // 执行实际的 copy 操作
      _copy_some(obc, cop);
    } else {
      if (obc->obs.oi.manifest.is_redirect()) {
        _copy_some(obc, cop);
      } else if (obc->obs.oi.manifest.is_chunked()) {
        auto p = obc->obs.oi.manifest.chunk_map.begin();
        _copy_some_manifest(obc, cop, p->first);
      } else {
        ceph_abort_msg("unrecognized manifest type");
      }
    }
  }

  void PrimaryLogPG::_copy_some(ObjectContextRef obc, CopyOpRef cop)
  {
    dout(10) << __func__ << " " << *obc << " " << cop << dendl;

    unsigned flags = 0;
    if (cop->flags & CEPH_OSD_COPY_FROM_FLAG_FLUSH)
      flags |= CEPH_OSD_FLAG_FLUSH;
    if (cop->flags & CEPH_OSD_COPY_FROM_FLAG_IGNORE_CACHE)
      flags |= CEPH_OSD_FLAG_IGNORE_CACHE;
    if (cop->flags & CEPH_OSD_COPY_FROM_FLAG_IGNORE_OVERLAY)
      flags |= CEPH_OSD_FLAG_IGNORE_OVERLAY;
    if (cop->flags & CEPH_OSD_COPY_FROM_FLAG_MAP_SNAP_CLONE)
      flags |= CEPH_OSD_FLAG_MAP_SNAP_CLONE;
    if (cop->flags & CEPH_OSD_COPY_FROM_FLAG_RWORDERED)
      flags |= CEPH_OSD_FLAG_RWORDERED;

    C_GatherBuilder gather(cct);

    if (cop->cursor.is_initial() && cop->mirror_snapset) {
      // list snaps too.
      ceph_assert(cop->src.snap == CEPH_NOSNAP);
      ObjectOperation op;
      op.list_snaps(&cop->results.snapset, NULL);
      ceph_tid_t tid = osd->objecter->read(cop->src.oid, cop->oloc, op,
              CEPH_SNAPDIR, NULL,
              flags, gather.new_sub(), NULL);
      cop->objecter_tid2 = tid;
    }

    ObjectOperation op;
    if (cop->results.user_version) {
      op.assert_version(cop->results.user_version);
    } else {
      // we should learn the version after the first chunk, if we didn't know
      // it already!
      ceph_assert(cop->cursor.is_initial());
    }
    op.copy_get(&cop->cursor, get_copy_chunk_size(),
          &cop->results.object_size, &cop->results.mtime,
          &cop->attrs, &cop->data, &cop->omap_header, &cop->omap_data,
          &cop->results.snaps, &cop->results.snap_seq,
          &cop->results.flags,
          &cop->results.source_data_digest,
          &cop->results.source_omap_digest,
          &cop->results.reqids,
          &cop->results.reqid_return_codes,
          &cop->results.truncate_seq,
          &cop->results.truncate_size,
          &cop->rval);
    op.set_last_op_flags(cop->src_obj_fadvise_flags);

    C_Copyfrom *fin = new C_Copyfrom(this, obc->obs.oi.soid,
            get_last_peering_reset(), cop);
    unsigned n = info.pgid.hash_to_shard(osd->m_objecter_finishers);
    gather.set_finisher(new C_OnFinisher(fin,
                osd->objecter_finishers[n]));

    // 调用 objecter->read方法进行读取
    ceph_tid_t tid = osd->objecter->read(cop->src.oid, cop->oloc, op,
            cop->src.snap, NULL,
            flags,
            gather.new_sub(),
            // discover the object version if we don't know it yet
            cop->results.user_version ? NULL : &cop->results.user_version);
    fin->tid = tid;
    cop->objecter_tid = tid;
    gather.activate();
  }
  ```
  </details>

无论是 Proxy Read 还是 Promote Object 操作最终都是调用了 objecter 的 read 方法来从base storage层读取对象数据

## Cache flush & evict
flush
- cache pool 空间不够时，需要选择一些对象回刷到数据层

evict
- 将一些 clean 对象从缓存层中剔除。以释放更多的缓存空间
  
Data Structure
- OSDServices ：定义了 AgentThread 线程，用于完成 flush 和 evict 操作

  <details close> <summary>OSDService</summary>

  ```c++{.line-numbers}
  class OSDService {
    ....
    // -- agent shared state --
    // agent 线程锁，保护下面所有数据结构
    ceph::mutex agent_lock = ceph::make_mutex("OSDService::agent_lock");
    // 线程相应的条件变量
    ceph::condition_variable agent_cond;
    
    // 所有淘汰或者回刷所需的 PG 集合，根据 PG 集合的优先级，保存在不同的 map 中
    map<uint64_t, set<PGRef> > agent_queue;
    
    // 当前在扫描的 PG 集合的一个位置，只有 agent_valid_iterator 为 true 时，这个指针才有效，否则从集合的起始处开始扫描
    set<PGRef>::iterator agent_queue_pos;
    bool agent_valid_iterator;
    
    // 所有正在进行的回刷和淘汰操作
    int agent_ops;
    
    // once have one pg with FLUSH_MODE_HIGH then flush objects with high speed
    int flush_mode_high_count;
    
    // 所有正在进行的 agent 操作（回刷或者淘汰）的对象
    set<hobject_t> agent_oids;
    
    // agent 是否有效
    bool agent_active;
    
    // agent 线程
    struct AgentThread : public Thread {
      OSDService *osd;
      explicit AgentThread(OSDService *o) : osd(o) {}
      void *entry() override {
        osd->agent_entry();
        return NULL;
      }
    } agent_thread;
    
    // agent 停止的标志
    bool agent_stop_flag;
    ceph::mutex agent_timer_lock = ceph::make_mutex("OSDService::agent_timer_lock");
    
    // agent 相关定时器：当扫描一个 PG 对象时，该对象既没有剔除操作，也没有回刷操作，就停止 PG 的扫描，把该 PG 加入到定时器中，5S 后继续
    SafeTimer agent_timer;
  }
  ```
  </details>


flush/evict 执行入口
- agent_entry：agent_entry 是 agent_thread 的入口函数，它在后台完成 flush 操作和 evict 操作
  <details close> <summary>agent_entry</summary>

  ```c++{.line-numbers}
  void OSDService::agent_entry()
  {
    dout(10) << __func__ << " start" << dendl;
    // 加锁，保护相关字段
    std::unique_lock agent_locker{agent_lock};

    while (!agent_stop_flag) {
      if (agent_queue.empty()) {
        // 扫描 agent_queue 队列，如果为空则在 agent_cond 上等待
        dout(20) << __func__ << " empty queue" << dendl;
        agent_cond.wait(agent_locker);
        continue;
      }
      
      uint64_t level = agent_queue.rbegin()->first;
      // 从队列中取出优先级最高的 PG 的集合 top
      set<PGRef>& top = agent_queue.rbegin()->second;
      dout(10) << __func__
        << " tiers " << agent_queue.size()
        << ", top is " << level
        << " with pgs " << top.size()
        << ", ops " << agent_ops << "/"
        << cct->_conf->osd_agent_max_ops
        << (agent_active ? " active" : " NOT ACTIVE")
        << dendl;
      dout(20) << __func__ << " oids " << agent_oids << dendl;
      
      // 获取 agent 操作的最大数目 max 值和 agent_flush_quota
      int max = cct->_conf->osd_agent_max_ops - agent_ops;
      int agent_flush_quota = max;
      if (!flush_mode_high_count)
        agent_flush_quota = cct->_conf->osd_agent_max_low_ops - agent_ops;
      if (agent_flush_quota <= 0 || top.empty() || !agent_active) {
        agent_cond.wait(agent_locker);
        continue;
      }

      // 迭代器获取 PG 
      if (!agent_valid_iterator || agent_queue_pos == top.end()) {
        agent_queue_pos = top.begin();
        agent_valid_iterator = true;
      }
      PGRef pg = *agent_queue_pos;
      dout(10) << "high_count " << flush_mode_high_count
        << " agent_ops " << agent_ops
        << " flush_quota " << agent_flush_quota << dendl;
      agent_locker.unlock();
      
      // 调用 pg->agent_work()，正常返回 true，若返回 false，则处于 delay，需要加入定时器
      if (!pg->agent_work(max, agent_flush_quota)) {
        dout(10) << __func__ << " " << pg->pg_id
    << " no agent_work, delay for " << cct->_conf->osd_agent_delay_time
    << " seconds" << dendl;

        osd->logger->inc(l_osd_tier_delay);
        // Queue a timer to call agent_choose_mode for this pg in 5 seconds
        std::lock_guard timer_locker{agent_timer_lock};
        Context *cb = new AgentTimeoutCB(pg);
        agent_timer.add_event_after(cct->_conf->osd_agent_delay_time, cb);
      }
      agent_locker.lock();
    }
    dout(10) << __func__ << " finish" << dendl;
  }
  ```
  </details>

- agent_work：完成一个 PG 内的 evict 操作和 flush 操作

  <details close> <summary>agent_work</summary>

  ```c++{.line-numbers}
  bool PrimaryLogPG::agent_work(int start_max, int agent_flush_quota)
  {
    // 加锁
    std::scoped_lock locker{*this};
    if (!agent_state) {
      dout(10) << __func__ << " no agent state, stopping" << dendl;
      return true;
    }

    ceph_assert(!recovery_state.is_deleting());

    if (agent_state->is_idle()) {
      dout(10) << __func__ << " idle, stopping" << dendl;
      return true;
    }

    osd->logger->inc(l_osd_agent_wake);

    dout(10) << __func__
      << " max " << start_max
      << ", flush " << agent_state->get_flush_mode_name()
      << ", evict " << agent_state->get_evict_mode_name()
      << ", pos " << agent_state->position
      << dendl;
    ceph_assert(is_primary());
    ceph_assert(is_active());

    // 加载 hit_set 历史对象到内存
    agent_load_hit_sets();

    const pg_pool_t *base_pool = get_osdmap()->get_pg_pool(pool.info.tier_of);
    ceph_assert(base_pool);

    int ls_min = 1;
    int ls_max = cct->_conf->osd_pool_default_cache_max_evict_check_size;

    // list some objects.  this conveniently lists clones (oldest to
    // newest) before heads... the same order we want to flush in.
    //
    // NOTE: do not flush the Sequencer.  we will assume that the
    // listing we get back is imprecise.
    vector<hobject_t> ls;
    hobject_t next;
    
    // 扫描本 PG 的对象，从 agent_state->position 开始扫描，结果保存在 ls 中
    int r = pgbackend->objects_list_partial(agent_state->position, ls_min, ls_max, &ls, &next);
    ceph_assert(r >= 0);
    dout(20) << __func__ << " got " << ls.size() << " objects" << dendl;
    int started = 0;
    
    // 对扫描的 ls 对象做相应的检查
    for (vector<hobject_t>::iterator p = ls.begin();
        p != ls.end();
        ++p) {
        
      // 跳过 hitset   
      if (p->nspace == cct->_conf->osd_hit_set_namespace) {
        dout(20) << __func__ << " skip (hit set) " << *p << dendl;
        osd->logger->inc(l_osd_agent_skip);
        continue;
      }
      
      // 跳过 degraded 对象
      if (is_degraded_or_backfilling_object(*p)) {
        dout(20) << __func__ << " skip (degraded) " << *p << dendl;
        osd->logger->inc(l_osd_agent_skip);
        continue;
      }
      
      // 跳过 missing 对象
      if (is_missing_object(p->get_head())) {
        dout(20) << __func__ << " skip (missing head) " << *p << dendl;
        osd->logger->inc(l_osd_agent_skip);
        continue;
      }
      
      // 跳过 object_context 不存在的对象
      ObjectContextRef obc = get_object_context(*p, false, NULL);
      if (!obc) {
        // we didn't flush; we may miss something here.
        dout(20) << __func__ << " skip (no obc) " << *p << dendl;
        osd->logger->inc(l_osd_agent_skip);
        continue;
      }
      
      // 跳过对象的 obs
      if (!obc->obs.exists) {
        dout(20) << __func__ << " skip (dne) " << obc->obs.oi.soid << dendl;
        osd->logger->inc(l_osd_agent_skip);
        continue;
      }
      
      // 跳过正在进行 scrub 操作的对象
      if (range_intersects_scrub(obc->obs.oi.soid,
              obc->obs.oi.soid.get_head())) {
        dout(20) << __func__ << " skip (scrubbing) " << obc->obs.oi << dendl;
        osd->logger->inc(l_osd_agent_skip);
        continue;
      }
      
      // 跳过已经被阻塞的对象
      if (obc->is_blocked()) {
        dout(20) << __func__ << " skip (blocked) " << obc->obs.oi << dendl;
        osd->logger->inc(l_osd_agent_skip);
        continue;
      }
      
      // 跳过有正在读写请求的对象
      if (obc->is_request_pending()) {
        dout(20) << __func__ << " skip (request pending) " << obc->obs.oi << dendl;
        osd->logger->inc(l_osd_agent_skip);
        continue;
      }

      // 如果不支持 omap，跳过有 omap 的对象
      // be careful flushing omap to an EC pool.
      if (!base_pool->supports_omap() &&
    obc->obs.oi.is_omap()) {
        dout(20) << __func__ << " skip (omap to EC) " << obc->obs.oi << dendl;
        osd->logger->inc(l_osd_agent_skip);
        continue;
      }

      // agent_maybe_evict 完成对象的 evict 操作
      if (agent_state->evict_mode != TierAgentState::EVICT_MODE_IDLE &&
    agent_maybe_evict(obc, false))
        ++started;
      // agent_maybe_flush 完成一个对象的 flush 操作  
      else if (agent_state->flush_mode != TierAgentState::FLUSH_MODE_IDLE &&
              agent_flush_quota > 0 && agent_maybe_flush(obc)) {
        ++started;
        --agent_flush_quota;
      }
      if (started >= start_max) {
        // If finishing early, set "next" to the next object
        if (++p != ls.end())
    next = *p;
        break;
      }
    }

    if (++agent_state->hist_age > cct->_conf->osd_agent_hist_halflife) {
      dout(20) << __func__ << " resetting atime and temp histograms" << dendl;
      agent_state->hist_age = 0;
      agent_state->temp_hist.decay();
    }

    // Total objects operated on so far
    int total_started = agent_state->started + started;
    bool need_delay = false;

    dout(20) << __func__ << " start pos " << agent_state->position
      << " next start pos " << next
      << " started " << total_started << dendl;

    // See if we've made a full pass over the object hash space
    // This might check at most ls_max objects a second time to notice that
    // we've checked every objects at least once.
    if (agent_state->position < agent_state->start &&
        next >= agent_state->start) {
      dout(20) << __func__ << " wrap around " << agent_state->start << dendl;
      if (total_started == 0)
        need_delay = true;
      else
        total_started = 0;
      agent_state->start = next;
    }
    agent_state->started = total_started;

    // See if we are starting from beginning
    if (next.is_max())
      agent_state->position = hobject_t();
    else
      agent_state->position = next;

    // Discard old in memory HitSets
    hit_set_in_memory_trim(pool.info.hit_set_count);

    if (need_delay) {
      ceph_assert(agent_state->delaying == false);
      agent_delay();
      return false;
    }
    
    // 重新计算 agent 的 evict 和 flush 值
    agent_choose_mode();
    return true;
  }
  ```
  </details>

真正执行操作的方法
- evict：agent_maybe_evict
  <details close> <summary>agent_maybe_evict</summary>

  ```c++{.line-numbers}
  bool PrimaryLogPG::agent_maybe_evict(ObjectContextRef& obc, bool after_flush)
  {
    const hobject_t& soid = obc->obs.oi.soid;
    // 检查对象的状态
    if (!after_flush && obc->obs.oi.is_dirty()) {
      dout(20) << __func__ << " skip (dirty) " << obc->obs.oi << dendl;
      return false;
    }
    // This is already checked by agent_work() which passes after_flush = false
    if (after_flush && range_intersects_scrub(soid, soid.get_head())) {
        dout(20) << __func__ << " skip (scrubbing) " << obc->obs.oi << dendl;
        return false;
    }
    if (!obc->obs.oi.watchers.empty()) {
      dout(20) << __func__ << " skip (watchers) " << obc->obs.oi << dendl;
      return false;
    }
    if (obc->is_blocked()) {
      dout(20) << __func__ << " skip (blocked) " << obc->obs.oi << dendl;
      return false;
    }
    if (obc->obs.oi.is_cache_pinned()) {
      dout(20) << __func__ << " skip (cache_pinned) " << obc->obs.oi << dendl;
      return false;
    }

    if (soid.snap == CEPH_NOSNAP) {
      int result = _verify_no_head_clones(soid, obc->ssc->snapset);
      if (result < 0) {
        dout(20) << __func__ << " skip (clones) " << obc->obs.oi << dendl;
        return false;
      }
    }

    // 检查 evict 模式是否为 EVICT_MODE_SOME 模式
    if (agent_state->evict_mode != TierAgentState::EVICT_MODE_FULL) {
      
      // 检查 clean 的时间是否大于设置的最小淘汰时间
      // is this object old than cache_min_evict_age?
      utime_t now = ceph_clock_now();
      utime_t ob_local_mtime;
      if (obc->obs.oi.local_mtime != utime_t()) {
        ob_local_mtime = obc->obs.oi.local_mtime;
      } else {
        ob_local_mtime = obc->obs.oi.mtime;
      }
      if (ob_local_mtime + utime_t(pool.info.cache_min_evict_age, 0) > now) {
        dout(20) << __func__ << " skip (too young) " << obc->obs.oi << dendl;
        osd->logger->inc(l_osd_agent_skip);
        return false;
      }
      
      // 计算对象的热度值
      // is this object old and/or cold enough?
      int temp = 0;
      uint64_t temp_upper = 0, temp_lower = 0;
      if (hit_set)
        agent_estimate_temp(soid, &temp);
      agent_state->temp_hist.add(temp);
      agent_state->temp_hist.get_position_micro(temp, &temp_lower, &temp_upper);

      dout(20) << __func__
        << " temp " << temp
        << " pos " << temp_lower << "-" << temp_upper
        << ", evict_effort " << agent_state->evict_effort
        << dendl;
      dout(30) << "agent_state:\n";
      Formatter *f = Formatter::create("");
      f->open_object_section("agent_state");
      agent_state->dump(f);
      f->close_section();
      f->flush(*_dout);
      delete f;
      *_dout << dendl;

      if (1000000 - temp_upper >= agent_state->evict_effort)
        return false;
    }


    // evict_mode 为 FULL 模式，调用函数 _delete_oid 删除该对象
    dout(10) << __func__ << " evicting " << obc->obs.oi << dendl;
    OpContextUPtr ctx = simple_opc_create(obc);

    auto null_op_req = OpRequestRef();
    if (!ctx->lock_manager.get_lock_type(
    ObjectContext::RWState::RWWRITE,
    obc->obs.oi.soid,
    obc,
    null_op_req)) {
      close_op_ctx(ctx.release());
      dout(20) << __func__ << " skip (cannot get lock) " << obc->obs.oi << dendl;
      return false;
    }

    osd->agent_start_evict_op();
    ctx->register_on_finish(
      [this]() {
        osd->agent_finish_evict_op();
      });

    ctx->at_version = get_next_version();
    ceph_assert(ctx->new_obs.exists);
    
    // 删除该对象
    int r = _delete_oid(ctx.get(), true, false);
    if (obc->obs.oi.is_omap())
      ctx->delta_stats.num_objects_omap--;
    ctx->delta_stats.num_evict++;
    ctx->delta_stats.num_evict_kb += shift_round_up(obc->obs.oi.size, 10);
    if (obc->obs.oi.is_dirty())
      --ctx->delta_stats.num_objects_dirty;
    ceph_assert(r == 0);
    finish_ctx(ctx.get(), pg_log_entry_t::DELETE);
    
    // 发起实际的删除请求
    simple_opc_submit(std::move(ctx));
    osd->logger->inc(l_osd_tier_evict);
    osd->logger->inc(l_osd_agent_evict);
    return true;
  }
  ```
  </details>

- flush：该方法完成一个对象的 flush 操作（非最底层的实现）

  <details close> <summary>agent_maybe_flush</summary>

  ```c++{.line-numbers}
  bool PrimaryLogPG::agent_maybe_flush(ObjectContextRef& obc)
  {
    // 检查对象是否为脏数据
    if (!obc->obs.oi.is_dirty()) {
      dout(20) << __func__ << " skip (clean) " << obc->obs.oi << dendl;
      osd->logger->inc(l_osd_agent_skip);
      return false;
    }
    
    // 检查对象是否为 cache_pinned 状态
    if (obc->obs.oi.is_cache_pinned()) {
      dout(20) << __func__ << " skip (cache_pinned) " << obc->obs.oi << dendl;
      osd->logger->inc(l_osd_agent_skip);
      return false;
    }

    // 统计时间
    utime_t now = ceph_clock_now();
    utime_t ob_local_mtime;
    if (obc->obs.oi.local_mtime != utime_t()) {
      ob_local_mtime = obc->obs.oi.local_mtime;
    } else {
      ob_local_mtime = obc->obs.oi.mtime;
    }
    // 判断当前 evict 状态是否为 full
    bool evict_mode_full =
      (agent_state->evict_mode == TierAgentState::EVICT_MODE_FULL);
    
    // 未满则检查该对象作为脏数据的时间，和最短刷回时间进行对比
    if (!evict_mode_full &&
        obc->obs.oi.soid.snap == CEPH_NOSNAP &&  // snaps immutable; don't delay
        (ob_local_mtime + utime_t(pool.info.cache_min_flush_age, 0) > now)) {
      dout(20) << __func__ << " skip (too young) " << obc->obs.oi << dendl;
      osd->logger->inc(l_osd_agent_skip);
      return false;
    }

    // 检查对象是否处于 activate 状态
    if (osd->agent_is_active_oid(obc->obs.oi.soid)) {
      dout(20) << __func__ << " skip (flushing) " << obc->obs.oi << dendl;
      osd->logger->inc(l_osd_agent_skip);
      return false;
    }

    dout(10) << __func__ << " flushing " << obc->obs.oi << dendl;

    // FIXME: flush anything dirty, regardless of what distribution of
    // ages we expect.

    hobject_t oid = obc->obs.oi.soid;
    osd->agent_start_op(oid);
    // no need to capture a pg ref, can't outlive fop or ctx
    std::function<void()> on_flush = [this, oid]() {
      osd->agent_finish_op(oid);
    };

    // 调用函数 start_flush   完成对象的刷回操作
    int result = start_flush(
      OpRequestRef(), obc, false, NULL,
      on_flush);
    if (result != -EINPROGRESS) {
      on_flush();
      dout(10) << __func__ << " start_flush() failed " << obc->obs.oi
        << " with " << result << dendl;
      osd->logger->inc(l_osd_agent_skip);
      return false;
    }

    osd->logger->inc(l_osd_agent_flush);
    return true;
  }
  ```
  </details>


- start_flush：该函数完成实际的 flush 操作

  <details close> <summary>start_flush</summary>

  ```c++{.line-numbers}
  int PrimaryLogPG::start_flush(
    OpRequestRef op, ObjectContextRef obc,
    bool blocking, hobject_t *pmissing,
    std::optional<std::function<void()>> &&on_flush)
  {
    const object_info_t& oi = obc->obs.oi;
    const hobject_t& soid = oi.soid;
    dout(10) << __func__ << " " << soid
      << " v" << oi.version
      << " uv" << oi.user_version
      << " " << (blocking ? "blocking" : "non-blocking/best-effort")
      << dendl;

    bool preoctopus_compat =
      get_osdmap()->require_osd_release < ceph_release_t::octopus;
    SnapSet snapset;
    if (preoctopus_compat) {
      // 过滤掉已经删除的 snap 对象
      // for pre-octopus compatibility, filter SnapSet::snaps.  not
      // certain we need this, but let's be conservative.
      snapset = obc->ssc->snapset.get_filtered(pool.info);
    } else {
      // NOTE: change this to a const ref when we remove this compat code
      snapset = obc->ssc->snapset;
    }

    // 检查比当前 clone 对象更早版本的克隆对象
    // verify there are no (older) check for dirty clones
    {
      dout(20) << " snapset " << snapset << dendl;
      vector<snapid_t>::reverse_iterator p = snapset.clones.rbegin();
      while (p != snapset.clones.rend() && *p >= soid.snap)
        ++p;
      if (p != snapset.clones.rend()) {
        hobject_t next = soid;
        next.snap = *p;
        ceph_assert(next.snap < soid.snap);
        if (recovery_state.get_pg_log().get_missing().is_missing(next)) {
    dout(10) << __func__ << " missing clone is " << next << dendl;
    if (pmissing)
      *pmissing = next;
    return -ENOENT;
        }
        ObjectContextRef older_obc = get_object_context(next, false);
        if (older_obc) {
    dout(20) << __func__ << " next oldest clone is " << older_obc->obs.oi
      << dendl;
    if (older_obc->obs.oi.is_dirty()) {
      dout(10) << __func__ << " next oldest clone is dirty: "
        << older_obc->obs.oi << dendl;
      return -EBUSY;
    }
        } else {
    dout(20) << __func__ << " next oldest clone " << next
      << " is not present; implicitly clean" << dendl;
        }
      } else {
        dout(20) << __func__ << " no older clones" << dendl;
      }
    }

    // 设置对应的对象为 blocked 状态
    if (blocking)
      obc->start_block();

    // 检查该对象是否在 flush_ops 中，也就是该对象是否已经在 flush
    map<hobject_t,FlushOpRef>::iterator p = flush_ops.find(soid);
    if (p != flush_ops.end()) {
      FlushOpRef fop = p->second;
      if (fop->op == op) {
        // we couldn't take the write lock on a cache-try-flush before;
        // now we are trying again for the lock.
        return try_flush_mark_clean(fop);
      }
      if (fop->flushed_version == obc->obs.oi.user_version &&
    (fop->blocking || !blocking)) {
        // nonblocking can join anything
        // blocking can only join a blocking flush
        dout(20) << __func__ << " piggybacking on existing flush " << dendl;
        if (op)
        fop->dup_ops.push_back(op);
        return -EAGAIN;   // clean up this ctx; op will retry later
      }

      // cancel current flush since it will fail anyway, or because we
      // are blocking and the existing flush is nonblocking.
      dout(20) << __func__ << " canceling previous flush; it will fail" << dendl;
      if (fop->op)
        osd->reply_op_error(fop->op, -EBUSY);
      while (!fop->dup_ops.empty()) {
        osd->reply_op_error(fop->dup_ops.front(), -EBUSY);
        fop->dup_ops.pop_front();
      }
      vector<ceph_tid_t> tids;
      cancel_flush(fop, false, &tids);
      osd->objecter->op_cancel(tids, -ECANCELED);
    }

    if (obc->obs.oi.has_manifest() && obc->obs.oi.manifest.is_chunked()) {
      // 执行对应的 flush 操作
      int r = start_manifest_flush(op, obc, blocking, std::move(on_flush));
      if (r != -EINPROGRESS) {
        if (blocking)
    obc->stop_block();
      }
      return r;
    }

  ```
  </details>

- start_manifest_flush：真正刷回数据之前的数据准备
  <details close> <summary>start_manifest_flush</summary>

  ```c++{.line-numbers}
  int PrimaryLogPG::start_manifest_flush(OpRequestRef op, ObjectContextRef obc, bool blocking,
                std::optional<std::function<void()>> &&on_flush)
  {
    auto p = obc->obs.oi.manifest.chunk_map.begin();
    FlushOpRef manifest_fop(std::make_shared<FlushOp>());
    manifest_fop->op = op;
    manifest_fop->obc = obc;
    manifest_fop->flushed_version = obc->obs.oi.user_version;
    manifest_fop->blocking = blocking;
    manifest_fop->on_flush = std::move(on_flush);
    int r = do_manifest_flush(op, obc, manifest_fop, p->first, blocking);
    if (r < 0) {
      return r;
    }

    flush_ops[obc->obs.oi.soid] = manifest_fop;
    return -EINPROGRESS;
  }
  ```
  </details>

- do_manifest_flush：真正刷回数据的过程

  <details close> <summary>do_manifest_flush</summary>

  ```c++{.line-numbers}
  int PrimaryLogPG::do_manifest_flush(OpRequestRef op, ObjectContextRef obc, FlushOpRef manifest_fop,
              uint64_t start_offset, bool block)
  {
    // 获取 manifest 和 实际的对象数据
    struct object_manifest_t &manifest = obc->obs.oi.manifest;
    hobject_t soid = obc->obs.oi.soid;
    ceph_tid_t tid;
    SnapContext snapc;
    uint64_t max_copy_size = 0, last_offset = 0;
    
    // 遍历 manifest 统计要复制刷回的数据大小
    map<uint64_t, chunk_info_t>::iterator iter = manifest.chunk_map.find(start_offset); 
    ceph_assert(iter != manifest.chunk_map.end());
    for (;iter != manifest.chunk_map.end(); ++iter) {
      if (iter->second.is_dirty()) {
        last_offset = iter->first;
        max_copy_size += iter->second.length;
      }
      if (get_copy_chunk_size() < max_copy_size) {
        break;
      }
    }

    iter = manifest.chunk_map.find(start_offset);
    for (;iter != manifest.chunk_map.end(); ++iter) {
      // 如果数据 clean 则跳过
      if (!iter->second.is_dirty()) {
        continue;
      }
      uint64_t tgt_length = iter->second.length;
      uint64_t tgt_offset= iter->second.offset;
      hobject_t tgt_soid = iter->second.oid;
      object_locator_t oloc(tgt_soid);
      ObjectOperation obj_op;
      bufferlist chunk_data;
      
      // 先读取数据到 chunk_data 中
      int r = pgbackend->objects_read_sync(soid, iter->first, tgt_length, 0, &chunk_data);
      if (r < 0) {
        dout(0) << __func__ << " read fail " << " offset: " << tgt_offset
          << " len: " << tgt_length << " r: " << r << dendl;
        return r;
      }
      if (!chunk_data.length()) {
        return -ENODATA;
      }

      // 判断刷回的模式
      unsigned flags = CEPH_OSD_FLAG_IGNORE_CACHE | CEPH_OSD_FLAG_IGNORE_OVERLAY |
          CEPH_OSD_FLAG_RWORDERED;
      tgt_length = chunk_data.length();
      
      // 根据不同的存储池指纹信息，选择对应的摘要算法获取 chunk_data 对应的 hash 值
      if (pg_pool_t::fingerprint_t fp_algo = pool.info.get_fingerprint_type(); iter->second.has_reference() && fp_algo != pg_pool_t::TYPE_FINGERPRINT_NONE) {
        object_t fp_oid = [fp_algo, &chunk_data]() -> string {
          switch (fp_algo) {
            case pg_pool_t::TYPE_FINGERPRINT_SHA1:
                return crypto::digest<crypto::SHA1>(chunk_data).to_str();
            case pg_pool_t::TYPE_FINGERPRINT_SHA256:
                return crypto::digest<crypto::SHA256>(chunk_data).to_str();
            case pg_pool_t::TYPE_FINGERPRINT_SHA512:
                return crypto::digest<crypto::SHA512>(chunk_data).to_str();
            default:
                assert(0 == "unrecognized fingerprint type");
                return {};
        }}();
        bufferlist in;
        
        // 如果 oid 不一致
        if (fp_oid != tgt_soid.oid) {
          // 减小旧块的引用计数
        // decrement old chunk's reference count 
        ObjectOperation dec_op;
        cls_chunk_refcount_put_op put_call;
        put_call.source = soid;
        ::encode(put_call, in);
        // 对 chunk 的计数执行修改 PUT 操作
        dec_op.call("cas", "chunk_put", in);         
        
        // 执行 objecter_mutate 方法会将请求转化为 Op 请求，再进行请求的提交，写入到后端存储池 dec_op chunk_put
        // we don't care dec_op's completion. scrub for dedup will fix this.
        tid = osd->objecter->mutate(
            tgt_soid.oid, oloc, dec_op, snapc,
            ceph::real_clock::from_ceph_timespec(obc->obs.oi.mtime),
            flags, NULL);
        in.clear();
        }
        tgt_soid.oid = fp_oid;
        iter->second.oid = tgt_soid;
        
        // 编码实际操作的关键数据（偏移量和数据长度）
        // add data op
        ceph_osd_op osd_op;
        osd_op.extent.offset = 0;
        osd_op.extent.length = chunk_data.length();
        
        // 将数据编码
        encode(osd_op, in);
        encode(soid, in);
        in.append(chunk_data);
        obj_op.call("cas", "cas_write_or_get", in);
      } else {
        obj_op.add_data(CEPH_OSD_OP_WRITE, tgt_offset, tgt_length, chunk_data);
      }

      C_ManifestFlush *fin = new C_ManifestFlush(this, soid, get_last_peering_reset());
      fin->offset = iter->first;
      fin->last_offset = last_offset;
      manifest_fop->chunks++;

      unsigned n = info.pgid.hash_to_shard(osd->m_objecter_finishers);
      
      // 封装写请求写入到后端存储池 obj_op  cas_write_or_get
      tid = osd->objecter->mutate(
        tgt_soid.oid, oloc, obj_op, snapc,
        ceph::real_clock::from_ceph_timespec(obc->obs.oi.mtime),
        flags, new C_OnFinisher(fin, osd->objecter_finishers[n]));
      fin->tid = tid;
      manifest_fop->io_tids[iter->first] = tid;

      dout(20) << __func__ << " offset: " << tgt_offset << " len: " << tgt_length 
        << " oid: " << tgt_soid.oid << " ori oid: " << soid.oid.name 
        << " tid: " << tid << dendl;
      if (last_offset < iter->first) {
        break;
      }
    }

    return 0;
  }
  ```
  </details>

通过源码分析我们不难看出，flush 操作最终是以 Op 请求的方式传递到底层存储层的，也就意味着需要再执行一次 Ceph 存储池写数据的相关逻辑。

- command
ceph osd tier add {data_pool} {cache pool} // Bind cache pool to storage pool
ceph osd tier cache-mode {cache-pool} {cache-mode} // Set cache mode for cache pool
ceph osd tier cache-mode {cache-pool} {cache-mode} // Set read tier/write tier according to the cache mode

