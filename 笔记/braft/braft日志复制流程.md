# 2. 日志复制
RAFT需要三种不同的持久存储, 分别是:
- RaftMetaStorage, 用来存放一些RAFT算法自身的状态数据， 比如term, vote_for等信息.
- LogStorage, 用来存放用户提交的WAL
- SnapshotStorage, 用来存放用户的Snapshot以及元信息. 用三个不同的uri来表示, 并且提供了基于本地文件系统的默认实现，type为local, 比如 local://data 就是存放到当前文件夹的data目录，local:///home/disk1/data 就是存放在 /home/disk1/data中。libraft中有默认的local://实现，用户可以根据需要继承实现相应的Storage。
## 2.1 提交任务
在Raft中，只有Leader才能处理客户端的请求。
当客户端请求过来的时候，服务端需要将request转化为log（IOBuf），并构造一个braft::Task，将Task的data设置为log，并将回调函数done构造Closure传给Task的done，当函数最终成功执行或者失败的时候会执行回调。下面是example里面的counter的一个接口：
```c++
void fetch_add(const FetchAddRequest* request,
                   CounterResponse* response,
                   google::protobuf::Closure* done) {
        ...
        braft::Task task;
        task.data = &log;
        task.done = new FetchAddClosure(this, request, response,
                                        done_guard.release());
        ...
        return _node->apply(task);
    }
```
将任务提交到_apply_queue, 它会把task和回调一起放到_apply_queue去执行
```c++
void NodeImpl::apply(const Task& task) {
    LogEntry* entry = new LogEntry;
    ...
    if (_apply_queue->execute(m, &bthread::TASK_OPTIONS_INPLACE, NULL) != 0) {
        ...
    }
}
```
调用NodeImpl::apply(LogEntryAndClosure tasks[], size_t size)执行每个任务
```c++
void NodeImpl::apply(LogEntryAndClosure tasks[], size_t size) {
    ...
    // 1. 检查当前的状态是否为leader，以及task的expected_term是否等于当前term等。一旦出错就会调用task的done返回给用户
    if (_state != STATE_LEADER || reject_new_user_logs) {
        ...
    }

    // 2. 遍历所有task
    for (size_t i = 0; i < size; ++i) {
        ...
        // 2.1 把task里面的entry放到entries数组里面
        entries.push_back(tasks[i].entry);
        ...
        // 2.2 并将task放到ballot的pending_task用于投票
        _ballot_box->append_pending_task(_conf.conf,
                                         _conf.stable() ? NULL : &_conf.old_conf,
                                         tasks[i].done);
    }
    
    // 3. append_entries
    _log_manager->append_entries(&entries,
                               new LeaderStableClosure(
                                        NodeId(_group_id, _server_id),
                                        entries.size(),
                                        _ballot_box));
    // 4. 更新当前配置
    _log_manager->check_and_set_configuration(&_conf);
}

void LogManager::append_entries(
            std::vector<LogEntry*> *entries, StableClosure* done) {
    ...
    // 1. 分配index, 并缓存到内存中
    if (!entries->empty()) {
        done->_first_log_index = entries->front()->id.index;
        _logs_in_memory.insert(_logs_in_memory.end(), entries->begin(), entries->end());
    }
    ...

    // 2. 提交任务到_disk_queue
    int ret = bthread::execution_queue_execute(_disk_queue, done);
    ...
}
```
## 2.2 发送空entries

当一个节点当选为leader之后，会为所有其他节点创建一个replicator，然后调用Replicator::start，该函数最后会调用Replicator::_send_empty_entries向其他节点发送空的AppendEntries RPC。follower收到leader的append entries之后，会去比较request中的log id和term。最后会调用回调_on_rpc_returned。

```c++
void Replicator::_on_rpc_returned(ReplicatorId id, brpc::Controller* cntl,
                     AppendEntriesRequest* request, 
                     AppendEntriesResponse* response,
                     int64_t rpc_send_time) {
    // 1. 进行一系列的检查
    ... 
    // 2. 正式发起_send_entries
    r->_send_entries();
    return;
}
```

## 2.3 发送用户数据entry

```c++
void Replicator::_send_entries() {
    // 1. 调用_fill_common_fields填充request
    ...
    if (_fill_common_fields(request.get(), _next_index - 1, false) != 0) {
       // 1.1 填充失败，意味着当前index为0，需要安装快照
        _reset_next_index();
        return _install_snapshot();
    }
    
    // 2. 获取entry并添加到request中
    for (int i = 0; i < max_entries_size; ++i) {
        ...
        request->add_entries()->Swap(&em);
    }
    
    // 3. 没有entry, 等待新任务到来
    if (request->entries_size() == 0) {
        ...
        return _wait_more_entries();
    }
    ...

    // 4. 发送entries
    stub.append_entries(cntl.release(), request.release(), 
                        response.release(), done);
    _wait_more_entries();
}
```

## 2.4 follower收到entry
前面的步骤和收到空的entries是一样的，然后构造一个FollowerStableClosure传给LogManager::append_entries试图追加entries。
```c++
void LogManager::append_entries(
            std::vector<LogEntry*> *entries, StableClosure* done) {
    ...
    // 1. 检查并解决冲突
    if (!entries->empty() && check_and_resolve_conflict(entries, done) != 0) {
        ...
    }
 
    // 2. 插入缓存
    for (size_t i = 0; i < entries->size(); ++i) {
            ...
            _config_manager->add(conf_entry);
            ...
    }
    ...

    // 3. 提交到_disk_queue持久化 
    int ret = bthread::execution_queue_execute(_disk_queue, done);
    ...
}
```
持久化成功后调用done->Run()，也就是FollowerStableClosure::Run()，该函数最后会检查一下term来判断leader有没有变化，如果一切正常，则调用BallotBox::set_last_committed_indexcommit index更新commit index 如果更新成功，就调用FsmCaller的on_committed，on_committed将构造一个任务提交到execution_queue里面，最后调用FSMCaller::do_committed去调用用户传入的自定义的StateMachine::on_apply函数执行状态机的操作。
leader收到follower响应 当follower返回RPC后会调用_on_rpc_returned，前面的部分和空的rpc一样，但是有一个分支不一样，它会调用BallotBox::commit_at去投票并决定是否更新commit index
