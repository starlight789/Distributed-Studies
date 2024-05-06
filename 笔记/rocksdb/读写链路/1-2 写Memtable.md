# 2 MEMTABLE

双写：先写wal，然后写，memtable。每个CF的memtable互不影响。

memtable实现: SkipList/HashSkipList/HashLinkList/Vector【https://github.com/facebook/rocksdb/wiki/MemTable】

## 2.1 创建MEMTABLE

时机：创建CF时(SkipListRep)
```c++
ConstructNewMemtable
->CreateNewMemtable->ioptions.memtable_factory  //ioptions根据用户设置选择对应的MEMTABLE
->CreateMemTableRep->return new SkipListRep
```


## 2.2 MEMTABLE写入

WriteImpl
#### -> WriteBatchInternal::InsertInto
```c++
static Status InsertInto(WriteThread::WriteGroup& write_group, xxx)
static Status InsertInto(const WriteBatch* batch, xxx)
static Status InsertInto(WriteThread::Writer* writer, xxx)
```

```c++
Status WriteBatchInternal::InsertInto(
    WriteThread::WriteGroup& write_group, SequenceNumber sequence,
    ColumnFamilyMemTables* memtables, FlushScheduler* flush_scheduler,
    bool ignore_missing_column_families, uint64_t recovery_log_number, DB* db,
    bool concurrent_memtable_writes, bool seq_per_batch, bool batch_per_txn) {
  MemTableInserter inserter(
      sequence, memtables, flush_scheduler, ignore_missing_column_families,
      recovery_log_number, db, concurrent_memtable_writes,
      nullptr /*has_valid_writes*/, seq_per_batch, batch_per_txn);
  for (auto w : write_group) {
    if (w->CallbackFailed()) {
      continue;
    }
    w->sequence = inserter.sequence();
    if (!w->ShouldWriteToMemtable()) {
      // In seq_per_batch_ mode this advances the seq by one.
      inserter.MaybeAdvanceSeq(true);
      continue;
    }
    // 在写 WAL 时，RocksDB 会给 WriteGroup 分配一个 seq num，这里的 sequence和WAL 中的对应。
    SetSequence(w->batch, inserter.sequence()); 
    inserter.set_log_number_ref(w->log_ref);
    w->status = w->batch->Iterate(&inserter);
    if (!w->status.ok()) {
      return w->status;
    }
    assert(!seq_per_batch || w->batch_cnt != 0);
    assert(!seq_per_batch || inserter.sequence() - w->sequence == w->batch_cnt);
  }
  return Status::OK();
}
```

##### WriteBatch::Iterate->virtual Status PutCF()->PutCFImpl()

```c++
Status PutCFImpl(uint32_t column_family_id, const Slice& key,
                   const Slice& value, ValueType value_type) {
    // optimize for non-recovery mode
    if (UNLIKELY(write_after_commit_ && rebuilding_trx_ != nullptr)) {
      WriteBatchInternal::Put(rebuilding_trx_, column_family_id, key, value);
      return Status::OK();
      // else insert the values to the memtable right away
    }

    Status seek_status;
    if (UNLIKELY(!SeekToColumnFamily(column_family_id, &seek_status))) {
      bool batch_boundry = false;
      if (rebuilding_trx_ != nullptr) {
        assert(!write_after_commit_);
        // The CF is probably flushed and hence no need for insert but we still
        // need to keep track of the keys for upcoming rollback/commit.
        WriteBatchInternal::Put(rebuilding_trx_, column_family_id, key, value);
        batch_boundry = IsDuplicateKeySeq(column_family_id, key);
      }
      MaybeAdvanceSeq(batch_boundry);
      return seek_status;
    }
    Status ret_status;

    // 获取当前的ColumnFamilyData）current_的memtable
    MemTable* mem = cf_mems_->GetMemTable();
    auto* moptions = mem->GetImmutableMemTableOptions();
    // inplace_update_support is inconsistent with snapshots, and therefore with
    // any kind of transactions including the ones that use seq_per_batch
    assert(!seq_per_batch_ || !moptions->inplace_update_support);
    // 如何memtable操作中的内部不支持更新就添加这条记录
    if (!moptions->inplace_update_support) {
      bool mem_res =
          mem->Add(sequence_, value_type, key, value,
                   concurrent_memtable_writes_, get_post_process_info(mem));
      if (UNLIKELY(!mem_res)) {
        assert(seq_per_batch_);
        ret_status = Status::TryAgain("key+seq exists");
        const bool BATCH_BOUNDRY = true;
        MaybeAdvanceSeq(BATCH_BOUNDRY);
      }
    } else if (moptions->inplace_callback == nullptr) {
      // 更新这条记录并且Callback
      assert(!concurrent_memtable_writes_);
      mem->Update(sequence_, key, value);
    } else {
      assert(!concurrent_memtable_writes_);
      if (mem->UpdateCallback(sequence_, key, value)) {
      } else {
        // 支持内部更新,但在memtable中找不到这条记录，就去从sst获取，并且更新，添加
        SnapshotImpl read_from_snapshot;
        read_from_snapshot.number_ = sequence_;
        ReadOptions ropts;
        // it's going to be overwritten for sure, so no point caching data block
        // containing the old version
        ropts.fill_cache = false;
        ropts.snapshot = &read_from_snapshot;

        std::string prev_value;
        std::string merged_value;

        auto cf_handle = cf_mems_->GetColumnFamilyHandle();
        Status s = Status::NotSupported();
        if (db_ != nullptr && recovering_log_number_ == 0) {
          if (cf_handle == nullptr) {
            cf_handle = db_->DefaultColumnFamily();
          }
          // 调用数据库的Get的操作获获取这个key之前的值，并存在快照中
          s = db_->Get(ropts, cf_handle, key, &prev_value);
        }

        char* prev_buffer = const_cast<char*>(prev_value.c_str());
        uint32_t prev_size = static_cast<uint32_t>(prev_value.size());
        auto status = moptions->inplace_callback(s.ok() ? prev_buffer : nullptr,
                                                 s.ok() ? &prev_size : nullptr,
                                                 value, &merged_value);
        if (status == UpdateStatus::UPDATED_INPLACE) {
          // prev_value is updated in-place with final value.
          bool mem_res __attribute__((__unused__));
          // 之前的的值已经内部更新了，其实就是把新的值写在原来的地址
          mem_res = mem->Add(
              sequence_, value_type, key, Slice(prev_buffer, prev_size));
          assert(mem_res);
          RecordTick(moptions->statistics, NUMBER_KEYS_WRITTEN);
        } else if (status == UpdateStatus::UPDATED) {
          // merged_value contains the final value.
          bool mem_res __attribute__((__unused__));
          // 没有内部更新的话，就存合并后的值，
          mem_res =
              mem->Add(sequence_, value_type, key, Slice(merged_value));
          assert(mem_res);
          RecordTick(moptions->statistics, NUMBER_KEYS_WRITTEN);
        }
      }
    }
    // optimize for non-recovery mode
    if (UNLIKELY(!ret_status.IsTryAgain() && rebuilding_trx_ != nullptr)) {
      assert(!write_after_commit_);
      // If the ret_status is TryAgain then let the next try to add the ky to
      // the rebuilding transaction object.
      WriteBatchInternal::Put(rebuilding_trx_, column_family_id, key, value);
    }
    // Since all Puts are logged in transaction logs (if enabled), always bump
    // sequence number. Even if the update eventually fails and does not result
    // in memtable add/update.
    MaybeAdvanceSeq();
    CheckMemtableFull();
    return ret_status;
  }
```

#### Add()
```c++
bool MemTable::Add(SequenceNumber s, ValueType type,
                   const Slice& key, /* user key */
                   const Slice& value, bool allow_concurrent,
                   MemTablePostProcessInfo* post_process_info) {
  // 存储的格式如下
  // Format of an entry is concatenation of:
  //  key_size     : varint32 of internal_key.size()
  //  key bytes    : char[internal_key.size()]
  //  value_size   : varint32 of value.size()
  //  value bytes  : char[value.size()]
  // 这里为了节省空间，将整型编码成变长整型，存储为变长整型（可以查下资料）
  uint32_t key_size = static_cast<uint32_t>(key.size());
  uint32_t val_size = static_cast<uint32_t>(value.size());
  uint32_t internal_key_size = key_size + 8;
  // 获取编码后的长度
  const uint32_t encoded_len = VarintLength(internal_key_size) +
                               internal_key_size + VarintLength(val_size) +
                               val_size;
  char* buf = nullptr;
  std::unique_ptr<MemTableRep>& table =
      type == kTypeRangeDeletion ? range_del_table_ : table_;
  KeyHandle handle = table->Allocate(encoded_len, &buf);

  // 依次将key和value的长度和值，还有类型，编码到buf里面
  char* p = EncodeVarint32(buf, internal_key_size);
  memcpy(p, key.data(), key_size);
  Slice key_slice(p, key_size);
  p += key_size;
  uint64_t packed = PackSequenceAndType(s, type);
  EncodeFixed64(p, packed);
  p += 8;
  p = EncodeVarint32(p, val_size);
  memcpy(p, value.data(), val_size);
  assert((unsigned)(p + val_size - buf) == (unsigned)encoded_len);
  if (!allow_concurrent) {
    // Extract prefix for insert with hint.
    if (insert_with_hint_prefix_extractor_ != nullptr &&
        insert_with_hint_prefix_extractor_->InDomain(key_slice)) {
      Slice prefix = insert_with_hint_prefix_extractor_->Transform(key_slice);
      bool res = table->InsertKeyWithHint(handle, &insert_hints_[prefix]);
      if (UNLIKELY(!res)) {
        return res;
      }
    } else {
      bool res = table->InsertKey(handle);
      if (UNLIKELY(!res)) {
        return res;
      }
    }

    // this is a bit ugly, but is the way to avoid locked instructions
    // when incrementing an atomic
    num_entries_.store(num_entries_.load(std::memory_order_relaxed) + 1,
                       std::memory_order_relaxed);
    data_size_.store(data_size_.load(std::memory_order_relaxed) + encoded_len,
                     std::memory_order_relaxed);
    if (type == kTypeDeletion) {
      num_deletes_.store(num_deletes_.load(std::memory_order_relaxed) + 1,
                         std::memory_order_relaxed);
    }

    if (bloom_filter_ && prefix_extractor_) {
      bloom_filter_->Add(prefix_extractor_->Transform(key));
    }
    if (bloom_filter_ && moptions_.memtable_whole_key_filtering) {
      bloom_filter_->Add(key);
    }

    // The first sequence number inserted into the memtable
    assert(first_seqno_ == 0 || s >= first_seqno_);
    if (first_seqno_ == 0) {
      first_seqno_.store(s, std::memory_order_relaxed);

      if (earliest_seqno_ == kMaxSequenceNumber) {
        earliest_seqno_.store(GetFirstSequenceNumber(),
                              std::memory_order_relaxed);
      }
      assert(first_seqno_.load() >= earliest_seqno_.load());
    }
    assert(post_process_info == nullptr);
    UpdateFlushState();
  } else {
    bool res = table->InsertKeyConcurrently(handle);
    if (UNLIKELY(!res)) {
      return res;
    }

    assert(post_process_info != nullptr);
    post_process_info->num_entries++;
    post_process_info->data_size += encoded_len;
    if (type == kTypeDeletion) {
      post_process_info->num_deletes++;
    }

    if (bloom_filter_ && prefix_extractor_) {
      bloom_filter_->AddConcurrently(prefix_extractor_->Transform(key));
    }
    if (bloom_filter_ && moptions_.memtable_whole_key_filtering) {
      bloom_filter_->AddConcurrently(key);
    }

    // atomically update first_seqno_ and earliest_seqno_.
    uint64_t cur_seq_num = first_seqno_.load(std::memory_order_relaxed);
    while ((cur_seq_num == 0 || s < cur_seq_num) &&
           !first_seqno_.compare_exchange_weak(cur_seq_num, s)) {
    }
    uint64_t cur_earliest_seqno =
        earliest_seqno_.load(std::memory_order_relaxed);
    while (
        (cur_earliest_seqno == kMaxSequenceNumber || s < cur_earliest_seqno) &&
        !first_seqno_.compare_exchange_weak(cur_earliest_seqno, s)) {
    }
  }
  if (type == kTypeRangeDeletion) {
    is_range_del_table_empty_.store(false, std::memory_order_relaxed);
  }
  UpdateOldestKeyTime();
  return true;
}

```
Add()函数将用户的key和value封装成一个buf，然后根据不同的条件调用table->Insert()插入至Memtable。table就是Memtable的工厂类实现，默认SkiplistRep, 即通过调用SkipList的Insert()完成key的插入。

#### Insert()
```c++
bool InlineSkipList<Comparator>::Insert(const char* key, Splice* splice,
                                        bool allow_partial_splice_fix) {
  Node* x = reinterpret_cast<Node*>(const_cast<char*>(key)) - 1;
  const DecodedKey key_decoded = compare_.decode_key(key);
...............................
}
```
（1）对插入的key进行解码，并获取该key对应节点的高度。
（2）检查该节点的高度是否超过了当前SkipList的最大高度，如果超过则更新最大高度。
（3）检查是否需要重新计算Splice的高度。Splice是一个辅助结构，它保存了在各个层级上，插入点前后节点的引用。如果Splice的高度小于最大高度或者Splice不包含当前key，则需要重新计算。
（4）对于需要重新计算的层级，使用RecomputeSpliceLevels函数进行计算。
（5）对于每个层级，进行插入操作。如果使用CAS（Compare And Swap）操作，由于可能存在并发插入，所以需要在插入失败时重新计算Splice。如果不使用CAS操作，直接插入即可。
（6）插入完成后，更新Splice的信息，如果Splice已经失效（例如在插入过程中有节点被插入到Splice表示的区间中），则将Splice的高度设为0。
（7）最后，返回true表示插入成功。




