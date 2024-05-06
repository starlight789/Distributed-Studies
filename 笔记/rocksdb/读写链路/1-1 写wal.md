
WAL 主要的功能是当 RocksDB 异常退出后，能够恢复出错前的 memtable 中的数据，因此 RocksDB 默认是每次用户写都会刷新数据到 WAL。 每次当当前 WAL 对应的 memtable 刷新到磁盘后，都会新建一个WAL，即一个 memtable 对应一个 WAL。实际上，memtable 刷新为 sstable 是通过 immutable memtable 后台完成的，所以只要 memtable 转换为 immutable memtable，就会新生成一个 memtable 和对应的 WAL。
## 1. WAL结构


WAL文件由一堆变长的record组成，而每个record是由kBlockSize(32k)来分组，比如某一个record大于kBlockSize的话，他就会被切分为多个record（通过type来判断).

```
+---------+-----------+-----------+--- ... ---+
|CRC (4B) | Size (2B) | Type (1B) | Payload   |
+---------+-----------+-----------+--- ... ---+

CRC = 32bit hash computed over the payload using CRC
Size = Length of the payload data
Type = Type of record
       (kZeroType, kFullType, kFirstType, kLastType, kMiddleType )
       The type is used to group a bunch of records together to represent
       blocks that are larger than kBlockSize
Payload = Byte stream as long as specified by the payload size
```

## 1.1 创建wal
时机
- (1) 代码中调用打开一个新的DB
```c++
调用：
rocksdb::DB* db;
rocksdb::Options options;
options.create_if_missing = true;
rocksdb::Status status = rocksdb::DB::Open(options, "/tmp/testdb", &db);

底层：
Status DB::Open(const DBOptions& db_options, const std::string& dbname,
                const std::vector<ColumnFamilyDescriptor>& column_families,
                std::vector<ColumnFamilyHandle*>* handles, DB** dbptr) {
......................................................................
  s = impl->Recover(column_families);
  if (s.ok()) {
    uint64_t new_log_number = impl->versions_->NewFileNumber();
.............................................
    s = NewWritableFile(
        impl->immutable_db_options_.env,
        LogFileName(impl->immutable_db_options_.wal_dir, new_log_number),
        &lfile, opt_env_options);
................................................

```
- (2) 当一个CF(column family)被刷新到磁盘之后
当 CF 的 memtable 要 flush 时，通过 DBImpl::Flush() 调用自身的 FlushMemTable() 函数，在flush memtable 的过程中进行新的 WAL 的创建。 这里当触发 CF 的 flush 时，需要将内存中 memtable 标记为imutable memetable，然后在后台转换为 sstable，同时会生成新的 memtable。这个时候 WAL 记录的是旧的 memtable 的请求，为了数据的隔离性，且 WAL 不会过大，每个 WAL 文件只和一个 memtable 绑定，所以切换memtable 的过程中会创建新的wal文件，用来接收新的请求。
```c++
Status DBImpl::Flush(const FlushOptions& flush_options,
                     ColumnFamilyHandle* column_family) {
    ...
    // 主要就是flush memtable
    s = FlushMemTable(cfh->cfd(), flush_options, FlushReason::kManualFlush);
    ...
}

Status DBImpl::FlushMemTable(ColumnFamilyData* cfd,
                             const FlushOptions& flush_options,
                             FlushReason flush_reason, bool writes_stopped) {
    ...
    // 切换memtable
    s = SwitchMemtable(cfd, &context);
    ...
}

Status DBImpl::SwitchMemtable(ColumnFamilyData* cfd, WriteContext* context) {
//..................................................
  if (creating_new_log) {
    // TODO: Write buffer size passed in should be max of all CF's instead
    // of mutable_cf_options.write_buffer_size.
    io_s = CreateWAL(new_log_number, recycle_log_number, preallocate_block_size,
                     &new_log);
    if (s.ok()) {
      s = io_s;
    }
  }
//...............................................
  return s;
}
```

## 1.2 wal实例
```c++
#include <iostream>
#include <iostream>
#include <cassert>
#include "rocksdb/db.h"
#include <rocksdb/write_batch.h>

using namespace std;
using namespace rocksdb;

int main() {
    rocksdb::DB* db;
    rocksdb::Options options;
    options.create_if_missing = true;
    rocksdb::Status status = rocksdb::DB::Open(options, "/tmp/testdb", &db);
    assert(status.ok());
    cout << "Open rocksdb success." << endl;

    // 单个键值对写入
    string key1 = "1";
    string value1 = "aaaaa";
    status = db->Put(rocksdb::WriteOptions(), key1, value1);
    assert(status.ok());
    printf("Put[%s,%s] success.\n", key1.c_str(), value1.c_str());

    string value;
    status = db->Get(rocksdb::ReadOptions(), key1, &value);
    assert(status.ok());
    printf("Put key[%s] = %s\n", key1.c_str(), value.c_str());

    status = db->Delete(rocksdb::WriteOptions(), key1);
    assert(status.ok());
    printf("Delete key[%s] success.\n", key1.c_str());

    // 多个键值对批量写入
    WriteBatch batch;

     在 WriteBatch 对象中添加操作
    batch.Put("key1", "value1");
    batch.Put("key2", "value2");
    batch.Delete("key3");

     执行批量写入操作
    status = db->Write(WriteOptions(), &batch);
    assert(status.ok());

    delete db;

    return 0;
}


```

运行上述代码后，dump wal, 批量操作会添加到同一个record中：
```bash
dump_wal --walfile=./000004.log  --header
Sequence,Count,ByteSize,Physical Offset,Key(s)
1,1,21,0,PUT(0) : 0x31 
2,1,15,28,DELETE(0) : 0x31 

rocksdb_ldb dump_wal --walfile=./000009.log  --header
Sequence,Count,ByteSize,Physical Offset,Key(s)
3,3,44,0,PUT(0) : 0x6B657931 PUT(0) : 0x6B657932 DELETE(0) : 0x6B657933
```

## 1.3 WAL写入

函数WriteToWAL：
- MergeBatch
- SetSequence
- WriteToWAL（针对 WriteBatch）
- Sync

### 1.3.1 MergeBatch
遍历一遍 WriteGroup，把其中的所有 WriteBatch 都 Append 进 merged_batch 中。
```c++
WriteBatch* DBImpl::MergeBatch(const WriteThread::WriteGroup& write_group,
                               WriteBatch* tmp_batch, size_t* write_with_wal,
                               WriteBatch** to_be_cached_state) {
  assert(write_with_wal != nullptr);
  assert(tmp_batch != nullptr);
  assert(*to_be_cached_state == nullptr);
  WriteBatch* merged_batch = nullptr;
  *write_with_wal = 0;
  auto* leader = write_group.leader;
  assert(!leader->disable_wal);  // Same holds for all in the batch group
  if (write_group.size == 1 && !leader->CallbackFailed() &&
      leader->batch->GetWalTerminationPoint().is_cleared()) {
    // we simply write the first WriteBatch to WAL if the group only
    // contains one batch, that batch should be written to the WAL,
    // and the batch is not wanting to be truncated
    merged_batch = leader->batch;
    if (WriteBatchInternal::IsLatestPersistentState(merged_batch)) {
      *to_be_cached_state = merged_batch;
    }
    *write_with_wal = 1;
  } else {
    // WAL needs all of the batches flattened into a single batch.
    // We could avoid copying here with an iov-like AddRecord
    // interface
    merged_batch = tmp_batch;
    for (auto writer : write_group) {
      if (!writer->CallbackFailed()) {
        WriteBatchInternal::Append(merged_batch, writer->batch,
                                   /*WAL_only*/ true);
        if (WriteBatchInternal::IsLatestPersistentState(writer->batch)) {
          // We only need to cache the last of such write batch
          *to_be_cached_state = writer->batch;
        }
        (*write_with_wal)++;
      }
    }
  }
  return merged_batch;
}
```

### 1.3.2 SetSequence

到目前为止，写操作都没有被分配 seq num。RocksDB 生成完 merged_batch 之后，会给其分配一个 seq num，而这个 seq 就是 last_sequence + 1。
```c++
void WriteBatchInternal::SetSequence(WriteBatch* b, SequenceNumber seq) {
  EncodeFixed64(&b->rep_[0], seq);
}
```

### 1.3.2 WriteToWAL

WriteToWAL() 一共有两个重载，一个针对 WriteGroup，另一个针对 WriteBatch，会将 merged_batch 包装成一个 log_entry，作为 WAL 中的 record。接着，调用 Writer::AddRecord() 来将改 record 写入到 WAL 中，并最终写入 WAL 文件。

```c++
Status DBImpl::WriteToWAL(const WriteBatch& merged_batch,
                          log::Writer* log_writer, uint64_t* log_used,
                          uint64_t* log_size) {
  assert(log_size != nullptr);
  Slice log_entry = WriteBatchInternal::Contents(&merged_batch);
  *log_size = log_entry.size();
  // When two_write_queues_ WriteToWAL has to be protected from concurretn calls
  // from the two queues anyway and log_write_mutex_ is already held. Otherwise
  // if manual_wal_flush_ is enabled we need to protect log_writer->AddRecord
  // from possible concurrent calls via the FlushWAL by the application.
  const bool needs_locking = manual_wal_flush_ && !two_write_queues_;
  // Due to performance cocerns of missed branch prediction penalize the new
  // manual_wal_flush_ feature (by UNLIKELY) instead of the more common case
  // when we do not need any locking.
  if (UNLIKELY(needs_locking)) {
    log_write_mutex_.Lock();
  }
  Status status = log_writer->AddRecord(log_entry);
  if (UNLIKELY(needs_locking)) {
    log_write_mutex_.Unlock();
  }
  if (log_used != nullptr) {
    *log_used = logfile_number_;
  }
  total_log_size_ += log_entry.size();
  // TODO(myabandeh): it might be unsafe to access alive_log_files_.back() here
  // since alive_log_files_ might be modified concurrently
  alive_log_files_.back().AddSize(log_entry.size());
  log_empty_ = false;
  return status;
}
```

### 1.3.3 WritableFile
AddRecord->EmitPhysicalRecord后会调用到WritableFile类去执行真正的写入
由于文件写入在不同平台(比如posix && win)需要使用不同的接口，所以LevelDB将文件写入相关的操作抽象出了一个接口WritableFile ，rocksdb复用了这部分逻辑。
```c++
WritableFile
    PosixWritableFile -子类，用于实现posix系统的文件写入
        PosixWritableFile::Append(const Slice& data)
        PosixWritableFile::Flush()
        PosixWritableFile::Sync()
        PosixWritableFile::Close()
        ...
```
PosixWritableFile的构造:
```c++
class PosixWritableFile : public WritableFile {
 protected:
  const std::string filename_;
  const bool use_direct_io_;
  int fd_;                      // 文件描述符
  uint64_t filesize_;
  size_t logical_sector_size_;
}
```

##### PosixWritableFile::Append(const Slice& data)

Append方法的作用是将数据追加到文件。
```c++
Status PosixWritableFile::Append(const Slice& data) {
  if (use_direct_io()) {
    // 如果启用了直接 I/O（也就是说，数据将直接从应用程序缓冲区写入磁盘，绕过操作系统的缓存），那么需要确保数据的大小和地址都按照扇区对齐。
    // 如果不满足这些条件，程序将报错并终止。这是因为直接 I/O 需要硬件支持，且数据必须按照硬件的扇区大小进行对齐。
    assert(IsSectorAligned(data.size(), GetRequiredBufferAlignment()));
    assert(IsSectorAligned(data.data(), GetRequiredBufferAlignment()));
  }
  const char* src = data.data();
  size_t left = data.size();
  // 使用一个 while 循环来写入数据。在每一轮循环中，都会尝试将 left 大小的数据从 src 写入到文件。
  // write 函数会返回实际写入的字节数，如果返回值小于 0，表示发生了错误，此时需要检查错误码 errno。
  // 如果错误码是 EINTR（表示系统调用被中断），则忽略这个错误并重新尝试写入；
  // 否则，返回一个包含错误信息的 IOError。如果 write 成功，那么更新 left 和 src，并继续下一轮循环，直到所有数据都被写入。
  while (left != 0) {
    ssize_t done = write(fd_, src, left);  // 系统调用
    if (done < 0) {
      if (errno == EINTR) {
        continue;
      }
      return IOError("While appending to file", filename_, errno);
    }
    left -= done;
    src += done;
  }
  filesize_ += data.size();
  return Status::OK();
}
```
Linux 在内核设有缓冲区高速缓存或页面高速缓存，大多数磁盘 I/O 都通过缓冲区进行。当我们向文件写数据时，内核通常先将数据复制到一个缓冲区中，如果该缓冲区尚未写满，则并不将其排入输出队列，而是等待写满或者内核需要重用该缓冲区以便存放其他数据时，才会将该缓冲区排入输出队列，然后等它到达队首时，才进行实际的I/O 操作。这就是被称为延迟写的输出方式。延迟写减少了磁盘读次数，但是却减低了文件内容跟新的速度。当系统发生故障时，延迟写的方式可能造成文件跟新丢失。

为了应对此种情况，Linux 提供了三个函数来保证实际文件系统与缓冲区中内容的一致：

- fdatasyncsync：该函数只是将所有修改过的块缓冲区排入写队列，然后就返回，他并不等待实际写磁盘操作结束。
- fsync：只对由文件描述符fd指定的一个文件起作用，并且等待写磁盘操作结束才返回。
- fdatasync：类似于 fsync，但是它只影响文件的数据部分。而除数据外，fsync 还会同步更新文件的属性。

因此，上一步的 WriteToWAL() 并不一定真正写入了文件系统，期间可能出现故障导致写缓冲区内容的丢失。保证写内容的顺利落盘，RocksDB 在 WriteToWAL() 之后使用了刷盘操作，由 need_log_sync 决定是否使用。
fdatasync性能更高，因为它不会去同步文件的一些元数据信息。另外提一下，操作系统的写文件操作，默认都是异步刷盘，也就是写磁盘操作由进程提交给操作系统之后，就立即返回，而不是等到操作系统真正把数据写入到磁盘之后。异步刷盘的速度比同步刷盘快上千倍，当然其缺点是如果在进程把数据提交到操作系统后，系统突然宕机，那么这些数据就不会被真正写到磁盘上，而进程却以为数据已经成功写入了。当然这种情况只有在宕机才会出现，如果进程崩溃，是不会出现数据丢失的（因为这时候进程已经把写盘请求提交给OS了）。要确保宕机数据不丢，就需要使用同步刷盘（在posix系统中，同步刷盘的方式是在写操作返回之前调用fsync(...) 或 fdatasync(...) 或 msync(..., MS_SYNC) ）。

#### WriteToWAL
```c++
if (status.ok() && need_log_sync) {
    StopWatch sw(env_, stats_, WAL_FILE_SYNC_MICROS);
    // It's safe to access logs_ with unlocked mutex_ here because:
    //  - we've set getting_synced=true for all logs,
    //    so other threads won't pop from logs_ while we're here,
    //  - only writer thread can push to logs_, and we're in
    //    writer thread, so no one will push to logs_,
    //  - as long as other threads don't modify it, it's safe to read
    //    from std::deque from multiple threads concurrently.
    for (auto& log : logs_) {
      status = log.writer->file()->Sync(immutable_db_options_.use_fsync);
      if (!status.ok()) {
        break;
      }
    }
    if (status.ok() && need_log_dir_sync) {
      // We only sync WAL directory the first time WAL syncing is
      // requested, so that in case users never turn on WAL sync,
      // we can avoid the disk I/O in the write code path.
      status = directories_.GetWalDir()->Fsync();
    }
}
```
log.writer->file()->Sync() 会进一步调用 WritableFileWriter::SyncInternal()， 最终调用了 fdatasync()

```c++
IOStatus WritableFileWriter::SyncInternal(bool use_fsync) {
  if (use_fsync) {
    s = writable_file_->Fsync(io_options, nullptr);
  } else {
    s = writable_file_->Sync(io_options, nullptr);
  }
}

Status PosixWritableFile::Sync() {
  if (fdatasync(fd_) < 0) {
    return IOError("While fdatasync", filename_, errno);
  }
  return Status::OK();
}
```






