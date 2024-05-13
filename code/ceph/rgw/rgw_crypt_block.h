#ifndef CEPH_RGW_CRYPT_BLOCK_H
#define CEPH_RGW_CRYPT_BLOCK_H

#include <rgw/rgw_common.h>

class BlockCrypt {
public:
  BlockCrypt(){};
  virtual ~BlockCrypt(){};

  /**
    * Determines size of encryption block.
    * This is usually multiply of key size.
    * It determines size of chunks that should be passed to \ref encrypt and \ref decrypt.
    */
  virtual size_t get_block_size() = 0;
  virtual string get_crypt_type() = 0;

  /**
   * Encrypts data.
   * Argument \ref stream_offset shows where in generalized stream chunk is located.
   * Input for encryption is \ref input buffer, with relevant data in range <in_ofs, in_ofs+size).
   * \ref input and \output may not be the same buffer.
   *
   * \params
   * input - source buffer of data
   * in_ofs - offset of chunk inside input
   * size - size of chunk, must be chunk-aligned unless last part is processed
   * output - destination buffer to encrypt to
   * stream_offset - location of <in_ofs,in_ofs+size) chunk in data stream, must be chunk-aligned
   * \return true iff successfully encrypted
   */
  virtual bool encrypt(bufferlist& input,
                       off_t in_ofs,
                       size_t size,
                       bufferlist& output,
                       off_t stream_offset) = 0;

  /**
   * Decrypts data.
   * Argument \ref stream_offset shows where in generalized stream chunk is located.
   * Input for decryption is \ref input buffer, with relevant data in range <in_ofs, in_ofs+size).
   * \ref input and \output may not be the same buffer.
   *
   * \params
   * input - source buffer of data
   * in_ofs - offset of chunk inside input
   * size - size of chunk, must be chunk-aligned unless last part is processed
   * output - destination buffer to encrypt to
   * stream_offset - location of <in_ofs,in_ofs+size) chunk in data stream, must be chunk-aligned
   * \return true iff successfully encrypted
   */
  virtual bool decrypt(bufferlist& input,
                       off_t in_ofs,
                       size_t size,
                       bufferlist& output,
                       off_t stream_offset) = 0;
};

#endif
