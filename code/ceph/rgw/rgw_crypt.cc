// -*- mode:C; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab
/**
 * Crypto filters for Put/Post/Get operations.
 */
#include <rgw/rgw_op.h>
#include <rgw/rgw_crypt.h>
#include <auth/Crypto.h>
#include <rgw/rgw_b64.h>
#include <rgw/rgw_rest_s3.h>
#include "include/assert.h"
#include <boost/utility/string_view.hpp>
#include <rgw/rgw_keystone.h>
#include <rgw/rgw_kms.h>
#include "include/str_map.h"
#include "crypto/crypto_accel.h"
#include "crypto/crypto_plugin.h"
#include "sms4.h"

#include <openssl/evp.h>

#define dout_context g_ceph_context
#define dout_subsys ceph_subsys_rgw

#define RGW_CRYPT_AES256 "AES256"
#define RGW_CRYPT_SM4 "SM4"
#define BOS_KMS_MASTER_KEY_SIZE 36

using namespace rgw;

CryptoAccelRef get_crypto_accel(CephContext *cct)
{
  CryptoAccelRef ca_impl = nullptr;
  stringstream ss;
  PluginRegistry *reg = cct->get_plugin_registry();
  string crypto_accel_type = cct->_conf->plugin_crypto_accelerator;

  CryptoPlugin *factory = dynamic_cast<CryptoPlugin*>(reg->get_with_load("crypto", crypto_accel_type));
  if (factory == nullptr) {
    lderr(cct) << __func__ << " cannot load crypto accelerator of type " << crypto_accel_type << dendl;
    return nullptr;
  }
  int err = factory->factory(&ca_impl, &ss);
  if (err) {
    lderr(cct) << __func__ << " factory return error " << err <<
        " with description: " << ss.str() << dendl;
  }
  return ca_impl;
}

template <std::size_t KeySizeV, std::size_t IvSizeV>
static inline
bool evp_sym_transform(CephContext* const cct,
                       const EVP_CIPHER* const type,
                       unsigned char* const out,
                       const unsigned char* const in,
                       const size_t size,
                       const unsigned char* const iv,
                       const unsigned char* const key,
                       const bool encrypt)
{
  using pctx_t = \
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)>;
  pctx_t pctx{ EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free };

  if (!pctx) {
    return false;
  }

  if (1 != EVP_CipherInit_ex(pctx.get(), type, nullptr,
                             nullptr, nullptr, encrypt)) {
    ldout(cct, 5) << "EVP: failed to 1st initialization stage" << dendl;
    return false;
  }

  // we want to support ciphers that don't use IV at all like AES-256-ECB
  if constexpr (static_cast<bool>(IvSizeV)) {
    ceph_assert(EVP_CIPHER_CTX_iv_length(pctx.get()) == IvSizeV);
    ceph_assert(EVP_CIPHER_CTX_block_size(pctx.get()) == IvSizeV);
  }
  ceph_assert(EVP_CIPHER_CTX_key_length(pctx.get()) == KeySizeV);

  if (1 != EVP_CipherInit_ex(pctx.get(), nullptr, nullptr, key, iv, encrypt)) {
    ldout(cct, 5) << "EVP: failed to 2nd initialization stage" << dendl;
    return false;
  }

  // disable padding
  if (1 != EVP_CIPHER_CTX_set_padding(pctx.get(), 0)) {
    ldout(cct, 5) << "EVP: cannot disable PKCS padding" << dendl;
    return false;
  }

  // operate!
  int written = 0;
  ceph_assert(size <= static_cast<size_t>(std::numeric_limits<int>::max()));
  if (1 != EVP_CipherUpdate(pctx.get(), out, &written, in, size)) {
    ldout(cct, 5) << "EVP: EVP_CipherUpdate failed" << dendl;
    return false;
  }

  int finally_written = 0;
  static_assert(sizeof(*out) == 1);
  if (1 != EVP_CipherFinal_ex(pctx.get(), out + written, &finally_written)) {
    ldout(cct, 5) << "EVP: EVP_CipherFinal_ex failed" << dendl;
    return false;
  }

  // padding is disabled so EVP_CipherFinal_ex should not append anything
  ceph_assert(finally_written == 0);
  return (written + finally_written) == static_cast<int>(size);
}

/**
 * Encryption in CBC mode. Chunked to 4K blocks. Offset is used as IV for each 4K block.
 *
 *
 *
 * A. Encryption
 * 1. Input is split to 4K chunks + remainder in one, smaller chunk
 * 2. Each full chunk is encrypted separately with CBC chained mode, with initial IV derived from offset
 * 3. Last chunk is 16*m + n.
 * 4. 16*m bytes are encrypted with CBC chained mode, with initial IV derived from offset
 * 5. Last n bytes are xor-ed with pattern obtained by CBC encryption of
 *    last encrypted 16 byte block <16m-16, 16m-15) with IV = {0}.
 * 6. (Special case) If m == 0 then last n bytes are xor-ed with pattern
 *    obtained by CBC encryption of {0} with IV derived from offset
 *
 * B. Decryption
 * 1. Input is split to 4K chunks + remainder in one, smaller chunk
 * 2. Each full chunk is decrypted separately with CBC chained mode, with initial IV derived from offset
 * 3. Last chunk is 16*m + n.
 * 4. 16*m bytes are decrypted with CBC chained mode, with initial IV derived from offset
 * 5. Last n bytes are xor-ed with pattern obtained by CBC ENCRYPTION of
 *    last (still encrypted) 16 byte block <16m-16,16m-15) with IV = {0}
 * 6. (Special case) If m == 0 then last n bytes are xor-ed with pattern
 *    obtained by CBC ENCRYPTION of {0} with IV derived from offset
 */
class AES_256_CBC : public BlockCrypt {
public:
  static const size_t AES_256_KEYSIZE = 256 / 8;
  static const size_t AES_256_IVSIZE = 128 / 8;
  static const size_t AES_256_BOS_KMS_MASTER_KEYESIZE = 256 / 8;
  static const size_t CHUNK_SIZE = 4096;
private:
  static const uint8_t IV[AES_256_IVSIZE];
  CephContext* cct;
  uint8_t key[AES_256_KEYSIZE];
  string crypt_type = "AES256";
public:
  AES_256_CBC(CephContext* cct): cct(cct) {
  }
  ~AES_256_CBC() {
    memset(key, 0, AES_256_KEYSIZE);
  }
  bool set_key(const uint8_t* _key, size_t key_size) {
    if (key_size != AES_256_KEYSIZE) {
      return false;
    }
    memcpy(key, _key, AES_256_KEYSIZE);
    return true;
  }
  size_t get_block_size() {
    return CHUNK_SIZE;
  }
  string get_crypt_type() {
    return crypt_type;
  }
  bool cbc_transform(unsigned char* out,
                     const unsigned char* in,
                     size_t size,
                     const unsigned char (&iv)[AES_256_IVSIZE],
                     const unsigned char (&key)[AES_256_KEYSIZE],
                     bool encrypt)
  {
    return evp_sym_transform<AES_256_KEYSIZE, AES_256_IVSIZE>(
      cct, EVP_aes_256_cbc(), out, in, size, iv, key, encrypt);
  }


  bool cbc_transform(unsigned char* out,
                     const unsigned char* in,
                     size_t size,
                     off_t stream_offset,
                     const unsigned char (&key)[AES_256_KEYSIZE],
                     bool encrypt)
  {
    static std::atomic<bool> failed_to_get_crypto(false);
    CryptoAccelRef crypto_accel;
    if (! failed_to_get_crypto.load())
    {
      crypto_accel = get_crypto_accel(cct);
      if (!crypto_accel)
        failed_to_get_crypto = true;
    }
    bool result = true;
    unsigned char iv[AES_256_IVSIZE];
    for (size_t offset = 0; result && (offset < size); offset += CHUNK_SIZE) {
      size_t process_size = offset + CHUNK_SIZE <= size ? CHUNK_SIZE : size - offset;
      prepare_iv(iv, stream_offset + offset);
      if (crypto_accel != nullptr) {
        if (encrypt) {
          result = crypto_accel->cbc_encrypt(out + offset, in + offset,
                                             process_size, iv, key);
        } else {
          result = crypto_accel->cbc_decrypt(out + offset, in + offset,
                                             process_size, iv, key);
        }
      } else {
        result = cbc_transform(
            out + offset, in + offset, process_size,
            iv, key, encrypt);
      }
    }
    return result;
  }


  bool encrypt(bufferlist& input,
               off_t in_ofs,
               size_t size,
               bufferlist& output,
               off_t stream_offset)
  {
    bool result = false;
    size_t aligned_size = size / AES_256_IVSIZE * AES_256_IVSIZE;
    size_t unaligned_rest_size = size - aligned_size;
    output.clear();
    buffer::ptr buf(aligned_size + AES_256_IVSIZE);
    unsigned char* buf_raw = reinterpret_cast<unsigned char*>(buf.c_str());
    const unsigned char* input_raw = reinterpret_cast<const unsigned char*>(input.c_str());

    /* encrypt main bulk of data */
    result = cbc_transform(buf_raw,
                           input_raw + in_ofs,
                           aligned_size,
                           stream_offset, key, true);
    if (result && (unaligned_rest_size > 0)) {
      /* remainder to encrypt */
      if (aligned_size % CHUNK_SIZE > 0) {
        /* use last chunk for unaligned part */
        unsigned char iv[AES_256_IVSIZE] = {0};
        result = cbc_transform(buf_raw + aligned_size,
                               buf_raw + aligned_size - AES_256_IVSIZE,
                               AES_256_IVSIZE,
                               iv, key, true);
      } else {
        /* 0 full blocks in current chunk, use IV as base for unaligned part */
        unsigned char iv[AES_256_IVSIZE] = {0};
        unsigned char data[AES_256_IVSIZE];
        prepare_iv(data, stream_offset + aligned_size);
        result = cbc_transform(buf_raw + aligned_size,
                               data,
                               AES_256_IVSIZE,
                               iv, key, true);
      }
      if (result) {
        for(size_t i = aligned_size; i < size; i++) {
          *(buf_raw + i) ^= *(input_raw + in_ofs + i);
        }
      }
    }
    if (result) {
      ldout(cct, 25) << "Encrypted " << size << " bytes by AES256"<< dendl;
      buf.set_length(size);
      output.append(buf);
    } else {
      ldout(cct, 5) << "Failed to encrypt by AES256" << dendl;
    }
    return result;
  }


  bool decrypt(bufferlist& input,
               off_t in_ofs,
               size_t size,
               bufferlist& output,
               off_t stream_offset)
  {
    bool result = false;
    size_t aligned_size = size / AES_256_IVSIZE * AES_256_IVSIZE;
    size_t unaligned_rest_size = size - aligned_size;
    output.clear();
    buffer::ptr buf(aligned_size + AES_256_IVSIZE);
    unsigned char* buf_raw = reinterpret_cast<unsigned char*>(buf.c_str());
    unsigned char* input_raw = reinterpret_cast<unsigned char*>(input.c_str());

    /* decrypt main bulk of data */
    result = cbc_transform(buf_raw,
                           input_raw + in_ofs,
                           aligned_size,
                           stream_offset, key, false);
    if (result && unaligned_rest_size > 0) {
      /* remainder to decrypt */
      if (aligned_size % CHUNK_SIZE > 0) {
        /*use last chunk for unaligned part*/
        unsigned char iv[AES_256_IVSIZE] = {0};
        result = cbc_transform(buf_raw + aligned_size,
                               input_raw + in_ofs + aligned_size - AES_256_IVSIZE,
                               AES_256_IVSIZE,
                               iv, key, true);
      } else {
        /* 0 full blocks in current chunk, use IV as base for unaligned part */
        unsigned char iv[AES_256_IVSIZE] = {0};
        unsigned char data[AES_256_IVSIZE];
        prepare_iv(data, stream_offset + aligned_size);
        result = cbc_transform(buf_raw + aligned_size,
                               data,
                               AES_256_IVSIZE,
                               iv, key, true);
      }
      if (result) {
        for(size_t i = aligned_size; i < size; i++) {
          *(buf_raw + i) ^= *(input_raw + in_ofs + i);
        }
      }
    }
    if (result) {
      ldout(cct, 25) << "Decrypted " << size << " bytes"<< dendl;
      buf.set_length(size);
      output.append(buf);
    } else {
      ldout(cct, 5) << "Failed to decrypt" << dendl;
    }
    return result;
  }


  void prepare_iv(unsigned char (&iv)[AES_256_IVSIZE], off_t offset) {
    off_t index = offset / AES_256_IVSIZE;
    off_t i = AES_256_IVSIZE - 1;
    unsigned int val;
    unsigned int carry = 0;
    while (i>=0) {
      val = (index & 0xff) + IV[i] + carry;
      iv[i] = val;
      carry = val >> 8;
      index = index >> 8;
      i--;
    }
  }
};

class SM4_CTR : public BlockCrypt {
public:
  static const size_t SM4_KEYSIZE = 128 / 8;
  static const size_t SM4_IVSIZE = 128 / 8;
  static const size_t CHUNK_SIZE = 4096;
private:
  const uint8_t IV[SM4_IVSIZE] = { 's', 'm', '4', '2', '5', '6', 'i', 'v', '_', 'c', 't', 'r', '1', '3', '3', '7' };
  unsigned char user_iv[SM4_IVSIZE] = { 0 };
  CephContext* cct;
  unsigned char key[SM4_KEYSIZE];
  string crypt_type = "SM4";
public:
  SM4_CTR(CephContext* cct) : cct(cct) {}
  ~SM4_CTR() {}
  bool set_key(string _key, size_t key_size) {
    if (key_size != SM4_KEYSIZE) {
      return false;
    }
    _key.erase(_key.end() - 1);
    _key += '\0';
    memcpy(key, _key.c_str(), SM4_KEYSIZE);
    return true;
  }
  size_t get_block_size() {
    return CHUNK_SIZE;
  }
  string get_crypt_type() {
    return crypt_type;
  }

  void sm4_encrypt(unsigned char* const out,
                   const unsigned char* const in,
                   const size_t size,
                   const bool encrypt) {
    unsigned int num = 0;
    unsigned char ecount[16];
    memset(ecount, 0, 16);
    if (encrypt) {
      sms4_key_t enc_key;
      ldout(cct, 20) << __func__ << " encrypt data, data_size: " << size << dendl;
      sms4_set_encrypt_key(&enc_key, key);
      sms4_ctr128_encrypt(in, out, size, &enc_key, user_iv, ecount, &num);
    } else {
      sms4_key_t dec_key;
      ldout(cct, 20) << __func__ << " decrypt data, data_size: " << size << dendl;
      sms4_set_encrypt_key(&dec_key, key);
      sms4_ctr128_encrypt(in, out, size, &dec_key, user_iv, ecount, &num);
    }
  }

  bool encrypt(bufferlist& input,
               off_t in_ofs,
               size_t size,
               bufferlist& output,
               off_t stream_offset)
  {
    output.clear();
    buffer::ptr buf(size);
    unsigned char* buf_raw = reinterpret_cast<unsigned char*>(buf.c_str());
    unsigned char input_raw[size];

    memcpy(input_raw, input.c_str(), size);
    memcpy(user_iv, IV, SM4_IVSIZE);

    sm4_encrypt(buf_raw,
                input_raw + in_ofs,
                size,
                true);

    ldout(cct, 25) << "Encrypted " << size << " bytes by SM4"<< dendl;
    buf.set_length(size);
    output.append(buf);

    return true;
  }

  bool decrypt(bufferlist& input,
               off_t in_ofs,
               size_t size,
               bufferlist& output,
               off_t stream_offset)
  {
    output.clear();
    buffer::ptr buf(size);
    unsigned char* buf_raw = reinterpret_cast<unsigned char*>(buf.c_str());
    unsigned char* input_raw = reinterpret_cast<unsigned char*>(input.c_str());

    memcpy(user_iv, IV, SM4_IVSIZE);

    sm4_encrypt(buf_raw,
                 input_raw + in_ofs,
                 size,
                 false);

    ldout(cct, 25) << "Decrypted " << size << " bytes"<< dendl;
    buf.set_length(size);
    output.append(buf);

    return true;
  }

};

std::unique_ptr<BlockCrypt> AES_256_CBC_create(CephContext* cct, const uint8_t* key, size_t len)
{
  auto cbc = std::unique_ptr<AES_256_CBC>(new AES_256_CBC(cct));
  cbc->set_key(key, AES_256_KEYSIZE);
  return std::move(cbc);
}

const uint8_t AES_256_CBC::IV[AES_256_CBC::AES_256_IVSIZE] =
    { 'a', 'e', 's', '2', '5', '6', 'i', 'v', '_', 'c', 't', 'r', '1', '3', '3', '7' };

bool aes_cbc_128_enc(CephContext* cct,
                     const char* in,
                     char* out,
                     const unsigned char* const iv,
                     const unsigned char* const key,
                     int& actual_size) {
  using pctx_t = \
  std::unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)>;
  pctx_t pctx{ EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free };

  if (!pctx) {
    return false;
  }

  // Enc is 1 to encrypt, 0 to decrypt, or -1 (see documentation).
  EVP_CipherInit_ex(pctx.get(), EVP_aes_128_cbc(), nullptr, key, iv, 1);

  // EVP_CipherUpdate can encrypt all your data at once, or you can do small chunks at a time.
  EVP_CipherUpdate(pctx.get(), (unsigned char*)out, &actual_size,
                   (const unsigned char*)in, strlen(in));

  // EVP_CipherFinal_ex is what applies the padding.  If your data is
  // a multiple of the block size, you'll get an extra AES block filled
  // with nothing but padding.
  int final_size;
  EVP_CipherFinal_ex(pctx.get(), (unsigned char*)out + actual_size, &final_size);

  actual_size += final_size;
  out[actual_size] = '\0';

  EVP_CIPHER_CTX_cleanup(pctx.get());
  return true;
}

bool encrypt_request_id(CephContext* cct,
                        const char* in,
                        char* out,
                        int& size) {
  // same with bos secret key
  static unsigned char key[] =
      { 'd', 's', 'w', 'y', 'b', 's', '_', 'b', 'o', 's', '_', '@', '2', '0', '1', '7' };
  return aes_cbc_128_enc(cct, in, out, key, key, size);
}

bool AES_256_ECB_encrypt(CephContext* cct,
                         const uint8_t* key,
                         size_t key_size,
                         const uint8_t* data_in,
                         uint8_t* data_out,
                         size_t data_size) {

  if (key_size == AES_256_KEYSIZE) {
    return evp_sym_transform<AES_256_KEYSIZE, 0 /* no IV in ECB */>(
      cct, EVP_aes_256_ecb(),  data_out, data_in, data_size,
      nullptr /* no IV in ECB */, key, true /* encrypt */);
  } else {
    ldout(cct, 5) << "Key size must be 256 bits long" << dendl;
    return false;
  }
}



RGWGetObj_BlockDecrypt::RGWGetObj_BlockDecrypt(CephContext* cct,
                                               RGWGetObj_Filter* next,
                                               std::unique_ptr<BlockCrypt> crypt):
    RGWGetObj_Filter(next),
    cct(cct),
    crypt(std::move(crypt)),
    enc_begin_skip(0),
    ofs(0),
    end(0),
    cache()
{
  block_size = this->crypt->get_block_size();
}

RGWGetObj_BlockDecrypt::~RGWGetObj_BlockDecrypt() {
}

int RGWGetObj_BlockDecrypt::read_manifest(bufferlist& manifest_bl) {
  parts_len.clear();
  RGWObjManifest manifest;
  if (manifest_bl.length()) {
    bufferlist::iterator miter = manifest_bl.begin();
    try {
      decode(manifest, miter);
    } catch (buffer::error& err) {
      ldout(cct, 0) << "ERROR: couldn't decode manifest" << dendl;
      return -EIO;
    }
    RGWObjManifest::obj_iterator mi;
    for (mi = manifest.obj_begin(); mi != manifest.obj_end(); ++mi) {
      if (mi.get_cur_stripe() == 0) {
        parts_len.push_back(0);
      }
      parts_len.back() += mi.get_stripe_size();
    }
    if (cct->_conf->subsys.should_gather<ceph_subsys_rgw, 20>()) {
      for (size_t i = 0; i<parts_len.size(); i++) {
        ldout(cct, 20) << "Manifest part " << i << ", size=" << parts_len[i] << dendl;
      }
    }
  }
  return 0;
}

int RGWGetObj_BlockDecrypt::fixup_range(off_t& bl_ofs, off_t& bl_end) {
  off_t inp_ofs = bl_ofs;
  off_t inp_end = bl_end;
  if (parts_len.size() > 0) {
    off_t in_ofs = bl_ofs;
    off_t in_end = bl_end;

    size_t i = 0;
    while (i<parts_len.size() && (in_ofs > (off_t)parts_len[i])) {
      in_ofs -= parts_len[i];
      i++;
    }
    //in_ofs is inside block i
    size_t j = 0;
    while (j<parts_len.size() && (in_end > (off_t)parts_len[j])) {
      in_end -= parts_len[j];
      j++;
    }
    //in_end is inside block j

    size_t rounded_end;
    rounded_end = ( in_end & ~(block_size - 1) ) + (block_size - 1);
    if (rounded_end + 1 >= parts_len[j]) {
      rounded_end = parts_len[j] - 1;
    }

    enc_begin_skip = in_ofs & (block_size - 1);
    ofs = bl_ofs - enc_begin_skip;
    end = bl_end;
    bl_ofs = bl_ofs - enc_begin_skip;
    bl_end += rounded_end - in_end;
  }
  else
  {
    enc_begin_skip = bl_ofs & (block_size - 1);
    ofs = bl_ofs & ~(block_size - 1);
    end = bl_end;
    bl_ofs = bl_ofs & ~(block_size - 1);
    bl_end = ( bl_end & ~(block_size - 1) ) + (block_size - 1);
  }
  ldout(cct, 20) << "fixup_range [" << inp_ofs << "," << inp_end
      << "] => [" << bl_ofs << "," << bl_end << "]" << dendl;
  return 0;
}

int RGWGetObj_BlockDecrypt::process(bufferlist& in, size_t part_ofs, size_t size)
{
  bufferlist data;
  if (!crypt->decrypt(in, 0, size, data, part_ofs)) {
    ldout(cct, 0) << __func__ << "() ERROR: decrypt " << size << "bytes failed. ofs: " << part_ofs << dendl;
    return -ERR_INTERNAL_ERROR;
  }
  off_t send_size = size - enc_begin_skip;
  if (ofs + enc_begin_skip + send_size > end + 1) {
    send_size = end + 1 - ofs - enc_begin_skip;
  }
  int res = next->handle_data(data, enc_begin_skip, send_size);
  enc_begin_skip = 0;
  ofs += size;
  in.splice(0, size);
  return res;
}

int RGWGetObj_BlockDecrypt::handle_data(bufferlist& bl, off_t bl_ofs, off_t bl_len) {
  ldout(cct, 25) << "Decrypt " << bl_len << " bytes" << dendl;
  bl.copy(bl_ofs, bl_len, cache);

  int res = 0;
  size_t part_ofs = ofs;
  if (crypt->get_crypt_type() == "SM4") {
    size_t i = 0;
    while (i<parts_len.size() && (part_ofs >= parts_len[i])) {
      part_ofs -= parts_len[i];
      i++;
    }
    off_t aligned_size = cache.length() & ~(block_size - 1);
    if (aligned_size > 0) {
      bufferlist data;
      if (! crypt->decrypt(cache, 0, aligned_size, data, part_ofs) ) {
        return -ERR_INTERNAL_ERROR;
      }
      off_t send_size = aligned_size - enc_begin_skip;
      if (ofs + enc_begin_skip + send_size > end + 1) {
        send_size = end + 1 - ofs - enc_begin_skip;
      }
      res = next->handle_data(data, enc_begin_skip, send_size);
      enc_begin_skip = 0;
      ofs += aligned_size;
      cache.splice(0, aligned_size);
    }
    return res;
  }

  for (size_t part : parts_len) {
    if (part_ofs >= part) {
      part_ofs -= part;
    } else if (part_ofs + cache.length() >= part) {
      res = process(cache, part_ofs, part - part_ofs);
      if (res < 0) {
        return res;
      }
      part_ofs = 0;
    } else {
      break;
    }
  }

  off_t aligned_size = cache.length() & ~(block_size - 1);
  if (aligned_size > 0) {
    res = process(cache, part_ofs, aligned_size);
  }
  return res;
}

int RGWGetObj_BlockDecrypt::flush() {
  int res = 0;
  size_t part_ofs = ofs;
  if (crypt->get_crypt_type() == "SM4") {
    size_t i = 0;
    while (i<parts_len.size() && (part_ofs > parts_len[i])) {
      part_ofs -= parts_len[i];
      i++;
    }
    if (cache.length() > 0) {
      bufferlist data;
      if (! crypt->decrypt(cache, 0, cache.length(), data, part_ofs) ) {
        return -ERR_INTERNAL_ERROR;
      }
      off_t send_size = cache.length() - enc_begin_skip;
      if (ofs + enc_begin_skip + send_size > end + 1) {
        send_size = end + 1 - ofs - enc_begin_skip;
      }
      res = next->handle_data(data, enc_begin_skip, send_size);
      enc_begin_skip = 0;
      ofs += send_size;
    }
    return res;
  }

  for (size_t part : parts_len) {
    if (part_ofs >= part) {
      part_ofs -= part;
    } else if (part_ofs + cache.length() >= part) {
      res = process(cache, part_ofs, part - part_ofs);
      if (res < 0) {
        return res;
      }
      part_ofs = 0;
    } else {
      break;
    }
  }
  if (cache.length() > 0) {
    res = process(cache, part_ofs, cache.length());
  }
  return res;
}

RGWPutObj_BlockEncrypt::RGWPutObj_BlockEncrypt(CephContext* cct,
                                               RGWPutObjDataProcessor* next,
                                               std::unique_ptr<BlockCrypt> crypt):
    RGWPutObj_Filter(next),
    cct(cct),
    crypt(std::move(crypt)),
    ofs(0),
    cache()
{
  block_size = this->crypt->get_block_size();
}

RGWPutObj_BlockEncrypt::~RGWPutObj_BlockEncrypt() {
}

int RGWPutObj_BlockEncrypt::handle_data(bufferlist& bl,
                                        off_t in_ofs,
                                        void **phandle,
                                        rgw_raw_obj *pobj,
                                        bool *again) {
  int res = 0;
  ldout(cct, 25) << "Encrypt " << bl.length() << " bytes" << dendl;

  if (*again) {
    bufferlist no_data;
    res = next->handle_data(no_data, in_ofs, phandle, pobj, again);
    //if *again is not set to false, we will have endless loop
    //drop info on log
    if (*again) {
      ldout(cct, 20) << "*again==true" << dendl;
    }
    return res;
  }

  cache.append(bl);
  off_t proc_size = cache.length() & ~(block_size - 1);
  if (bl.length() == 0) {
    proc_size = cache.length();
  }
  if (proc_size > 0) {
    bufferlist data;
    if (! crypt->encrypt(cache, 0, proc_size, data, ofs) ) {
      return -ERR_INTERNAL_ERROR;
    }

    res = next->handle_data(data, ofs, phandle, pobj, again);
    ofs += proc_size;
    cache.splice(0, proc_size);
    if (res < 0)
      return res;
  }

  if (bl.length() == 0) {
    /*replicate 0-sized handle_data*/
    res = next->handle_data(bl, ofs, phandle, pobj, again);
  }
  return res;
}

int RGWPutObj_BlockEncrypt::pre_handle_data(bufferlist& bl, bool *has_tail) {
  next->set_crypt(&crypt);
  return next->pre_handle_data(bl, has_tail);
}

int RGWPutObj_BlockEncrypt::throttle_data(void *handle,
                                          const rgw_raw_obj& obj,
                                          uint64_t size,
                                          bool need_to_wait) {
  return next->throttle_data(handle, obj, size, need_to_wait);
}

std::string create_random_key_selector(CephContext * const cct, string encrypt_type) {
  if (encrypt_type == RGW_CRYPT_AES256) {
    char random[AES_256_KEYSIZE];
    cct->random()->get_bytes(&random[0], sizeof(random));
    return std::string(random, sizeof(random));
  } else {
    char random[SM4_KEYSIZE];
    cct->random()->get_bytes(&random[0], sizeof(random));
    return std::string(random, sizeof(random));
  }
//  cct->random()->get_bytes(&random[0], sizeof(random));
//  return std::string(random, sizeof(random));
}

static inline void set_attr(map<string, bufferlist>& attrs,
                            const char* key,
                            boost::string_view value)
{
  bufferlist bl;
  bl.append(value.data(), value.size());
  attrs[key] = std::move(bl);
}

static inline std::string get_str_attribute(map<string, bufferlist>& attrs,
                                            const char *name)
{
  auto iter = attrs.find(name);
  if (iter == attrs.end()) {
    return {};
  }
  return iter->second.to_str();
}

typedef enum {
  X_AMZ_SERVER_SIDE_ENCRYPTION_CUSTOMER_ALGORITHM=0,
  X_AMZ_SERVER_SIDE_ENCRYPTION_CUSTOMER_KEY,
  X_AMZ_SERVER_SIDE_ENCRYPTION_CUSTOMER_KEY_MD5,
  X_AMZ_SERVER_SIDE_ENCRYPTION,
  X_AMZ_SERVER_SIDE_ENCRYPTION_AWS_KMS_KEY_ID,
  X_BCE_SERVER_SIDE_ENCRYPTION,
  X_BCE_SERVER_SIDE_ENCRYPTION_CUSTOMER_KEY,
  X_BCE_SERVER_SIDE_ENCRYPTION_CUSTOMER_KEY_MD5,
  X_BCE_SERVER_SIDE_ENCRYPTION_BOS_KMS_KEY_ID,
  X_AMZ_SERVER_SIDE_ENCRYPTION_LAST
} crypt_option_e;

typedef struct {
  const char* http_header_name;
  const std::string post_part_name;
} crypt_option_names;

static const crypt_option_names crypt_options[] = {
    {"HTTP_X_AMZ_SERVER_SIDE_ENCRYPTION_CUSTOMER_ALGORITHM",  "x-amz-server-side-encryption-customer-algorithm"},
    {"HTTP_X_AMZ_SERVER_SIDE_ENCRYPTION_CUSTOMER_KEY",        "x-amz-server-side-encryption-customer-key"},
    {"HTTP_X_AMZ_SERVER_SIDE_ENCRYPTION_CUSTOMER_KEY_MD5",    "x-amz-server-side-encryption-customer-key-md5"},
    {"HTTP_X_AMZ_SERVER_SIDE_ENCRYPTION",                     "x-amz-server-side-encryption"},
    {"HTTP_X_AMZ_SERVER_SIDE_ENCRYPTION_AWS_KMS_KEY_ID",      "x-amz-server-side-encryption-aws-kms-key-id"},
    {"HTTP_X_BCE_SERVER_SIDE_ENCRYPTION",                     "x-bce-server-side-encryption"},
    {"HTTP_X_BCE_SERVER_SIDE_ENCRYPTION_CUSTOMER_KEY",        "x-bce-server-side-encryption-customer-key"},
    {"HTTP_X_BCE_SERVER_SIDE_ENCRYPTION_CUSTOMER_KEY_MD5",    "x-bce-server-side-encryption-customer-key-md5"},
    {"HTTP_X_BCE_SERVER_SIDE_ENCRYPTION_BOS_KMS_KEY_ID",      "x-bce-server-side-encryption-bos-kms-key-id"},
};

static boost::string_view get_crypt_attribute(
    const RGWEnv* env,
    std::map<std::string,
             RGWPostObj_ObjStore::post_form_part,
             const ltstr_nocase>* parts,
    crypt_option_e option)
{
  static_assert(
      X_AMZ_SERVER_SIDE_ENCRYPTION_LAST == sizeof(crypt_options)/sizeof(*crypt_options),
      "Missing items in crypt_options");
  if (parts != nullptr) {
    auto iter
      = parts->find(crypt_options[option].post_part_name);
    if (iter == parts->end())
      return boost::string_view();
    bufferlist& data = iter->second.data;
    boost::string_view str = boost::string_view(data.c_str(), data.length());
    return rgw_trim_whitespace(str);
  } else {
    const char* hdr = env->get(crypt_options[option].http_header_name, nullptr);
    if (hdr != nullptr) {
      return boost::string_view(hdr);
    } else {
      return boost::string_view();
    }
  }
}


int rgw_s3_prepare_encrypt(struct req_state* s,
                           std::map<std::string, ceph::bufferlist>& attrs,
                           std::map<std::string,
                                    RGWPostObj_ObjStore::post_form_part,
                                    const ltstr_nocase>* parts,
                           std::unique_ptr<BlockCrypt>* block_crypt,
                           std::map<std::string, std::string>& crypt_http_responses)
{
  if (!s->cct->_conf->rgw_crypt_enable) {
    ldout(s->cct, 20) << __func__ << "disabled encrypt data." << dendl;
    return 0;
  }
    crypt_http_responses.clear();

  {
    boost::string_view req_sse_ca =
        get_crypt_attribute(s->info.env, parts, X_AMZ_SERVER_SIDE_ENCRYPTION_CUSTOMER_ALGORITHM);
    if (! req_sse_ca.empty()) {
      if (req_sse_ca != RGW_CRYPT_AES256 && req_sse_ca != RGW_CRYPT_SM4) {
        ldout(s->cct, 5) << "ERROR: Invalid value for header "
                         << "x-amz-server-side-encryption-customer-algorithm"
                         << dendl;
        s->err.message = "The requested encryption algorithm is not valid, must be AES256 or SM4.";
        return -ERR_INVALID_ENCRYPTION_ALGORITHM;
      }

      if (s->cct->_conf->rgw_crypt_require_ssl &&
          !rgw_transport_is_secure(s->cct, *s->info.env)) {
        ldout(s->cct, 5) << "ERROR: Insecure request, rgw_crypt_require_ssl is set" << dendl;
        return -ERR_INVALID_REQUEST;
      }

      std::string key_bin;
      try {
        key_bin = from_base64(
          get_crypt_attribute(s->info.env, parts, X_AMZ_SERVER_SIDE_ENCRYPTION_CUSTOMER_KEY) );
      } catch (...) {
        ldout(s->cct, 5) << "ERROR: rgw_s3_prepare_encrypt invalid encryption "
                         << "key which contains character that is not base64 encoded."
                         << dendl;
        s->err.message = "Requests specifying Server Side Encryption with Customer "
                         "provided keys must provide an appropriate secret key.";
        return -EINVAL;
      }

      if (key_bin.size() != AES_256_CBC::AES_256_KEYSIZE && key_bin.size() != SM4_KEYSIZE) {
        ldout(s->cct, 5) << "ERROR: invalid encryption key size" << dendl;
        s->err.message = "Requests specifying Server Side Encryption with Customer "
                         "provided keys must provide an appropriate secret key.";
        return -EINVAL;
      }

      boost::string_view keymd5 =
          get_crypt_attribute(s->info.env, parts, X_AMZ_SERVER_SIDE_ENCRYPTION_CUSTOMER_KEY_MD5);

      std::string keymd5_bin;
      try {
        keymd5_bin = from_base64(keymd5);
      } catch (...) {
        ldout(s->cct, 5) << "ERROR: rgw_s3_prepare_encrypt invalid encryption key "
                         << "md5 which contains character that is not base64 encoded."
                         << dendl;
        s->err.message = "Requests specifying Server Side Encryption with Customer "
                         "provided keys must provide an appropriate secret key md5.";
        return -EINVAL;
      }

      if (keymd5_bin.size() != CEPH_CRYPTO_KEY_MD5SIZE) {
        ldout(s->cct, 5) << "ERROR: Invalid key md5 size, actual size: " << keymd5_bin.size() << dendl;
        s->err.message = "Requests specifying Server Side Encryption with Customer "
                         "provided keys must provide an appropriate secret key md5.";
        return -EINVAL;
      }

      MD5 key_hash;
      unsigned char key_hash_res[CEPH_CRYPTO_MD5_DIGESTSIZE];
      key_hash.Update(reinterpret_cast<const unsigned char*>(key_bin.c_str()), key_bin.size());
      key_hash.Final(key_hash_res);
      char calc_md5[CEPH_CRYPTO_MD5_DIGESTSIZE * 2 + 1];
      buf_to_hex(key_hash_res, CEPH_CRYPTO_MD5_DIGESTSIZE, calc_md5);

      if (memcmp(calc_md5, keymd5_bin.c_str(), CEPH_CRYPTO_KEY_MD5SIZE) != 0) {
        ldout(s->cct, 5) << "ERROR: Invalid key md5 hash" << dendl;
        s->err.message = "The calculated MD5 hash of the key did not match the hash that was provided.";
        return -EINVAL;
      }

      set_attr(attrs, RGW_ATTR_CRYPT_MODE, "SSE-C");
      set_attr(attrs, RGW_ATTR_CRYPT_KEYMD5, keymd5_bin);
      set_attr(attrs, RGW_ATTR_CRYPT_SSE_C_KEY, key_bin);
      set_attr(attrs, RGW_ATTR_CRYPT_ALGORITHM, req_sse_ca);

      if (block_crypt) {
        if (req_sse_ca == RGW_CRYPT_AES256) {
          auto aes = std::unique_ptr<AES_256_CBC>(new AES_256_CBC(s->cct));
          aes->set_key(reinterpret_cast<const uint8_t*>(key_bin.c_str()), AES_256_KEYSIZE);
          *block_crypt = std::move(aes);
        } else {
          auto sm4 = std::unique_ptr<SM4_CTR>(new SM4_CTR(s->cct));
          if (!sm4->set_key(key_bin, key_bin.size())) {
            return -ERR_INVALID_SECRET_KEY;
          }
          *block_crypt = std::move(sm4);
        }
      }

      crypt_http_responses["x-amz-server-side-encryption-customer-algorithm"] = req_sse_ca.to_string();
      crypt_http_responses["x-amz-server-side-encryption-customer-key-MD5"] = keymd5.to_string();
      return 0;
    } else {
      boost::string_view customer_key =
          get_crypt_attribute(s->info.env, parts, X_AMZ_SERVER_SIDE_ENCRYPTION_CUSTOMER_KEY);
      if (!customer_key.empty()) {
        ldout(s->cct, 5) << "ERROR: SSE-C encryption request is missing the header "
                         << "x-amz-server-side-encryption-customer-algorithm"
                         << dendl;
        s->err.message = "Requests specifying Server Side Encryption with Customer "
                         "provided keys must provide a valid encryption algorithm.";
        return -EINVAL;
      }

      boost::string_view customer_key_md5 =
          get_crypt_attribute(s->info.env, parts, X_AMZ_SERVER_SIDE_ENCRYPTION_CUSTOMER_KEY_MD5);
      if (!customer_key_md5.empty()) {
        ldout(s->cct, 5) << "ERROR: SSE-C encryption request is missing the header "
                         << "x-amz-server-side-encryption-customer-algorithm"
                         << dendl;
        s->err.message = "Requests specifying Server Side Encryption with Customer "
                         "provided keys must provide a valid encryption algorithm.";
        return -EINVAL;
      }
    }

    std::string master_key_id;
    std::string crypt_algorithm = RGW_CRYPT_AES256;
    if (!s->bucket_info.encryption_algorithm.empty() && !s->bucket_info.kms_master_key_id.empty()) {
      master_key_id = s->bucket_info.kms_master_key_id;
      crypt_algorithm = s->bucket_info.encryption_algorithm;
    }
    /* AMAZON server side encryption with KMS (key management service) */
    boost::string_view req_sse =
        get_crypt_attribute(s->info.env, parts, X_AMZ_SERVER_SIDE_ENCRYPTION);
    if (!req_sse.empty()) {
      if (req_sse != "aws:kms") {
        ldout(s->cct, 5) << "ERROR: Invalid value for header x-amz-server-side-encryption"
                         << dendl;
        s->err.message = "Server Side Encryption with KMS managed key requires "
                         "HTTP header x-amz-server-side-encryption : aws:kms";
        return -EINVAL;
      }
      if (s->cct->_conf->rgw_crypt_require_ssl &&
          !rgw_transport_is_secure(s->cct, *s->info.env)) {
        ldout(s->cct, 5) << "ERROR: insecure request, rgw_crypt_require_ssl is set" << dendl;
        return -ERR_INVALID_REQUEST;
      }

      master_key_id = string(
          get_crypt_attribute(s->info.env, parts, X_AMZ_SERVER_SIDE_ENCRYPTION_AWS_KMS_KEY_ID));
      if (master_key_id.empty() || master_key_id.size() != 36) {
        ldout(s->cct, 5) << "ERROR: not provide a valid key id" << dendl;
        s->err.message = "Server Side Encryption with KMS managed key requires "
                         "HTTP header x-amz-server-side-encryption-aws-kms-key-id";
        return -ERR_INVALID_ENCRY_KMS_MK_ID;
      }
    } else {
      boost::string_view key_id =
          get_crypt_attribute(s->info.env, parts, X_AMZ_SERVER_SIDE_ENCRYPTION_AWS_KMS_KEY_ID);
      if (!key_id.empty()) {
        ldout(s->cct, 5) << "ERROR: SSE-KMS encryption request is missing the header "
                         << "x-amz-server-side-encryption"
                         << dendl;
        s->err.message = "Server Side Encryption with KMS managed key requires "
                         "HTTP header x-amz-server-side-encryption : aws:kms";
        return -EINVAL;
      }
    }

    if (!master_key_id.empty()) {
      /* try to retrieve actual key */
      auto data_key = kms::KMSClient::instance().generate_data_key(s, master_key_id, crypt_algorithm == RGW_CRYPT_AES256 ? AES_256_KEYSIZE : SM4_KEYSIZE);
      if (!data_key) {
        ldout(s->cct, 5) << "ERROR: get data key from kms faild." << dendl;
        return -EINVAL;
      }
      std::string ciphertext_data_key, plaintext_data_key;
      std::tie(ciphertext_data_key, plaintext_data_key) = *data_key;
      if (plaintext_data_key.empty()) {
         ldout(s->cct, 5) << __func__ << "() ERROR: get data key form kms falid, kms master key: " << master_key_id << dendl;
         return -ERR_INVALID_ENCRY_KMS_MK_ID;
      }

      set_attr(attrs, RGW_ATTR_CRYPT_MODE, "SSE-KMS");
      set_attr(attrs, RGW_ATTR_CRYPT_CDK, ciphertext_data_key);
      set_attr(attrs, RGW_ATTR_CRYPT_ALGORITHM, crypt_algorithm);

      if (block_crypt) {
        if (crypt_algorithm == RGW_CRYPT_AES256) {
          auto aes = std::unique_ptr<AES_256_CBC>(new AES_256_CBC(s->cct));
          aes->set_key(reinterpret_cast<const uint8_t*>(plaintext_data_key.c_str()), AES_256_KEYSIZE);
          *block_crypt = std::move(aes);
        } else {
          auto sm4 = std::unique_ptr<SM4_CTR>(new SM4_CTR(s->cct));
          if (!sm4->set_key(plaintext_data_key, plaintext_data_key.size())) {
            return -ERR_INVALID_SECRET_KEY;
          }
          *block_crypt = std::move(sm4);
        }
      }

      crypt_http_responses["x-amz-server-side-encryption"] = "aws:kms";
      crypt_http_responses["x-amz-server-side-encryption-aws-kms-key-id"] = master_key_id;
      return 0;
    }

    /* no other encryption mode, check if default encryption is selected */
    if (!s->cct->_conf->rgw_crypt_default_encryption_key.empty() ||
        !s->bucket_info.encryption_algorithm.empty()) {
      std::string master_encryption_key;
      std::string crypt_algorithm = RGW_CRYPT_AES256;
      try {
        if (!s->bucket_info.encryption_algorithm.empty()) {
          if (get_str_attribute(attrs, RGW_ATTR_CRYPT_KEY).empty()) {
            crypt_algorithm = s->bucket_info.encryption_algorithm;
            auto key_size = s->bucket_info.encryption_algorithm == RGW_CRYPT_AES256 ? AES_256_KEYSIZE : SM4_KEYSIZE;
            char object_encryption_key[key_size + 1];
            gen_rand_alphanumeric_plain(s->cct, object_encryption_key, sizeof(object_encryption_key));
            master_encryption_key = object_encryption_key;
          }
        } else {
          master_encryption_key = from_base64(s->cct->_conf->rgw_crypt_default_encryption_key);
        }
        set_attr(attrs, RGW_ATTR_CRYPT_KEY, master_encryption_key);
      } catch (...) {
        ldout(s->cct, 5) << "ERROR: rgw_s3_prepare_encrypt invalid default encryption key "
                         << "which contains character that is not base64 encoded."
                         << dendl;
        s->err.message = "Requests specifying Server Side Encryption with Customer "
                         "provided keys must provide an appropriate secret key.";
        return -EINVAL;
      }

      if (crypt_algorithm == RGW_CRYPT_SM4 && master_encryption_key.size() != SM4_KEYSIZE) {
        ldout(s->cct, 0) << "ERROR: failed to decode 'rgw crypt default encryption key' to 128 bit string" << dendl;
        /* not an error to return; missing encryption does not inhibit processing */
        return 0;
      } else if (crypt_algorithm == RGW_CRYPT_AES256 && master_encryption_key.size() != AES_256_KEYSIZE) {
        ldout(s->cct, 0) << "ERROR: failed to decode 'rgw crypt default encryption key' to 256 bit string" << dendl;
        /* not an error to return; missing encryption does not inhibit processing */
        return 0;
      }

      std::string key_selector = create_random_key_selector(s->cct, crypt_algorithm);
      set_attr(attrs, RGW_ATTR_CRYPT_MODE, "RGW-AUTO");
      set_attr(attrs, RGW_ATTR_CRYPT_KEYSEL, key_selector);
      set_attr(attrs, RGW_ATTR_CRYPT_ALGORITHM, crypt_algorithm);

      if (crypt_algorithm == RGW_CRYPT_AES256) {
        uint8_t actual_key[AES_256_KEYSIZE];
        if (AES_256_ECB_encrypt(s->cct,
                                reinterpret_cast<const uint8_t*>(master_encryption_key.c_str()), AES_256_KEYSIZE,
                                reinterpret_cast<const uint8_t*>(key_selector.c_str()),
                                actual_key, AES_256_KEYSIZE) != true) {
          memset(actual_key, 0, sizeof(actual_key));
          return -EIO;
        }
        if (block_crypt) {
          auto aes = std::unique_ptr<AES_256_CBC>(new AES_256_CBC(s->cct));
          aes->set_key(reinterpret_cast<const uint8_t*>(actual_key), AES_256_KEYSIZE);
          *block_crypt = std::move(aes);
        }
        memset(actual_key, 0, sizeof(actual_key));
      } else if (crypt_algorithm == RGW_CRYPT_SM4) {
        const char* actual_key;
        actual_key = master_encryption_key.c_str();
        if (block_crypt) {
          auto sm4 = std::unique_ptr<SM4_CTR>(new SM4_CTR(s->cct));
          if (!sm4->set_key(master_encryption_key, strlen(actual_key))) {
            return -ERR_INVALID_SECRET_KEY;
          }
          *block_crypt = std::move(sm4);
        }
      }
      return 0;
    }
  }
  /*no encryption*/
  return 0;
}

int rgw_s3_prepare_decrypt(struct req_state* s,
                       map<string, bufferlist>& attrs,
                       std::unique_ptr<BlockCrypt>* block_crypt,
                       std::map<std::string, std::string>& crypt_http_responses)
{
  std::string stored_mode = get_str_attribute(attrs, RGW_ATTR_CRYPT_MODE);
  ldout(s->cct, 15) << "Encryption mode: " << stored_mode << dendl;

  const char *req_sse = s->info.env->get("HTTP_X_AMZ_SERVER_SIDE_ENCRYPTION", NULL);
  if (nullptr != req_sse && (s->op == OP_GET || s->op == OP_HEAD)) {
    return -ERR_INVALID_REQUEST;
  }

  std::string attr_sse = get_str_attribute(attrs, RGW_ATTR_CRYPT_ALGORITHM);

  if (stored_mode == "SSE-C") {
    if (s->cct->_conf->rgw_crypt_require_ssl &&
        !rgw_transport_is_secure(s->cct, *s->info.env)) {
      ldout(s->cct, 5) << "ERROR: Insecure request, rgw_crypt_require_ssl is set" << dendl;
      return -ERR_INVALID_REQUEST;
    }

    const char *req_cust_alg =
        s->info.env->get("HTTP_X_AMZ_SERVER_SIDE_ENCRYPTION_CUSTOMER_ALGORITHM", NULL);
    if (req_cust_alg == nullptr && !attr_sse.empty()) {
      req_cust_alg = attr_sse.c_str();
    }

    if (nullptr == req_cust_alg)  {
      if (s->system_request) {
        ldout(s->cct, 30) << "DEBUG: system request is regarded as multisite fetch "
                          << "obj request, if not carry this header in request. "
                          << "Multisite can only store encrypted data to public "
                          << "cloud with this mode."
                         << dendl;
        return 0;
      }
      ldout(s->cct, 5) << "ERROR: Request for SSE-C encrypted object missing "
                       << "x-amz-server-side-encryption-customer-algorithm"
                       << dendl;
      s->err.message = "Requests specifying Server Side Encryption with Customer "
                       "provided keys must provide a valid encryption algorithm.";
      return -EINVAL;
    } else if (strcmp(req_cust_alg, RGW_CRYPT_AES256) != 0 && strcmp(req_cust_alg, RGW_CRYPT_SM4) != 0) {
      ldout(s->cct, 5) << "ERROR: The requested encryption algorithm is not valid, must be AES256 or SM4." << dendl;
      s->err.message = "The requested encryption algorithm is not valid, must be AES256 or SM4.";
      return -ERR_INVALID_ENCRYPTION_ALGORITHM;
    }

    std::string key_bin = get_str_attribute(attrs, RGW_ATTR_CRYPT_SSE_C_KEY);
    try {
      if (key_bin.empty()) {
        ldout(s->cct, 5) << __func__ << "ERROR: attr not find RGW_ATTR_CRYPT_SSE_C_KEY or key is empty." << dendl;
        return -EINVAL;
      }

      if (key_bin != from_base64(s->info.env->get("HTTP_X_AMZ_SERVER_SIDE_ENCRYPTION_CUSTOMER_KEY", ""))) {
        ldout(s->cct, 5) << __func__ << "ERROR: header: x-amz-server-side-encryption-customer-key not match attr key" << dendl;
        return -EINVAL;
      }
    } catch (...) {
      ldout(s->cct, 5) << "ERROR: rgw_s3_prepare_decrypt invalid encryption key "
                       << "which contains character that is not base64 encoded."
                       << dendl;
      s->err.message = "Requests specifying Server Side Encryption with Customer "
                       "provided keys must provide an appropriate secret key.";
      return -EINVAL;
    }

    if ((key_bin.size() != AES_256_CBC::AES_256_KEYSIZE && strcmp(req_cust_alg, RGW_CRYPT_AES256) == 0) ||
        (key_bin.size() != SM4_KEYSIZE && strcmp(req_cust_alg, RGW_CRYPT_SM4) == 0)){
      ldout(s->cct, 5) << "ERROR: Invalid encryption key size" << dendl;
      s->err.message = "Requests specifying Server Side Encryption with Customer "
                       "provided keys must provide an appropriate secret key.";
      return -EINVAL;
    }

    std::string keymd5 =
        s->info.env->get("HTTP_X_AMZ_SERVER_SIDE_ENCRYPTION_CUSTOMER_KEY_MD5", "");
    std::string keymd5_bin = get_str_attribute(attrs, RGW_ATTR_CRYPT_KEYMD5);
    try {
      if (keymd5_bin.empty()) {
        ldout(s->cct, 5) << __func__ << "ERROR: attr not find RGW_ATTR_CRYPT_KEYMD5" << dendl;
        return -EINVAL;
      }

      if (keymd5_bin != from_base64(keymd5)) {
        ldout(s->cct, 5) << __func__ << "ERROR: header x-amz-server-side-encryption-customer-key-md5 not match attr key md5" << dendl;
        return -EINVAL;
      }
    } catch (...) {
      ldout(s->cct, 5) << "ERROR: rgw_s3_prepare_decrypt invalid encryption key md5 "
                       << "which contains character that is not base64 encoded."
                       << dendl;
      s->err.message = "Requests specifying Server Side Encryption with Customer "
                       "provided keys must provide an appropriate secret key md5.";
      return -EINVAL;
    }

    if (keymd5_bin.size() != CEPH_CRYPTO_KEY_MD5SIZE) {
      ldout(s->cct, 5) << "ERROR: Invalid key md5 size " << dendl;
      s->err.message = "Requests specifying Server Side Encryption with Customer "
                       "provided keys must provide an appropriate secret key md5.";
      return -EINVAL;
    }

    MD5 key_hash;
    uint8_t key_hash_res[CEPH_CRYPTO_MD5_DIGESTSIZE];
    key_hash.Update(reinterpret_cast<const unsigned char*>(key_bin.c_str()), key_bin.size());
    key_hash.Final(key_hash_res);
    char calc_md5[CEPH_CRYPTO_MD5_DIGESTSIZE * 2 + 1];
    buf_to_hex(key_hash_res, CEPH_CRYPTO_MD5_DIGESTSIZE, calc_md5);

    if ((memcmp(calc_md5, keymd5_bin.c_str(), CEPH_CRYPTO_KEY_MD5SIZE) != 0) ||
        (get_str_attribute(attrs, RGW_ATTR_CRYPT_KEYMD5) != keymd5_bin)) {
      s->err.message = "The calculated MD5 hash of the key did not match the hash that was provided.";
      return -EINVAL;
    }
    if (strcmp(req_cust_alg, RGW_CRYPT_AES256) == 0) {
      auto aes = std::unique_ptr<AES_256_CBC>(new AES_256_CBC(s->cct));
      aes->set_key(reinterpret_cast<const uint8_t*>(key_bin.c_str()), AES_256_CBC::AES_256_KEYSIZE);
      if (block_crypt) *block_crypt = std::move(aes);
    } else if (strcmp(req_cust_alg, RGW_CRYPT_SM4) == 0) {
      auto sm4 = std::unique_ptr<SM4_CTR>(new SM4_CTR(s->cct));
      if (!sm4->set_key(key_bin, key_bin.size())) {
        return -ERR_INVALID_SECRET_KEY;
      }
      if (block_crypt) *block_crypt = std::move(sm4);
    }

    crypt_http_responses["x-amz-server-side-encryption-customer-algorithm"] = req_cust_alg;
    crypt_http_responses["x-amz-server-side-encryption-customer-key-MD5"] = keymd5;
    return 0;
  }

  if (stored_mode == "SSE-KMS") {
    if (s->cct->_conf->rgw_crypt_require_ssl &&
        !rgw_transport_is_secure(s->cct, *s->info.env)) {
      ldout(s->cct, 5) << "ERROR: Insecure request, rgw_crypt_require_ssl is set" << dendl;
      return -ERR_INVALID_REQUEST;
    }
    /* try to retrieve actual key */
    std::string ciphertext_data_key = get_str_attribute(attrs, RGW_ATTR_CRYPT_CDK);
    std::string plaintext_data_key = kms::KMSClient::instance().decrypt_data_key(s, ciphertext_data_key);
    if (plaintext_data_key.empty()) {
      ldout(s->cct, 0) << __func__ << "() ERROR: get data key form kms falid" << dendl;
      return -ERR_INVALID_ENCRY_KMS_MK_ID;
    }
    if (plaintext_data_key.size() != AES_256_KEYSIZE && plaintext_data_key.size() != SM4_KEYSIZE) {
      ldout(s->cct, 0) << __func__ << "() ERROR: actual data key size is not AES256 or SM4 size." << dendl;
      return -ERR_INVALID_ENCRY_KMS_MK_ID;
    }

    if (plaintext_data_key.size() == AES_256_KEYSIZE) {
      auto aes = std::unique_ptr<AES_256_CBC>(new AES_256_CBC(s->cct));
      aes->set_key(reinterpret_cast<const uint8_t*>(plaintext_data_key.c_str()), AES_256_KEYSIZE);
      if (block_crypt) *block_crypt = std::move(aes);
    } else if (plaintext_data_key.size() == SM4_KEYSIZE) {
      auto sm4 = std::unique_ptr<SM4_CTR>(new SM4_CTR(s->cct));
      if (!sm4->set_key(plaintext_data_key, plaintext_data_key.size())) {
        return -ERR_INVALID_SECRET_KEY;
      }
      if (block_crypt) *block_crypt = std::move(sm4);
    }

    crypt_http_responses["x-amz-server-side-encryption"] = "aws:kms";
    return 0;
  }

  if (stored_mode == "RGW-AUTO") {
    std::string master_encryption_key;
    try {
      master_encryption_key = get_str_attribute(attrs, RGW_ATTR_CRYPT_KEY);
    } catch (...) {
      ldout(s->cct, 5) << "ERROR: rgw_s3_prepare_decrypt invalid default encryption key "
                       << "which contains character that is not base64 encoded."
                       << dendl;
      s->err.message = "The default encryption key is not valid base64.";
      return -EINVAL;
    }

    if (master_encryption_key.size() == AES_256_KEYSIZE) {
      std::string attr_key_selector = get_str_attribute(attrs, RGW_ATTR_CRYPT_KEYSEL);
      if (attr_key_selector.size() != AES_256_CBC::AES_256_KEYSIZE) {
        ldout(s->cct, 0) << "ERROR: missing or invalid " RGW_ATTR_CRYPT_KEYSEL << dendl;
        return -EIO;
      }
      uint8_t actual_key[AES_256_KEYSIZE];
      if (AES_256_ECB_encrypt(s->cct,
                              reinterpret_cast<const uint8_t*>(master_encryption_key.c_str()),
                              AES_256_KEYSIZE,
                              reinterpret_cast<const uint8_t*>(attr_key_selector.c_str()),
                              actual_key, AES_256_KEYSIZE) != true) {
        memset(actual_key, 0, sizeof(actual_key));
        return -EIO;
      }
      auto aes = std::unique_ptr<AES_256_CBC>(new AES_256_CBC(s->cct));
      aes->set_key(actual_key, AES_256_KEYSIZE);
      memset(actual_key, 0, sizeof(actual_key));
      if (block_crypt) *block_crypt = std::move(aes);
      return 0;
    } else if (master_encryption_key.size() == SM4_KEYSIZE) {
      std::string attr_key_selector = get_str_attribute(attrs, RGW_ATTR_CRYPT_KEYSEL);
      if (attr_key_selector.size() != SM4_CTR::SM4_KEYSIZE) {
        ldout(s->cct, 0) << "ERROR: missing or invalid " RGW_ATTR_CRYPT_KEYSEL << dendl;
        return -EIO;
      }
      const char* actual_key;
      actual_key = master_encryption_key.c_str();
      auto sm4 = std::unique_ptr<SM4_CTR>(new SM4_CTR(s->cct));
      if (!sm4->set_key(master_encryption_key, strlen(actual_key))) {
        return -ERR_INVALID_SECRET_KEY;
      }
      if (block_crypt) *block_crypt = std::move(sm4);
    }
    return 0;
  }
  /*no decryption*/
  return 0;
}

enum SSEMode {
  SSE_C = 0,
  SSE_KMS,
  SSE_BOS,
};

int rgw_bos_prepare_encrypt(struct req_state* s,
                            std::map<std::string, ceph::bufferlist>& attrs,
                            std::map<std::string,
                                     RGWPostObj_ObjStore::post_form_part,
                                     const ltstr_nocase>* parts,
                            std::unique_ptr<BlockCrypt>* block_crypt,
                            std::map<std::string, std::string>& crypt_http_responses)
{
  if (!s->cct->_conf->rgw_crypt_enable) {
    ldout(s->cct, 20) << __func__ << "disabled encrypt data." << dendl;
    return 0;
  }
  crypt_http_responses.clear();
  SSEMode sse_mode = SSE_C;
  std::string master_key_id, actual_key;
  boost::string_view req_sse = get_crypt_attribute(s->info.env, parts, X_BCE_SERVER_SIDE_ENCRYPTION);
  string crypt_algorithm = string(req_sse);

  if (!req_sse.empty()) {
    if (req_sse != RGW_CRYPT_AES256 && req_sse != RGW_CRYPT_SM4) {
      /* now just support AES256 and SM4*/
      ldout(s->cct, 0) << __func__ << "() ERROR: Invalid value for header "
                       << "x-bce-server-side-encryption" << dendl;
      s->err.message = "The specified encryption algorithm is invalid";
      return -ERR_INVALID_ENCRYPTION_ALGORITHM;
    }

    std::string keybin_b64 = string(get_crypt_attribute(s->info.env, parts, X_BCE_SERVER_SIDE_ENCRYPTION_CUSTOMER_KEY));
    std::string keymd5_b64 = string(get_crypt_attribute(s->info.env, parts, X_BCE_SERVER_SIDE_ENCRYPTION_CUSTOMER_KEY_MD5));
    std::string keybin, keymd5;
    if (!keybin_b64.empty() || !keymd5_b64.empty()) {
      /* if have header x-bce-server-side-encryption-customer_key and
       * x-bce-server-encryption-customer_key_md5
       * mode SSE-C */
      try {
        keybin = from_base64(keybin_b64);
      } catch (...) {
        ldout(s->cct, 0) << __func__ << "() ERROR: rgw_bos_prepare_encrypt invalid encryption "
                         << "key which contains character that is not base64 encoded." << dendl;
        return -EINVAL;
      }
      try {
        keymd5 = from_base64(keymd5_b64);
      } catch (...) {
        ldout(s->cct, 0) << __func__ << "() ERROR: rgw_bos_prepare_encrypt invalid encryption key "
                         << "md5 which contains character that is not base64 encoded." << dendl;
        return -EINVAL;
      }

      if ((req_sse == RGW_CRYPT_AES256 && keybin.size() != AES_256_KEYSIZE) ||
          (req_sse == RGW_CRYPT_SM4 && keybin.size() != SM4_KEYSIZE)) {
        ldout(s->cct, 0) << __func__ << "() ERROR: invalid encryption key size encryption: " << req_sse << "and keysize: " << keybin.size() << dendl;
        return -EINVAL;
      }
      if (keymd5.size() != CEPH_CRYPTO_KEY_MD5SIZE) {
        ldout(s->cct, 0) << __func__ << "() ERROR: invalid key md5 size" << dendl;
        return -EINVAL;
      }

      MD5 key_hash;
      unsigned char key_hash_res[CEPH_CRYPTO_MD5_DIGESTSIZE];
      key_hash.Update(reinterpret_cast<const unsigned char*>(keybin.c_str()), keybin.size());
      key_hash.Final(key_hash_res);
      char calc_md5[CEPH_CRYPTO_MD5_DIGESTSIZE * 2 + 1];
      buf_to_hex(key_hash_res, CEPH_CRYPTO_MD5_DIGESTSIZE, calc_md5);
      if (memcmp(calc_md5, keymd5.c_str(), CEPH_CRYPTO_KEY_MD5SIZE) != 0) {
        ldout(s->cct, 0) << __func__ << "() ERROR: Invalid key md5 hash" << dendl;
        return -EINVAL;
      }

      set_attr(attrs, RGW_ATTR_CRYPT_MODE, "SSE-C");
      set_attr(attrs, RGW_ATTR_CRYPT_ALGORITHM, req_sse);
      set_attr(attrs, RGW_ATTR_CRYPT_KEYMD5, keymd5);
      set_attr(attrs, RGW_ATTR_CRYPT_SSE_C_KEY, keybin);

      if (block_crypt) {
        if (req_sse == RGW_CRYPT_AES256) {
          auto aes = std::unique_ptr<AES_256_CBC>(new AES_256_CBC(s->cct));
          aes->set_key(reinterpret_cast<const uint8_t*>(keybin.c_str()), AES_256_KEYSIZE);
          *block_crypt = std::move(aes);
        } else if (req_sse == RGW_CRYPT_SM4) {
          auto sm4 = std::unique_ptr<SM4_CTR>(new SM4_CTR(s->cct));
          if (!sm4->set_key(keybin, keybin.size())) {
            return -ERR_INVALID_SECRET_KEY;
          }
          *block_crypt = std::move(sm4);
        }
      }

      crypt_http_responses["x-bce-server-side-encryption"] = crypt_algorithm;
      crypt_http_responses["x-bce-server-side-encryption-customer-key"] = keybin_b64.c_str();
      crypt_http_responses["x-bce-server-side-encryption-customer-key-md5"] = keymd5_b64.c_str();
      return 0;
    }

    master_key_id = std::string(get_crypt_attribute(s->info.env, parts,
                                                    X_BCE_SERVER_SIDE_ENCRYPTION_BOS_KMS_KEY_ID));

    if (!master_key_id.empty()) {
      /* if have x-bcepserver-side-encryption-bos-kms-key-id
       * mdoe SSE-KMS */
      sse_mode = SSE_KMS;
      crypt_http_responses["x-bce-server-side-encryption-bos-kms-key-id"] = master_key_id;
    } else {
      /* mode SSE-BOS */
      sse_mode = SSE_BOS;
    }
  } else {
    if (s->info.env->exists("HTTP_X_BCE_SERVER_SIDE_ENCRYPTION_CUSTOMER_KEY") ||
        s->info.env->exists("HTTP_X_BCE_SERVER_SIDE_ENCRYPTION_CUSTOMER_KEY_MD5") ||
        s->info.env->exists("HTTP_X_BCE_SERVER_SIDE_ENCRYPTION_BOS_KMS_KEY_ID")) {
      ldout(s->cct, 0) << __func__ << "(): ERROR encryption request is missing the header "
                       << "x-bce-server-side-encryption" << dendl;
      s->err.message = "server side encryption request miss HTTP header x-bce-side-encryption";
      return -EINVAL;
    }

    if (!s->bucket_info.encryption_algorithm.empty()) {
      crypt_algorithm = s->bucket_info.encryption_algorithm;
      string bucket_master_key_id = s->bucket_info.kms_master_key_id;
      if (!bucket_master_key_id.empty()) {
        /* if bucket encrypt mode is kms, mode SSE-KMS */
        master_key_id = bucket_master_key_id;
        sse_mode = SSE_KMS;
      } else {
        /* mode SSE-BOS */
        sse_mode = SSE_BOS;
      }
    } else if (!s->cct->_conf->rgw_crypt_default_encryption_key.empty()) {
      /* global encryption */
      sse_mode = SSE_BOS;
      crypt_algorithm = RGW_CRYPT_AES256;
      actual_key = from_base64(std::string(s->cct->_conf->rgw_crypt_default_encryption_key));
    }
  }

  if (sse_mode == SSE_KMS) {
    if (master_key_id.size() != BOS_KMS_MASTER_KEY_SIZE) {
      ldout(s->cct, 0) << __func__ << "() ERROR: invalid kms mstaer key size, kms master key: " << master_key_id << dendl;
      return -ERR_INVALID_ENCRY_KMS_MK_ID;
    }

    auto data_key = kms::KMSClient::instance().generate_data_key_to_proxy(s, master_key_id, crypt_algorithm == RGW_CRYPT_AES256 ? AES_256_KEYSIZE : SM4_KEYSIZE);
    if (!data_key) {
      ldout(s->cct, 0) << __func__ << "() ERROR: get data key from kms faild." << dendl;
      return -EINVAL;
    }
    std::string ciphertext_data_key, plaintext_data_key;
    std::tie(ciphertext_data_key, plaintext_data_key) = *data_key;
    if (plaintext_data_key.empty()) {
      ldout(s->cct, 0) << __func__ << "() ERROR: get data key form kms falid, kms master key: " << master_key_id << dendl;
      return -ERR_INVALID_ENCRY_KMS_MK_ID;
    }

    set_attr(attrs, RGW_ATTR_CRYPT_MODE, "SSE-KMS");
    set_attr(attrs, RGW_ATTR_CRYPT_ALGORITHM, crypt_algorithm);
    set_attr(attrs, RGW_ATTR_CRYPT_CDK, ciphertext_data_key);

    if (block_crypt) {
      if (crypt_algorithm == RGW_CRYPT_AES256) {
        auto aes = std::unique_ptr<AES_256_CBC>(new AES_256_CBC(s->cct));
        aes->set_key(reinterpret_cast<const uint8_t*>(plaintext_data_key.c_str()), AES_256_KEYSIZE);
        *block_crypt = std::move(aes);
      } else if (crypt_algorithm == RGW_CRYPT_SM4) {
        auto sm4 = std::unique_ptr<SM4_CTR>(new SM4_CTR(s->cct));
        if (!sm4->set_key(plaintext_data_key, plaintext_data_key.size())) {
          return -ERR_INVALID_SECRET_KEY;
        }
        *block_crypt = std::move(sm4);
      }
    }
    return 0;
  }

  if (sse_mode == SSE_BOS) {
    std::string key_selector = create_random_key_selector(s->cct, crypt_algorithm);
    if (actual_key.empty()) {
      if (!s->bucket_info.encryption_algorithm.empty() &&
          s->bucket_info.encryption_algorithm != RGW_CRYPT_AES256 &&
          s->bucket_info.encryption_algorithm != RGW_CRYPT_SM4) {
        ldout(s->cct, 0) << __func__ << "() ERROR: encrypt mode sse-bos, "
                         << "use bucket encryption but this not support this encryption." << dendl;
        return -EINVAL;
      }
      /* if rgw conf don't have global encryption key, create it */
      auto key_size = crypt_algorithm == RGW_CRYPT_AES256 ? AES_256_KEYSIZE : SM4_KEYSIZE;
      char encryption_key_char[key_size + 1];
      gen_rand_alphanumeric_plain(s->cct, encryption_key_char, sizeof(encryption_key_char));
      actual_key = encryption_key_char;
      crypt_http_responses["x-bce-server-side-encryption"] = crypt_algorithm;
    }

    if ((actual_key.size() != AES_256_KEYSIZE && crypt_algorithm == RGW_CRYPT_AES256) ||
        (actual_key.size() != SM4_KEYSIZE && crypt_algorithm == RGW_CRYPT_SM4)) {
      ldout(s->cct, 0) << __func__ << "() ERROR: falid to decode rgw crypt default key to AES256 or SM4 string" << dendl;
      return -EINVAL;
    }

    set_attr(attrs, RGW_ATTR_CRYPT_MODE, "RGW-AUTO");
    set_attr(attrs, RGW_ATTR_CRYPT_ALGORITHM, crypt_algorithm);
    set_attr(attrs, RGW_ATTR_CRYPT_KEYSEL, key_selector);
    set_attr(attrs, RGW_ATTR_CRYPT_KEY, actual_key);

    if (crypt_algorithm == RGW_CRYPT_AES256) {
      uint8_t crypt_actual_key[AES_256_KEYSIZE];
      if (AES_256_ECB_encrypt(s->cct,
                              reinterpret_cast<const uint8_t*>(actual_key.c_str()), AES_256_KEYSIZE,
                              reinterpret_cast<const uint8_t*>(key_selector.c_str()),
                             crypt_actual_key, AES_256_KEYSIZE) != true) {
        memset(crypt_actual_key, 0, sizeof(crypt_actual_key));
        return -EIO;
      }

      if (block_crypt) {
        auto aes = std::unique_ptr<AES_256_CBC>(new AES_256_CBC(s->cct));
        aes->set_key(reinterpret_cast<const uint8_t*>(crypt_actual_key), AES_256_KEYSIZE);
        *block_crypt = std::move(aes);
      }
      memset(crypt_actual_key, 0, sizeof(crypt_actual_key));
    } else if (crypt_algorithm == RGW_CRYPT_SM4) {
      if (block_crypt) {
        auto sm4 = std::unique_ptr<SM4_CTR>(new SM4_CTR(s->cct));
        if (!sm4->set_key(actual_key, actual_key.size())) {
          return -ERR_INVALID_SECRET_KEY;
        }
        *block_crypt = std::move(sm4);
      }
    }
  }

  /*no decryption*/
  return 0;
}

int rgw_bos_prepare_decrypt(struct req_state* s,
                            map<string, bufferlist>& attrs,
                            std::unique_ptr<BlockCrypt>* block_crypt,
                            std::map<std::string, std::string>& crypt_http_responses)
{
  std::string stored_mode = get_str_attribute(attrs, RGW_ATTR_CRYPT_MODE);
  ldout(s->cct, 20) << __func__ << "() get encryption mode: " << stored_mode << dendl;

  std::string req_sse = s->info.env->get("HTTP_X_BCE_SERVER_SIDE_ENCRYPTION", "");
  std::string attr_sse = get_str_attribute(attrs, RGW_ATTR_CRYPT_ALGORITHM);
  if (!req_sse.empty() && attr_sse != req_sse) {
    ldout(s->cct, 0) << __func__ << "() ERROR: object attr crypt algorithm diff with req_sse" << dendl;
    return -ERR_INVALID_ENCRYPTION_ALGORITHM;
  }
  req_sse = attr_sse;
  if (!req_sse.empty() && req_sse != RGW_CRYPT_AES256 && req_sse != RGW_CRYPT_SM4) {
    ldout(s->cct, 0) << __func__ << "() ERROR: http header x-bce-server-side-encryption must be AES256 or SM4" << dendl;
    return -ERR_INVALID_ENCRYPTION_ALGORITHM;
  }

  if (stored_mode == "SSE-C") {
    if (req_sse.empty()) {
      ldout(s->cct, 0) << __func__ << "() ERROR: this object encryption mode SSE-C, "
                       << "but miss header x-bce-server-side-encryption" << dendl;
      return -ERR_INVALID_REQUEST;
    }

    std::string keybin_b64 = s->info.env->get("HTTP_X_BCE_SERVER_SIDE_ENCRYPTION_CUSTOMER_KEY", "");
    std::string keymd5_b64 = s->info.env->get("HTTP_X_BCE_SERVER_SIDE_ENCRYPTION_CUSTOMER_KEY_MD5", "");

    std::string keybin, keymd5;
    if (keybin_b64.empty() && keymd5_b64.empty() && !attr_sse.empty()) {
      keybin = get_str_attribute(attrs, RGW_ATTR_CRYPT_KEYMD5);
      keymd5 = get_str_attribute(attrs, RGW_ATTR_CRYPT_SSE_C_KEY);
    } else {
      try {
        keybin = from_base64(keybin_b64);
      } catch (...) {
        ldout(s->cct, 0) << __func__ << "() ERROR: invalid encryption key which contains character that is not base64 encoded." << dendl;
        return -EINVAL;
      }

      try {
        keymd5 = from_base64(keymd5_b64);
      } catch (...) {
        ldout(s->cct, 0) << __func__ << "() ERROR: Invalid key md5 size which contains character that is not base64 encoded." << dendl;
        return -EINVAL;
      }
    }

    if ((keybin.size() != AES_256_KEYSIZE && req_sse == RGW_CRYPT_AES256) ||
        (keybin.size() != SM4_KEYSIZE && req_sse == RGW_CRYPT_SM4)) {
      ldout(s->cct, 0) << __func__ << "() ERROR: header x-bce-server-side-encryption-customer-key size is not AES256 or SM4 key size." << dendl;
      return -EINVAL;
    }

    if (keymd5.size() != CEPH_CRYPTO_KEY_MD5SIZE) {
      ldout(s->cct, 0) << __func__ << "() ERROR: header x-bce-server-side-encryption-customer-key-MD5 size is not SM4 key size." << dendl;
      return -EINVAL;
    }

    MD5 key_hash;
    uint8_t key_hash_res[CEPH_CRYPTO_MD5_DIGESTSIZE];
    key_hash.Update(reinterpret_cast<const unsigned char*>(keybin.c_str()), keybin.size());
    key_hash.Final(key_hash_res);
    char calc_md5[CEPH_CRYPTO_MD5_DIGESTSIZE * 2 + 1];
    buf_to_hex(key_hash_res, CEPH_CRYPTO_MD5_DIGESTSIZE, calc_md5);

    if ((memcmp(calc_md5, keymd5.c_str(), CEPH_CRYPTO_KEY_MD5SIZE) != 0) ||
        (get_str_attribute(attrs, RGW_ATTR_CRYPT_KEYMD5) != keymd5)) {
      ldout(s->cct, 0) << __func__ << "() ERROR: The calculated MD5 hash of the key did not match the hash that was provided." << dendl;
      return -EINVAL;
    }

    if (req_sse == RGW_CRYPT_AES256) {
      auto aes = std::unique_ptr<AES_256_CBC>(new AES_256_CBC(s->cct));
      aes->set_key(reinterpret_cast<const uint8_t*>(keybin.c_str()), AES_256_KEYSIZE);
      if (block_crypt) *block_crypt = std::move(aes);
      keybin.replace(0, keybin.length(), keybin.length(), '\000');
    } else if (req_sse == RGW_CRYPT_SM4) {
      auto sm4 = std::unique_ptr<SM4_CTR>(new SM4_CTR(s->cct));
      if (!sm4->set_key(keybin, keybin.size())) {
        return -ERR_INVALID_SECRET_KEY;
      }
      if (block_crypt) *block_crypt = std::move(sm4);
    }

    crypt_http_responses["x-bce-server-side-encryption"] = req_sse;
    crypt_http_responses["x-bce-server-side-encryption-customer-key-md5"] = keymd5_b64;
  }

  if (stored_mode == "SSE-KMS") {
    std::string ciphertext_data_key = get_str_attribute(attrs, RGW_ATTR_CRYPT_CDK);
    std::string plaintext_data_key = kms::KMSClient::instance().decrypt_data_key_to_proxy(s, ciphertext_data_key);
    if (plaintext_data_key.empty()) {
      ldout(s->cct, 0) << __func__ << "() ERROR: get data key form kms falid." << dendl;
      return -ERR_INVALID_ENCRY_KMS_MK_ID;
    }
    if (plaintext_data_key.size() != AES_256_KEYSIZE && plaintext_data_key.size() != SM4_KEYSIZE) {
      ldout(s->cct, 0) << __func__ << "() ERROR: actual data key size is not AES256 or SM4 size." << dendl;
      return -ERR_INVALID_ENCRY_KMS_MK_ID;
    }

    if (plaintext_data_key.size() == AES_256_KEYSIZE) {
      auto aes = std::unique_ptr<AES_256_CBC>(new AES_256_CBC(s->cct));
      aes->set_key(reinterpret_cast<const uint8_t*>(plaintext_data_key.c_str()), AES_256_KEYSIZE);
      if (block_crypt) *block_crypt = std::move(aes);
      crypt_http_responses["x-bce-server-side-encryption"] = RGW_CRYPT_AES256;
    } else if (plaintext_data_key.size() == SM4_KEYSIZE) {
      auto sm4 = std::unique_ptr<SM4_CTR>(new SM4_CTR(s->cct));
      if (!sm4->set_key(plaintext_data_key, plaintext_data_key.size())) {
        return -ERR_INVALID_SECRET_KEY;
      }
      *block_crypt = std::move(sm4);
      crypt_http_responses["x-bce-server-side-encryption"] = RGW_CRYPT_SM4;
    }

  }

  if (stored_mode == "RGW-AUTO") {
    std::string actual_key = get_str_attribute(attrs, RGW_ATTR_CRYPT_KEY);
    std::string key_selector = get_str_attribute(attrs, RGW_ATTR_CRYPT_KEYSEL);
    if (actual_key.size() != AES_256_KEYSIZE && actual_key.size() != SM4_KEYSIZE) {
      ldout(s->cct, 0) << __func__ << "() ERROR: actual key size is not 256 bit size." << dendl;
      return -EINVAL;
    }
    if (key_selector.size() != AES_256_KEYSIZE && key_selector.size() != SM4_KEYSIZE) {
      ldout(s->cct, 0) << __func__ << "() ERROR: key selector size is not 256 bit size." << dendl;
      return -EINVAL;
    }

    if (actual_key.size() == AES_256_KEYSIZE) {
      uint8_t crypt_actual_key[AES_256_KEYSIZE];
      if (AES_256_ECB_encrypt(s->cct,
                              reinterpret_cast<const uint8_t*>(actual_key.c_str()),
                              AES_256_KEYSIZE,
                              reinterpret_cast<const uint8_t*>(key_selector.c_str()),
                              crypt_actual_key, AES_256_KEYSIZE) != true) {
        memset(crypt_actual_key, 0, sizeof(crypt_actual_key));
        return -EIO;
      }

      auto aes = std::unique_ptr<AES_256_CBC>(new AES_256_CBC(s->cct));
      aes->set_key(crypt_actual_key, AES_256_KEYSIZE);
      memset(crypt_actual_key, 0, sizeof(crypt_actual_key));
      if (block_crypt) *block_crypt = std::move(aes);
      crypt_http_responses["x-bce-server-side-encryption"] = RGW_CRYPT_AES256;
    } else if (actual_key.size() == SM4_KEYSIZE) {
      auto sm4 = std::unique_ptr<SM4_CTR>(new SM4_CTR(s->cct));
      if (!sm4->set_key(actual_key, actual_key.size())) {
        return -ERR_INVALID_SECRET_KEY;
      }
      *block_crypt = std::move(sm4);
      crypt_http_responses["x-bce-server-side-encryption"] = RGW_CRYPT_SM4;
    }
  }
  return 0;
}
