// -*- mode:C; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab
/**
 * Crypto filters for Put/Post/Get operations.
 */
#ifndef CEPH_RGW_CRYPT_H
#define CEPH_RGW_CRYPT_H

#include <rgw/rgw_op.h>
#include <rgw/rgw_rest.h>
#include <rgw/rgw_rest_s3.h>
#include <rgw/rgw_crypt_block.h>
#include <boost/utility/string_view.hpp>

static const size_t AES_256_KEYSIZE = 256 / 8;
static const size_t SM4_KEYSIZE = 128 / 8;

bool AES_256_ECB_encrypt(CephContext* cct,
                         const uint8_t* key,
                         size_t key_size,
                         const uint8_t* data_in,
                         uint8_t* data_out,
                         size_t data_size);

bool encrypt_request_id(CephContext* cct,
                        const char* in,
                        char* out,
                        int& size);

class RGWGetObj_BlockDecrypt : public RGWGetObj_Filter {
  CephContext* cct;

  std::unique_ptr<BlockCrypt> crypt; /**< already configured stateless BlockCrypt
                                          for operations when enough data is accumulated */
  off_t enc_begin_skip; /**< amount of data to skip from beginning of received data */
  off_t ofs; /**< stream offset of data we expect to show up next through \ref handle_data */
  off_t end; /**< stream offset of last byte that is requested */
  bufferlist cache; /**< stores extra data that could not (yet) be processed by BlockCrypt */
  size_t block_size; /**< snapshot of \ref BlockCrypt.get_block_size() */
  int process(bufferlist& cipher, size_t part_ofs, size_t size);
protected:
  std::vector<size_t> parts_len; /**< size of parts of multipart object, parsed from manifest */
public:
  RGWGetObj_BlockDecrypt(CephContext* cct,
                         RGWGetObj_Filter* next,
                         std::unique_ptr<BlockCrypt> crypt);
  virtual ~RGWGetObj_BlockDecrypt();

  virtual int fixup_range(off_t& bl_ofs,
                          off_t& bl_end) override;
  virtual int handle_data(bufferlist& bl,
                          off_t bl_ofs,
                          off_t bl_len) override;

  virtual bool is_crypt() { return true; }

  virtual int flush() override;

  int read_manifest(bufferlist& manifest_bl);
}; /* RGWGetObj_BlockDecrypt */


class RGWPutObj_BlockEncrypt : public RGWPutObj_Filter
{
  CephContext* cct;
  std::unique_ptr<BlockCrypt> crypt; /**< already configured stateless BlockCrypt
                                          for operations when enough data is accumulated */
  off_t ofs; /**< stream offset of data we expect to show up next through \ref handle_data */
  bufferlist cache; /**< stores extra data that could not (yet) be processed by BlockCrypt */
  size_t block_size; /**< snapshot of \ref BlockCrypt.get_block_size() */
public:
  RGWPutObj_BlockEncrypt(CephContext* cct,
                         RGWPutObjDataProcessor* next,
                         std::unique_ptr<BlockCrypt> crypt);
  virtual ~RGWPutObj_BlockEncrypt();
  virtual int handle_data(bufferlist& bl,
                          off_t ofs,
                          void **phandle,
                          rgw_raw_obj *pobj,
                          bool *again) override;
  virtual int throttle_data(void *handle,
                            const rgw_raw_obj& obj,
                            uint64_t size,
                            bool need_to_wait) override;

  virtual int pre_handle_data(bufferlist& bl, bool *has_tail) override;
}; /* RGWPutObj_BlockEncrypt */


int rgw_s3_prepare_encrypt(struct req_state* s,
                           std::map<std::string, ceph::bufferlist>& attrs,
                           std::map<std::string,
                                    RGWPostObj_ObjStore::post_form_part,
                                    const ltstr_nocase>* parts,
                           std::unique_ptr<BlockCrypt>* block_crypt,
                           std::map<std::string,
                                    std::string>& crypt_http_responses);

int rgw_s3_prepare_decrypt(struct req_state* s,
                           std::map<std::string, ceph::bufferlist>& attrs,
                           std::unique_ptr<BlockCrypt>* block_crypt,
                           std::map<std::string, std::string>& crypt_http_responses);

int rgw_bos_prepare_encrypt(struct req_state* s,
                           std::map<std::string, ceph::bufferlist>& attrs,
                           std::map<std::string,
                                    RGWPostObj_ObjStore::post_form_part,
                                    const ltstr_nocase>* parts,
                           std::unique_ptr<BlockCrypt>* block_crypt,
                           std::map<std::string,
                                    std::string>& crypt_http_responses);

int rgw_bos_prepare_decrypt(struct req_state* s,
                           std::map<std::string, ceph::bufferlist>& attrs,
                           std::unique_ptr<BlockCrypt>* block_crypt,
                           std::map<std::string,
                                    std::string>& crypt_http_responses);

#endif
