// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*- 
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2013 eNovance SAS <licensing@enovance.com>
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation. See file COPYING.
 *
 */

#ifndef CEPH_RGW_CORS_S3_H
#define CEPH_RGW_CORS_S3_H

#include <map>
#include <string>
#include <iosfwd>

#include <include/types.h>
#include <common/Formatter.h>
#include "rgw_xml.h"
#include "rgw_cors.h"

class RGWCORSRule_S3 : public RGWCORSRule, public XMLObj
{
public:
    RGWCORSRule_S3() {}
    ~RGWCORSRule_S3() override {}

    bool xml_end(const char *el) override;
    void to_xml(XMLFormatter& f);
    void to_json(JSONFormatter& jf);
};

class RGWCORSConfiguration_S3 : public RGWCORSConfiguration, public XMLObj
{
public:
    RGWCORSConfiguration_S3() {}
    ~RGWCORSConfiguration_S3() override {}

    bool xml_end(const char *el) override;
    void to_xml(ostream& out);
    void to_json(ostream& out);
};

class RGWCORSXMLParser_S3 : public RGWXMLParser
{
  CephContext *cct;

  XMLObj *alloc_obj(const char *el) override;
public:
  explicit RGWCORSXMLParser_S3(CephContext *_cct) : cct(_cct) {}
};

class RGWCORSJSONParser_S3 : public JSONParser
{
public:
  RGWCORSJSONParser_S3() {}
  ~RGWCORSJSONParser_S3() {
    if (cors_config != nullptr)
      delete cors_config;
  }

  RGWCORSConfiguration_S3 *cors_config = nullptr;
};
#endif /*CEPH_RGW_CORS_S3_H*/