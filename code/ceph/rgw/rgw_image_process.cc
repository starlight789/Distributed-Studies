#include <map>

#include "rgw/rgw_b64.h"

#include "rgw_image_process.h"
#include "rgw_rest.h"
#include "rgw_op.h"
#include "common/errno.h"
#include "common/strtol.h"
#include "common/dout.h"
#include "aws_s3.h"

#define dout_context g_ceph_context
#define dout_subsys ceph_subsys_rgw

#define ImageBosV2ActionNone           ""
#define ImageBosV2ActionResize         "resize"
#define ImageBosV2ActionCrop           "crop"
#define ImageBosV2ActionCircle         "circle"
#define ImageBosV2ActionRoundedCorners "rounded-corners"
#define ImageBosV2ActionRotate         "rotate"
#define ImageBosV2ActionAutoOrient     "auto-orient"
#define ImageBosV2ActionFormat         "format"
#define ImageBosV2ActionQuality        "quality"
#define ImageBosV2ActionBlur           "blur"
#define ImageBosV2ActionBright         "bright"
#define ImageBosV2ActionSharpen        "sharpen"
#define ImageBosV2ActionWatermark      "watermark"
#define ImageBosV2ActionBlindWatermark "blind-watermark"

#define ImageBosV2ResizeModeLfit  "lfit"
#define ImageBosV2ResizeModeMfit  "mfit"
#define ImageBosV2ResizeModeFill  "fill"
#define ImageBosV2ResizeModePad   "pad"
#define ImageBosV2ResizeModeFixed "fixed"

#define ImageV1SizeMax       100 * 1024 * 1024
#define ImageV2SizeMax       20 * 1024 * 1024
#define ImageSizeMax         ImageV1SizeMax
#define ImageAnimatedSizeMax 2 * 1024 * 1024
#define ImageSizeMin         4
#define ImageFramesMax       100

#define ImageInputWidthMin  1
#define ImageInputWidthMax  65536 // 16384 is enough, 65536 is for baike
#define ImageInputHeightMin 1
#define ImageInputHeightMax 65536
#define ImageOutputWidthMin  1
#define ImageOutputWidthMax  4096
#define ImageOutputHeightMin 1
#define ImageOutputHeightMax 4096

#define ImagePercentageMin 1
#define ImagePercentageMax 1000

#define ImageOutputRadiusMin 1
#define ImageOutputRadiusMax 2048

#define ImageBlurRadiusMin 1
#define ImageBlurRadiusMax 50
#define ImageBlurSigmaMin  1
#define ImageBlurSigmaMax  50

#define ImageOutputAngleMin -360
#define ImageOutputAngleMax 360

#define ImageCropIndexMax 65536

#define ImageWidthPercentMax  100
#define ImageHeightPercentMax 100

#define ImageQualityMin  1
#define ImageQualityMax  100

#define QualityLess     0x01
#define QualityEqual    0x02
#define QualityGreater  0x04
#define QualityAbsolute 0x20

#define ImageSelfieAnimeMaskIdMin 1
#define ImageSelfieAnimeMaskIdMax 8

#define ImageContrastMin -100
#define ImageContrastMax 100

#define ImageSharpenRadiusMin 1
#define ImageSharpenRadiusMax 50
#define ImageSharpenSigmaMin  1
#define ImageSharpenSigmaMax  50

#define ImageWmPercentageMin 1
#define ImageWmPercentageMax 100

#define ImageWmOpacityMin 1
#define ImageWmOpacityMax 100

#define ImageWmGravityMin 1
#define ImageWmGravityMax 9

#define ImageWmTextSizeMin 1
#define ImageWmTextSizeMax 1024

#define StrokeWidthMin 1
#define StrokeWidthMax 1024

#define BlurRadiusMin 1
#define BlurRadiusMax 50

#define BlurSigmaMin 1
#define BlurSigmaMax 50

#define ImageShadowMin 0
#define ImageShadowMax 10

#define WatermarkOrderPic 0
#define WatermarkOrderText 1
#define WatermarkOrderDefault WatermarkOrderPic
#define WatermarkOrderMin WatermarkOrderPic
#define WatermarkOrderMax WatermarkOrderText

#define WatermarkAlignMin 0
#define WatermarkAlignMax 2

#define WatermarkIntervalMin 0
#define WatermarkIntervalMax 1000

#define EffectHardShadow 1
#define EffectSoftShadow 2
#define EffectSoftOutline 3

enum {
  ImageResizeModeLfit  = 0,
  ImageResizeModeFixed,
  ImageResizeModeFill,
  ImageResizeModeMfit,
  ImageResizeModePad,
};

#define ImageBosV2ResizeModeLfit  "lfit"
#define ImageBosV2ResizeModeMfit  "mfit"
#define ImageBosV2ResizeModeFill  "fill"
#define ImageBosV2ResizeModePad   "pad"
#define ImageBosV2ResizeModeFixed "fixed"

#define ImageBOSExtractBlindWatermark "extractBlindWatermark"
#define ImageBOSEmbedBlindWatermark   "embedBlindWatermark"

std::unordered_map<string, int> imageBosV2ResizeMode = {
  {ImageBosV2ResizeModeLfit, ImageResizeModeLfit},
  {ImageBosV2ResizeModeFixed, ImageResizeModeFixed},
  {ImageBosV2ResizeModeFill, ImageResizeModeFill},
  {ImageBosV2ResizeModeMfit, ImageResizeModeMfit},
  {ImageBosV2ResizeModePad, ImageResizeModePad},
};

static unordered_map<std::string, std::string> font_map = {
  {"microsoftyahei", "MicrosoftYaHei"},
  {"fangsong", "FangSong"},
  {"simhei", "SimHei"},
  {"kaiti", "KaiTi"},
  {"simsun", "SimSun"},
  {"arialunicode", "ArialUnicode"},
  {"pingfangsc", "PingFangSC"},
  {"fzbeiweikaishujianti", "FZBeiWeiKaiShuJianTi"},
  {"fzboyasongjianti", "FZBoYaSongJianTi"},
  {"fzcuheisongjianti", "FZCuHeiSongJianTi"},
  {"fzlantingzhongheijianti", "FZLanTingZhongHeiJianTi"},
  {"fzzhenghei", "FZZhengHei"},
  {"avantgarde", "AvantGarde"},
  {"bookman", "Bookman"},
  {"courier", "Courier"},
  {"helvetica", "Helvetica"},
  {"helveticanarrow", "HelveticaNarrow"},
  {"newcenturyschlbk", "NewCenturySchlbk"},
  {"palatino", "Palatino"},
  {"times", "Times"},
  {"symbol", "Symbol"},
  {"fzlantingheisbgb", "FZLanTingHeiSBGB"},
  {"fzlantingheisdb1gb", "FZLanTingHeiSDB1GB"},
  {"fzlantingheisdbgb", "FZLanTingHeiSDBGB"},
  {"fzlantingheisebgb", "FZLanTingHeiSEBGB"},
  {"fzlantingheiselgb", "FZLanTingHeiSELGB"},
  {"fzlantingheishgb", "FZLanTingHeiSHGB"},
  {"fzlantingheislgb", "FZLanTingHeiSLGB"},
  {"fzlantingheismgb", "FZLanTingHeiSMGB"},
  {"fzlantingheisrgb", "FZLanTingHeiSRGB"},
  {"fzlantingheisulgb", "FZLanTingHeiSULGB"},
  {"fzbangshuxingsrgb", "FZBangShuXingSRGB"},
  {"fzcuqianm17s", "FZCuQianM17S"},
  {"fzcuyuanm03s", "FZCuYuanM03S"},
  {"fzcuyuansongsrgb", "FZCuYuanSongSRGB"},
  {"fzdaheib02s", "FZDaHeiB02S"},
  {"fzdaweitisrgb", "FZDaWeiTiSRGB"},
  {"fzfangsongz02s", "FZFangSongZ02S"},
  {"fzheib01s", "FZHeiB01S"},
  {"fzheilisebgb", "FZHeiLiSEBGB"},
  {"fzhupom04s", "FZHuPoM04S"},
  {"fzkaiz03s", "FZKaiZ03S"},
  {"fzkatongm19s", "FZKaTongM19S"},
  {"fzlantingyuansbgb", "FZLanTingYuanSBGB"},
  {"fzlantingyuansdb1gb", "FZLanTingYuanSDB1GB"},
  {"fzmeiheim07s", "FZMeiHeiM07S"},
  {"fzpangtouyum24", "FZPangTouYuM24"},
  {"fzpangtouyum24s", "FZPangTouYuM24S"},
  {"fzpangwam18s", "FZPangWaM18S"},
  {"fzpinghes11s", "FZPingHeS11S"},
  {"fzqusongsrgb", "FZQuSongSRGB"},
  {"fzruizhengheisebgb", "FZRuiZhengHeiSEBGB"},
  {"fzshaoerm11s", "FZShaoErM11S"},
  {"fzshusongz01s", "FZShuSongZ01S"},
  {"fzxiaobiaosongb05s", "FZXiaoBiaoSongB05S"},
  {"fzxingheisrgb", "FZXingHeiSRGB"},
  {"fzxiqianm15s", "FZXiQianM15S"},
  {"fzyasongshgb", "FZYaSongSHGB"},
  {"fzyiheim20s", "FZYiHeiM20S"},
  {"fzyundongheishgb", "FZYunDongHeiSHGB"},
  {"fzzhengheisebgb", "FZZhengHeiSEBGB"},
  {"fzzhongqianm16s", "FZZhongQianM16S"},
  {"fzzjfojw", "FZZJFOJW"},
  {"jimojw", "JIMOJW"},
  {"fzfangsong", "FZFangSongZ02S"},
  {"fzhei", "FZHeiB01S"},
  {"fzkai", "FZKaiZ03S"},
  {"fzkatong", "FZKaTongM19S"},
  {"fzlantinghei", "FZLanTingHeiSRGB"},
  {"fzpangwa", "FZPangWaM18S"},
  {"fzshusong", "FZShuSongZ01S"},
};

static unordered_map<std::string, bool> font_style = {
  {"normal", true},
  {"italic", true},
  {"bold", true},
};

static unordered_map<std::string, int> effect_map = {
  {"hardshadow", EffectHardShadow},
  {"softshadow", EffectSoftShadow},
  {"softoutline", EffectSoftOutline},
};

static unordered_map<int, int> align_map = {
  {0, WatermarkAlignTop},
  {1, WatermarkAlignMiddle},
  {2, WatermarkAlignBottom},
};

int convert_to_int(std::string& v_string, int32_t& v_int, int min, int max) {
  try {
    v_int = int32_t(stoi(v_string));
  } catch (std::exception &e) {
    dout(10) << __func__ << "() invalid value:" << v_string << ", err:" << e.what() << dendl;
    return -1;
  }
  if (v_int < min || v_int > max) {
    dout(10) << __func__ << "() value out of range:" << v_int << dendl;
    return -2;
  }
  return 0;
}

/**
 * generate_presigned_url() - get presign url for timg, which use it to fetch original picture
 *   if WITH_BCEIAM: try use rgw_iam_admin_read_ak/sk to presign url,
 *      else local user -> use user's ak/sk to presign url.
 */
std::string ImageProcess::generate_presigned_url(const std::string& bucket, const std::string& object) {
  string port;
  string local_ip = g_conf->public_addr.ip_only_to_str();
  list<string> frontends;
  get_str_list(g_conf->rgw_frontends, " ", frontends);
  for (auto frontend : frontends) {
    if (frontend.find("port=") == 0) {
      port = frontend.substr(strlen("port="));
      //port=8080+8443s
      if (port.find("+") != string::npos) {
        list<string> ports;
        get_str_list(port, "+", ports);
        for(auto p : ports)
          if (p.find("s") == string::npos) {
            port = p;
            break;
          }
      }
#ifdef WITH_RADOSGW_BEAST_FRONTEND
      //port=8080s+8443s && port=8443s
      if (port.find("s") != string::npos) {
        port = port.substr(0, port.find("s"));
      }
#endif
      break;
    }
  }
  string host = string_cat_reserve(local_ip.c_str(), ":", port.c_str());

  if (s->user->user_id.id == "anonymous" && s->user->user_id.tenant == "") {
    RGWUserInfo uinfo;
    int r = rgw_get_user_info_by_uid(store, s->bucket_info.owner, uinfo);
    if (r < 0) {
      ldout(s->cct, 0) << "could not get user info for uid="
             << s->bucket_info.owner.id << ", "<< r << dendl;
      return "http://" + host + "/" + bucket + "/" + object;
    }
    map<string, RGWAccessKey>::iterator aiter = uinfo.access_keys.begin();
    if (aiter == uinfo.access_keys.end()) {

#ifdef WITH_BCEIAM
      if (s->cct->_conf->rgw_s3_auth_use_iam) {
        if (s->cct->_conf->rgw_iam_admin_read_ak.empty() ||
            s->cct->_conf->rgw_iam_admin_read_sk.empty()) {
          ldout(s->cct, 0) << "rgw_iam_admin_read_ak is empty in iam authorization" << dendl;
          return "http://" + host + "/" + bucket + "/" + object;
        }
        return awss3::get_presign_url(s, host, s->cct->_conf->rgw_iam_admin_read_ak,
                                      s->cct->_conf->rgw_iam_admin_read_sk,
                                      bucket, object);
      } else
#endif

      {
        ldout(s->cct, 0) << "invalid user without accesskey, user id:"
          << uinfo.user_id << dendl;
        return "http://" + host + "/" + bucket + "/" + object;
      }
    }

    return awss3::get_presign_url(s, host, aiter->second.id, aiter->second.key,
                                  bucket, object);
  }

#ifdef WITH_BCEIAM
  if (s->cct->_conf->rgw_s3_auth_use_iam && s->user->access_keys.size() == 0) {
    if (s->cct->_conf->rgw_iam_admin_read_ak.empty() ||
        s->cct->_conf->rgw_iam_admin_read_sk.empty()) {
      ldout(s->cct, 0) << "rgw_iam_admin_read_ak is empty in iam authorization" << dendl;
      return "http://" + host + "/" + bucket + "/" + object;
    }
    return awss3::get_presign_url(s, host, s->cct->_conf->rgw_iam_admin_read_ak,
                                  s->cct->_conf->rgw_iam_admin_read_sk,
                                  bucket, object);
  } else
#endif
  {
    map<string, RGWAccessKey>::iterator aiter = s->user->access_keys.begin();
    if (aiter == s->user->access_keys.end()) {
      ldout(s->cct, 0) << "invalid user without accesskey, user id:"
        << s->user->user_id.id << dendl;
      return "http://" + host + "/" + bucket + "/" + object;
    }

    return awss3::get_presign_url(s, host, aiter->second.id, aiter->second.key,
                                  bucket, object);
  }
}

void ImageProcess::generate_timg_body(std::vector<std::shared_ptr<ImageBase>>& timg_cmds,
                                      std::string& result)
{
  JSONFormatter f;

  f.open_object_section("");
  std::string presigned_url = generate_presigned_url(s->bucket.name, s->object.name);
  f.dump_string("origin_url", presigned_url);

  f.open_array_section("operations");
  for (const auto& t : timg_cmds) {
    if (t != nullptr) {
      t->dump(&f);
    }
  }
  
  f.close_section();  // operations

  f.close_section();

  std::ostringstream oss;
  f.flush(oss);

  result = oss.str();
}

/**
 * parse_commands() - parse image process command to timg format
 *
 * PARAMS:
 *   - [IN] actions: vector<> of pure commands, split by / 
 *   - [IN] start: start index of pure commands in vector<>
 *                 vector[0] maybe prefix like: x-bce-process=styple/ or image/
 *   - [OUT] result: timg format commands
 */
int ImageProcess::parse_commands(std::vector<std::string>& actions,
                                 uint8_t start,
                                 vector<std::shared_ptr<ImageBase>>& result) {

  for (uint32_t i = start; i < actions.size(); i++) {
    int ret = 0;
    std::vector<std::string> details;
    boost::split(details, actions[i], boost::is_any_of(","));
    if (details.size() < 2) {
      dout(10) << __func__ << "() image process invalid param:" << actions[i] << dendl;
      return -EINVAL;
    }

    if (details[0] == ImageBosV2ActionResize) {
      ret = parseActionResize(details, result);
    } else if (details[0] == ImageBosV2ActionCrop) {
      ret = parseActionCrop(details, result);
    } else if (details[0] == ImageBosV2ActionRoundedCorners) {
      ret = parseActionRoundedCorners(details, result);
    } else if (details[0] == ImageBosV2ActionCircle) {
      ret = parseActionCircle(details, result);
    } else if (details[0] == ImageBosV2ActionRotate) {
      ret = parseActionRotate(details, result);
    } else if (details[0] == ImageBosV2ActionAutoOrient) {
      ret = parseActionAutoOrient(details, result);
    } else if (details[0] == ImageBosV2ActionFormat) {
      ret = parseActionFormat(details, result);
    } else if (details[0] == ImageBosV2ActionQuality) {
      ret = parseActionQuality(details, result);
    } else if (details[0] == ImageBosV2ActionBlur) {
      ret = parseActionBlur(details, result);
    } else if (details[0] == ImageBosV2ActionBright) {
      ret = parseActionBright(details, result);
    } else if (details[0] == ImageBosV2ActionSharpen) {
      ret = parseActionSharpen(details, result);
    } else if (details[0] == ImageBosV2ActionWatermark) {
      ret = parseActionWatermark(details, result);
    } else if (details[0] == ImageBosV2ActionBlindWatermark) {
      ret = parseActionBlindWatermark(details, result);
    } else {
      dout(10) << __func__ << "() unsupport image action:" << details[0] << dendl;
      return -EINVAL;
    }
    if (ret < 0) {
      return ret;
    }
  }
  return 0;
}

int ImageProcess::parseActionResize(std::vector<std::string>& details, vector<std::shared_ptr<ImageBase>>& result) {
  auto scale = std::make_shared<ImageScale>();

  for (uint32_t i = 1; i < details.size(); i++) {
    std::vector<std::string> kvs;
    boost::split(kvs, details[i], boost::is_any_of("_"));
    if (kvs.size() != 2) {
      dout(20) << __func__ << "() invalid param:" << details[i] << dendl;
      return -EINVAL;
    }

    if (kvs[0] == "m") {
      auto iter = imageBosV2ResizeMode.find(kvs[1]);
      if (iter != imageBosV2ResizeMode.end()) {
        scale->scale = iter->second;
      } else {
        dout(20) << __func__ << "() unsupport resize mode:" << kvs[1] << dendl;
        return -EINVAL;
      }
    } else if (kvs[0] == "p") {
      if (convert_to_int(kvs[1], scale->percentage, ImagePercentageMin, ImagePercentageMax) < 0) {
        return -EINVAL;
      }
    } else if (kvs[0] == "w") {
      if (convert_to_int(kvs[1], scale->width, ImageOutputWidthMin, ImageOutputWidthMax) < 0) {
        return -EINVAL;
      }
    } else if (kvs[0] == "h") {
      if (convert_to_int(kvs[1], scale->height, ImageOutputHeightMin, ImageOutputHeightMax) < 0) {
        return -EINVAL;
      }
    } else if (kvs[0] == "wp") {
      if (convert_to_int(kvs[1], scale->widthPercentage, ImagePercentageMin, ImagePercentageMax) < 0) {
        return -EINVAL;
      }
    } else if (kvs[0] == "hp") {
      if (convert_to_int(kvs[1], scale->heightPercentage, ImagePercentageMin, ImagePercentageMax) < 0) {
        return -EINVAL;
      }
    } else if (kvs[0] == "l") {
      if (convert_to_int(kvs[1], scale->longEdge, ImageOutputWidthMin, ImageOutputWidthMax) < 0) {
        return -EINVAL;
      }
    } else if (kvs[0] == "s") {
      if (convert_to_int(kvs[1], scale->shortEdge, ImageOutputWidthMin, ImageOutputWidthMax) < 0) {
        return -EINVAL;
      }
    } else if (kvs[0] == "limit") {
      if (convert_to_int(kvs[1], scale->limit, 0, 1) < 0) {
        return -EINVAL;
      }
    } else if (kvs[0] == "color") {
      scale->color = kvs[1];
    } else if (kvs[0] == "align") {
      if (convert_to_int(kvs[1], scale->align, 0, 100) < 0) {
        return -EINVAL;
      }
    } else {
      dout(10) << __func__ << "() invalid color value:" << kvs[0] << dendl;
      return -EINVAL;
    }
  }

  if (scale->scale == ImageResizeModeFixed || scale->scale == ImageResizeModeFill) {
    if (scale->width == -1 || scale->height == -1) {
      dout(20) << __func__ << "() width and height can't be empty when fixed or fill mode" << dendl;
      return -EINVAL;
    }
    if (scale->percentage > 0 || scale->widthPercentage > 0 || scale->heightPercentage > 0) {
      dout(20) << __func__ << "() width, height percentage or percentage must be empty" << dendl;
      return -EINVAL;
    }
  } else {
    if (scale->percentage != -1) {
      if (scale->width != -1 || scale->height != -1 || scale->longEdge != -1
          || scale->shortEdge != -1 || scale->widthPercentage != -1 || scale->heightPercentage != -1) {
        dout(20) << __func__ << "() when provide percentage, can't provide scale/width/height/long/short/widthPercentage/heightPercentage" << dendl;
        return -EINVAL;
      }
    } else if (scale->widthPercentage > 0 || scale->heightPercentage > 0) {
      if (scale->width != -1 || scale->height != -1 || scale->shortEdge != -1
          || scale->longEdge != -1) {
        dout(20) << __func__ << "() when provide percentage, can't provide scale/width/height/long/short" << dendl;
        return -EINVAL;
      }
    } else if (scale->longEdge != -1 || scale->shortEdge != -1) {
      if (scale->width != -1 || scale->height != -1) {
        dout(20) << __func__ << "() when provide long/short edge, can't provide width/height" << dendl;
        return -EINVAL;
      }
    } else if (scale->width == -1 && scale->height == -1) {
        dout(20) << __func__ << "() width and height both empty" << dendl;
        return -EINVAL;
    }
  }

  if (!scale->color.empty()) {
    if (scale->scale != ImageResizeModePad) {
      dout(20) << __func__ << "() width and height can't be empty when fixed or fill mode" << dendl;
      return -EINVAL;
    }
  }

  result.emplace_back(scale);
  return 0;
}

int ImageProcess::parseActionCrop(std::vector<std::string>& details, vector<std::shared_ptr<ImageBase>>& result) {
  auto crop = std::make_shared<ImageCrop>();

  for (uint32_t i = 1; i < details.size(); i++) {
    std::vector<std::string> kvs;
    boost::split(kvs, details[i], boost::is_any_of("_"));
    if (kvs.size() != 2) {
      dout(20) << __func__ << "() invalid param:" << details[i] << dendl;
      return -EINVAL;
    }

    if (kvs[0] == "w") {
      if (convert_to_int(kvs[1], crop->width, ImageOutputWidthMin, ImageOutputWidthMax) < 0) {
        return -EINVAL;
      }
    } else if (kvs[0] == "h") {
      if (convert_to_int(kvs[1], crop->height, ImageOutputHeightMin, ImageOutputHeightMax) < 0) {
        return -EINVAL;
      }
    } else if (kvs[0] == "x") {
      if (convert_to_int(kvs[1], crop->offsetX, 0, ImageInputWidthMax) < 0) {
        return -EINVAL;
      }
    } else if (kvs[0] == "y") {
      if (convert_to_int(kvs[1], crop->offsetY, 0, ImageInputHeightMax) < 0) {
        return -EINVAL;
      }
    }else if (kvs[0] == "g") {
      if (convert_to_int(kvs[1], crop->gravity, ImageWmGravityMin, ImageWmGravityMax) < 0) {
        return -EINVAL;
      }
    } else {
      dout(10) << __func__ << "() unsupport key:" << kvs[0] << dendl;
      return -EINVAL;
    }
  }
  result.emplace_back(crop);
  return 0;
}

int ImageProcess::parseActionRoundedCorners(std::vector<std::string>& details, vector<std::shared_ptr<ImageBase>>& result) {
  auto crop = std::make_shared<CropRoundRectOperation>();

  for (uint32_t i = 1; i < details.size(); i++) {
    std::vector<std::string> kvs;
    boost::split(kvs, details[i], boost::is_any_of("_"));
    if (kvs.size() != 2) {
      dout(20) << __func__ << "() invalid param:" << details[i] << dendl;
      return -EINVAL;
    }

    if (kvs[0] == "r") {
      if (convert_to_int(kvs[1], crop->radius, ImageOutputRadiusMin, ImageOutputRadiusMax) < 0) {
        return -EINVAL;
      }
    } else {
      dout(10) << __func__ << "() unsupport key:" << kvs[0] << dendl;
      return -EINVAL;
    }
  }

  result.emplace_back(crop);
  return 0;
}

int ImageProcess::parseActionBlur(std::vector<std::string>& details, vector<std::shared_ptr<ImageBase>>& result) {
  auto blur = std::make_shared<BlurOperation>();

  for (uint32_t i = 1; i < details.size(); i++) {
    std::vector<std::string> kvs;
    boost::split(kvs, details[i], boost::is_any_of("_"));
    if (kvs.size() != 2) {
      dout(20) << __func__ << "() invalid param:" << details[i] << dendl;
      return -EINVAL;
    }

    if (kvs[0] == "r") {
      if (convert_to_int(kvs[1], blur->radius, ImageBlurRadiusMin, ImageBlurRadiusMax) < 0) {
        return -EINVAL;
      }
    } else if (kvs[0] == "s") {
      if (convert_to_int(kvs[1], blur->sigma, ImageBlurSigmaMin, ImageBlurSigmaMax) < 0) {
        return -EINVAL;
      }
    } else {
      dout(20) << __func__ << "() unsupport key:" << kvs[0] << dendl;
      return -EINVAL;
    }
  }
  if (blur->radius == -1 || blur->sigma == -1) {
    dout(20) << __func__ << "() radius and sigma can't be empty" << dendl;
    return -EINVAL;
  }

  result.emplace_back(blur);
  return 0;
}

int ImageProcess::parseActionBright(std::vector<std::string>& details, vector<std::shared_ptr<ImageBase>>& result) {
  auto bright = std::make_shared<BrightOperation>();

  for (uint32_t i = 1; i < details.size(); i++) {
    std::vector<std::string> kvs;
    boost::split(kvs, details[i], boost::is_any_of("_"));
    if (kvs.size() != 2) {
      dout(20) << __func__ << "() invalid param:" << details[i] << dendl;
      return -EINVAL;
    }

    if (kvs[0] == "b") {
      if (convert_to_int(kvs[1], bright->bright, ImageBrightMin, ImageBrightMax) < 0) {
        return -EINVAL;
      }
    } else {
      dout(20) << __func__ << "() unsupport key:" << kvs[0] << dendl;
      return -EINVAL;
    }
  }

  result.emplace_back(bright);
  return 0;
}

int ImageProcess::parseActionSharpen(std::vector<std::string>& details, vector<std::shared_ptr<ImageBase>>& result) {
  auto sharpen = std::make_shared<SharpenOperation>();

  for (uint32_t i = 1; i < details.size(); i++) {
    std::vector<std::string> kvs;
    boost::split(kvs, details[i], boost::is_any_of("_"));
    if (kvs.size() != 2) {
      dout(20) << __func__ << "() invalid param:" << details[i] << dendl;
      return -EINVAL;
    }

    if (kvs[0] == "r") {
      if (convert_to_int(kvs[1], sharpen->radius, ImageSharpenRadiusMin, ImageSharpenRadiusMax) < 0) {
        return -EINVAL;
      }
    } else if (kvs[0] == "s") {
      if (convert_to_int(kvs[1], sharpen->sigma, ImageSharpenSigmaMin, ImageSharpenSigmaMax) < 0) {
        return -EINVAL;
      }
    } else {
      dout(20) << __func__ << "() unsupport key:" << kvs[0] << dendl;
      return -EINVAL;
    }
  }
  if (sharpen->radius == -1 || sharpen->sigma == -1) {
    dout(20) << __func__ << "() radius and sigma can't be empty" << dendl;
    return -EINVAL;
  }

  result.emplace_back(sharpen);
  return 0;
}

int ImageProcess::parseActionCircle(std::vector<std::string>& details, vector<std::shared_ptr<ImageBase>>& result) {
  auto crop = std::make_shared<CropCircleOperation>();

  for (uint32_t i = 1; i < details.size(); i++) {
    std::vector<std::string> kvs;
    boost::split(kvs, details[i], boost::is_any_of("_"));
    if (kvs.size() != 2) {
      dout(20) << __func__ << "() invalid param:" << details[i] << dendl;
      return -EINVAL;
    }

    if (kvs[0] == "r") {
      if (convert_to_int(kvs[1], crop->radius, ImageOutputRadiusMin, ImageOutputRadiusMax) < 0) {
        return -EINVAL;
      }
    } else {
      dout(20) << __func__ << "() unsupport key:" << kvs[0] << dendl;
      return -EINVAL;
    }
  }

  result.emplace_back(crop);
  return 0;
}

int ImageProcess::parseActionRotate(std::vector<std::string>& details, vector<std::shared_ptr<ImageBase>>& result) {
  auto scale = std::make_shared<ImageScale>();

  for (uint32_t i = 1; i < details.size(); i++) {
    std::vector<std::string> kvs;
    boost::split(kvs, details[i], boost::is_any_of("_"));
    if (kvs.size() != 2) {
      dout(20) << __func__ << "() invalid param:" << details[i] << dendl;
      return -EINVAL;
    }

    if (kvs[0] == "a") {
      if (convert_to_int(kvs[1], scale->angle, ImageOutputAngleMin, ImageOutputAngleMax) < 0) {
        return -EINVAL;
      }
    } else {
      dout(20) << __func__ << "() unsupport key:" << kvs[0] << dendl;
      return -EINVAL;
    }
  }

  result.emplace_back(scale);
  return 0;
}

int ImageProcess::parseActionAutoOrient(std::vector<std::string>& details, vector<std::shared_ptr<ImageBase>>& result) {
  auto scale = std::make_shared<ImageScale>();

  for (uint32_t i = 1; i < details.size(); i++) {
    std::vector<std::string> kvs;
    boost::split(kvs, details[i], boost::is_any_of("_"));
    if (kvs.size() != 2) {
      dout(20) << __func__ << "() invalid param:" << details[i] << dendl;
      return -EINVAL;
    }

    if (kvs[0] == "o") {
      if (convert_to_int(kvs[1], scale->orientation, 0, 1) < 0) {
        return -EINVAL;
      }
    } else {
      dout(20) << __func__ << "() unsupport key:" << kvs[0] << dendl;
      return -EINVAL;
    }
  }

  result.emplace_back(scale);
  return 0;
}

int ImageProcess::parseActionFormat(std::vector<std::string>& details,
                                    vector<std::shared_ptr<ImageBase>>& result) {
  static unordered_map<std::string, bool> supported_format = {
    {"jpg", true},
    {"jpeg", true},
    {"png", true},
    {"bmp", true},
    {"gif", true},
    {"webp", true},
    {"heic", true},
    {"auto", true},
  };

  auto scale = std::make_shared<ImageScale>();

  for (uint32_t i = 1; i < details.size(); i++) {
    std::vector<std::string> kvs;
    boost::split(kvs, details[i], boost::is_any_of("_"));
    if (kvs.size() != 2) {
      dout(20) << __func__ << "() invalid param:" << details[i] << dendl;
      return -EINVAL;
    }

    if (kvs[0] == "f") {
      if (supported_format.find(kvs[1]) == supported_format.end()) {
        dout(20) << __func__ << "() unsupport format value:" << kvs[1] << dendl;
        return -EINVAL;
      }

      // auto format must work with ACCEPT header, and webp in this header specifically
      // or, jump this command.
      // Meanwhile, need Vary: Accept in response header
      if (kvs[1].compare("auto") == 0) {
        if (op) {
          bufferlist bl;
          string val = "Accept";
          bl.append(val.c_str(), val.length());
          static_cast<RGWGetObj*>(op)->attrs[RGW_ATTR_VARY] = bl;
        }
        string accept = s->info.env->get("HTTP_ACCEPT", "");
        if (accept.length() != 0) {
          if (accept.find("webp") == string::npos) {
            // without webp, use default format
            return 0;
          }
          kvs[1] = "webp";
        } else {
          return 0;
        }
      }

      scale->format = kvs[1];
      const char *mime = rgw_find_mime_by_ext(kvs[1]);
      if (mime) {
        s->explicit_content_type = mime;
      } else {
        s->explicit_content_type = "image/" + kvs[1];
      }
    } else {
      dout(20) << __func__ << "() unsupport key:" << kvs[0] << dendl;
      return -EINVAL;
    }
  }

  result.emplace_back(scale);
  return 0;
}

int ImageProcess::parseActionQuality(std::vector<std::string>& details, vector<std::shared_ptr<ImageBase>>& result) {
  auto scale = std::make_shared<ImageScale>();

  int32_t abs_quality = -1;
  int32_t quality_flags = 0;

  for (uint32_t i = 1; i < details.size(); i++) {
    std::vector<std::string> kvs;
    boost::split(kvs, details[i], boost::is_any_of("_"));
    if (kvs.size() != 2) {
      dout(20) << __func__ << "() invalid param:" << details[i] << dendl;
      return -EINVAL;
    }

    if (kvs[0] == "q") {
      if (convert_to_int(kvs[1], scale->quality, ImageQualityMin, ImageQualityMax) < 0) {
        return -EINVAL;
      }
    } else if (kvs[0] == "Q") {
      if (convert_to_int(kvs[1], abs_quality, ImageQualityMin, ImageQualityMax) < 0) {
        return -EINVAL;
      }
    } else if (kvs[0] == "c") {
      if (kvs[1].compare("le") == 0) {
        quality_flags = QualityLess | QualityEqual;
      } else if (kvs[1].compare("ge") == 0) {
        quality_flags = QualityGreater | QualityEqual;
      } else if (kvs[1].compare("any") == 0) {
        quality_flags = QualityLess | QualityEqual | QualityGreater;
      } else {
        dout(20) << __func__ << "() unsupport flag:" << kvs[1] << dendl;
        return -EINVAL;
      }
    } else {
      dout(20) << __func__ << "() unsupport key:" << kvs[0] << dendl;
      return -EINVAL;
    }
  }

  if (quality_flags != 0 && abs_quality == -1) {
    dout(20) << __func__ << "() when condition is not null, absolute quality must exist" << dendl;
    return -EINVAL;
  }
  if (scale->quality > 0 && abs_quality > 0) {
    dout(20) << __func__ << "() q and Q are conflict" << dendl;
    return -EINVAL;
  }
  if (abs_quality > 0) {
    scale->quality = abs_quality;
    if (quality_flags != 0) {
      scale->flags |= quality_flags | QualityAbsolute;
    } else {
      // default le
      scale->flags |= QualityLess | QualityEqual | QualityAbsolute;
    }
  }

  result.emplace_back(scale);
  return 0;
}

int ImageProcess::parseActionWatermark(std::vector<std::string>& details,
                                       vector<std::shared_ptr<ImageBase>>& result) {
  string pic = "";
  string text = "";
  for (uint32_t i = 1; i < details.size(); i++) {
    std::vector<std::string> kvs;
    boost::split(kvs, details[i], boost::is_any_of("_"));
    if (kvs.size() != 2) {
      dout(20) << __func__ << "() invalid param:" << details[i] << dendl;
      return -EINVAL;
    }

    if (kvs[0] == "image") {
      pic = kvs[0];
    } else if (kvs[0] == "text") {
      text = kvs[0];
    }
  }
  if (!pic.empty() && !text.empty()) {
    return parseActionWatermarkMix(details, result);
  } else if (!pic.empty()) {
    return parseActionWatermarkImage(details, result);
  } else if (!text.empty()) {
    return parseActionWatermarkText(details, result);
  }
  return 0;
}

int ImageProcess::parseActionWatermarkImage(std::vector<std::string>& details,
                                 vector<std::shared_ptr<ImageBase>>& result) {
  auto pic_watermark = std::make_shared<ImageWatermarkPic>();

  string src_bucket_name = s->bucket.name;
  string src_key = "";

  for (uint32_t i = 1; i < details.size(); i++) {
    std::vector<std::string> kvs;
    boost::split(kvs, details[i], boost::is_any_of("_"));
    if (kvs.size() != 2) {
      dout(20) << __func__ << "() invalid param:" << details[i] << dendl;
      return -EINVAL;
    }

    if (kvs[0] == "text" || kvs[0] == "size" || kvs[0] == "color" ||
        kvs[0] == "type" || kvs[0] == "style" || kvs[0] == "image") {
      try {
        src_key = rgw::from_base64(kvs[1]);
      } catch (...) {
        ldout(s->cct, 5) << "ERROR: invalid param:" << src_key << dendl;
        return -EINVAL;
      }
    } else if (kvs[0] == "bucket") {
      src_bucket_name = kvs[1];
    } else if (kvs[0] == "t") {
      if (convert_to_int(kvs[1], pic_watermark->opacity, ImageWmOpacityMin, ImageWmOpacityMax) < 0) {
        return -EINVAL;
      }
    } else if (kvs[0] == "g") {
      if (convert_to_int(kvs[1], pic_watermark->gravity, ImageWmGravityMin, ImageWmGravityMax) < 0) {
        return -EINVAL;
      }
    } else if (kvs[0] == "x") {
      if (convert_to_int(kvs[1], pic_watermark->gravityX, -ImageOutputWidthMax, ImageOutputWidthMax) < 0) {
        return -EINVAL;
      }
    } else if (kvs[0] == "y") {
      if (convert_to_int(kvs[1], pic_watermark->gravityY, -ImageOutputHeightMax, ImageOutputHeightMax) < 0) {
        return -EINVAL;
      }
    } else if (kvs[0] == "a") {
      if (convert_to_int(kvs[1], pic_watermark->angle, ImageOutputAngleMin, ImageOutputAngleMax) < 0) {
        return -EINVAL;
      }
    } else {
      dout(20) << __func__ << "() unsupport key:" << kvs[0] << dendl;
      return -EINVAL;
    }
  }

  if (src_key.empty()) {
    dout(20) << __func__ << "() key empty" << dendl;
    return -EINVAL;
  }

  int ret = verify_object_permission(s, store, src_bucket_name, src_key,
                                     rgw::IAM::s3GetObject, RGW_PERM_READ);
  if (ret < 0) {
    dout(20) << __func__ << "() no permission to access src image:"
                         << src_bucket_name << "/" << src_key
                         << dendl;
    return -EINVAL;
  }


  pic_watermark->pic_url = generate_presigned_url(src_bucket_name, src_key);

  result.emplace_back(pic_watermark);
  return 0;
}

int ImageProcess::parseActionWatermarkText(std::vector<std::string>& details, vector<std::shared_ptr<ImageBase>>& result) {
  auto text_watermark = std::make_shared<ImageWatermarkText>();

  for (uint32_t i = 1; i < details.size(); i++) {
    std::vector<std::string> kvs;
    boost::split(kvs, details[i], boost::is_any_of("_"));
    if (kvs.size() != 2) {
      dout(20) << __func__ << "() invalid param:" << details[i] << dendl;
      return -EINVAL;
    }

    if (kvs[0] == "image" || kvs[0] == "bucket" || kvs[0] == "t" ||
        kvs[0] == "P" || kvs[0] == "text") {
      bufferlist bl;
      bufferlist temp;
      temp.append(kvs[1].c_str(), kvs[1].length());
      try {
        bl.decode_base64(temp);
      } catch (buffer::error& err) {
        ldout(s->cct, 20) << "failed to decode_base64:" << kvs[1] << dendl;
        return -EINVAL;
      }
      text_watermark->text = bl.to_str();
    } else if (kvs[0] == "type") {
      bufferlist bl;
      bufferlist temp;
      temp.append(kvs[1].c_str(), kvs[1].length());
      try {
        bl.decode_base64(temp);
      } catch (buffer::error& err) {
        ldout(s->cct, 20) << "failed to decode_base64:" << kvs[1] << dendl;
        return -EINVAL;
      }

      auto iter = font_map.find(boost::algorithm::to_lower_copy(bl.to_str()));
      if (iter == font_map.end()) {
        dout(20) << __func__ << "() unsupport font type:" << bl.to_str() << dendl;
        return -EINVAL;
      }
      text_watermark->fontFamily = iter->second;
    } else if (kvs[0] == "color") {
      if (kvs[1].length() != 6 && kvs[1].length() != 8) {
        dout(20) << __func__ << "() color invalid length:" << kvs[1] << dendl;
        return -EINVAL;
      }
      text_watermark->fontColor = kvs[1];
    } else if (kvs[0] == "style") {
      auto iter = font_style.find(boost::algorithm::to_lower_copy(kvs[1]));
      if (iter == font_style.end()) {
        dout(20) << __func__ << "() unsupport font style:" << kvs[1] << dendl;
      }
      text_watermark->fontStyle = kvs[1];
    } else if (kvs[0] == "size") {
      if (convert_to_int(kvs[1], text_watermark->fontSize, ImageWmTextSizeMin, ImageWmTextSizeMax) < 0) {
        return -EINVAL;
      }
    } else if (kvs[0] == "g") {
      if (convert_to_int(kvs[1], text_watermark->gravity, ImageWmGravityMin, ImageWmGravityMax) < 0) {
        return -EINVAL;
      }
    } else if (kvs[0] == "x") {
      if (convert_to_int(kvs[1], text_watermark->gravityX, -ImageOutputWidthMax, ImageOutputWidthMax) < 0) {
        return -EINVAL;
      }
    } else if (kvs[0] == "y") {
      if (convert_to_int(kvs[1], text_watermark->gravityY, -ImageOutputHeightMax, ImageOutputHeightMax) < 0) {
        return -EINVAL;
      }
    } else if (kvs[0] == "a") {
      if (convert_to_int(kvs[1], text_watermark->angle, ImageOutputAngleMin, ImageOutputAngleMax) < 0) {
        return -EINVAL;
      }
    } else {
      dout(20) << __func__ << "() unsupport key:" << kvs[0] << dendl;
      return -EINVAL;
    }
  }

  if (text_watermark->text.empty()) {
    dout(20) << __func__ << "() text watermark empty" << dendl;
    return -EINVAL;
  }

  result.emplace_back(text_watermark);
  return 0;
}

int ImageProcess::parseActionWatermarkMix(std::vector<std::string>& details,
                            vector<std::shared_ptr<ImageBase>>& result) {
  auto watermark = std::make_shared<WatermarkOperation>();
  watermark->align = WatermarkAlignBottom;

  string bucket = s->bucket.name;
  string key = "";

  for (uint32_t i = 1; i < details.size(); i++) {
    std::vector<std::string> kvs;
    boost::split(kvs, details[i], boost::is_any_of("_"));
    if (kvs.size() != 2) {
      dout(20) << __func__ << "() invalid param:" << details[i] << dendl;
      return -EINVAL;
    }

    if (kvs[0] == "text") {
      bufferlist bl;
      bufferlist temp;
      temp.append(kvs[1].c_str(), kvs[1].length());
      try {
        bl.decode_base64(temp);
      } catch (...) {
        ldout(s->cct, 5) << "ERROR: invalid params:" << kvs[1] << dendl;
        return -EINVAL;
      }
      watermark->text = bl.to_str();
    } else if (kvs[0] == "image") {
      try {
        key = rgw::from_base64(kvs[1]);
      } catch (...) {
        ldout(s->cct, 5) << "ERROR: invalid params:" << kvs[1] << dendl;
        return -EINVAL;
      }
    } else if (kvs[0] == "bucket") {
      bucket = kvs[1];
    } else if (kvs[0] == "type") {
      try {
        auto iter = font_map.find(boost::algorithm::to_lower_copy(
                                    rgw::from_base64(
                                      boost::string_view(kvs[1]))));
        if (iter == font_map.end()) {
          dout(20) << __func__ << "() unsupport font type:" << rgw::from_base64(boost::string_view(kvs[1])) << dendl;
          return -EINVAL;
        }
        watermark->fontFamily = iter->second;
      } catch (...) {
        ldout(s->cct, 5) << "ERROR: invalid params:" << kvs[1] << dendl;
        return -EINVAL;
      }
    } else if (kvs[0] == "color") {
      if (kvs[1].length() != 6 && kvs[1].length() != 8) {
        dout(20) << __func__ << "() color invalid length:" << kvs[1] << dendl;
        return -EINVAL;
      }
      watermark->fontColor = kvs[1];
    } else if (kvs[0] == "style") {
      auto iter = font_style.find(boost::algorithm::to_lower_copy(kvs[1]));
      if (iter == font_style.end()) {
        dout(20) << __func__ << "() unsupport font style:" << kvs[1] << dendl;
      }
      watermark->fontStyle = kvs[1];
    } else if (kvs[0] == "size") {
      if (convert_to_int(kvs[1], watermark->fontSize, ImageWmTextSizeMin, ImageWmTextSizeMax) < 0) {
        return -EINVAL;
      }
    } else if (kvs[0] == "t") {
      if (convert_to_int(kvs[1], watermark->opacity, ImageWmOpacityMin, ImageWmOpacityMax) < 0) {
        return -EINVAL;
      }
    } else if (kvs[0] == "g") {
      if (convert_to_int(kvs[1], watermark->gravity, ImageWmGravityMin, ImageWmGravityMax) < 0) {
        return -EINVAL;
      }
    } else if (kvs[0] == "x") {
      if (convert_to_int(kvs[1], watermark->gravityX, -ImageOutputWidthMax, ImageOutputWidthMax) < 0) {
        return -EINVAL;
      }
    } else if (kvs[0] == "y") {
      if (convert_to_int(kvs[1], watermark->gravityY, -ImageOutputHeightMax, ImageOutputHeightMax) < 0) {
        return -EINVAL;
      }
    } else if (kvs[0] == "a") {
      if (convert_to_int(kvs[1], watermark->angle, ImageOutputAngleMin, ImageOutputAngleMax) < 0) {
        return -EINVAL;
      }
    } /*else if (kvs[0] == "skw") {  // new version in timg, no support it temporary
      if (convert_to_int(kvs[1], watermark->strokeWidth, StrokeWidthMin, StrokeWidthMax) < 0) {
        return -EINVAL;
      }
    } else if (kvs[0] == "skc") {
      if (kvs[1].length() != 6 && kvs[1].length() != 8) {
        dout(20) << __func__ << "() invalid color value:" << kvs[0] << dendl;
        return -EINVAL;
      }
      watermark->strokeColor = kvs[1];
    }*/ else if (kvs[0] == "blr") {
      if (convert_to_int(kvs[1], watermark->blurRadius, BlurRadiusMin, BlurRadiusMax) < 0) {
        return -EINVAL;
      }
    } else if (kvs[0] == "bls") {
      if (convert_to_int(kvs[1], watermark->blurSigma, BlurSigmaMin, BlurSigmaMax) < 0) {
        return -EINVAL;
      }
    } else if (kvs[0] == "effect") {
      auto iter = effect_map.find(boost::algorithm::to_lower_copy(kvs[1]));
      if (iter == effect_map.end()) {
        dout(20) << __func__ << "() unsupport effect:" << kvs[1] << dendl;
      }
      watermark->effect = iter->second;
    } else if (kvs[0] == "shx") {
      if (convert_to_int(kvs[1], watermark->shadowX, ImageShadowMin, ImageShadowMax) < 0) {
        return -EINVAL;
      }
    } else if (kvs[0] == "shy") {
      if (convert_to_int(kvs[1], watermark->shadowY, ImageShadowMin, ImageShadowMax) < 0) {
        return -EINVAL;
      }
    } else if (kvs[0] == "order") {
      if (convert_to_int(kvs[1], watermark->order, WatermarkOrderMin, WatermarkOrderMax) < 0) {
        return -EINVAL;
      }
    } else if (kvs[0] == "align") {
      int32_t a = 2;
      if (convert_to_int(kvs[1], a, WatermarkAlignMin, WatermarkAlignMax) < 0) {
        return -EINVAL;
      }
      watermark->align = align_map[a];
    } else if (kvs[0] == "interval") {
      if (convert_to_int(kvs[1], watermark->interval, WatermarkIntervalMin, WatermarkIntervalMax) < 0) {
        return -EINVAL;
      }
    } else {
      dout(20) << __func__ << "() unsupport key:" << kvs[0] << dendl;
      return -EINVAL;
    }
  }

  if (key.empty() || watermark->text.empty()) {
    dout(20) << __func__ << "() key or text empty" << dendl;
    return -EINVAL;
  }

  watermark->pic_url = generate_presigned_url(bucket, key);

  result.emplace_back(watermark);
  return 0;
}

int ImageProcess::parseActionBlindWatermark(std::vector<std::string>& details,
                                            vector<std::shared_ptr<ImageBase>>& result) {
  auto blind = std::make_shared<BlindWatermark>();

  string bucket_name = s->bucket.name;
  string image = "";

  for (uint32_t i = 1; i < details.size(); i++) {
    std::vector<std::string> kvs;
    boost::split(kvs, details[i], boost::is_any_of("_"));
    if (kvs.size() != 2) {
      dout(20) << __func__ << "() invalid param:" << details[i] << dendl;
      return -EINVAL;
    }

    if (kvs[0] == "method") {
      if (kvs[1].compare("extract") == 0) {
        blind->type = ImageBOSExtractBlindWatermark;
      } else if (kvs[1].compare("embed") == 0) {
        blind->type = ImageBOSEmbedBlindWatermark;
      } else {
        ldout(s->cct, 5) << "ERROR: invalid method param:" << kvs[1] << dendl;
        return -EINVAL;
      }
    } else if (kvs[0] == "mode") {
      if (convert_to_int(kvs[1], blind->mode, 0, 1) < 0) {
        return -EINVAL;
      }
    } else if (kvs[0] == "bucket") {
      bucket_name = kvs[1];
    } else if (kvs[0] == "image") {
      try {
        image = rgw::from_base64(kvs[1]);
      } catch (...) {
        ldout(s->cct, 5) << "ERROR: invalid param:" << kvs[1] << dendl;
        return -EINVAL;
      }
    } else if (kvs[0] == "text") {
      bufferlist bl;
      bufferlist temp;
      temp.append(kvs[1].c_str(), kvs[1].length());
      try {
        bl.decode_base64(temp);
      } catch (buffer::error& err) {
        ldout(s->cct, 20) << "failed to decode_base64:" << kvs[1] << dendl;
        return -EINVAL;
      }
      blind->text = rgw_bl_to_str(bl);
    }
  }

  if (!image.empty()) {
    int ret = verify_object_permission(s, store, bucket_name, image,
                                       rgw::IAM::s3GetObject, RGW_PERM_READ);
    if (ret < 0) {
      dout(20) << __func__ << "() no permission to access src image:"
                           << bucket_name << "/" << image
                           << dendl;
      return -EINVAL;
    }
    blind->pic_url = generate_presigned_url(bucket_name, image);
  }

  if (blind->type.compare(ImageBOSExtractBlindWatermark) == 0 && blind->mode == 1) {
    s->explicit_content_type = CONTENT_TYPE_JSON;
  }

  result.emplace_back(blind);
  return 0;
}

void ImageScale::dump(Formatter* f) const {
  f->open_object_section("");
  f->dump_string("type", type);
  if (scale > 0) {
    f->dump_int("scale", scale);
  }
  if (width > 0) {
    f->dump_int("width", width);
  }
  if (height > 0) {
    f->dump_int("height", height);
  }
  if (quality >= 0) {
    f->dump_int("quality", quality);
  }
  // flags ???
  if (flags != 0) {
    f->dump_int("flags", flags);
  }
  if (!format.empty()) {
    f->dump_string("format", format);
  }
  if (angle < 361) {
    f->dump_int("angle", angle);
  }
  if (limit >= 0) {
    f->dump_int("limit", limit);
  }
  if (orientation >= 0) {
    f->dump_int("orientation", orientation);
  }
  if (!color.empty()) {
    f->dump_string("color", color);
  }
  if (percentage > 0) {
    f->dump_int("percentage", percentage);
  }
  if (align > 0) {
    f->dump_int("align", align);
    f->dump_int("anchor", align);  // Deprecated, instead of Align
  }
  if (longEdge > 0) {
    f->dump_int("long_edge", longEdge);
  }
  if (shortEdge > 0) {
    f->dump_int("short_edge", shortEdge);
  }
  if (widthPercentage > 0) {
    f->dump_int("width_percentage", widthPercentage);
  }
  if (heightPercentage > 0) {
    f->dump_int("heightPercentage", heightPercentage);
  }
  f->close_section();
}

void ImageCrop::dump(Formatter* f) const {
  f->open_object_section("");
  f->dump_string("type", type);
  if (width > 0) {
    f->dump_int("width", width);
  }
  if (height > 0) {
    f->dump_int("height", height);
  }
  // proxy doesn't allow camelcase
  if (offsetX >= 0) {
    f->dump_int("offset_x", offsetX);
  }
  if (offsetY >= 0) {
    f->dump_int("offset_y", offsetY);
  }
  f->dump_int("gravity", gravity);
  f->close_section();
}

void CropRoundRectOperation::dump(Formatter* f) const {
  f->open_object_section("");
  f->dump_string("type", type);
  if (radius > 0) {
    f->dump_int("radius", radius);
  }
  f->close_section();
}

void BlurOperation::dump(Formatter* f) const {
  f->open_object_section("");
  f->dump_string("type", type);
  if (radius != -1) {
    f->dump_int("radius", radius);
  }
  if (sigma != -1) {
    f->dump_int("sigma", sigma);
  }
  f->close_section();
}

void BrightOperation::dump(Formatter* f) const {
  f->open_object_section("");
  f->dump_string("type", type);
  if (bright <= ImageBrightMax ) {
    f->dump_int("bright", bright);
  }
  f->close_section();
}

void SharpenOperation::dump(Formatter* f) const {
  f->open_object_section("");
  f->dump_string("type", type);
  if (radius != -1) {
    f->dump_int("radius", radius);
  }
  if (sigma != -1) {
    f->dump_int("sigma", sigma);
  }
  f->close_section();
}

void CropCircleOperation::dump(Formatter* f) const {
  f->open_object_section("");
  f->dump_string("type", type);
  if (radius > 0) {
    f->dump_int("radius", radius);
  }
  f->close_section();
}

void ImageWatermarkPic::dump(Formatter* f) const {
  f->open_object_section("");
  f->dump_string("type", type);
  f->dump_string("pic_url", pic_url);
  if (opacity > 0) {
    f->dump_int("opacity", opacity);
  }
  if (gravity > 0) {
    f->dump_int("gravity", gravity);
  }
  f->dump_int("gravity_x", gravityX);
  f->dump_int("gravity_y", gravityY);
  if (angle < 361) {
    f->dump_int("angle", angle);
  }
  f->close_section();
}

void ImageWatermarkText::dump(Formatter* f) const {
  f->open_object_section("");
  f->dump_string("type", type);
  f->dump_string("text", text);
  if (fontSize > 0) {
    f->dump_int("font_size", fontSize);
  }
  if (!fontColor.empty()) {
    f->dump_string("font_color", fontColor);
  }
  if (!fontFamily.empty()) {
    f->dump_string("font_family", fontFamily);
  }
  if (!fontStyle.empty()) {
    f->dump_string("font_style", fontStyle);
  }
  if (gravity > 0) {
    f->dump_int("gravity", gravity);
  }
  f->dump_int("gravity_x", gravityX);
  f->dump_int("gravity_y", gravityY);
  if (angle < 361) {
    f->dump_int("angle", angle);
  }
  f->close_section();
}

void WatermarkOperation::dump(Formatter* f) const {
  f->open_object_section("");
  f->dump_string("type", type);
  f->dump_string("pic_url", pic_url);
  if (opacity > 0) {
    f->dump_int("opacity", opacity);
  }
  f->dump_string("text", text);
  if (fontSize > 0) {
    f->dump_int("font_size", fontSize);
  }
  if (!fontColor.empty()) {
    f->dump_string("font_color", fontColor);
  }
  if (!fontFamily.empty()) {
    f->dump_string("font_family", fontFamily);
  }
  if (!fontStyle.empty()) {
    f->dump_string("font_style", fontStyle);
  }
  if (gravity > 0) {
    f->dump_int("gravity", gravity);
  }
  f->dump_int("gravity_x", gravityX);
  f->dump_int("gravity_y", gravityY);
  if (angle < 361) {
    f->dump_int("angle", angle);
  }
  if (blurRadius != 0) {
    f->dump_int("blur_radius", blurRadius);
  }
  if (blurSigma != 0) {
    f->dump_int("blur_sigma", blurSigma);
  }
  if (effect != 0) {
    f->dump_int("effect", effect);
  }
  if (shadowX != 0) {
    f->dump_int("shadow_x", shadowX);
  }
  if (shadowY != 0) {
    f->dump_int("shadow_y", shadowY);
  }
  if (order != 0) {
    f->dump_int("order", order);
  }
  f->dump_int("align", align);
  if (interval != 0) {
    f->dump_int("interval", order);
  }
  f->close_section();
}

void BlindWatermark::dump(Formatter* f) const {
  f->open_object_section("");
  f->dump_string("type", type);
  f->dump_int("mode", mode);
  if (!pic_url.empty()) {
    f->dump_string("pic_url", pic_url);
  }
  if (!text.empty()) {
    f->dump_string("text", text);
  }
  f->close_section();
}
