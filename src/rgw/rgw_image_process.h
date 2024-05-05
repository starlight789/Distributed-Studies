#ifndef CEPH_RGW_IMAGE_PROCESS_H
#define CEPH_RGW_IMAGE_PROCESS_H

#include <vector>
#include <string>
#include <sstream>
#include <algorithm>
#include <iostream>

#include "rgw_common.h"

#define dout_context g_ceph_context
#define dout_subsys ceph_subsys_rgw

#define ImageOffsetXDefault 10
#define ImageOffsetYDefault 10

#define WatermarkAlignTop 4
#define WatermarkAlignMiddle 5
#define WatermarkAlignBottom 6

#define  ImageBrightMin -100
#define  ImageBrightMax 100

class RGWGetObj;
class RGWImageStyle {
public:
  string name;
  string command;
  ceph::real_time t;

  void encode(bufferlist& bl) const {
    ENCODE_START(1, 1, bl);
    ceph::encode(name, bl);
    ceph::encode(command, bl);
    ceph::encode(t, bl);
    ENCODE_FINISH(bl);
  }

  void decode(bufferlist::iterator& bl) {
    DECODE_START_LEGACY_COMPAT_LEN_32(1, 1, 1, bl);
    ceph::decode(name, bl);
    ceph::decode(command, bl);
    ceph::decode(t, bl);
    DECODE_FINISH(bl);
  }

  RGWImageStyle() : name(""), command("") {}
  RGWImageStyle(string name, string command) :
    name(name), command(command), t(ceph::real_clock::now()) {}
};
WRITE_CLASS_ENCODER(RGWImageStyle)

class ImageBase {
public:
  string type;
  ImageBase() = default;
  virtual ~ImageBase() = default;

  virtual void dump(Formatter* f) const = 0;
};

class ImageScale : public ImageBase {
public:
  int32_t scale = 0;
  int32_t width = -1;
  int32_t height = -1;
  int32_t quality = -1;
  int32_t flags = 0;
  string format;
  int32_t angle = 361;
  int32_t limit = -1;
  int32_t orientation = -1;
  string color;
  int32_t align = -1;
  int32_t percentage = -1;
  int32_t longEdge = -1;
  int32_t shortEdge = -1;
  int32_t widthPercentage = -1;
  int32_t heightPercentage = -1;

  ImageScale() {
    type = "scale";
  }
  ~ImageScale() override {}

  void dump(Formatter* f) const override;
};

class ImageCrop : public ImageBase {
public:
  int32_t width = -1;
  int32_t height = -1;
  int32_t offsetX = -1;
  int32_t offsetY = -1;
  int32_t gravity = 1; // default: 1, pass it to timg always

  ImageCrop() {
    type = "crop";
  }
  ~ImageCrop() override {}

  void dump(Formatter* f) const override;
};

class CropRoundRectOperation : public ImageBase {
public:
  int32_t radius = -1;

  CropRoundRectOperation() {
    type = "crop-roundrect";
  }
  ~CropRoundRectOperation() override {}

  void dump(Formatter* f) const override;
};

class CropCircleOperation : public ImageBase {
public:
  int32_t radius = -1;

  CropCircleOperation() {
    type = "crop-circle";
  }
  ~CropCircleOperation() override {}

  void dump(Formatter* f) const override;
};

class BlurOperation : public ImageBase {
public:
  int32_t radius = -1;
  int32_t sigma = -1;

  BlurOperation() {
    type = "blur";
  }
  ~BlurOperation() override {}

  void dump(Formatter* f) const override;
};

class BrightOperation : public ImageBase {
public:
  int32_t bright = ImageBrightMax + 1;

  BrightOperation() {
    type = "bright";
  }
  ~BrightOperation() override {}

  void dump(Formatter* f) const override;
};

class SharpenOperation : public ImageBase {
public:
  int32_t radius = -1;
  int32_t sigma = -1;

  SharpenOperation() {
    type = "sharpen";
  }
  ~SharpenOperation() override {}

  void dump(Formatter* f) const override;
};

class ImageWatermark : public ImageBase {
public:
  int32_t gravity = -1;
  int32_t gravityX = ImageOffsetXDefault;
  int32_t gravityY = ImageOffsetYDefault;
  int32_t angle = 361;

};

class ImageWatermarkPic : public ImageWatermark {
public:
  string pic_url;
  int32_t opacity = -1;

  ImageWatermarkPic() {
    type = "picWatermark";
  }
  ~ImageWatermarkPic() override {}

  void dump(Formatter* f) const override;
};

class ImageWatermarkText : public ImageWatermark {
public:
  string text = "";
  string fontFamily = "";
  int32_t fontSize = -1;
  string fontStyle = "";
  string fontColor = "";

  ImageWatermarkText() {
    type = "textWatermark";
  }
  ~ImageWatermarkText() override {}

  void dump(Formatter* f) const override;
};

class BlindWatermark : public ImageBase {
public:
  int32_t mode;
  string pic_url = "";
  string text = "";

  BlindWatermark() {}
  ~BlindWatermark() override {}

  void dump(Formatter* f) const override;
};

class WatermarkOperation : public ImageWatermark {
public:
  string pic_url;
  int32_t opacity = -1;

  string text = "";
  string fontFamily = "";
  int32_t fontSize = -1;
  string fontStyle = "";
  string fontColor = "";

  int32_t angle = 361;
  int32_t blurRadius = 0;
  int32_t blurSigma = 0;
  int32_t effect = 0;
  int32_t shadowX = 0;
  int32_t shadowY = 0;
  int32_t order = 0;
  int32_t align;
  int32_t interval = 0;

  WatermarkOperation() {
    type = "watermark";
  }
  ~WatermarkOperation() override {}

  void dump(Formatter* f) const override;
};

class ImageProcess {
private:
  req_state* s;
  RGWRados* store;
  void* op;

  int parseActionResize(std::vector<std::string>& details,
                        vector<std::shared_ptr<ImageBase>>& result);

  int parseActionCrop(std::vector<std::string>& details,
                      vector<std::shared_ptr<ImageBase>>& result);

  int parseActionRoundedCorners(std::vector<std::string>& details,
                                vector<std::shared_ptr<ImageBase>>& result);

  int parseActionCircle(std::vector<std::string>& details,
                        vector<std::shared_ptr<ImageBase>>& result);

  int parseActionRotate(std::vector<std::string>& details,
                        vector<std::shared_ptr<ImageBase>>& result);

  int parseActionAutoOrient(std::vector<std::string>& details,
                            vector<std::shared_ptr<ImageBase>>& result);

  int parseActionFormat(std::vector<std::string>& details,
                        vector<std::shared_ptr<ImageBase>>& result);

  int parseActionQuality(std::vector<std::string>& details,
                         vector<std::shared_ptr<ImageBase>>& result);

  int parseActionBlur(std::vector<std::string>& details,
                      vector<std::shared_ptr<ImageBase>>& result);

  int parseActionBright(std::vector<std::string>& details,
                        vector<std::shared_ptr<ImageBase>>& result);

  int parseActionSharpen(std::vector<std::string>& details,
                         vector<std::shared_ptr<ImageBase>>& result);


  int parseActionWatermark(std::vector<std::string>& details,
                           vector<std::shared_ptr<ImageBase>>& result);

  int parseActionWatermarkImage(std::vector<std::string>& details,
                                vector<std::shared_ptr<ImageBase>>& result);

  int parseActionWatermarkText(std::vector<std::string>& details,
                               vector<std::shared_ptr<ImageBase>>& result);

  int parseActionWatermarkMix(std::vector<std::string>& details,
                              vector<std::shared_ptr<ImageBase>>& result);

  int parseActionBlindWatermark(std::vector<std::string>& details,
                                vector<std::shared_ptr<ImageBase>>& result);

  string generate_presigned_url(const std::string& bucket, const std::string& object);

public:
  ImageProcess(req_state* _s, RGWRados* _store, void* _op) : s(_s), store(_store), op(_op) {}

  int parse_commands(std::vector<std::string>& actions,
                     uint8_t start,
                     vector<std::shared_ptr<ImageBase>>& result);

  void generate_timg_body(std::vector<std::shared_ptr<ImageBase>>& timg_cmds,
                          std::string& result);
};

#endif /* CEPH_RGW_IMAGE_PROCESS_H */
