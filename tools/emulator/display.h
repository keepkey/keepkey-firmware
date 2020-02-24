#ifndef TOOLS_EMULATOR_DISPLAY_H
#define TOOLS_EMULATOR_DISPLAY_H

#include <memory>
#include <cinttypes>

struct KKDisplay {
  virtual void setPixel(int x, int y, uint8_t r, uint8_t g, uint8_t b) = 0;
  virtual void swapOnVSync() = 0;

  static KKDisplay *CreateMatrix();
};

#endif
