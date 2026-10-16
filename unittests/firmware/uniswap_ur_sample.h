// 1,000 consecutive execute() calls to the Base Universal Router the Uniswap
// app sends to (0xd6145b2D3F379919E8CdEda7B97e37c4b2Ca9c40, UR 2.1.2, all
// callers, base.blockscout.com 2026-10-04): the D-021 sample. Packed by
// scripts/uniswap/gen_ur_vectors.py pack; scripts/uniswap/v4_classify.py
// reproduces the D-021 counts from the same file.
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>
namespace urs {
struct Call {
  std::string tx;
  bool ok;  // status on chain
  std::vector<uint8_t> value;  // msg.value, 32 bytes big-endian
  std::vector<uint8_t> calldata;
};
// Records: hash(32) | status(1) | msg.value(32) | length(4, big-endian) |
// calldata.
inline const std::vector<Call>& calls() {
  static std::vector<Call> v;
  if (!v.empty()) return v;
  FILE* f = fopen(UR_SAMPLE_PATH, "rb");
  if (!f) return v;
  std::vector<uint8_t> b;
  uint8_t buf[4096];
  size_t n;
  while ((n = fread(buf, 1, sizeof(buf), f)) > 0) b.insert(b.end(), buf, buf + n);
  fclose(f);
  static const char* d = "0123456789abcdef";
  for (size_t i = 0; i + 69 <= b.size();) {
    Call c;
    c.tx = "0x";
    for (size_t k = 0; k < 32; k++) {
      c.tx += d[b[i + k] >> 4];
      c.tx += d[b[i + k] & 15];
    }
    c.ok = b[i + 32] != 0;
    c.value.assign(b.begin() + i + 33, b.begin() + i + 65);
    size_t len = ((size_t)b[i + 65] << 24) | ((size_t)b[i + 66] << 16) |
                 ((size_t)b[i + 67] << 8) | b[i + 68];
    if (i + 69 + len > b.size()) break;
    c.calldata.assign(b.begin() + i + 69, b.begin() + i + 69 + len);
    v.push_back(c);
    i += 69 + len;
  }
  return v;
}
}  // namespace urs
