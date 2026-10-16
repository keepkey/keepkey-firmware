// Plans and reviews of every D-021 sample call, every vector, and 2,048
// mutated V4 calls, as the independent Python model reads them
// (scripts/uniswap/gen_ur_vectors.py expect). One line per call:
//   key [base-tx n off:byte...] D 0
//   key [...] D 1 n {kind tin tout rcpt amount limit payer expiration}*n
//     H nh hook* S 0
//   key [...] D 1 ... S 1 exact_in in_eth out_eth tin tout amount_in
//     amount_out rcpt rcpt_is_sender has_permit ptoken pamount pexp
//     has_fee bips fee_rcpt
#include <cstdint>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <vector>
namespace ure {
struct Step {
  int kind;
  std::string tin, tout, rcpt, amount, limit;
  int payer;
  uint64_t exp;
};
struct Expect {
  std::string key, base;  // base: the sample tx a mutant edits
  std::vector<std::pair<size_t, uint8_t>> edits;
  bool decoded = false, reviewed = false;
  std::vector<Step> steps;
  std::vector<std::string> hooks;
  std::vector<std::string> review;  // the S 1 fields, in order
};
inline const std::vector<Expect>& all() {
  static std::vector<Expect> v;
  if (!v.empty()) return v;
  std::ifstream f(UR_EXPECTED_PATH);
  std::string line;
  while (std::getline(f, line)) {
    std::istringstream in(line);
    Expect e;
    std::string t;
    in >> e.key;
    if (e.key.compare(0, 3, "mut") == 0) {
      size_t n;
      in >> e.base >> n;
      for (size_t i = 0; i < n; i++) {
        in >> t;
        const size_t c = t.find(':');
        e.edits.push_back({std::stoul(t.substr(0, c)),
                           (uint8_t)std::stoul(t.substr(c + 1))});
      }
    }
    in >> t >> t;  // D x
    e.decoded = t == "1";
    if (e.decoded) {
      size_t n;
      in >> n;
      for (size_t i = 0; i < n; i++) {
        Step s;
        in >> s.kind >> s.tin >> s.tout >> s.rcpt >> s.amount >> s.limit >>
            s.payer >> s.exp;
        e.steps.push_back(s);
      }
      in >> t >> n;  // H n
      for (size_t i = 0; i < n; i++) {
        in >> t;
        e.hooks.push_back(t);
      }
      in >> t >> t;  // S x
      e.reviewed = t == "1";
      while (e.reviewed && in >> t) e.review.push_back(t);
    }
    v.push_back(e);
  }
  return v;
}
}  // namespace ure
