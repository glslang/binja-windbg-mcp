#include "clrbhb.h"

#include <array>
#include <iostream>

namespace {
int failures = 0;
void Check(bool condition, const char *message) {
  if (!condition) {
    std::cerr << message << '\n';
    ++failures;
  }
}
} // namespace

int main() {
  constexpr std::array<uint8_t, 4> clrbhb{0xdf, 0x22, 0x03, 0xd5};
  constexpr std::array<uint8_t, 4> nearbyHint{0xbf, 0x22, 0x03, 0xd5};
  const auto fallback = GetAarch64ClrBhbFallback("aarch64", 0x14010fc00,
                                                 clrbhb.data(), clrbhb.size());
  Check(fallback.has_value(), "CLRBHB encoding was not recognized");
  if (fallback) {
    Check(fallback->size == 4, "CLRBHB fallback size is not four bytes");
    Check(fallback->mnemonic == "clrbhb", "CLRBHB fallback mnemonic changed");
    Check(fallback->fallthrough, "CLRBHB fallback must preserve fallthrough");
  }
  Check(
      !GetAarch64ClrBhbFallback("x86_64", 0x1000, clrbhb.data(), clrbhb.size()),
      "wrong architecture accepted");
  Check(!GetAarch64ClrBhbFallback("aarch64", 0x1002, clrbhb.data(),
                                  clrbhb.size()),
        "unaligned address accepted");
  Check(!GetAarch64ClrBhbFallback("aarch64", 0x1000, clrbhb.data(), 3),
        "short encoding accepted");
  Check(!GetAarch64ClrBhbFallback("aarch64", 0x1000, nearbyHint.data(),
                                  nearbyHint.size()),
        "nearby hint accepted");
  Check(!GetAarch64ClrBhbFallback("aarch64", 0x1000, nullptr, clrbhb.size()),
        "null input accepted");
  return failures == 0 ? 0 : 1;
}
