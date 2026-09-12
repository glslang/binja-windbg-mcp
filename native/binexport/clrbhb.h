#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

struct ClrBhbFallback {
  uint16_t size;
  std::string_view mnemonic;
  bool fallthrough;
};

inline std::optional<ClrBhbFallback>
GetAarch64ClrBhbFallback(std::string_view architecture, uint64_t address,
                         const uint8_t *bytes, size_t length) {
  if (architecture != "aarch64" || (address & 3) != 0 || !bytes || length < 4 ||
      bytes[0] != 0xdf || bytes[1] != 0x22 || bytes[2] != 0x03 ||
      bytes[3] != 0xd5)
    return std::nullopt;
  return ClrBhbFallback{4, "clrbhb", true};
}
