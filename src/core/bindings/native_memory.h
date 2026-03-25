#pragma once
#include <string>

namespace chromatic::js {
struct NativeMemory {
  /// Read `size` bytes from `address` (hex string), return hex-encoded data
  static std::string readMemory(const std::string &address, int size);

  /// Like readMemory but returns empty string on access fault instead of crashing
  static std::string safeReadMemory(const std::string &address, int size);

  /// Write hex-encoded `hexData` to `address`
  static void writeMemory(const std::string &address,
                          const std::string &hexData);

  /// Allocate `size` bytes of RWX memory, return address as hex string
  static std::string allocateMemory(int size);

  /// Free previously allocated memory at `address` of given `size`
  static void freeMemory(const std::string &address, int size);

  /// Change memory protection. `protection` is like "rwx"/"r-x"/etc.
  /// Returns old protection string.
  static std::string protectMemory(const std::string &address, int size,
                                   const std::string &protection);

  /// Write bytes + flush instruction cache (for code patching)
  static void patchCode(const std::string &address,
                        const std::string &hexBytes);

  /// Flush instruction cache for region
  static void flushIcache(const std::string &address, int size);

  /// Copy `size` bytes from `src` to `dst`
  static void copyMemory(const std::string &dst, const std::string &src,
                         int size);

  /// Scan memory region for pattern (e.g. "48 8b ?? 00").
  /// Returns JSON array of matching addresses.
  static std::string scanMemory(const std::string &address, int size,
                                const std::string &pattern);
};
} // namespace chromatic::js
