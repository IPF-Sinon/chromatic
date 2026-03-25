#pragma once
#include <functional>
#include <string>

namespace chromatic::js {
struct NativeInterceptor {
  /// Attach an inline hook to `target`.
  /// onEnter/onLeave receive the cpuContext pointer as a hex string.
  /// Returns a hookId string used for detaching.
  static std::string attach(const std::string &target,
                            std::function<void(std::string)> onEnter,
                            std::function<void(std::string)> onLeave);

  /// Detach a hook by hookId.
  static void detach(const std::string &hookId);

  /// Detach all active hooks.
  static void detachAll();

  /// Replace target function with replacement.
  /// Returns trampoline address (hex) to call the original function.
  static std::string replace(const std::string &target,
                             const std::string &replacement);

  /// Revert a replacement.
  static void revert(const std::string &target);
};
} // namespace chromatic::js
