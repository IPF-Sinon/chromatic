#pragma once
#include <cstddef>
#include <cstdint>

namespace chromatic::internal {

/// Make the code page containing [addr, addr+len) writable, patch it, flush
/// icache, then restore RX.  Cross-platform (Windows, macOS, Linux, Android).
void makeWritableAndPatch(void *addr, const uint8_t *data, size_t len);

/// Fill `buf` with an absolute jump to `jumpTarget`.
/// ARM64: LDR X16,#8; BR X16; .quad addr  (16 bytes)
/// x86_64: FF 25 00 00 00 00 + .quad addr  (14 bytes)
void generatePatchBytes(uint8_t *buf, uint64_t jumpTarget);

/// Patch size required for an absolute jump.
#ifdef CHROMATIC_ARM64
static constexpr size_t PATCH_SIZE = 16;
#else
static constexpr size_t PATCH_SIZE = 14;
#endif

/// Copy (and relocate) original instructions from `source`, fixing up
/// PC-relative instructions.  Appends a jump back to `source + bytesConsumed`.
/// Returns pointer to the JIT-allocated relocated code.
void *buildRelocatedCode(uint64_t source, size_t minBytes,
                         size_t &bytesConsumed);

/// Dispatch function signature expected by the trampoline.
/// Receives (cpuContext*, userData*).
using DispatchFn = void (*)(void *, void *);

/// Build a trampoline that:
///   1. saves all registers to the stack
///   2. calls `onEnterFn(cpuContext*, userData)`
///   3. calls `onLeaveFn(cpuContext*, userData)`  (may be nullptr)
///   4. restores all registers
///   5. jumps to `relocatedAddr`
/// Returns pointer to the JIT-allocated trampoline code.
void *buildTrampoline(DispatchFn onEnterFn, DispatchFn onLeaveFn,
                      void *userData, uint64_t relocatedAddr);

/// Release a JIT-allocated code block.
void releaseCode(void *code);

} // namespace chromatic::internal
