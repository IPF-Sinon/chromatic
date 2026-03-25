#include "native_interceptor.h"
#include "native_disassembler.h"

#ifdef CHROMATIC_ARM64
#include <asmjit/a64.h>
#else
#include <asmjit/x86.h>
#endif
#include <asmjit/core.h>
#include <cstdint>
#include <cstring>
#include <functional>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <unordered_map>
#include <vector>

#ifdef CHROMATIC_WINDOWS
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

#ifdef CHROMATIC_DARWIN
#include <mach/mach.h>
#include <libkern/OSCacheControl.h>
#endif

namespace {

// ─── Utilities ───

uint64_t parseHexAddr(const std::string &s) {
  return std::stoull(s, nullptr, 16);
}

std::string toHexAddr(uint64_t addr) {
  std::ostringstream oss;
  oss << "0x" << std::hex << addr;
  return oss.str();
}

// ─── Hook entry ───

struct HookEntry {
  uint64_t target;
  void *trampolineCode;     // asmjit-managed trampoline
  void *relocatedCode;      // asmjit-managed relocated original
  std::vector<uint8_t> originalBytes;
  size_t patchSize;
  std::function<void(std::string)> onEnter;
  std::function<void(std::string)> onLeave;
};

std::mutex hookMutex;
uint64_t nextHookId = 1;
std::unordered_map<uint64_t, HookEntry *> hooksById;
std::unordered_map<uint64_t, HookEntry *> hooksByTarget;

// Global JitRuntime — handles RW→RX, MAP_JIT, icache flush internally
asmjit::JitRuntime jitRuntime;

// ─── C dispatch function ───
// Called from trampoline with (cpuContext*, hookEntry*)
// Catches all exceptions to prevent crashes.

extern "C" void chromatic_interceptor_dispatch(void *cpuContext,
                                                void *hookEntryPtr) {
  auto *entry = static_cast<HookEntry *>(hookEntryPtr);
  if (!entry)
    return;

  std::string ctxHex = toHexAddr(reinterpret_cast<uint64_t>(cpuContext));

  if (entry->onEnter) {
    try {
      entry->onEnter(ctxHex);
    } catch (const std::exception &e) {
      fprintf(stderr, "[chromatic] onEnter threw: %s\n", e.what());
    } catch (...) {
      fprintf(stderr, "[chromatic] onEnter threw unknown exception\n");
    }
  }
}

extern "C" void chromatic_interceptor_dispatch_leave(void *cpuContext,
                                                      void *hookEntryPtr) {
  auto *entry = static_cast<HookEntry *>(hookEntryPtr);
  if (!entry)
    return;

  std::string ctxHex = toHexAddr(reinterpret_cast<uint64_t>(cpuContext));

  if (entry->onLeave) {
    try {
      entry->onLeave(ctxHex);
    } catch (const std::exception &e) {
      fprintf(stderr, "[chromatic] onLeave threw: %s\n", e.what());
    } catch (...) {
      fprintf(stderr, "[chromatic] onLeave threw unknown exception\n");
    }
  }
}

// ─── Patch writing ───

void makeWritableAndPatch(void *addr, const uint8_t *data, size_t len) {
#ifdef CHROMATIC_WINDOWS
  DWORD oldProt;
  VirtualProtect(addr, len, PAGE_EXECUTE_READWRITE, &oldProt);
  std::memcpy(addr, data, len);
  FlushInstructionCache(GetCurrentProcess(), addr, len);
  VirtualProtect(addr, len, oldProt, &oldProt);
#elif defined(CHROMATIC_DARWIN)
  // macOS: Use mach_vm_protect with VM_PROT_COPY to modify signed code pages
  size_t pageSize = static_cast<size_t>(sysconf(_SC_PAGESIZE));
  uintptr_t pageStart = reinterpret_cast<uintptr_t>(addr) & ~(pageSize - 1);
  size_t totalSize = (reinterpret_cast<uintptr_t>(addr) + len) - pageStart;

  kern_return_t kr = vm_protect(mach_task_self(),
      static_cast<vm_address_t>(pageStart), totalSize, FALSE,
      VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
  if (kr != KERN_SUCCESS)
    throw std::runtime_error("vm_protect(RW|COPY) failed: " + std::to_string(kr));

  std::memcpy(addr, data, len);

  kr = vm_protect(mach_task_self(),
      static_cast<vm_address_t>(pageStart), totalSize, FALSE,
      VM_PROT_READ | VM_PROT_EXECUTE);
  if (kr != KERN_SUCCESS)
    throw std::runtime_error("vm_protect(RX) failed: " + std::to_string(kr));

  sys_icache_invalidate(addr, len);
#else
  // Linux/Android
  size_t pageSize = static_cast<size_t>(sysconf(_SC_PAGESIZE));
  uintptr_t pageStart = reinterpret_cast<uintptr_t>(addr) & ~(pageSize - 1);
  size_t totalSize = (reinterpret_cast<uintptr_t>(addr) + len) - pageStart;
  if (mprotect(reinterpret_cast<void *>(pageStart), totalSize,
               PROT_READ | PROT_WRITE) != 0)
    throw std::runtime_error("mprotect(RW) failed");
  std::memcpy(addr, data, len);
  if (mprotect(reinterpret_cast<void *>(pageStart), totalSize,
               PROT_READ | PROT_EXEC) != 0)
    throw std::runtime_error("mprotect(RX) failed");
#ifdef CHROMATIC_ARM64
  __builtin___clear_cache(reinterpret_cast<char *>(addr),
                          reinterpret_cast<char *>(addr) + len);
#endif
#endif
}

// ─── Patch size ───

#ifdef CHROMATIC_ARM64
static constexpr size_t PATCH_SIZE = 16; // LDR X16, #8; BR X16; .quad addr
#else
static constexpr size_t PATCH_SIZE = 14; // FF 25 00 00 00 00 + 8-byte addr
#endif

// ─── Generate inline patch (jump to target) using asmjit ───

void generatePatchBytes(uint8_t *buf, uint64_t jumpTarget) {
#ifdef CHROMATIC_ARM64
  // LDR X16, #8
  uint32_t ldr = 0x58000050;
  std::memcpy(buf + 0, &ldr, 4);
  // BR X16
  uint32_t br = 0xD61F0200;
  std::memcpy(buf + 4, &br, 4);
  // .quad jumpTarget
  std::memcpy(buf + 8, &jumpTarget, 8);
#else
  // FF 25 00 00 00 00 = JMP [RIP+0]
  buf[0] = 0xFF;
  buf[1] = 0x25;
  uint32_t zero = 0;
  std::memcpy(buf + 2, &zero, 4);
  std::memcpy(buf + 6, &jumpTarget, 8);
#endif
}

// ─── Build trampoline with asmjit ───
// Saves all registers → calls dispatch(cpuContext*, hookEntry*) → restores → jumps to relocated

void *buildTrampoline(HookEntry *entry, uint64_t relocatedAddr) {
  using namespace asmjit;
  CodeHolder code;
  code.init(jitRuntime.environment(), jitRuntime.cpuFeatures());

#ifdef CHROMATIC_ARM64
  a64::Assembler a(&code);

  // Save all general-purpose registers to stack
  // We need space for x0-x30, sp snapshot, nzcv = 33*8 = 264 bytes, round to 272 (0x110)
  constexpr int FRAME_SIZE = 0x110;
  a.sub(a64::sp, a64::sp, FRAME_SIZE);

  // STP pairs x0-x27
  for (int i = 0; i < 28; i += 2) {
    a.stp(a64::x(i), a64::x(i + 1), a64::Mem(a64::sp, i * 8));
  }
  // STP x28, x29
  a.stp(a64::x(28), a64::x(29), a64::Mem(a64::sp, 28 * 8));
  // STR x30 (LR)
  a.str(a64::x(30), a64::Mem(a64::sp, 30 * 8));
  // Save SP snapshot: add x16, sp, FRAME_SIZE; str x16, [sp, 31*8]
  a.add(a64::x(16), a64::sp, FRAME_SIZE);
  a.str(a64::x(16), a64::Mem(a64::sp, 31 * 8));
  // Save NZCV: mrs x16, nzcv; str x16, [sp, 32*8]
  a.mrs(a64::x(16), Imm(0xDA10)); // NZCV system register encoding
  a.str(a64::x(16), a64::Mem(a64::sp, 32 * 8));

  // Call dispatch: x0 = sp (context ptr), x1 = hookEntry*
  a.mov(a64::x(0), a64::sp);
  a.mov(a64::x(1), reinterpret_cast<uint64_t>(entry));
  a.mov(a64::x(16), reinterpret_cast<uint64_t>(&chromatic_interceptor_dispatch));
  a.blr(a64::x(16));

  // Call leave dispatch
  a.mov(a64::x(0), a64::sp);
  a.mov(a64::x(1), reinterpret_cast<uint64_t>(entry));
  a.mov(a64::x(16), reinterpret_cast<uint64_t>(&chromatic_interceptor_dispatch_leave));
  a.blr(a64::x(16));

  // Restore NZCV
  a.ldr(a64::x(16), a64::Mem(a64::sp, 32 * 8));
  a.msr(Imm(0xDA10), a64::x(16));

  // Restore x0-x27
  for (int i = 0; i < 28; i += 2) {
    a.ldp(a64::x(i), a64::x(i + 1), a64::Mem(a64::sp, i * 8));
  }
  // LDP x28, x29
  a.ldp(a64::x(28), a64::x(29), a64::Mem(a64::sp, 28 * 8));
  // LDR x30
  a.ldr(a64::x(30), a64::Mem(a64::sp, 30 * 8));
  // Restore SP
  a.add(a64::sp, a64::sp, FRAME_SIZE);

  // Jump to relocated code
  a.mov(a64::x(16), relocatedAddr);
  a.br(a64::x(16));

#else // x86_64
  x86::Assembler a(&code);

  // Save all general-purpose registers
  a.pushfq();
  a.push(x86::rax);
  a.push(x86::rcx);
  a.push(x86::rdx);
  a.push(x86::rbx);
  a.push(x86::rbp);
  a.push(x86::rsi);
  a.push(x86::rdi);
  a.push(x86::r8);
  a.push(x86::r9);
  a.push(x86::r10);
  a.push(x86::r11);
  a.push(x86::r12);
  a.push(x86::r13);
  a.push(x86::r14);
  a.push(x86::r15);

  // System V ABI: rdi = arg0 (cpuContext), rsi = arg1 (hookEntry*)
  a.mov(x86::rdi, x86::rsp);
  a.mov(x86::rsi, reinterpret_cast<uint64_t>(entry));

  // Align stack to 16 bytes (16 pushes + pushfq = 17*8 = 136 = 0x88, need +8 for alignment)
  a.sub(x86::rsp, 0x8);

  // Call onEnter dispatch
  a.mov(x86::rax, reinterpret_cast<uint64_t>(&chromatic_interceptor_dispatch));
  a.call(x86::rax);

  // Call onLeave dispatch (reuse same context)
  a.mov(x86::rdi, x86::rsp);
  a.add(x86::rdi, 0x8); // point back to saved regs
  a.mov(x86::rsi, reinterpret_cast<uint64_t>(entry));
  a.mov(x86::rax, reinterpret_cast<uint64_t>(&chromatic_interceptor_dispatch_leave));
  a.call(x86::rax);

  // Undo alignment
  a.add(x86::rsp, 0x8);

  // Restore all registers
  a.pop(x86::r15);
  a.pop(x86::r14);
  a.pop(x86::r13);
  a.pop(x86::r12);
  a.pop(x86::r11);
  a.pop(x86::r10);
  a.pop(x86::r9);
  a.pop(x86::r8);
  a.pop(x86::rdi);
  a.pop(x86::rsi);
  a.pop(x86::rbp);
  a.pop(x86::rbx);
  a.pop(x86::rdx);
  a.pop(x86::rcx);
  a.pop(x86::rax);
  a.popfq();

  // Jump to relocated code (absolute indirect jump)
  a.jmp(x86::ptr(x86::rip));
  a.embedUInt64(relocatedAddr);
#endif

  void *result = nullptr;
  asmjit::Error err = jitRuntime.add(&result, &code);
  if (err != asmjit::kErrorOk || !result)
    throw std::runtime_error("asmjit: failed to build trampoline");
  return result;
}

// ─── Build relocated code with asmjit ───
// Copies original instructions (with PC-relative fixups) then jumps back

void *buildRelocatedCode(uint64_t source, size_t minBytes, size_t &bytesConsumed) {
  using namespace asmjit;
  CodeHolder code;
  code.init(jitRuntime.environment(), jitRuntime.cpuFeatures());

  auto *srcPtr = reinterpret_cast<const uint8_t *>(source);
  size_t srcOffset = 0;

#ifdef CHROMATIC_ARM64
  a64::Assembler a(&code);

  while (srcOffset < minBytes) {
    auto insn = chromatic::js::NativeDisassembler::disassembleOne(
        toHexAddr(source + srcOffset));
    int insnSize = insn.size;
    if (insnSize == 0)
      throw std::runtime_error("Cannot disassemble at " +
                               toHexAddr(source + srcOffset));

    auto analysis = chromatic::js::NativeDisassembler::analyzeInstruction(
        toHexAddr(source + srcOffset));

    if (analysis.isPcRelative) {
      uint64_t target = parseHexAddr(analysis.target);
      std::string mnemonic = insn.mnemonic;

      if (mnemonic == "b") {
        // Absolute branch via x16
        a.mov(a64::x(16), target);
        a.br(a64::x(16));
      } else if (mnemonic == "bl") {
        // Absolute branch-with-link via x16
        a.mov(a64::x(16), target);
        a.blr(a64::x(16));
      } else if (mnemonic == "adr" || mnemonic == "adrp") {
        // Load absolute address into the destination register
        uint32_t rawInsn;
        std::memcpy(&rawInsn, srcPtr + srcOffset, 4);
        uint32_t rd = rawInsn & 0x1F;
        a.mov(a64::x(rd), target);
      } else {
        // Other PC-relative: embed raw bytes (best effort)
        a.embed(srcPtr + srcOffset, insnSize);
      }
    } else {
      // Non-PC-relative: copy raw bytes
      a.embed(srcPtr + srcOffset, insnSize);
    }

    srcOffset += insnSize;
  }

  // Jump back to original code after the patch area
  uint64_t jumpBackTarget = source + srcOffset;
  a.mov(a64::x(16), jumpBackTarget);
  a.br(a64::x(16));

#else // x86_64
  x86::Assembler a(&code);

  while (srcOffset < minBytes) {
    auto insn = chromatic::js::NativeDisassembler::disassembleOne(
        toHexAddr(source + srcOffset));
    int insnSize = insn.size;
    if (insnSize == 0)
      throw std::runtime_error("Cannot disassemble at " +
                               toHexAddr(source + srcOffset));

    auto analysis = chromatic::js::NativeDisassembler::analyzeInstruction(
        toHexAddr(source + srcOffset));

    if (analysis.isPcRelative) {
      uint64_t target = parseHexAddr(analysis.target);
      uint8_t firstByte = srcPtr[srcOffset];

      if (firstByte == 0xE9) {
        // JMP rel32 → absolute jmp
        a.jmp(x86::ptr(x86::rip));
        a.embedUInt64(target);
      } else if (firstByte == 0xE8) {
        // CALL rel32 → absolute call
        // CALL [RIP+2]; JMP skip; .quad target
        a.call(x86::ptr(x86::rip, 2));
        a.jmp(a.newLabel()); // will be bound after embedUInt64
        auto skipLabel = a.newLabel();
        a.embedUInt64(target);
        a.bind(skipLabel);
      } else if (analysis.isBranch && !analysis.isCall) {
        // Conditional branch — emit as: Jcc over absolute jmp, then absolute jmp
        // For simplicity, embed the raw conditional + absolute fallback
        // We invert the condition to skip the absolute jump
        uint8_t cc = 0;
        if (firstByte >= 0x70 && firstByte <= 0x7F) {
          cc = firstByte - 0x70;
        } else if (firstByte == 0x0F) {
          cc = srcPtr[srcOffset + 1] - 0x80;
        }
        // Emit: J_not_cc skip; JMP [RIP]; .quad target; skip:
        auto skipLabel = a.newLabel();
        // Inverted Jcc (near)
        a.embedUInt8(0x0F);
        a.embedUInt8(static_cast<uint8_t>(0x80 + (cc ^ 1)));
        a.embedUInt32(14); // skip 14 bytes (6 for jmp + 8 for addr)
        // Absolute JMP
        a.jmp(x86::ptr(x86::rip));
        a.embedUInt64(target);
        a.bind(skipLabel);
      } else {
        // RIP-relative memory operand — copy raw and we can't easily fix
        // disp32 without knowing the final address. Embed raw as best effort.
        a.embed(srcPtr + srcOffset, insnSize);
      }
    } else {
      // Non-PC-relative: copy raw bytes
      a.embed(srcPtr + srcOffset, insnSize);
    }

    srcOffset += insnSize;
  }

  // Jump back to original code
  uint64_t jumpBackTarget = source + srcOffset;
  a.jmp(x86::ptr(x86::rip));
  a.embedUInt64(jumpBackTarget);
#endif

  bytesConsumed = srcOffset;

  void *result = nullptr;
  asmjit::Error err = jitRuntime.add(&result, &code);
  if (err != asmjit::kErrorOk || !result)
    throw std::runtime_error("asmjit: failed to build relocated code");
  return result;
}

} // anonymous namespace

namespace chromatic::js {

std::string NativeInterceptor::attach(const std::string &targetStr,
                                       std::function<void(std::string)> onEnter,
                                       std::function<void(std::string)> onLeave) {
  uint64_t target = parseHexAddr(targetStr);

  std::lock_guard<std::mutex> lock(hookMutex);

  if (hooksByTarget.count(target))
    throw std::runtime_error("Already hooked at " + targetStr);

  auto *entry = new HookEntry();
  entry->target = target;
  entry->onEnter = std::move(onEnter);
  entry->onLeave = std::move(onLeave);
  entry->patchSize = PATCH_SIZE;

  // 1. Save original bytes
  auto *targetPtr = reinterpret_cast<uint8_t *>(target);
  entry->originalBytes.resize(PATCH_SIZE);
  std::memcpy(entry->originalBytes.data(), targetPtr, PATCH_SIZE);

  // 2. Build relocated code (copies original instructions + jump-back)
  size_t bytesConsumed = 0;
  try {
    entry->relocatedCode = buildRelocatedCode(target, PATCH_SIZE, bytesConsumed);
  } catch (...) {
    delete entry;
    throw;
  }

  // 3. Build trampoline (save ctx → dispatch → restore → jump to relocated)
  try {
    entry->trampolineCode = buildTrampoline(entry,
        reinterpret_cast<uint64_t>(entry->relocatedCode));
  } catch (...) {
    jitRuntime.release(entry->relocatedCode);
    delete entry;
    throw;
  }

  // 4. Patch target to jump to trampoline
  uint8_t patchBuf[16];
  generatePatchBytes(patchBuf, reinterpret_cast<uint64_t>(entry->trampolineCode));
  makeWritableAndPatch(targetPtr, patchBuf, PATCH_SIZE);

  // 5. Register
  uint64_t hookId = nextHookId++;
  hooksById[hookId] = entry;
  hooksByTarget[target] = entry;

  return toHexAddr(hookId);
}

void NativeInterceptor::detach(const std::string &hookIdStr) {
  uint64_t hookId = parseHexAddr(hookIdStr);

  std::lock_guard<std::mutex> lock(hookMutex);

  auto it = hooksById.find(hookId);
  if (it == hooksById.end())
    return;

  auto *entry = it->second;

  // Restore original bytes
  makeWritableAndPatch(reinterpret_cast<void *>(entry->target),
                       entry->originalBytes.data(), entry->patchSize);

  // Release asmjit-managed code
  if (entry->trampolineCode)
    jitRuntime.release(entry->trampolineCode);
  if (entry->relocatedCode)
    jitRuntime.release(entry->relocatedCode);

  hooksByTarget.erase(entry->target);
  hooksById.erase(it);
  delete entry;
}

void NativeInterceptor::detachAll() {
  std::lock_guard<std::mutex> lock(hookMutex);

  for (auto &[id, entry] : hooksById) {
    makeWritableAndPatch(reinterpret_cast<void *>(entry->target),
                         entry->originalBytes.data(), entry->patchSize);
    if (entry->trampolineCode)
      jitRuntime.release(entry->trampolineCode);
    if (entry->relocatedCode)
      jitRuntime.release(entry->relocatedCode);
    delete entry;
  }
  hooksById.clear();
  hooksByTarget.clear();
}

std::string NativeInterceptor::replace(const std::string &targetStr,
                                        const std::string &replacementStr) {
  uint64_t target = parseHexAddr(targetStr);
  uint64_t replacement = parseHexAddr(replacementStr);

  std::lock_guard<std::mutex> lock(hookMutex);

  if (hooksByTarget.count(target))
    throw std::runtime_error("Already hooked at " + targetStr);

  auto *entry = new HookEntry();
  entry->target = target;
  entry->patchSize = PATCH_SIZE;
  entry->trampolineCode = nullptr;

  // Save original bytes
  auto *targetPtr = reinterpret_cast<uint8_t *>(target);
  entry->originalBytes.resize(PATCH_SIZE);
  std::memcpy(entry->originalBytes.data(), targetPtr, PATCH_SIZE);

  // Build relocated code (= trampoline to call original)
  size_t bytesConsumed = 0;
  try {
    entry->relocatedCode = buildRelocatedCode(target, PATCH_SIZE, bytesConsumed);
  } catch (...) {
    delete entry;
    throw;
  }

  // Patch target to jump to replacement
  uint8_t patchBuf[16];
  generatePatchBytes(patchBuf, replacement);
  makeWritableAndPatch(targetPtr, patchBuf, PATCH_SIZE);

  uint64_t hookId = nextHookId++;
  hooksById[hookId] = entry;
  hooksByTarget[target] = entry;

  return toHexAddr(reinterpret_cast<uint64_t>(entry->relocatedCode));
}

void NativeInterceptor::revert(const std::string &targetStr) {
  uint64_t target = parseHexAddr(targetStr);

  std::lock_guard<std::mutex> lock(hookMutex);

  auto it = hooksByTarget.find(target);
  if (it == hooksByTarget.end())
    return;

  auto *entry = it->second;
  makeWritableAndPatch(reinterpret_cast<void *>(entry->target),
                       entry->originalBytes.data(), entry->patchSize);

  if (entry->trampolineCode)
    jitRuntime.release(entry->trampolineCode);
  if (entry->relocatedCode)
    jitRuntime.release(entry->relocatedCode);

  // Find in hooksById
  for (auto jt = hooksById.begin(); jt != hooksById.end(); ++jt) {
    if (jt->second == entry) {
      hooksById.erase(jt);
      break;
    }
  }
  hooksByTarget.erase(it);
  delete entry;
}

} // namespace chromatic::js
