#include "core/script.h"
#include <cstdint>
#include <cstdio>
#include <gtest/gtest.h>
#include <string>

#include <async_simple/coro/Lazy.h>
#include "async_simple/coro/SyncAwait.h"

// Shared runtime — created once, used by all tests
static chromatic::script::runtime *g_rt = nullptr;

// Helper: eval JS and return true if no error
static bool jsEval(const std::string &code) {
  auto res = g_rt->eval_script(code, "<test>");
  if (!res) {
    std::fprintf(stderr, "JS error: %s\n", res.error().c_str());
    return false;
  } else {
    syncAwait(res.value().await())
                         .as<std::string>();
  }
  return true;
}

// Helper: format a C pointer as hex string for injection into JS
static std::string ptrHex(void *p) {
  char buf[32];
  std::snprintf(buf, sizeof(buf), "0x%llx",
                (unsigned long long)reinterpret_cast<uintptr_t>(p));
  return buf;
}

// ── C functions for hooking/calling from JS ──

extern "C" int chromatic_test_add(int a, int b) { return a + b; }
extern "C" int chromatic_test_mul(int a, int b) { return a * b; }
extern "C" int chromatic_test_sub(int a, int b) { return a - b; }

static int g_side_effect = 0;
extern "C" void chromatic_test_set_global(int v) { g_side_effect = v; }
extern "C" int chromatic_test_get_global() { return g_side_effect; }

// ── Fixture ──

class ChromaticTest : public ::testing::Test {
protected:
  static void SetUpTestSuite() {
    g_rt = new chromatic::script::runtime();
    g_rt->reset();
  }
  static void TearDownTestSuite() {
    delete g_rt;
    g_rt = nullptr;
  }
};

// ═══════════════════════════════════════════
// NativePointer
// ═══════════════════════════════════════════

TEST_F(ChromaticTest, NativePointer_Construction) {
  EXPECT_TRUE(jsEval(R"(
    (() => {
      const p = new NativePointer(0x1234);
      if (p.toString() !== '0x1234') throw new Error('toString: ' + p.toString());
    })()
  )"));
}

TEST_F(ChromaticTest, NativePointer_FromHexString) {
  EXPECT_TRUE(jsEval(R"(
    (() => {
      const p = new NativePointer('0xdeadbeef');
      if (p.toUInt32() !== 0xdeadbeef) throw new Error('toUInt32: ' + p.toUInt32());
    })()
  )"));
}

TEST_F(ChromaticTest, NativePointer_IsNull) {
  EXPECT_TRUE(jsEval(R"(
    (() => {
      if (!new NativePointer(0).isNull()) throw new Error('0 should be null');
      if (new NativePointer(1).isNull()) throw new Error('1 should not be null');
    })()
  )"));
}

TEST_F(ChromaticTest, NativePointer_Arithmetic) {
  EXPECT_TRUE(jsEval(R"(
    (() => {
      const sum = new NativePointer(100).add(50);
      if (!sum.equals(new NativePointer(150))) throw new Error('add');
      const diff = new NativePointer(200).sub(50);
      if (!diff.equals(new NativePointer(150))) throw new Error('sub');
    })()
  )"));
}

// ═══════════════════════════════════════════
// Memory
// ═══════════════════════════════════════════

TEST_F(ChromaticTest, Memory_AllocReadWriteU32) {
  EXPECT_TRUE(jsEval(R"(
    (() => {
      const p = Memory.alloc(64);
      if (p.isNull()) throw new Error('alloc null');
      p.writeU32(0xCAFEBABE);
      const val = p.readU32();
      if (val !== 0xCAFEBABE) throw new Error('mismatch: 0x' + val.toString(16));
    })()
  )"));
}

TEST_F(ChromaticTest, Memory_Copy) {
  EXPECT_TRUE(jsEval(R"(
    (() => {
      const src = Memory.alloc(16);
      src.writeU32(0x12345678);
      const dst = Memory.alloc(16);
      Memory.copy(dst, src, 4);
      if (dst.readU32() !== 0x12345678) throw new Error('copy mismatch');
    })()
  )"));
}

TEST_F(ChromaticTest, Memory_ReadWriteMultipleTypes) {
  EXPECT_TRUE(jsEval(R"(
    (() => {
      const p = Memory.alloc(64);
      // U8
      p.writeU8(0xFF);
      if (p.readU8() !== 0xFF) throw new Error('U8 mismatch');
      // U16
      p.add(4).writeU16(0x1234);
      if (p.add(4).readU16() !== 0x1234) throw new Error('U16 mismatch');
      // U64 (via writeU32 pairs since we may not have writeU64)
      p.add(8).writeU32(0xDEADBEEF);
      if (p.add(8).readU32() !== 0xDEADBEEF) throw new Error('U32 mismatch');
    })()
  )"));
}

TEST_F(ChromaticTest, Memory_Protect) {
  EXPECT_TRUE(jsEval(R"(
    (() => {
      const p = Memory.alloc(4096);
      // Allocate gives RW, protect to R-only
      Memory.protect(p, 4096, 'r');
      // Protect back to RW
      Memory.protect(p, 4096, 'rw');
      // Should be writable again
      p.writeU32(42);
      if (p.readU32() !== 42) throw new Error('protect round-trip failed');
    })()
  )"));
}

// ═══════════════════════════════════════════
// Process
// ═══════════════════════════════════════════

TEST_F(ChromaticTest, Process_Arch) {
  EXPECT_TRUE(jsEval(R"(
    (() => {
      const a = Process.arch;
      if (a !== 'arm64' && a !== 'x64') throw new Error('bad arch: ' + a);
    })()
  )"));
}

TEST_F(ChromaticTest, Process_Platform) {
  EXPECT_TRUE(jsEval(R"(
    (() => {
      const p = Process.platform;
      if (!['windows','linux','darwin','android'].includes(p))
        throw new Error('bad platform: ' + p);
    })()
  )"));
}

TEST_F(ChromaticTest, Process_PointerSize) {
  EXPECT_TRUE(jsEval(R"(
    (() => {
      const s = Process.pointerSize;
      if (s !== 4 && s !== 8) throw new Error('bad: ' + s);
    })()
  )"));
}

TEST_F(ChromaticTest, Process_PageSize) {
  EXPECT_TRUE(jsEval(R"(
    (() => {
      if (Process.pageSize < 4096) throw new Error('bad pageSize');
    })()
  )"));
}

TEST_F(ChromaticTest, Process_EnumerateRanges) {
  EXPECT_TRUE(jsEval(R"(
    (() => {
      const ranges = Process.enumerateRanges('r--');
      if (!Array.isArray(ranges)) throw new Error('not array');
      if (ranges.length === 0) throw new Error('no ranges');
      const r = ranges[0];
      if (typeof r.base !== 'object') throw new Error('base not ptr');
      if (typeof r.size !== 'number') throw new Error('no size');
      if (typeof r.protection !== 'string') throw new Error('no protection');
    })()
  )"));
}

// ═══════════════════════════════════════════
// Module
// ═══════════════════════════════════════════

TEST_F(ChromaticTest, Module_EnumerateModules) {
  EXPECT_TRUE(jsEval(R"(
    (() => {
      const mods = Process.enumerateModules();
      if (mods.length === 0) throw new Error('no modules');
      const m = mods[0];
      if (typeof m.name !== 'string') throw new Error('no name');
      if (typeof m.base !== 'object') throw new Error('base not ptr');
      if (typeof m.size !== 'number') throw new Error('no size');
      if (typeof m.path !== 'string') throw new Error('no path');
    })()
  )"));
}

TEST_F(ChromaticTest, Module_FindExportByName) {
  EXPECT_TRUE(jsEval(R"(
    (() => {
      const addr = Module.findExportByName(null, 'malloc');
      if (!addr || addr.isNull()) throw new Error('malloc not found');
    })()
  )"));
}

TEST_F(ChromaticTest, Module_EnumerateExports) {
  EXPECT_TRUE(jsEval(R"(
    (() => {
      const mods = Process.enumerateModules();
      // Find a module with exports (the main module or first available)
      let found = false;
      for (const m of mods) {
        const exports = Module.enumerateExports(m.name);
        if (exports.length > 0) {
          const ex = exports[0];
          if (typeof ex.name !== 'string') throw new Error('no name');
          if (typeof ex.address !== 'object') throw new Error('no address');
          found = true;
          break;
        }
      }
      if (!found) throw new Error('no module with exports');
    })()
  )"));
}

TEST_F(ChromaticTest, Module_FindModuleByAddress) {
  EXPECT_TRUE(jsEval(R"(
    (() => {
      const addr = Module.findExportByName(null, 'malloc');
      const mod = Process.findModuleByAddress(addr);
      if (!mod) throw new Error('findModuleByAddress returned null');
      if (typeof mod.name !== 'string') throw new Error('no name');
    })()
  )"));
}

// ═══════════════════════════════════════════
// Instruction
// ═══════════════════════════════════════════

TEST_F(ChromaticTest, Instruction_Parse) {
  EXPECT_TRUE(jsEval(R"(
    (() => {
      const addr = Module.findExportByName(null, 'malloc');
      const insn = Instruction.parse(addr);

      if (!insn.mnemonic) throw new Error('no mnemonic');
      if (insn.size <= 0) throw new Error('bad size');
    })()
  )"));
}

TEST_F(ChromaticTest, Instruction_ParseMultiple) {
  EXPECT_TRUE(jsEval(R"(
    (() => {
      const addr = Module.findExportByName(null, 'malloc');
      const insn1 = Instruction.parse(addr);
      const insn2 = Instruction.parse(addr.add(insn1.size));
      // Both should parse successfully
      if (!insn1.mnemonic || !insn2.mnemonic)
        throw new Error('parse multiple failed');
      // Should be different addresses
      if (insn1.address.equals(insn2.address))
        throw new Error('same address');
    })()
  )"));
}

// ═══════════════════════════════════════════
// NativeFunction (FFI)
// ═══════════════════════════════════════════

TEST_F(ChromaticTest, NativeFunction_Call) {
  std::string code = R"(
    (() => {
      const fn = new NativeFunction(ptr(')" + ptrHex((void *)&chromatic_test_add) + R"('), 'int', ['int', 'int']);
      const r = fn(3, 4);
      if (r !== 7) throw new Error('expected 7, got ' + r);
    })()
  )";
  EXPECT_TRUE(jsEval(code));
}

TEST_F(ChromaticTest, NativeFunction_CallMultiple) {
  std::string code = R"(
    (() => {
      const add = new NativeFunction(ptr(')" + ptrHex((void *)&chromatic_test_add) + R"('), 'int', ['int', 'int']);
      const mul = new NativeFunction(ptr(')" + ptrHex((void *)&chromatic_test_mul) + R"('), 'int', ['int', 'int']);
      if (add(10, 20) !== 30) throw new Error('add');
      if (mul(5, 6) !== 30) throw new Error('mul');
    })()
  )";
  EXPECT_TRUE(jsEval(code));
}

// ═══════════════════════════════════════════
// NativeCallback
// ═══════════════════════════════════════════

TEST_F(ChromaticTest, NativeCallback_CreateAndCall) {
  EXPECT_TRUE(jsEval(R"(
    (() => {
      const cb = new NativeCallback(function(a, b) {
        return a + b;
      }, 'int', ['int', 'int']);
      if (cb.address.isNull()) throw new Error('null addr');
      const fn = new NativeFunction(cb.address, 'int', ['int', 'int']);
      const r = fn(10, 20);
      if (r !== 30) throw new Error('expected 30, got ' + r);
      cb.destroy();
    })()
  )"));
}

TEST_F(ChromaticTest, NativeCallback_ThrowDoesNotCrash) {
  EXPECT_TRUE(jsEval(R"(
    (() => {
      const cb = new NativeCallback(function(a, b) {
        throw new Error('intentional throw in callback');
      }, 'int', ['int', 'int']);
      const fn = new NativeFunction(cb.address, 'int', ['int', 'int']);
      // Should not crash, just return 0 or default
      const r = fn(1, 2);
      cb.destroy();
    })()
  )"));
}

// ═══════════════════════════════════════════
// hexdump
// ═══════════════════════════════════════════

TEST_F(ChromaticTest, Hexdump) {
  EXPECT_TRUE(jsEval(R"(
    (() => {
      const buf = Memory.alloc(32);
      for (let i = 0; i < 32; i++) buf.add(i).writeU8(i);
      const dump = hexdump(buf, { length: 32 });
      if (!dump || dump.length === 0) throw new Error('empty');
    })()
  )"));
}

// ═══════════════════════════════════════════
// Interceptor — basic attach/detach
// ═══════════════════════════════════════════

TEST_F(ChromaticTest, Interceptor_AttachDetach) {
  std::string code = R"(
    (() => {
      let enterCount = 0;
      const target = ptr(')" + ptrHex((void *)&chromatic_test_add) + R"(');
      const listener = Interceptor.attach(target, {
        onEnter(args) { enterCount++; }
      });
      const fn = new NativeFunction(target, 'int', ['int', 'int']);
      fn(1, 2);
      if (enterCount !== 1) throw new Error('count=' + enterCount);
      fn(3, 4);
      if (enterCount !== 2) throw new Error('count=' + enterCount);
      listener.detach();
      fn(5, 6);
      if (enterCount !== 2) throw new Error('still firing: ' + enterCount);
    })()
  )";
  EXPECT_TRUE(jsEval(code));
}

// ═══════════════════════════════════════════
// Interceptor — multiple hooks on different functions
// ═══════════════════════════════════════════

TEST_F(ChromaticTest, Interceptor_MultipleHooks) {
  std::string code = R"(
    (() => {
      let addCount = 0;
      let mulCount = 0;

      const addTarget = ptr(')" + ptrHex((void *)&chromatic_test_add) + R"(');
      const mulTarget = ptr(')" + ptrHex((void *)&chromatic_test_mul) + R"(');

      const listener1 = Interceptor.attach(addTarget, {
        onEnter(args) { addCount++; }
      });
      const listener2 = Interceptor.attach(mulTarget, {
        onEnter(args) { mulCount++; }
      });

      const addFn = new NativeFunction(addTarget, 'int', ['int', 'int']);
      const mulFn = new NativeFunction(mulTarget, 'int', ['int', 'int']);

      addFn(1, 2);
      mulFn(3, 4);
      addFn(5, 6);

      if (addCount !== 2) throw new Error('addCount=' + addCount);
      if (mulCount !== 1) throw new Error('mulCount=' + mulCount);

      listener1.detach();
      listener2.detach();

      // After detach, counts should not change
      addFn(7, 8);
      mulFn(9, 10);
      if (addCount !== 2) throw new Error('addCount after detach=' + addCount);
      if (mulCount !== 1) throw new Error('mulCount after detach=' + mulCount);
    })()
  )";
  EXPECT_TRUE(jsEval(code));
}

// ═══════════════════════════════════════════
// Interceptor — original function still works correctly
// ═══════════════════════════════════════════

TEST_F(ChromaticTest, Interceptor_OriginalReturnValue) {
  std::string code = R"(
    (() => {
      let entered = false;
      const target = ptr(')" + ptrHex((void *)&chromatic_test_add) + R"(');
      const listener = Interceptor.attach(target, {
        onEnter(args) { entered = true; }
      });
      const fn = new NativeFunction(target, 'int', ['int', 'int']);
      const result = fn(100, 200);
      if (result !== 300) throw new Error('expected 300, got ' + result);
      if (!entered) throw new Error('onEnter not called');
      listener.detach();
    })()
  )";
  EXPECT_TRUE(jsEval(code));
}

// ═══════════════════════════════════════════
// Interceptor — re-attach after detach
// ═══════════════════════════════════════════

TEST_F(ChromaticTest, Interceptor_ReattachAfterDetach) {
  std::string code = R"(
    (() => {
      let count = 0;
      const target = ptr(')" + ptrHex((void *)&chromatic_test_sub) + R"(');
      const fn = new NativeFunction(target, 'int', ['int', 'int']);

      // First attach
      const listener1 = Interceptor.attach(target, {
        onEnter(args) { count++; }
      });
      fn(10, 3);
      if (count !== 1) throw new Error('first attach count=' + count);

      // Detach
      listener1.detach();
      fn(10, 3);
      if (count !== 1) throw new Error('after detach count=' + count);

      // Re-attach
      const listener2 = Interceptor.attach(target, {
        onEnter(args) { count += 10; }
      });
      fn(10, 3);
      if (count !== 11) throw new Error('re-attach count=' + count);
      listener2.detach();
    })()
  )";
  EXPECT_TRUE(jsEval(code));
}

// ═══════════════════════════════════════════
// Interceptor — onEnter JS throw doesn't crash
// ═══════════════════════════════════════════

TEST_F(ChromaticTest, Interceptor_OnEnterThrowNoCrash) {
  std::string code = R"(
    (() => {
      const target = ptr(')" + ptrHex((void *)&chromatic_test_add) + R"(');
      const listener = Interceptor.attach(target, {
        onEnter(args) {
          throw new Error('intentional throw in onEnter');
        }
      });
      const fn = new NativeFunction(target, 'int', ['int', 'int']);
      // Should not crash — the exception is caught and logged
      const result = fn(5, 10);
      // Original function should still execute and return correct result
      if (result !== 15) throw new Error('expected 15 after throw, got ' + result);
      listener.detach();
    })()
  )";
  EXPECT_TRUE(jsEval(code));
}

// ═══════════════════════════════════════════
// Interceptor — detachAll
// ═══════════════════════════════════════════

TEST_F(ChromaticTest, Interceptor_DetachAll) {
  std::string code = R"(
    (() => {
      let count1 = 0, count2 = 0;
      const target1 = ptr(')" + ptrHex((void *)&chromatic_test_add) + R"(');
      const target2 = ptr(')" + ptrHex((void *)&chromatic_test_mul) + R"(');

      Interceptor.attach(target1, { onEnter(args) { count1++; } });
      Interceptor.attach(target2, { onEnter(args) { count2++; } });

      const fn1 = new NativeFunction(target1, 'int', ['int', 'int']);
      const fn2 = new NativeFunction(target2, 'int', ['int', 'int']);

      fn1(1, 2);
      fn2(3, 4);
      if (count1 !== 1 || count2 !== 1)
        throw new Error('before detachAll: ' + count1 + ',' + count2);

      Interceptor.detachAll();

      fn1(5, 6);
      fn2(7, 8);
      if (count1 !== 1 || count2 !== 1)
        throw new Error('after detachAll: ' + count1 + ',' + count2);
    })()
  )";
  EXPECT_TRUE(jsEval(code));
}

// ═══════════════════════════════════════════
// Context dispose auto-cleanup
// ═══════════════════════════════════════════

TEST_F(ChromaticTest, ContextDispose_AutoDetachHooks) {
  // Create a separate runtime, hook a function, then destroy the runtime.
  // The hook should be automatically detached.

  // First, hook with the current runtime
  std::string hookCode = R"(
    (() => {
      const target = ptr(')" + ptrHex((void *)&chromatic_test_sub) + R"(');
      Interceptor.attach(target, {
        onEnter(args) {}
      });
    })()
  )";
  EXPECT_TRUE(jsEval(hookCode));

  // Reset the runtime — this should auto-detach all hooks
  g_rt->reset();

  // The original function should still work correctly after cleanup
  int result = chromatic_test_sub(50, 20);
  EXPECT_EQ(result, 30);
}

// ═══════════════════════════════════════════
// Memory scan
// ═══════════════════════════════════════════

TEST_F(ChromaticTest, Memory_Scan) {
  EXPECT_TRUE(jsEval(R"(
    (() => {
      const buf = Memory.alloc(64);
      // Write a recognizable pattern
      buf.writeU32(0xDEADBEEF);
      buf.add(4).writeU32(0x00000000);
      buf.add(8).writeU32(0xDEADBEEF);

      // Scan for the pattern
      const results = Memory.scanSync(buf, 64, 'ef be ad de');
      if (!results || results.length < 2)
        throw new Error('expected at least 2 matches, got ' + (results ? results.length : 0));
    })()
  )"));
}

// ═══════════════════════════════════════════
// main
// ═══════════════════════════════════════════

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
