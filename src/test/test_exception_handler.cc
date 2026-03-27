// test_exception_handler.cc — Exception handler tests
#include "test_common.h"

TEST_F(ChromaticTest, Signal_ExceptionHandler_EnableDisable) {
  SKIP_SIGNAL();
  EXPECT_TRUE(jsEval(R"(
    (() => {
      ExceptionHandler.enable();
      if (!ExceptionHandler.isEnabled) throw new Error('not enabled');
      ExceptionHandler.disable();
      if (ExceptionHandler.isEnabled) throw new Error('still enabled');
    })()
  )"));
}

TEST_F(ChromaticTest, Signal_ExceptionHandler_IdempotentEnable) {
  SKIP_SIGNAL();
  EXPECT_TRUE(jsEval(R"(
    (() => {
      ExceptionHandler.enable();
      ExceptionHandler.enable();
      ExceptionHandler.disable();
      ExceptionHandler.disable();
      // No crash = success
    })()
  )"));
}

TEST_F(ChromaticTest, Signal_ExceptionHandler_ProtectRoundTrip) {
  SKIP_SIGNAL();
  // This test demonstrates the original crash scenario from the issue:
  // Memory.protect to read-only, then write → should not crash if
  // exception handler catches it. Here we just test the safe path.
  EXPECT_TRUE(jsEval(R"(
    (() => {
      ExceptionHandler.enable();
      const p = Memory.alloc(4096);
      // Make writable, write, verify
      Memory.protect(p, 4096, 'rw');
      p.writeU32(42);
      if (p.readU32() !== 42) throw new Error('write/read failed');
      ExceptionHandler.disable();
    })()
  )"));
}
