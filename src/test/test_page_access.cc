// test_page_access.cc — MemoryAccessMonitor tests
#include "test_common.h"

// ════════════════════════════════════════════════════════════════════════
// MemoryAccessMonitor Tests
// ════════════════════════════════════════════════════════════════════════

TEST_F(ChromaticTest, Signal_PageAccess_WriteDetection) {
  SKIP_SIGNAL();
  EXPECT_TRUE(jsEval(R"(
    (() => {
      let accessCount = 0;
      let lastOp = '';

      const buf = Memory.alloc(4096);
      buf.writeU32(0); // Initialize

      const handle = MemoryAccessMonitor.enable(
        [{ address: buf, size: 4096 }],
        (details) => {
          accessCount++;
          lastOp = details.operation;
        }
      );

      // Write to the watched page — triggers SIGSEGV, handled internally
      buf.writeU32(0xDEADBEEF);

      // Drain pending events (fires the callback)
      MemoryAccessMonitor.drain();

      if (accessCount < 1) throw new Error('expected at least 1 access, got ' + accessCount);

      handle.disable();

      // After disable, writes should not trigger (page permissions restored)
      const prevCount = accessCount;
      buf.writeU32(0x12345678);
      MemoryAccessMonitor.drain();
      if (accessCount !== prevCount)
        throw new Error('still firing after disable');

      // Verify data is correct
      if (buf.readU32() !== 0x12345678)
        throw new Error('data corrupted');
    })()
  )"));
}

TEST_F(ChromaticTest, Signal_PageAccess_DisableRestoresPermissions) {
  SKIP_SIGNAL();
  EXPECT_TRUE(jsEval(R"(
    (() => {
      const buf = Memory.alloc(4096);
      buf.writeU32(42);

      const handle = MemoryAccessMonitor.enable(
        [{ address: buf, size: 4096 }],
        (details) => {}
      );

      // Disable the monitor
      handle.disable();

      // Memory should be fully accessible again
      buf.writeU32(0xCAFEBABE);
      if (buf.readU32() !== 0xCAFEBABE)
        throw new Error('memory not accessible after disable');
    })()
  )"));
}

TEST_F(ChromaticTest, Signal_PageAccess_DisableAll) {
  SKIP_SIGNAL();
  EXPECT_TRUE(jsEval(R"(
    (() => {
      const buf1 = Memory.alloc(4096);
      const buf2 = Memory.alloc(4096);
      buf1.writeU32(0);
      buf2.writeU32(0);

      MemoryAccessMonitor.enable(
        [{ address: buf1, size: 4096 }],
        (details) => {}
      );
      MemoryAccessMonitor.enable(
        [{ address: buf2, size: 4096 }],
        (details) => {}
      );

      // Disable all
      MemoryAccessMonitor.disableAll();

      // Both should be accessible
      buf1.writeU32(1);
      buf2.writeU32(2);
      if (buf1.readU32() !== 1 || buf2.readU32() !== 2)
        throw new Error('memory not accessible after disableAll');
    })()
  )"));
}

TEST_F(ChromaticTest, Signal_PageAccess_ReadDetection) {
  SKIP_SIGNAL();
  // Reading from a PROT_NONE page should also trigger the monitor
  EXPECT_TRUE(jsEval(R"(
    (() => {
      let accessCount = 0;

      const buf = Memory.alloc(4096);
      buf.writeU32(0xBEEF); // Initialize before monitoring

      const handle = MemoryAccessMonitor.enable(
        [{ address: buf, size: 4096 }],
        (details) => {
          accessCount++;
        }
      );

      // Read from the watched page — triggers fault on PROT_NONE
      const val = buf.readU32();

      MemoryAccessMonitor.drain();

      if (accessCount < 1)
        throw new Error('expected at least 1 access on read, got ' + accessCount);
      if (val !== 0xBEEF)
        throw new Error('read value corrupted: ' + val);

      handle.disable();
    })()
  )"));
}

TEST_F(ChromaticTest, Signal_PageAccess_OneShotSemantics) {
  SKIP_SIGNAL();
  // After the first access triggers, subsequent accesses should NOT trigger
  // (one-shot mode: permissions restored permanently after first hit)
  EXPECT_TRUE(jsEval(R"(
    (() => {
      let accessCount = 0;

      const buf = Memory.alloc(4096);
      buf.writeU32(0);

      const handle = MemoryAccessMonitor.enable(
        [{ address: buf, size: 4096 }],
        (details) => {
          accessCount++;
        }
      );

      // First write — triggers fault
      buf.writeU32(1);
      MemoryAccessMonitor.drain();
      if (accessCount !== 1)
        throw new Error('first write: expected 1, got ' + accessCount);

      // Second write — permissions already restored, should NOT trigger
      buf.writeU32(2);
      MemoryAccessMonitor.drain();
      if (accessCount !== 1)
        throw new Error('second write should not trigger, got ' + accessCount);

      // Third write — same, no trigger
      buf.writeU32(3);
      MemoryAccessMonitor.drain();
      if (accessCount !== 1)
        throw new Error('third write should not trigger, got ' + accessCount);

      // Verify final value
      if (buf.readU32() !== 3) throw new Error('data corrupted');

      handle.disable();
    })()
  )"));
}

TEST_F(ChromaticTest, Signal_PageAccess_MultiRange) {
  SKIP_SIGNAL();
  // Multiple ranges in a single enable() call, check rangeIndex
  EXPECT_TRUE(jsEval(R"(
    (() => {
      let events = [];

      const buf1 = Memory.alloc(4096);
      const buf2 = Memory.alloc(4096);
      buf1.writeU32(0);
      buf2.writeU32(0);

      const handle = MemoryAccessMonitor.enable(
        [
          { address: buf1, size: 4096 },
          { address: buf2, size: 4096 }
        ],
        (details) => {
          events.push({ rangeIndex: details.rangeIndex });
        }
      );

      // Access range 0
      buf1.writeU32(0xAAAA);
      MemoryAccessMonitor.drain();

      // Access range 1
      buf2.writeU32(0xBBBB);
      MemoryAccessMonitor.drain();

      if (events.length < 2)
        throw new Error('expected 2 events, got ' + events.length);

      // Verify rangeIndex values
      const indices = events.map(e => e.rangeIndex).sort();
      if (indices[0] !== 0 || indices[1] !== 1)
        throw new Error('rangeIndex mismatch: ' + JSON.stringify(indices));

      // Verify data
      if (buf1.readU32() !== 0xAAAA) throw new Error('buf1 corrupted');
      if (buf2.readU32() !== 0xBBBB) throw new Error('buf2 corrupted');

      handle.disable();
    })()
  )"));
}

TEST_F(ChromaticTest, Signal_PageAccess_DrainReturnsCount) {
  SKIP_SIGNAL();
  EXPECT_TRUE(jsEval(R"(
    (() => {
      const buf = Memory.alloc(4096);
      buf.writeU32(0);

      const handle = MemoryAccessMonitor.enable(
        [{ address: buf, size: 4096 }],
        (details) => {}
      );

      // No access yet — drain should return 0
      const before = MemoryAccessMonitor.drain();
      if (before !== 0)
        throw new Error('expected 0 drained before access, got ' + before);

      // Trigger access
      buf.writeU32(1);

      const after = MemoryAccessMonitor.drain();
      if (after !== 1)
        throw new Error('expected 1 drained after access, got ' + after);

      // Drain again — should be 0 (already consumed)
      const again = MemoryAccessMonitor.drain();
      if (again !== 0)
        throw new Error('expected 0 on second drain, got ' + again);

      handle.disable();
    })()
  )"));
}

TEST_F(ChromaticTest, Signal_PageAccess_DisableIdempotent) {
  SKIP_SIGNAL();
  // Calling disable() multiple times should not crash
  EXPECT_TRUE(jsEval(R"(
    (() => {
      const buf = Memory.alloc(4096);
      buf.writeU32(0);

      const handle = MemoryAccessMonitor.enable(
        [{ address: buf, size: 4096 }],
        (details) => {}
      );

      handle.disable();
      handle.disable(); // second disable — should be a no-op
    })()
  )"));
}

TEST_F(ChromaticTest, Signal_PageAccess_DataIntegrity) {
  SKIP_SIGNAL();
  // Verify that monitoring doesn't corrupt existing data
  EXPECT_TRUE(jsEval(R"(
    (() => {
      const buf = Memory.alloc(4096);
      // Write a pattern before monitoring
      for (let i = 0; i < 16; i++) {
        buf.add(i * 4).writeU32(i * 0x11111111);
      }

      const handle = MemoryAccessMonitor.enable(
        [{ address: buf, size: 4096 }],
        (details) => {}
      );

      // Read all values back (triggers one-shot fault on first access)
      const val0 = buf.add(0).readU32();
      MemoryAccessMonitor.drain();

      // After one-shot, rest should be normal reads
      for (let i = 0; i < 16; i++) {
        const expected = (i * 0x11111111) >>> 0;
        const actual = buf.add(i * 4).readU32();
        if (actual !== expected)
          throw new Error('offset ' + (i*4) + ': expected 0x' +
            expected.toString(16) + ', got 0x' + actual.toString(16));
      }

      handle.disable();
    })()
  )"));
}

TEST_F(ChromaticTest, Signal_PageAccess_MultipleMonitors) {
  SKIP_SIGNAL();
  // Multiple independent monitors on different buffers
  EXPECT_TRUE(jsEval(R"(
    (() => {
      let count1 = 0, count2 = 0;

      const buf1 = Memory.alloc(4096);
      const buf2 = Memory.alloc(4096);
      buf1.writeU32(0);
      buf2.writeU32(0);

      const h1 = MemoryAccessMonitor.enable(
        [{ address: buf1, size: 4096 }],
        (details) => { count1++; }
      );
      const h2 = MemoryAccessMonitor.enable(
        [{ address: buf2, size: 4096 }],
        (details) => { count2++; }
      );

      // Access only buf1
      buf1.writeU32(1);
      MemoryAccessMonitor.drain();

      if (count1 < 1) throw new Error('monitor1 not triggered');
      if (count2 !== 0) throw new Error('monitor2 triggered unexpectedly');

      // Access buf2
      buf2.writeU32(2);
      MemoryAccessMonitor.drain();

      if (count2 < 1) throw new Error('monitor2 not triggered');

      h1.disable();
      h2.disable();
    })()
  )"));
}
