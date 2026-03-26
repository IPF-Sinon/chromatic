// Stress tests for breeze-js event loop / post_sync reliability
#include "test_common.h"

// Rapid-fire eval: many sequential evals to stress the post_sync path
TEST_F(ChromaticTest, Stress_RapidEval) {
  for (int i = 0; i < 200; i++) {
    ASSERT_TRUE(jsEval("(() => { return 1 + 1; })()"))
        << "Failed at iteration " << i;
  }
}

// Async stress: many sequential async evals
TEST_F(ChromaticTest, Stress_RapidAsyncEval) {
  for (int i = 0; i < 100; i++) {
    ASSERT_TRUE(jsEval("(async () => { return 42; })()"))
        << "Failed at iteration " << i;
  }
}

// Mixed sync/async to stress event loop wake-up
TEST_F(ChromaticTest, Stress_MixedSyncAsync) {
  for (int i = 0; i < 100; i++) {
    if (i % 2 == 0) {
      ASSERT_TRUE(jsEval("(() => { return 'sync'; })()"))
          << "Sync failed at iteration " << i;
    } else {
      ASSERT_TRUE(jsEval("(async () => { return 'async'; })()"))
          << "Async failed at iteration " << i;
    }
  }
}
