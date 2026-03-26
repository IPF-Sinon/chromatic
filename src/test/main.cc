// main.cc — gtest entry point + C function definitions
#include "test_common.h"

// ── C functions for hooking/calling from JS ──
// These are defined here (once) and declared extern in test_common.h
// noinline + optnone to ensure the functions have a proper prologue
// that the interceptor can disassemble and hook in release builds.

#ifdef __GNUC__
#define CHROMATIC_NOINLINE __attribute__((noinline, optnone))
#elif defined(_MSC_VER)
#define CHROMATIC_NOINLINE __declspec(noinline)
#else
#define CHROMATIC_NOINLINE
#endif

extern "C" CHROMATIC_NOINLINE int chromatic_test_add(int a, int b) { return a + b; }
extern "C" CHROMATIC_NOINLINE int chromatic_test_mul(int a, int b) { return a * b; }
extern "C" CHROMATIC_NOINLINE int chromatic_test_sub(int a, int b) { return a - b; }

static int g_side_effect = 0;
extern "C" void chromatic_test_set_global(int v) { g_side_effect = v; }
extern "C" int chromatic_test_get_global() { return g_side_effect; }

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
