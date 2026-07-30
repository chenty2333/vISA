#include "aot.h"

#include <chrono>
#include <cstdio>
#include <thread>

extern "C" void checkpoint_window(ExecEnv *) {
  std::puts("1003");
  std::fflush(stdout);
  std::this_thread::sleep_for(std::chrono::seconds(2));
}
