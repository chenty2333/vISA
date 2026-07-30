#include "aot.h"

#include <array>
#include <cerrno>
#include <chrono>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <thread>
#include <unistd.h>

namespace {

constexpr const char *kWitnessEnvironment =
    "VISA_WANCO_IMPORT_WITNESS_NONCE";
constexpr const char *kEnteredPath = "import-entered.txt";
constexpr const char *kReleasePath = "signal-dispatched.txt";
constexpr const char *kObservedPath = "import-release-observed.txt";

[[noreturn]] void fail(const char *message) {
  std::fprintf(stderr, "post-import witness failed: %s: %s\n", message,
               std::strerror(errno));
  std::fflush(stderr);
  std::_Exit(74);
}

void write_exclusive(const char *path, const std::string &contents) {
  const int descriptor =
      ::open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  if (descriptor < 0) {
    fail("open");
  }
  std::size_t offset = 0;
  while (offset < contents.size()) {
    const ssize_t written =
        ::write(descriptor, contents.data() + offset, contents.size() - offset);
    if (written <= 0) {
      const int saved_errno = errno;
      ::close(descriptor);
      errno = saved_errno;
      fail("write");
    }
    offset += static_cast<std::size_t>(written);
  }
  if (::fsync(descriptor) != 0 || ::close(descriptor) != 0) {
    fail("fsync or close");
  }
}

std::string read_release() {
  std::array<char, 256> buffer{};
  const int descriptor = ::open(kReleasePath, O_RDONLY | O_CLOEXEC);
  if (descriptor < 0) {
    fail("open release");
  }
  const ssize_t count = ::read(descriptor, buffer.data(), buffer.size());
  const int saved_errno = errno;
  if (::close(descriptor) != 0 || count <= 0 ||
      static_cast<std::size_t>(count) == buffer.size()) {
    errno = saved_errno;
    fail("read release");
  }
  return std::string(buffer.data(), static_cast<std::size_t>(count));
}

bool canonical_nonce(const std::string &nonce) {
  if (nonce.size() != 64) {
    return false;
  }
  for (const unsigned char value : nonce) {
    if (!std::isdigit(value) && (value < 'a' || value > 'f')) {
      return false;
    }
  }
  return true;
}

} // namespace

extern "C" void checkpoint_window(ExecEnv *) {
  const char *raw_nonce = std::getenv(kWitnessEnvironment);
  const std::string nonce = raw_nonce == nullptr ? "" : raw_nonce;
  if (!nonce.empty()) {
    if (!canonical_nonce(nonce)) {
      errno = EINVAL;
      fail("invalid nonce");
    }
    write_exclusive(kEnteredPath, "entered " + nonce + "\n");
  }

  std::puts("1003");
  std::fflush(stdout);

  if (!nonce.empty()) {
    bool released = false;
    for (int attempt = 0; attempt < 1000; ++attempt) {
      if (::access(kReleasePath, F_OK) == 0) {
        released = true;
        break;
      }
      if (errno != ENOENT) {
        fail("inspect release");
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (!released) {
      errno = ETIMEDOUT;
      fail("wait for release");
    }
    const std::string expected = "signal-dispatched " + nonce + "\n";
    if (read_release() != expected) {
      errno = EINVAL;
      fail("release nonce mismatch");
    }
    write_exclusive(kObservedPath, "release-observed " + nonce + "\n");
  }

  std::puts("1005");
  std::fflush(stdout);
}
