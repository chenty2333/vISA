#include "aot.h"

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace {

int event_fd = -1;
bool canonical_bound = false;

std::string env_or_empty(char const *name) {
  char const *value = std::getenv(name);
  return value == nullptr ? std::string{} : std::string{value};
}

bool write_all(int fd, void const *data, std::size_t size) {
  auto const *cursor = static_cast<std::uint8_t const *>(data);
  while (size != 0) {
    ssize_t const written = ::write(fd, cursor, size);
    if (written < 0) {
      if (errno == EINTR) {
        continue;
      }
      return false;
    }
    cursor += written;
    size -= static_cast<std::size_t>(written);
  }
  return true;
}

void append_event(std::string const &line);

bool canonical_enabled() {
  return !env_or_empty("VISA_HA_CANONICAL_SOCKET").empty();
}

bool safe_wire_field(std::string_view value) {
  return !value.empty() && value.find('\t') == std::string_view::npos &&
         value.find('\n') == std::string_view::npos &&
         value.find('\r') == std::string_view::npos;
}

void append_binding_error(std::int32_t progress, std::string_view stage, int error);

bool wait_for_destination_resume(std::int32_t progress) {
  if (progress != 5 || env_or_empty("VISA_HA_ENDPOINT_ROLE") != "destination") {
    return true;
  }
  std::string const gate = env_or_empty("VISA_HA_RESUME_GATE");
  if (gate.empty()) {
    errno = EINVAL;
    append_binding_error(progress, "missing-resume-gate", errno);
    return false;
  }
  for (std::uint32_t attempt = 0; attempt < 30000; ++attempt) {
    if (::access(gate.c_str(), F_OK) == 0) {
      return true;
    }
    if (errno != ENOENT) {
      append_binding_error(progress, "inspect-resume-gate", errno);
      return false;
    }
    ::usleep(1000);
  }
  errno = ETIMEDOUT;
  append_binding_error(progress, "resume-gate-timeout", errno);
  return false;
}

bool canonical_call(std::string request, std::string_view expected_event) {
  std::string const socket_path = env_or_empty("VISA_HA_CANONICAL_SOCKET");
  sockaddr_un address {};
  if (socket_path.empty() || socket_path.size() >= sizeof(address.sun_path)) {
    errno = EINVAL;
    return false;
  }
  int const fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    return false;
  }
  address.sun_family = AF_UNIX;
  std::memcpy(address.sun_path, socket_path.c_str(), socket_path.size() + 1);
  if (::connect(fd, reinterpret_cast<sockaddr *>(&address), sizeof(address)) != 0) {
    int const saved = errno;
    ::close(fd);
    errno = saved;
    return false;
  }
  request.push_back('\n');
  if (!write_all(fd, request.data(), request.size()) || ::shutdown(fd, SHUT_WR) != 0) {
    int const saved = errno;
    ::close(fd);
    errno = saved;
    return false;
  }
  std::string response;
  std::array<char, 4096> chunk {};
  while (true) {
    ssize_t count = ::read(fd, chunk.data(), chunk.size());
    if (count < 0 && errno == EINTR) {
      continue;
    }
    if (count < 0) {
      int const saved = errno;
      ::close(fd);
      errno = saved;
      return false;
    }
    if (count == 0) {
      break;
    }
    response.append(chunk.data(), static_cast<std::size_t>(count));
    if (response.size() > 4 * 1024 * 1024) {
      ::close(fd);
      errno = EOVERFLOW;
      return false;
    }
  }
  ::close(fd);
  if (!response.empty() && response.back() == '\n') {
    response.pop_back();
  }
  if (response.empty() || response.find('\n') != std::string::npos) {
    errno = EPROTO;
    return false;
  }
  append_event(response);
  std::string prefix(expected_event);
  prefix.push_back('\t');
  if (!response.starts_with(prefix)) {
    errno = EIO;
    return false;
  }
  return true;
}

std::string canonical_request_prefix(std::string_view operation,
                                     std::int32_t progress,
                                     std::int32_t is_start) {
  std::string const role = env_or_empty("VISA_HA_ENDPOINT_ROLE");
  std::string const case_name = env_or_empty("VISA_HA_CASE");
  if (!safe_wire_field(role) || !safe_wire_field(case_name)) {
    errno = EINVAL;
    return {};
  }
  return std::string(operation) + "\t" + role + "\t" + case_name + "\t" +
         std::to_string(progress) + "\t" + std::to_string(is_start);
}

void append_event(std::string const &line) {
  if (event_fd < 0) {
    std::string const path = env_or_empty("VISA_HA_EVENT_LOG");
    if (path.empty()) {
      return;
    }
    event_fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (event_fd < 0) {
      return;
    }
  }
  std::string record = line;
  record.push_back('\n');
  if (write_all(event_fd, record.data(), record.size())) {
    ::fsync(event_fd);
  }
}

std::string hex_bytes(std::vector<std::uint8_t> const &bytes) {
  static constexpr char digits[] = "0123456789abcdef";
  std::string encoded;
  encoded.reserve(bytes.size() * 2);
  for (std::uint8_t byte : bytes) {
    encoded.push_back(digits[byte >> 4]);
    encoded.push_back(digits[byte & 0x0f]);
  }
  return encoded;
}

void append_binding_error(std::int32_t progress, std::string_view stage, int error) {
  append_event("BINDING_ERROR\t" + std::to_string(progress) + "\t" +
               std::string(stage) + "\t" + std::to_string(error));
}

bool ensure_resource(std::int32_t progress, bool is_start) {
  if (!canonical_enabled()) {
    errno = ENOTCONN;
    append_binding_error(progress, "lost-process-local-binding", errno);
    return false;
  }
  if (canonical_bound) {
    return true;
  }
  std::string request = canonical_request_prefix("OPEN", progress, is_start ? 1 : 0);
  if (request.empty() || !canonical_call(std::move(request), "OPEN")) {
    return false;
  }
  canonical_bound = true;
  return true;
}

void append_operation_error(std::int32_t progress, std::string_view operation_id,
                            std::uint32_t attempt, std::string_view operation_kind,
                            std::string_view stage, int error, bool retryable,
                            std::string_view request_value,
                            std::string_view durability) {
  append_event("ERROR\t" + std::to_string(progress) + "\t" +
               std::string(operation_id) + "\t" + std::to_string(attempt) + "\t" +
               std::string(operation_kind) + "\t" + std::string(stage) + "\t" +
               std::to_string(error) + "\t" + (retryable ? "1" : "0") + "\t" +
               std::string(request_value) + "\t" + std::string(durability));
}

int read_operation(std::int32_t progress, std::string_view operation_id,
                   std::uint32_t attempt, std::uint32_t max_bytes) {
  if (!safe_wire_field(operation_id)) {
    errno = EINVAL;
    return errno;
  }
  std::string request = canonical_request_prefix("READ", progress, 0);
  request += "\t" + std::string(operation_id) + "\t" + std::to_string(attempt) +
             "\t" + std::to_string(max_bytes);
  return canonical_call(std::move(request), "READ") ? 0 : (errno == 0 ? EIO : errno);
}

int write_operation(std::int32_t progress) {
  std::string request = canonical_request_prefix("WRITE", progress, 0);
  request += "\twrite-middle\t0\t5859\tvisible";
  return canonical_call(std::move(request), "WRITE") ? 0 : (errno == 0 ? EIO : errno);
}

int append_operation(std::int32_t progress, std::string_view operation_id,
                     std::uint32_t attempt, std::uint8_t byte, bool replay) {
  if (!safe_wire_field(operation_id)) {
    errno = EINVAL;
    return errno;
  }
  std::vector<std::uint8_t> appended = {byte};
  std::string request = canonical_request_prefix("APPEND", progress, 0);
  request += "\t" + std::string(operation_id) + "\t" + std::to_string(attempt) +
             "\t" + hex_bytes(appended) + "\tvisible";
  std::string_view expected = replay ? "APPEND_REPLAY" : "APPEND";
  return canonical_call(std::move(request), expected) ? 0 : (errno == 0 ? EIO : errno);
}

} // namespace

extern "C" std::int32_t visa_ha_regular_file_step(ExecEnv *, std::int32_t progress,
                                                  std::int32_t is_start) {
  append_event("CALL\t" + std::to_string(progress) + "\t" +
               std::to_string(is_start));
  int result = 0;
  if (!wait_for_destination_resume(progress)) {
    result = errno == 0 ? EIO : errno;
  } else if (progress == 0 || progress == 1 || progress == 12) {
    if (!ensure_resource(progress, is_start != 0)) {
      result = errno == 0 ? EIO : errno;
      std::string_view const operation_id =
          progress == 0 ? "read-prefix" : (progress == 1 ? "write-middle" : "read-suffix");
      std::string_view const operation_kind = progress == 1 ? "write" : "read";
      append_operation_error(progress, operation_id, 0, operation_kind,
                             "lost-process-local-binding", result, false,
                             progress == 1 ? "5859" : (progress == 0 ? "2" : "4"),
                             progress == 1 ? "visible" : "-");
    } else if (progress == 0) {
      std::uint8_t ignored = 0;
      errno = 0;
      ssize_t const transient = ::read(-1, &ignored, 1);
      int const transient_error = transient < 0 ? errno : EIO;
      append_operation_error(progress, "read-prefix", 0, "read",
                             "transient-invalid-fd", transient_error, true, "2", "-");
      result = read_operation(progress, "read-prefix", 1, 2);
    } else if (progress == 1) {
      result = write_operation(progress);
    } else {
      result = read_operation(progress, "read-suffix", 0, 4);
    }
  }
  append_event("RETURN\t" + std::to_string(progress) + "\t" +
               std::to_string(result));
  return result;
}

extern "C" std::int32_t visa_ha_append_step(ExecEnv *, std::int32_t progress,
                                            std::int32_t is_start) {
  append_event("CALL\t" + std::to_string(progress) + "\t" +
               std::to_string(is_start));
  int result = 0;
  if (!wait_for_destination_resume(progress)) {
    result = errno == 0 ? EIO : errno;
  } else if (progress == 0 || progress == 1 || progress == 12) {
    if (!ensure_resource(progress, is_start != 0)) {
      result = errno == 0 ? EIO : errno;
      std::string_view const operation_id =
          progress == 12 ? "append-destination" : "append-source";
      append_operation_error(progress, operation_id, progress == 1 ? 1 : 0, "append",
                             "lost-process-local-binding", result, false,
                             progress == 12 ? "44" : "53", "visible");
    } else {
      if (progress == 0) {
        result = append_operation(progress, "append-source", 0, 'S', false);
      } else if (progress == 1) {
        result = append_operation(progress, "append-source", 1, 'S', true);
      } else {
        result = append_operation(progress, "append-destination", 0, 'D', false);
      }
    }
  }
  append_event("RETURN\t" + std::to_string(progress) + "\t" +
               std::to_string(result));
  return result;
}
