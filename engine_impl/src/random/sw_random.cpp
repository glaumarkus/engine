#include "sw_random.hpp"
#include <openssl/rand.h>

namespace Factory {
namespace SoftwareImpl {

void SwRandom::Cleanup() noexcept {}

int SwRandom::RandomBytes(unsigned char *buf, int num) noexcept {
  return RAND_bytes(buf, num);
}

int SwRandom::RandomStatus() noexcept { return 1; }

int SwRandom::SetSeed() noexcept { return 1; }

} // namespace SoftwareImpl
} // namespace Factory
