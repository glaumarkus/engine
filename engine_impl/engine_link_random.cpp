#include "engine_link.h"
#include <openssl/rand.h>
#include "src/random/sw_random.hpp"

void rand_cleanup() 
{
  Factory::SoftwareImpl::SwRandom rng;
  rng.Cleanup();
}
int rand_bytes(unsigned char *buf, int num) {
  Factory::SoftwareImpl::SwRandom rng;
  return rng.RandomBytes(buf, num);
}
int random_status() { 
  Factory::SoftwareImpl::SwRandom rng;
  return rng.RandomStatus();
}
int set_seed() {
  Factory::SoftwareImpl::SwRandom rng;
  return rng.SetSeed();
 }