#include "engine_link.h"
#include <openssl/rand.h>

void rand_cleanup() {}
int rand_bytes(unsigned char *buf, int num) {
  RAND_bytes(buf, num);
  return 1;
}
int random_status() { return 1; }
int set_seed() { return 1; }