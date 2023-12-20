#include <inttypes.h>

int popcount_simple(uint32_t x) {
  int count = 0;
  for (int it = 0; it < sizeof(uint32_t) * 8; it++) {
    if (x & (1 << it)) {
      count++;
    }
  }
  return count;
}

int popcount_fast(uint32_t x) {
  // See https://en.wikipedia.org/wiki/Hamming_weight for an explanation
  // of this approach
  x = (x & 0x55555555) + ((x >> 1) & 0x55555555);
  x = (x & 0x33333333) + ((x >> 2) & 0x33333333);
  x = (x & 0x0f0f0f0f) + ((x >> 4) & 0x0f0f0f0f);
  x = (x & 0x00ff00ff) + ((x >> 8) & 0x00ff00ff);
  x = (x & 0x0000ffff) + ((x >> 16) & 0x0000ffff);
  return x;
}

