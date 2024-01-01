#include <inttypes.h>

int64_t abs_1(int64_t x) {
  if (x < 0) {
    return -x;
  } else {
    return x;
  }
}

int64_t abs_2(int64_t x) {
  return (x ^ (x >> 63)) + ((x >> 63) & 1);
}
