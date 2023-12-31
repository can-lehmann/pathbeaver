// Copyright 2023 Can Joshua Lehmann
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <stdlib.h>
#include <inttypes.h>
#include <stdbool.h>

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

int64_t abs_3(int64_t x) {
  return x < 0 ? -x : x;
}

bool parity_1(uint16_t x) {
  bool parity = false;
  for (size_t it = 0; it < sizeof(x) * 8; it++) {
    if (x & (1 << it)) {
      parity = !parity;
    }
  }
  return parity;
}

bool parity_2(uint16_t x) {
  size_t ones = 0;
  for (size_t it = sizeof(x) * 8; it-- > 0; ) {
    if ((x >> it) & 1) {
      ones++;
    }
  }
  return ones & 1;
}

bool parity_3(uint16_t x) {
  for (int it = 8; it != 0; it >>= 1) {
    x = (x >> it) ^ x;
  }
  return x & 1;
}

void binstr(char* str, size_t size, uint64_t value) {
  for (size_t it = 0; it < size; it++) {
    size_t idx = size - it - 1;
    if (value & 1) {
      str[idx] = '1';
    } else {
      str[idx] = '0';
    }
    value >>= 1;
  }
}

bool parity_4(uint16_t x) {
  char bits[sizeof(x) * 8];
  binstr(bits, sizeof(x) * 8, x);
  
  bool parity = false;
  for (size_t it = 0; it < sizeof(x) * 8; it++) {
    if (bits[it] == '1') {
      parity = !parity;
    }
  }
  return parity;
}

bool parity_5(uint16_t x) {
  uint64_t y = x;
  y <<= 64 - 16;
  bool parity = false;
  for (size_t it = 0; it < sizeof(y) * 8; it++) {
    if (y & (1UL << it)) {
      parity = !parity;
    }
  }
  return parity;
}

int popcount_1(uint16_t x) {
  int count = 0;
  for (int it = 0; it < sizeof(x) * 8; it++) {
    if (x & (1 << it)) {
      count++;
    }
  }
  return count;
}

int popcount_2(uint16_t x) {
  // See https://en.wikipedia.org/wiki/Hamming_weight for an explanation
  // of this approach
  x = (x & 0x5555) + ((x >> 1) & 0x5555);
  x = (x & 0x3333) + ((x >> 2) & 0x3333);
  x = (x & 0x0f0f) + ((x >> 4) & 0x0f0f);
  x = (x & 0x00ff) + ((x >> 8) & 0x00ff);
  return x;
}

int popcount_3(uint16_t x) {
  // See https://en.wikipedia.org/wiki/Hamming_weight for an explanation
  // of this approach
  x = (x & 0x5555) + ((x >> 1) & 0x5555);
  x = (x & 0x3333) + ((x >> 2) & 0x3333);
  x = (x & 0x0f0f) + ((x >> 4) & 0x0f0f);
  uint8_t* vals = (uint8_t*)&x;
  return vals[0] + vals[1];
}

int popcount_4_rec(uint16_t x, size_t size) {
  if (size == 1) {
    return x & 1;
  } else {
    size_t half = size >> 1;
    return popcount_4_rec(x, half) + popcount_4_rec(x >> half, half);
  }
}

int popcount_4(uint16_t x) {
  return popcount_4_rec(x, sizeof(x) * 8);
}

void swap_1(int32_t* a, int32_t* b) {
  int32_t temp = *a;
  *a = *b;
  *b = temp;
}

void swap_2(int32_t* a, int32_t* b) {
  *a ^= *b;
  *b ^= *a;
  *a ^= *b;
}

int32_t sum_1(int32_t* values, uint32_t size) {
  int32_t sum = 0;
  for (uint32_t it = 0; it < size; it++) {
    sum += values[it];
  }
  return sum;
}

int32_t sum_2(int32_t* values, uint32_t size) {
  if (size == 0) {
    return 0;
  } else if (size == 1) {
    return *values;
  } else {
    uint32_t split = (size >> 1);
    int32_t left = sum_2(values, split);
    int32_t right = sum_2(values + split, size - split);
    return left + right;
  }
}

int32_t sum_3(int32_t* values, uint32_t size) {
  switch (size) {
    case 0: return 0;
    case 1: return *values;
    default: {
      uint32_t split = (size >> 1);
      int32_t left = sum_3(values, split);
      int32_t right = sum_3(values + split, size - split);
      return left + right;
    }
  }
}

bool is_sorted(int32_t* values, uint32_t size) {
  for (uint32_t it = 0; it + 1 < size; it++) {
    if (values[it] > values[it + 1]) {
      return false;
    }
  }
  return true;
}

void sort_1(int32_t* values, uint32_t size) {
  for (uint32_t upper = size; upper-- > 1; ) {
    for (uint32_t it = 0; it < upper; it++) {
      if (values[it] > values[it + 1]) {
        swap_1(values + it, values + it + 1);
      }
    }
  }
}

void sort_2(int32_t* values, uint32_t size) {
  for (uint32_t upper = size; upper-- > 1; ) {
    uint32_t max_idx = 0;
    for (uint32_t it = 1; it <= upper; it++) {
      if (values[it] > values[max_idx]) {
        max_idx = it;
      }
    }
    
    if (max_idx != upper) {
      swap_1(values + max_idx, values + upper);
    }
  }
}

bool sort_1_is_sorted(int32_t* values, uint32_t size) {
  sort_1(values, size);
  return is_sorted(values, size);
}

bool sort_2_is_sorted(int32_t* values, uint32_t size) {
  sort_2(values, size);
  return is_sorted(values, size);
}

void subst_1_apply(uint8_t* message, uint32_t size, uint8_t* table) {
  for (size_t it = 0; it < size; it++) {
    message[it] = table[message[it]];
  }
}

void subst_1_invert_table(uint8_t* table, uint8_t* inv_table) {
  for (size_t it = 0; it < 256; it++) {
    inv_table[table[it]] = it;
  }
}

void subst_1(uint8_t* message, uint32_t size, uint8_t* table) {
  uint8_t inv_table[256];
  subst_1_apply(message, size, table);
  subst_1_invert_table(table, inv_table);
  subst_1_apply(message, size, inv_table);
}

void binstr_wrong_1(char* str, size_t size, uint64_t value) {
  for (size_t it = 0; it < size; it++) {
    size_t idx = size - it;
    if (value & 1) {
      str[idx] = '1';
    } else {
      str[idx] = '0';
    }
    value >>= 1;
  }
}
