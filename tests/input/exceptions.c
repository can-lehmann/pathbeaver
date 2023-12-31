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

int32_t sum(int32_t* values, int32_t size) {
  int32_t sum = 0;
  for (int32_t it = 0; it < size; it++) {
    sum += values[it];
  }
  return sum;
}

// OutOfBounds

int out_of_bounds_1() {
  int values[2] = {0, 1};
  return values[2];
}

int out_of_bounds_2(int32_t index) {
  int values[2] = {0, 1};
  return values[index];
}

int32_t out_of_bounds_3() {
  int32_t values[2] = {0, 1};
  return sum(values, 3);
}

int32_t out_of_bounds_4(int32_t x) {
  int32_t values[2] = {0, 1};
  return x == 10 ? values[3] : values[1];
}

int out_of_bounds_5(int32_t index) {
  int values[2] = {0, 1};
  return index < 2 ? values[index] : 0;
}

int out_of_bounds_6(uint32_t index) {
  int values[3] = {0, 1, 2};
  int indices[5] = {1, 2, 0, 3, 2};
  return values[index < 5 ? indices[index] : 0];
}

int no_out_of_bounds_1() {
  int values[2] = {0, 1};
  return values[1];
}

int no_out_of_bounds_2(int32_t index) {
  int values[2] = {0, 1};
  return index >= 0 && index < 2 ? values[index] : 0;
}

int32_t no_out_of_bounds_3() {
  int32_t values[3] = {0, 1, 2};
  return sum(values, 3);
}

// UseAfterFree

int64_t* use_after_free_1_fn() {
  int64_t local = 123;
  return &local;
}

int64_t use_after_free_1() {
  int64_t* local = use_after_free_1_fn();
  return *local;
}

int64_t* use_after_free_2_fn(int32_t x) {
  static int64_t local1 = 123;
  int64_t local2 = 456;
  if (x == 1234567) {
    return &local2;
  } else {
    return &local1;
  }
}

int64_t use_after_free_2(int32_t x) {
  int64_t* local = use_after_free_2_fn(x);
  return *local;
}

const char* no_use_after_free_1_fn() {
  return "Hello";
}

char no_use_after_free_1() {
  const char* str = no_use_after_free_1_fn();
  return *str;
}

int64_t* no_use_after_free_2_fn() {
  static int64_t local = 123;
  return &local;
}

int64_t no_use_after_free_2() {
  int64_t* local = no_use_after_free_2_fn();
  return *local;
}

// DoubleFree

// NullAccess

int64_t null_access_1() {
  int64_t* ptr = NULL;
  return *ptr;
}

unsigned char null_access_2() {
  unsigned char value = 123;
  return *((unsigned char*)(&value - &value));
}
