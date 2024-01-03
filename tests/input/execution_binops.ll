; Copyright 2023 Can Joshua Lehmann
;
; Licensed under the Apache License, Version 2.0 (the "License");
; you may not use this file except in compliance with the License.
; You may obtain a copy of the License at
;
;     http://www.apache.org/licenses/LICENSE-2.0
;
; Unless required by applicable law or agreed to in writing, software
; distributed under the License is distributed on an "AS IS" BASIS,
; WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
; See the License for the specific language governing permissions and
; limitations under the License.

; Binary Operators i32

define i32 @binop_add_i32(i32 %a, i32 %b) {
  %c = add i32 %a, %b
  ret i32 %c
}

define i32 @binop_sub_i32(i32 %a, i32 %b) {
  %c = sub i32 %a, %b
  ret i32 %c
}

define i32 @binop_mul_i32(i32 %a, i32 %b) {
  %c = mul i32 %a, %b
  ret i32 %c
}

define i32 @binop_and_i32(i32 %a, i32 %b) {
  %c = and i32 %a, %b
  ret i32 %c
}

define i32 @binop_or_i32(i32 %a, i32 %b) {
  %c = or i32 %a, %b
  ret i32 %c
}

define i32 @binop_xor_i32(i32 %a, i32 %b) {
  %c = xor i32 %a, %b
  ret i32 %c
}

define i32 @binop_ashr_i32(i32 %a, i32 %b) {
  %shift = and i32 %b, 31
  %c = ashr i32 %a, %shift
  ret i32 %c
}

define i32 @binop_lshr_i32(i32 %a, i32 %b) {
  %shift = and i32 %b, 31
  %c = lshr i32 %a, %shift
  ret i32 %c
}

define i32 @binop_shl_i32(i32 %a, i32 %b) {
  %shift = and i32 %b, 31
  %c = shl i32 %a, %shift
  ret i32 %c
}

; Binary Operators i64

define i64 @binop_add_i64(i64 %a, i64 %b) {
  %c = add i64 %a, %b
  ret i64 %c
}

define i64 @binop_sub_i64(i64 %a, i64 %b) {
  %c = sub i64 %a, %b
  ret i64 %c
}

define i64 @binop_mul_i64(i64 %a, i64 %b) {
  %c = mul i64 %a, %b
  ret i64 %c
}

define i64 @binop_and_i64(i64 %a, i64 %b) {
  %c = and i64 %a, %b
  ret i64 %c
}

define i64 @binop_or_i64(i64 %a, i64 %b) {
  %c = or i64 %a, %b
  ret i64 %c
}

define i64 @binop_xor_i64(i64 %a, i64 %b) {
  %c = xor i64 %a, %b
  ret i64 %c
}

define i64 @binop_ashr_i64(i64 %a, i64 %b) {
  %shift = and i64 %b, 63
  %c = ashr i64 %a, %shift
  ret i64 %c
}

define i64 @binop_lshr_i64(i64 %a, i64 %b) {
  %shift = and i64 %b, 63
  %c = lshr i64 %a, %shift
  ret i64 %c
}

define i64 @binop_shl_i64(i64 %a, i64 %b) {
  %shift = and i64 %b, 63
  %c = shl i64 %a, %shift
  ret i64 %c
}

