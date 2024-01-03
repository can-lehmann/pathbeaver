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

; Vector Instructions

define i32 @vector_insert_extract_1(i32 %a) {
  %1 = insertelement <4 x i32> undef, i32 %a, i32 0
  %2 = extractelement <4 x i32> %1, i32 0
  ret i32 %2
}

define i32 @vector_insert_extract_2(i32 %a, i32 %b, i32 %c, i32 %d) {
  %1 = insertelement <4 x i32> undef, i32 %a, i32 0
  %2 = insertelement <4 x i32> %1, i32 %b, i32 1
  %3 = insertelement <4 x i32> %2, i32 %c, i32 2
  %4 = insertelement <4 x i32> %3, i32 %d, i32 3
  %r1 = extractelement <4 x i32> %4, i32 0
  %r2 = extractelement <4 x i32> %4, i32 1
  %r3 = extractelement <4 x i32> %4, i32 2
  %r4 = extractelement <4 x i32> %4, i32 3
  %sum1 = add i32 %r1, %r2
  %sum2 = add i32 %r3, %r4
  %sum = add i32 %sum1, %sum2
  ret i32 %sum
}

define i32 @vector_shuffle_1(i32 %a) {
  %1 = insertelement <4 x i32> undef, i32 %a, i32 0
  %2 = shufflevector <4 x i32> %1, <4 x i32> undef, <4 x i32> <i32 undef, i32 undef, i32 undef, i32 0>
  %3 = extractelement <4 x i32> %2, i32 3
  ret i32 %3
}

define i32 @vector_shuffle_2(i32 %a) {
  %1 = insertelement <4 x i32> undef, i32 %a, i32 0
  %2 = shufflevector <4 x i32> undef, <4 x i32> %1, <2 x i32> <i32 undef, i32 4>
  %3 = extractelement <2 x i32> %2, i32 1
  ret i32 %3
}

define i32 @vector_memory_1(i32 %a) {
  %1 = alloca <4 x i32>, align 16
  %2 = load <4 x i32>, ptr %1, align 16
  %3 = insertelement <4 x i32> %2, i32 %a, i32 0
  store <4 x i32> %3, ptr %1, align 16
  %4 = load <4 x i32>, ptr %1, align 16
  %5 = extractelement <4 x i32> %4, i32 0
  ret i32 %5
}

define i32 @vector_memory_2(i32 %a) {
  %1 = alloca <4 x i32>, align 16
  %2 = insertelement <4 x i32> undef, i32 %a, i32 0
  store <4 x i32> %2, ptr %1, align 16
  %3 = load <4 x i32>, ptr %1, align 16
  %4 = extractelement <4 x i32> %3, i32 0
  ret i32 %4
}

define i32 @vector_memory_3(i32 %a) {
  %1 = alloca <4 x i32>, align 16
  %2 = insertelement <4 x i32> undef, i32 %a, i32 0
  store <4 x i32> %2, ptr %1, align 16
  %3 = load i32, ptr %1
  ret i32 %3
}

define i32 @vector_memory_4(i32 %a) {
  %1 = alloca <4 x i32>, align 16
  %2 = insertelement <4 x i32> undef, i32 %a, i32 1
  store <4 x i32> %2, ptr %1, align 16
  %3 = getelementptr <4 x i32>, ptr %1, i32 0, i32 1
  %4 = load i32, ptr %3
  ret i32 %4
}

; Intrinsic not supported by the interpreter
; declare i32 @llvm.vector.reduce.add.v4i32(<4 x i32>)
; define i32 @vector_reduce_add_1_trace_only(i32 %a, i32 %b, i32 %c, i32 %d) {
;   %1 = insertelement <4 x i32> undef, i32 %a, i32 0
;   %2 = insertelement <4 x i32> %1, i32 %b, i32 1
;   %3 = insertelement <4 x i32> %2, i32 %c, i32 2
;   %4 = insertelement <4 x i32> %3, i32 %d, i32 3
;   %sum = call i32 @llvm.vector.reduce.add.v4i32(<4 x i32> %4)
;   ret i32 %sum
; }


