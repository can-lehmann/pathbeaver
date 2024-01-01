# Pathbeaver

Pathbeaver is a symbolic execution engine for LLVM IR.
Its main application is hardware/software equivalence checking.

Take a look at these two implementations of the absolute value function.
We can use pathbeaver to prove that they are equivalent.

```c
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
```

We use pathbeaver to execute both functions on a symbolic input.

```cpp
hdl::Value* x = module.input("x", 64);

pathbeaver::Trace trace(module, globals);
pathbeaver::Value ret_a = trace.trace_simple(llvm_module->getFunction("abs_1"), {x});
pathbeaver::Value ret_b = trace.trace_simple(llvm_module->getFunction("abs_2"), {x});
```

Then we prove the equivalence of the resulting traces using Z3:

```cpp
z3::context context;
z3::solver solver(context);
hdl::proof::z3::Builder builder(context);

builder.free(x);
builder.require(
  solver,
  module.op(hdl::Op::Kind::Eq, {
    ret_a.primitive(), ret_b.primitive()
  }),
  hdl::BitString::from_bool(false)
);

std::cout << solver.check() << std::endl;
```

Running this outputs

```bash
$ make
clang++ -g -I/usr/include/z3 -lz3 `llvm-config-16 --cflags --libs` main.cpp -o main
clang -Xclang -disable-O0-optnone -c -emit-llvm -o abs.bc abs.c
./main abs.bc
unsat
```

**Note:** Pathbeaver is currently a hobby project and should not be used for important applications.
If you are interested in collaborating on projects involving pathbeaver, feel free to get in contact by opening an issue.

## Installation

Pathbeaver requires LLVM 16 and the Z3 theorem prover.

```bash
$ git clone https://github.com/can-lehmann/pathbeaver.git
$ cd pathbeaver
$ git submodule update --init
$ make test
```

## Documentation

You can find examples in the [examples](examples/) folder.

## References

Pathbeaver is inspired by and based on techniques developed in other symbolic execution projects such as KLEE and SAW.
It uses LLVM and the Z3 theorem prover.

## License

Copyright 2023 Can Joshua Lehmann

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
