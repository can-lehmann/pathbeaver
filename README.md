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

```bash
TODO
```

**Note:** Pathbeaver is currently a hobby project and should not be used for important applications.
If you are interested in collaborating on projects involving pathbeaver, feel free to get in contact by opening an issue.

## Installation

Pathbeaver requires LLVM 16 and the Z3 theorem prover.

```bash
TODO
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
