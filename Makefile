all: bin/pathbeaver

bin/pathbeaver: src/pathbeaver.hpp src/main.cpp
	clang++ -g -I/usr/include/z3 -lz3 `llvm-config-16 --cflags --libs` src/main.cpp -o bin/pathbeaver

test: tests/test_exceptions tests/input/exceptions.bc tests/test_equivalence tests/input/equivalence.bc
	./tests/test_exceptions tests/input/exceptions.bc
	./tests/test_equivalence tests/input/equivalence.bc

tests/input/exceptions.bc: tests/input/exceptions.c
	clang -c -emit-llvm -o tests/input/exceptions.bc tests/input/exceptions.c

tests/input/equivalence.bc: tests/input/equivalence.c
	clang -c -emit-llvm -o tests/input/equivalence.bc tests/input/equivalence.c


tests/test_exceptions: tests/test_exceptions.cpp src/pathbeaver.hpp
	clang++ -g -I/usr/include/z3 -lz3 `llvm-config-16 --cflags --libs` -o tests/test_exceptions tests/test_exceptions.cpp

tests/test_equivalence: tests/test_equivalence.cpp src/pathbeaver.hpp
	clang++ -g -I/usr/include/z3 -lz3 `llvm-config-16 --cflags --libs` -o tests/test_equivalence tests/test_equivalence.cpp


