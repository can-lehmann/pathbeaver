test: tests/test_exceptions tests/input/exceptions.bc tests/test_equivalence tests/input/equivalence.bc tests/input/equivalence_o1.bc tests/input/equivalence_o2.bc tests/input/equivalence_o3.bc tests/test_execution tests/input/execution_binops.ll tests/input/execution_vector.ll
	./tests/test_execution tests/input/execution_binops.ll
	./tests/test_execution tests/input/execution_vector.ll
	./tests/test_exceptions tests/input/exceptions.bc
	./tests/test_equivalence tests/input/equivalence.bc
	./tests/test_equivalence tests/input/equivalence_o1.bc
	./tests/test_equivalence tests/input/equivalence_o2.bc
	./tests/test_equivalence tests/input/equivalence_o3.bc

tests/input/exceptions.bc: tests/input/exceptions.c
	clang -c -emit-llvm -o tests/input/exceptions.bc tests/input/exceptions.c

tests/input/equivalence.bc: tests/input/equivalence.c
	clang -c -emit-llvm -o tests/input/equivalence.bc tests/input/equivalence.c

tests/input/equivalence_o1.bc: tests/input/equivalence.c
	clang -O1 -c -emit-llvm -o tests/input/equivalence_o1.bc tests/input/equivalence.c

tests/input/equivalence_o2.bc: tests/input/equivalence.c
	clang -O2 -c -emit-llvm -o tests/input/equivalence_o2.bc tests/input/equivalence.c

tests/input/equivalence_o3.bc: tests/input/equivalence.c
	clang -O3 -c -emit-llvm -o tests/input/equivalence_o3.bc tests/input/equivalence.c


tests/test_exceptions: tests/test_exceptions.cpp src/pathbeaver.hpp
	clang++ -g -I/usr/include/z3 -lz3 `llvm-config-16 --cflags --libs` -o tests/test_exceptions tests/test_exceptions.cpp

tests/test_equivalence: tests/test_equivalence.cpp src/pathbeaver.hpp
	clang++ -g -I/usr/include/z3 -lz3 `llvm-config-16 --cflags --libs` -o tests/test_equivalence tests/test_equivalence.cpp

tests/test_execution: tests/test_execution.cpp src/pathbeaver.hpp
	clang++ -g -I/usr/include/z3 -lz3 `llvm-config-16 --cflags --libs` -o tests/test_execution tests/test_execution.cpp

