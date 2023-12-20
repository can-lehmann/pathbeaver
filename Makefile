all: bin/pathbeaver

bin/pathbeaver: src/pathbeaver.hpp src/main.cpp
	clang++ -g -I/usr/include/z3 -lz3 `llvm-config-16 --cflags --libs` src/main.cpp -o bin/pathbeaver
