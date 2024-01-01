all: main
	clang -Xclang -disable-O0-optnone -c -emit-llvm -o popcount.bc popcount.c
	./main popcount.bc

main: main.cpp ../../src/pathbeaver.hpp
	clang++ -g -I/usr/include/z3 -lz3 `llvm-config-16 --cflags --libs` main.cpp -o main
