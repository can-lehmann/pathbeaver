all:
	$(MAKE) -C ../.. all
	clang -Xclang -disable-O0-optnone -c -emit-llvm -o popcount.bc popcount.c
	./../../bin/pathbeaver popcount.bc