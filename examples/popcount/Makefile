all:
	$(MAKE) -C ../.. all
	clang -O1 -c -emit-llvm -o popcount.bc popcount.c
	./../../bin/pathbeaver popcount.bc