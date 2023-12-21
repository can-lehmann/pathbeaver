all:
	$(MAKE) -C ../.. all
	clang -Xclang -disable-O0-optnone -c -emit-llvm -o popcount.bc popcount.c
	opt popcount.bc -o popcount_opt.bc -passes=mem2reg
	./../../bin/pathbeaver popcount_opt.bc