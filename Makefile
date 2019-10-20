# LD_PRELOAD usage is because I'm using my own build of unicorn. 
# If you're trying to debug things or have issues, you can set it to your own.
#
# Also, LD_LIBRARY_PATH=./ is just a way to avoid installing libstfu.so on my
# box. Presumably if you were a user, you'd run `make install` to write the
# shared library somewhere in your linker's search path.

MY_LIBUNICORN	:= ~/src/unicorn/libunicorn.so.1

# For building libstfu.so
LIBSTFU_LDEPS	:= -lunicorn -lpthread
LIBSTFU_CFLAGS	:= -shared -fPIC -g 
LIBSTFU_SRC	:= src/starlet.c src/util.c src/mmio.c src/ecc.c

all:
	gcc $(LIBSTFU_LDEPS) $(LIBSTFU_CFLAGS) $(LIBSTFU_SRC) -o libstfu.so
	gcc -g -L. -lstfu src/test.c -o stfu
clean:
	rm -rf *.o *.so stfu cachegrind.out.*
vgtest:
	@LD_LIBRARY_PATH=./ LD_PRELOAD=$(MY_LIBUNICORN) \
		valgrind ./stfu
cgtest:
	@LD_LIBRARY_PATH=./ LD_PRELOAD=$(MY_LIBUNICORN) \
		valgrind --tool=cachegrind ./stfu
strace:
	@LD_LIBRARY_PATH=./ LD_PRELOAD=$(MY_LIBUNICORN) \
		strace -f ./stfu
test:
	@LD_LIBRARY_PATH=./ LD_PRELOAD=$(MY_LIBUNICORN) \
		./stfu

.PHONY: all clean test vgtest
