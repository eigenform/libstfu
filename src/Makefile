# libstfu Makefile
# Build shared/static versions of libstfu

SRC	:= $(wildcard *.c)
OBJ	:= $(SRC:.c=.o)
TARGET 	:= libstfu
SHARED	:= $(TARGET).so
STATIC	:= $(TARGET).a
CFLAGS	:= -lunicorn -lpthread -lcrypto -fPIC -g

all: $(SHARED) $(STATIC)
%.o: %.c
	gcc -c $(CFLAGS) $< -o $@
$(STATIC): $(OBJ)
	ar rcs $@ $^
$(SHARED):
	gcc -shared $(CFLAGS) *.c -o $@
clean:
	rm -fv $(SHARED) $(STATIC) *.o
.PHONY: all clean
