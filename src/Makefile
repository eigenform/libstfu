# libstfu Makefile
# Build shared/static versions of libstfu

SRC	:= $(wildcard *.c)
OBJ	:= $(SRC:.c=.o)
TARGET 	:= libstfu
SHARED	:= $(TARGET).so
STATIC	:= $(TARGET).a

all: $(SHARED) $(STATIC)
%.o: %.c
	gcc -c -lunicorn -lpthread -lcrypto -fPIC $< -o $@
$(STATIC): $(OBJ)
	ar rcs $@ $^
$(SHARED):
	gcc -shared -lunicorn -lpthread -lcrypto -fPIC *.c -o $@
clean:
	rm -fv $(SHARED) $(STATIC)
.PHONY: clean
