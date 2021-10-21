STRICT_COMPILE = 0

CFLAGS = -Wall
LDFLAGS = -L$(shell pwd) -lbfd -lpthread -lrt -lcap -lnet

ifeq ($(STRICT_COMPILE),1)
CFLAGS += -O2 -W -Werror -Wstrict-prototypes -Wmissing-prototypes
CFLAGS += -Wmissing-declarations -Wold-style-definition -Wpointer-arith
CFLAGS += -Wcast-align -Wnested-externs -Wcast-qual
CFLAGS += -Wformat-security -Wundef -Wwrite-strings
CFLAGS += -Wbad-function-cast -Wformat-nonliteral -Wsuggest-attribute=format -Winline
CFLAGS += -std=gnu99
endif

BIN = bfd_test

bfd_test_FILES = \
	libbfd.c \
	bfd_session.c \
	bfd_packet.c \
	libbfd_test.c

# Use SDK environment if available
CC = $(shell echo $$CC)
ifeq ($(CC),)
	CC = $(shell which gcc)
endif

all: libs
	@$(CC) $(CFLAGS) $(bfd_test_FILES) -o $(BIN) $(LDFLAGS)

libs:
	@$(CC) -c $(CFLAGS) -fpic libbfd.c bfd_session.c bfd_packet.c
	@$(CC) -shared -o libbfd.so libbfd.o bfd_session.o bfd_packet.o
	@rm *.o

clean:
	@rm $(BIN) 2> /dev/null ||:
	@rm libbfd.so 2> /dev/null ||: