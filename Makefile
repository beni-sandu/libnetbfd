STRICT_COMPILE = 0

CFLAGS = -Wall
LDFLAGS = -lnetbfd -lpthread -lrt -lcap -lnet
OUTDIR = build

ifeq ($(STRICT_COMPILE),1)
CFLAGS += -O2 -W -Werror -Wstrict-prototypes -Wmissing-prototypes
CFLAGS += -Wmissing-declarations -Wold-style-definition -Wpointer-arith
CFLAGS += -Wcast-align -Wnested-externs -Wcast-qual
CFLAGS += -Wformat-security -Wundef -Wwrite-strings
CFLAGS += -Wbad-function-cast -Wformat-nonliteral -Wsuggest-attribute=format -Winline
CFLAGS += -std=gnu99
endif

TEST_BIN = bfd_test

VERSION = $(shell grep LIBNETBFD_VERSION libnetbfd.h | cut -d " " -f 3)

bfd_test_FILES = libnetbfd_test.c

# Use SDK environment if available
CC = $(shell echo $$CC)
ifeq ($(CC),)
	CC = $(shell which gcc)
endif

ifeq ($(PREFIX),)
    PREFIX := /usr/local
endif

libs:
	@rm -rf $(OUTDIR) 2> /dev/null ||:
	@mkdir $(OUTDIR)
	@$(CC) -c $(CFLAGS) -fpic libnetbfd.c bfd_session.c bfd_packet.c
	@$(CC) -shared -Wl,-soname,libnetbfd.so.$(VERSION) -o $(OUTDIR)/libnetbfd.so.$(VERSION) libnetbfd.o bfd_session.o bfd_packet.o
	@rm *.o

install:
	@mkdir -p $(PREFIX)/include/libnetbfd
	@cp -d $(OUTDIR)/libnetbfd.so* $(PREFIX)/lib
	@cp *.h $(PREFIX)/include/libnetbfd
	@ln -sf $(PREFIX)/lib/libnetbfd.so.$(VERSION) $(PREFIX)/lib/libnetbfd.so

uninstall:
	@rm -rf $(PREFIX)/include/libnetbfd 2> /dev/null ||:
	@rm $(PREFIX)/lib/libnetbfd.so* 2> /dev/null ||:

test:
	@$(CC) $(CFLAGS) $(bfd_test_FILES) -o $(TEST_BIN) $(LDFLAGS)

clean:
	@rm -rf $(OUTDIR) 2> /dev/null ||:
