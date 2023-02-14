STRICT_COMPILE = 0

CFLAGS = -Wall
LDFLAGS = -lnetbfd -lpthread -lrt -lcap -lnet
OUTDIR = build

# Use VERBOSE=1 to echo all Makefile commands when running
VERBOSE ?= 0
ifneq ($(VERBOSE), 1)
Q=@
endif

# Use DEBUG_ENABLE=1 for a debug build
DEBUG_ENABLE ?= 0
ifeq ($(DEBUG_ENABLE), 1)
CFLAGS += -DDEBUG_ENABLE -g
endif

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
	$(Q)rm -rf $(OUTDIR) 2> /dev/null ||:
	$(Q)mkdir $(OUTDIR)
	$(Q)$(CC) -c $(CFLAGS) -fpic libnetbfd.c bfd_session.c bfd_packet.c
	$(Q)$(CC) -shared -Wl,-soname,libnetbfd.so.$(VERSION) -o $(OUTDIR)/libnetbfd.so.$(VERSION) libnetbfd.o bfd_session.o bfd_packet.o
	$(Q)rm *.o

install:
	$(Q)mkdir -p $(PREFIX)/include/libnetbfd
	$(Q)cp -d $(OUTDIR)/libnetbfd.so* $(PREFIX)/lib
	$(Q)cp *.h $(PREFIX)/include/libnetbfd
	$(Q)ln -sf $(PREFIX)/lib/libnetbfd.so.$(VERSION) $(PREFIX)/lib/libnetbfd.so

uninstall:
	$(Q)rm -rf $(PREFIX)/include/libnetbfd 2> /dev/null ||:
	$(Q)rm -rf $(PREFIX)/lib/libnetbfd.so* 2> /dev/null ||:

test:
	$(Q)$(CC) $(CFLAGS) $(bfd_test_FILES) -o $(TEST_BIN) $(LDFLAGS)

clean:
	$(Q)rm -rf $(OUTDIR) 2> /dev/null ||:
