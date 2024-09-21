STRICT_COMPILE = 0

CFLAGS = -Wall
LDFLAGS = -lpthread -lrt -lcap -lnet
OUTDIR = $(shell pwd)/build
TESTDIR = tests
SRCDIR = library
INCLDIR = include

# Use V=1 to echo all Makefile commands when running
V ?= 0
ifneq ($(V), 1)
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

VERSION = $(shell grep LIBNETBFD_VERSION $(INCLDIR)/libnetbfd.h | cut -d " " -f 3)

# Use SDK environment if available
CC = $(shell echo $$CC)
ifeq ($(CC),)
	CC = $(shell which gcc)
endif

ifeq ($(PREFIX),)
    PREFIX := /usr/local
endif

# Pass on vars to submakes
export

libs:
	$(Q)rm -rf $(OUTDIR) 2> /dev/null ||:
	$(Q)mkdir $(OUTDIR)
	$(Q)$(CC) -c $(CFLAGS) -fpic $(SRCDIR)/libnetbfd.c $(SRCDIR)/bfd_session.c $(SRCDIR)/bfd_packet.c
	$(Q)$(CC) -shared -Wl,-soname,libnetbfd.so.$(VERSION) -o $(OUTDIR)/libnetbfd.so.$(VERSION) libnetbfd.o bfd_session.o bfd_packet.o $(LDFLAGS)
	$(Q)ln -sf $(OUTDIR)/libnetbfd.so.$(VERSION) $(OUTDIR)/libnetbfd.so
	$(Q)rm *.o

install:
	$(Q)mkdir -p $(PREFIX)/include/libnetbfd
	$(Q)mkdir -p $(PREFIX)/lib
	$(Q)cp -d $(OUTDIR)/libnetbfd.so* $(PREFIX)/lib
	$(Q)cp $(INCLDIR)/*.h $(PREFIX)/include/libnetbfd
	$(Q)ln -sf $(PREFIX)/lib/libnetbfd.so.$(VERSION) $(PREFIX)/lib/libnetbfd.so

uninstall:
	$(Q)rm -rf $(PREFIX)/include/libnetbfd 2> /dev/null ||:
	$(Q)rm -rf $(PREFIX)/lib/libnetbfd.so* 2> /dev/null ||:

test:
	$(Q)$(MAKE) -s -C $(TESTDIR) bins

test-run: test
	$(Q)cd $(TESTDIR) ; \
	./run.sh

clean:
	$(Q)rm -rf $(OUTDIR) 2> /dev/null ||:
	$(Q)$(MAKE) -s -C $(TESTDIR) clean
