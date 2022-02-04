STRICT_COMPILE = 0

CFLAGS = -Wall
LDFLAGS = -lbfd -lpthread -lrt -lcap -lnet
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

VERSION = $(shell grep LIBBFD_VERSION libbfd.h | cut -d " " -f 3)

bfd_test_FILES = libbfd_test.c

# Use SDK environment if available
CC = $(shell echo $$CC)
ifeq ($(CC),)
	CC = $(shell which gcc)
endif

ifeq ($(PREFIX),)
    PREFIX := /usr/local
endif

libs:
	@mkdir $(OUTDIR)
	@$(CC) -c $(CFLAGS) -fpic libbfd.c bfd_session.c bfd_packet.c
	@$(CC) -shared -o $(OUTDIR)/libbfd.so.$(VERSION) libbfd.o bfd_session.o bfd_packet.o
	@ln -rsf $(OUTDIR)/libbfd.so.$(VERSION) $(OUTDIR)/libbfd.so
	@rm *.o

install:
	@mkdir -p $(PREFIX)/include/libbfd
	@cp -d $(OUTDIR)/libbfd.so* $(PREFIX)/lib
	@cp *.h $(PREFIX)/include/libbfd
	@ldconfig

uninstall:
	@rm -rf $(PREFIX)/include/libbfd 2> /dev/null ||:
	@rm $(PREFIX)/lib/libbfd.so* 2> /dev/null ||:
	@ldconfig

test:
	@$(CC) $(CFLAGS) $(bfd_test_FILES) -o $(TEST_BIN) $(LDFLAGS)

clean:
	@rm -rf $(OUTDIR) 2> /dev/null ||: