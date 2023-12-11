SRCS := $(wildcard *.c)
BINS := $(SRCS:%.c=%)

bins:
	@for i in $(SRCS) ; do \
		$(CC) $(CFLAGS) $${i} -o $${i%.*} -lnetbfd; \
	done

clean:
	@rm -f $(BINS) 2> /dev/null ||:
	@rm -f *.out 2> /dev/null ||:
	@rm -f *.err 2> /dev/null ||: