SRCS := $(wildcard *.c)
BINS := $(SRCS:%.c=%)

bins:
	$(Q)for i in $(SRCS) ; do \
		$(CC) $(CFLAGS) $${i} -L$(OUTDIR) -o $${i%.*} -lnetbfd; \
	done

clean:
	$(Q)rm -f $(BINS) 2> /dev/null ||:
	$(Q)rm -f *.out 2> /dev/null ||:
	$(Q)rm -f *.err 2> /dev/null ||: