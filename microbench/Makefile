CC      = gcc
CFLAGS  = -O2 -std=gnu99 -Wall -Wextra
TARGETS = hypercall devnotify programtimer sendipi

.PHONY: all clean

all: $(TARGETS)

hypercall: hypercall.c
	$(CC) $(CFLAGS) -o $@ $<

devnotify: devnotify.c
	$(CC) $(CFLAGS) -o $@ $<

programtimer: programtimer.c
	$(CC) $(CFLAGS) -o $@ $<

sendipi: sendipi.c
	$(CC) $(CFLAGS) -pthread -o $@ $<

clean:
	rm -f $(TARGETS)
