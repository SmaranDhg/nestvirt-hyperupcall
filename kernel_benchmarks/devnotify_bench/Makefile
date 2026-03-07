obj-m += devnotify_bench.o
KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

install: all
	sudo insmod devnotify_bench.ko
	@echo "Check: dmesg | tail"

uninstall:
	sudo rmmod devnotify_bench 2>/dev/null || true

.PHONY: all clean install uninstall
