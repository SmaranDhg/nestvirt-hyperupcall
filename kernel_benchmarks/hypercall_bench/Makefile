obj-m += hypercall_bench.o
KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

install: all
	sudo insmod hypercall_bench.ko
	@echo "Check: dmesg | tail"

uninstall:
	sudo rmmod hypercall_bench 2>/dev/null || true

.PHONY: all clean install uninstall
