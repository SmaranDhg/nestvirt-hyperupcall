# Build against the running kernel by default.
# Override: make KDIR=/path/to/kernel/source
obj-m += ipi_bench.o
KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

install: all
	sudo insmod ipi_bench.ko
	@echo "Check: dmesg | tail"

uninstall:
	sudo rmmod ipi_bench 2>/dev/null || true

.PHONY: all clean install uninstall
