KERNEL_DIR = /lib/modules/`uname -r`/build
MODULEDIR := $(shell pwd)


.PHONY: modules start stop restart
default: modules

modules:
	make -C $(KERNEL_DIR) M=$(MODULEDIR) modules

clean distclean:
	rm -f *.o *.mod.c .*.*.cmd *.ko *.ko.unsigned
	rm -rf .tmp_versions
	rm -f *.order *.symvers .*.cmd

start:
	insmod ./anycast_roaming.ko

stop:
	rmmod anycast_roaming

restart:
	rmmod anycast_roaming && insmod ./anycast_roaming.ko
