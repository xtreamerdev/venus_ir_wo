ifneq ($(KERNELRELEASE),)
# call from kernel build system

obj-m	:= venus_ir_wo.o

else

KERNELDIR ?= /home/playonhd/source/linux-2.6.12
PWD       := $(shell pwd)

default:
	$(MAKE) -C $(KERNELDIR) SUBDIRS=$(PWD) modules

endif


clean:
	rm -rf *.o *.ko *~ core .depend *.mod.c .*.cmd .tmp_versions .*.o.d

depend .depend dep:
	$(CC) $(CFLAGS) -M *.c > .depend


ifeq (.depend,$(wildcard .depend))
include .depend
endif
