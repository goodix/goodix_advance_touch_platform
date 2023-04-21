ifneq ($(KERNELRELEASE),)
# kbuild part of makefile
obj-m += gatp_hid.o
gatp_hid-y := \
				main.o \
				hid.o
else
# normal makefile
KDIR ?= /lib/modules/`uname -r`/build

default:
	$(MAKE) -C $(KDIR) M=$$PWD
clean:
	@rm *.o *.mod *.mod.c .*.cmd Module.symvers *.a *.ko modules.order
endif
