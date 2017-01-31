RPMMIO_ROOT=..
BIN=$(RPMMIO_ROOT)/bin


obj-m := rpmmio.o
rpmmio-objs := rpmmio_main2.o rpmmio_tpm2.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
all:
	make -C $(KDIR) M=$(PWD) modules
clean:
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions Module.symvers modules.order
