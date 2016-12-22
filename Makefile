ifneq ($(KERNELRELEASE),)  
	obj-m := nf_http_modify.o
else
	KDIR := /home/slinking/workspace/source/linux-3.10.14.x/

all:
	make -C $(KDIR) M=$(PWD) modules ARCH=mips CROSS_COMPILE=mipsel-linux-

clean:
	rm -f *.ko *.o *.mod.o *.mod.c *.symvers *.order
endif

