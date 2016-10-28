KER=`uname -r`

obj-m += virtio-prodcons.o

all:
	make -C /lib/modules/$(KER)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(KER)/build M=$(PWD) clean
