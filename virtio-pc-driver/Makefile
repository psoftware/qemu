KER=`uname -r`

obj-m += virtio-prodcons.o

all: ker producer

ker:
	make -C /lib/modules/$(KER)/build M=$(PWD) modules

producer: producer.c
	gcc -g -Wall -o producer producer.c

clean: cker cusr

cker:
	make -C /lib/modules/$(KER)/build M=$(PWD) clean

cusr:
	-rm -f producer
