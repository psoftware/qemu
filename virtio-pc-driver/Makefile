KER=`uname -r`

obj-m += producer.o
obj-m += consumer.o

all: ker test

ker:
	make -C /lib/modules/$(KER)/build M=$(PWD) modules

test: test.c
	gcc -g -Wall -o test test.c

clean: cker cusr

cker:
	make -C /lib/modules/$(KER)/build M=$(PWD) clean

cusr:
	-rm -f test
