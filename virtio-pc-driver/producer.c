#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <stropts.h>

#include "virtio-prodcons.h"


int
main(int argc, char **argv)
{
	int fd = open("/dev/virtio-pc", O_RDWR);
	struct virtpc_ioctl vio;
	int ret;

	if (fd < 0) {
		printf("open(virtio-pc) failed [%s]\n", strerror(errno));
		return -1;
	}

	vio.wp = 150;
	vio.devid = 0;
	ret = ioctl(fd, 0, &vio);
	if (ret < 0) {
		printf("ioctl(virtio-pc) failed [%s]\n", strerror(errno));
	}

	close(fd);

	return 0;
}

