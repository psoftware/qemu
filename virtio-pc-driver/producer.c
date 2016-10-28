#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>


int
main(int argc, char **argv)
{
	int fd = open("/dev/virtio-pc", O_RDWR);

	if (fd < 0) {
		printf("Failed to open virtio prodcons device %s", strerror(errno));
		return -1;
	}

	close(fd);

	return 0;
}

