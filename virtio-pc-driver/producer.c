#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <stropts.h>

#include "virtio-prodcons.h"


static void
usage(void)
{
	printf("producer [-w NANOSECONDS]\n");
}

int
main(int argc, char **argv)
{
	struct virtpc_ioctl vio;
	int fd;
	int ret;
	int ch;
	int x;

	vio.wp = 150; /* in nanoseconds */
	vio.devid = 0;

	while ((ch = getopt(argc, argv, "hw:")) != -1) {
		switch (ch) {
		default:
		case 'h':
			usage();
			return 0;

		case 'w':
			x = atoi(optarg);
			if (x < 1) {
				printf("Invalid -w option argument\n");
				usage();
				return 0;
			}
			vio.wp = (unsigned int)x;
			break;
		}
	}

	fd = open("/dev/virtio-pc", O_RDWR);
	if (fd < 0) {
		printf("open(virtio-pc) failed [%s]\n", strerror(errno));
		return -1;
	}

	ret = ioctl(fd, 0, &vio);
	if (ret < 0 && errno != EAGAIN) {
		printf("ioctl(virtio-pc) failed [%s]\n", strerror(errno));
	}

	close(fd);

	return 0;
}

