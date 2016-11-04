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
	printf("producer [-p WP_NANOSEC] [-c WC_NANOSEC] "
                        "[-P YP_NANOSEC] [-C YC_NANOSEC] "
                        "[-d DURATION_SEC] [-s]\n");
}

static unsigned int
parseuint(const char *s)
{
    int x;

    x = atoi(optarg);
    if (x < 1) {
        printf("Invalid -p option argument\n");
        usage();
        exit(EXIT_FAILURE);
    }

    return (unsigned int)x;
}

int
main(int argc, char **argv)
{
	struct virtpc_ioctl_data vio;
	int fd;
	int ret;
	int ch;

	vio.wp = 150; /* in nanoseconds */
	vio.wc = 300; /* in nanoseconds */
	vio.yp = 5000; /* in nanoseconds */
	vio.yc = 5000; /* in nanoseconds */
	vio.duration = 15; /* in seconds */
        vio.sleeping = 0; /* producer don't use sleeping */
	vio.devid = 0;

	while ((ch = getopt(argc, argv, "hsp:d:c:P:C:")) != -1) {
		switch (ch) {
		default:
		case 'h':
			usage();
			return 0;

                case 's':
                        vio.sleeping = 1;
                        break;

		case 'p':
                        vio.wp = parseuint(optarg);
			break;

		case 'c':
			vio.wc = parseuint(optarg);
			break;

		case 'P':
                        vio.yp = parseuint(optarg);
			break;

		case 'C':
			vio.yc = parseuint(optarg);
			break;

		case 'd':
			vio.duration = parseuint(optarg);
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

