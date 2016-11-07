/*
 * Test program to configure and run the kernel producer, whose code
 * is contained in the virtio prodcons driver.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <stropts.h>
#include <stdint.h>

#include "producer.h"


static void
usage(void)
{
    printf("test [-p WP_NANOSEC] [-c WC_NANOSEC] "
            "[-P YP_NANOSEC] [-C YC_NANOSEC] "
            "[-d DURATION_SEC] [-s <producer sleeps>] "
            "[-S <consumer sleeps>]\n");
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

    /* Prepare the configuration to be passed to the prodcons virtio device. */

    vio.wp = 150; /* in nanoseconds */
    vio.wc = 300; /* in nanoseconds */
    vio.yp = 5000; /* in nanoseconds */
    vio.yc = 5000; /* in nanoseconds */
    vio.duration = 20; /* in seconds */
    vio.psleep = 0; /* producer doesn't use sleeping */
    vio.csleep = 0; /* consumer doesn't use sleeping */
    vio.incsc = 0; /* in nanoseconds */
    vio.incsp = 0; /* in nanoseconds */
    vio.devid = 0; /* virtio-prodcons device to be selected */

    while ((ch = getopt(argc, argv, "hd:sSp:c:P:C:")) != -1) {
        switch (ch) {
            default:
            case 'h':
                usage();
                return 0;

            case 's':
                vio.psleep = 1;
                break;

            case 'S':
                vio.csleep = 1;
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

    /* Open the device file to be used to run the producer. */
    fd = open("/dev/virtio-pc", O_RDWR);
    if (fd < 0) {
        printf("open(virtio-pc) failed [%s]\n", strerror(errno));
        return -1;
    }

    /*
     * The producer will run in the process context of this program,
     * implemented in kernel by the following ioctl. The ioctl returns
     * upon receiving a signal (e.g. SIGTERM) or after the number of
     * seconds specified in vio.duration.
     * The ioctl command (0) is ignored by the kernel to keep it simple.
     */
    ret = ioctl(fd, 0, &vio);
    if (ret < 0 && errno != EAGAIN) {
        printf("ioctl(virtio-pc) failed [%s]\n", strerror(errno));
    }

    close(fd);

    return 0;
}

