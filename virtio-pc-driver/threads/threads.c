#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <pthread.h>
#include <errno.h>


static void *
producer(void *opaque)
{
    return NULL;
}

static void *
consumer(void *opaque)
{
    return NULL;
}

int main(int argc, char **argv)
{
    pthread_t thp, thc;
    int ret;

    ret = pthread_create(&thp, NULL, producer, NULL);
    if (ret) {
        perror("pthread_create(P)");
        exit(EXIT_FAILURE);
    }

    ret = pthread_create(&thc, NULL, consumer, NULL);
    if (ret) {
        perror("pthread_create(C)");
        exit(EXIT_FAILURE);
    }

    ret = pthread_join(thp, NULL);
    if (ret) {
        perror("pthread_join(P)");
        exit(EXIT_FAILURE);
    }

    ret = pthread_join(thc, NULL);
    if (ret) {
        perror("pthread_join(C)");
        exit(EXIT_FAILURE);
    }

    return 0;
}
