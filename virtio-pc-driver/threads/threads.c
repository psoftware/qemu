#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <pthread.h>
#include <errno.h>

static struct global {
    unsigned int wp;
    unsigned int wc;
    unsigned int yp;
    unsigned int yc;
    unsigned int psleeps;
    unsigned int csleeps;
} _g;


static void *
producer(void *opaque)
{
    struct global *g = opaque;

    (void)g;

    return NULL;
}

static void *
consumer(void *opaque)
{
    struct global *g = opaque;

    (void)g;

    return NULL;
}

int main(int argc, char **argv)
{
    struct global *g = &_g;
    pthread_t thp, thc;
    int ret;

    g->wp = 2100;
    g->wc = 2000;
    g->yp = 5000;
    g->yc = 5000;
    g->psleeps = 0;
    g->csleeps = 0;

    ret = pthread_create(&thp, NULL, producer, g);
    if (ret) {
        perror("pthread_create(P)");
        exit(EXIT_FAILURE);
    }

    ret = pthread_create(&thc, NULL, consumer, g);
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
