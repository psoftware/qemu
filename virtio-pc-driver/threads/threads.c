#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <pthread.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/eventfd.h>


/* QLEN must be a power of two */
#define QLEN 128

static struct global {
    unsigned int stop;
    unsigned int wp;
    unsigned int wc;
    unsigned int yp;
    unsigned int yc;
    unsigned int psleeps;
    unsigned int csleeps;
    int pnotify;
    int cnotify;

    uint64_t q[QLEN];
    volatile unsigned int p;
    volatile unsigned int ce;
    uint64_t pnotifs;

    volatile unsigned int c;
    volatile unsigned int pe;
    uint64_t pkts;
    uint64_t cnotifs;
} _g;

static inline int
queue_empty(struct global *g)
{
    return g->p == g->c;
}

static inline unsigned int
queue_next(unsigned int idx)
{
    return (idx + 1) & (QLEN-1);
}

static inline int
queue_full(struct global *g)
{
    return queue_next(g->p) == g->c;
}

static void *
producer(void *opaque)
{
    struct global *g = opaque;
    int need_notify;
    uint64_t x;

    while (!g->stop) {
        if (queue_full(g)) {
            g->ce = g->c;
            /* barrier and double-check */
            read(g->cnotify, &x, sizeof(x));
        }
        usleep(g->wp);
        need_notify = (g->p == g->pe);
        g->p = queue_next(g->p);
        if (need_notify) {
            x = 1;
            write(g->pnotify, &x, sizeof(x));
            g->pnotifs ++;
        }
    }

    return NULL;
}

static void *
consumer(void *opaque)
{
    struct global *g = opaque;
    int need_notify;
    uint64_t x;

    while (!g->stop) {
        if (queue_empty(g)) {
            g->pe = g->p;
            /* barrier and double-check */
            read(g->pnotify, &x, sizeof(x));
        }
        usleep(g->wc);
        need_notify = (g->c == g->ce);
        g->c = queue_next(g->c);
        if (need_notify) {
            x = 1;
            write(g->cnotify, &x, sizeof(x));
            g->cnotifs ++;
        }
        g->pkts ++;
    }

    return NULL;
}

static void
sigint_handler(int sig)
{
    struct global *g = &_g;
    g->stop = 1;
}

int main(int argc, char **argv)
{
    struct global *g = &_g;
    pthread_t thp, thc;
    int ret;

    memset(g, 0, sizeof(*g));

    g->pnotify = eventfd(0, 0);
    g->cnotify = eventfd(0, 0);
    if (g->pnotify < 0 || g->cnotify < 0) {
        perror("eventfd()");
        return -1;
    }

    g->stop = 0;

    g->wp = 2;
    g->wc = 1;
    g->yp = 5000;
    g->yc = 5000;
    g->psleeps = 0;
    g->csleeps = 0;

    if (signal(SIGINT, sigint_handler)) {
        perror("signal()");
        exit(EXIT_FAILURE);
    }

    if (signal(SIGTERM, sigint_handler)) {
        perror("signal()");
        exit(EXIT_FAILURE);
    }

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
