#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <pthread.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/time.h>
#include <stropts.h>
#include <assert.h>


#define barrier() __sync_synchronize()
#define ACCESS_ONCE(x) (*(volatile typeof(x) *)&(x))

/******************************* TSC support ***************************/

/* initialize to avoid a division by 0 */
static uint64_t ticks_per_second = 1000000000; /* set by calibrate_tsc */

static inline uint64_t
rdtsc(void)
{
    uint32_t hi, lo;
    __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
    return (uint64_t)lo | ((uint64_t)hi << 32);
}

/*
 * do an idle loop to compute the clock speed. We expect
 * a constant TSC rate and locked on all CPUs.
 * Returns ticks per second
 */
static uint64_t
calibrate_tsc(void)
{
    struct timeval a, b;
    uint64_t ta_0, ta_1, tb_0, tb_1, dmax = ~0;
    uint64_t da, db, cy = 0;
    int i;
    for (i=0; i < 3; i++) {
	ta_0 = rdtsc();
	gettimeofday(&a, NULL);
	ta_1 = rdtsc();
	usleep(20000);
	tb_0 = rdtsc();
	gettimeofday(&b, NULL);
	tb_1 = rdtsc();
	da = ta_1 - ta_0;
	db = tb_1 - tb_0;
	if (da + db < dmax) {
	    cy = (b.tv_sec - a.tv_sec)*1000000 + b.tv_usec - a.tv_usec;
	    cy = (double)(tb_0 - ta_1)*1000000/(double)cy;
	    dmax = da + db;
	}
    }
    ticks_per_second = cy;
    return cy;
}

#define NS2TSC(x) ((x)*ticks_per_second/1000000000UL)
#define TSC2NS(x) ((x)*1000000000UL/ticks_per_second)

static inline void
tsc_sleep_till(uint64_t when)
{
    while (rdtsc() < when)
        barrier();
}
/*************************************************************************/

/* QLEN must be a power of two */
#define QLEN 1024

static struct global {
    /* Variables read by both P and C */
    unsigned int duration;
    unsigned int wp;
    unsigned int wc;
    unsigned int yp;
    unsigned int yc;
    unsigned int psleep;
    unsigned int csleep;
    unsigned int stop;
    int pnotify;
    int cnotify;

    /* Variables written by P */
    uint64_t q[QLEN];
    unsigned int p;
    unsigned int ce;
    uint64_t pnotifs;

    /* Variables written by C */
    unsigned int c;
    unsigned int pe;
    uint64_t items;
    uint64_t cnotifs;

    /* Miscellaneous, cache awareness not important. */
    uint64_t test_start;
    uint64_t test_end;
} _g;

static inline int
queue_empty(struct global *g)
{
    return ACCESS_ONCE(g->p) == g->c;
}

static inline unsigned int
queue_next(unsigned int idx)
{
    return (idx + 1) & (QLEN-1);
}

static inline int
queue_full(struct global *g)
{
    return queue_next(g->p) == ACCESS_ONCE(g->c);
}

static void *
producer(void *opaque)
{
    struct global *g = opaque;
    int need_notify;
    uint64_t next;
    uint64_t x;
    int ret;

    g->test_start = rdtsc();
    next = g->test_start + g->wp;

    while (!g->stop) {
        if (queue_full(g)) {
            // g->ce = (g->c + QLEN * 3 / 4) & (QLEN-1);
            ACCESS_ONCE(g->ce) = ACCESS_ONCE(g->c);
            /* barrier and double-check */
            barrier();
            if (queue_full(g)) {
                ret = read(g->cnotify, &x, sizeof(x));
                assert(ret == 8);
                next = rdtsc() + g->wp;
            }
        }
        tsc_sleep_till(next);
        next += g->wp;
        need_notify = (g->p == ACCESS_ONCE(g->pe));
        barrier();
        ACCESS_ONCE(g->p) = queue_next(g->p);
        if (need_notify) {
            x = 1;
            ret = write(g->pnotify, &x, sizeof(x));
            assert(ret == 8);
            g->pnotifs ++;
            next = rdtsc() + g->wp;
        }
    }

    return NULL;
}

static void *
consumer(void *opaque)
{
    struct global *g = opaque;
    int need_notify;
    uint64_t next;
    uint64_t x;
    int ret;

    next = rdtsc() + g->wc; /* just in case */

    while (!g->stop) {
        if (queue_empty(g)) {
            ACCESS_ONCE(g->pe) = ACCESS_ONCE(g->p);
            /* barrier and double-check */
            barrier();
            if (queue_empty(g)) {
                ret = read(g->pnotify, &x, sizeof(x));
                assert(ret == 8);
                next = rdtsc() + g->wc;
            }
        }
        tsc_sleep_till(next);
        next += g->wc;
        need_notify = (g->c == ACCESS_ONCE(g->ce));
        barrier();
        ACCESS_ONCE(g->c) = queue_next(g->c);
        if (need_notify) {
            x = 1;
            ret = write(g->cnotify, &x, sizeof(x));
            assert(ret == 8);
            g->cnotifs ++;
            next = rdtsc() + g->wc;
        }
        g->items ++;
    }

    g->test_end = rdtsc();

    return NULL;
}

static void
csb_dump(struct global *g)
{
    /* CSB dump */
    printf("p=%u pe=%u c=%u ce=%u\n",
            g->p, g->pe, g->c, g->ce);
}

static void
sigint_handler(int sig)
{
    struct global *g = &_g;
    uint64_t x;

    csb_dump(g);

    /* Stop and wake up. */
    g->stop = 1;
    write(g->pnotify, &x, sizeof(x));
    write(g->cnotify, &x, sizeof(x));
}

static void
usage(void)
{
    printf("test [-p WP_NANOSEC] [-c WC_NANOSEC] "
            "[-y YP_NANOSEC] [-Y YC_NANOSEC] "
            "[-d DURATION_SEC] [-s <producer sleeps>] "
            "[-S <consumer sleeps>] \n");
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

int main(int argc, char **argv)
{
    struct global *g = &_g;
    pthread_t thp, thc;
    int ret;
    int ch;

    memset(g, 0, sizeof(*g));

    g->pnotify = eventfd(0, 0);
    g->cnotify = eventfd(0, 0);
    if (g->pnotify < 0 || g->cnotify < 0) {
        perror("eventfd()");
        return -1;
    }

    g->stop = 0;

    g->wp = 2100;
    g->wc = 2000;
    g->yp = 5000;
    g->yc = 5000;
    g->psleep = 0;
    g->csleep = 0;

    while ((ch = getopt(argc, argv, "hc:p:sSy:Y:d:")) != -1) {
        switch (ch) {
            default:
            case 'h':
                usage();
                return 0;

            case 's':
                g->psleep = 1;
                break;

            case 'S':
                g->csleep = 1;
                break;

            case 'p':
                g->wp = parseuint(optarg);
                break;

            case 'c':
                g->wc = parseuint(optarg);
                break;

            case 'y':
                g->yp = parseuint(optarg);
                break;

            case 'Y':
                g->yc = parseuint(optarg);
                break;

            case 'd':
                g->duration = parseuint(optarg);
                break;
        }
    }

    if (signal(SIGINT, sigint_handler)) {
        perror("signal()");
        exit(EXIT_FAILURE);
    }

    if (signal(SIGTERM, sigint_handler)) {
        perror("signal()");
        exit(EXIT_FAILURE);
    }

    calibrate_tsc();
    g->wp = NS2TSC(g->wp);
    g->wc = NS2TSC(g->wc);
    g->yp = NS2TSC(g->yp);
    g->yc = NS2TSC(g->yc);
    // printf("wp %u wc %u\n", g->wp, g->wc);

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

    /* statistics */
    {
        double test_len = TSC2NS(g->test_end - g->test_start) / 1000000000.0;

        printf("#items: %lu, testlen: %3.4f\n", g->items, test_len);
        printf("%10.0f items/s %9.0f pnotifs/s %9.0f cnotifs/s\n",
                g->items / test_len,
                g->pnotifs / test_len,
                g->cnotifs / test_len);
    }

    return 0;
}
