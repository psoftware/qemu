#include <stdio.h>
#include <stdlib.h>
#include <time.h>

typedef unsigned int AT;

AT sel(AT *a, unsigned int n, unsigned int k)
{
    unsigned int r, w, b, e;
    AT pivot, tmp;
    unsigned int h;

    b = 0;
    e = n - 1;

    while (b < e) {
        pivot = a[(b + e) >> 1];
        r = b;
        w = e;
        for (h = 0; h < n; h++) { printf("%u ", a[h]); } printf("\n");
        printf("b=%u e=%u pivot=%u\n", b, e, pivot);
        while (r < w) {
            if (a[r] >= pivot) {
                tmp = a[w];
                a[w] = a[r];
                a[r] = tmp;
                w --;
            } else {
                r ++;
            }
        }

        if (a[r] > pivot) {
            r --;
        }

        if (k <= r) {
            e = r;
        } else {
            b = r + 1;
        }
    }

    return a[k];
}


int main()
{
#define N   100
    unsigned int a[N];
    int i = 0;
    unsigned x;

    for (i = 0; i < N; i++) {
        a[i] = i;
    }

    srand(time(0));

    for (i = 0; i < 40; i++) {
        unsigned int x, y, tmp;

        x = rand() % N;
        y = rand() % N;
        tmp = a[x];
        a[x] = a[y];
        a[y] = tmp;
    }

    x = sel(a, N, N*9/10);

    printf("Select %u\n", x);

    return 0;
}
