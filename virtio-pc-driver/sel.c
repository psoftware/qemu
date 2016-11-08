#include <stdio.h>
#include <stdlib.h>
#include <time.h>

unsigned int sel(unsigned int *a, unsigned int n, unsigned int k)
{
    unsigned int i, j, b, e;
    unsigned int pivot, tmp;
    unsigned int h;

    b = 0;
    e = n - 1;

    for (h = 0; h < n; h++) { printf("%u ", a[h]); } printf("\n");

    while (b < e) {
        pivot = a[b];
        i = b;
        j = e;
        printf("b=%u e=%u pivot=%u\n", b, e, pivot);
        while (i < j) {
            while (i < j && a[i] < pivot) i ++;
            while (i < j && a[j] > pivot) j --;
            if (i < j) {
                printf("i-->%u j-->%u, swap %u <--> %u\n", i, j, a[i], a[j]);
                tmp = a[i];
                a[i] = a[j];
                a[j] = tmp;
                for (h = 0; h < n; h++) { printf("%u ", a[h]); } printf("\n");
            }
        }

        if (k < i) {
            e = i - 1;
        } else {
            b = j + 1;
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

    x = sel(a, N, 95);

    printf("Select %u\n", x);

    return 0;
}
