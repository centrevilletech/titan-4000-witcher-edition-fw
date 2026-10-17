/* Bootstrap seed collector. Never substitutes predictable data after failure. */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "jitterentropy.h"

int main(int argc, char **argv)
{
    int test = argc == 2 && strcmp(argv[1], "--self-test") == 0;
    if (argc != 1 && !test) return 64;
    /* Bounds startup and collection even if the platform timer stalls. */
    alarm(90);
    unsigned int flags = JENT_FORCE_FIPS | JENT_DISABLE_INTERNAL_TIMER;
    int rc = jent_entropy_init_ex(3, flags);
    if (rc) {
        fprintf(stderr, "Entropy startup health check failed (%d)\n", rc);
        return 1;
    }
    struct rand_data *collector = jent_entropy_collector_alloc(3, flags);
    if (!collector) return 2;
    char seed[64];
    ssize_t size = jent_read_entropy(collector, seed, sizeof(seed));
    jent_entropy_collector_free(collector);
    if (size != sizeof(seed)) {
        jent_memset_secure(seed, sizeof(seed));
        fprintf(stderr, "Entropy collection health check failed (%ld)\n", (long)size);
        return 3;
    }
    int result = test ? 0 : (fwrite(seed, 1, sizeof(seed), stdout) != sizeof(seed) || fflush(stdout));
    jent_memset_secure(seed, sizeof(seed));
    if (test) puts("Jitterentropy startup and collection health checks passed");
    return result ? 4 : 0;
}
