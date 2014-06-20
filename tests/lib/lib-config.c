#include <libmonkey.h>
#include <stdio.h>

int main(void) {
    int workers, resume, timeout, keepalive;
    FILE *f;
    mklib_ctx ctx = mklib_init(NULL, 0, 0, NULL);

    if (!ctx)
        return 1;

    if (!mklib_config(ctx,
                MKC_WORKERS, 2,
                MKC_RESUME, MKLIB_FALSE,
                MKC_TIMEOUT, 1000,
                MKC_KEEPALIVE, MKLIB_FALSE,
                NULL))
        return 1;

    if (!mklib_get_config(ctx,
                MKC_WORKERS, &workers,
                MKC_RESUME, &resume,
                MKC_TIMEOUT, &timeout,
                MKC_KEEPALIVE, &keepalive,
                NULL))
        return 1;

    if (workers != 2 ||
            resume != MKLIB_FALSE ||
            timeout != 1000 ||
            keepalive != MKLIB_FALSE
       )
        return 1;

    if (!mklib_start(ctx))
        return 1;

    f = popen("ps -eLf | grep lib-config | grep -v run-tests | grep -v grep", "r");
    if (!f)
        return 1;
    fscanf(f, "%d\n", &workers);
    pclose(f);

    if (!mklib_stop(ctx))
        return 1;

    if (workers != 2)
        return 1;

    return 0;
}
