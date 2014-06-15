#include <libmonkey.h>
#include <unistd.h>
#include <pthread.h>
#include "md5_check.h"

#define NUM_THREADS 10
#define REQ_PER_THREAD 10

const char datac[] = "data";

int data(const mklib_session *sr, const char *vhost, const char *url,
		const char *get, unsigned long get_len,
		const char *post, unsigned long post_len,
		unsigned int *status, const char **content,
		unsigned long *content_len, char *header) {

	*content_len = 4;
	*content = datac;
	return MKLIB_TRUE;
}

void *simple_request(void *portp)
{
    int port = *((int *) portp);
    char comm[1024];
    int i;
    FILE *f;

	snprintf(comm, 1024, "wget --timeout=1 -t2 -q -O- http://localhost:%d", port);
    for (i = 0; i < REQ_PER_THREAD; i++) {
        f = popen(comm, "r");
        if (!f)
            return NULL;
        pclose(f);
    }
    return NULL;
}

int main()
{
    pthread_t threads[NUM_THREADS];
    int i, total = 0, port = 8094;

	mklib_ctx ctx = mklib_init(NULL, port, 0, NULL);
	if (!ctx) return 1;

	mklib_callback_set(ctx, MKCB_DATA, data);

	if (!mklib_start(ctx))
        return 1;

    for (i = 0; i < NUM_THREADS; i++)
        pthread_create(&threads[i], NULL, simple_request, &port);

    for (i = 0; i < NUM_THREADS; i++)
        pthread_join(threads[i], NULL);

    struct mklib_worker_info **mwi = mklib_scheduler_worker_info(ctx);

    for (i = 0; mwi[i]; i++) {
        total += mwi[i]->closed_connections;
        printf("mk_session_create %lld:%lld\n", mwi[i]->mk_session_create_n, mwi[i]->mk_session_create);
        printf("mk_session_get %lld:%lld\n", mwi[i]->mk_session_get_n, mwi[i]->mk_session_get);
        printf("mk_http_method_get %lld:%lld\n", mwi[i]->mk_http_method_get_n, mwi[i]->mk_http_method_get);
        printf("mk_sched_get_connection %lld:%lld\n", mwi[i]->mk_sched_get_connection_n, mwi[i]->mk_sched_get_connection);
        printf("------------------\n");
    }

	if (!mklib_stop(ctx))
        return 1;

    if (total != NUM_THREADS * REQ_PER_THREAD)
        return 1;

	return 0;
}
