#include <dlfcn.h>
#include <monkey/mk_stats.h>

struct client_session;
struct sched_list_node;
struct session_request;

static void *monkey_so;
#if defined(STATS_ALL) || defined(MK_SESSION_CREATE)
static struct client_session *(*__mk_session_create)(int, struct sched_list_node *);
#endif
#if defined(STATS_ALL) || defined(MK_SESSION_GET)
static struct client_session *(*__mk_session_get)(int);
#endif
#if defined(STATS_ALL) || defined(MK_HTTP_METHOD_GET)
static int (*__mk_http_method_get)(char *);
#endif
#if defined(STATS_ALL) || defined(MK_HTTP_REQUEST_END)
static int (*__mk_http_request_end)(int);
#endif
#if defined(STATS_ALL) || defined(MK_HTTP_RANGE_PARSE)
static int (*__mk_http_range_parse)(struct session_request *);
#endif
#if defined(STATS_ALL) || defined(MK_HTTP_INIT)
static int (*__mk_http_init)(struct client_session *, struct session_request *);
#endif
#if defined(STATS_ALL) || defined(MK_SCHED_GET_CONNECTION)
static struct sched_connection *(*__mk_sched_get_connection)(struct sched_list_node *, int);
#endif
#if defined(STATS_ALL) || defined(MK_SCHED_REMOVE_CLIENT)
static int (*__mk_sched_remove_client)(struct sched_list_node *, int);
#endif
#if defined(STATS_ALL) || defined(MK_PLUGIN_STAGE_RUN)
static int (*__mk_plugin_stage_run)(unsigned int, unsigned int, struct sched_connection *, struct client_session *, struct session_request *);
#endif
#if defined(STATS_ALL) || defined(MK_PLUGIN_EVENT_READ)
static int (*__mk_plugin_event_read)(int);
#endif
#if defined(STATS_ALL) || defined(MK_PLUGIN_EVENT_WRITE)
static int (*__mk_plugin_event_write)(int);
#endif
#if defined(STATS_ALL) || defined(MK_HEADER_SEND)
static int (*__mk_header_send)(int, struct client_session *, struct session_request *);
#endif
#if defined(STATS_ALL) || defined(MK_CONN_READ)
static int (*__mk_conn_read)(int);
#endif
#if defined(STATS_ALL) || defined(MK_CONN_WRITE)
static int (*__mk_conn_write)(int);
#endif

__thread struct stats *stats;

__attribute__((constructor))
void stats_init(void)
{
    monkey_so = dlopen("libmonkey.so", RTLD_LAZY);
#if defined(STATS_ALL) || defined(MK_SESSION_CREATE)
    *(void **) (&__mk_session_create) = dlsym(monkey_so, "mk_session_create");
#endif
#if defined(STATS_ALL) || defined(MK_SESSION_GET)
    *(void **) (&__mk_session_get) = dlsym(monkey_so, "mk_session_get");
#endif
#if defined(STATS_ALL) || defined(MK_HTTP_METHOD_GET)
    *(void **) (&__mk_http_method_get) = dlsym(monkey_so, "mk_http_method_get");
#endif
#if defined(STATS_ALL) || defined(MK_HTTP_REQUEST_END)
    *(void **) (&__mk_http_request_end) = dlsym(monkey_so, "mk_http_request_end");
#endif
#if defined(STATS_ALL) || defined(MK_HTTP_RANGE_PARSE)
    *(void **) (&__mk_http_range_parse) = dlsym(monkey_so, "mk_http_range_parse");
#endif
#if defined(STATS_ALL) || defined(MK_HTTP_INIT)
    *(void **) (&__mk_http_init) = dlsym(monkey_so, "mk_http_init");
#endif
#if defined(STATS_ALL) || defined(MK_SCHED_GET_CONNECTION)
    *(void **) (&__mk_sched_get_connection) = dlsym(monkey_so, "mk_sched_get_connection");
#endif
#if defined(STATS_ALL) || defined(MK_SCHED_REMOVE_CLIENT)
    *(void **) (&__mk_sched_remove_client) = dlsym(monkey_so, "mk_sched_remove_client");
#endif
#if defined(STATS_ALL) || defined(MK_PLUGIN_STAGE_RUN)
    *(void **) (&__mk_plugin_stage_run) = dlsym(monkey_so, "mk_plugin_stage_run");
#endif
#if defined(STATS_ALL) || defined(MK_PLUGIN_EVENT_READ)
    *(void **) (&__mk_plugin_event_read) = dlsym(monkey_so, "mk_plugin_event_read");
#endif
#if defined(STATS_ALL) || defined(MK_PLUGIN_EVENT_WRITE)
    *(void **) (&__mk_plugin_event_write) = dlsym(monkey_so, "mk_plugin_event_write");
#endif
#if defined(STATS_ALL) || defined(MK_HEADER_SEND)
    *(void **) (&__mk_header_send) = dlsym(monkey_so, "mk_header_send");
#endif
#if defined(STATS_ALL) || defined(MK_CONN_READ)
    *(void **) (&__mk_conn_read) = dlsym(monkey_so, "mk_conn_read");
#endif
#if defined(STATS_ALL) || defined(MK_CONN_WRITE)
    *(void **) (&__mk_conn_write) = dlsym(monkey_so, "mk_conn_write");
#endif
}

__attribute__((destructor))
void stats_fini(void)
{
    dlclose(monkey_so);
}

#if defined(STATS_ALL) || defined(MK_SESSION_CREATE)
struct client_session *mk_session_create(int socket, struct sched_list_node *sched)
{
    struct client_session *ret;
    STATS_COUNTER_START(mk_session_create);
    ret = __mk_session_create(socket, sched);
    STATS_COUNTER_STOP(mk_session_create);
    return ret;
}
#endif

#if defined(STATS_ALL) || defined(MK_SESSION_GET)
struct client_session *mk_session_get(int socket)
{
    struct client_session *ret;
    STATS_COUNTER_START(mk_session_get);
    ret = __mk_session_get(socket);
    STATS_COUNTER_STOP(mk_session_get);
    return ret;
}
#endif

#if defined(STATS_ALL) || defined(MK_HTTP_METHOD_GET)
int mk_http_method_get(char *body)
{
    int ret;
    STATS_COUNTER_START(mk_http_method_get);
    ret = __mk_http_method_get(body);
    STATS_COUNTER_STOP(mk_http_method_get);
    return ret;
}
#endif

#if defined(STATS_ALL) || defined(MK_HTTP_REQUEST_END)
int mk_http_request_end(int socket)
{
    int ret;
    STATS_COUNTER_START(mk_http_request_end);
    ret = __mk_http_request_end(socket);
    STATS_COUNTER_STOP(mk_http_request_end);
    return ret;
}
#endif

#if defined(STATS_ALL) || defined(MK_HTTP_RANGE_PARSE)
int mk_http_range_parse(struct session_request *sr)
{
    int ret;
    STATS_COUNTER_START(mk_http_range_parse);
    ret = __mk_http_range_parse(sr);
    STATS_COUNTER_STOP(mk_http_range_parse);
    return ret;
}
#endif

#if defined(STATS_ALL) || defined(MK_HTTP_INIT)
int mk_http_init(struct client_session *cs, struct session_request *sr)
{
    int ret;
    STATS_COUNTER_START(mk_http_init);
    ret = __mk_http_init(cs, sr);
    STATS_COUNTER_STOP(mk_http_init);
    return ret;
}
#endif

#if defined(STATS_ALL) || defined(MK_SCHED_GET_CONNECTION)
struct sched_connection *mk_sched_get_connection(struct sched_list_node *sched, int remote_fd)
{
    struct sched_connection *ret;
    STATS_COUNTER_START(mk_sched_get_connection);
    ret = __mk_sched_get_connection(sched, remote_fd);
    STATS_COUNTER_STOP(mk_sched_get_connection);
    return ret;
}
#endif

#if defined(STATS_ALL) || defined(MK_SCHED_REMOVE_CLIENT)
int mk_sched_remove_client(struct sched_list_node *sched, int remote_fd)
{
    int ret;
    STATS_COUNTER_START(mk_sched_remove_client);
    ret = __mk_sched_remove_client(sched, remote_fd);
    STATS_COUNTER_STOP(mk_sched_remove_client);
    return ret;
}
#endif

#if defined(STATS_ALL) || defined(MK_PLUGIN_STAGE_RUN)
int mk_plugin_stage_run(unsigned int hook, unsigned int socket, struct sched_connection *conx, struct client_session *cs, struct session_request *sr)
{
    int ret;
    STATS_COUNTER_START(mk_plugin_stage_run);
    ret = __mk_plugin_stage_run(hook, socket, conx, cs, sr);
    STATS_COUNTER_STOP(mk_plugin_stage_run);
    return ret;
}
#endif

#if defined(STATS_ALL) || defined(MK_PLUGIN_EVENT_READ)
int mk_plugin_event_read(int socket)
{
    int ret;
    STATS_COUNTER_START(mk_plugin_event_read);
    ret = __mk_plugin_event_read(socket);
    STATS_COUNTER_STOP(mk_plugin_event_read);
    return ret;
}
#endif

#if defined(STATS_ALL) || defined(MK_PLUGIN_EVENT_WRITE)
int mk_plugin_event_write(int socket)
{
    int ret;
    STATS_COUNTER_START(mk_plugin_event_write);
    ret = __mk_plugin_event_write(socket);
    STATS_COUNTER_STOP(mk_plugin_event_write);
    return ret;
}
#endif

#if defined(STATS_ALL) || defined(MK_HEADER_SEND)
int mk_header_send(int fd, struct client_session *cs, struct session_request *sr)
{
    int ret = 0;
    STATS_COUNTER_START(mk_header_send);
    ret = __mk_header_send(fd, cs, sr);
    STATS_COUNTER_STOP(mk_header_send);
    return ret;
}
#endif

#if defined(STATS_ALL) || defined(MK_CONN_READ)
int mk_conn_read(int socket)
{
    int ret = 0;
    STATS_COUNTER_START(mk_conn_read);
    ret = __mk_conn_read(socket);
    STATS_COUNTER_STOP(mk_conn_read);
    return ret;
}
#endif

#if defined(STATS_ALL) || defined(MK_CONN_WRITE)
int mk_conn_write(int socket)
{
    int ret = 0;
    STATS_COUNTER_START(mk_conn_write);
    ret = __mk_conn_write(socket);
    STATS_COUNTER_STOP(mk_conn_write);
    return ret;
}
#endif
