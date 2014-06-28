#include <stdio.h>
#include <dlfcn.h>
#include "mk_stats.h"

struct client_session;
struct sched_list_node;
struct session_request;

static void *monkey_so;
static struct client_session *(*__mk_session_create)(int, struct sched_list_node *);
static struct client_session *(*__mk_session_get)(int);
static int (*__mk_http_method_get)(char *);
static int (*__mk_http_request_end)(int);
static int (*__mk_http_range_parse)(struct session_request *);
static int (*__mk_http_init)(struct client_session *, struct session_request *);
static struct sched_connection *(*__mk_sched_get_connection)(struct sched_list_node *, int);
static int (*__mk_sched_remove_client)(struct sched_list_node *, int);
static int (*__mk_plugin_stage_run)(unsigned int, unsigned int, struct sched_connection *, struct client_session *, struct session_request *);
static int (*__mk_plugin_event_read)(int);
static int (*__mk_plugin_event_write)(int);
static int (*__mk_header_send)(int, struct client_session *, struct session_request *);
static int (*__mk_conn_read)(int);
static int (*__mk_conn_write)(int);

__thread struct stats *stats;

__attribute__((constructor))
void stats_init(void)
{
    monkey_so = dlopen("libmonkey.so", RTLD_LAZY); //TODO NOW
    *(void **) (&__mk_session_create) = dlsym(monkey_so, "mk_session_create");
    *(void **) (&__mk_session_get) = dlsym(monkey_so, "mk_session_get");
    *(void **) (&__mk_http_method_get) = dlsym(monkey_so, "mk_http_method_get");
    *(void **) (&__mk_http_request_end) = dlsym(monkey_so, "mk_http_request_end");
    *(void **) (&__mk_http_range_parse) = dlsym(monkey_so, "mk_http_range_parse");
    *(void **) (&__mk_http_init) = dlsym(monkey_so, "mk_http_init");
    *(void **) (&__mk_sched_get_connection) = dlsym(monkey_so, "mk_sched_get_connection");
    *(void **) (&__mk_sched_remove_client) = dlsym(monkey_so, "mk_sched_remove_client");
    *(void **) (&__mk_plugin_stage_run) = dlsym(monkey_so, "mk_plugin_stage_run");
    *(void **) (&__mk_plugin_event_read) = dlsym(monkey_so, "mk_plugin_event_read");
    *(void **) (&__mk_plugin_event_write) = dlsym(monkey_so, "mk_plugin_event_write");
    *(void **) (&__mk_header_send) = dlsym(monkey_so, "mk_header_send");
    *(void **) (&__mk_conn_read) = dlsym(monkey_so, "mk_conn_read");
    *(void **) (&__mk_conn_write) = dlsym(monkey_so, "mk_conn_write");
}

__attribute__((destructor))
void stats_fini(void)
{
    dlclose(monkey_so);
}

struct client_session *mk_session_create(int socket, struct sched_list_node *sched)
{
    struct client_session *ret;
    STATS_COUNTER_START(mk_session_create);
    ret = __mk_session_create(socket, sched);
    STATS_COUNTER_STOP(mk_session_create);
    return ret;
}

struct client_session *mk_session_get(int socket)
{
    struct client_session *ret;
    STATS_COUNTER_START(mk_session_get);
    ret = __mk_session_get(socket);
    STATS_COUNTER_STOP(mk_session_get);
    return ret;
}

int mk_http_method_get(char *body)
{
    int ret;
    STATS_COUNTER_START(mk_http_method_get);
    ret = __mk_http_method_get(body);
    STATS_COUNTER_STOP(mk_http_method_get);
    return ret;
}

int mk_http_request_end(int socket)
{
    int ret;
    STATS_COUNTER_START(mk_http_request_end);
    ret = __mk_http_request_end(socket);
    STATS_COUNTER_STOP(mk_http_request_end);
    return ret;
}

int mk_http_range_parse(struct session_request *sr)
{
    int ret;
    STATS_COUNTER_START(mk_http_range_parse);
    ret = __mk_http_range_parse(sr);
    STATS_COUNTER_STOP(mk_http_range_parse);
    return ret;
}

int mk_http_init(struct client_session *cs, struct session_request *sr)
{
    int ret;
    STATS_COUNTER_START(mk_http_init);
    ret = __mk_http_init(cs, sr);
    STATS_COUNTER_STOP(mk_http_init);
    return ret;
}

struct sched_connection *mk_sched_get_connection(struct sched_list_node *sched, int remote_fd)
{
    struct sched_connection *ret;
    STATS_COUNTER_START(mk_sched_get_connection);
    ret = __mk_sched_get_connection(sched, remote_fd);
    STATS_COUNTER_STOP(mk_sched_get_connection);
    return ret;
}

int mk_sched_remove_client(struct sched_list_node *sched, int remote_fd)
{
    int ret;
    STATS_COUNTER_START(mk_sched_remove_client);
    ret = __mk_sched_remove_client(sched, remote_fd);
    STATS_COUNTER_STOP(mk_sched_remove_client);
    return ret;
}

int mk_plugin_stage_run(unsigned int hook, unsigned int socket, struct sched_connection *conx, struct client_session *cs, struct session_request *sr)
{
    int ret;
    STATS_COUNTER_START(mk_plugin_stage_run);
    ret = __mk_plugin_stage_run(hook, socket, conx, cs, sr);
    STATS_COUNTER_STOP(mk_plugin_stage_run);
    return ret;
}

int mk_plugin_event_read(int socket)
{
    int ret;
    STATS_COUNTER_START(mk_plugin_event_read);
    ret = __mk_plugin_event_read(socket);
    STATS_COUNTER_STOP(mk_plugin_event_read);
    return ret;
}

int mk_plugin_event_write(int socket)
{
    int ret;
    STATS_COUNTER_START(mk_plugin_event_write);
    ret = __mk_plugin_event_write(socket);
    STATS_COUNTER_STOP(mk_plugin_event_write);
    return ret;
}

int mk_header_send(int fd, struct client_session *cs, struct session_request *sr)
{
    int ret = 0;
    STATS_COUNTER_START(mk_header_send);
    ret = __mk_header_send(fd, cs, sr);
    STATS_COUNTER_STOP(mk_header_send);
    return ret;
}

int mk_conn_read(int socket)
{
    int ret = 0;
    STATS_COUNTER_START(mk_conn_read);
    ret = __mk_conn_read(socket);
    STATS_COUNTER_STOP(mk_conn_read);
    return ret;
}

int mk_conn_write(int socket)
{
    int ret = 0;
    STATS_COUNTER_START(mk_conn_write);
    ret = __mk_conn_write(socket);
    STATS_COUNTER_STOP(mk_conn_write);
    return ret;
}
