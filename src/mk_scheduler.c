/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2014 Monkey Software LLC <eduardo@monkey.io>
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <string.h>

#include <monkey/monkey.h>
#include <monkey/mk_vhost.h>
#include <monkey/mk_connection.h>
#include <monkey/mk_scheduler.h>
#include <monkey/mk_server.h>
#include <monkey/mk_memory.h>
#include <monkey/mk_request.h>
#include <monkey/mk_cache.h>
#include <monkey/mk_config.h>
#include <monkey/mk_clock.h>
#include <monkey/mk_signals.h>
#include <monkey/mk_plugin.h>
#include <monkey/mk_utils.h>
#include <monkey/mk_macros.h>
#include <monkey/mk_rbtree.h>
#include <monkey/mk_linuxtrace.h>
#include <monkey/mk_stats.h>
#include <monkey/mk_server.h>


struct sched_list_node *sched_list;

static pthread_mutex_t mutex_sched_init = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex_worker_init = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex_worker_exit = PTHREAD_MUTEX_INITIALIZER;

__thread struct rb_root *cs_list;
__thread struct mk_list *cs_incomplete;
__thread struct sched_list_node *worker_sched_node;

#ifdef STATS
__thread struct stats *stats;
#endif

/*
 * Returns the worker id which should take a new incomming connection,
 * it returns the worker id with less active connections. Just used
 * if config->scheduler_mode is MK_SCHEDULER_FAIR_BALANCING.
 */
static inline int _next_target()
{
    int i;
    int target = 0;
    unsigned long long tmp = 0, cur = 0;

    cur = sched_list[0].accepted_connections - sched_list[0].closed_connections;
    if (cur == 0)
        return 0;

    /* Finds the lowest load worker */
    for (i = 1; i < config->workers; i++) {
        tmp = sched_list[i].accepted_connections - sched_list[i].closed_connections;
        if (tmp < cur) {
            target = i;
            cur = tmp;

            if (cur == 0)
                break;
        }
    }

    /*
     * If sched_list[target] worker is full then the whole server too, because
     * it has the lowest load.
     */
    if (mk_unlikely(cur >= config->server_capacity)) {
        MK_TRACE("Too many clients: %i", config->server_capacity);

        /* Instruct to close the connection anyways, we lie, it will die */
        return -1;
    }

    return target;
}

struct sched_list_node *mk_sched_next_target()
{
    int t = _next_target();

    if (mk_likely(t != -1))
        return &sched_list[t];
    else
        return NULL;
}

/*
 * This function synchronize the worker scheduler counters in case
 * we face the ULONG_MAX bug, this is an unexpected behavior but
 * until it become fixed this routine must run with mutual exclusion
 * to avoid data corruption.
 */
int mk_sched_sync_counters()
{
    uint64_t n = 0;
    struct mk_list *head;
    struct sched_list_node *sched;

    /* we only aim to fix the value of closed_connections */
    pthread_mutex_lock(&mutex_sched_init);
    sched = mk_sched_get_thread_conf();

    MK_LT_SCHED(sched->signal_channel, "SYNC COUNTERS");

    if (sched->closed_connections > sched->accepted_connections) {
        /* Count the real number of active connections */
        mk_list_foreach(head, &sched->busy_queue) {
            n++;
        }

        /*
         * At this point we have N active connections in the busy
         * queue, lets assume that we need to close N to reach the number
         * of accepted connections.
         */
        sched->accepted_connections = n;
        sched->closed_connections   = 0;
        sched->over_capacity        = 0;
    }
    pthread_mutex_unlock(&mutex_sched_init);

    return 0;
}

/*
 * This function is invoked when the core triggers a MK_SCHED_SIGNAL_FREE_ALL
 * event through the signal channels, it means the server will stop working
 * so this is the last call to release all memory resources in use. Of course
 * this takes place in a thread context.
 */
void mk_sched_worker_free()
{
    int i;
    pthread_t tid;
    struct sched_list_node *sl = NULL;

    pthread_mutex_lock(&mutex_worker_exit);

    /*
     * Fix Me: needs to implement API to make plugins release
     * their resources first at WORKER LEVEL
     */

    /* External */
    mk_plugin_exit_worker();
    mk_vhost_fdt_worker_exit();
    mk_cache_worker_exit();

    /* Scheduler stuff */
    tid = pthread_self();
    for (i = 0; i < config->workers; i++) {
        if (sched_list[i].tid == tid) {
            sl = &sched_list[i];
        }
    }

    mk_bug(!sl);

    //sl->request_handler;

    /* Free master array (av queue & busy queue) */
    mk_mem_free(sl->sched_array);
    mk_mem_free(cs_list);
    pthread_mutex_unlock(&mutex_worker_exit);
}

/*
 * It checks that current worker (under sched context) have enough
 * capacity for a new connection. If its not the case, the connection
 * is held until it can be accepted, then it counts up to 5000 fails
 * of this type and then increase capacity by 10%.
 */
int mk_sched_check_capacity(struct sched_list_node *sched)
{
    if (mk_list_is_empty(&sched->av_queue) == 0) {
        /* The server is over capacity */
        sched->over_capacity++;
        if (sched->over_capacity % 5000) {
            //mk_warn("Scheduler: Server is over capacity\n"
            //        "- more than 5000 attemps stalled\n"
            //        "- increasing worker %lu capacity by 10%%",
            //        syscall(__NR_gettid));
            sched->over_capacity = 0;
        }
        return -1;
    }

    return 0;
}

/*
 * Register a new client connection into the scheduler, this call takes place
 * inside the worker/thread context.
 */
int mk_sched_register_client(int remote_fd, struct sched_list_node *sched)
{
    int ret;
    struct sched_connection *sched_conn;
    struct mk_list *av_queue = &sched->av_queue;

    if ((config->kernel_features & MK_KERNEL_SO_REUSEPORT) &&
        mk_list_is_empty(av_queue) == 0) {
        mk_event_del(sched->loop, remote_fd);
        close(remote_fd);
        return -1;
    }

    sched_conn = mk_list_entry_first(av_queue, struct sched_connection, _head);

    /* Before to continue, we need to run plugin stage 10 */
    ret = mk_plugin_stage_run(MK_PLUGIN_STAGE_10,
                              remote_fd,
                              sched_conn, NULL, NULL);

    /* Close connection, otherwise continue */
    if (ret == MK_PLUGIN_RET_CLOSE_CONX) {
        mk_event_del(sched->loop, remote_fd);
        mk_socket_close(remote_fd);
        MK_LT_SCHED(remote_fd, "PLUGIN_CLOSE");
        return -1;
    }

    /* Socket and status */
    sched_conn->socket = remote_fd;
    sched_conn->status = MK_SCHEDULER_CONN_PENDING;
    sched_conn->arrive_time = log_current_utime;

    /* Register the entry in the red-black tree queue for fast lookup */
    struct rb_node **new = &(sched->rb_queue.rb_node);
    struct rb_node *parent = NULL;

    /* Figure out where to put new node */
    while (*new) {
        struct sched_connection *this = container_of(*new, struct sched_connection, _rb_head);

        parent = *new;
        if (sched_conn->socket < this->socket)
            new = &((*new)->rb_left);
        else if (sched_conn->socket > this->socket)
            new = &((*new)->rb_right);
        else {
            break;
        }
    }

    /* Add new node and rebalance tree. */
    rb_link_node(&sched_conn->_rb_head, parent, new);
    rb_insert_color(&sched_conn->_rb_head, &sched->rb_queue);

    /* Move to busy queue */
    mk_list_del(&sched_conn->_head);
    mk_list_add(&sched_conn->_head, &sched->busy_queue);

    /* As the connection is still pending, add it to the incoming_queue */
    mk_list_add(&sched_conn->status_queue, &sched->incoming_queue);

    /* Linux trace message */
    MK_LT_SCHED(remote_fd, "REGISTERED");

    return 0;
}

static void mk_sched_thread_lists_init()
{
    /* client_session mk_list */
    cs_list = mk_mem_malloc_z(sizeof(struct rb_root));
    cs_incomplete = mk_mem_malloc(sizeof(struct mk_list));
    mk_list_init(cs_incomplete);
}

/* Register thread information. The caller thread is the thread information's owner */
static int mk_sched_register_thread()
{
    unsigned int i;
    struct sched_connection *sched_conn;
    struct sched_list_node *sl;
    static int wid = 0;

    /*
     * If this thread slept inside this section, some other thread may touch wid.
     * So protect it with a mutex, only one thread may handle wid.
     */
    pthread_mutex_lock(&mutex_sched_init);

    sl = &sched_list[wid];
    sl->idx = wid++;
    sl->tid = pthread_self();

    /*
     * Under Linux does not exists the difference between process and
     * threads, everything is a thread in the kernel task struct, and each
     * one has it's own numerical identificator: PID .
     *
     * Here we want to know what's the PID associated to this running
     * task (which is different from parent Monkey PID), it can be
     * retrieved with gettid() but Glibc does not export to userspace
     * the syscall, we need to call it directly through syscall(2).
     */
    sl->pid = syscall(__NR_gettid);

    pthread_mutex_unlock(&mutex_sched_init);

    /* Initialize lists */
    sl->rb_queue = RB_ROOT;
    mk_list_init(&sl->busy_queue);
    mk_list_init(&sl->av_queue);
    mk_list_init(&sl->incoming_queue);

    /* Start filling the array */
    sl->sched_array = mk_mem_malloc_z(sizeof(struct sched_connection) *
                                      config->server_capacity);
    for (i = 0; i < config->server_capacity; i++) {
        sched_conn = &sl->sched_array[i];
        sched_conn->status = MK_SCHEDULER_CONN_AVAILABLE;
        sched_conn->socket = -1;
        sched_conn->arrive_time = 0;
        mk_list_add(&sched_conn->_head, &sl->av_queue);
    }
    sl->request_handler = NULL;

    return sl->idx;
}

/* created thread, all this calls are in the thread context */
void *mk_sched_launch_worker_loop(void *thread_conf)
{
    int ret;
    int wid;
    unsigned long len;
    char *thread_name = 0;
    struct sched_list_node *sched = NULL;
    struct mk_server_listen server_listen;

#ifdef STATS
    stats = mk_mem_malloc_z(sizeof(struct stats));
#endif

#ifndef SHAREDLIB
    /* Avoid SIGPIPE signals */
    mk_signal_thread_sigpipe_safe();
#endif

    /* Init specific thread cache */
    mk_sched_thread_lists_init();
    mk_cache_worker_init();

    /* Register working thread */
    wid = mk_sched_register_thread();

    /* Plugin thread context calls */
    mk_plugin_event_init_list();

    sched = &sched_list[wid];
    sched->loop = mk_event_loop_create(MK_EVENT_QUEUE_SIZE);
    if (!sched->loop) {
        mk_err("Error creating Scheduler loop");
        exit(EXIT_FAILURE);
    }

    /* Register the scheduler channel to signal active workers */
    ret = mk_event_channel_create(sched->loop,
                                  &sched->signal_channel_r,
                                  &sched->signal_channel_w);
    if (ret < 0) {
        exit(EXIT_FAILURE);
    }

    /*
     * ULONG_MAX BUG test only
     * =======================
     * to test the workaround we can use the following value:
     *
     *  thinfo->closed_connections = 1000;
     */

#ifdef SHAREDLIB
#ifdef STATS
    thconf->ctx->worker_info[wid]->stats = stats;
#endif
    //thinfo->ctx = thconf->ctx;
#endif

    mk_mem_free(thread_conf);

    /* Rename worker */
    mk_string_build(&thread_name, &len, "monkey: wrk/%i", sched->idx);
    mk_utils_worker_rename(thread_name);
    mk_mem_free(thread_name);

    /* Export known scheduler node to context thread */
    worker_sched_node = sched;
    mk_plugin_core_thread();

    if (config->scheduler_mode == MK_SCHEDULER_REUSEPORT) {
        if (mk_server_listen_init(config, &server_listen)) {
            mk_err("[sched] Failed to initialize listen sockets.");
            return 0;
        }
    }

    __builtin_prefetch(sched);
    __builtin_prefetch(&worker_sched_node);

    pthread_mutex_lock(&mutex_worker_init);
    sched->initialized = 1;
    pthread_mutex_unlock(&mutex_worker_init);

    /* init server thread loop */
    mk_server_worker_loop(&server_listen);
    return 0;
}

/* Create thread which will be listening for incomings requests */
int mk_sched_launch_thread(int max_events, pthread_t *tout, mklib_ctx ctx UNUSED_PARAM)
{
    pthread_t tid;
    pthread_attr_t attr;
    sched_thread_conf *thconf;
    (void) max_events;

    /* Thread data */
    thconf = mk_mem_malloc_z(sizeof(sched_thread_conf));
#ifdef SHAREDLIB
    thconf->ctx = ctx;
#endif

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
    if (pthread_create(&tid, &attr, mk_sched_launch_worker_loop,
                       (void *) thconf) != 0) {
        mk_libc_error("pthread_create");
        return -1;
    }

    *tout = tid;

    return 0;
}

/*
 * The scheduler nodes are an array of struct sched_list_node type,
 * each worker thread belongs to a scheduler node, on this function we
 * allocate a scheduler node per number of workers defined.
 */
void mk_sched_init()
{
    int size;

    size = sizeof(struct sched_list_node) * config->workers;
    sched_list = mk_mem_malloc_z(size);
    mk_event_initalize();
}

void mk_sched_set_request_list(struct rb_root *list)
{
    cs_list = list;
}

int mk_sched_remove_client(struct sched_list_node *sched, int remote_fd)
{
    struct sched_connection *sc;

    /*
     * Close socket and change status: we must invoke mk_epoll_del()
     * because when the socket is closed is cleaned from the queue by
     * the Kernel at its leisure, and we may get false events if we rely
     * on that.
     */
    mk_event_del(sched->loop, remote_fd);

    sc = mk_sched_get_connection(sched, remote_fd);
    if (sc) {
        MK_TRACE("[FD %i] Scheduler remove", remote_fd);

#ifdef TRACE
        /*
         * This is a double check just enable on Trace mode to try to find
         * conditions of bad API usage. When a Session is exiting, no
         * client_session context associated to the remote_fd must exists.
         */
        struct client_session *cs = mk_session_get(remote_fd);
        if (cs) {
            mk_err("[FD %i] A client_session exists, bad API usage",
                   remote_fd);
            mk_session_remove(remote_fd);
        }
#endif

        /* Invoke plugins in stage 50 */
        mk_plugin_stage_run(MK_PLUGIN_STAGE_50, remote_fd, NULL, NULL, NULL);

        sched->closed_connections++;

        /* Change node status */
        sc->status = MK_SCHEDULER_CONN_AVAILABLE;
        sc->socket = -1;

        /* Unlink from the red-black tree */
        rb_erase(&sc->_rb_head, &sched->rb_queue);

        /* Unlink from busy queue and put it in available queue again */
        mk_list_del(&sc->_head);
        mk_list_add(&sc->_head, &sched->av_queue);

        if (mk_list_entry_orphan(&sc->status_queue) == 0) {
            mk_list_del(&sc->status_queue);
        }

        /* Only close if this was our connection.
         *
         * This has to happen _after_ the busy list removal,
         * otherwise we could get a new client accept()ed with
         * the same FD before we do the removal from the busy list,
         * causing ghosts.
         */
        mk_socket_close(remote_fd);
        MK_LT_SCHED(remote_fd, "DELETE_CLIENT");
        return 0;
    }
    else {
        MK_TRACE("[FD %i] Not found", remote_fd);
        MK_LT_SCHED(remote_fd, "DELETE_NOT_FOUND");
    }
    return -1;
}

struct sched_connection *mk_sched_get_connection(struct sched_list_node *sched,
                                                 int remote_fd)
{
    struct rb_node *node;
    struct sched_connection *this;

    /*
     * In some cases the sched node can be NULL when is a premature close,
     * an example of this situation is when the function mk_sched_add_client()
     * close an incoming connection when invoking the MK_PLUGIN_STAGE_10 stage plugin,
     * so no thread context exists.
     */
    if (!sched) {
        MK_TRACE("[FD %i] No scheduler information", remote_fd);
        mk_socket_close(remote_fd);
        return NULL;
    }

  	node = sched->rb_queue.rb_node;
  	while (node) {
  		this = container_of(node, struct sched_connection, _rb_head);
		if (remote_fd < this->socket)
  			node = node->rb_left;
		else if (remote_fd > this->socket)
  			node = node->rb_right;
		else {
            MK_LT_SCHED(remote_fd, "GET_CONNECTION");
  			return this;
        }
	}

    MK_TRACE("[FD %i] not found in scheduler list", remote_fd);
    MK_LT_SCHED(remote_fd, "GET_FAILED");
    return NULL;
}

int mk_sched_check_timeouts(struct sched_list_node *sched)
{
    int client_timeout;
    struct client_session *cs_node;
    struct sched_connection *entry_conn;
    struct mk_list *head;
    struct mk_list *temp;

    /* PENDING CONN TIMEOUT */
    mk_list_foreach_safe(head, temp, &sched->incoming_queue) {
        entry_conn = mk_list_entry(head, struct sched_connection, status_queue);
        client_timeout = entry_conn->arrive_time + config->timeout;

        /* Check timeout */
        if (client_timeout <= log_current_utime) {
            MK_TRACE("Scheduler, closing fd %i due TIMEOUT", entry_conn->socket);
            MK_LT_SCHED(entry_conn->socket, "TIMEOUT_CONN_PENDING");
            mk_sched_remove_client(sched, entry_conn->socket);
        }
    }

    /* PROCESSING CONN TIMEOUT */
    if (mk_list_is_empty(cs_incomplete) != 0) {
        return 0;
    }

    mk_list_foreach_safe(head, temp, cs_incomplete) {
        cs_node = mk_list_entry(head, struct client_session, request_incomplete);
        if (cs_node->counter_connections == 0) {
            client_timeout = cs_node->init_time + config->timeout;
        }
        else {
            client_timeout = cs_node->init_time + config->keep_alive_timeout;
        }

        /* Check timeout */
        if (client_timeout <= log_current_utime) {
            MK_TRACE("[FD %i] Scheduler, closing due to timeout (incomplete)",
                     cs_node->socket);
            MK_LT_SCHED(cs_node->socket, "TIMEOUT_REQ_INCOMPLETE");
            mk_sched_remove_client(sched, cs_node->socket);
            mk_session_remove(cs_node->socket);
        }
    }

    return 0;
}


int mk_sched_update_conn_status(struct sched_list_node *sched,
                                int remote_fd, int status)
{
    struct sched_connection *sched_conn;

    if (mk_unlikely(!sched)) {
        return -1;
    }

    sched_conn = mk_sched_get_connection(sched, remote_fd);
    mk_bug(!sched_conn);
    sched_conn->status = status;

    /* Incoming queue check */
    if (status == MK_SCHEDULER_CONN_PENDING) {
        mk_list_add(&sched_conn->status_queue, &sched->incoming_queue);
    }
    else {
        if (mk_list_entry_orphan(&sched_conn->status_queue) == 0) {
            mk_list_del(&sched_conn->status_queue);
        }
    }

    return 0;
}
