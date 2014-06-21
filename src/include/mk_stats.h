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

#ifndef MK_STATS_H
#define MK_STATS_H

#include <time.h>

struct stats
{
    long long mk_session_create_n;
    long long mk_session_create;
    long long mk_session_get_n;
    long long mk_session_get;
    long long mk_http_method_get_n;
    long long mk_http_method_get;
    long long mk_http_request_end_n;
    long long mk_http_request_end;
    long long mk_http_range_parse_n;
    long long mk_http_range_parse;
    long long mk_http_init_n;
    long long mk_http_init;
    long long mk_sched_get_connection_n;
    long long mk_sched_get_connection;
    long long mk_sched_remove_client_n;
    long long mk_sched_remove_client;
    long long mk_plugin_stage_run_n;
    long long mk_plugin_stage_run;
    long long mk_plugin_event_read_n;
    long long mk_plugin_event_read;
    long long mk_plugin_event_write_n;
    long long mk_plugin_event_write;
    long long mk_header_send_n;
    long long mk_header_send;
    long long mk_conn_read_n;
    long long mk_conn_read;
    long long mk_conn_write_n;
    long long mk_conn_write;
    //...
};

static inline long long stats_current_time()
{
    struct timespec ts;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts);

    return ts.tv_sec * 1000000000 + ts.tv_nsec;
}

#ifdef STATS

#define STATS_COUNTER_START(sched_list_node, func_name)\
    do {\
        sched_list_node->stats->func_name##_n++;\
        sched_list_node->stats->func_name -= stats_current_time();\
    } while (0)

#define STATS_COUNTER_STOP(sched_list_node, func_name)\
    do {\
        sched_list_node->stats->func_name += stats_current_time();\
    } while (0)

#define STATS_COUNTER_INIT_NO_SCHED\
    struct sched_list_node *__sched = pthread_getspecific(worker_sched_node)

#define STATS_COUNTER_START_NO_SCHED(func_name)\
    do {\
        STATS_COUNTER_START(__sched, func_name);\
    } while (0)

#define STATS_COUNTER_STOP_NO_SCHED(func_name)\
    do {\
        STATS_COUNTER_STOP(__sched, func_name);\
    } while (0)

#else

#define STATS_COUNTER_START(sched_list_node, func_name)
#define STATS_COUNTER_STOP(sched_list_node, func_name)
#define STATS_COUNTER_INIT_NO_SCHED
#define STATS_COUNTER_START_NO_SCHED(func_name)
#define STATS_COUNTER_STOP_NO_SCHED(func_name)

#endif

#endif
