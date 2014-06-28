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

#ifdef STATS

#include <time.h>

struct stats
{
    long long mk_session_create[2];
    long long mk_session_get[2];
    long long mk_http_method_get[2];
    long long mk_http_request_end[2];
    long long mk_http_range_parse[2];
    long long mk_http_init[2];
    long long mk_sched_get_connection[2];
    long long mk_sched_remove_client[2];
    long long mk_plugin_stage_run[2];
    long long mk_plugin_event_read[2];
    long long mk_plugin_event_write[2];
    long long mk_header_send[2];
    long long mk_conn_read[2];
    long long mk_conn_write[2];
    //...
};

static inline long long stats_current_time()
{
    struct timespec ts;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts);

    return ts.tv_sec * 1000000000 + ts.tv_nsec;
}

#define STATS_COUNTER_START(func_name)\
    do {\
        stats->func_name[0]++;\
        stats->func_name[1] -= stats_current_time();\
    } while (0)

#define STATS_COUNTER_STOP(func_name)\
    do {\
        stats->func_name[1] += stats_current_time();\
    } while (0)

#else

#define STATS_COUNTER_START(sched_list_node, func_name)
#define STATS_COUNTER_STOP(sched_list_node, func_name)

#endif

#endif
