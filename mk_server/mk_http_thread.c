/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2016 Monkey Software LLC <eduardo@monkey.io>
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

#include <stdlib.h>

#include <monkey/mk_plugin.h>
#include <monkey/mk_thread.h>
#include <monkey/mk_net.h>
#include <monkey/mk_http_thread.h>

static void cb_http_thread_destroy(void *data)
{
    struct mk_http_thread *mth;

    /* Before to destroy the thread context, unlink it */
    mth = (struct mk_http_thread *) data;
    mk_list_del(&mth->_head);
}

struct mk_http_thread *mk_http_thread_new(struct mk_plugin *plugin,
                                          struct mk_http_session *session,
                                          struct mk_http_request *request,
                                          int n_params,
                                          struct mk_list *params)
{
    struct mk_thread *th;
    struct mk_http_thread *mth;
    struct mk_sched_worker *sched;

    sched = mk_sched_get_thread_conf();
    if (!sched) {
        return NULL;
    }

    th = mk_thread_new(sizeof(struct mk_http_thread), cb_http_thread_destroy);
    if (!th) {
        return NULL;
    }

    mth = (struct mk_http_thread *) MK_THREAD_DATA(th);
    if (!mth) {
        return NULL;
    }

    mth->session = session;
    mth->request = request;
    mth->parent  = th;
    mk_list_add(&mth->_head, &sched->threads);

    makecontext(&th->callee, (void (*)()) plugin->stage->stage30_thread, 5,
                              plugin, session, request, n_params, params);

    return mth;
}

int mk_http_thread_event(struct mk_event *event)
{
    struct mk_net_connection *conn;

    conn = (struct mk_net_connection *) event;
    mk_thread_resume(conn->thread);
    return 0;
}
