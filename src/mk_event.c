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

#include <monkey/mk_event.h>
#include <monkey/mk_memory.h>

#include "mk_event_epoll.c"

mk_event_loop_t *mk_event_new_loop(int size)
{
    mk_event_loop_t *loop;

    loop = mk_mem_malloc_z(sizeof(mk_event_loop_t));
    if (!loop) {
        return NULL;
    }

    loop->data = mk_event_create(size);
    if (!loop->data) {
        mk_mem_free(loop);
        return NULL;
    }

    return loop;
}
