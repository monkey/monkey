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

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

#include <sys/time.h>
#include <sys/resource.h>

#include <monkey/mk_event.h>
#include <monkey/mk_memory.h>

#include "mk_event_epoll.c"

/*
 * Initialize the global Event structure used by threads to access the
 * global file descriptor table.
 */
int mk_event_initalize()
{
    int ret;
    int entries;
    mk_event_fdt_t *efdt;
    struct rlimit rlim;

    ret = getrlimit(RLIMIT_NOFILE, &rlim);
    if (ret == -1) {
        mk_libc_error("getrlimit");
        return -1;
    }

    efdt = mk_mem_malloc_z(sizeof(struct mk_event_fdt_t));
    if (!efdt) {
        mk_err("Event: could not allocate memory for event FD Table");
        exit(EXIT_ERROR);
    }

    efdt->size = rlim.rlim_cur;
    efdt->states = mk_mem_malloc_z(sizeof(struct mk_event_fd_state) * efdt->size);
    if (!efdt->states) {
        mk_err("Event: could not allocate memory for events states on FD Table");
        exit(EXIT_ERROR);
    }

    return 0;
}

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
