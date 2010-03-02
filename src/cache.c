/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2010, Eduardo Silva P.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Library General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include <pthread.h>
#include "iov.h"
#include "cache.h"
#include "request.h"

#include <stdio.h>
#include <stdlib.h>

/* This function is called when a thread is created */
void mk_cache_thread_init()
{
    struct request_idx *cache_request_idx;
    struct mk_iov *cache_iov_log;
    struct mk_iov *cache_iov_header;
    struct header_toc *cache_header_toc;

    /* client request index */
    cache_request_idx = mk_mem_malloc(sizeof(struct request_idx));
    cache_request_idx->first = NULL;
    cache_request_idx->last = NULL;
    pthread_setspecific(request_index, (void *) cache_request_idx);

    /* Cache iov log struct */
    cache_iov_log = mk_iov_create(15, 0);
    pthread_setspecific(mk_cache_iov_log, (void *) cache_iov_log);

    /* Cache iov header struct */
    cache_iov_header = mk_iov_create(45, 0);
    pthread_setspecific(mk_cache_iov_header, (void *) cache_iov_header);

    /* Cache header toc, monkey just search for MK_KNOWN_HEADERS
     * in request 
     */
    cache_header_toc = mk_mem_malloc_z(sizeof(struct header_toc) *
                                       MK_KNOWN_HEADERS);
    pthread_setspecific(mk_cache_header_toc, (void *) cache_header_toc);
}
