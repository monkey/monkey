/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2011, Eduardo Silva P. <edsiper@gmail.com>
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
#include "str.h"
#include "config.h"
#include "macros.h"

#include <stdio.h>
#include <stdlib.h>
#include "utils.h"

/* This function is called when a thread is created */
void mk_cache_thread_init()
{
    mk_pointer *cache_header_lm; 
    mk_pointer *cache_header_cl;
    mk_pointer *cache_header_ka;
    mk_pointer *cache_header_ka_max = NULL;

    struct tm *cache_utils_gmtime;
    struct mk_iov *cache_iov_header;
    
    /* Cache header request -> last modified */
    cache_header_lm = mk_mem_malloc_z(sizeof(mk_pointer));
    cache_header_lm->data = mk_mem_malloc_z(32);
    cache_header_lm->len = -1;
    pthread_setspecific(mk_cache_header_lm, (void *) cache_header_lm);

    /* Cache header request -> content length */
    cache_header_cl = mk_mem_malloc_z(sizeof(mk_pointer));
    cache_header_cl->data = mk_mem_malloc_z(MK_UTILS_INT2MKP_BUFFER_LEN);
    cache_header_cl->len = -1;
    pthread_setspecific(mk_cache_header_cl, (void *) cache_header_cl);

    /* Cache header response -> keep-alive */
    cache_header_ka = mk_mem_malloc_z(sizeof(mk_pointer));
    mk_string_build(&cache_header_ka->data, &cache_header_ka->len,
                    "Keep-Alive: timeout=%i, max=%i%s",
                    config->keep_alive_timeout,
                    config->max_keep_alive_request,
                    MK_CRLF);
    pthread_setspecific(mk_cache_header_ka, (void *) cache_header_ka);

    /* Cache header response -> keep-alive -> 'max' field */
    cache_header_ka_max = mk_mem_malloc_z(sizeof(mk_pointer));
    mk_string_build(&cache_header_ka_max->data, &cache_header_ka_max->len,
                    "%i", config->max_keep_alive_request);
    pthread_setspecific(mk_cache_header_ka_max, (void *) cache_header_ka_max);

    /* 
     * This is a position indicator defined in src/include/header.h, which points
     * to the 'max=' field
     */
    mk_header_ka_max = mk_string_search(cache_header_ka->data,
                                        ", max=", MK_STR_INSENSITIVE);
    mk_bug(mk_header_ka_max <= 0);
    mk_header_ka_max += 6; /* length of ', max=' */

    /* Cache iov header struct */
    cache_iov_header = mk_iov_create(32, 0);
    pthread_setspecific(mk_cache_iov_header, (void *) cache_iov_header);

    /* Cache gmtime buffer */
    cache_utils_gmtime = mk_mem_malloc(sizeof(struct tm));
    pthread_setspecific(mk_cache_utils_gmtime, (void *) cache_utils_gmtime);
}

void *mk_cache_get(pthread_key_t key)
{
    return ( void *) pthread_getspecific(key);
}
