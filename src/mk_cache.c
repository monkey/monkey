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
#include <pthread.h>

#include "mk_iov.h"
#include "mk_cache.h"
#include "mk_request.h"
#include "mk_string.h"
#include "mk_config.h"
#include "mk_macros.h"
#include "mk_utils.h"
#include "mk_vhost.h"

pthread_key_t mk_cache_iov_header;
pthread_key_t mk_cache_header_lm;
pthread_key_t mk_cache_header_cl;
pthread_key_t mk_cache_header_ka;
pthread_key_t mk_cache_header_ka_max;
pthread_key_t mk_cache_utils_gmtime;
pthread_key_t mk_cache_utils_gmt_text;
pthread_key_t mk_utils_error_key;

/* This function is called when a thread is created */
void mk_cache_thread_init()
{
    char *cache_error;
    mk_ptr_t *cache_header_lm;
    mk_ptr_t *cache_header_cl;
    mk_ptr_t *cache_header_ka;
    mk_ptr_t *cache_header_ka_max;

    struct tm *cache_utils_gmtime;
    struct mk_iov *cache_iov_header;
    struct mk_gmt_cache *cache_utils_gmt_text;

    /* Cache header request -> last modified */
    cache_header_lm = mk_mem_malloc_z(sizeof(mk_ptr_t));
    cache_header_lm->data = mk_mem_malloc_z(32);
    cache_header_lm->len = -1;
    pthread_setspecific(mk_cache_header_lm, (void *) cache_header_lm);

    /* Cache header request -> content length */
    cache_header_cl = mk_mem_malloc_z(sizeof(mk_ptr_t));
    cache_header_cl->data = mk_mem_malloc_z(MK_UTILS_INT2MKP_BUFFER_LEN);
    cache_header_cl->len = -1;
    pthread_setspecific(mk_cache_header_cl, (void *) cache_header_cl);

    /* Cache header response -> keep-alive */
    cache_header_ka = mk_mem_malloc_z(sizeof(mk_ptr_t));
    mk_string_build(&cache_header_ka->data, &cache_header_ka->len,
                    "Keep-Alive: timeout=%i, max=",
                    config->keep_alive_timeout);
    pthread_setspecific(mk_cache_header_ka, (void *) cache_header_ka);

    /* Cache header response -> max=%i */
    cache_header_ka_max = mk_mem_malloc_z(sizeof(mk_ptr_t));
    cache_header_ka_max->data = mk_mem_malloc_z(64);
    cache_header_ka_max->len  = 0;
    pthread_setspecific(mk_cache_header_ka_max, (void *) cache_header_ka_max);

    /* Cache iov header struct */
    cache_iov_header = mk_iov_create(32, 0);
    pthread_setspecific(mk_cache_iov_header, (void *) cache_iov_header);

    /* Cache gmtime buffer */
    cache_utils_gmtime = mk_mem_malloc(sizeof(struct tm));
    pthread_setspecific(mk_cache_utils_gmtime, (void *) cache_utils_gmtime);

    /* Cache the most used text representations of utime2gmt */
    cache_utils_gmt_text = mk_mem_malloc_z(sizeof(struct mk_gmt_cache) * MK_GMT_CACHES);
    pthread_setspecific(mk_cache_utils_gmt_text, (void *) cache_utils_gmt_text);

    /* Cache buffer for strerror_r(2) */
    cache_error = mk_mem_malloc(MK_UTILS_ERROR_SIZE);
    pthread_setspecific(mk_utils_error_key, (void *) cache_error);

    /* Virtual hosts: initialize per thread-vhost data */
    mk_vhost_fdt_worker_init();
}
