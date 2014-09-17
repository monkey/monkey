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

#ifndef MK_CACHE_H
#define MK_CACHE_H

extern pthread_key_t mk_cache_iov_header;
extern pthread_key_t mk_cache_header_lm;
extern pthread_key_t mk_cache_header_cl;
extern pthread_key_t mk_cache_header_ka;
extern pthread_key_t mk_cache_header_ka_max;

extern __thread struct tm *worker_cache_gmtime;
extern __thread struct mk_gmt_cache *worker_cache_gmtext;

void mk_cache_worker_init();
void mk_cache_worker_exit();

static inline void *mk_cache_get(pthread_key_t key)
{
    return pthread_getspecific(key);
}

static inline struct tm *mk_cache_get_utils_gmtime()
{
    return worker_cache_gmtime;
}

static inline struct mk_gmt_cache *mk_cache_get_utils_gmtext()
{
    return worker_cache_gmtext;
}

#endif
