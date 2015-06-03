/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2015 Monkey Software LLC <eduardo@monkey.io>
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

#ifndef MK_UTILS_H
#define MK_UTILS_H

#include <string.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <monkey/mk_core.h>

#define MK_UTILS_INT2MKP_BUFFER_LEN 16    /* Maximum buffer length when
                                           * converting an int to mk_ptr_t */
/*
 * Max amount of pid digits. Glibc's pid_t is implemented as a signed
 * 32bit integer, for both 32 and 64bit systems - max value: 2147483648.
 */
#define MK_MAX_PID_LEN 10
#define MK_GMT_CACHES 10

struct mk_gmt_cache {
    time_t time;
    char text[32];
    unsigned long long hits;
};


int    mk_utils_utime2gmt(char **data, time_t date);
time_t mk_utils_gmt2utime(char *date);

int mk_buffer_cat(mk_ptr_t * p, char *buf1, int len1, char *buf2, int len2);

int mk_utils_set_daemon(void);
char *mk_utils_url_decode(mk_ptr_t req_uri);

int mk_utils_register_pid(void);
int mk_utils_remove_pid(void);

pthread_t mk_utils_worker_spawn(void (*func) (void *), void *arg);
int mk_utils_worker_rename(const char *title);
void mk_utils_stacktrace(void);

unsigned int mk_utils_gen_hash(const void *key, int len);

#endif
