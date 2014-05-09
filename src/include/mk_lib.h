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

#ifndef MK_LIB_H
#define MK_LIB_H

#include "mk_macros.h"
#include "public/libmonkey.h"

/* Data */

struct mklib_ctx_t {
    pthread_t tid;
    pthread_t clock;
    pthread_t *workers;

    cb_ipcheck ipf;
    cb_urlcheck urlf;
    cb_data dataf;
    cb_close closef;

    struct mklib_worker_info **worker_info;

    const char *plugdir;

    int lib_running;
};

#endif
