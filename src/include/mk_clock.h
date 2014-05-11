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

/* clock.h */

#ifndef MK_CLOCK_H
#define MK_CLOCK_H

#include <time.h>
#include "memory.h"

extern time_t log_current_utime;
extern time_t monkey_init_time;

extern mk_ptr_t log_current_time;
extern mk_ptr_t header_current_time;

#define GMT_DATEFORMAT "%a, %d %b %Y %H:%M:%S GMT\r\n"
#define HEADER_TIME_BUFFER_SIZE 32
#define LOG_TIME_BUFFER_SIZE 30

void *mk_clock_worker_init(void *args);
void mk_clock_set_time(void);
void mk_clock_sequential_init();

#endif
