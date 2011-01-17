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

/* clock.c */

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>

#include "memory.h"
#include "clock.h"
#include "utils.h"

static void mk_clock_log_set_time()
{
    time_t utime;

    if (!log_current_time.data) {
        log_current_time.data = mk_mem_malloc_z(30);
        log_current_time.len = 28;
    }

    if ((utime = time(NULL)) == -1) {
        return;
    }

    log_current_utime = utime;
    strftime(log_current_time.data, 30, "[%d/%b/%G %T %z]",
             (struct tm *) localtime((time_t *) & utime));
}

void mk_clock_header_set_time()
{
    int n, len = 32;
    time_t date;
    struct tm *gmt_tm;

    if (!header_current_time.data) {
        header_current_time.data = mk_mem_malloc_z(len);
        header_current_time.len = len - 1;
    }

    date = time(NULL);
    gmt_tm = (struct tm *) gmtime(&date);
    n = strftime(header_current_time.data, len, GMT_DATEFORMAT, gmt_tm);
}

void *mk_clock_worker_init(void *args)
{
    /* Time when monkey was started */
    monkey_init_time = time(NULL);

    while (1) {
        mk_clock_log_set_time();
        mk_clock_header_set_time();
        sleep(1);
    }
}
