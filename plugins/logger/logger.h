/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2010, Eduardo Silva P. <edsiper@gmail.com>
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

/* s_log status */
#ifndef MK_LOGGER_H
#define MK_LOGGER_H

#define MK_LOGGER_PIPE_LIMIT 0.75
#define MK_LOGGER_TIMEOUT_DEFAULT 3

int mk_logger_timeout;

#include "pthread.h"
pthread_key_t timer;
pthread_key_t cache_content_length;

struct log_target
{
    /* Pipes */
    int fd_access[2];
    int fd_error[2];

    /* File paths */
    char *file_access;
    char *file_error;

    struct host *host;
    struct log_target *next;
};

struct log_target *lt;

/* Global Monkey core API */
struct plugin_api *mk_api;

void *mk_logger_worker_init(void *args);
void mk_logger_target_add(int fd, char *target);

#endif
