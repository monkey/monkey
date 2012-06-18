/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2012, Eduardo Silva P. <edsiper@gmail.com>
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

#ifndef MK_CACHE_H
#define MK_CACHE_H

pthread_key_t mk_cache_iov_header;
pthread_key_t mk_cache_header_lm;
pthread_key_t mk_cache_header_cl;
pthread_key_t mk_cache_header_ka;
pthread_key_t mk_cache_header_ka_max;
pthread_key_t mk_cache_utils_gmtime;
pthread_key_t mk_cache_utils_gmt_text;

struct mk_cache_date_t
{
    time_t unix_time;
    time_t expire;
    time_t last_access;
    mk_pointer date;
};

struct mk_cache_date_t *mk_cache_file_date;

void mk_cache_thread_init(void);
void *mk_cache_get(pthread_key_t key);
char *mk_cache_file_date_get(time_t time);

#endif
