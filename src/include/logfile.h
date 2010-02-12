/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2008, Eduardo Silva P.
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

#ifndef MK_LOGFILE_H
#define MK_LOGFILE_H

/* s_log status */
#define S_LOG_ON 0
#define S_LOG_OFF 1

#define MK_LOGFILE_IOV_DASH " - "

mk_pointer mk_logfile_iov_dash;

/* logfile.c */
pthread_key_t timer;

struct log_target
{
    int fd;
    char *target;
    struct log_target *next;
};
struct log_target *lt;

struct log_info
{
    int method;
    int protocol;

    mk_pointer uri;
    mk_pointer ip;

    int final_response;         /* Ok: 200, Not Found 400, etc... */
    int size;
    mk_pointer size_p;
    int status;                 /* on/off : 301. */
    mk_pointer error_msg;
    mk_pointer error_details;

    struct host *host_conf;
};

int mk_logger_write_log(struct client_request *cr, struct log_info *log,
                        struct host *h);
int mk_logger_register_pid();
int mk_logger_remove_pid();

void *mk_logger_worker_init(void *args);

int logger_add_request(struct log_info *log);

void mk_logger_target_add(int fd, char *target);
struct log_target *mk_logger_match(int fd);

#endif
