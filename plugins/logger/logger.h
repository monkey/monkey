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
#define S_LOG_ON 0
#define S_LOG_OFF 1


#define MK_LOGGER_PIPE_LIMIT 0.75
#define MK_LOGGER_TIMEOUT_DEFAULT 3

#define MK_LOGGER_IOV_DASH " - "

mk_pointer mk_logger_iov_dash;
mk_pointer mk_logger_iov_space;
mk_pointer mk_logger_iov_crlf;

int mk_logger_timeout;

pthread_key_t timer;

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
