/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2009, Eduardo Silva P.
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
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

/* palm.c */
#ifndef MK_PALM_H
#define MK_PALM_H

#define MK_PALM_BUFFER_SIZE 32768 /* 32KB */

#include "request.h"

#define MK_PALM_ERROR_LINE "\nPalm Error: invalid configuration on palm.conf\n %s\n\n"

struct mk_palm
{
    char *extension;
    char *mimetype;
    char *server_addr;
    int server_port;
    struct mk_palm *next;
};

pthread_key_t cache_ip_str;

struct plugin_api *mk_api;
struct mk_config *conf;

#include "mk_iov.h"

mk_pointer mk_server_protocol;
mk_pointer mk_server_port;
mk_pointer mk_server_address;

mk_pointer mk_iov_empty;
mk_pointer mk_iov_crlf;
mk_pointer mk_iov_crlfcrlf;
mk_pointer mk_iov_equal;

struct mk_palm *palms;

struct mk_palm_request *mk_palm_connect(struct mk_palm *palm,
                                        struct client_session *cs, 
                                        struct session_request *sr);
int mk_palm_send_request(struct client_session *cs, struct session_request *sr);
int hangup(int sockfd);

#endif
