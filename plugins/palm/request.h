/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2010, Eduardo Silva P.
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

#ifndef MK_PALM_REQUEST_H
#define MK_PALM_REQUEST_H

#include "palm.h"

struct mk_palm_request
{
    int client_fd;
    int palm_fd;

    char data_pending[MK_PALM_BUFFER_SIZE*2];
    char data_read[MK_PALM_BUFFER_SIZE];

  
    int len_pending;
    int len_read;
    int offset_pending;

    /* Traffic bytes between plugin and Palm server */
    unsigned long bytes_sent;
    unsigned long bytes_read;
    int headers_sent;

    struct mk_palm *palm;

    /* Client request data */
    struct client_request *cr;
    struct request *sr;

    /* Next node */
    struct mk_palm_request *next;
};

struct mk_palm_request *mk_palm_request_create(int client_fd,
                                               int palm_fd,
                                               struct client_request *cr,
                                               struct request *sr,
                                               struct mk_palm *palm);
void mk_palm_request_add(struct mk_palm_request *pr);
struct mk_palm_request *mk_palm_request_get(int socket);
struct mk_palm_request *mk_palm_request_get_by_http(int socket);
void mk_palm_request_update(int socket, struct mk_palm_request  *pr);
void mk_palm_request_delete(int socket);
void mk_palm_free_request(int sockfd);
#endif
