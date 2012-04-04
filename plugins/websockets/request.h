/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2012, Eduardo Silva P.
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

#ifndef MK_WEBSOCKETS_REQUEST_H
#define MK_WEBSOCKETS_REQUEST_H

#include "ws.h"
#include "mk_list.h"

struct mk_ws_request
{
    int socket_fd;

    /* Websocket subprotocol */
    unsigned int subprotocol_id;

    /* Payload data */
    unsigned char *payload;
    uint64_t payload_len;

    /* Client request data */
    struct client_session *cs;
    struct session_request *sr;

    struct mk_list _head;
};

void mk_ws_request_init();
struct mk_ws_request *mk_ws_request_create(int socket_fd,
                                           struct client_session *cs,
                                           struct session_request *sr,
                                           unsigned int subprotocol_id);

void mk_ws_request_add(struct mk_ws_request *pr);
struct mk_ws_request *mk_ws_request_get(int socket);
void mk_ws_request_update(int socket, struct mk_ws_request *wr);
int mk_ws_request_delete(int socket);
void mk_ws_free_request(int sockfd);

#endif
