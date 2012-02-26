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

#ifndef DUDA_MAIN_H
#define DUDA_MAIN_H

#include "MKPlugin.h"

#define MAP_WS_APP_NAME   0X00
#define MAP_WS_INTERFACE  0X10
#define MAP_WS_METHOD     0X20
#define MAP_WS_PARAM      0X30
#define MAP_WS_END        0X40

/* Max number of parameters allowed in Duda URI */
#define MAP_WS_MAX_PARAMS 8

/*
 * The response body holds an IOV array struct of BODY_BUFFER_SIZE,
 * when the limit is reached, the pointer is reallocated adding a new chunk
 */
#define BODY_BUFFER_SIZE  8

/*
 * This struct represent the web service request, as well it contains detailed
 * information about the response type and buffers associated
 */
struct duda_request {

    /* web service details */
    struct web_service *web_service;
    mk_pointer appname;
    mk_pointer interface;
    mk_pointer method;
    mk_pointer params[MAP_WS_MAX_PARAMS];
    short int n_params;

    /* Monkey request: client_session & session_request */
    struct client_session *cs;
    struct session_request *sr;

    /* Body buffer stuff */
    struct mk_iov *body_buffer;
    unsigned short int body_buffer_size;
    unsigned int body_buffer_sent;

    /* Internal statuses */
    unsigned int _st_http_headers_sent;  /* HTTP headers sent? */
    unsigned int _st_body_writes;        /* Number of body_writes invoked */

    /* Lists linked to (events)*/
    struct mk_list _head_events_write;

    /* Events mask */
    short int events_mask;
};

pthread_key_t duda_global_events_write;

#endif
