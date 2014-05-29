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

#ifndef MK_PROXY_H
#define MK_PROXY_H

#include "MKPlugin.h"
#include "regex.h"

/* Protocols supported by the Proxy */
#define PROXY_PROTOCOL_HTTP           1
#define PROXY_PROTOCOL_HTTPS          2  /* not yet supported */
#define PROXY_PROTOCOL_FASTCGI        4  /* not yet supported */
#define PROXY_PROTOCOL_FASTCGI_UNIX   8  /* not yet supported */
#define PROXY_PROTOCOL_SPDY          16  /* not yet supported */

/* A backend server */
struct proxy_backend {
    char    *name;        /* descriptive name */
    char    *route;       /* original route */
    char    *host;        /* target host IP */
    int      port;        /* TCP port */
    long     keepalive;   /* should use KeepAlive connection ? */
    int      protocol;    /* protocol, e.g: PROXY_PROTOCOL_XYZ */

    struct mk_list _head; /* proxy_config link */
};

/* A rule that exists under a Virtual Host */
struct proxy_match {
    regex_t regex;
};

/* Group a set of rules for a Virtual Host */
struct proxy_vhost {
    struct host vhost;

    struct mk_list _head;
};

#endif
