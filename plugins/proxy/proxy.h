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

/* Default number of backend connections */
#define PROXY_BACKEND_CONNECTIONS    16

/* A backend server */
struct proxy_backend {
    char    *name;        /* descriptive name */
    char    *route;       /* original route */
    char    *host;        /* target host IP */
    char     cport[16];   /* TCP port in char */
    int      port;        /* TCP port */
    long     keepalive;   /* should we use KeepAlive connection ? */
    int      protocol;    /* protocol, e.g: PROXY_PROTOCOL_XYZ */
    int      connections; /* number of persistent connections */

    /*
     * Total number of slots still available to let workers initialize
     * the connections to the backend.
     */
    int      _total_conx;

    /* Available slots while initializing across workers */
    int      _av_conx;

    /* Balance difference */
    int      _av_diff;

    struct mk_list _head; /* proxy_config link */
};

/* A rule that exists under a Virtual Host [PROXY] */
struct proxy_match {
    struct proxy_backend *router;
    regex_t regex;
    struct mk_list _head;
};

/* Group a set of rules for a Virtual Host */
struct proxy_vhost {
    struct host *vhost;       /* Virtual host reference */
    struct mk_list matches;   /* List of [PROXY] associated to this VHost */
    struct mk_list _head;     /* Head to linked list */
};

/* A global channel to receive signals, mostly to restore suspended backends */
struct proxy_worker_channel {
    int channel[2];
    struct mk_list _head;
};

/* A mutex to initialize backends on workers, just used on startup */
pthread_mutex_t mutex_proxy_backend;

/* Reference to th2e plugin with Monkey internals */
struct plugin *proxy_plugin;

/* Global channels for workers */
struct mk_list proxy_channels;

extern __thread int channel_read;
extern __thread int channel_write;

#endif
