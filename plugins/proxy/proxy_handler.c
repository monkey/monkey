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

#include "MKPlugin.h"
#include "proxy.h"

int proxy_handler_start(struct client_session *cs,
                        struct session_request *sr,
                        struct proxy_backend *backend)
{
    (void) sr;

    PLUGIN_TRACE("[FD %i] Proxy Handler routed by '%s'",
                 cs->socket, backend->name);

    if (backend->protocol == PROXY_PROTOCOL_HTTP) {
        mk_api->event_socket_change_mode(cs->socket,
                                         MK_EPOLL_SLEEP,
                                         MK_EPOLL_LEVEL_TRIGGERED);
    }

    return 0;
}
