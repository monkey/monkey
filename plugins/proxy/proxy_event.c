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
#include "proxy_backend.h"

static inline int mkp_event_close(int sock)
{
    (void) sock;
    return MK_PLUGIN_RET_EVENT_OWNED;
}

int _mkp_event_read(int sockfd)
{
    struct proxy_backend_conx *conx;

    conx = proxy_conx_get(sockfd);
    if (conx) {
    }

    return MK_PLUGIN_RET_EVENT_CONTINUE;
}

int _mkp_event_write(int sockfd)
{
    socklen_t len;
    int sock_error;
    struct proxy_backend_conx *conx;

    conx = proxy_conx_get(sockfd);
    if (conx) {
        if (conx->status == PROXY_POOL_CONNECTING) {
            /* Check if we faced some error */
            len = sizeof(sock_error);
            getsockopt(conx->fd, SOL_SOCKET, SO_ERROR, &sock_error, &len);
            if (sock_error != 0) {
                mk_warn("Proxy: error connecting to backend");
                return MK_PLUGIN_RET_EVENT_OWNED;
            }

            /* Mark this connection as available */
            proxy_conx_set_available(conx);
            return MK_PLUGIN_RET_EVENT_OWNED;
        }
    }

    return MK_PLUGIN_RET_EVENT_CONTINUE;
}

int _mkp_event_close(int sockfd)
{
    return mkp_event_close(sockfd);
}

int _mkp_event_error(int sockfd)
{
    return mkp_event_close(sockfd);
}

int _mkp_event_timeout(int sockfd)
{
    return mkp_event_close(sockfd);
}
