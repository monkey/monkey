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
#include "proxy_conf.h"

/* Initialize connections to each backend defined at a worker level */
int proxy_backend_worker_init()
{
    int min;
    int diff = 0;
    int workers;
    int connections;
    struct mk_list *head;
    struct proxy_backend *backend;

    workers = mk_api->config->workers;
    mk_list_foreach(head, &proxy_config.backends) {
        backend = mk_list_entry(head, struct proxy_backend, _head);


        /*
         * Calculate the number of connections this worker will have
         * for the backend in question
         */
        if (backend->_av_diff > 0) {
            if (backend->_av_diff < workers) {
                diff = 1;
                backend->_av_diff--;
            }
        }
        else {
            diff = 0;
        }

        min = (backend->_total_conx / workers) + diff;

        if (backend->_av_conx < min) {
            connections = backend->_av_conx;
            backend->_av_conx = 0;
        }
        else {
            connections = min;
            backend->_av_conx -= connections;
        }

        printf("'%s' will have %i conx (diff=%i)\n",
               backend->name, connections, diff);


    }

    return 0;
}
