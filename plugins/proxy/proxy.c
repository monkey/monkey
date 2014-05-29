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

MONKEY_PLUGIN("proxy",             /* shortname */
              "HTTP Proxy",        /* name */
              VERSION,             /* version */
              MK_PLUGIN_STAGE_30); /* hooks */

int _mkp_init(struct plugin_api **api, char *confdir)
{
    int ret;
    (void) confdir;
    mk_api = *api;

    PLUGIN_TRACE("Initializing");

    /* Start the plugin configuration */
    ret = proxy_conf_init(confdir);
    if (ret != 0) {
        mk_err("Proxy configuration failed. Aborting.");
        exit(EXIT_FAILURE);
    }

    return 0;
}

void _mkp_exit()
{
    PLUGIN_TRACE("Exiting");
}

int _mkp_stage_30(struct plugin *plugin, struct client_session *cs,
                  struct session_request *sr)
{
    (void) plugin;
    (void) cs;
    struct proxy_backend *backend;

    backend = proxy_conf_vhost_match(sr);
    if (!backend) {
        return MK_PLUGIN_RET_CLOSE_CONX;
    }


    return MK_PLUGIN_RET_NOT_ME;
}
