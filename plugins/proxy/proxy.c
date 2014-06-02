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
#include "proxy_handler.h"

MONKEY_PLUGIN("proxy",             /* shortname */
              "Proxy",             /* name */
              VERSION,             /* version */
              MK_PLUGIN_STAGE_30 | MK_PLUGIN_CORE_THCTX); /* hooks */

/* Init plugin */
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
    pthread_mutex_init(&mutex_proxy_backend, (pthread_mutexattr_t *) NULL);

    return 0;
}

/* Exit plugin */
void _mkp_exit()
{
    PLUGIN_TRACE("Exiting");
}

/* Initialize thread contexts */
void _mkp_core_thctx(void)
{
    /* Initialize each backend connections pool */
    pthread_mutex_lock(&mutex_proxy_backend);
    proxy_backend_worker_init();
    pthread_mutex_unlock(&mutex_proxy_backend);
}

/* Content handler: the real proxy stuff happens here */
int _mkp_stage_30(struct plugin *plugin, struct client_session *cs,
                  struct session_request *sr)
{
    (void) plugin;
    (void) cs;
    int ret;
    struct proxy_backend *backend;

    backend = proxy_conf_vhost_match(sr);
    if (!backend) {
        return MK_PLUGIN_RET_NOT_ME;
    }

    ret = proxy_handler_start(cs, sr, backend);
    if (ret == 0) {
        return MK_PLUGIN_RET_CONTINUE;
    }

    return MK_PLUGIN_RET_NOT_ME;
}
