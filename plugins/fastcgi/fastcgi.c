/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2015 Monkey Software LLC <eduardo@monkey.io>
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

#include <monkey/mk_api.h>

static int mk_fastcgi_start_processing(struct mk_http_session *cs,
                                       struct mk_http_request *sr)
{
    struct fcgi_handler *handler;

    handler = fcgi_handler_new(cs, sr);
    if (!handler) {
        return -1;
    }

    return 0;
}


/* Callback handler */
int mk_fastcgi_stage30(struct mk_plugin *plugin,
                       struct mk_http_session *cs,
                       struct mk_http_request *sr)
{
    int ret;
    (void) plugin;

    ret = mk_fastcgi_start_processing(cs, sr);
    if (ret == 0) {
        return MK_PLUGIN_RET_CONTINUE;
    }

    return MK_PLUGIN_RET_NOT_ME;
}

int mk_fastcgi_stage30_hangup(struct mk_plugin *plugin,
                              struct mk_http_session *cs,
                              struct mk_http_request *sr)
{
    (void) plugin;
    (void) cs;
    (void) sr;

    return 0;
}

int mk_fastcgi_plugin_init(struct plugin_api **api, char *confdir)
{
    (void) api;
    (void) confdir;

	return 0;
}

int mk_fastcgi_plugin_exit()
{

    return 0;
}

int mk_fastcgi_master_init(struct mk_server_config *config)
{
    (void) config;

	return 0;
}

void mk_fastcgi_worker_init()
{
}

struct mk_plugin_stage mk_plugin_stage_fastcgi = {
    .stage30        = &mk_fastcgi_stage30,
    .stage30_hangup = &mk_fastcgi_stage30_hangup
};

struct mk_plugin mk_plugin_fastcgi = {
    /* Identification */
    .shortname     = "fastcgi",
    .name          = "FastCGI Client",
    .version       = "1.0",
    .hooks         = MK_PLUGIN_STAGE,

    /* Init / Exit */
    .init_plugin   = mk_fastcgi_plugin_init,
    .exit_plugin   = mk_fastcgi_plugin_exit,

    /* Init Levels */
    .master_init   = mk_fastcgi_master_init,
    .worker_init   = mk_fastcgi_worker_init,

    /* Type */
    .stage         = &mk_plugin_stage_fastcgi
};
