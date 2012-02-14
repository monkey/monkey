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

#include "MKPlugin.h"

#include "conf.h"
#include "request.h"

MONKEY_PLUGIN("duda",                                     /* shortname */
              "Duda Web Services Framework",              /* name */
              VERSION,                                    /* version */
              MK_PLUGIN_CORE_THCTX | MK_PLUGIN_STAGE_30); /* hooks */


void _mkp_core_prctx(struct server_config *config)
{

}

void _mkp_core_thctx()
{
}

int _mkp_init(void **api, char *confdir)
{
    mk_api = *api;

    mk_duda_conf_main_init(confdir);
    mk_duda_conf_vhost_init();

    return 0;
}

void _mkp_exit()
{
}

/* 
 * Request handler: when the request arrives, this callback is invoked.
 */
int _mkp_stage_30(struct plugin *plugin, struct client_session *cs, 
                  struct session_request *sr)
{
    return MK_PLUGIN_RET_CONTINUE;
}


