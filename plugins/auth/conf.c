/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2011, Eduardo Silva P. <edsiper@gmail.com>
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
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include <string.h>
#include "MKPlugin.h"

/*
 * Read all vhost configuration nodes and looks for users files under an [AUTH]
 * section, if present, it add that file to the unique list. It parse all user's 
 * files mentioned to avoid duplicated lists in memory.
 */
int mk_auth_conf_init_users_list()
{
    /* Section data */
    char *location;
    char *title;
    char *users_path;

    /* vhost configuration */
    struct host *vhost = mk_api->config->hosts;
    struct mk_config_section *section;

    PLUGIN_TRACE("Loading user's files");
    while (vhost) {
        /* 
         * check 'config' and look for [AUTH] sections, we don't use 
         * mk_config_section_get() because we can have multiple [AUTH]
         * sections.
         */
        section = vhost->config->section;
        while (section) {
            if (strcasecmp(section->name, "[AUTH]") == 0) {
                location = NULL;
                title = NULL;
                users_path = NULL;

                /* Get section keys */
                location = mk_config_section_getval(section, 
                                                    "Location",
                                                    MK_CONFIG_VAL_STR);
                title = mk_config_section_getval(section,
                                                 "Title",
                                                 MK_CONFIG_VAL_STR);

                users_path = mk_config_section_getval(section,
                                                      "Users",
                                                      MK_CONFIG_VAL_STR);
                mk_info("****");
                mk_info("Location: '%s'", location);
                mk_info("Title   : '%s'", title);
                mk_info("Users   : '%s'", users_path);
            }
            section = section->next;
        }
        vhost = vhost->next;
    }

    return 0;
}
