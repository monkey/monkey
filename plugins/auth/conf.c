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

#include "auth.h"

/*
 * Register a users file into the main list, if the users
 * file already exists it just return the node in question,
 * otherwise add the node to the list and return the node
 * created.
 */
struct users_file *mk_auth_conf_add_users(char *users_path)
{
    struct file_info finfo;
    struct mk_list *head;
    struct users_file *entry;

    mk_list_foreach(head, &users_file_list) {
        entry = mk_list_entry(head, struct users_file, _head);
        if (strcmp(entry->path, users_path) == 0) {
            return entry;
        }
    }

    if (mk_api->file_get_info(users_path, &finfo) != 0) {
        mk_warn("Auth: Invalid users file '%s'", users_path);
        return NULL;
    }

    if (finfo.read_access == MK_FILE_FALSE) {
        mk_warn("Auth: Could not read file '%s'", users_path);
        return NULL;
    }

    /* We did not find the path in our list, let's create a new node */
    entry  = mk_api->mem_alloc(sizeof(struct users_file));
    entry->last_updated = finfo.last_modification;
    entry->path = users_path;
    mk_list_init(&entry->_users);

    /* Link node to global list */
    mk_list_add(&entry->_head, &users_file_list);

    return entry;
}

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

    /* auth vhost list */
    struct vhost *auth_vhost;

    /* vhost configuration */
    struct host *vhost = mk_api->config->hosts;
    struct mk_config_section *section;
    
    /* vhost [AUTH] locations */
    struct location *loc;

    /* User files list */
    struct users_file *uf;

    PLUGIN_TRACE("Loading user's files");
    while (vhost) {
        auth_vhost = mk_api->mem_alloc(sizeof(struct vhost));
        auth_vhost->host = vhost;             /* link virtual host entry */
        mk_list_init(&auth_vhost->locations); /* init locations list */

        /* 
         * check vhost 'config' and look for [AUTH] sections, we don't use 
         * mk_config_section_get() because we can have multiple [AUTH]
         * sections.
         */
        section = vhost->config->section;
        while (section) {
            if (strcasecmp(section->name, "AUTH") == 0) {
                location = NULL;
                title = NULL;
                users_path = NULL;
                
                /* Get section keys */
                location = mk_api->config_section_getval(section, 
                                                         "Location",
                                                         MK_CONFIG_VAL_STR);
                title = mk_api->config_section_getval(section,
                                                      "Title",
                                                      MK_CONFIG_VAL_STR);
                
                users_path = mk_api->config_section_getval(section,
                                                           "Users",
                                                           MK_CONFIG_VAL_STR);

                /* get or create users file entry */
                uf = mk_auth_conf_add_users(users_path);
                if (!uf) {
                    continue;
                }

                /* Location node */
                loc = mk_api->mem_alloc(sizeof(struct location));
                loc->path  = location;
                loc->title = title;
                loc->users = uf;

                /* Add new location to auth_vhost node */
                mk_list_add(&loc->_head, &auth_vhost->locations);
            }
            section = section->next;
        }

        /* Link auth_vhost node to global list vhosts_list */
        mk_list_add(&auth_vhost->_head, &vhosts_list);

        /* next global virtual host */
        vhost = vhost->next;
    }

#ifdef TRACE
    struct mk_list *vh_head, *loc_head;
    struct vhost *vh_entry;
    struct location *loc_entry;

    mk_list_foreach(vh_head, &vhosts_list) {
        vh_entry = mk_list_entry(vh_head, struct vhost, _head);
        PLUGIN_TRACE("Auth VHost: %p", vh_entry->host);

        mk_list_foreach(loc_head, &vh_entry->locations) {
            loc_entry = mk_list_entry(loc_head, struct location, _head);
            PLUGIN_TRACE("---");
            PLUGIN_TRACE(" location: %s", loc_entry->path);
            PLUGIN_TRACE(" title   : %s", loc_entry->title);
            PLUGIN_TRACE(" users   : %s", loc_entry->users->path);
        }
    }

#endif

    return 0;
}
