 /* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2012, Eduardo Silva P. <edsiper@gmail.com>
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

#include "duda_conf.h"

int duda_conf_main_init(const char *confdir)
{
    int ret = 0;
    unsigned long len;
    char *conf_path = NULL;
    struct mk_config_section *section;
    struct mk_config *conf;
    struct file_info finfo;
    struct mk_list *head;

    /* Read palm configuration file */
    mk_api->str_build(&conf_path, &len, "%s/duda.conf", confdir);
    conf = mk_api->config_create(conf_path);

    mk_list_foreach(head, &conf->sections) {
        section = mk_list_entry(head, struct mk_config_section, _head);
        if (strcasecmp(section->name, "DUDA") != 0) {
            continue;
        }

        /* ServicesRoot */
        services_root = mk_api->config_section_getval(section, "ServicesRoot",
                                                      MK_CONFIG_VAL_STR);

        if (mk_api->file_get_info(services_root, &finfo) != 0) {
            mk_err("Duda: Invalid services root path");
            exit(EXIT_FAILURE);
        }

        if (finfo.is_directory == MK_FALSE) {
            mk_err("Duda: ServicesRoot must be a valid directory");
            exit(EXIT_FAILURE);
        }

        /* Packages */
        packages_root = mk_api->config_section_getval(section, "PackagesRoot",
                                                      MK_CONFIG_VAL_STR);
        if (mk_api->file_get_info(packages_root, &finfo) != 0) {
            mk_err("Duda: Invalid packages root path");
            exit(EXIT_FAILURE);
        }

        if (finfo.is_directory == MK_FALSE) {
            mk_err("Duda: PackagesRoot must be a valid directory");
            exit(EXIT_FAILURE);
        }

        PLUGIN_TRACE("Services Root '%s'", services_root);
        PLUGIN_TRACE("Packages Root '%s'", packages_root);
    }

    mk_api->mem_free(conf_path);

    return ret;
}

int duda_conf_vhost_init()
{
    /* Section data */
    char *app_name;
    int   app_enabled;

    /* vhost services list */
    struct vhost_services *vs;

    /* web service details */
    struct web_service *ws;

    /* monkey vhost configuration */
    struct mk_list *head_host;
    struct mk_list *hosts = &mk_api->config->hosts;
    struct mk_list *head_section;
    struct host *entry_host;
    struct mk_config_section *section;

    mk_list_init(&services_list);

    PLUGIN_TRACE("Loading applications");
    mk_list_foreach(head_host, hosts) {
        entry_host = mk_list_entry(head_host, struct host, _head);

        vs = mk_api->mem_alloc(sizeof(struct vhost_services));
        vs->host = entry_host;              /* link virtual host entry */
        mk_list_init(&vs->services);        /* init services list */

        /*
         * check vhost 'config' and look for [WEB_SERVICE] sections, we don't use
         * mk_config_section_get() because we can have multiple [WEB_SERVICE]
         * sections.
         */
        mk_list_foreach(head_section, &entry_host->config->sections) {
            section = mk_list_entry(head_section, struct mk_config_section, _head);

            if (strcasecmp(section->name, "WEB_SERVICE") == 0) {
                app_name = NULL;
                app_enabled = MK_FALSE;

                /* Get section keys */
                app_name = mk_api->config_section_getval(section,
                                                         "Name",
                                                         MK_CONFIG_VAL_STR);
                app_enabled = (size_t) mk_api->config_section_getval(section,
                                                                     "Enabled",
                                                                     MK_CONFIG_VAL_BOOL);

                if (app_name && mk_is_bool(app_enabled)) {
                    ws = mk_api->mem_alloc_z(sizeof(struct web_service));
                    ws->app_name = mk_api->str_dup(app_name);
                    ws->app_name_len = strlen(ws->app_name);
                    ws->app_enabled = app_enabled;

                    mk_list_add(&ws->_head, &vs->services);
                }
                else {
                    mk_warn("Invalid web service, skipping");
                }
            }
        }

        /* Link web_service node to global list services_list */
        mk_list_add(&vs->_head, &services_list);
    }

#ifdef TRACE
    struct mk_list *list_head, *service_head;
    struct vhost_services *service_entry;
    struct web_service *ws_entry;

    mk_list_foreach(list_head, &services_list) {
        service_entry = mk_list_entry(list_head, struct vhost_services, _head);
        PLUGIN_TRACE("Duda Web Service VHost: %p", service_entry->host);

        mk_list_foreach(service_head, &service_entry->services) {
            ws_entry = mk_list_entry(service_head, struct web_service, _head);
            PLUGIN_TRACE("---");
            PLUGIN_TRACE(" app_name    : %s", ws_entry->app_name);
            PLUGIN_TRACE(" app_enabled : %i", ws_entry->app_enabled);
        }
    }
#endif

    return 0;
}
