/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2011, Eduardo Silva P.
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

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "MKPlugin.h"

#include "mandril.h"

MONKEY_PLUGIN("mandril",  /* shortname */
              "Mandril",  /* name */ 
              VERSION,    /* version */
              MK_PLUGIN_STAGE_10 | MK_PLUGIN_STAGE_20); /* hooks */

struct mk_config *conf;

/* Read database configuration parameters */
int mk_security_conf(char *confdir)
{
    int ret = 0;
    unsigned long len;
    char *conf_path = NULL;
    struct mk_security *new, *r;
    struct mk_config_section *section;
    struct mk_config_entry *entry;

    /* Read configuration */
    mk_api->str_build(&conf_path, &len, "%s/mandril.conf", confdir);
    conf = mk_api->config_create(conf_path);
    section = mk_api->config_section_get(conf, "RULES");
    entry = section->entry;

    r = rules;
    while (entry) {
        /* Passing to internal struct */
        new = mk_api->mem_alloc(sizeof(struct mk_security));
        if (strcasecmp(entry->key, "IP") == 0) {
            new->type = MK_SECURITY_TYPE_IP;
        }
        else if (strcasecmp(entry->key, "URL") == 0) {
            new->type = MK_SECURITY_TYPE_URL;
        }

        new->value = entry->val;
        new->next = NULL;

        /* Linking node */
        if (!rules) {
            rules = new;
        }
        else {
            r = rules;
            while (r->next) {
                r = r->next;
            }
            r->next = new;
        }
        entry = entry->next;
    }

#ifdef TRACE
    PLUGIN_TRACE("Security rules");
    r = rules;
    printf("%s", ANSI_YELLOW);
    while (r) {
        if (r->type == MK_SECURITY_TYPE_IP) {
            printf("IP  :'");
        }
        else if (r->type == MK_SECURITY_TYPE_URL) {
            printf("URL :'");
        }
        printf("%s'\n", r->value);
        fflush(stdout);
        r = r->next;
    }
    printf("%s", ANSI_RESET);
    fflush(stdout);
#endif

    mk_api->mem_free(conf_path);
    return ret;
}

int mk_security_check_ip(char *ipv4)
{
    unsigned int i = 0;
    struct mk_security *p;

    p = rules;
    while (p) {
        if (p->type == MK_SECURITY_TYPE_IP) {
            for (i = 0; p->value[i]; i++) {
                if (p->value[i] == '?') {
                    if (ipv4[i] == '.' || ipv4[i] == '\0')
                        return -1;
                    else
                        continue;
                }

                if (p->value[i] == '*') {
                    return -1;
                }

                if (p->value[i] != ipv4[i]) {
                    return 0;
                }
            }
        }
        p = p->next;
    }

    if (ipv4[i] == '\0') {
        return -1;
    }

    return 0;
}

int mk_security_check_url(mk_pointer url)
{
    int n;
    struct mk_security *p;

    p = rules;
    while (p) {
        if (p->type == MK_SECURITY_TYPE_URL) {
            n = mk_api->str_search_n(url.data, p->value, MK_STR_INSENSITIVE, url.len);
            if (n >= 0) {
                return -1;
            }
        }
        p = p->next;
    }

    return 0;
}

int _mkp_init(void **api, char *confdir)
{
    mk_api = *api;
    rules = 0;

    /* Read configuration */
    mk_security_conf(confdir);
    return 0;
}

void _mkp_exit()
{
}

int _mkp_stage_10(unsigned int socket, struct sched_connection *conx)
{
    if (mk_security_check_ip(conx->ipv4.data) != 0) {
        PLUGIN_TRACE("Close connection FD %i", socket);
        return MK_PLUGIN_RET_CLOSE_CONX;
    }

    return MK_PLUGIN_RET_CONTINUE;
}

int _mkp_stage_20(struct client_session *cs, struct session_request *sr)
{
    if (mk_security_check_url(sr->uri) < 0) {
        PLUGIN_TRACE("Close connection FD %i", cs->socket);
        mk_api->header_set_http_status(sr, MK_CLIENT_FORBIDDEN);
        return MK_PLUGIN_RET_CLOSE_CONX;
    }

    return MK_PLUGIN_RET_CONTINUE;
}
