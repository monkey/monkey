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
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* network */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Monkey API */
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
    int n;
    int ret = 0;
    unsigned long len;
    char *conf_path = NULL;
    char *_net, *_mask;

    struct mk_secure_ip_t *new_ip;
    struct mk_secure_url_t *new_url;

    struct mk_config_section *section;
    struct mk_config_entry *entry;
    struct mk_list *head;

    /* Read configuration */
    mk_api->str_build(&conf_path, &len, "%s/mandril.conf", confdir);
    conf = mk_api->config_create(conf_path);
    section = mk_api->config_section_get(conf, "RULES");


    mk_list_foreach(head, &section->entries) {
        entry = mk_list_entry(head, struct mk_config_entry, _head);

        /* Passing to internal struct */
        if (strcasecmp(entry->key, "Deny_IP") == 0) {
            new_ip = mk_api->mem_alloc(sizeof(struct mk_secure_ip_t));
            n = mk_api->str_search(entry->val, "/", 1);

            /* subnet */
            if (n > 0) {
                /* split network addr and netmask */
                _net  = mk_api->str_copy_substr(entry->val, 0, n);
                _mask = mk_api->str_copy_substr(entry->val,
                                                n + 1,
                                                strlen(entry->val));

                /* validations... */
                if (!_net ||  !_mask) {
                    mk_warn("Mandril: cannot parse entry '%s' in RULES section",
                            entry->val);
                    goto ip_next;
                }

                mk_info("network: '%s' mask: '%s'", _net, _mask);

                /* convert ip string to network address */
                if (inet_aton(_net, &new_ip->ip) == 0) {
                    mk_warn("Mandril: invalid ip address '%s' in RULES section",
                            entry->val);
                    goto ip_next;
                }

                /* parse mask */
                new_ip->netmask = strtol(_mask, (char **) NULL, 10);
                if (new_ip->netmask <= 0 || new_ip->netmask >= 32) {
                    mk_warn("Mandril: invalid mask value '%s' in RULES section",
                            entry->val);
                    goto ip_next;
                }

                /* complete struct data */
                new_ip->is_subnet = MK_TRUE;
                new_ip->network = MK_NET_NETWORK(new_ip->ip.s_addr, new_ip->netmask);
                new_ip->hostmin = MK_NET_HOSTMIN(new_ip->ip.s_addr, new_ip->netmask);
                new_ip->hostmax = MK_NET_HOSTMAX(new_ip->ip.s_addr, new_ip->netmask);

                /* link node with main list */
                mk_list_add(&new_ip->_head, &mk_secure_ip);

            /*
             * I know, you were instructed to hate 'goto' statements!, ok, show this
             * code to your teacher and let him blame :P
             */
            ip_next:
                if (_net) {
                    mk_api->mem_free(_net);
                }
                if (_mask) {
                    mk_api->mem_free(_mask);
                }
            }
            else { /* normal IP address */

                /* convert ip string to network address */
                if (inet_aton(entry->val, &new_ip->ip) == 0) {
                    mk_warn("Mandril: invalid ip address '%s' in RULES section",
                            entry->val);
                }
                else {
                    new_ip->is_subnet = MK_FALSE;
                    mk_list_add(&new_ip->_head, &mk_secure_ip);
                }
            }
        }
        else if (strcasecmp(entry->key, "Deny_URL") == 0) {
            /* simple allcotion and data association */
            new_url = mk_api->mem_alloc(sizeof(struct mk_secure_url_t));
            new_url->criteria = entry->val;

            /* link node with main list */
            mk_list_add(&new_url->_head, &mk_secure_url);
        }
    }

    mk_api->mem_free(conf_path);
    return ret;
}

int mk_security_check_ip(int socket)
{
    int network;
    struct mk_secure_ip_t *entry;
    struct mk_list *head;
    struct in_addr addr_t, *addr = &addr_t;
    socklen_t len = sizeof(addr);

    if (getpeername(socket, (struct sockaddr *)&addr_t, &len) < 0)
        return -1;

    PLUGIN_TRACE("[FD %i] Mandril validating IP address", socket);
    mk_list_foreach(head, &mk_secure_ip) {
        entry = mk_list_entry(head, struct mk_secure_ip_t, _head);

        if (entry->is_subnet == MK_TRUE) {
            /* Validate network */
            network = MK_NET_NETWORK(addr->s_addr, entry->netmask);
            if (network != entry->network) {
                continue;
            }

            /* Validate host range */
            if (addr->s_addr <= entry->hostmax && addr->s_addr >= entry->hostmin) {
                PLUGIN_TRACE("[FD %i] Mandril closing by rule in ranges", socket);
                return -1;
            }
        }
        else {
            if (addr->s_addr == entry->ip.s_addr) {
                PLUGIN_TRACE("[FD %i] Mandril closing by rule in IP match", socket);
                return -1;
            }
        }
    }
    return 0;
}

/* Check if the incoming URL is restricted for some rule */
int mk_security_check_url(mk_pointer url)
{
    int n;
    struct mk_list *head;
    struct mk_secure_url_t *entry;

    PLUGIN_TRACE("[FD %i] Mandril validating URL", socket);
    mk_list_foreach(head, &mk_secure_url) {
        entry = mk_list_entry(head, struct mk_secure_url_t, _head);
        n = mk_api->str_search_n(url.data, entry->criteria, MK_STR_INSENSITIVE, url.len);
        if (n >= 0) {
            PLUGIN_TRACE("[FD %i] Mandril closing by rule in URL match", socket);
            return -1;
        }
    }

    return 0;
}

int _mkp_init(void **api, char *confdir)
{
    mk_api = *api;

    /* Init security lists */
    mk_list_init(&mk_secure_ip);
    mk_list_init(&mk_secure_url);

    /* Read configuration */
    mk_security_conf(confdir);
    return 0;
}

void _mkp_exit()
{
}

int _mkp_stage_10(unsigned int socket, struct sched_connection *conx)
{
    /* Validate ip address with Mandril rules */
    if (mk_security_check_ip(socket) != 0) {
        PLUGIN_TRACE("[FD %i] Mandril close connection", socket);
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
