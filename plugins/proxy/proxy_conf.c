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

#include <regex.h>

#include "MKPlugin.h"
#include "proxy.h"
#include "proxy_conf.h"

/* Lookup a backend (defined in proxy.conf) by it's host pointer ref */
struct proxy_backend *proxy_conf_vhost_match(struct session_request *sr)
{
    int ret;
    struct mk_list *head;
    struct mk_list *m_head;
    struct proxy_vhost *pvh;
    struct proxy_match *match;
    struct proxy_backend *router = NULL;

    /*
     * Regexec do not support string lengths, it just lookup for a NULL
     * byte from the start position. As a workaround we insert the NULL
     * byte in the original buffer and then we remove it.
     */
    sr->uri_processed.data[sr->uri_processed.len] = '\0';

    /* Lookup the virtual host */
    mk_list_foreach(head, &proxy_config.vhosts) {
        pvh = mk_list_entry(head, struct proxy_vhost, _head);
        if (pvh->vhost == sr->host_conf) {
            mk_list_foreach(m_head, &pvh->matches) {
                match = mk_list_entry(m_head, struct proxy_match, _head);
                ret = regexec(&match->regex,
                              sr->uri_processed.data,
                              0, NULL, 0);
                if (ret == 0) {
                    router = match->router;
                    break;
                }
            }
        }
    }
    sr->uri_processed.data[sr->uri_processed.len] = ' ';

    return router;
}

/* Lookup a backend (defined in proxy.conf) by it's name */
static struct proxy_backend *proxy_conf_backend_lookup_by_name(char *name)
{
    struct mk_list *head;
    struct proxy_backend *backend;

    mk_list_foreach(head, &proxy_config.backends) {
        backend = mk_list_entry(head, struct proxy_backend, _head);
        if (strcmp(backend->name, name) == 0) {
            return backend;
        }
    }

    return NULL;
}


/* Read the list of virtual hosts and prepare the proxies */
static int proxy_conf_vhosts()
{
    int ret;
    char *router;
    char *pattern;
    struct host *host;
    struct mk_list *head;
    struct mk_list *vh_section;
    struct mk_config_section *section;
    struct proxy_vhost *pvh;
    struct proxy_match *match;
    struct proxy_backend *backend;

    mk_list_foreach(head, &mk_api->config->hosts) {
        host = mk_list_entry(head, struct host, _head);

        pvh = mk_api->mem_alloc(sizeof(struct proxy_vhost));
        pvh->vhost = host;
        mk_list_init(&pvh->matches);
        mk_list_add(&pvh->_head, &proxy_config.vhosts);

        /* lookup PROXY sections */
        mk_list_foreach(vh_section, &host->config->sections) {
            section = mk_list_entry(vh_section, struct mk_config_section, _head);
            if (strcasecmp(section->name, "PROXY") != 0) {
                continue;
            }

            router = mk_api->config_section_getval(section,
                                                   "Router",
                                                   MK_CONFIG_VAL_STR);
            pattern = mk_api->config_section_getval(section,
                                                    "Match",
                                                    MK_CONFIG_VAL_STR);

            /* Validate router */
            if (!router) {
                mk_err("No Router defined in PROXY section");
                exit(EXIT_FAILURE);
            }

            backend = proxy_conf_backend_lookup_by_name(router);
            if (!backend) {
                mk_err("Router '%s' don't exists in proxy.conf", router);
                exit(EXIT_FAILURE);
            }

            /* Validate regex expression */
            if (!pattern) {
                mk_err("No Match rule defined in PROXY section");
                exit(EXIT_FAILURE);
            }

            /* Allocate node */
            match = mk_api->mem_alloc(sizeof(struct proxy_match));
            match->router = backend;
            ret = regcomp(&match->regex, pattern, REG_EXTENDED | REG_NOSUB);
            if (ret != 0) {
                mk_err("Invalid expression on Match pattern in PROXY section");
                exit(EXIT_FAILURE);
            }

            PLUGIN_TRACE("Proxy Match: {Router=%s, Match=%s}", router, pattern);
            mk_list_add(&match->_head, &pvh->matches);
        }
    }

    return 0;
}

static int proxy_conf_parse_route(struct proxy_backend *backend)
{
    /* FIXME: parse Route string */
    int pos;
    char *route = backend->route;
    char *host = NULL;
    char *port = NULL;

    pos = mk_api->str_search(route, "://", 0);
    if (pos <= 1) {
        return -1;
    }

    /* Validate the protocol */
    if (strncasecmp(route, "http", pos) == 0) {
        backend->protocol = PROXY_PROTOCOL_HTTP;
    }
    else {
        mk_err("Invalid Route protocol for Backend '%s'", backend->name);
        return -1;
    }

    /* Check the Host part */
    host = route + pos + 3;
    if (strlen(host) < 8) {
        mk_err("Invalid Route host for Backend '%s'", backend->name);
        return -1;
    }

    /* do we have a specified port ? */
    pos = mk_api->str_search(host, ":", 0);
    if (pos == -1) {
        backend->host = mk_api->str_dup(host);
        if (backend->protocol == PROXY_PROTOCOL_HTTP) {
            backend->port = 80;
        }
    }
    else {
        backend->host = mk_api->str_copy_substr(host, 0, pos);
        port = mk_api->str_dup(host + pos + 1);
        if (strlen(port) != 0) {
            backend->port = atoi(port);
            if (backend->port <= 0) {
                mk_err("Invalid Route port for Backend '%s'", backend->name);
                return -1;
            }
        }
        else {
            mk_err("Invalid Route port for Backend '%s'", backend->name);
            return -1;
        }
    }

    snprintf(backend->cport, sizeof(backend->cport), "%i", backend->port);
    if (port) {
        mk_api->mem_free(port);
    }
    return 0;
}

static int proxy_conf_read_main(char *confdir)
{
    int ret;
    int backends = 0;
    unsigned long len;
    char *conf_path = NULL;
    struct mk_config *config;
    struct mk_config_section *section;
    struct mk_list *head;
    struct proxy_backend *backend = NULL;

    mk_api->str_build(&conf_path, &len, "%s/proxy.conf", confdir);
    config = mk_api->config_create(conf_path);
    if (!config) {
        return -1;
    }
    mk_api->mem_free(conf_path);

    /* Check every section */
    mk_list_foreach(head, &config->sections) {
        section = mk_list_entry(head, struct mk_config_section, _head);

        /* Process only [PROXY_BACKEND] */
        if (strcasecmp(section->name, "PROXY_BACKEND") != 0) {
            continue;
        }

        backend = mk_api->mem_alloc(sizeof(struct proxy_backend));
        backend->name  = mk_api->config_section_getval(section,
                                                       "Name",
                                                       MK_CONFIG_VAL_STR);
        backend->route = mk_api->config_section_getval(section,
                                                       "Route",
                                                       MK_CONFIG_VAL_STR);
        backend->keepalive = (long) mk_api->config_section_getval(section,
                                                                  "KeepAlive",
                                                                  MK_CONFIG_VAL_BOOL);

        backend->connections = (long) mk_api->config_section_getval(section,
                                                                    "Connections",
                                                                    MK_CONFIG_VAL_NUM);

        if (!backend->name) {
            mk_err("Proxy backend don't have a Name.");
            exit(EXIT_FAILURE);
        }

        if (!backend->route) {
            mk_err("Proxy backend don't have a Route.");
            exit(EXIT_FAILURE);
        }

        if (backend->keepalive < 0) {
            /* set default ON */
            backend->keepalive = MK_TRUE;
        }

        if (backend->connections <= 0) {
            backend->connections = PROXY_BACKEND_CONNECTIONS;
        }

        ret = proxy_conf_parse_route(backend);
        if (ret == -1) {
            continue;
        }

        PLUGIN_TRACE("BACKEND:\n {Name='%s',  Route='%s', Keepalive='%s', "
                     "Prot='%s', Host='%s', Port=%i}",
                     backend->name,
                     backend->route,
                     backend->keepalive ? "On": "Off",
                     backend->protocol == PROXY_PROTOCOL_HTTP ? "HTTP" : "Unknown",
                     backend->host,
                     backend->port);

        /* Temporal value: Each backend entry register 16 persistent connections */
        backend->_av_conx = backend->_total_conx = backend->connections;
        backend->_av_diff = (backend->_total_conx % mk_api->config->workers);

        mk_list_add(&backend->_head, &proxy_config.backends);
        backends++;
    }

    if (backends < 1) {
        mk_warn("Proxy Config: no backends defined");
    }

    return 0;
}

/* Initialize configuration */
int proxy_conf_init(char *confdir)
{
    int ret;

    memset(&proxy_config, '\0', sizeof(struct proxy_conf));
    mk_list_init(&proxy_config.backends);
    mk_list_init(&proxy_config.vhosts);

    /* Read main configuration */
    ret = proxy_conf_read_main(confdir);
    if (ret != 0) {
        return -1;
    }

    /* Parse and load proxies per virtual host */
    ret = proxy_conf_vhosts();
    if (ret != 0) {
        return -1;
    }

    return 0;
}
