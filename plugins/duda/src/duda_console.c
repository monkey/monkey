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

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdarg.h>

#include "MKPlugin.h"
#include "duda.h"
#include "duda_api.h"
#include "duda_conf.h"

struct duda_api_console *duda_console_object()
{
    struct duda_api_console *c;

    c = mk_api->mem_alloc(sizeof(struct duda_api_console));
    c->_debug = duda_console_write;

    return c;
}

/* callback for /app/console/debug */
void duda_console_cb_debug(duda_request_t *dr)
{
    http_status(dr, 200);
    http_header(dr, "Content-Type: text/plain", 24);
    sendfile_enqueue(dr, "/tmp/duda.console");
    end_response(dr, NULL);
}

/* callback for /app/console/map */
void duda_console_cb_map(duda_request_t *dr)
{
    struct web_service *ws = dr->ws_root;
    struct mk_list *head_iface, *head_method;
    struct duda_interface *entry_iface;
    struct duda_method *entry_method;

    char *header = "<html><head><title>Duda Map: %s</title>%s</head><body>\n";
    char *css    = "<STYLE type=\"text/css\">\n"
                   "body {\n"
                   "      font-family: trebuchet, Arial, Verdana, Helvetica, sans-serif;\n"
		           "      letter-spacing: 0.015em;\n"
                   " 	  word-spacing: 0.080em;\n"
		           "      font-style:normal;\n"
                   "	  font-weight:normal;\n"
                   "      font-size: 0.75em;\n"
                   "	  color: #073a61;\n"
                   "  	  border-width: 6px 0 0 0;\n"
                   "      border-style: solid;\n"
                   "      margin: 0;\n"
                   "      padding-left: 10px;\n"
                   "}\n"
                   "</STYLE>\n";
    char *footer = "</body></html>\n";

    http_status(dr, 200);
    http_header(dr, "Content-Type: text/html", 23);

    /* Header */
    body_printf(dr, header, dr->ws_root->app_name, css);
    body_printf(dr, "<h2>%s/</h2>\n<ul>", dr->ws_root->app_name);

    /* List of interfaces */
    mk_list_foreach(head_iface, ws->map) {
        entry_iface = mk_list_entry(head_iface, struct duda_interface, _head);
        body_printf(dr, "<h3>%s/<h3>\n<ul>\n", entry_iface->uid);

        /* List methods */
        mk_list_foreach(head_method, &entry_iface->methods) {
            entry_method = mk_list_entry(head_method, struct duda_method, _head);
            body_printf(dr, "\t<li>%s()</li>\n", entry_method->uid);

            /* FIXME: print parameters
            mk_list_foreach(head_param, &entry_method->params) {
                entry_param = mk_list_entry(head_param, struct duda_param, _head);
                body_printf(dr, "\t\t<li>%s</li>\n", entry_param->name);
            }
            body_printf(dr, "\t\t</ul>\n");
            */
        }
        body_printf(dr, "</ul>\n");
    }

    body_printf(dr, "</ul>");

    /* Footer */
    body_print(dr, footer, strlen(footer));
    end_response(dr, NULL);
}

void duda_console_write(duda_request_t *dr, char *file, int line, char *format, ...)
{
    int fd;
    int buf_size = 1024;
    char buf[buf_size];
    mk_pointer *now;

    /* Guess we need no more than 128 bytes. */
    int n, size = 128;
    char *p, *np;
    va_list ap;

    if ((p = mk_api->mem_alloc(size)) == NULL) {
        return;
    }

    while (1) {
        /* Try to print in the allocated space. */
        va_start(ap, format);
        n = vsnprintf(p, size, format, ap);
        va_end(ap);
        /* If that worked, return the string. */
        if (n > -1 && n < size)
            break;

        size *= 2;  /* twice the old size */
        if ((np = realloc (p, size)) == NULL) {
            free(p);
            return;
        } else {
            p = np;
        }
    }


    fd = open("/tmp/duda.console", O_WRONLY | O_APPEND | O_CREAT, 0644);
    if (fd == -1) {
        perror("open");
    }

    now = mk_api->time_human();
    n = snprintf(buf, buf_size, "%s [fd=%i req=%p] [%s:%i] %s\n", now->data, dr->cs->socket,
                 dr, file, line, p);
    n = write(fd, buf, n);
    close(fd);

    mk_api->mem_free(p);
}
