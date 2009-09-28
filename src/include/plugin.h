/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2009, Eduardo Silva P.
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

#ifndef MK_PLUGIN_H
#define MK_PLUGIN_H 

#define MK_PLUGIN_LOAD "plugins.load"

#define MK_PLUGIN_ERROR -1  /* plugin execution error */
#define MK_PLUGIN_

#define MK_PLUGIN_STAGE_10 ((__uint32_t) 1)  /* Before server's loop */
#define MK_PLUGIN_STAGE_20 ((__uint32_t) 2)  /* Accepted connection */
#define MK_PLUGIN_STAGE_30 ((__uint32_t) 4)  /* Connection assigned */
#define MK_PLUGIN_STAGE_40 ((__uint32_t) 8)  /* Object Handler */
#define MK_PLUGIN_STAGE_50 ((__uint32_t) 16) /* Request ended */
#define MK_PLUGIN_STAGE_60 ((__uint32_t) 32) /* Connection closed */

struct plugins {
        struct plugin *stage_10;
        struct plugin *stage_20;
        struct plugin *stage_30;
        struct plugin *stage_40;
        struct plugin *stage_50;
        struct plugin *stage_60;
};

struct plugin {
        char *name;
        char *version;
        void *handler;
        __uint32_t *stages;

        /* Plugin external functions */
        int (*call_init)(void *api);
        int (*call_stage_10)();

        struct plugin *next;
};

struct plugin_api {
        struct server_config *config;
        struct sched_list_node **sched_list;

        void (*malloc)(void *);
};

typedef char mk_plugin_data_t[];
typedef __uint32_t mk_plugin_stage_t;

struct plugins *plgs;

void mk_plugin_init();
void mk_plugin_stage_run(mk_plugin_stage_t stage);

#endif
