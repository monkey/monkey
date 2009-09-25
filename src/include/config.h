/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2003, Eduardo Silva P.
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

#include "memory.h"

#ifndef MK_CONFIG_H
#define MK_CONFIG_H

#include <unistd.h>
#include <sys/types.h>

#define O_NOATIME       01000000

#define M_DEFAULT_CONFIG_FILE	"monkey.conf"
#define MK_WORKERS_DEFAULT 1

#define VALUE_ON "on"
#define VALUE_OFF "off"

/* Base struct of server */
struct server_config {
        mk_pointer port;

	char *serverconf;	/* path to configuration files */

	mk_pointer server_addr;
	mk_pointer server_software;

	char *user;
	char *user_dir;
	char *pid_file_path; /* pid of server */
	char *file_config;
	char **request_headers_allowed;

        int  workers; /* number of worker threads */
        int  worker_capacity; /* how many clients per thread... */

	int  symlink; /* symbolic links */
	int  serverport; /* port */
	int  timeout;  /* max time to wait for a new connection */
	int  maxclients; /* max clients (max threads) */
	int  hideversion; /* hide version of server to clients ? */
	int  standard_port; /* common port used in web servers (80) */
	int  pid_status;
	int  resume; /* Resume (on/off) */
	
	/* keep alive */
	int  keep_alive; /* it's a persisten connection ? */
	int  max_keep_alive_request;  /* max persistent connections to allow */
	int  keep_alive_timeout; /* persistent connection timeout */

	/* counter of threads working */
	int thread_counter;
	/* real user */
	uid_t egid;
	gid_t euid;

	/* max ip */
	int max_ip;

        struct dir_html_theme *dir_theme;

	 /* configured host quantity */
	int nhosts;	
	struct host *hosts;

        mode_t open_flags;
        int cheetah; /* VAR_ON / VAR_OFF */
};

struct server_config *config;

struct host {
    char *file; /* configuration file */
    char *servername; /* host name */
    mk_pointer documentroot;

    char *access_log_path; /* access log file */
    char *error_log_path;  /* error log file */
    int  getdir; /* allow show directory info ? */

    char *cgi_alias;
    char *cgi_path;
    char **scriptalias;
    char *host_signature;
    mk_pointer header_host_signature;

    int log_access[2];
    int log_error[2];

    struct host *next;
};

/* Functions */
void mk_config_start_configure(void);
void mk_config_read_files(char *path_conf, char *file_conf);
void mk_config_add_index(char *indexname);
void mk_config_print_error_msg(char *variable, char *path);
void mk_config_set_init_values(void);

int mk_config_get_bool(char *value);
void mk_config_read_hosts(char *path);
void mk_config_sanity_check();

struct host *mk_config_get_host(char *path);
struct host *mk_config_host_find(mk_pointer host);

#endif
