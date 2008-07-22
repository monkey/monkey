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

#define M_DEFAULT_CONFIG_FILE	"monkey.conf"

#define VALUE_ON "on"
#define VALUE_OFF "off"

/* Base struct of server */
struct server_config {
	char *serverconf;	/* path to configuration files */
	char *server_addr;
	char *server_software;
	char *user;
	char *user_dir;
	char *pid_file_path; /* pid of server */
	char *file_config;
	char **request_headers_allowed;

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

	 /* configured host quantity */
	int nhosts;	
	struct host *hosts;
};

struct server_config *config;

struct host {
    char *file; /* configuration file */
    char *servername; /* host name */
    char *documentroot;

    char *access_log_path; /* access log file */
    char *error_log_path;  /* error log file */
    char *header_file;  /* Path file with information about directory shown */
    char *footer_file;   /* Path file with information about directory shown */

    int  getdir; /* allow show directory info ? */

    char *cgi_alias;
    char *cgi_path;
    char **scriptalias;
    char *host_signature;
    char *header_host_signature;
    int header_len_host_signature;
    int log_access[2];
    int log_error[2];
    struct host *next;
};

/* Functions */
void	M_Config_start_configure(void);
void	M_Config_read_files(char *path_conf, char *file_conf);
void	M_Config_add_index(char *indexname);
void	M_Config_print_error_msg(char *variable, char *path);
void	M_Config_set_init_values(void);

int M_Config_Get_Bool(char *value);
void M_Config_Read_Hosts(char *path);
struct host *M_Config_Get_Host(char *path);

