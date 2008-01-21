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
 
 /*
 ---------------------------------------------------------------
 This module allow you register log entries in a Mysql Database

 Module		: mod_mysql.o
 Version	: 0.1
 Written by	: Eduardo Silva P.	
 ---------------------------------------------------------------
*/

#include "mod_mysql.h"

int mod_mysql_init()
{
	char *status=0, *mod_name = {"mod_mysql"};
	char **ptr_conf=0;

	mysql_config = malloc(sizeof(struct mod_mysql_config));
	ptr_conf = (char **) MOD_Read_Config(mod_name);
	
	mysql_config->user = (char *) m_build_buffer("%s", (char *) MOD_get_ptr_value(ptr_conf, "User"));
	mysql_config->pass = (char *) m_build_buffer("%s", (char *) MOD_get_ptr_value(ptr_conf, "Password"));
	mysql_config->host = (char *) m_build_buffer("%s", (char *) MOD_get_ptr_value(ptr_conf, "Host"));
	mysql_config->dbname = (char *) m_build_buffer("%s", (char *) MOD_get_ptr_value(ptr_conf, "DBname"));

	status = (char *) m_build_buffer("%s", (char *) MOD_get_ptr_value(ptr_conf, "Enabled"));

	if(strcasecmp(status,"yes")){
		mysql_config->enabled=VAR_ON;
	}
	else
		mysql_config->enabled=VAR_OFF;
		
	free(ptr_conf);
	free(status);
	return 0;
}

MYSQL *mod_mysql_connect()
{
	MYSQL *conx;
	
	if(!(conx = mysql_init(NULL))){
		fprintf(stderr, "Error: i can't start mysql_init().");
		return NULL;	
	}	
	
	mysql_real_connect(conx, \
					mysql_config->host, \
					mysql_config->user, \
					mysql_config->pass, \
					mysql_config->dbname, 0, NULL, 0);
		
	if(conx==NULL){
		fprintf(stderr, "Error: Bad user or password connecting to MySQL DB.");
		return NULL;	
	}
	
	return (MYSQL *) conx;
}

void mod_mysql_close(MYSQL *conx)
{
	mysql_close(conx);	
}

int mod_mysql_log_main(struct request *sr)
{
	char *sql=NULL;
	MYSQL *conx;

	if(mysql_config->enabled==VAR_ON)
		return 0;
		
	if(!(conx=mod_mysql_connect()))
		return -1;	

	/* Access Log */
	if(sr->log->final_response==M_HTTP_OK || sr->log->final_response==M_REDIR_MOVED_T){
		
		sql = (char *) m_build_buffer("INSERT INTO log_access VALUES('','%s', NOW(), '%s', '%s', '%s', '%i', '%i')", \
			sr->log->ip, M_METHOD_get_name(sr->method), sr->uri, get_name_protocol(sr->protocol), sr->log->final_response,  \
			sr->log->size);
	}
	else{
		sql = (char *) m_build_buffer("INSERT INTO log_error VALUES('', '%s', NOW(), '%s', '%s', '%s', '%s')", \
			sr->log->ip, M_METHOD_get_name(sr->method), sr->uri, get_name_protocol(sr->protocol), \
			sr->log->error_msg);
	}
	
	if(mysql_query(conx, sql)!=0){
		fprintf(stderr, "ERROR: SQL Query\n");
		return -1;
	}	

	mod_mysql_close(conx);
	M_free(sql);
	sql=NULL;
	return 0;
}