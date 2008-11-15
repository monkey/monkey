/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2008, Eduardo Silva P.
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
#include <string.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "monkey.h"
#include "memory.h"
#include "http.h"
#include "http_status.h"
#include "file.h"
#include "utils.h"
#include "config.h"
#include "cgi.h"
#include "str.h"
#include "method.h"
#include "socket.h"
#include "mimetype.h"
#include "dir_html.h"
#include "logfile.h"
#include "header.h"

#define O_NOATIME       01000000

int mk_http_method_check(char *method)
{
        if(strcasecmp(method, HTTP_METHOD_GET_STR)==0)
        {
                return HTTP_METHOD_GET;
        }
        
        if(strcasecmp(method, HTTP_METHOD_POST_STR)==0)
        {
                return HTTP_METHOD_POST;
        }
        
        if(strcasecmp(method, HTTP_METHOD_HEAD_STR)==0)
        {
                return HTTP_METHOD_HEAD;
        }
        
        return METHOD_NOT_FOUND;
}

char *mk_http_method_check_str(int method)
{
        switch(method){
                case HTTP_METHOD_GET:
                                return (char *) HTTP_METHOD_GET_STR;
                                
                case HTTP_METHOD_POST:
                                return (char *) HTTP_METHOD_POST_STR;
                                
                case HTTP_METHOD_HEAD:
                                return (char *) HTTP_METHOD_HEAD_STR;
        }

        return "";
}

int mk_http_method_get(mk_pointer body)
{
        int int_method, pos = 0;
        int max_len_method = 5;
        char *str_method;
        
        pos = mk_string_search(body.data, " ");
        if(pos<=2 || pos>=max_len_method){
                return METHOD_NOT_FOUND;      
        }

        str_method = mk_string_copy_substr(body.data, 0, pos);
        int_method = mk_http_method_check(str_method);
        mk_mem_free(str_method);

        return int_method;
}

int mk_http_protocol_check(char *protocol)
{
        if(strcasecmp(protocol, HTTP_PROTOCOL_11_STR)==0)
        {
                return HTTP_PROTOCOL_11;
        }
        if(strcasecmp(protocol, HTTP_PROTOCOL_10_STR)==0)
        {
                return HTTP_PROTOCOL_10;
        }
        if(strcasecmp(protocol, HTTP_PROTOCOL_09_STR)==0)
        {
                return HTTP_PROTOCOL_09;
        }

        return HTTP_PROTOCOL_UNKNOWN;
}

char *mk_http_protocol_check_str(int protocol)
{
        if(protocol==HTTP_PROTOCOL_11)
        {
                return (char *) HTTP_PROTOCOL_11_STR;
        }
        if(protocol==HTTP_PROTOCOL_10)
        {
                return (char *) HTTP_PROTOCOL_10_STR;
        }
        if(protocol==HTTP_PROTOCOL_09)
        {
                return (char *) HTTP_PROTOCOL_09_STR;
        }

        return "";
}

int mk_http_init(struct client_request *cr, struct request *sr)
{
        int debug_error=0, bytes=0;
        char *location=0, *real_location=0; /* ruta para redireccion */
        char **mime_info;
        mk_pointer gmt_file_unix_time; // gmt time of server file (unix time)
        struct file_info *path_info;
        unsigned long len;

        /* Normal request default site */
        if((strcmp(sr->uri_processed,"/"))==0)
        {
                m_build_buffer(&sr->real_path, &len, "%s", 
                                sr->host_conf->documentroot);
        }

        if(sr->user_home==VAR_OFF)
        {
                m_build_buffer(&sr->real_path, &len, "%s%s", 
                                sr->host_conf->documentroot, 
                                sr->uri_processed);
        }
        
        if(sr->method!=HTTP_METHOD_HEAD){
                debug_error=1;
        }

        path_info = mk_file_get_info(sr->real_path);
        if(!path_info){
                mk_request_error(M_CLIENT_NOT_FOUND, cr, sr, 
                                debug_error, sr->log);
                return -1;
        }

        /* Check symbolic link file */
        if(path_info->is_link == MK_FILE_TRUE){
                if(config->symlink==VAR_OFF){
                        sr->log->final_response=M_CLIENT_FORBIDDEN;
                        mk_request_error(M_CLIENT_FORBIDDEN, cr, sr, 
                                        debug_error, sr->log);
                        return -1;
                }               
                else{
                        char linked_file[MAX_PATH];
                        readlink(sr->real_path, linked_file, MAX_PATH);
                        /*              
                        if(Deny_Check(linked_file)==-1) {
                                sr->log->final_response=M_CLIENT_FORBIDDEN;
                                mk_request_error(M_CLIENT_FORBIDDEN, cr, sr, debug_error, sr->log);
                                return -1;
                        }
                        */
                        
                }                       
        }
        /* is it a valid directory ? */
        if(path_info->is_directory == MK_FILE_TRUE) {
                /* This pointer never must be freed */
                char *index_file = 0; 

                /* 
                  We have to check if exist an slash to the end of
                  this string, if doesn't exist we send a redirection header
                */
                if(sr->uri_processed[strlen(sr->uri_processed) - 1] != '/') {
                        char *host;
                        host = mk_pointer_to_buf(sr->host);

                        m_build_buffer(&location, &len, "%s/", sr->uri_processed);
                        if(config->serverport == config->standard_port)
                        {
                                m_build_buffer(&real_location, &len, "http://%s%s", 
                                                host, location);
                        }
                        else
                        {
                                m_build_buffer(&real_location, &len, "http://%s:%i%s",
                                                host, config->serverport,
                                                location);
                        }
                        mk_mem_free(host);

                        sr->headers->status = M_REDIR_MOVED;
                        sr->headers->content_length = 0;
                        sr->headers->content_type = NULL;
                        sr->headers->location = real_location;
                        sr->headers->cgi = SH_NOCGI;
                        sr->headers->pconnections_left = 
                                (config->max_keep_alive_request - 
                                cr->counter_connections);

                        mk_header_send(cr->socket, cr, sr, sr->log);
                        mk_socket_set_cork_flag(cr->socket, TCP_CORK_OFF);

                        /* 
                         *  we do not free() real_location 
                         *  as it's freed by iov 
                         */
                        mk_mem_free(location);
                        sr->headers->location=NULL;
                        return 0;
                }

                /* looking for a index file */
                index_file = (char *) mk_request_index(sr->real_path);

                if(!index_file) {
                        /* No index file found, show the content directory */
                        if(sr->host_conf->getdir==VAR_ON) {
                                int getdir_res = 0;

                                getdir_res = mk_dirhtml_init(cr, sr);
                                        
                                if(getdir_res == -1){
                                        mk_request_error(M_CLIENT_FORBIDDEN, cr, sr, 1, sr->log);
                                        return -1;
                                }
                                return getdir_res;
                        }
                        else {
                                mk_request_error(M_CLIENT_FORBIDDEN, cr, sr, 1, sr->log);
                                return -1;
                        }
                }
                else{
                        mk_mem_free(path_info);
                        sr->real_path = 
                                m_build_buffer_from_buffer(sr->real_path, "%s", index_file);

                        path_info = mk_file_get_info(sr->real_path);
                }
        }

        /* read permission */ 
        if(path_info->read_access == MK_FILE_FALSE){
                mk_request_error(M_CLIENT_FORBIDDEN, cr, sr, 1, sr->log);
                return -1;      
        }
                
        /* Matching MimeType  */
        mime_info=Mimetype_Find(sr->real_path);

        /* FIXME:
         *
         * Some returns are not freeing all memory blocks allocated
         */

        if(mime_info[1]){
                struct file_info *fcgi;
                fcgi = mk_file_get_info(mime_info[1]);
                
                /* executable script (e.g PHP) ? */
                if(fcgi){
                        int cgi_status=0;
                        char *arg_script[3];
                        
                        /* is it  normal file ? */
                        if(fcgi->is_directory==MK_FILE_TRUE || fcgi->exec_access==MK_FILE_FALSE){
                                mk_request_error(M_SERVER_INTERNAL_ERROR, cr, sr, 1, sr->log);
                                Mimetype_free(mime_info);
                                return -1;
                        }
                        /*
                         * FIXME: CHECK FOR TARGET PERMISSION AS GCI DOES
                         *                      
                         ftarget = mk_file_get_info(sr->script_filename);
                        if(!ftarget)
                        {
                        
                        }
                        */
                        sr->log->final_response=M_HTTP_OK;
                        sr->script_filename=mk_string_dup(sr->real_path);

                        arg_script[0] = mime_info[1];
                        arg_script[1] = sr->script_filename;
                        arg_script[2] = NULL;

                        if(sr->method==HTTP_METHOD_GET || sr->method==HTTP_METHOD_POST)
                        {
                                cgi_status=M_CGI_run(cr, sr, mime_info[1], arg_script);
                        }
                        
                        switch(cgi_status){
                                case -2:        /* Timeout */
                                        sr->log->final_response=M_CLIENT_REQUEST_TIMEOUT;
                                        break;
                                case -3:  /* Internal server Error */
                                        sr->log->final_response=M_SERVER_INTERNAL_ERROR;
                                        break;
                                case -1:
                                        sr->make_log=VAR_OFF;
                                        break;
                                case 0:  /* Ok */
                                        sr->log->final_response=M_HTTP_OK;
                                        break;
                        };      

                        if(cgi_status==M_CGI_TIMEOUT || 
                                        cgi_status==M_CGI_INTERNAL_SERVER_ERR)
                        {
                                mk_request_error(sr->log->final_response, cr, 
                                                sr, 1, sr->log);        
                        }

                        Mimetype_free(mime_info);
                        mk_mem_free(fcgi);
                        return cgi_status;
                }
        }
        /* get file size */
        if(path_info->size < 0) {
                mk_request_error(M_CLIENT_NOT_FOUND, cr, sr, 1, sr->log);
                Mimetype_free(mime_info);
                return -1;
        }
        
        /* counter connections */
        sr->headers->pconnections_left = (int) 
                (config->max_keep_alive_request - cr->counter_connections);

        gmt_file_unix_time = 
                PutDate_string((time_t) path_info->last_modification);

        if(sr->if_modified_since.data && sr->method==HTTP_METHOD_GET){
                time_t date_client; // Date send by client
                time_t date_file_server; // Date server file
        
        
                date_client = PutDate_unix(sr->if_modified_since.data);
                date_file_server = PutDate_unix(gmt_file_unix_time.data);

                if( (date_file_server <= date_client) && (date_client > 0) )
                {
                        sr->headers->status = M_NOT_MODIFIED;
                        mk_header_send(cr->socket, cr, sr, sr->log);    
                        Mimetype_free(mime_info);
                        mk_mem_free(path_info);
                        mk_pointer_free(&gmt_file_unix_time);
                        return 0;
                }
        }
        sr->headers->status = M_HTTP_OK;
        sr->headers->content_length = path_info->size;
        sr->headers->cgi = SH_NOCGI;
        sr->headers->last_modified = gmt_file_unix_time.data;
        sr->headers->location = NULL;

        sr->log->size = path_info->size;
        if(sr->method==HTTP_METHOD_GET || sr->method==HTTP_METHOD_POST)
        {
                sr->headers->content_type = mime_info[0];
                /* Range */
                if(sr->range.data!=NULL && config->resume==VAR_ON){
                        if(mk_http_range_parse(sr)<0)
                        {
                                mk_request_error(M_CLIENT_BAD_REQUEST, cr, 
                                        sr, 1, sr->log);
                                mk_pointer_free(&gmt_file_unix_time);
                                return -1;
                        }
                        if(sr->headers->ranges[0]>=0 || sr->headers->ranges[1]>=0)
                                sr->headers->status = M_HTTP_PARTIAL;
                }
        }
        else{ /* without content-type */
                sr->headers->content_type = NULL;
        }

        mk_header_send(cr->socket, cr, sr, sr->log);

        if(sr->headers->content_length==0){
                Mimetype_free(mime_info);
                return 0;
        }

        /* Sending file */
        if((sr->method==HTTP_METHOD_GET || sr->method==HTTP_METHOD_POST) 
                        && path_info->size>0)
        {
                /* O_NOATIME will just work if process owner has 
                 * root privileges */
                sr->fd_file = open(sr->real_path, 
                                   O_RDONLY|O_NOATIME|O_NONBLOCK);

                /* Calc bytes to send & offset */
                if(mk_http_range_set(sr, path_info->size)!=0)
                {
                        mk_request_error(M_CLIENT_BAD_REQUEST, cr, 
                                        sr, 1, sr->log);
                        return -1;
                }
                
                mk_socket_set_cork_flag(cr->socket, TCP_CORK_OFF);
                bytes = SendFile(cr->socket, sr);
        }

        Mimetype_free(mime_info);
        mk_mem_free(path_info);
        sr->headers->content_type=NULL;

        return bytes;
}

/* 
 * Check if a connection can continue open using as criteria
 * the keepalive headers vars and Monkey configuration
 */
int mk_http_keepalive_check(int socket, struct client_request *cr)
{
        if(!cr->request)
        {
                return -1;
        }

        if(config->keep_alive==VAR_OFF || cr->request->keep_alive==VAR_OFF)
        {
                return -1;
        }

        if(cr->counter_connections>=config->max_keep_alive_request)
        {
                return -1;
        }

        return 0;
}

int mk_http_range_set(struct request *sr, long file_size)
{
        struct header_values *sh = sr->headers;

        sr->bytes_to_send = file_size;
        sr->bytes_offset = 0;
        
        if(config->resume==VAR_ON && sr->range.data){
                /* yyy- */
                if(sh->ranges[0]>=0 && sh->ranges[1]==-1){
                        sr->bytes_offset = sh->ranges[0];
                        sr->bytes_to_send = file_size - sr->bytes_offset;
                }

                /* yyy-xxx */
                if(sh->ranges[0]>=0 && sh->ranges[1]>=0){
                        sr->bytes_offset = sh->ranges[0];
                        sr->bytes_to_send = labs(sh->ranges[1]-sh->ranges[0])+1;
                }

                /* -xxx */
                if(sh->ranges[0]==-1 && sh->ranges[1]>=0){
                        sr->bytes_to_send = file_size - sh->ranges[1];
                }

                if(sr->bytes_offset>file_size || sr->bytes_to_send>file_size)
                {
                        return -1;
                }

                lseek(sr->fd_file, sr->bytes_offset, SEEK_SET);
        }
        return 0;


}

int mk_http_range_parse(struct request *sr)
{
        int eq_pos, sep_pos, len;
        char *buffer=0;

        if(!sr->range.data)
                return -1;      

        if((eq_pos = mk_string_search_n(sr->range.data, "=",
                                        sr->range.len))<0)
                return -1;      

        if(strncasecmp(sr->range.data, "Bytes", eq_pos)!=0)
                return -1;      
        
        if((sep_pos = mk_string_search_n(sr->range.data, "-",
                                        sr->range.len))<0)
                return -1;
        
        len = sr->range.len;

        /* =-xxx */
        if(eq_pos+1 == sep_pos){
                sr->headers->ranges[0] = -1;
                sr->headers->ranges[1] = (unsigned long) atol(sr->range.data + sep_pos + 1);

                if(sr->headers->ranges[1]<=0)
                {
                        return -1;
                }
                return 0;
        }

        /* =yyy-xxx */
        if( (eq_pos+1 != sep_pos) && (len > sep_pos + 1))
        {
                buffer = mk_string_copy_substr(sr->range.data, eq_pos+1, sep_pos);
                sr->headers->ranges[0] = (unsigned long) atol(buffer);
                mk_mem_free(buffer);

                buffer = mk_string_copy_substr(sr->range.data, sep_pos+1, len);
                sr->headers->ranges[1] = (unsigned long) atol(buffer);
                mk_mem_free(buffer);
                
                if(sr->headers->ranges[1]<=0 || 
                                sr->headers->ranges[0]>sr->headers->ranges[1])
                {
                        return -1;
                }

                return 0;
        }
        /* =yyy- */
        if( (eq_pos+1 != sep_pos) && (len == sep_pos + 1))
        {
                buffer = mk_string_copy_substr(sr->range.data, eq_pos+1, len);
                sr->headers->ranges[0] = (unsigned long) atol(buffer);
                mk_mem_free(buffer);
                return 0;
        }
        
        return -1;      
}

