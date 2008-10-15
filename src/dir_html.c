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

/***********************************************/ 
/* Modulo dir_html.c written by Daniel R. Ome */
/***********************************************/

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <time.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "monkey.h"
#include "http.h"
#include "http_status.h"
#include "str.h"
#include "memory.h"
#include "utils.h"
#include "config.h"
#include "method.h"
#include "socket.h"
#include "dir_html.h"
#include "header.h"
#include "file.h"
#include "iov.h"

struct mk_f_list
{
        char *name;
        char *ft_modif;
        char *size;
        unsigned char type;
        struct file_info *info;
};

/* Function wrote by Max (Felipe Astroza), thanks! */
char *mk_dirhtml_human_readable_size(off_t size)
{
        unsigned long u = 1024, i, len;
        char *buf;

        for(i = 0; __units[i] != NULL; i++) {
                if((size / u) == 0){
                        break;
                }
                u *= 1024;
        }
        if(!i){
                m_build_buffer(&buf, &len, "%u%s", size, __units[0]);
        }
        else {
                float fsize = (float)((double)size / (u/1024));
                m_build_buffer(&buf, &len, "%.1f%s\n", fsize, __units[i]);
        }

        return buf;
}

void mk_dirhtml_add_element(struct mk_f_list *list, char *file,
                            unsigned char type, char *full_path, unsigned long *count)
{
        unsigned long len;
        off_t size;
        char size_type;

        list[*count].name = file;
        list[*count].type = type;
        list[*count].info = (struct file_info *) mk_file_get_info(full_path);

        size = list[*count].info->size;

        if(type != DT_DIR){
                list[*count].size = mk_dirhtml_human_readable_size(size);
        }
        else{
                list[*count].size = MK_DIRHTML_SIZE_DIR;
        }

        *count = *count + 1;
}

int mk_dirhtml_create_list(DIR *dir, struct mk_f_list *file_list,
                           char *path, unsigned long *list_len, int offset)
{
	unsigned long len;
        char *full_path;
        struct dirent *ent;

	/* Before to send the information, we need to build
         * the list of entries, this really sucks because the user
         * always will want to have the information sorted, why we don't 
         * add some spec to the HTTP protocol in order to send the information
         * in a generic way and let the client choose how to show it
         * as they does browsing a FTP server ???, we can save bandweight,
         * let the cool firefox developers create different templates and
         * we are going to have a more happy end users.
         *
         * that kind of ideas comes when you are in an airport just waiting :)
         */

	while((ent = readdir(dir)) != NULL)
	{
                if(strcmp((char *) ent->d_name, "." )  == 0) continue;
                if(strcmp((char *) ent->d_name, ".." ) == 0) continue;

                /* Look just for files and dirs */
                if(ent->d_type!=DT_REG && ent->d_type!=DT_DIR)
                {
                        continue;
                }

		if(!ent->d_name)
                {
			puts("mk_dirhtml :: buffer error");
		}


		m_build_buffer(&full_path, &len, "%s%s", path, ent->d_name);
		mk_dirhtml_add_element(file_list, ent->d_name, ent->d_type,
                                       full_path, list_len);

                if (!file_list)
                {
                        closedir(dir);
			return -1;
		}
 	}
        
        return 0;
}

/* Read dirhtml config and themes */
int mk_dirhtml_conf()
{
        int ret = 0;
        unsigned long len;
        char *themes_path;
        
        m_build_buffer(&themes_path, &len, "%s/dir_themes/", config->serverconf);
        ret = mk_dirhtml_read_config(themes_path);

        /* This function will load the default theme 
         * setted in dirhtml_conf struct 
         */
        ret = mk_dirhtml_theme_load();

        return ret;
}

/* 
 * Read the main configuration file for dirhtml: dirhtml.conf, 
 * it will alloc the dirhtml_conf struct
*/
int mk_dirhtml_read_config(char *path)
{
        unsigned long len;
        char *default_file;
        char buffer[255];
        FILE *fileconf;
        char *variable, *value, *last;

        m_build_buffer(&default_file, &len, "%sdirhtml.conf", path);

        if(!(fileconf = fopen(default_file, "r")))
        {
          puts("Error: Cannot open dirhtml conf file");
          return -1;
        }

        /* alloc dirhtml config struct */
        dirhtml_conf = mk_mem_malloc(sizeof(struct dirhtml_config));

        while(fgets(buffer, 255, fileconf))
        {
                 len = strlen(buffer);
                 if(buffer[len-1] == '\n') {
                   buffer[--len] = 0;
                   if(len && buffer[len-1] == '\r')
                     buffer[--len] = 0;
                 }
        
                 if(!buffer[0] || buffer[0] == '#')
                          continue;
            
                 variable   = strtok_r(buffer, "\"\t ", &last);
                 value     = strtok_r(NULL, "\"\t ", &last);

                 if (!variable || !value) continue;

                 /* Server Name */
                 if(strcasecmp(variable,"Theme")==0)
                 {
                         dirhtml_conf->theme = mk_string_dup(value);
                         m_build_buffer(&dirhtml_conf->theme_path, &len, 
                                        "%s%s/", path, dirhtml_conf->theme);
                 }
        }
        fclose(fileconf);
        return 0;
}

int mk_dirhtml_theme_load()
{
        /* List of Values */
        char *lov_header[] = MK_DIRHTML_TPL_HEADER;
        char *lov_entry[] = MK_DIRHTML_TPL_ENTRY;
        char *lov_footer[] = MK_DIRHTML_TPL_FOOTER;

        /* Data */
	char *header, *entry, *footer;

        /* Load theme files */
        header = mk_dirhtml_load_file(MK_DIRHTML_FILE_HEADER);
        entry = mk_dirhtml_load_file(MK_DIRHTML_FILE_ENTRY);
        footer = mk_dirhtml_load_file(MK_DIRHTML_FILE_FOOTER);

        if(!header || !entry || !footer)
        {
                mk_mem_free(header);
                mk_mem_free(entry);
                mk_mem_free(footer);
                return -1;
        }

        /* Parse themes */
        mk_dirhtml_tpl_header = mk_dirhtml_theme_parse(header, lov_header);
        mk_dirhtml_tpl_entry = mk_dirhtml_theme_parse(entry, lov_entry);
        mk_dirhtml_tpl_footer = mk_dirhtml_theme_parse(footer, lov_footer);

#ifdef DEBUG_THEME
        /* Debug data */
        mk_dirhtml_theme_debug(mk_dirhtml_tpl_header, lov_header);
        mk_dirhtml_theme_debug(mk_dirhtml_tpl_entry, lov_entry);
        mk_dirhtml_theme_debug(mk_dirhtml_tpl_footer, lov_footer);
#endif
        return 0;
}

#ifdef DEBUG_THEME
int mk_dirhtml_theme_debug(struct dirhtml_template *st_tpl, char *tpl[])
{
        int i=0;
        struct dirhtml_template *aux;

        aux = st_tpl;
        printf("\n** DEBUG_THEME **");
        
        while(aux)
        {
                if(!aux->buf)
                {
                        //printf("\n%i) %s", i, tpl[st_tpl[i].tag]);
                        printf("\n%i) %s (tag=%i)", i, tpl[aux->tag], aux->tag);
                }
                else{
                        printf("\n%i) %s", i, aux->buf);
                }

                fflush(stdout);
                aux = aux->next;
                i++;
        }
        return 0;
}
#endif

/* Search which tag exists first in content :
 * ex: %_html_title_%
 */
int mk_dirhtml_theme_match_tag(char *content, char *tpl[])
{
        int i, len, match;
        
        for(i=0; tpl[i]; i++){
                len = strlen(tpl[i]);
                match = _mk_string_search(content, tpl[i], -1);
                if(match>=0){
                        return i;
                }
        }

        return -1;
}

/* return the number of valid tags found in text string */
int mk_dirhtml_content_count_tags(char *content, char *tpl[])
{
        int pos=0, count=0;
        int len, tpl_idx;
        int loop=0;

        len = strlen(content);
        while(loop<len)
        {
                pos = _mk_string_search(content+loop, MK_DIRHTML_TAG_INIT, -1);
                if(pos>=0){
                        tpl_idx = mk_dirhtml_theme_match_tag(content+loop, tpl);
                        if(tpl_idx>=0){
                                count++;
                        }
                        loop+=pos;
                }
                else{
                        break;
                }
                loop++;

        }
        return count;
}

struct dirhtml_template *mk_dirhtml_theme_parse(char *content, char *tpl[])
{
        int i=0, arr_len, cont_len;
        int pos, last=0; /* 0=search init, 1=search end */
        int n_tags=0, tpl_idx=0;
        int c_tags=0;

        char *_buf;
        int _len;
        struct dirhtml_template *st_tpl=0;

        cont_len = strlen(content);
        if(cont_len<=0){
                return NULL;
        };
        
        arr_len = mk_string_array_count(tpl);

        /* Alloc memory for the typical case where exist n_tags, 
         * no repetitive tags
         */
        c_tags = mk_dirhtml_content_count_tags(content, tpl);

        //st_tpl = (struct dirhtml_template **) mk_mem_malloc_z(sizeof(struct dirhtml_template)*(*tpl_length));

        /* Parsing content */
        while(i<cont_len)
        {
                pos = _mk_string_search(content+i,
                                                MK_DIRHTML_TAG_INIT, -1);

                if(pos<0){
                        break;
                }

                tpl_idx = mk_dirhtml_theme_match_tag(content+i+pos, tpl);

                if(tpl_idx>=0){
                        
                        _buf = mk_string_copy_substr(content, i, i+pos);
                        _len = strlen(_buf);
                        if(!st_tpl){
                                st_tpl = mk_dirhtml_template_list_add(NULL, _buf, _len, -1);
                        }
                        else{
                                mk_dirhtml_template_list_add(&st_tpl, _buf, _len, -1);
                        }
                        i += (pos+strlen(tpl[tpl_idx]));

                        /* This means that a value need to be replaced */
                        mk_dirhtml_template_list_add(&st_tpl, NULL, -1, tpl_idx);
                        n_tags++;
                }
                else{
                        i++;
                }
                
        }

        if(last<cont_len){
                _buf = mk_string_copy_substr(content, i, cont_len);
                _len = strlen(_buf);

                if(n_tags<=0){
                        st_tpl = mk_dirhtml_template_list_add(NULL, _buf, _len, -1);
                }
                else{
                        mk_dirhtml_template_list_add(&st_tpl, _buf, _len, -1);
                }
        }

        /*
        printf("\n**********FINAL LIST:");
        aux = st_tpl;
        while(aux){
                printf("\n---\nbuf: %s", aux->buf);
                printf("\nlen: %i", aux->len);
                printf("\ntag: %i", aux->tag);
                aux = aux->next;
        }
        fflush(stdout);
        */
        return (struct dirhtml_template *) st_tpl;
}

struct dirhtml_template *mk_dirhtml_template_list_add(struct dirhtml_template **header, 
                                                      char *buf, int len, int tag)
{
        struct dirhtml_template *node, *aux;

        node = mk_mem_malloc_z(sizeof(struct dirhtml_template));
        if(!node)
        {
                return NULL;
        }

        node->buf = buf;
        node->len = len;
        node->tag = tag;
        node->next = NULL;

        if(!header){
                return (struct dirhtml_template *) node;
        }

        aux = *header;
        while((*aux).next!=NULL){
                aux = (*aux).next;
        }

        (*aux).next = node;
        return (struct dirhtml_template *) node;
}

int mk_dirhtml_tag_get_id(char *tpl_tags[], char *tag)
{
        int i;
        for(i=0; tpl_tags[i]; i++)
        {
                if(strcmp(tpl_tags[i], tag)==0){
                        return i;
                }
        }

        return -1;
}

int mk_dirhtml_template_len(struct dirhtml_template *tpl)
{
        int len=0;
        struct dirhtml_template *aux;

        aux = tpl;
        while(aux){
                len++;
                aux = aux->next;
        }

        return len;
}

struct mk_iov *mk_dirhtml_theme_compose(char *tpl_tags[], 
                             struct dirhtml_template *tpl_tpl,
                             struct dirhtml_tplval *tpl_values)
{
        /*
         * tpl_tags = MK_DIRHTML_TPL_HEADER = {xy, yz}
         * tpl_tpl = struct { char buf ; int len, int tag }
         * tpl_values = struct {int tag, char *value, struct *next}
         */

        struct dirhtml_tplval *tpl_val = tpl_values;
        struct mk_iov *iov;
        struct dirhtml_template *tpl_list;
        int tpl_len;

        tpl_len = mk_dirhtml_template_len(tpl_tpl);
        iov = mk_iov_create(tpl_len);
        tpl_list = tpl_tpl;

        while(tpl_list){
                /* check for dynamic value */
                if(!tpl_list->buf && tpl_list->tag>=0){
                        tpl_val = tpl_values;
                        while(tpl_val){
                                if(tpl_val->tag == tpl_list->tag)
                                {
                                        mk_iov_add_entry(iov, tpl_val->value, tpl_val->len,
                                                         tpl_val->sep, MK_IOV_NOT_FREE_BUF);

                                        break;
                                }
                                tpl_val = tpl_val->next;
                        }
                        if(!tpl_val){
                                break; 
                        }
                        
                } 
                /* static */
                else{
                        mk_iov_add_entry(iov, tpl_list->buf, tpl_list->len, MK_IOV_NONE, MK_IOV_NOT_FREE_BUF);
                }
                tpl_list = tpl_list->next;
        }
        return (struct mk_iov *) iov;
}

struct dirhtml_tplval *mk_dirhtml_tag_assign(struct dirhtml_tplval **tplval, 
                                             int tag_id, int sep, char *value)
{
        struct dirhtml_tplval *check, *aux=0;
        
        aux = mk_mem_malloc(sizeof(struct dirhtml_tplval));
        if(!aux){
                return NULL;
        }

        aux->tag = tag_id;
        aux->value = value;
        aux->sep = sep;
        aux->len = strlen(value);
        aux->next = NULL;

        if(!tplval){
                return (struct dirhtml_tplval *) aux;
        }

        check = *tplval;
        while((*check).next){
                check = (*check).next;
        }

        (*check).next = aux;


        return (struct dirhtml_tplval *) aux;
}

char *mk_dirhtml_load_file(char *filename)
{
        char *tmp=0, *data=0;
        unsigned long len;

        m_build_buffer(&tmp, &len, "%s%s",
                       dirhtml_conf->theme_path, filename);

        if(!tmp)
        {
                return NULL;
        }

        data = mk_file_to_buffer(tmp);
        mk_mem_free(tmp);

        if(!data)
        {
                return NULL;
        }

        return (char *) data;
}

int mk_dirhtml_entry_cmp(const void *a, const void *b)
{
        struct mk_f_list *f_a = (struct mk_f_list *) a;
        struct mk_f_list *f_b = (struct mk_f_list *) b;

        return strcmp(f_a->name, f_b->name);

}

int mk_dirhtml_init(struct client_request *cr, struct request *sr)
{
        DIR *dir;
        int ret, i, sep;
        unsigned long len;

        char *tags_header[] = MK_DIRHTML_TPL_HEADER;
        char *tags_entry[] = MK_DIRHTML_TPL_ENTRY;
        char *tags_footer[] = MK_DIRHTML_TPL_FOOTER;

	/* file info */
	unsigned long list_len=0;
        struct mk_f_list *file_list;
        struct mk_iov *iov_header, *iov_footer, *iov_entry;
        struct dirhtml_tplval *tplval_header;
        struct dirhtml_tplval *tplval_entry;
        
        if(!(dir = opendir(sr->real_path)))
        {
                return -1;
        }

        file_list = mk_mem_malloc(
                                  sizeof(struct mk_f_list)*
                                  MK_DIRHTML_BUFFER_LIMIT);

        ret = mk_dirhtml_create_list(dir, file_list, sr->real_path, &list_len, 0);

        /* Building headers */
        sr->headers->transfer_encoding = -1;
	sr->headers->status = M_HTTP_OK;
	sr->headers->cgi = SH_CGI;
        sr->headers->breakline = MK_HEADER_BREAKLINE;

	m_build_buffer(&sr->headers->content_type, &len, "text/html");

        /*
	if(sr->protocol==HTTP_PROTOCOL_11)
	{
		sr->headers->transfer_encoding = MK_HEADER_TE_TYPE_CHUNKED;
	}
	*/

	/* Sending headers */
	mk_header_send(cr->socket, cr, sr, sr->log);

        //mk_iov_add_entry(html_list, chunked_line, strlen(chunked_line), MK_IOV_NONE, MK_IOV_FREE_BUF);

        /* Creating response template */
        tplval_header = mk_dirhtml_tag_assign(NULL, 0, MK_IOV_NONE, sr->uri_processed);

        /* HTML Header */
        iov_header = mk_dirhtml_theme_compose(tags_header,
                                              mk_dirhtml_tpl_header, 
                                              tplval_header);

        /* HTML Footer */
        iov_footer = mk_dirhtml_theme_compose(tags_footer,
                                              mk_dirhtml_tpl_footer, NULL);

        mk_socket_set_cork_flag(cr->socket, TCP_CORK_OFF);
        mk_iov_send(cr->socket, iov_header);

        /* sort entries */
        qsort(file_list, list_len, sizeof(struct mk_f_list), mk_dirhtml_entry_cmp);

        for (i=0; i<list_len; i++)
	{
                /* %_target_title_% */
                if(file_list[i].type==DT_DIR){
                        sep = MK_IOV_SLASH;
                }
                else{
                        sep = MK_IOV_NONE;
                }


                /* target title */
                tplval_entry = mk_dirhtml_tag_assign(NULL, 0, sep, file_list[i].name);
                /* target url */
                mk_dirhtml_tag_assign(&tplval_entry, 1, sep, file_list[i].name);
                /* target name */
                mk_dirhtml_tag_assign(&tplval_entry, 2, sep, file_list[i].name);
                /* target time */
                // mk_dirhtml_tag_assign(&tplval_entry, 3, sep, file_list[i].ft_modif);

                /* target size */
                mk_dirhtml_tag_assign(&tplval_entry, 4, MK_IOV_NONE, file_list[i].size);

                iov_entry = mk_dirhtml_theme_compose(tags_entry, mk_dirhtml_tpl_entry,
                                                     tplval_entry);
                mk_iov_send(cr->socket, iov_entry);
        }
        mk_iov_send(cr->socket, iov_footer);

        close(cr->socket);
        closedir(dir);
	return -1;
}



/* Send information of current directory on HTML format
   Modified : 2007/01/21
   -> Add struct client_request support

   Modified : 2002/10/22 
   -> Chunked Transfer Encoding support added to HTTP/1.1

  FIXME: REWRITE THIS SECTION >:)
*/

