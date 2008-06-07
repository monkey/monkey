/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2007, Eduardo Silva P.
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

#define  DIRECTORIO		  "     -"

/* Longitud de la cadena */
#define  MAX_LEN_STR		 30

/* Longitud de la fecha y hora */
#define  MAX_TIME			 17

/* Longitud del tama�o */
#define  MAX_SIZE			  6

/* Incremento */
#define  GROW				  100

#define  SPACE				 ' '
#define  ZERO				  '\0'

/* Estructura de lista de archivos y directorios */
struct f_list {
	char	  path[MAX_PATH+1];			/* Ruta de acceso               */
	char	  size[MAX_SIZE+1];			/* Tama�o del archivo           */
	char	  ft_modif[MAX_TIME+1];	  /* Fecha y hora de modificacion */
};

/* Ordenar cadenas de caracteres por el metodo SHELL */
/* C�digo tomado del libro de Kernighan y Ritchie    */
struct f_list *shell (struct f_list *b, int n)
{
	int				gap, i, j;
	struct f_list  temp;

	for (gap = n/2; gap > 0; gap /= 2)
		for (i = gap; i <= n; i ++)
			for (j = i-gap;
					j >= 0 && ((strcmp(b[j].path, b[j+gap].path))>0);
					j -= gap)
			{
				temp			  = b[j];
				b[j]			  = b[j+gap];
				b[j+gap]		 = temp;
			}

	return (struct f_list *)b;
}

/* Si encuentra un ' ' en la cadena lo reemplaza por su valor 
   en hexadecimal (%20). Autor: Eduardo Silva */
char *check_string(char *str)
{
	int cnt=0;
	char *s, *f;
	char *final_buffer=0;

	if (str==NULL)
		return str;

	for(s=str;*s!='\0';++s)
		if(*s==' ') cnt++;

	if(cnt==0)
		return M_strdup(str);

	final_buffer=M_malloc(strlen(str)+1+(cnt*3));

	for(f=final_buffer,s=str;*s!='\0';++s) {
		if (*s==' ') {
			*f++='%'; *f++='2'; *f++='0';
		} else {
			*f++=*s;
		}
	}

	*f='\0';
	return final_buffer;
}

/* Recortar la cadena si excede el ancho de MAX_LEN_STR */
char *cut_string(char *str)
{
	int i, k, j, len;
	char *s;

	if ((len = strlen(str)) > MAX_LEN_STR) {
		s=M_malloc(MAX_LEN_STR);
		k = MAX_LEN_STR/2 - 2;
		for (i=0; i<k; i++)
			s[i] = str[i];

		s[i++] = '.';
		s[i++] = '.';
		s[i++] = '.';
		j		= i;
		k		= len - k;

		for (i=k; str[i]; i++, j++)
			s[j] = str[i];

		s[j] = ZERO;
		return (char *) s;
	}

	return M_strdup(str);
}

/* Agregar un elemento del directorio */
struct f_list *add_element(struct f_list *object, char *string,
                              int *count, int *max, struct stat *buffer)
{
	off_t	tam = 0;
	char	tipo;
	struct f_list  *bak;

	if ((tam = strlen(string)) >= MAX_PATH-5)
		return (struct f_list *) object;

	(*count) ++;
	/* Un elemento maxs ... */
	/* Si object->count = 0 es */
	/* el primer elemento      */

	if ((*count) != 0){              /* Aumentar el tama�o del array */
		if ((*count) >= (*max)) {
			bak = (struct f_list *) M_realloc(object, (GROW+(*max)) * sizeof(struct f_list));
	
			(*max)+= GROW;
			object = bak;
		}
	}
	
	/* Guardar la fecha y hora del elemento */
	strftime(object[*count].ft_modif, 255, "%d-%b-%G %H:%M", 
		(struct tm *)localtime((time_t *) &buffer->st_mtime));
	

	/* Es directorio o archivo ?? */
	if (S_ISDIR(buffer->st_mode)) {
		strncpy(object[*count].size, DIRECTORIO, MAX_SIZE);

		/* Colocar el slash de terminacion */
		string[tam++] = '/';
		string[tam]	= ZERO;
	} else {
		tam = buffer->st_size;

		if (tam < 9999) {
			tipo = 'b';
		} else
			if((tam /= 1024) < 9999) {
				tipo = 'K';
			} else
				if((tam /= 1024) < 9999) {
					tipo = 'M';
				} else
					tipo = 'G';

		sprintf(object[*count].size, "%5lu%c", (unsigned long )tam, tipo);
	}

	/* Guardar el nombre del directorio o archivo para ingresar */
	strncpy(object[*count].path, string, MAX_PATH);
	object[*count].path[MAX_PATH] = ZERO;

	return (struct f_list *) object;
}

char *read_header_footer_file(char *file_path)
{
	FILE *file;
	int bytes;
	char *file_content=0;
	static char buffer[BUFFER_SOCKET];
	struct stat f;

	stat(file_path, &f);	
	file = fopen(file_path, "r");
	if(!file)
	{	
		return NULL;
	}	
	
	memset(buffer, '\0', sizeof(buffer));
	while((bytes=fread(buffer,1, BUFFER_SOCKET, file)>0)){
		file_content = m_build_buffer_from_buffer(file_content,"%s", buffer);
		memset(buffer, '\0', sizeof(buffer));
	}
	fclose(file);
		
	return (char *) file_content;
}
 
/* Send information of current directory on HTML format
   Modified : 2007/01/21
   -> Add struct client_request support

   Modified : 2002/10/22 
   -> Chunked Transfer Encoding support added to HTTP/1.1
*/
int GetDir(struct client_request *cr, struct request *sr)
{
	DIR *dir;
	struct dirent *ent;
	char *path=0, *real_header_file, *real_footer_file, *content_buffer=0;
	struct stat *buffer;
	struct f_list *file_list;
	struct header_values *hd;
	
	int i,
 		count_file=-1,	  /* Cantidad de elementos        */
	     max_file=0,		  /* Cantidad tope usada por GROW */
		 transfer_type; /* Tipo de transferencia de datos */
		 
	if ((dir = opendir(sr->real_path)) == NULL)
		return -1;

	if ((file_list = (struct f_list *) M_malloc(sizeof(struct f_list))) == NULL)
	{
		closedir(dir);
		return -1;
	}

	if ((buffer = (struct stat *) M_malloc(sizeof(struct stat))) == NULL)
	{
		M_free(file_list);
		closedir(dir);
		return -1;
	}

	/* Leer los archivos y directorios */
	while ((ent = readdir(dir)) != NULL) {
		if (strcmp((char *) ent->d_name, "." )  == 0) continue;
		if (strcmp((char *) ent->d_name, ".." ) == 0) continue;

		if(strcmp(ent->d_name, sr->host_conf->header_file)==0 || strcmp(ent->d_name, sr->host_conf->footer_file)==0){
			continue;	
		}
		
		path = m_build_buffer("%s%s", sr->real_path, ent->d_name);
		
		if (stat(path, buffer) == -1) continue;

		if(!buffer || !ent->d_name || !file_list){
			puts("error en buffer");	
		}
		
		file_list = (struct f_list *) add_element(file_list, ent->d_name, &count_file, &max_file,
                                                      buffer);
		if (!file_list) {
			M_free(path);
			M_free(buffer);
			closedir(dir);
			return -1;
		}
		M_free(path);
 	}

	/* Ordenar el arreglo de archivos y directorios */
	shell(file_list, count_file);

    hd = M_malloc(sizeof(struct header_values));
	hd->status = M_HTTP_OK;
	hd->content_length = 0;
	hd->content_type = m_build_buffer("text/html");
	hd->location = NULL;
	hd->cgi = SH_CGI;
	hd->pconnections_left = config->max_keep_alive_request - cr->counter_connections;

    sr->headers = hd;

	if(sr->protocol==HTTP_PROTOCOL_11){
		transfer_type=CHUNKED;
		M_METHOD_send_headers(cr->socket, sr, sr->log);
		fdprintf(cr->socket, NO_CHUNKED, "Transfer-Encoding: Chunked\r\n\r\n");
	}
	else{
		transfer_type=NO_CHUNKED;
		M_METHOD_send_headers(cr->socket, sr, sr->log);
		fdprintf(cr->socket, transfer_type, "\r\n");
	}


	content_buffer = m_build_buffer_from_buffer(content_buffer, 
		"<HTML>\n<HEAD><TITLE>Index of %s</TITLE></HEAD>\n <BODY> \
				 <H1>Index of %s</H1>", sr->uri_processed, sr->uri_processed);
				 
				 
	real_header_file = m_build_buffer("%s%s", sr->real_path, sr->host_conf->header_file);

	if(real_header_file){
		char *header_file_buffer=0;
		
		header_file_buffer = read_header_footer_file(real_header_file);
		if(header_file_buffer){
			content_buffer = m_build_buffer_from_buffer(content_buffer, "%s", header_file_buffer);
		}
		M_free(header_file_buffer);
	}
	
	content_buffer = m_build_buffer_from_buffer(content_buffer,
		"<BR> <PRE>    Modified        Size     Name\n<HR> \
			 \n\t\t\t -   <A HREF=\"../\">Parent Directory</A>\n");
	

	for (i=0; i<=count_file; i++)
	{
		char* c_str = check_string(file_list[i].path);
		char* x_str = cut_string(file_list[i].path);
		
		content_buffer = m_build_buffer_from_buffer(content_buffer,
			" %s  %s   <A HREF=\"%s\">%s</A>\n",
            file_list[i].ft_modif, file_list[i].size,
            c_str, x_str);

		M_free(c_str);
		M_free(x_str);
	}


	content_buffer = m_build_buffer_from_buffer(content_buffer,"</PRE><HR>");
	real_footer_file = m_build_buffer("%s%s", sr->real_path, sr->host_conf->footer_file);

	if(real_footer_file){
		char *footer_file_buffer=0;
		
		footer_file_buffer = read_header_footer_file(real_footer_file);
		if(footer_file_buffer){
			content_buffer = m_build_buffer_from_buffer(content_buffer, "%s<HR>", footer_file_buffer);
		}
		M_free(footer_file_buffer);
	}
	
	content_buffer = m_build_buffer_from_buffer(content_buffer,"<ADDRESS>%s</ADDRESS></BODY></HTML>\r\n\r\n", sr->host_conf->host_signature);

	fdprintf(cr->socket, transfer_type, "%s", content_buffer);

	if(transfer_type==CHUNKED)
		fdprintf(cr->socket, CHUNKED, "");
		
	M_free(file_list);
	M_free(buffer);
	M_free(real_header_file);
	M_free(real_footer_file);
	M_free(content_buffer);
	closedir(dir);

	return 0;
}
