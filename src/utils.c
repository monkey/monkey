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

#include <ctype.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <sys/sendfile.h>

#define __USE_XOPEN
#include <time.h>

#include "monkey.h"

#ifndef DISABLE_SENDFILE_SYSCALL
int SendFile(struct client_request *cr, 
                char *header_range, char *pathfile, size_t size, int ranges[2])
{
    long int fd;
    int st_status=0;
    off_t offset=0;
    long int off_size=0;
    fd = open(pathfile, O_RDONLY);
    off_size = size;

    if(config->resume==VAR_ON && header_range){
        /* yyy- */
        if(ranges[0]>=0 && ranges[1]==-1){
            offset = ranges[0];
            off_size = size - offset;
            fflush(stdout);
        }

        /* yyy-xxx */
        if(ranges[0]>=0 && ranges[1]>=0){
            offset = ranges[0];
            off_size = labs(ranges[1]-ranges[0]) + 1;
        }

        /* -xxx */
        if(ranges[0]==-1 && ranges[1]>=0){
            offset = size - ranges[1];
            off_size = ranges[1];
        }
    }

    st_status = sendfile(cr->socket, fd, &offset, off_size);
    if (st_status == -1) {
        fprintf(stderr, "error from sendfile: %s\n", strerror(errno));
    }

    close(fd);
    return 0;
}
#else
/* Sending file... */
int SendFile(struct client_request *cr, 
                char *header_range, char *pathfile, size_t size, int ranges[2])
{
	long int num_bytes , offset_range=0;
	int st_status=0;
	char buffer[BUFFER_SOCKET];
	FILE *file_request;

	if((file_request=fopen(pathfile,"r"))==NULL)
		return -1;

	if(config->resume==VAR_ON){
		/* yyy- */
		if(ranges[0]>=0 && ranges[1]==-1){
			if(fseek(file_request, ranges[0], SEEK_SET)<0)
				return -1;	
		}
	
		/* yyy-xxx */
		if(ranges[0]>=0 && ranges[1]>=0){
			if(fseek(file_request, ranges[0], SEEK_SET)<0)
				return -1;
		
			offset_range = (unsigned int) (ranges[1] - ranges[0]) + 1;
		}	

		/* -xxx */
		if(ranges[0]==-1 && ranges[1]>=0){
			struct stat buf;
	
			if(stat(pathfile, &buf)==0){
				if(fseek( file_request, (buf.st_size - ranges[1] ), SEEK_SET)<0)
					return -1;	
			}
		}
	}
	
	while((num_bytes=fread(buffer,1, BUFFER_SOCKET, file_request)) > 0 ){
		if( num_bytes<offset_range || offset_range==0) {
			st_status=Socket_Timeout(cr->socket, buffer, num_bytes, config->timeout, ST_SEND);
			if(config->resume==VAR_ON && offset_range>0)
				offset_range = (unsigned int ) offset_range - num_bytes;
		}
		else {
			num_bytes = offset_range;				
			st_status=Socket_Timeout(cr->socket, buffer, num_bytes, config->timeout, ST_SEND);
			break;
		}
		if(st_status==-2){
			fclose(file_request);
			return -2;
		}
	}
	fclose(file_request);	
	return 0;	
}
#endif

/* It's an valid directory ? */
int CheckDir(char *pathfile)
{
	struct stat path;
	
	if(stat(pathfile,&path)==-1)
		return -1;
		
	if(!(path.st_mode & S_IFDIR))
		return -1;
		
	return 0;
}

/* It's a normal file ? */
int CheckFile(char *pathfile)
{
	struct stat path;
	
	if(stat(pathfile,&path)==-1)
		return -1;
		
	if(!(path.st_mode & S_IFREG))
		return -1;
		
	return 0;
}

/* Checking read access 
   Written by Carlos Oliva 
   (carlos.oliva@igloo.cl) */
int AccessFile(char *pathfile)
{
	struct stat file;

	if(stat(pathfile,&file)==-1)
		return -1;

	if( (file.st_mode & S_IRUSR && file.st_uid == geteuid()) || (file.st_mode & S_IRGRP && file.st_gid == getegid()) || (file.st_mode & S_IROTH))
		return 0;

	return -1; /* I can't read it */
}

/* Permisos de ejecucion */
int ExecFile(char *pathfile)
{
	struct stat file;

	if(stat(pathfile,&file)==-1)
		return -1;

	if( (file.st_mode & S_IXUSR && file.st_uid == geteuid()) || (file.st_mode & S_IXGRP && file.st_gid == getegid()) || (file.st_mode & S_IXOTH))
		return 0;

	return -1; /* No se puede leer */
}

/* Compara 2 strings sin importar 
 Mayusculas ni minusculas */
char *strstr2(char *s, char *t)
{
	static char res[MAX_REQUEST_BODY];
	int i, j, k;
				
	for (i=0; s[i] ; i++) {
		for (j=i, k=0; t[k] && toupper(s[j]) == toupper(t[k]); j++, k++) ;
			if (k > 0 && t[k] == '\0') {
			  for (j=i, k=0; s[j]; j++, k++)
				res[k] = s[j];
			
			  res[k] = s[j];
			  return (char *) res;
			}
		}
	
	return NULL;
}

/* Devuelve la fecha para enviarla 
 en el header */
char *PutDate_string(time_t date) {

	static char date_gmt[255];
	struct tm *gmt_tm;
	
	if(date==0){
		if ( (date = time(NULL)) == -1 ){
			return 0;
		}
	}

	gmt_tm	= (struct tm *) gmtime(&date);
	
	strftime(date_gmt,255,  DATEFORMAT, gmt_tm);
		
	return (char *) date_gmt;
}

time_t PutDate_unix(char *date)
{
	time_t new_unix_time;
	struct tm t_data;
	
//	t_data = M_malloc(sizeof(struct tm));

	if(!strptime(date, DATEFORMAT, (struct tm *) &t_data)){
		return -1;
	}

	new_unix_time = mktime((struct tm *) &t_data);

	return (new_unix_time);
}

/*  Envia buffer de parametros pasados por *format
 a traves del descriptor fd. 
 Funcion escrita por Waldo (fatwaldo@yahoo.com) 
*/
int fdprintf(int fd, int type, const char *format, ...)
{
	va_list	ap;
	int length, status;
	char *buffer = 0;
	static size_t alloc = 0;
	
	if(!buffer) {
		buffer = (char *)M_malloc(256);
		if(!buffer)
			return -1;
		alloc = 256;
	}

	va_start(ap, format);
	length = vsnprintf(buffer, alloc, format, ap);
	if(length >= alloc) {
		char *ptr;
		
		/* glibc 2.x, x > 0 */
		ptr = M_realloc(buffer, length + 1);
		if(!ptr) {
			va_end(ap);
			return -1;
		}
		buffer = ptr;
		alloc = length + 1;
		length = vsnprintf(buffer, alloc, format, ap);
	}
	va_end(ap);

	if(length<0){
		return -1;
	}
		
	if(type==CHUNKED)
		status = fdchunked(fd, buffer, length);
	else
		status = Socket_Timeout(fd, buffer, length, config->timeout, ST_SEND);

	M_free(buffer);
	return status;
}

/* Envia datos a traves de un socket con 
transferencia de tipo 'chunked' */
int fdchunked(int fd, char *data, int length)
{
	int lenhexlen, st_status;
	char hexlength[10];
	char *buffer=0;
	
	snprintf(hexlength, 10, "%x\r\n", length);
	lenhexlen=strlen(hexlength);

	buffer = M_malloc(lenhexlen + length + 3);
	memset(buffer,'\0', sizeof(buffer));	

	memcpy(buffer, hexlength, lenhexlen);
	memcpy(buffer+lenhexlen, data, length);
	if((st_status=Socket_Timeout(fd, buffer, lenhexlen+length, config->timeout, ST_SEND))<0){
		M_free(buffer);
		return st_status;	
	}
	if((st_status=Socket_Timeout(fd, "\r\n", 2, 1, ST_SEND))<0){
		M_free(buffer);
		return st_status;		
	}	

	M_free(buffer);
	return 0;
}

char *m_build_buffer(const char *format, ...)
{
	va_list	ap;
	int length;
	char *buffer = NULL;
	static size_t alloc = 0;
	
	if(!buffer) {
		buffer = (char *)M_malloc(256);
		if(!buffer)
			return NULL;
		alloc = 256;
	}

	va_start(ap, format);
	length = vsnprintf(buffer, alloc, format, ap);

    if(length >= alloc) {
		char *ptr;
		
		/* glibc 2.x, x > 0 */
		ptr = M_realloc(buffer, length + 1);
		if(!ptr) {
			va_end(ap);
			return NULL;
		}
		buffer = ptr;
		alloc = length + 1;
		length = vsnprintf(buffer, alloc, format, ap);
	}
	va_end(ap);

	if(length<0){
		return NULL;
	}
	buffer[length]='\0';
	return (char * ) buffer;
}

char *m_build_buffer_from_buffer(char *buffer, const char *format, ...)
{
	va_list	ap;
	int length;
	char *new_buffer=0;
	char *buffer_content=0;
	static size_t alloc = 0;
	
	new_buffer = (char *)M_malloc(256);
	if(!new_buffer){
		return NULL;
	}
	alloc = 256;

	if(buffer){
		buffer_content = M_strdup(buffer);		
		M_free(buffer);
	}

	va_start(ap, format);
	length = vsnprintf(new_buffer, alloc, format, ap);

    if(length >= alloc) {
		char *ptr;
		
		/* glibc 2.x, x > 0 */
		ptr = M_realloc(new_buffer, length + 1);
		if(!ptr) {
			va_end(ap);
			return NULL;
		}
		new_buffer = ptr;
		alloc = length + 1;
		length = vsnprintf(new_buffer, alloc, format, ap);
	}
	va_end(ap);

	if(length<0){
		return NULL;
	}
	new_buffer[length]='\0';

	if(buffer_content){
		buffer = m_build_buffer("%s%s", buffer_content, new_buffer);
        buffer = strdup(strcat(buffer_content, new_buffer));
		//M_free(buffer_content);
		//M_free(new_buffer);
	}else{
		buffer = new_buffer;
	}
	return (char * ) buffer;
}

/* Return a buffer with a new string from string */
char *m_copy_string(const char *string, int pos_init, int pos_end)
{
	unsigned int size, bytes;
	char *buffer=0;
	
	size = (unsigned int) (pos_end - pos_init ) + 1;
	if(size<=2) size=4;

	buffer = M_malloc(size);
	
	if(!buffer){
		return NULL;
	}
	
	if(pos_end>strlen(string) || (pos_init > pos_end)){
		return NULL;
	}
	
	bytes =  pos_end - pos_init;
	strncpy(buffer, string+pos_init, bytes);
	buffer[bytes]='\0';

	return (char *) buffer;	
}

/* Rutina para pasar Monkey a daemon */
int set_daemon()
{
	 switch (fork())
  	  {
		case 0 : break;
		case -1: exit(1); break;	/* Error */
		default: exit(0);			/* Exito */
	  };

	  setsid();			/* Crear una nueva sesion */
	  fclose(stdin);		/* Cerrar las salidas en pantallas */
	  fclose(stderr);
	  fclose(stdout);

	return 0;
}

/* Retorna la posicion de search en string */
int str_search(char *string, char *search, int length_cmp)
{
	long int length;
	long i;
	
	if(!string || !search)
		return -1;
		
	length = strlen(string);
	for(i=0; string[i]!='\0'  &&  i<length; i++){
		if(string[i]==search[0]){
			if(strncasecmp(string+i, search, length_cmp)==0)
				return i;
		}
	}

	return -1;
}

int get_version_protocol(char *remote_protocol)
{
	if(strcmp(remote_protocol,"HTTP/1.1")==0)
		return HTTP_11;

	if(strcmp(remote_protocol,"HTTP/1.0")==0)
		return HTTP_10;

	return -1;
}

char *get_name_protocol(int remote_protocol)
{
	switch(remote_protocol){
		case HTTP_11:
				return (char *) "HTTP/1.1";
				
		case HTTP_10:
				return (char *) "HTTP/1.0";
	}
	return (char *) "";
}

char *get_real_string(char *req_uri){
	
	int length=0, hex_result;
	int new_i=0, i=0;
	char *buffer=0, hex[3];

	length=strlen(req_uri);

	buffer=M_malloc(length + 3);

	do {
		if(req_uri[i]=='%' && i+2<=length){
			memset(hex,'\0', sizeof(hex));
			strncpy(hex, req_uri+i+1, 2);
			hex[2]='\0';

			if((hex_result=hex2int(hex))<=127){
				buffer[new_i]=toascii(hex_result);
				i=i+3;
				new_i++;
			}
			else {
				int auxchar;
				if((auxchar=get_char(hex_result))!=-1){
					buffer[new_i]=get_char(hex_result);
					i=i+3;
					new_i++;			
				}
				else{
					M_free(buffer);
					return NULL;
				}
			}
			buffer[new_i+1]='\0';
			continue;
		}
		else {
			buffer[new_i] = req_uri[i];
		}
		i++;
		new_i++;
		buffer[new_i]='\0';
	}while(i<length);

	return (char *) buffer;
}

void *M_malloc(size_t size)
{
	char *aux=0;

	size++;
	if((aux=malloc(size))==NULL){
		perror("malloc");
		pthread_kill(pthread_self(), SIGPIPE);
		return NULL;						
	}
	memset(aux, '\0', size);
	return (void *) aux;
}

char *M_strdup(const char *s)
{
	char *aux=0;
	size_t size;
 	
	if(!s)
		return NULL;
	
	size = strlen(s)+1;	
	if((aux=malloc(size))==NULL){
		perror("strdup");
		pthread_kill(pthread_self(), SIGPIPE);
		return NULL;						
	}

	memcpy(aux, s, size);
	return (char *) aux;
} 	

void *M_realloc(void* ptr, size_t size)
{
	char *aux=0;

	if((aux=realloc(ptr, size))==NULL){
		perror("realloc");
		pthread_kill(pthread_self(), SIGPIPE);
		return NULL;						
	}
	return (void *) aux;
}

void M_free(void *ptr)
{
	if(ptr!=NULL){
		//memset(ptr, '\0', sizeof(*ptr));
		free(ptr);
		ptr=NULL;
	}
}

// Return 0 if path it's an symbolic link
int Check_symlink(const char *path)
{
	struct stat st;	

	if(lstat(path, &st)==-1){
			return SYML_ERR_NOTFOUND;
	}

	if((S_ISLNK(st.st_mode))){
		return SYML_OK;	
	}

	return SYML_NOT;	
}

char *get_end_position(char *buf)
{
    char *sl=0, *dsl=0;

    sl = strstr(buf, "\r\n\r\n");
    dsl = strstr(buf, "\n\n");

    if(sl)
    {
        return sl;
    }
    else if(dsl)
    {
        return dsl;
    }

    return NULL;
}

char *remove_space(char *buf)
{
    size_t bufsize;
    int new_i=0, i, len, spaces=0;
    char *new_buf=0;

    len = strlen(buf);
    for(i=0; i<len; i++)
    {
        if(buf[i] == ' '){
            spaces++;
        }
    }

    bufsize = len+1-spaces;
    if(bufsize <= 1){
        return NULL;
    }

    new_buf = M_malloc(bufsize);
    memset(new_buf, '\0', bufsize);

    for(i=0; i<len; i++)
    {
        if(buf[i] != ' '){
            new_buf[new_i] = buf[i];
            new_i++;
        }
    }

    return new_buf;
}
