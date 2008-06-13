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

#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>

#include <ctype.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <unistd.h>
#include <signal.h>
#include <sys/sendfile.h>

#include <time.h>

#include "monkey.h"

int SendFile(int socket, struct request *sr)
{
	long int nbytes=0;

	nbytes = sendfile(socket, sr->fd_file, &sr->bytes_offset,
			sr->bytes_to_send);

	if (nbytes == -1) {
		fprintf(stderr, "error from sendfile: %s\n", strerror(errno));
		return -1;
	}
	else
	{
		sr->bytes_to_send-=nbytes;
	}
	return sr->bytes_to_send;
}

/* It's a valid directory ? */
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

/* Devuelve la fecha para enviarla 
 en el header */
char *PutDate_string(time_t date) {

	char *date_gmt;
	struct tm *gmt_tm;
	
	if(date==0){
		if ( (date = time(NULL)) == -1 ){
			return 0;
		}
	}

	gmt_tm	= (struct tm *) gmtime(&date);
	date_gmt = M_malloc(250);

	strftime(date_gmt,250,  DATEFORMAT, gmt_tm);
	return (char *) date_gmt;
}

time_t PutDate_unix(char *date)
{
	time_t new_unix_time;
	struct tm t_data;
	
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
		buffer = (char *)malloc(256);
		if(!buffer)
			return NULL;
		alloc = 256;
	}

	va_start(ap, format);
	length = vsnprintf(buffer, alloc, format, ap);

	if(length >= alloc) {
		char *ptr;
		
		ptr = realloc(buffer, length + 1);
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
		printf("\nret NULL: 1");
		fflush(stdout);
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
		M_free(buffer_content);
		M_free(new_buffer);
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

	buffer = malloc(size);
	
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

	//size++;
	if((aux=malloc(size))==NULL){
		perror("malloc");
		//pthread_kill(pthread_self(), SIGPIPE);
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
		printf("\n** Monkey ERROR");
		perror("realloc");
		pthread_kill(pthread_self(), SIGPIPE);
		return NULL;						
	}
	return (void *) aux;
}

void M_free(void *ptr)
{
	if(ptr!=NULL){
		free(ptr);
	}
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

    for(i=0; i<len; i++)
    {
        if(buf[i] != ' '){
            new_buf[new_i] = buf[i];
            new_i++;
        }
    }

    return new_buf;
}

char *mk_strcasestr(char *heystack, char *needle)
{
	if(!heystack || !needle)
	{
		return NULL;
	}

	return strcasestr(heystack, needle);
}

