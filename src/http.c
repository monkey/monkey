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

#include <stdio.h>
#include <string.h>

#include "monkey.h"
#include "http.h"

int mk_http_method_check(char *method)
{
	if(*method==*HTTP_METHOD_GET_STR)
	{
		return HTTP_METHOD_GET;
	}

	if(*method==*HTTP_METHOD_POST_STR)
	{
		return HTTP_METHOD_POST;
	}

	if(*method==*HTTP_METHOD_HEAD_STR)
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

int mk_http_method_get(char *body)
{
	int int_method, pos = 0, max_length_method = 5;
	char *str_method;
	
	pos = str_search(body, " ",1);
	if(pos<=2 || pos>=max_length_method){
		return -1;	
	}
	
	str_method = M_malloc(max_length_method);
	strncpy(str_method, body, pos);
	str_method[pos]='\0';

	int_method = mk_http_method_check(str_method);
	M_free(str_method);
	
	return int_method;
}

int mk_http_protocol_check(char *protocol)
{
	if(*protocol==*HTTP_PROTOCOL_11_STR)
	{
		return HTTP_PROTOCOL_11;
	}
	if(*protocol==*HTTP_PROTOCOL_10_STR)
	{
		return HTTP_PROTOCOL_10;
	}
	if(*protocol==*HTTP_PROTOCOL_09_STR)
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

