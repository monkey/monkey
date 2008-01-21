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

/* method.c */

#define GET_METHOD_STR "GET"
#define POST_METHOD_STR "POST"
#define HEAD_METHOD_STR "HEAD"

int 	M_METHOD_Get_and_Head(struct client_request *cr, struct request *s_request, int socket); /* Process get and head methods*/
int M_METHOD_Post(struct client_request *cr, 
                                struct request *s_request, char *request_body);
int	 M_METHOD_send_headers(int fd, struct header_values *sh, struct log_info *s_log); /* Send basic headers */
int	 M_METHOD_get_range(char *header, int range_from_to[2]); /* Process and get range request */
int	 M_METHOD_get_number(char *method); /* Return value assigned to Method called */
char *M_METHOD_get_name(int method); /* Return name of Method */

