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

int M_METHOD_Get_and_Head(struct client_request *cr, 
		struct request *s_request, int socket); 

int M_METHOD_Post(struct client_request *cr, struct request *sr);
int M_METHOD_send_headers(int fd, struct client_request *cr,
		struct request *sr, struct log_info *s_log);

/* Get request range */
int M_METHOD_get_range(char *header, int range_from_to[2]);

/* Return value assigned to Method called */
int M_METHOD_get_number(char *method); 

/* Return method name */
char *M_METHOD_get_name(int method);
mk_pointer mk_method_post_get_vars(char *body, int index);
char *M_Get_POST_Vars(char *request, int index, char *strend);


