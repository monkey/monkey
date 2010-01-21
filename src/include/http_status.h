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

/* http status - jci@tux.cl */


/* Informational status */

#define M_INFO_CONTINUE	100
#define M_INFO_SWITCH_PROTOCOL	101

/* Succesful */

#define M_HTTP_OK				200
#define M_HTTP_CREATED				201
#define M_HTTP_ACCEPTED				202
#define M_HTTP_NON_AUTH_INFO			203
#define M_HTTP_NOCONTENT			204
#define M_HTTP_RESET				205
#define M_HTTP_PARTIAL				206

/* Redirections */

#define M_REDIR_MULTIPLE			300
#define M_REDIR_MOVED				301
#define M_REDIR_MOVED_T				302
#define	M_REDIR_SEE_OTHER			303
#define M_NOT_MODIFIED			        304
#define M_REDIR_USE_PROXY			305

/* Client Errors */

#define M_CLIENT_BAD_REQUEST			400
#define M_CLIENT_UNAUTH				401
#define M_CLIENT_PAYMENT_NEEDED			402     /* Wtf?! :-) */
#define M_CLIENT_FORBIDDEN			403
#define M_CLIENT_NOT_FOUND			404
#define M_CLIENT_METHOD_NOT_ALLOWED		405
#define M_CLIENT_NOT_ACCEPTABLE			406
#define M_CLIENT_PROXY_AUTH			407
#define M_CLIENT_REQUEST_TIMEOUT		408
#define M_CLIENT_CONFLICT			409
#define M_CLIENT_GONE				410
#define M_CLIENT_LENGTH_REQUIRED		411
#define M_CLIENT_PRECOND_FAILED			412
#define M_CLIENT_REQUEST_ENTITY_TOO_LARGE	413
#define M_CLIENT_REQUEST_URI_TOO_LARGE		414
#define M_CLIENT_UNSUPPORTED_MEDIA		415

/* Server Errors */

#define M_SERVER_INTERNAL_ERROR			500
#define M_SERVER_NOT_IMPLEMENTED		501
#define M_SERVER_BAD_GATEWAY			502
#define M_SERVER_SERVICE_UNAV			503
#define M_SERVER_GATEWAY_TIMEOUT		504
#define M_SERVER_HTTP_VERSION_UNSUP		505

/* Text header messages */
#define M_HTTP_OK_TXT				"HTTP/1.1 200 OK\r\n"

mk_list_sint_t *mk_http_status_list;
