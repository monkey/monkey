/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2012, Eduardo Silva P. <edsiper@gmail.com>
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
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#ifndef MK_CONNECTION_H
#define MK_CONNECTION_H

#define MK_CONN_SWITCH_READ 0
#define MK_CONN_SWITCH_WRITE 1

int mk_conn_switch(int action, int socket);
int mk_conn_switch_error(int socket);

int mk_conn_read(int socket);
int mk_conn_write(int socket);
int mk_conn_error(int socket);
int mk_conn_close(int socket);
int mk_conn_timeout(int socket);

#endif
