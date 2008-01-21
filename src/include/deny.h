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

/* deny.c */

/* Estructura para denegacion de IP & URL */
#define MAX_DENY_VALUE 255

#define DENY_CONF_FILENAME "monkey.deny"
#define DENY_IP 0
#define DENY_URL 1
#define DENY_CONF_IP "IP"
#define DENY_CONF_URL "URL"

struct deny{
	short int type;
	char value[MAX_DENY_VALUE];
	struct deny *next;
} *first_deny;

void	Deny_Read_Config();
void	Deny_Add(const short int type, char *value);
int     Deny_Check(char *uri);
