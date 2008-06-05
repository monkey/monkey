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

/* Methods */
#define GET_METHOD (0)
#define POST_METHOD (1)
#define HEAD_METHOD (2)

#define GET_METHOD_STR "GET"
#define POST_METHOD_STR "POST"
#define HEAD_METHOD_STR "HEAD"

/* Method status */
#define METHOD_NOT_ALLOWED (-1)
#define METHOD_NOT_FOUND (-2)
#define METHOD_EMPTY (-3)


