/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2008, Eduardo Silva P.
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

char *mk_string_copy_substr(const char *string, int pos_init, int pos_end);

int _mk_string_search(char *string, char *search, int n);
int mk_string_search(char *string, char *search);
int mk_string_search_n(char *string, char *search, int n);

char *mk_string_remove_space(char *buf);
char *mk_string_casestr(char *heystack, char *needle);
char *mk_string_dup(const char *s);
int mk_string_array_count(char *arr[]);

