/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2012, Eduardo Silva P.
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

#include "MKPlugin.h"
#include "duda_utime.h"

struct duda_api_utime *duda_utime_object() {
    struct duda_api_utime *t;

    t = mk_api->mem_alloc(sizeof(struct duda_api_utime));
    t->now = duda_utime_now;
    t->tomorrow = duda_utime_tomorrow;
    t->next_hours = duda_utime_next_hours;

    return t;
}

/* Return the current time in unix time format */
time_t duda_utime_now()
{
    return mk_api->time_unix();
}

/* Return the unix time for the next 24 hours */
time_t duda_utime_tomorrow()
{
    return (mk_api->time_unix() + TIME_DAY);
}

/* Return the unix time in the next 'h' hours */
time_t duda_utime_next_hours(int h)
{
    return (mk_api->time_unix() + (h * TIME_HOUR));
}
