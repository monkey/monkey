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

#ifndef DUDA_TIME_H
#define DUDA_TIME_H

#define TIME_HOUR   3600
#define TIME_DAY    (TIME_HOUR * 24)

struct duda_api_xtime {
    time_t (*now) ();
    time_t (*tomorrow) ();
    time_t (*next_hours) (int);
};

time_t duda_xtime_now();
time_t duda_xtime_tomorrow();
time_t duda_xtime_next_hours(int h);
struct duda_api_xtime *duda_xtime_object();

#endif
