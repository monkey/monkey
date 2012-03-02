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

#ifndef DUDA_EVENT_H
#define DUDA_EVENT_H

#include "duda.h"

#define DUDA_EVENT_BODYFLUSH    1
#define DUDA_EVENT_SENDFILE     2

int duda_event_register_write(duda_request_t *dr);
int duda_event_unregister_write(duda_request_t *dr);
int duda_event_is_registered_write(duda_request_t *dr);
int duda_event_write_callback(int sockfd);
int __body_flush(duda_request_t *dr);
#endif
