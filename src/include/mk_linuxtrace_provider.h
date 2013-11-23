/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2013, Eduardo Silva P. <edsiper@gmail.com>
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

#undef  TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER mk_linuxtrace

#if !defined(_MK_LINUXTRACE_PROVIDER_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _MK_LINUXTRACE_PROVIDER_H
#include <lttng/tracepoint.h>

TRACEPOINT_EVENT(
                 mk_linuxtrace,
                 message,
                 TP_ARGS(char *, text),
                 TP_FIELDS(ctf_string(message, text))
                 )

TRACEPOINT_LOGLEVEL(
                    mk_linuxtrace,
                    message,
                    TRACE_WARNING)
#endif

#undef  TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "./mk_linuxtrace_provider.h"

#include <lttng/tracepoint-event.h>
