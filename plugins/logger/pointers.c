/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2001-2009, Eduardo Silva P.
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

#include "logger.h"
#include "pointers.h"
#include "mk_plugin.h"

void mk_logger_init_pointers()
{
    /* Writter helpers */
    mk_api->pointer_set(&mk_logger_iov_dash, MK_LOGGER_IOV_DASH);
    mk_api->pointer_set(&mk_logger_iov_space, MK_IOV_SPACE);
    mk_api->pointer_set(&mk_logger_iov_lf, MK_IOV_LF);
    mk_api->pointer_set(&mk_logger_iov_empty, MK_LOGGER_IOV_EMPTY);

    /* Error messages */
    mk_api->pointer_set(&error_msg_400, ERROR_MSG_400);
    mk_api->pointer_set(&error_msg_403, ERROR_MSG_403);
    mk_api->pointer_set(&error_msg_404, ERROR_MSG_404);
    mk_api->pointer_set(&error_msg_405, ERROR_MSG_405);
    mk_api->pointer_set(&error_msg_408, ERROR_MSG_408);
    mk_api->pointer_set(&error_msg_411, ERROR_MSG_411);
    mk_api->pointer_set(&error_msg_413, ERROR_MSG_413);
    mk_api->pointer_set(&error_msg_500, ERROR_MSG_500);
    mk_api->pointer_set(&error_msg_501, ERROR_MSG_501);
    mk_api->pointer_set(&error_msg_505, ERROR_MSG_505);

    /* None */
    mk_api->pointer_set(&mk_iov_none, "");
}
