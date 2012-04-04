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
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#ifndef MK_WEBSOCKETS_H
#define MK_WEBSOCKETS_H

/* GUID is defined by websockets v10 */
#define WS_GUID                    "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

#define WS_PATH                    "/websockets"
#define WS_CONN_UPGRADE            "Upgrade"
#define WS_UPGRADE_WS              "websocket"

/* Request headers */
#define WS_HEADER_UPGRADE          "Upgrade:"
#define WS_HEADER_SEC_WS_ORIGIN    "Sec-WebSocket-Origin:"
#define WS_HEADER_SEC_WS_KEY       "Sec-WebSocket-Key:"
#define WS_HEADER_SEC_WS_VERSION   "Sec-WebSocket-Version:"
#define WS_HEADER_SEC_WS_PROTOCOL  "Sec-WebSocket-Protocol:"

/* Response headers */
#define WS_RESP_SWITCHING          "HTTP/1.1 101 Switching Protocols\r\n"
#define WS_RESP_UPGRADE            "Upgrade: websocket"
#define WS_RESP_CONNECTION         "Connection: Upgrade"
#define WS_RESP_WS_ACCEPT          "Sec-WebSocket-Accept: "

/* Frame Opcode */
#define WS_FRAME_CONTINUE   0x00
#define WS_FRAME_TEXT       0x01
#define WS_FRAME_BINARY     0x02

#define WS_FRAME_CTL_CLOSE  0x08
#define WS_FRAME_CTL_PING   0x09
#define WS_FRAME_CTL_PONG   0x0a

/* Framing macros */
#define WS_FRAME_MASK_LEN       4

#define CHECK_BIT(var, pos) !!((var) & (1 << (pos)))

/* SHA1 stuff */
#define SHA1_DIGEST_LEN            20


int ws_send_data(int sockfd,
                unsigned int fin,
                unsigned int rsv1,
                unsigned int rsv2,
                unsigned int rsv3,
                unsigned int opcode,
                unsigned int frame_mask,
                uint64_t payload_len,
                unsigned char *frame_masking_key,
                unsigned char *payload_data);

#endif
