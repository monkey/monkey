/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2015 Monkey Software LLC <eduardo@monkey.io>
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifndef MK_HTTP2_H
#define MK_HTTP2_H

#include <stdint.h>

/*
 * HTTP2 Error codes
 * -----------------
 */

/* The associated condition is not a result of an error */
#define MK_HTTP2_NO_ERROR            0x0
/* The endpoint detected an unspecific protocol error */
#define MK_HTTP2_PROTOCOL_ERROR      0x1
/* The endpoint encountered an unexpected internal error */
#define MK_HTTP2_INTERNAL_ERROR      0x2
/* The endpoint detected that its peer violated the flow-control protocol */
#define MK_HTTP2_FLOW_CONTROL_ERROR  0x3
/* The endpoint sent a SETTINGS frame but did not receive a response */
#define MK_HTTP2_SETTINGS_TIMEOUT    0x4
/* The endpoint received a frame after a stream was half-closed */
#define MK_HTTP2_STREAM_CLOSED       0x5
/* The endpoint received a frame with an invalid size */
#define MK_HTTP2_FRAME_SIZE_ERROR    0x6
/* The endpoint refused the stream prior to performing any application processing */
#define MK_HTTP2_REFUSED_STREAM      0x7
/* Used by the endpoint to indicate that the stream is no longer needed */
#define MK_HTTP2_CANCEL              0x8
/* The endpoint is unable to maintain the header compression context for the connection */
#define MK_HTTP2_COMPRESSION_ERROR   0x9
/* The connection established in response to a CONNECT request was reset */
#define MK_HTTP2_CONNECT_ERROR       0xa
/* The endpoint detected that its peer is exhibiting a behavior that might be generating excessive load */
#define MK_HTTP2_ENHANCE_YOUR_CALM   0xb
/* The underlying transport has properties that do not meet minimum security requirements (see Section 9.2) */
#define MK_HTTP2_INADEQUATE_SECURITY 0xc
/* The endpoint requires that HTTP/1.1 be used instead of HTTP/2 */
#define MK_HTTP2_HTTP_1_1_REQUIRED   0xd

/*
 * 4.1 HTTP2 Frame format
 *
 * +-----------------------------------------------+
 * |                 Length (24)                   |
 * +---------------+---------------+---------------+
 * |   Type (8)    |   Flags (8)   |
 * +-+-------------+---------------+-------------------------------+
 * |R|                 Stream Identifier (31)                      |
 * +=+=============================================================+
 * |                   Frame Payload (0...)                      ...
 * +---------------------------------------------------------------+
 *
 */

/* Structure to represent a readed frame (not to write) */
struct mk_http2_frame {
  uint32_t  len_type;  /* (24 length + 8 type) */
  uint8_t   flags;
  uint32_t  stream_id;
  void      *payload;
};

#endif
