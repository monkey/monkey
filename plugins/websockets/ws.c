/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Daemon
 *  ------------------
 *  Copyright (C) 2010-2011, Eduardo Silva P. <edsiper@gmail.com>
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

#define _GNU_SOURCE

/* Common  */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>

/* Networking - I/O*/
#include <fcntl.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

/* Plugin */
#include "MKPlugin.h"
#include "sha1.h"
#include "base64.h"
#include "request.h"
#include "ws.h"
#include "echo.h"

MONKEY_PLUGIN("websocket",          /* shortname */
              "Web Sockets",        /* name */ 
              VERSION,              /* version */
              MK_PLUGIN_STAGE_30);  /* hook for thread context call */


struct ws_subprotocol
{
    char *name;
    unsigned int id;

    int (*event_write_callback)(int, unsigned char *, uint64_t);
};

#define WS_SUBPROTOCOL_NUM 2
static struct ws_subprotocol subprotocol_list[WS_SUBPROTOCOL_NUM] = {
    {"/websockets", 0, NULL},
    {"/echo", 1, NULL},
};

int ws_handler(int socket, struct client_session *cs, struct session_request *sr,
               struct plugin *plugin, unsigned int subprotocol_id)
{
    int len;
    size_t out_len;
    char buffer[256];
    char accept_token[256];
    mk_pointer row;
    mk_pointer ws_key;
    struct mk_ws_request *wr_node;
    unsigned char digest[SHA1_DIGEST_LEN];
    unsigned char *encoded_accept = NULL;
    SHA_CTX sha; /* defined in sha1/sha1.h */

    wr_node = mk_ws_request_get(socket);

    if (!wr_node) {
        /* Validate if it's a WebSockets upgrade request */
        if (strncasecmp(sr->connection.data,
                        WS_CONN_UPGRADE, sizeof(WS_CONN_UPGRADE) - 1) != 0) {
            return MK_PLUGIN_RET_NOT_ME;
        }

        PLUGIN_TRACE("[FD %i] WebSockets Connection Upgrade", cs->socket);

        /* Get upgrade type */
        row = mk_api->header_get(&sr->headers_toc, WS_HEADER_UPGRADE,
                                 sizeof(WS_HEADER_UPGRADE) - 1);

        if (strncasecmp(row.data, WS_UPGRADE_WS, sizeof(WS_UPGRADE_WS) - 1) != 0) {
            return MK_PLUGIN_RET_NOT_ME;
        }

        PLUGIN_TRACE("[FD %i] WebSockets Upgrade to 'websocket'", cs->socket);

        /* Validate Sec-WebSocket-Key */
        ws_key = mk_api->header_get(&sr->headers_toc, WS_HEADER_SEC_WS_KEY,
                                    sizeof(WS_HEADER_SEC_WS_KEY) - 1);
        if (ws_key.data == NULL) {
            PLUGIN_TRACE("[FD %i] WebSockets missing key", cs->socket);
            return MK_PLUGIN_RET_NOT_ME;
        }
        
        mk_api->event_socket_change_mode(cs->socket, MK_EPOLL_RW, MK_EPOLL_LEVEL_TRIGGERED);

        /* Ok Baby, Handshake time! */
        strncpy(buffer, ws_key.data, ws_key.len);
        buffer[ws_key.len] = '\0';

        /* Websockets GUID */
        strncpy(buffer + ws_key.len, WS_GUID, sizeof(WS_GUID) - 1);
        buffer[ws_key.len + sizeof(WS_GUID) - 1] = '\0'; 

        /* Buffer to sha1() */
        SHA1_Init(&sha);
        SHA1_Update(&sha, buffer, strlen(buffer));
        SHA1_Final(digest, &sha); 

        /* Encode accept key with base64 */
        encoded_accept = base64_encode(digest, SHA1_DIGEST_LEN, &out_len);
        encoded_accept[out_len] = '\0';

        /* Set a custom response status */
        strncpy(buffer, WS_RESP_SWITCHING, sizeof(WS_RESP_SWITCHING) - 1);

        sr->headers.status = MK_CUSTOM_STATUS;
        sr->headers.custom_status.data = buffer;
        sr->headers.custom_status.len  = (sizeof(WS_RESP_SWITCHING) -1);

        /* Monkey core must not handle the Connection header */
        sr->headers.connection = -1;

        /* Set 'Upgrade: websocket' */
        mk_api->header_add(sr, WS_RESP_UPGRADE, sizeof(WS_RESP_UPGRADE) - 1);
        
        /* Set 'Connection: upgrade' */
        mk_api->header_add(sr, WS_RESP_CONNECTION, sizeof(WS_RESP_CONNECTION) - 1);        

        /* Compose accept token */
        len = sizeof(WS_RESP_WS_ACCEPT) - 1;
        strncpy(accept_token, WS_RESP_WS_ACCEPT, len);
        strncpy(accept_token + len, (char *) encoded_accept, out_len);
        len += out_len - 1;
        accept_token[len] = '\0';
        
        /* Add accept token to response headers */
        mk_api->header_add(sr, accept_token, len);

        mk_api->header_send(cs->socket, cs, sr);
        mk_api->socket_cork_flag(cs->socket, TCP_CORK_OFF);

        /* Free block used by base64_encode() */
        mk_api->mem_free(encoded_accept);
        
        /* Register node in main list */
        wr_node = mk_ws_request_create(socket, cs, sr, subprotocol_id);
        mk_ws_request_add(wr_node);

        /* Register socket with plugin events interface */
        mk_api->event_add(cs->socket, MK_EPOLL_RW, plugin, 
                          cs, sr, MK_EPOLL_LEVEL_TRIGGERED);
        return MK_PLUGIN_RET_CONTINUE;
    }
    else {
        return MK_PLUGIN_RET_END;
    }

    return MK_PLUGIN_RET_CONTINUE;
}

int ws_send_data(int sockfd,
                unsigned int fin,
                unsigned int rsv1,
                unsigned int rsv2,
                unsigned int rsv3,
                unsigned int opcode,
                unsigned int frame_mask,
                uint64_t payload_len,
                unsigned char *frame_masking_key,
                unsigned char *payload_data)
{
    unsigned char buf[256];
    unsigned int offset = 0;
    int n;

    memset(buf, 0, sizeof(buf));
    buf[0] |= ((fin << 7) | (rsv1 << 6) | (rsv2 << 5) | (rsv3 << 4) | opcode);

    if (payload_len < 126) {
        buf[1] |= ((frame_mask << 7) | payload_len);
        offset = 2;
    }
    else if (payload_len >= 126 && payload_len <= 0xFFFF) {
        buf[1] |= ((frame_mask << 7) | 126);
        buf[2] = payload_len >> 8;
        buf[3] = payload_len & 0x0F;
        offset = 4;
    }
    else {
        buf[1] |= ((frame_mask << 7) | 127);
        memcpy(buf + 2, &payload_len, 8);
        offset = 10;
    }

    if (frame_mask) {
        memcpy(buf + offset, frame_masking_key, WS_FRAME_MASK_LEN);
        offset += WS_FRAME_MASK_LEN;
    }

    memcpy(buf + offset, payload_data, payload_len);

    n = mk_api->socket_send(sockfd, buf, offset + payload_len);
    if (n <= 0) {
        return -1;
    }

    return n;
}

/* _MKP_EVENTs */
int _mkp_event_read(int sockfd)
{
    int i, n;
    unsigned char buf[256];
    unsigned int frame_size = 0;
    unsigned int frame_opcode = 0;
    unsigned int frame_mask = 0;
    unsigned char *frame_payload;
    unsigned char frame_masking_key[WS_FRAME_MASK_LEN];
    uint64_t payload_length = 0;
    unsigned int masking_key_offset = 0;
    struct mk_ws_request *wr;

    wr = mk_ws_request_get(sockfd);
    if (!wr){
        PLUGIN_TRACE("[FD %i] this FD is not a WebSocket Frame", sockfd);
        return MK_PLUGIN_RET_EVENT_NEXT;
    }

    /* Read incoming data from Palm socket */
    memset(buf, '\0', sizeof(buf));
    n = mk_api->socket_read(sockfd, buf, 256);
    if (n <= 0) {
        return MK_PLUGIN_RET_EVENT_CLOSE;

    }

    frame_size    = n;
    frame_opcode  = buf[0] & 0x0f;
    frame_mask    = CHECK_BIT(buf[1], 7);
    payload_length = buf[1] & 0x7f;

    if (payload_length == 126) {
        payload_length = buf[2] * 256 + buf[3];
        masking_key_offset = 4;
    }
    else if (payload_length == 127) {
        memcpy(&payload_length, buf + 2, 8);
        masking_key_offset = 10;
    }
    else {
        masking_key_offset = 2;
    }

    
#ifdef TRACE
    PLUGIN_TRACE("Frame Headers:");
    (CHECK_BIT(buf[0], 7)) ? printf("FIN  ON\n") : printf("FIN  OFF\n");
    (CHECK_BIT(buf[0], 6)) ? printf("RSV1 ON\n") : printf("RSV1 OFF\n");
    (CHECK_BIT(buf[0], 5)) ? printf("RSV2 ON\n") : printf("RSV2 OFF\n");
    (CHECK_BIT(buf[0], 4)) ? printf("RSV3 ON\n") : printf("RSV3 OFF\n");   

    printf("Op Code\t%i\n", frame_opcode);
    printf("Mask ?\t%i\n", frame_mask);
    printf("Frame Size\t%i\n", frame_size);
    printf("Payload Length\t%i\n", (unsigned int) payload_length);
    printf("Mask Key Offset\t%i\n", (unsigned int) masking_key_offset);
    fflush(stdout);
#endif

    wr->payload_len = payload_length;
    wr->payload = mk_api->mem_alloc(256);
    memset(wr->payload, '\0', sizeof(wr->payload));

    if (frame_mask) {
        memcpy(frame_masking_key, buf + masking_key_offset, WS_FRAME_MASK_LEN);

        if (payload_length != (frame_size - (masking_key_offset + WS_FRAME_MASK_LEN))) {
            //mk_err("Invalid frame size: %i", (frame_size - (mask_key_init + WS_FRAME_MASK_LEN)));
            /* FIXME: Send error, frame size does not cover the payload size */
            //return MK_PLUGIN_RET_EVENT_CLOSE;
        }

        /* Unmasking the frame payload */
        frame_payload = buf + masking_key_offset + WS_FRAME_MASK_LEN;
        for (i = 0; i < payload_length; i++) {
            wr->payload[i] = frame_payload[i] ^ frame_masking_key[i & 0x03];
        }
    }
    else {
        // There is no masking key, get to the frame payload
        frame_payload = buf + masking_key_offset;
        memcpy(wr->payload, frame_payload, payload_length);
    }

#ifdef TRACE
    if (frame_opcode == 1) printf("Data:\n\"%s\"\n", wr->data);
#endif

    return MK_PLUGIN_RET_EVENT_OWNED;
}

int _mkp_event_write(int sockfd)
{
    struct mk_ws_request *wr;

    wr = mk_ws_request_get(sockfd);
    if (!wr){
        PLUGIN_TRACE("[FD %i] this FD is not a WebSocket Frame", sockfd);
        return MK_PLUGIN_RET_EVENT_NEXT;
    }

    if (wr->payload_len == 0 || wr->payload == NULL)
        return MK_PLUGIN_RET_EVENT_OWNED;

    subprotocol_list[wr->subprotocol_id].event_write_callback(sockfd,
        wr->payload, wr->payload_len); 

    mk_api->mem_free(wr->payload);
    wr->payload_len = 0;

    return MK_PLUGIN_RET_EVENT_OWNED;
}

int _mkp_init(void **api, char *confdir)
{
    mk_api = *api;
    
    subprotocol_list[1].event_write_callback = ws_echo_write_callback;

    return 0;
}

void _mkp_exit()
{
}

void _mkp_core_thctx()
{
    /* Init request list */
    mk_ws_request_init();
}

int _mkp_stage_30(struct plugin *plugin, struct client_session *cs, 
                  struct session_request *sr)
{
    int i;

    PLUGIN_TRACE("[FD %i] STAGE 30", cs->socket);

    /* Do websocket stuff just for the defined path */
    for (i = 0; i < WS_SUBPROTOCOL_NUM; i++) {

        if (sr->uri_processed.len == strlen(subprotocol_list[i].name) &&
                strncmp(sr->uri_processed.data, subprotocol_list[i].name, 
                    strlen(subprotocol_list[i].name)) == 0) {

            return ws_handler(cs->socket, cs, sr, plugin, subprotocol_list[i].id);
        }
    }
    return MK_PLUGIN_RET_NOT_ME;
}
