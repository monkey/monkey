/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef PROXY_NETWORK_H
#define PROXY_NETWORK_H

int proxy_net_socket_create();
int proxy_net_socket_nonblock(int fd);
int proxy_net_connect(int fd, char *host, char *port);

#endif
