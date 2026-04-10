/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2026 Monkey Software LLC <eduardo@monkey.io>
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

#include <monkey/mk_core.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#endif

#include "mk_tests.h"

static int write_signal(int fd, uint64_t value)
{
#ifdef _WIN32
    return send((SOCKET) fd, (const char *) &value, sizeof(value), 0);
#else
    return write(fd, &value, sizeof(value));
#endif
}

static int read_signal(int fd, uint64_t *value)
{
#ifdef _WIN32
    return recv((SOCKET) fd, (char *) value, sizeof(*value), MSG_WAITALL);
#else
    return read(fd, value, sizeof(*value));
#endif
}

static void close_fd(int fd)
{
    mk_event_closesocket(fd);
}

static int create_connected_pair(int pair[2])
{
    int ret;
    int listener = -1;
    int client = -1;
    int server = -1;
    socklen_t addrlen;
    struct sockaddr_in addr;

    listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) {
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;

    ret = bind(listener, (struct sockaddr *) &addr, sizeof(addr));
    if (ret < 0) {
        close_fd(listener);
        return -1;
    }

    ret = listen(listener, 1);
    if (ret < 0) {
        close_fd(listener);
        return -1;
    }

    addrlen = sizeof(addr);
    ret = getsockname(listener, (struct sockaddr *) &addr, &addrlen);
    if (ret < 0) {
        close_fd(listener);
        return -1;
    }

    client = socket(AF_INET, SOCK_STREAM, 0);
    if (client < 0) {
        close_fd(listener);
        return -1;
    }

    ret = connect(client, (struct sockaddr *) &addr, sizeof(addr));
    if (ret < 0) {
        close_fd(client);
        close_fd(listener);
        return -1;
    }

    server = accept(listener, NULL, NULL);
    close_fd(listener);
    if (server < 0) {
        close_fd(client);
        return -1;
    }

    pair[0] = server;
    pair[1] = client;
    return 0;
}

void test_event_channel_wait_destroy(void)
{
    int ret;
    int channels[2];
    uint64_t value = 42;
    struct mk_event *event;
    struct mk_event loop_event = {0};
    struct mk_event_loop *loop;

    TEST_CHECK(mk_event_init() == 0);

    loop = mk_event_loop_create(8);
    TEST_ASSERT(loop != NULL);

    ret = mk_event_channel_create(loop, &channels[0], &channels[1], &loop_event);
    TEST_ASSERT(ret == 0);

    ret = write_signal(channels[1], value);
    TEST_ASSERT(ret == sizeof(value));

    ret = mk_event_wait_2(loop, 1000);
    TEST_ASSERT(ret == 1);

    event = NULL;
    mk_event_foreach(event, loop) {
        TEST_ASSERT(event == &loop_event);
        TEST_ASSERT(event->fd == channels[0]);
        TEST_ASSERT((event->mask & MK_EVENT_READ) != 0);
        break;
    }

    value = 0;
    ret = read_signal(channels[0], &value);
    TEST_ASSERT(ret == sizeof(value));
    TEST_ASSERT(value == 42);

    ret = mk_event_channel_destroy(loop, channels[0], channels[1], &loop_event);
    TEST_ASSERT(ret == 0);

    mk_event_loop_destroy(loop);
}

void test_event_add_wait_del(void)
{
    int ret;
    int pair[2];
    uint64_t value = 7;
    struct mk_event *fired;
    struct mk_event event = {0};
    struct mk_event_loop *loop;

    TEST_CHECK(mk_event_init() == 0);

    TEST_ASSERT(create_connected_pair(pair) == 0);

    loop = mk_event_loop_create(8);
    TEST_ASSERT(loop != NULL);

    ret = mk_event_add(loop, pair[0], MK_EVENT_CUSTOM, MK_EVENT_READ, &event);
    TEST_ASSERT(ret == 0);

    ret = write_signal(pair[1], value);
    TEST_ASSERT(ret == sizeof(value));

    ret = mk_event_wait_2(loop, 1000);
    TEST_ASSERT(ret == 1);

    fired = NULL;
    mk_event_foreach(fired, loop) {
        TEST_ASSERT(fired == &event);
        TEST_ASSERT((fired->mask & MK_EVENT_READ) != 0);
        break;
    }

    value = 0;
    ret = read_signal(pair[0], &value);
    TEST_ASSERT(ret == sizeof(value));
    TEST_ASSERT(value == 7);

    ret = mk_event_del(loop, &event);
    TEST_ASSERT(ret == 0);

    value = 9;
    ret = write_signal(pair[1], value);
    TEST_ASSERT(ret == sizeof(value));

    ret = mk_event_wait_2(loop, 50);
    TEST_ASSERT(ret == 0);

    value = 0;
    ret = read_signal(pair[0], &value);
    TEST_ASSERT(ret == sizeof(value));
    TEST_ASSERT(value == 9);

    close_fd(pair[0]);
    close_fd(pair[1]);
    mk_event_loop_destroy(loop);
}

void test_event_inject_prevent_duplication(void)
{
    int ret;
    struct mk_event event = {0};
    struct mk_event *fired;
    struct mk_event_loop *loop;

    loop = mk_event_loop_create(4);
    TEST_ASSERT(loop != NULL);

    ret = mk_event_inject(loop, &event, MK_EVENT_READ, MK_TRUE);
    TEST_ASSERT(ret == 0);

    ret = mk_event_inject(loop, &event, MK_EVENT_READ, MK_TRUE);
    TEST_ASSERT(ret == 0);
    TEST_ASSERT(loop->n_events == 1);

    fired = NULL;
    mk_event_foreach(fired, loop) {
        TEST_ASSERT(fired == &event);
        TEST_ASSERT((fired->mask & MK_EVENT_READ) != 0);
        break;
    }

    mk_event_loop_destroy(loop);
}

void test_event_wait_timeout_empty(void)
{
    int ret;
    struct mk_event_loop *loop;

    loop = mk_event_loop_create(4);
    TEST_ASSERT(loop != NULL);

    ret = mk_event_wait_2(loop, 25);
    TEST_ASSERT(ret == 0);

    mk_event_loop_destroy(loop);
}

TEST_LIST = {
    {"event_channel_wait_destroy", test_event_channel_wait_destroy},
    {"event_add_wait_del", test_event_add_wait_del},
    {"event_inject_prevent_duplication", test_event_inject_prevent_duplication},
    {"event_wait_timeout_empty", test_event_wait_timeout_empty},
    {NULL, NULL}
};
