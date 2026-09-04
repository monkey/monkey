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

#include <monkey/mk_core.h>

#include "mk_tests.h"

#define EVENT_LOOP_MAX_EVENTS 4
#define EVENT_LOOP_OVERFLOW_EVENTS (EVENT_LOOP_MAX_EVENTS * 4)

static int write_event(int fd, uint64_t *value)
{
#ifdef _WIN32
    return send(fd, (char *) value, sizeof(*value), 0);
#else
    return write(fd, value, sizeof(*value));
#endif
}

static int read_event(int fd, uint64_t *value)
{
#ifdef _WIN32
    return recv(fd, (char *) value, sizeof(*value), MSG_WAITALL);
#else
    return read(fd, value, sizeof(*value));
#endif
}

/*
 * Regression test: more events become ready in a single wait than the loop
 * was created for. The libevent backend collected fired events in an array
 * sized once at loop creation and wrote past its end in this situation.
 */
void test_more_ready_events_than_loop_size(void)
{
    int i;
    int ret;
    int seen;
    uint64_t value = 1;
    struct mk_event *event;
    struct mk_event *events;
    struct mk_event_loop *evl;
    int (*fds)[2];

    TEST_CHECK(mk_event_init() == 0);

    evl = mk_event_loop_create(EVENT_LOOP_MAX_EVENTS);
    TEST_ASSERT(evl != NULL);

    events = calloc(EVENT_LOOP_OVERFLOW_EVENTS, sizeof(struct mk_event));
    fds = calloc(EVENT_LOOP_OVERFLOW_EVENTS, sizeof(*fds));
    TEST_ASSERT(events != NULL && fds != NULL);

    /* Register every read end and make all of them readable at once. */
    for (i = 0; i < EVENT_LOOP_OVERFLOW_EVENTS; i++) {
        MK_EVENT_NEW(&events[i]);

        ret = mk_event_channel_create(evl, &fds[i][0], &fds[i][1],
                                      &events[i]);
        TEST_ASSERT(ret == 0);

        ret = write_event(fds[i][1], &value);
        TEST_ASSERT(ret == sizeof(value));
    }

    ret = mk_event_wait_2(evl, 1000);
    TEST_ASSERT(ret == EVENT_LOOP_OVERFLOW_EVENTS);

    seen = 0;
    mk_event_foreach(event, evl) {
        i = (int) (event - events);
        TEST_ASSERT(i >= 0 && i < EVENT_LOOP_OVERFLOW_EVENTS);

        ret = read_event(event->fd, &value);
        TEST_ASSERT(ret == sizeof(value));

        ret = mk_event_channel_destroy(evl, fds[i][0], fds[i][1], event);
        TEST_ASSERT(ret == 0);
        seen++;
    }

    TEST_CHECK(seen == EVENT_LOOP_OVERFLOW_EVENTS);
    TEST_MSG("expected %d events, got %d",
             EVENT_LOOP_OVERFLOW_EVENTS, seen);

    free(fds);
    free(events);
    mk_event_loop_destroy(evl);
}

TEST_LIST = {
    {
        "more_ready_events_than_loop_size",
        test_more_ready_events_than_loop_size,
    },
    {NULL, NULL}
};
