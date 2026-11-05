/* Regression checks for HTTP framing, body boundaries and incremental state. */
#include <monkey/mk_http.h>
#include <monkey/mk_http_parser.h>
#include "mk_tests.h"

static int error_status;
static int error_count;

/* Capture the production parser's response decision without starting a server. */
int mk_http_error(int status, struct mk_http_session *session,
                  struct mk_http_request *request, struct mk_server *server)
{
    (void) session;
    (void) request;
    (void) server;
    error_status = status;
    error_count++;
    return MK_EXIT_OK;
}

struct framing_case {
    const char *name;
    const char *headers;
    const char *body;
    int status; /* Zero means the parser must accept the request. */
};

static const struct framing_case cases[] = {
    {"control", "", "", 0},
    {"unequal short first", "Content-Length: 7\r\nContent-Length: 20\r\n", "abcdefg", 400},
    {"unequal long first", "Content-Length: 20\r\nContent-Length: 7\r\n", "abcdefg", 400},
    {"equal", "Content-Length: 7\r\nContent-Length: 7\r\n", "abcdefg", 0},
    {"equal zero", "Content-Length: 0\r\nContent-Length: 0\r\n", "", 0},
    {"not-chunked", "Transfer-Encoding: not-chunked\r\n", "abcdefg", 501},
    {"xchunked", "Transfer-Encoding: xchunked\r\n", "abcdefg", 501},
    {"identity", "Transfer-Encoding: identity\r\n", "abcdefg", 501},
    {"gzip", "Transfer-Encoding: gzip\r\n", "abcdefg", 501},
    {"identity then chunked", "Transfer-Encoding: identity, chunked\r\n", "abcdefg", 501},
    {"gzip then chunked", "Transfer-Encoding: gzip, chunked\r\n", "abcdefg", 501},
    {"empty coding", "Transfer-Encoding: \r\n", "abcdefg", 400},
    {"duplicate chunked", "Transfer-Encoding: chunked, chunked\r\n", "abcdefg", 400},
    {"chunked not last", "Transfer-Encoding: chunked, gzip\r\n", "abcdefg", 400},
    {"leading comma", "Transfer-Encoding: ,chunked\r\n", "abcdefg", 400},
    {"trailing comma", "Transfer-Encoding: chunked,\r\n", "abcdefg", 400},
    {"chunked parameter", "Transfer-Encoding: chunked;foo=bar\r\n", "abcdefg", 400},
    {"repeated chunked field", "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n", "abcdefg", 400},
    {"split coding list", "Transfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n", "abcdefg", 501},
    {"CL0 then chunked", "Content-Length: 0\r\nTransfer-Encoding: chunked\r\n", "abcdefg", 400},
    {"chunked then CL0", "Transfer-Encoding: chunked\r\nContent-Length: 0\r\n", "abcdefg", 400},
    {"CL7 then chunked", "Content-Length: 7\r\nTransfer-Encoding: chunked\r\n", "abcdefg", 400},
    {"chunked then CL7", "Transfer-Encoding: chunked\r\nContent-Length: 7\r\n", "abcdefg", 400},
    {"CL0 then gzip", "Content-Length: 0\r\nTransfer-Encoding: gzip\r\n", "abcdefg", 400},
    {"gzip then CL0", "Transfer-Encoding: gzip\r\nContent-Length: 0\r\n", "abcdefg", 400},
    {"CL7 then gzip", "Content-Length: 7\r\nTransfer-Encoding: gzip\r\n", "abcdefg", 400},
    {"gzip then CL7", "Transfer-Encoding: gzip\r\nContent-Length: 7\r\n", "abcdefg", 400}
};

static void framing_validation(void)
{
    char message[512];
    struct mk_http_parser parser;
    struct mk_http_request req;
    size_t c;
    int len;
    int split;
    int ret;

    for (c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
        len = snprintf(message, sizeof(message),
                       "GET / HTTP/1.1\r\nHost: localhost\r\n%s\r\n%s",
                       cases[c].headers, cases[c].body);
        TEST_ASSERT(len > 0 && (size_t) len < sizeof(message));
        /* Include a single-buffer parse and every possible two-buffer split. */
        for (split = 1; split <= len; split++) {
            memset(&req, 0, sizeof(req));
            mk_http_parser_init(&parser);
            error_status = error_count = 0;
            ret = mk_http_parser(&req, &parser, message, split, NULL);
            if (ret == MK_HTTP_PARSER_PENDING && split < len) {
                ret = mk_http_parser(&req, &parser, message, len, NULL);
            }
            TEST_CHECK(ret == (cases[c].status ? MK_HTTP_PARSER_ERROR : MK_HTTP_PARSER_OK));
            TEST_MSG("case: %s, split: %d, result: %d", cases[c].name, split, ret);
            TEST_CHECK(error_status == cases[c].status);
            TEST_MSG("case: %s, split: %d, status: %d", cases[c].name, split, error_status);
            TEST_CHECK(error_count == (cases[c].status ? 1 : 0));
        }
    }
}

static void body_boundaries(const char *method, int chunked)
{
    char message[512];
    char buffer[512];
    char decoded[7];
    const char *next = "GET /next HTTP/1.1\r\nHost: localhost\r\n\r\n";
    struct mk_http_parser parser;
    struct mk_http_request req;
    size_t decoded_len;
    size_t end;
    size_t body;
    size_t total;
    size_t split;
    int pipelined;
    int len;
    int ret;

    len = snprintf(message, sizeof(message),
                   "%s / HTTP/1.1\r\nHost: localhost\r\n%s\r\n%s", method,
                   chunked ? "Transfer-Encoding: ChUnKeD\t\r\n" :
                             "Content-Length: 7\r\nContent-Length: 7\r\n",
                   chunked ? "7\r\nabcdefg\r\n0\r\n\r\n" : "abcdefg");
    if (len <= 0 || (size_t) len + strlen(next) >= sizeof(message)) {
        TEST_CHECK(0);
        TEST_MSG("request does not fit in the test buffer");
        return;
    }
    end = len;
    body = strstr(message, "\r\n\r\n") + 4 - message;
    strcpy(message + end, next);

    for (pipelined = 0; pipelined <= 1; pipelined++) {
        total = end + (pipelined ? strlen(next) : 0);
        for (split = 1; split <= end; split++) {
            memcpy(buffer, message, total);
            memset(&req, 0, sizeof(req));
            mk_http_parser_init(&parser);
            error_status = error_count = 0;
            ret = mk_http_parser(&req, &parser, buffer,
                                 split == end ? total : split, NULL);
            if (split < end) {
                TEST_CHECK(ret == MK_HTTP_PARSER_PENDING);
                ret = mk_http_parser(&req, &parser, buffer, total, NULL);
            }
            TEST_ASSERT(ret == MK_HTTP_PARSER_OK);
            TEST_CHECK(error_count == 0);
            TEST_CHECK(parser.i == (int) end - 1);
            TEST_CHECK(mk_http_parser_request_size(&parser, buffer, total) == end);
            TEST_CHECK(mk_http_parser_more(&parser, total) == pipelined);
            if (chunked) {
                TEST_CHECK(mk_http_parser_content_length(&parser) == 7);
                decoded_len = 0;
                /* Decode only this message, excluding any buffered next request. */
                ret = mk_http_parser_chunked_decode_buf(&parser, buffer, end,
                                                        decoded, sizeof(decoded),
                                                        &decoded_len);
                TEST_ASSERT(ret == 0);
                TEST_CHECK(decoded_len == 7);
                TEST_CHECK(memcmp(decoded, "abcdefg", 7) == 0);
            }
            else {
                TEST_CHECK(parser.body_received == 7);
                TEST_CHECK(req.data.len == 7);
                TEST_CHECK(req.data.data == buffer + body);
                TEST_CHECK(memcmp(req.data.data, "abcdefg", 7) == 0);
            }
            if (pipelined) {
                /* Follow the server's pipeline consumption and reset sequence. */
                memmove(buffer, buffer + parser.i + 1, total - end);
                memset(&req, 0, sizeof(req));
                mk_http_parser_init(&parser);
                ret = mk_http_parser(&req, &parser, buffer, total - end, NULL);
                TEST_ASSERT(ret == MK_HTTP_PARSER_OK);
                TEST_CHECK(req.uri.len == 5);
                TEST_CHECK(memcmp(req.uri.data, "/next", 5) == 0);
                TEST_CHECK(!mk_http_parser_more(&parser, total - end));
                TEST_CHECK(error_count == 0);
            }
        }
    }
}

static void fixed_body(void)
{
    body_boundaries("GET", 0);
    body_boundaries("POST", 0);
}

static void chunked_body(void)
{
    body_boundaries("GET", 1);
    body_boundaries("POST", 1);
}

TEST_LIST = {
    {"framing validation at every split", framing_validation},
    {"fixed body boundaries at every split", fixed_body},
    {"chunked body boundaries at every split", chunked_body},
    {NULL, NULL}
};
