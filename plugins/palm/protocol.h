pthread_key_t iov_protocol_request;
pthread_key_t iov_protocol_request_idx;

struct request_reset {
    int *idx;
    int len;
};

void mk_palm_protocol_thread_init();
void mk_palm_protocol_request_reset();
struct mk_iov *mk_palm_protocol_request_new(struct client_session *cs,
                                            struct session_request *sr);
