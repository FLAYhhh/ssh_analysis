#ifndef SSH_ANALYSIS
#define SSH_ANALYSIS

int proto_ssh_init(void **handle, void *userdata);
int process_ssh_stream(void *handle, const char *protodata, int32_t len, int32_t direction);
int ssh_callback(int type, void *content, void *userdata);
int proto_ssh_release(void **handle);

int process_id_string(void *handle, const char *protodata, int32_t len, int32_t direction);
int process_dh_request(void *handle, const char *protodata, int32_t len, int32_t direction);
int process_dh_group(void *handle, const char *protodata, int32_t len, int32_t direction);
int process_dh_init(void *handle, const char *protodata, int32_t len, int32_t direction);
int process_dh_reply(void *handle, const char *protodata, int32_t len, int32_t direction);
int process_new_keys(void *handle, const char *protodata, int32_t len, int32_t direction);

#endif
