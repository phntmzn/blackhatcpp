// ============================================================
// es_trace.cpp — EndpointSecurity file-open monitor
// ------------------------------------------------------------
// Compile: clang++ -O2 -o es_trace es_trace.cpp -framework EndpointSecurity
// Run:     sudo ./es_trace
// Note:    Requires Full Disk Access + EndpointSecurity entitlement
//          (com.apple.developer.endpoint-security.client). Must be
//          code-signed with the entitlement and run as root.
// ============================================================
#include <EndpointSecurity/EndpointSecurity.h>
#include <cstdio>
#include <unistd.h>

int main() {
    es_client_t* client = nullptr;
    es_new_client_result_t r = es_new_client(&client,
        ^(es_client_t*, const es_message_t* msg) {
            if (msg->event_type == ES_EVENT_TYPE_NOTIFY_OPEN) {
                const es_file_t* f = msg->event.open.file;
                printf("open: %s (pid %d)\n",
                       f->path.data, msg->process->audit_token.val[5]);
            }
        });
    if (r != ES_NEW_CLIENT_RESULT_SUCCESS) {
        fprintf(stderr, "es_new_client failed: %d\n", r);
        return 1;
    }
    es_subscribe(client, ES_EVENT_TYPE_NOTIFY_OPEN);
    for (;;) sleep(1);
    return 0;
}
