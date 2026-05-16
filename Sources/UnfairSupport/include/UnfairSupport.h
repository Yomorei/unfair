#ifndef UNFAIR_SUPPORT_H
#define UNFAIR_SUPPORT_H

#include <stddef.h>

int unfair_prepare_app_bundle_decryption(char *error, size_t error_size);
int unfair_run_executable(
    const char *path,
    int argument_count,
    char **arguments,
    int *exit_status,
    char **output,
    char **error_message
);
void unfair_free(void *pointer);

#endif
