#include "UnfairSupport.h"

#include <dlfcn.h>
#include <errno.h>
#include <spawn.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <TargetConditionals.h>
#endif

#define UNFAIR_CS_PLATFORM_BINARY 0x04000000u

typedef int (*jbclient_initialize_primitives_fn)(void);
typedef int (*jbclient_root_set_mac_label_fn)(uint64_t, uint64_t, uint64_t *);
typedef uint64_t (*proc_find_fn)(int);
typedef void (*proc_csflags_set_fn)(uint64_t, uint32_t);

static void set_error(char *error, size_t error_size, const char *format, ...) {
    if (error == NULL || error_size == 0) {
        return;
    }

    va_list args;
    va_start(args, format);
    vsnprintf(error, error_size, format, args);
    va_end(args);
}

static void set_allocated_error(char **error_message, const char *format, ...) {
    if (error_message == NULL) {
        return;
    }

    va_list args;
    va_start(args, format);
    va_list copy;
    va_copy(copy, args);
    int length = vsnprintf(NULL, 0, format, copy);
    va_end(copy);

    if (length < 0) {
        va_end(args);
        *error_message = NULL;
        return;
    }

    char *message = malloc((size_t)length + 1);
    if (message == NULL) {
        va_end(args);
        *error_message = NULL;
        return;
    }

    vsnprintf(message, (size_t)length + 1, format, args);
    va_end(args);
    *error_message = message;
}

static int append_output(char **output, size_t *length, size_t *capacity, const char *bytes, size_t byte_count) {
    if (*length + byte_count + 1 > *capacity) {
        size_t next_capacity = *capacity == 0 ? 4096 : *capacity;
        while (*length + byte_count + 1 > next_capacity) {
            next_capacity *= 2;
        }

        char *next_output = realloc(*output, next_capacity);
        if (next_output == NULL) {
            return -1;
        }
        *output = next_output;
        *capacity = next_capacity;
    }

    memcpy(*output + *length, bytes, byte_count);
    *length += byte_count;
    (*output)[*length] = '\0';
    return 0;
}

static void *open_libjailbreak(char *error, size_t error_size) {
    const char *paths[] = {
        "/var/jb/usr/lib/libjailbreak.dylib",
        "/var/jb/basebin/libjailbreak.dylib",
        "/basebin/libjailbreak.dylib",
        "libjailbreak.dylib",
    };

    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        void *handle = dlopen(paths[i], RTLD_NOW);
        if (handle != NULL) {
            return handle;
        }
    }

    set_error(error, error_size, "dlopen libjailbreak failed: %s", dlerror());
    return NULL;
}

static void *required_symbol(void *handle, const char *name, char *error, size_t error_size) {
    void *symbol = dlsym(handle, name);
    if (symbol == NULL) {
        set_error(error, error_size, "dlsym %s failed: %s", name, dlerror());
    }
    return symbol;
}

int unfair_prepare_app_bundle_decryption(char *error, size_t error_size) {
#if defined(TARGET_OS_IPHONE) && TARGET_OS_IPHONE
    static int prepared = 0;
    if (prepared) {
        return 0;
    }

    if (geteuid() != 0) {
        set_error(error, error_size, "root privileges required for jailbreak primitives");
        return -1;
    }

    void *handle = open_libjailbreak(error, error_size);
    if (handle == NULL) {
        return -1;
    }

    jbclient_initialize_primitives_fn jbclient_initialize_primitives =
        (jbclient_initialize_primitives_fn)required_symbol(handle, "jbclient_initialize_primitives", error, error_size);
    jbclient_root_set_mac_label_fn jbclient_root_set_mac_label =
        (jbclient_root_set_mac_label_fn)required_symbol(handle, "jbclient_root_set_mac_label", error, error_size);
    proc_find_fn proc_find =
        (proc_find_fn)required_symbol(handle, "proc_find", error, error_size);
    proc_csflags_set_fn proc_csflags_set =
        (proc_csflags_set_fn)required_symbol(handle, "proc_csflags_set", error, error_size);

    if (jbclient_initialize_primitives == NULL ||
        jbclient_root_set_mac_label == NULL ||
        proc_find == NULL ||
        proc_csflags_set == NULL) {
        return -1;
    }

    if (jbclient_initialize_primitives() != 0) {
        set_error(error, error_size, "jbclient_initialize_primitives failed");
        return -1;
    }

    uint64_t original_label = 0;
    if (jbclient_root_set_mac_label(1, UINT64_MAX, &original_label) != 0) {
        set_error(error, error_size, "jbclient_root_set_mac_label failed");
        return -1;
    }

    uint64_t proc = proc_find(getpid());
    if (proc == 0) {
        set_error(error, error_size, "proc_find(%d) failed", getpid());
        return -1;
    }

    proc_csflags_set(proc, UNFAIR_CS_PLATFORM_BINARY);
    prepared = 1;
    return 0;
#else
    (void)error;
    (void)error_size;
    return 0;
#endif
}

int unfair_run_executable(
    const char *path,
    int argument_count,
    char **arguments,
    int *exit_status,
    char **output,
    char **error_message
) {
    if (output != NULL) {
        *output = NULL;
    }
    if (error_message != NULL) {
        *error_message = NULL;
    }

    if (path == NULL || exit_status == NULL || output == NULL) {
        set_allocated_error(error_message, "invalid command execution arguments");
        return -1;
    }

    int output_pipe[2] = {-1, -1};
    if (pipe(output_pipe) != 0) {
        set_allocated_error(error_message, "pipe failed: %s", strerror(errno));
        return -1;
    }

    posix_spawn_file_actions_t actions;
    int actions_initialized = 0;
    int result = posix_spawn_file_actions_init(&actions);
    if (result != 0) {
        set_allocated_error(error_message, "posix_spawn_file_actions_init failed: %s", strerror(result));
        close(output_pipe[0]);
        close(output_pipe[1]);
        return -1;
    }
    actions_initialized = 1;

    result = posix_spawn_file_actions_adddup2(&actions, output_pipe[1], STDOUT_FILENO);
    if (result == 0) {
        result = posix_spawn_file_actions_adddup2(&actions, output_pipe[1], STDERR_FILENO);
    }
    if (result == 0) {
        result = posix_spawn_file_actions_addclose(&actions, output_pipe[0]);
    }
    if (result == 0) {
        result = posix_spawn_file_actions_addclose(&actions, output_pipe[1]);
    }
    if (result != 0) {
        set_allocated_error(error_message, "posix_spawn file action setup failed: %s", strerror(result));
        posix_spawn_file_actions_destroy(&actions);
        close(output_pipe[0]);
        close(output_pipe[1]);
        return -1;
    }

    char **spawn_argv = calloc((size_t)argument_count + 2, sizeof(char *));
    if (spawn_argv == NULL) {
        set_allocated_error(error_message, "command argument allocation failed");
        if (actions_initialized) {
            posix_spawn_file_actions_destroy(&actions);
        }
        close(output_pipe[0]);
        close(output_pipe[1]);
        return -1;
    }

    spawn_argv[0] = (char *)path;
    for (int index = 0; index < argument_count; index++) {
        spawn_argv[index + 1] = arguments[index];
    }
    spawn_argv[argument_count + 1] = NULL;

    pid_t pid = 0;
    char *empty_environment[] = {NULL};
    result = posix_spawn(&pid, path, &actions, NULL, spawn_argv, empty_environment);
    free(spawn_argv);
    posix_spawn_file_actions_destroy(&actions);
    close(output_pipe[1]);
    output_pipe[1] = -1;

    if (result != 0) {
        set_allocated_error(error_message, "posix_spawn failed: %s", strerror(result));
        close(output_pipe[0]);
        return -1;
    }

    char *command_output = NULL;
    size_t output_length = 0;
    size_t output_capacity = 0;
    if (append_output(&command_output, &output_length, &output_capacity, "", 0) != 0) {
        set_allocated_error(error_message, "command output allocation failed");
        close(output_pipe[0]);
        return -1;
    }

    char buffer[4096];
    for (;;) {
        ssize_t count = read(output_pipe[0], buffer, sizeof(buffer));
        if (count > 0) {
            if (append_output(&command_output, &output_length, &output_capacity, buffer, (size_t)count) != 0) {
                free(command_output);
                set_allocated_error(error_message, "command output allocation failed");
                close(output_pipe[0]);
                return -1;
            }
            continue;
        }
        if (count == 0) {
            break;
        }
        if (errno == EINTR) {
            continue;
        }

        free(command_output);
        set_allocated_error(error_message, "read command output failed: %s", strerror(errno));
        close(output_pipe[0]);
        return -1;
    }
    close(output_pipe[0]);

    int status = 0;
    pid_t waited = 0;
    do {
        waited = waitpid(pid, &status, 0);
    } while (waited < 0 && errno == EINTR);

    if (waited != pid) {
        free(command_output);
        set_allocated_error(error_message, "waitpid failed: %s", strerror(errno));
        return -1;
    }

    if (WIFEXITED(status)) {
        *exit_status = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        *exit_status = 128 + WTERMSIG(status);
    } else {
        *exit_status = status;
    }

    *output = command_output;
    return 0;
}

void unfair_free(void *pointer) {
    free(pointer);
}
