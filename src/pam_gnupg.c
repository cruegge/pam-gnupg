#define _GNU_SOURCE

#include <fcntl.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <wait.h>

#define PAM_SM_AUTH
#define PAM_SM_SESSION

#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>

#include "config.h"

#define KEYGRIP_LENGTH 40

#define READ_END 0
#define WRITE_END 1

char tohex(char n) {
    if (n < 10) {
        return n + '0';
    } else {
        return n - 10 + 'A';
    }
}

/* Copied from gnupg */
char *hexify(const char *token) {
    char *result = malloc(2*strlen(token)+1);
    char *r;
    const char *s;
    if (result == NULL) {
        return NULL;
    }
    for (s = token, r = result; *s; s++) {
        *r++ = tohex((*s>>4) & 15);
        *r++ = tohex(*s & 15);
    }
    *r = 0;
    return result;
}

/* Copied from gnome-keyring */
void wipestr(char *data) {
    volatile char *vp;
    size_t len;
    if (!data) {
        return;
    }
    /* Defeats some optimizations */
    len = strlen(data);
    memset(data, 0xAA, len);
    memset(data, 0xBB, len);
    /* Defeats others */
    vp = (volatile char*) data;
    while (*vp) {
        *(vp++) = 0xAA;
    }
    free((void *) data);
}

void cleanup_token(pam_handle_t *pamh, void *data, int error_status) {
    wipestr(data);
}

bool preset_passphrase(pam_handle_t *pamh, const char *tok, bool autostart) {
    const char *user = NULL;
    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || user == NULL) {
        return false;
    }

    struct passwd *pwd = getpwnam(user);
    if (pwd == NULL) {
        return false;
    }

    struct sigaction sigchld, old_sigchld;
    memset(&sigchld, 0, sizeof(sigchld));
    memset(&old_sigchld, 0, sizeof(old_sigchld));
    sigchld.sa_handler = SIG_DFL;
    sigaction(SIGCHLD, &sigchld, &old_sigchld);

    pid_t pid = fork();
    if (pid == -1) {
        sigaction(SIGCHLD, &old_sigchld, NULL);
        return false;
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
        sigaction(SIGCHLD, &old_sigchld, NULL);
        return (WIFEXITED(status) && WEXITSTATUS(status) == EXIT_SUCCESS);
    }

    // We're in the child process now. From here on, the function will not return.

    if (setregid(pwd->pw_gid, pwd->pw_gid) < 0 || setreuid(pwd->pw_uid, pwd->pw_uid) < 0) {
        exit(EXIT_FAILURE);
    }

    int inp[2] = {-1, -1};
    if (pipe(inp) < 0) {
        exit(EXIT_FAILURE);
    }
    signal(SIGPIPE, SIG_IGN);

    int dev_null = open("/dev/null", O_RDWR);
    if (dev_null != -1) {
        dup2(dev_null, STDIN_FILENO);
        dup2(dev_null, STDOUT_FILENO);
        dup2(dev_null, STDERR_FILENO);
        close(dev_null);
    }

    int dirfd = open(pwd->pw_dir, O_RDONLY | O_CLOEXEC);
    if (dirfd < 0) {
        exit(EXIT_FAILURE);
    }
    int fd = openat(dirfd, ".pam-gnupg", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        exit(EXIT_FAILURE);
    }
    FILE *file = fdopen(fd, "r");
    if (file == NULL) {
        exit(EXIT_FAILURE);
    }

    pid = fork();
    if (pid == -1) {
        exit(EXIT_FAILURE);
    } else if (pid == 0) {
        // Grandchild
        if (dup2(inp[READ_END], STDIN_FILENO) < 0) {
            exit(EXIT_FAILURE);
        }
        close(inp[READ_END]);
        close(inp[WRITE_END]);

        // gpg-connect-agent has an option --no-autostart, which *should* return
        // non-zero when the agent is not running. Unfortunately, the exit code is
        // always 0 in version 2.1. Passing an invalid agent program here is a
        // workaround. See https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=797334
        const char *cmd[] = {GPG_CONNECT_AGENT, "--agent-program", "/dev/null", NULL};
        if (autostart) {
            cmd[1] = NULL;
        }

        char **env = pam_getenvlist(pamh);
        if (env != NULL) {
            execve(cmd[0], (char * const *) cmd, env);
        } else {
            execv(cmd[0], (char * const *) cmd);
        }
        exit(EXIT_FAILURE);
    }

    close(inp[READ_END]);

    char *presetcmd;
    const int presetlen = asprintf(&presetcmd, "PRESET_PASSPHRASE xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx -1 %s\n", tok);
    if (presetlen < 0) {
        exit(EXIT_FAILURE);
    }
    char * const keygrip = presetcmd + 18;

    char *line = NULL;
    size_t len = 0;
    ssize_t rd;
    while ((rd = getline(&line, &len, file)) != -1) {
        if (line[rd-1] == '\n') {
            line[rd-1] = '\0';
        }
        const char *cur = line;
        while (*cur && strchr(" \t\n\r\f\v", *cur)) {
            cur++;
        }
        if (!*cur || *cur == '#') {
            continue;
        }
        strncpy(keygrip, cur, KEYGRIP_LENGTH);
        if (strlen(keygrip) < KEYGRIP_LENGTH) {
            // We hit an unexpected eol or null byte.
            continue;
        }
        if (write(inp[WRITE_END], presetcmd, presetlen) < 0) {
            exit(EXIT_FAILURE);
        }
    }

    int status;
    close(inp[WRITE_END]);
    waitpid(pid, &status, 0);
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        exit(EXIT_SUCCESS);
    } else {
        exit(EXIT_FAILURE);
    }
}

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *tok = NULL;
    if (pam_get_item(pamh, PAM_AUTHTOK, (const void **) &tok) == PAM_SUCCESS && tok != NULL) {
        tok = hexify(tok);
        if (tok != NULL) {
            pam_set_data(pamh, "pam-gnupg-token", (void *) tok, cleanup_token);
        }
    }
    return PAM_SUCCESS;
}

int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *tok = NULL;
    if ((argc > 0 && strcmp(argv[0], "store-only") == 0) ||
        (flags & PAM_DELETE_CRED) ||
        pam_get_data(pamh, "pam-gnupg-token", (const void **) &tok) != PAM_SUCCESS ||
        tok == NULL) {
        return PAM_SUCCESS;
    }
    if (!preset_passphrase(pamh, tok, false)) {
        return PAM_IGNORE;
    }
    pam_set_data(pamh, "pam-gnupg-token", NULL, NULL);
    return PAM_SUCCESS;
}

int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *tok = NULL;
    if (pam_get_data(pamh, "pam-gnupg-token", (const void **) &tok) == PAM_SUCCESS && tok != NULL) {
        preset_passphrase(pamh, tok, (argc == 0 || strcmp(argv[0], "no-autostart") != 0));
        pam_set_data(pamh, "pam-gnupg-token", NULL, NULL);
    }
    return PAM_SUCCESS;
}

int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}
