#include <fcntl.h>
#include <pwd.h>
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

#define TRUE 1
#define FALSE 0

struct userinfo {
    int uid, gid;
    char *home;
};

void free_userinfo(struct userinfo *userinfo) {
    if (userinfo == NULL) {
        return;
    }
    if (userinfo->home != NULL) {
        free((void *) userinfo->home);
    }
    free((void *) userinfo);
}

int get_userinfo(pam_handle_t *pamh, struct userinfo **userinfo) {
    const char *user;
    struct passwd pwd, *result;
    char *buf;
    size_t bufsize;

    *userinfo = NULL;

    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || user == NULL) {
        return FALSE;
    }

    bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (bufsize == -1) {
        bufsize = 16384;
    }

    buf = malloc(bufsize);
    if (buf == NULL) {
        return FALSE;
    }

    if (getpwnam_r(user, &pwd, buf, bufsize, &result) != 0 || result == NULL ||
        pwd.pw_dir == NULL || pwd.pw_dir[0] != '/') {
        free(buf);
        return FALSE;
    }

    *userinfo = malloc(sizeof(*userinfo));
    if (*userinfo == NULL) {
        free(buf);
        return FALSE;
    }

    (*userinfo)->uid = pwd.pw_uid;
    (*userinfo)->gid = pwd.pw_gid;
    (*userinfo)->home = strdup(pwd.pw_dir);
    free(buf);

    if ((*userinfo)->home == NULL) {
        free_userinfo(*userinfo);
        *userinfo = NULL;
        return FALSE;
    }

    return TRUE;
}

/* Copied from gnome-keyring */
void cleanup_token(pam_handle_t *pamh, void *data, int error_status) {
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

void close_safe(int fd)
{
    if (fd != -1) {
        close(fd);
    }
}

void setup_sigs(struct sigaction **old) {
    struct sigaction sigchld, sigpipe;
    if ((*old = malloc(2*sizeof(struct sigaction))) == NULL) {
        return;
    }
    memset(*old, 0, 2*sizeof(struct sigaction));
    memset(&sigchld, 0, sizeof(sigchld));
    memset(&sigpipe, 0, sizeof(sigpipe));
    sigchld.sa_handler = SIG_DFL;
    sigpipe.sa_handler = SIG_IGN;
    sigaction(SIGCHLD, &sigchld, *old+0);
    sigaction(SIGPIPE, &sigpipe, *old+1);
}

void restore_sigs(const struct sigaction *old) {
    if (old == NULL) {
        return;
    }
    sigaction(SIGCHLD, old+0, NULL);
    sigaction(SIGPIPE, old+1, NULL);
    free((void *) old);
}

int run_as_user(const struct userinfo *user, const char * const cmd[], int *input) {
    int inp[2] = {-1, -1};
    int pid;
    int dev_null;

    if (input != NULL) {
        if (pipe(inp) < 0) {
            *input = -1;
            return 0;
        }
        *input = inp[WRITE_END];
    }

    switch (pid = fork()) {
    case -1:
        close_safe(inp[READ_END]);
        close_safe(inp[WRITE_END]);
        if (input != NULL) {
            *input = -1;
        }
        return FALSE;

    case 0:
        break;

    default:
        close_safe(inp[READ_END]);
        return pid;
    }

    /* We're in the child process now */

    if (inp[READ_END] != -1) {
        if (dup2(inp[READ_END], STDIN_FILENO) < 0) {
            exit(EXIT_FAILURE);
        }
    } else {
        if ((dev_null = open("/dev/null", O_RDONLY)) != -1) {
            dup2(dev_null, STDIN_FILENO);
            close(dev_null);
        }
    }
    close_safe(inp[READ_END]);
    close_safe(inp[WRITE_END]);

    if ((dev_null = open("/dev/null", O_WRONLY)) != -1) {
        dup2(dev_null, STDOUT_FILENO);
        dup2(dev_null, STDERR_FILENO);
        close(dev_null);
    }

    seteuid(getuid());
    setegid(getgid());
    if (setgid(user->gid) < 0 || setuid(user->uid) < 0 ||
        setegid(user->gid) < 0 || seteuid(user->uid) < 0) {
        exit(EXIT_FAILURE);
    }

    execv(cmd[0], (char * const *) cmd);
    exit(EXIT_FAILURE);
}

FILE *open_keygrip_file(const struct userinfo *user) {
    char keygrip_file[1024];
    if (snprintf(keygrip_file, sizeof(keygrip_file),
                 "%s/.pam-gnupg", user->home) >= sizeof(keygrip_file)) {
        return FALSE;
    }
    return fopen(keygrip_file, "r");
}

int extract_keygrip(const char *line, char *keygrip) {
    const char *cur = line;
    while (*cur && strchr(" \t\n\r\f\v", *cur)) {
        cur++;
    }
    if (!*cur || *cur == '#') {
        return FALSE;
    }
    strncpy(keygrip, cur, KEYGRIP_LENGTH);
    keygrip[KEYGRIP_LENGTH] = 0;
    if (strlen(keygrip) != KEYGRIP_LENGTH) {
        return FALSE;
    }
    return TRUE;
}

int start_agent(const struct userinfo *user) {
    int pid, status;
    const char * const cmd[] =
        {GPGCONF, "--launch", "gpg-agent", NULL};
    pid = run_as_user(user, cmd, NULL);
    if (pid == 0) {
        return FALSE;
    }
    waitpid(pid, &status, 0);
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

int preset_passphrase(const struct userinfo *user, const char *keygrip, const char *tok) {
    int pid, status, input;
    const char * const cmd[] =
        {GPG_PRESET_PASSPHRASE, "--preset", keygrip, NULL};
    pid = run_as_user(user, cmd, &input);
    if (pid == 0 || input < 0) {
        return 0;
    }
    write(input, tok, strlen(tok));
    close(input);
    waitpid(pid, &status, 0);
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *tok;
    if (pam_get_item(pamh, PAM_AUTHTOK, (const void **) &tok) == PAM_SUCCESS || tok != NULL) {
        pam_set_data(pamh, "pam-gnupg-token", (void *) strdup(tok), cleanup_token);
    }
    return PAM_SUCCESS;
}

int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    char keygrip[KEYGRIP_LENGTH+1];
    const char *tok;
    struct userinfo *user;
    struct sigaction *handlers = NULL;
    FILE *file = NULL;
    char *line = NULL;
    size_t len = 0;
    int ret = PAM_SUCCESS;

    if (flags & PAM_DELETE_CRED) {
        return PAM_SUCCESS;
    }

    if (pam_get_data(pamh, "pam-gnupg-token", (const void **) &tok) != PAM_SUCCESS) {
        return PAM_SUCCESS;
    }

    if (!get_userinfo(pamh, &user)) {
        return PAM_IGNORE;
    }

    if ((file = open_keygrip_file(user)) == NULL) {
        goto end;
    }

    setup_sigs(&handlers);
    if (handlers == NULL) {
        ret = PAM_IGNORE;
        goto end;
    }

    while (getline(&line, &len, file) != -1) {
        if (!extract_keygrip(line, keygrip)) {
            continue;
        }
        if (!preset_passphrase(user, keygrip, tok)) {
            /* We did not succeed setting the passphrase. Maybe the agent is not
             * running? Try again in open_session. */
            ret = PAM_IGNORE;
            goto end;
        }
    }

    pam_set_data(pamh, "pam-gnupg-token", NULL, NULL);

end:
    if (file != NULL) {
        fclose(file);
    }
    if (line != NULL) {
        free(line);
    }
    restore_sigs(handlers);
    free_userinfo(user);
    return ret;
}

int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    char keygrip[KEYGRIP_LENGTH+1];
    const char *tok;
    struct userinfo *user;
    struct sigaction *handlers;
    FILE *file = NULL;
    char *line = NULL;
    size_t len = 0;
    int ret = PAM_SUCCESS;

    if (pam_get_data(pamh, "pam-gnupg-token", (const void **) &tok) != PAM_SUCCESS) {
        return PAM_SUCCESS;
    }

    if (!get_userinfo(pamh, &user)) {
        ret = PAM_IGNORE;
        goto end;
    }

    if ((file = open_keygrip_file(user)) == NULL) {
        goto end;
    }

    setup_sigs(&handlers);
    if (handlers == NULL) {
        ret = PAM_IGNORE;
        goto end;
    }

    if (!start_agent(user)) {
        ret = PAM_IGNORE;
        goto end;
    }

    while (getline(&line, &len, file) != -1) {
        if (!extract_keygrip(line, keygrip)) {
            continue;
        }
        preset_passphrase(user, keygrip, tok);
    }

end:
    pam_set_data(pamh, "pam-gnupg-token", NULL, NULL);
    if (file != NULL) {
        fclose(file);
    }
    if (line != NULL) {
        free(line);
    }
    restore_sigs(handlers);
    free_userinfo(user);
    return ret;
}

int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}
