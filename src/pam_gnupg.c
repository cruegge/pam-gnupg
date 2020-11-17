#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <wait.h>

#define PAM_SM_AUTH
#define PAM_SM_SESSION

#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <security/pam_modutil.h>

#include "config.h"

#define TOKEN_DATA_NAME "pam-gnupg-token"

// Copied from gnome-keyring
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

bool preset_passphrase(pam_handle_t *pamh, const char *tok, bool autostart, bool send_env) {
    const char *user = NULL;
    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || user == NULL) {
        pam_syslog(pamh, LOG_ERR, "failed to get username");
        return false;
    }

    struct passwd *pwd = pam_modutil_getpwnam(pamh, user);
    if (pwd == NULL) {
        pam_syslog(pamh, LOG_ERR, "failed to get user info");
        return false;
    }
    uid_t uid = pwd->pw_uid;
    gid_t gid = pwd->pw_gid;

    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC) < 0) {
        pam_syslog(pamh, LOG_ERR, "failed to open pipe: %m");
        return false;
    }

    // pam_getenvlist() allocates, so we can't call it after fork().
    char **env = NULL;
    if (send_env) {
        env = pam_getenvlist(pamh);
        if (env == NULL) {
            pam_syslog(pamh, LOG_ERR, "failed to read pam environment");
            return false;
        }
    }

    // Reset SIGCHLD handler so we can use waitpid(). If the calling process
    // used a handler to manage its own child processes, and one of the
    // children exits while we're busy, things will probably break, but there
    // does not appear to be a sane way of avoiding this.
    //
    // TODO Add a noreap option like pam_unix to selectively disable this for
    // services that are able to handle it.
    struct sigaction sa, saved_sigchld;
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = SIG_DFL;
    sa.sa_flags = 0;
    sigaction(SIGCHLD, &sa, &saved_sigchld);

    bool ret = true;

    pid_t pid = fork();
    if (pid < 0) {
        pam_syslog(pamh, LOG_ERR, "failed to fork: %m");
        close(pipefd[0]);
        close(pipefd[1]);
        ret = false;
    }

    else if (pid == 0) {
        // TODO what about supplementary groups?
        if (setregid(gid, gid) < 0 || setreuid(uid, uid) < 0) {
            exit(errno);
        }

        // Unblock all signals. fork() clears pending signals in the child, so
        // this is safe.
        sigset_t emptyset;
        sigemptyset(&emptyset);
        sigprocmask(SIG_SETMASK, &emptyset, NULL);

        if (dup2(pipefd[0], STDIN_FILENO) < 0) {
            exit(errno);
        }
        int dev_null = open("/dev/null", O_WRONLY | O_CLOEXEC);
        if (dev_null != -1) {
            dup2(dev_null, STDOUT_FILENO);
            dup2(dev_null, STDERR_FILENO);
        }

        int maxfd = getdtablesize();
        for (int n = 3; n < maxfd; n++) {
            close(n);
        }

        char * cmd[] = {PAM_GNUPG_HELPER, "--autostart", NULL};
        if (!autostart) {
            cmd[1] = NULL;
        }
        if (send_env) {
            execve(cmd[0], cmd, env);
        } else {
            execv(cmd[0], cmd);
        }
        exit(errno);
    }

    else {
        if (pam_modutil_write(pipefd[1], tok, strlen(tok)) < 0) {
            pam_syslog(pamh, LOG_ERR, "failed to write to pipe: %m");
            ret = false;
        }
        // We close the read fd after writing in order to avoid SIGPIPE. Since
        // we write at most MAX_PASSPHRASE_LEN bytes, the pipe buffer won't
        // fill up and block us even if the child process dies.
        close(pipefd[0]);
        close(pipefd[1]);
        int status;
        while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
            ;
        if (WIFEXITED(status)) {
            status = WEXITSTATUS(status);
            if (status != EXIT_SUCCESS) {
                pam_syslog(pamh, LOG_ERR, "helper terminated with exit code %d", status);
                ret = false;
            }
        } else if (WIFSIGNALED(status)) {
            pam_syslog(pamh, LOG_ERR, "helper killed by signal %d", WTERMSIG(status));
            ret = false;
        } else {
            pam_syslog(pamh, LOG_ERR, "helper returned unknown status code %d", status);
            ret = false;
        }
    }

    free(env);
    sigaction(SIGCHLD, &saved_sigchld, NULL);
    return ret;
}

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *tok = NULL;
    bool debug = false;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "debug") == 0) {
            debug = true;
        }
        else if (strcmp(argv[i], "store-only") == 0) {
            // unused here
        }
        else {
            pam_syslog(pamh, LOG_ERR, "invalid option: %s", argv[i]);
            return PAM_IGNORE;
        }
    }
    if (pam_get_item(pamh, PAM_AUTHTOK, (const void **) &tok) != PAM_SUCCESS
            || tok == NULL
    ) {
        if (debug) pam_syslog(pamh, LOG_DEBUG, "failed to obtain passphrase");
        return PAM_AUTHINFO_UNAVAIL;
    }
    // Don't copy more bytes than gpg-agent is able to handle.
    tok = strndup(tok, MAX_PASSPHRASE_LEN);
    if (tok == NULL) {
        pam_syslog(pamh, LOG_ERR, "failed to copy passphrase");
        return PAM_SYSTEM_ERR;
    }
    if (pam_set_data(pamh, TOKEN_DATA_NAME, (void *) tok, cleanup_token) != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_ERR, "failed to store passphrase");
        return PAM_IGNORE;
    }
    if (debug) pam_syslog(pamh, LOG_DEBUG, "stored passphrase");
    return PAM_SUCCESS;
}

int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *tok = NULL;
    bool debug = false;
    bool store_only = false;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "debug") == 0) {
            debug = true;
        }
        else if (strcmp(argv[i], "store-only") == 0) {
            store_only = true;
        }
        else {
            pam_syslog(pamh, LOG_ERR, "invalid option: %s", argv[i]);
            return PAM_IGNORE;
        }
    }
    if (store_only) {
        if (debug) pam_syslog(pamh, LOG_DEBUG, "store-only set, skipping");
        return PAM_SUCCESS;
    }
    if (flags & PAM_DELETE_CRED) {
        if (debug) pam_syslog(pamh, LOG_DEBUG, "PAM_DELETE_CRED set, skipping");
        return PAM_SUCCESS;
    }
    if (pam_get_data(pamh, TOKEN_DATA_NAME, (const void **) &tok) != PAM_SUCCESS || tok == NULL) {
        if (debug) pam_syslog(pamh, LOG_DEBUG, "unable to obtain stored passphrase");
        return PAM_IGNORE;
    }
    if (preset_passphrase(pamh, tok, false, false)) {
        if (debug) pam_syslog(pamh, LOG_DEBUG, "presetting succeeded, cleaning up");
        pam_set_data(pamh, TOKEN_DATA_NAME, NULL, NULL);
        return PAM_SUCCESS;
    } else {
        if (debug) pam_syslog(pamh, LOG_DEBUG, "presetting failed, retaining passphrase");
        return PAM_IGNORE;
    }
}

int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *tok = NULL;
    bool debug = false;
    bool autostart = true;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "debug") == 0) {
            debug = true;
        }
        else if (strcmp(argv[i], "no-autostart") == 0) {
            autostart = false;
        }
        else {
            pam_syslog(pamh, LOG_ERR, "invalid option: %s", argv[i]);
            return PAM_IGNORE;
        }
    }
    if (pam_get_data(pamh, TOKEN_DATA_NAME, (const void **) &tok) != PAM_SUCCESS || tok == NULL) {
        if (debug) pam_syslog(pamh, LOG_DEBUG, "unable to obtain stored passphrase");
        return PAM_SUCCESS;  // this is not necessarily an error, so return PAM_SUCCESS here
    }
    if (preset_passphrase(pamh, tok, autostart, true)) {
        if (debug) pam_syslog(pamh, LOG_DEBUG, "presetting passphrase succeeded, cleaning up");
        pam_set_data(pamh, TOKEN_DATA_NAME, NULL, NULL);
        return PAM_SUCCESS;
    } else {
        if (debug) pam_syslog(pamh, LOG_DEBUG, "presetting passphrase failed, cleaning up");
        pam_set_data(pamh, TOKEN_DATA_NAME, NULL, NULL);
        return PAM_SESSION_ERR;
    }
}

int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}
