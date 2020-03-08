#define _GNU_SOURCE

#include <ctype.h>
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

#include "config.h"

#define KEYGRIP_LEN 40

#define xstr(x) str(x)
#define str(x) #x

char tohex(char n) {
    if (n < 10) {
        return n + '0';
    } else {
        return n - 10 + 'A';
    }
}

void nextline(FILE *f) {
    for (;;) {
        switch (getc(f)) {
            case EOF:
            case '\n':
                return;
        }
    }
}

bool nextkeygrip(FILE *f) {
    int c;
    for (;;) {
        do c = getc(f);
        while (c != EOF && strchr(" \t\n\r\f\v", c));
        if (c == EOF) {
            return false;
        }
        if (c != '#') {
            ungetc(c, f);
            return true;
        }
        nextline(f);
    }
}

int main(int argc, char **argv) {
    bool autostart = false;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--autostart") == 0) {
            autostart = true;
        }
    }

    openlog("pam_gnupg_helper", 0, LOG_AUTHPRIV);

    errno = 0;
    struct passwd *pwd = getpwuid(getuid());
    if (pwd == NULL) {
        if (errno == 0) {
            syslog(LOG_ERR, "getpwuid failed: User not found");
        } else {
            syslog(LOG_ERR, "getpwuid failed: %m");
        }
        exit(EXIT_FAILURE);
    }

    int dirfd = open(pwd->pw_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dirfd < 0) {
        syslog(LOG_ERR, "failed to open home directory: %m");
        exit(EXIT_FAILURE);
    }
    int fd = openat(dirfd, ".pam-gnupg", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT) {
            exit(EXIT_SUCCESS);
        } else {
            syslog(LOG_ERR, "failed to open config file: %m");
            exit(EXIT_FAILURE);
        }
    }
    FILE *f = fdopen(fd, "r");
    if (f == NULL) {
        syslog(LOG_ERR, "failed to fdopen config file: %m");
        exit(EXIT_FAILURE);
    }

    char tok[MAX_PASSPHRASE_LEN + 1];
    if (fgets(tok, MAX_PASSPHRASE_LEN + 1, stdin) == NULL) {
        syslog(LOG_ERR, "failed to read passphrase: %m");
        exit(EXIT_FAILURE);
    }

    char hextok[2 * MAX_PASSPHRASE_LEN + 1];
    char *s = tok, *h = hextok;
    while (*s != '\0' && *s != '\n') {
        *h++ = tohex((*s >> 4) & 15);
        *h++ = tohex(*s & 15);
        s++;
    }
    *s = *h = '\0';

    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC) < 0) {
        syslog(LOG_ERR, "failed to open pipe: %m");
        exit(EXIT_FAILURE);
    }

    FILE *p = fdopen(pipefd[1], "w");
    if (p == NULL) {
        syslog(LOG_ERR, "failed to fdopen pipe: %m");
        exit(EXIT_FAILURE);
    }

    signal(SIGCHLD, SIG_DFL);
    pid_t pid = fork();
    if (pid == -1) {
        syslog(LOG_ERR, "fork failed: %m");
        exit(EXIT_FAILURE);
    } else if (pid == 0) {
        if (dup2(pipefd[0], STDIN_FILENO) < 0) {
            exit(errno);
        }
        // gpg-connect-agent has an option --no-autostart, which *should* return
        // non-zero when the agent is not running. Unfortunately, the exit code is
        // always 0 in version 2.1. Passing an invalid agent program here is a
        // workaround. See https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=797334
        char *cmd[] = {GPG_CONNECT_AGENT, "--agent-program", "/dev/null", NULL};
        if (autostart) {
            cmd[1] = NULL;
        }
        execv(cmd[0], cmd);
        exit(errno);
    }

    close(pipefd[0]);

    signal(SIGPIPE, SIG_IGN);
    int ret = EXIT_SUCCESS;
    for (; nextkeygrip(f); nextline(f)) {
        char keygrip[KEYGRIP_LEN + 1];
        if (fscanf(f, "%" xstr(KEYGRIP_LEN) "[0-9A-Fa-f]", keygrip) < 1) {
            continue;
        }
        if (strlen(keygrip) < KEYGRIP_LEN) {
            continue;
        }
        for (s = keygrip; *s; s++) {
            *s = toupper(*s);
        }
        if (fprintf(p, "preset_passphrase %s -1 %s\n", keygrip, hextok) < 0) {
            syslog(LOG_ERR, "failed to write to pipe: %m");
            ret = EXIT_FAILURE;
            break;
        }
    }

    fclose(p);

    int status;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status)) {
        status = WEXITSTATUS(status);
        if (status == EXIT_SUCCESS) {
            return ret;
        }
        syslog(LOG_ERR, "child terminated with exit code %d", status);
        return EXIT_FAILURE;
    } else if (WIFSIGNALED(status)) {
        syslog(LOG_ERR, "child killed by signal %d", WTERMSIG(status));
        return EXIT_FAILURE;
    } else {
        syslog(LOG_ERR, "child returned unknown status code %d", status);
        return EXIT_FAILURE;
    }
}
