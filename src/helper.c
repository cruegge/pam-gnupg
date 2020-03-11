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

#define die(...) do { syslog(LOG_ERR, __VA_ARGS__); exit(EXIT_FAILURE); } while (0)

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

FILE *open_config(char *homedir) {
    if (chdir(homedir) < 0) {
        if (errno == ENOENT) {
            exit(EXIT_SUCCESS);
        }
        die("failed to open home directory: %m");
    }

    FILE *f = fopen(".pam-gnupg", "re");
    if (f != NULL) {
        return f;
    }
    if (errno != ENOENT) {
        die("failed to open config file: %m");
    }

    if (chdir(getenv("XDG_CONFIG_HOME") ?: ".config") < 0) {
        if (errno == ENOENT) {
            exit(EXIT_SUCCESS);
        }
        die("failed to open config directory: %m");
    }

    f = fopen("pam-gnupg", "re");
    if (f != NULL) {
        return f;
    }
    if (errno != ENOENT) {
        die("failed to open config file: %m");
    }

    exit(EXIT_SUCCESS);
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
            die("getpwuid failed: User not found");
        } else {
            die("getpwuid failed: %m");
        }
    }

    FILE *f = open_config(pwd->pw_dir);

    char tok[MAX_PASSPHRASE_LEN + 1];
    if (fgets(tok, MAX_PASSPHRASE_LEN + 1, stdin) == NULL) {
        die("failed to read passphrase: %m");
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
        die("failed to open pipe: %m");
    }

    FILE *p = fdopen(pipefd[1], "w");
    if (p == NULL) {
        die("failed to fdopen pipe: %m");
    }

    signal(SIGCHLD, SIG_DFL);
    pid_t pid = fork();
    if (pid == -1) {
        die("fork failed: %m");
    } else if (pid == 0) {
        if (dup2(pipefd[0], STDIN_FILENO) < 0) {
            die("dup failed: %m");
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
        die("exec failed: %m");
    }

    close(pipefd[0]);

    signal(SIGPIPE, SIG_IGN);
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
            die("failed to write to pipe: %m");
        }
    }

    fclose(p);

    int status;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status)) {
        status = WEXITSTATUS(status);
        if (status == EXIT_SUCCESS) {
            exit(EXIT_SUCCESS);
        }
        die("child terminated with exit code %d", status);
    } else if (WIFSIGNALED(status)) {
        die("child killed by signal %d", WTERMSIG(status));
    } else {
        die("child returned unknown status code %d", status);
    }
}
