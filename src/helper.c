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
#include <sys/wait.h>

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

bool nextentry(FILE *f) {
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

void read_gnupghome(FILE *f, char *homedir) {
    char *gnupghome = NULL;
    char *line = NULL;
    size_t bufsize = 0;
    size_t len = getline(&line, &bufsize, f);
    if (len < 0) {
        die("failed to read GNUPGHOME from file: %m");
    } else if (len > 0) {
        if (line[len - 1] = '\n') {
            line[len - 1] = '\0';
        }
        if (line[0] == '~') {
            if (asprintf(&gnupghome, "%s%s", homedir, line + 1) < 0) {
                die("tilde expansion failed: %m");
            }
            free(line);
        } else {
            gnupghome = line;
        }
        if (setenv("GNUPGHOME", gnupghome, true) < 0) {
            die("failed to set GNUPGHOME: %m");
        }
    }
    free(gnupghome);
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

pid_t connect_agent(bool autostart, int pipefd) {
    pid_t pid = fork();
    if (pid == -1) {
        die("fork failed: %m");
    } else if (pid == 0) {
        if (dup2(pipefd, STDIN_FILENO) < 0) {
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
    close(pipefd);
    return pid;
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
    signal(SIGPIPE, SIG_IGN);
    pid_t pid = 0;
    for (; nextentry(f); nextline(f)) {
        int c = getc(f);
        ungetc(c, f);
        if (c == '/' || c == '~') {
            if (pid != 0) {
                syslog(LOG_WARNING, "Ignored GNUPHOME setting after keygrip.");
            } else {
                // TODO Should we send the environment during auth, or completely rely on session env?
                read_gnupghome(f, pwd->pw_dir);
                // Push back a newline, so nextline won't skip anything
                ungetc('\n', f);
            }
            continue;
        }
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
        if (pid == 0) {
            // Connect when we see the first keygrip to allow setting GNUPGHOME first.
            pid = connect_agent(autostart, pipefd[0]);
        }
        if (fprintf(p, "preset_passphrase %s -1 %s\n", keygrip, hextok) < 0) {
            die("failed to write to pipe: %m");
        }
    }

    if (autostart && (pid == 0)) {
        // We're configured to autostart, but did not encounter any keygrips.
        pid = connect_agent(autostart, pipefd[0]);
    }

    fclose(p);

    if (pid == 0) {
        // We're not autostarting and did not encounter any keygrips.
        exit(EXIT_SUCCESS);
    }

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
