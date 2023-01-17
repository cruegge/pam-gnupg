#pragma once

#ifdef __MACH__

// ==> READ THIS <==
//
// This is an attempt to make the code at least compile on MacOS. I don't have
// access to that OS, and have not tested it in any way, so do NOT take the
// presence of this code as implying any kind of support or guarantee for that
// platform!

#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

int setflags(int fd, int flags) {
    int oldflags = fcntl(fd, F_GETFD, 0);
    if (oldflags < 0) {
        return oldflags;
    }
    return fcntl(fd, F_SETFD, oldflags | flags);
}

int pipe2(int fd[2], int flags) {
    if (pipe(fd) < 0) {
        return -1;
    }
    if (setflags(fd[0], flags) < 0 || setflags(fd[1], flags) < 0) {
        int err = errno;
        close(fd[0]);
        close(fd[1]);
        errno = err;
        return -1;
    }
    return 0;
}

#endif
