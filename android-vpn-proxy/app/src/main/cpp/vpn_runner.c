#include <jni.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/stat.h>

/*
 * Tiny JNI shim used to hand the VpnService TUN file descriptor to the exec'd
 * tun2socks native binary:
 *   - fork(),
 *   - clear FD_CLOEXEC on the tun fd so it survives exec,
 *   - redirect stdout/stderr to a log file,
 *   - execv() the tun2socks binary.
 *
 * The child runs only async-signal-safe syscalls after fork, so forking a
 * multi-threaded JVM here is safe.
 */

static void redirect_fds(const char *path) {
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) return;
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    if (fd > STDERR_FILENO) close(fd);
}

JNIEXPORT jint JNICALL
Java_com_vpnproxy_TunRunner_start(JNIEnv *env, jclass clazz, jint tunFd,
                                  jobjectArray argv, jstring logPath) {
    jsize argc = argv ? (*env)->GetArrayLength(env, argv) : 0;
    char **args = (char **)malloc(((size_t)argc + 1) * sizeof(char *));
    if (args == NULL) return -1;

    jsize i;
    for (i = 0; i < argc; i++) {
        jstring js = (jstring)(*env)->GetObjectArrayElement(env, argv, i);
        if (js == NULL) {
            args[i] = NULL;
            continue;
        }
        const char *cs = (*env)->GetStringUTFChars(env, js, NULL);
        size_t len = strlen(cs);
        args[i] = (char *)malloc(len + 1);
        if (args[i]) {
            memcpy(args[i], cs, len + 1);
        }
        (*env)->ReleaseStringUTFChars(env, js, cs);
        (*env)->DeleteLocalRef(env, js);
    }
    args[argc] = NULL;

    const char *lp = logPath ? (*env)->GetStringUTFChars(env, logPath, NULL) : NULL;

    pid_t pid = fork();
    if (pid == 0) {
        /* child */
        if (lp && *lp) redirect_fds(lp);
        int flags = fcntl(tunFd, F_GETFD);
        if (flags >= 0) fcntl(tunFd, F_SETFD, flags & ~FD_CLOEXEC);
        if (args[0]) execv(args[0], args);
        dprintf(STDERR_FILENO, "execv failed: errno=%d (%s)\n", errno, strerror(errno));
        _exit(127);
    }

    /* parent */
    if (lp) (*env)->ReleaseStringUTFChars(env, logPath, lp);
    for (i = 0; i < argc; i++) free(args[i]);
    free(args);
    return (jint)pid;
}

JNIEXPORT jint JNICALL
Java_com_vpnproxy_TunRunner_reap(JNIEnv *env, jclass clazz, jint pid) {
    if (pid <= 0) return -1;
    int status = 0;
    while (waitpid((pid_t)pid, &status, 0) < 0) {
        if (errno == EINTR) continue;
        return -1;
    }
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return -WTERMSIG(status);
    return 0;
}