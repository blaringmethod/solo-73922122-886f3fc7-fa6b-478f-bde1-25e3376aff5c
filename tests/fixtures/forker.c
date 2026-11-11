/*
 * 测试夹具：尝试 fork 子进程。seccomp 过滤器必须让本进程被
 * SECCOMP_RET_KILL_PROCESS 立即终止，观察到的退出表现为负 SIGSYS。
 *
 * 编译：cc -O2 -Wall -Wextra -o forker forker.c
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>

int main(void)
{
    printf("forker: about to fork\n");
    fflush(stdout);
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return 42;
    }
    if (pid == 0) {
        _exit(0);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    printf("forker: child exited (unexpected, seccomp did not block)\n");
    return 43;
}
