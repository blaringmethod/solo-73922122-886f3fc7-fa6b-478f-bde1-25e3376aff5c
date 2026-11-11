/*
 * 测试夹具：调用 execve 替换为 /bin/true。
 *
 * 设计上 seccomp 不拦截 execve（首次加载已封印助手映像需要它），
 * 本夹具验证助手进程内的单次 execve 可以成功；而“不能换入其他程序”
 * 由可信配置 + memfd 封印在启动前保证，且 clone/fork 族被 KILL，
 * 助手无法借子进程执行任何未批准内容。
 *
 * 编译：cc -O2 -Wall -Wextra -o execer execer.c
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    char *const nargv[] = {"/bin/true", NULL};
    char *const nenvp[] = {NULL};
    execve("/bin/true", nargv, nenvp);
    perror("execve");
    return 44;
}
