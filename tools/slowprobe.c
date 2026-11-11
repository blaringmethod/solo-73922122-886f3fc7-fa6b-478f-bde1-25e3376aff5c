/*
 * slowprobe：用于演示 3 秒超时回收的诊断助手。
 * 启动后周期性打印心跳，5 秒才退出；服务端应在 3 秒时杀掉整个进程组，
 * 客户端拿到 504 且没有任何部分输出。
 *
 * 编译：cc -O2 -Wall -Wextra -o slowprobe slowprobe.c
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <time.h>
#include <unistd.h>

int main(void)
{
    for (int i = 1; i <= 50; i++) {
        printf("slowprobe heartbeat %d/50\n", i);
        fflush(stdout);
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 100 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }
    printf("slowprobe finished (should never be reached under 3s limit)\n");
    return 0;
}
