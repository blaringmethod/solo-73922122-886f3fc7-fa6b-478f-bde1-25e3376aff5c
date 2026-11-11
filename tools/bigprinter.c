/*
 * bigprinter：用于演示 64 KiB 输出上限的诊断助手。
 * 连续输出 128 KiB 到 stdout；服务端应在合计输出越限时杀掉进程组，
 * 客户端拿到 413 且没有任何部分输出。
 *
 * 编译：cc -O2 -Wall -Wextra -o bigprinter bigprinter.c
 */
#include <stdio.h>
#include <string.h>

int main(void)
{
    char line[128];
    size_t total = 0;
    for (int i = 0; i < 2048; i++) {
        int n = snprintf(line, sizeof(line), "bigprinter line %04d %048d\n", i, 0);
        if (fwrite(line, 1, (size_t)n, stdout) != (size_t)n)
            return 1;
        total += (size_t)n;
    }
    fprintf(stderr, "bigprinter wrote %zu bytes (should never be reached)\n", total);
    return 0;
}
