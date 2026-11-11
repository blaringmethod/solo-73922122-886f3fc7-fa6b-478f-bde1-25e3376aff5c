/*
 * 测试夹具：把收到的参数原样输出到 stdout，固定字符串输出到 stderr，
 * 并回显退出码参数，用于验证参数固定、stdout/stderr 分离与退出码透传。
 *
 * 编译：cc -O2 -Wall -Wextra -o echoer echoer.c
 */
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    printf("echoer argc=%d\n", argc);
    for (int i = 0; i < argc; i++)
        printf("argv[%d]=%s\n", i, argv[i]);
    fprintf(stderr, "echoer stderr marker\n");
    int code = (argc > 1) ? atoi(argv[1]) : 0;
    if (code < 0 || code > 255)
        code = 0;
    return code;
}
