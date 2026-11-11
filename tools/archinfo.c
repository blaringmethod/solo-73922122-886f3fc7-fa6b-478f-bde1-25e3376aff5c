/*
 * archinfo：已批准的普通诊断助手（不派生子进程）。
 *
 * 输出架构与运行环境排障信息：uname、页大小、身份、argv、解释器路径、
 * /proc/self/status 关键字段。所有信息只读采集，输出体量远小于 64 KiB。
 *
 * 编译：cc -O2 -Wall -Wextra -o archinfo archinfo.c
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <sys/stat.h>

static void print_status_field(const char *wanted)
{
    FILE *fp = fopen("/proc/self/status", "r");
    if (!fp) {
        printf("status.%s: <unreadable>\n", wanted);
        return;
    }
    char line[512];
    size_t nlen = strlen(wanted);
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, wanted, nlen) == 0) {
            /* 去掉行尾换行后原样输出 */
            size_t l = strlen(line);
            if (l && line[l - 1] == '\n')
                line[l - 1] = '\0';
            printf("%s\n", line);
            break;
        }
    }
    fclose(fp);
}

int main(int argc, char **argv)
{
    struct utsname un;
    if (uname(&un) != 0) {
        perror("uname");
        return 1;
    }

    printf("=== archinfo diagnostic report ===\n");
    printf("sysname:  %s\n", un.sysname);
    printf("nodename: %s\n", un.nodename);
    printf("release:  %s\n", un.release);
    printf("version:  %s\n", un.version);
    printf("machine:  %s\n", un.machine);
    printf("page_size: %ld\n", sysconf(_SC_PAGESIZE));
    printf("pid=%ld ppid=%ld uid=%ld gid=%ld euid=%ld egid=%ld\n",
           (long)getpid(), (long)getppid(),
           (long)getuid(), (long)getgid(),
           (long)geteuid(), (long)getegid());

    printf("argv:");
    for (int i = 0; i < argc; i++)
        printf(" [%s]", argv[i]);
    printf("\n");

    char buf[4096];
    ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n >= 0) {
        buf[n] = '\0';
        printf("self_exe: %s\n", buf);
    }
    n = readlink("/proc/self/auxv", buf, sizeof(buf) - 1);
    (void)n;

    struct stat st;
    if (stat("/lib64/ld-linux-x86-64.so.2", &st) == 0)
        printf("loader: /lib64/ld-linux-x86-64.so.2 present (trusted)\n");

    print_status_field("Name:");
    print_status_field("Seccomp:");
    print_status_field("NoNewPrivs:");
    print_status_field("CapEff:");
    print_status_field("VmPeak:");
    print_status_field("VmRSS:");
    printf("=== end of report ===\n");
    return 0;
}
