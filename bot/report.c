#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>

#include "headers/report.h"

int create_socket(const char *ip_address, int port) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        return -1;
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip_address, &(server_addr.sin_addr)) <= 0) {
        close(sockfd);
        return -1;
    }

    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        close(sockfd);
        return -1;
    }

    return sockfd;
}

void report_kill(int pid, const char *realpath) {
    char message[256];
    int sockfd = create_socket("0.0.0.0", 199);
    if (sockfd != -1) {
        snprintf(message, sizeof(message), "Found And Killed Process: PID=%d, Realpath=%s", pid, realpath);
        write(sockfd, message, strlen(message));
        close(sockfd);
    }
}
