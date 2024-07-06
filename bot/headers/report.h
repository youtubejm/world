// report.h

#ifndef REPORT_H
#define REPORT_H

// Function to create a socket and report a kill
int create_socket(const char *ip_address, int port);

// Function to report a killed process
void report_kill(int pid, const char *realpath);

#endif // REPORT_H
