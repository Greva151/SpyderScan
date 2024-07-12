#ifndef SPYDER_SCAN_H
#define SPYDER_SCAN_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <sys/select.h>
#include <stdint.h>
#include <ctype.h>
#include <fcntl.h>
#include <time.h>
#include <netdb.h>
#include <sys/types.h>
#include <unistd.h>
#include <oping.h>

int validate_number(char *str); 
int validate_ip(char *ip); 
int is_tcp_port_open(const char *ip, int port, int timeout_ms); 
u_int32_t stringToIntIP(char input[]); 
void spyderscan(unsigned char TEAM_NUMBER, char NETWORK_NAME[]); 
void decimalToDotted(u_int32_t decimalIP, char dst[]);
int getLatency(const char *ip);
 
#endif // SPYDER_SCAN_H