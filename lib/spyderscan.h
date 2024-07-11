#include <stdint.h>

#ifndef SPYDER_SCAN_H
#define SPYDER_SCAN_H

int validate_number(char *str); 
int validate_ip(char *ip); 
int is_udp_port_open(const char *ip, int port); 
int is_tcp_port_open(const char *ip, int port); 
uint32_t getDecimalFromIPV4(char ip[]);
char spyderscan(unsigned char TEAM_NUMBER, char NETWORK_NAME[]); 
 
#endif // SPYDER_SCAN_H