#include <stdint.h>

#ifndef SPYDER_SCAN_H
#define SPYDER_SCAN_H

int validate_number(char *str); 
int validate_ip(char *ip); 
int is_udp_port_open(const char *ip, int port, size_t leght_message); 
int is_tcp_port_open(const char *ip, int port); 
u_int32_t stringToIntIP(char input[]); 
void spyderscan(unsigned char TEAM_NUMBER, char NETWORK_NAME[]); 
void generate_random_bytes(char *buffer, size_t length); 
void decimalToDotted(u_int32_t decimalIP, char dst[]);
 
#endif // SPYDER_SCAN_H