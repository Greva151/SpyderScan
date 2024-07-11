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
#include "../lib/spyderscan.h"


int validate_number(char *str) {
    while (*str) {
        if (!isdigit(*str)) { 
            return 0;
        }
        str++; 
    }
    return 1;
}


int validate_ip(char *ip) { 
    int num, dots = 0;
    char *ptr;

    if (ip == NULL) {
        return 0;
    }

    ptr = strtok(ip, "."); 
    if (ptr == NULL) {
        return 0;
    }

    while (ptr) {
        if (!validate_number(ptr)) { 
            return 0;
        }
        num = atoi(ptr); 
        if (num >= 0 && num <= 255) {
            ptr = strtok(NULL, "."); 
            if (ptr != NULL) {
                dots++; 
            }
        } else {
            return 0;
        }
    }

    if (dots != 3) {
        return 0;
    }

    return 1;
}


int is_udp_port_open(const char *ip, int port) {
    int sockfd;
    struct sockaddr_in server_addr;
    char message[] = "Ping";
    char buffer[1024];
    socklen_t addr_len;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Errore nella creazione del socket UDP");
        return 0;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, ip, &server_addr.sin_addr) <= 0) {
        perror("Errore nella conversione dell'indirizzo IP");
        close(sockfd);
        return 0;
    }

    addr_len = sizeof(server_addr);
    if (sendto(sockfd, message, sizeof(message), 0, (struct sockaddr *)&server_addr, addr_len) < 0) {
        perror("Errore nell'invio del messaggio UDP");
        close(sockfd);
        return 0;
    }

    fd_set read_fds;
    struct timeval timeout;
    FD_ZERO(&read_fds);
    FD_SET(sockfd, &read_fds);
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    if (select(sockfd + 1, &read_fds, NULL, NULL, &timeout) > 0) {
        if (recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&server_addr, &addr_len) >= 0) {
            close(sockfd);
            return 1;
        }
    }

    close(sockfd);
    return 0;
}


int is_tcp_port_open(const char *ip, int port) {
    int sockfd;
    struct sockaddr_in server_addr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Errore nella creazione del socket TCP");
        return 0;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, ip, &server_addr.sin_addr) <= 0) {
        perror("Errore nella conversione dell'indirizzo IP");
        close(sockfd);
        return 0;
    }

    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        if (errno == ECONNREFUSED || errno == ETIMEDOUT) {
            close(sockfd);
            return 0;
        } else {
            perror("Errore nella connessione TCP");
            close(sockfd);
            return 0;
        }
    }

    close(sockfd);
    return 1;
}


uint32_t stohi(char *ip){
	char c;
	c = *ip;
	unsigned int integer = 0;
	int val;
	int i, j = 0;

	for (j = 0; j < 4; j++) {
		if (!isdigit(c)){ 
			return (0);
		}

		val = 0;

		for (i = 0; i < 3; i++) {
			if (isdigit(c)) {
				val = (val * 10) + (c - '0');
				c = *++ip;
			} else
				break;
		}

		if(val < 0 || val > 255){
			return (0);	
		}	

		if (c == '.') {
			integer = (integer << 8) | val;
			c = *++ip;
		} 

		else if(j == 3 && c == '\0'){
			integer = (integer << 8) | val;
			break;
		}
			
	}

	if(c != '\0'){
		return (0);	
	}

	return htonl(integer);
}


void spyderscan(unsigned char TEAM_NUMBER, char NETWORK_NAME[]){
    uint32_t ip = stohi(NETWORK_NAME); 

    ip++;

    for(int i = 0; i <= TEAM_NUMBER; i++){

        struct in_addr ip_addr;
        ip_addr.s_addr = ip;
        char IPstr[16];
        strncpy(IPstr, inet_ntoa(ip_addr), 15);

        for(int port = 1; port < 0xffff; port++){
            printf("scanning %s IP\n", IPstr); 
            if(is_tcp_port_open(IPstr, port))
                printf("IP = %s, PORT = %d, PROTO = %s", IPstr, port, "TCP"); 
            if(is_udp_port_open(IPstr, port))
                printf("IP = %s, PORT = %d, PROTO = %s", IPstr, port, "TCP"); 
        }

        ip += 0x00000100;    

    }

}       