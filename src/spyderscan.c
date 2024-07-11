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
#include "../lib/spyderscan.h"


void generate_random_bytes(char *buffer, size_t length) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    if ((size_t)read(fd, buffer, length) != length) {
        perror("read");
        close(fd);
        exit(EXIT_FAILURE);
    }

    close(fd);
}


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


int is_udp_port_open(const char *ip, int port, size_t leght_message) {
    int sockfd;
    struct sockaddr_in server_addr;
    char message[leght_message];

    generate_random_bytes(message, leght_message); 

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


u_int32_t stringToIntIP(char input[]){
    unsigned short ip[4] = {0};
    u_int32_t somIP = 0;   
    int q = 0;                 

    for(int i = 0; i < 16; i++){
        if(input[i] == '\n' || input[i] == '\0'){
            ip[q] /= 10;
            break; 
        }
        else{
            if(input[i] == '.'){
                ip[q] /= 10;  
                q++; 
            }
            else{
                ip[q] += input[i] & 0x0f; 
                ip[q] *= 10; 
            }
        }
    }

    somIP += (((u_int32_t)ip[0]) << 24) + (((u_int32_t)ip[1]) << 16) + (((u_int32_t)ip[2]) << 8) + ip[3]; 

    return somIP; 
}


void decimalToDotted(u_int32_t decimalIP, char dst[]){    

    unsigned char bytes[4];

    bytes[0] = decimalIP & 0xFF;
    bytes[1] = (decimalIP >> 8) & 0xFF;
    bytes[2] = (decimalIP >> 16) & 0xFF;
    bytes[3] = (decimalIP >> 24) & 0xFF; 

    snprintf(dst, 16, "%d.%d.%d.%d", bytes[3], bytes[2], bytes[1], bytes[0]);
}


void spyderscan(unsigned char TEAM_NUMBER, char NETWORK_NAME[]){
    uint32_t ip = stringToIntIP(NETWORK_NAME); 

    ip++;

    printf("IP number %u\n", ip);           //debug

    for(int i = 0; i <= TEAM_NUMBER; i++){

        struct in_addr ip_addr;
        ip_addr.s_addr = ip;
        char IPstr[16];
        
        decimalToDotted(ip_addr.s_addr, IPstr); 

        for(int port = 1; port < 0xffff; port++){ 

            printf("IP = %s\nPORT = %d\n\n", IPstr, port);            //debug

            // if(is_tcp_port_open(IPstr, port))
            //     printf("IP = %s, PORT = %d, PROTO = %s", IPstr, port, "TCP"); 

            srand(time(0)); 

            if(is_udp_port_open(IPstr, port, (size_t)((rand() % 100) + 2)))
                printf("IP = %s, PORT = %d, PROTO = %s", IPstr, port, "UDP"); 
        }

        ip += 0x00000100;    

    }

}       