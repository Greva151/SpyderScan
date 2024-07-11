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


int getLatency(char *ip){
    pingobj_t *ping;
    pingobj_iter_t *iter;

    ping = ping_construct();
    if (ping == NULL) {
        fprintf(stderr, "Errore nella creazione dell'oggetto ping\n");
        return 1;
    }

    if (ping_host_add(ping, ip) != 0) {
        fprintf(stderr, "Errore nell'aggiunta dell'host\n");
        ping_destroy(ping);
        return 1;
    }

    if (ping_send(ping) < 0) {
        fprintf(stderr, "Errore nell'invio del pacchetto ping\n");
        ping_destroy(ping);
        return 1;
    }

    int count = 0; 
    double sum = 0; 

    for (iter = ping_iterator_get(ping); iter != NULL; iter = ping_iterator_next(iter)) {
        char hostname[256];
        double latency;
        size_t len = sizeof(hostname);
        size_t lenLatency = sizeof(lenLatency); 

        ping_iterator_get_info(iter, PING_INFO_HOSTNAME, hostname, &len);
        ping_iterator_get_info(iter, PING_INFO_LATENCY, &latency, &lenLatency);

        printf("Ping a %s: latenza = %.3f ms\n", hostname, latency);
        
        sum += latency;
        count++; 
    }

    ping_destroy(ping);

    return (int)(sum / count); 
}


int is_tcp_port_open(const char *ip, int port, int timeout_ms) {
    int sockfd;
    struct sockaddr_in server_addr;
    fd_set fdset;
    struct timeval tv;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Errore nella creazione del socket TCP");
        return 0;
    }

    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, ip, &server_addr.sin_addr) <= 0) {
        perror("Errore nella conversione dell'indirizzo IP");
        close(sockfd);
        return 0;
    }

    connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr));

    FD_ZERO(&fdset);
    FD_SET(sockfd, &fdset);
    tv.tv_sec = timeout_ms / 1000;             
    tv.tv_usec = (timeout_ms % 1000) * 1000;  

    if (select(sockfd + 1, NULL, &fdset, NULL, &tv) == 1) {
        int so_error;
        socklen_t len = sizeof so_error;

        getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_error, &len);
        if (so_error == 0) {
            close(sockfd);
            return 1; 
        }
    }

    close(sockfd);
    return 0;
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

    //printf("IP number %u\n", ip);           //debug

    for(int i = 0; i < TEAM_NUMBER; i++){

        struct in_addr ip_addr;
        ip_addr.s_addr = ip;
        char IPstr[16];
        
        decimalToDotted(ip_addr.s_addr, IPstr);

        int value = getLatency(IPstr); 

        if(value > 0){}

        printf("im scanning this IP = %s\n", IPstr);

        for(int port = 22; port < 0xffff; port++){      

            //printf("PORT = %d\n", port);            //debug

            if(is_tcp_port_open(IPstr, port, 150))
                printf("IP = %s, PORT = %d, PROTO = %s\n", IPstr, port, "TCP"); 

        }

        ip += 0x00000100;    

    }

}       