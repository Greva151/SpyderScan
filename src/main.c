#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>  
#include "../lib/spyderscan.h"

// ./spyderscan -n 45 -i 10.0.0.0
// number of teams: -n [int]
// network: -i [network_name/24]

unsigned char TEAM_NUMBER;
char NETWORK_NAME[16];  

int main(int argc, char *argv[]) {

    if (argc != 5) {
        fprintf(stderr, "Uso: ./spyder_scan -n <number of teams> -i <network_name>\n");
        return 1;
    }

    TEAM_NUMBER = 16; 
    strncpy(NETWORK_NAME, "10.60.0.0", 16); 

    for(int i = 1; i < argc; i++){
        if(strncmp("-n", argv[i], 2) == 0){
            if((TEAM_NUMBER = atoi(argv[++i])) != 0){}
            else{
                fprintf(stderr, "Error: the number of teams is invalid!\n");
                return 1;
            }
        }
        else if (strncmp("-i", argv[i], 2) == 0){
            unsigned char len; 
            if((len = strlen(argv[++i])) < 16){
                if(validate_ip(argv[i]))
                    strncpy(NETWORK_NAME, argv[i], len); 
                else{
                    fprintf(stderr, "Error: the name of network is invalid!\n");
                    return 1;
                }
            }
            else{
                fprintf(stderr, "Error: the name of network is invalid!\n");
                return 1;
            }
        }
        else{
            fprintf(stderr, "Error: invalid params!\n");
            return 1;
        }
    }

    spyderscan(TEAM_NUMBER, NETWORK_NAME); 

    return 0;
}