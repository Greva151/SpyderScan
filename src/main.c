// ./spyderscan -n 45 -i 127.0.0.0
// number of teams: -n [int]
// network: -i [network_name/24]

// gcc -I./lib src/spyderscan.c src/main.c -o spyderscan
// gcc -I./lib -Wall -Wextra -pedantic -O2 -g src/spyderscan.c src/main.c -o spyderscan

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../lib/spyderscan.h"

char TEAM_NUMBER;
char NETWORK_NAME[16];

int main(int argc, char *argv[]) {

    if (argc != 5) {
        fprintf(stderr, "Uso: ./spyder_scan -n <number of teams> -i <network_name>\n");
        return 1;
    }

    TEAM_NUMBER = 16;
    snprintf(NETWORK_NAME, sizeof(NETWORK_NAME), "10.60.0.0");

    for (int i = 1; i < argc; i++) {
        if (strncmp("-n", argv[i], 2) == 0) {
            if ((TEAM_NUMBER = atoi(argv[++i])) != 0) {
                if (TEAM_NUMBER < 1) {
                    fprintf(stderr, "Error: the number of teams can't be negative!\n");
                    return 1;
                }
            } else {
                fprintf(stderr, "Error: the number of teams is invalid!\n");
                return 1;
            }
        } else if (strncmp("-i", argv[i], 2) == 0) {
            char *ip_arg = argv[++i];
            if (strlen(ip_arg) < sizeof(NETWORK_NAME)) {
                snprintf(NETWORK_NAME, sizeof(NETWORK_NAME), "%s", ip_arg);

                //printf("IP letto da argv %s\n", NETWORK_NAME);        //debug

                if (!validate_ip(ip_arg)) {
                    fprintf(stderr, "Error: the name of network is invalid!\n");
                    return 1;
                }
            } else {
                fprintf(stderr, "Error: the name of network is invalid!\n");
                return 1;
            }
        } else {
            fprintf(stderr, "Error: invalid params!\n");
            return 1;
        }
    }

    spyderscan(TEAM_NUMBER, NETWORK_NAME);

    return 0;
}
