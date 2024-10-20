#include <stdio.h>
#include "common.h"
#include "ip.h"

// Analyser entete IP
void analyserIP(char *trame, IP *ip) 
{
   // Version et IHL
    ip->version = (trame[0] >> 4) & 0xF;
    ip->IHL = trame[0] & 0xF;

    // Type de service
    ip->typeOfService = trame[1];

    // Longueur totale 
    ip->totalLength = (trame[2] << 8) | trame[3];

    // Identification 
    ip->identification = (trame[4] << 8) | trame[5];

    // Flags et offset de fragment 
    ip->flags = (trame[6] >> 5) & 0x7;
    ip->fragmentOffset = ((trame[6] & 0x1F) << 8) | trame[7];

    // Durée de vie (TTL)
    ip->timeToLive = trame[8];

    // Protocole
    ip->protocol = trame[9];

    // Checksum d'en-tête 
    ip->HeaderChecksum = (trame[10] << 8) | trame[11];

    // Adresse IP source 
    ip->sourceIP = (trame[12] << 24) | (trame[13] << 16) | (trame[14] << 8) | trame[15];

    // Adresse IP destination 
    ip->destinationIP = (trame[16] << 24) | (trame[17] << 16) | (trame[18] << 8) | trame[19];
}

// Afficher une adresse IP
void afficherIPAddress(unsigned int address)
{
   unsigned char octets[4];

    octets[0] = (address >> 24) & 0xFF; 
    octets[1] = (address >> 16) & 0xFF; 
    octets[2] = (address >> 8) & 0xFF;  
    octets[3] = address & 0xFF;         

    // Afficher l'adresse IP au format x.x.x.x
    printf("%d.%d.%d.%d\n", octets[0], octets[1], octets[2], octets[3]);
}

// Afficher entete IP
void afficherIP(IP ip)
{
    printf("IP:\n");
    printf("    version: %d\n", ip.version);
    printf("    IHL: %d\n", ip.IHL);
    printf("    typeOfService: %d\n", ip.typeOfService);
    printf("    totalLength: %d\n", ip.totalLength);
    printf("    identification: %d\n", ip.identification);
    printf("    flags: %d\n", ip.flags);
    printf("    fragmentOffset: %d\n", ip.fragmentOffset);
    printf("    timeToLive: %d\n", ip.timeToLive);
    printf("    protocol: %d\n", ip.protocol);
    printf("    HeaderChecksum: %d\n", ip.HeaderChecksum);
    printf("    sourceIP: ");
    afficherIPAddress(ip.sourceIP);
    printf("\n    destinationIP: ");
    afficherIPAddress(ip.destinationIP);
    printf("\n");
}