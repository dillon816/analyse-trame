#include <stdio.h>
#include "common.h"
#include "tcp.h"

// Analyser entete TCP
void analyserTCP(char *trame, TCP *tcp) 
{
   // Utilisation de unsigned char pour éviter les problèmes de signe

    // Extraction du port source 
    tcp->source_port = ((unsigned char)trame[0] << 8) | (unsigned char)trame[1];

    // Extraction du port destination 
    tcp->destination_port = ((unsigned char)trame[2] << 8) | (unsigned char)trame[3];

    // Extraction du numéro de séquence 
    tcp->sequence_number = ((unsigned char)trame[4] << 24) | ((unsigned char)trame[5] << 16) | ((unsigned char)trame[6] << 8) | (unsigned char)trame[7];

    // Extraction du numéro d'accusé de réception (acknowledgment number) 
    tcp->acknowledhment_number = ((unsigned char)trame[8] << 24) | ((unsigned char)trame[9] << 16) | ((unsigned char)trame[10] << 8) | (unsigned char)trame[11];

    // Extraction du data offset 
    tcp->data_offset = (trame[12] >> 4) & 0xF;

    // Extraction des flags 
    tcp->flags = (unsigned char)(trame[13] & 0x3F);

    // Extraction de la taille de la fenêtre 
    tcp->window = ((unsigned char)trame[14] << 8) | (unsigned char)trame[15];

    // Extraction du checksum 
    tcp->checksum = ((unsigned char)trame[16] << 8) | (unsigned char)trame[17];

    // Extraction du pointeur urgent 
    tcp->urgent_pointer = ((unsigned char)trame[18] << 8) | (unsigned char)trame[19];

}

// Afficher entete TCP
void afficherTCP(TCP tcp)
{
    printf("TCP:\n");
    printf("    source_port: %d\n", tcp.source_port);
    printf("    destination_port: %d\n", tcp.destination_port);
    printf("    sequence_number: %d\n", tcp.sequence_number);
    printf("    acknowledhment_number: %d\n", tcp.acknowledhment_number);
    printf("    data_offset: %d\n", tcp.data_offset);
    printf("    reserved: %d\n", tcp.reserved);
    printf("    flags: %d\n", tcp.flags);
    printf("    window: %d\n", tcp.window);
    printf("    checksum: %d\n", tcp.checksum);
    printf("    urgent_pointer: %d\n", tcp.urgent_pointer);
}
