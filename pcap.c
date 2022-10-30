#include <stdio.h>
#include <time.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header);

int main(int argc, char *argv[]) {
    char *device;
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const u_char *packet;
    struct pcap_pkthdr packet_header;

    device = pcap_lookupdev(error_buffer);
    if (device == NULL) {
        printf("Error finding device: %s\n", error_buffer);
        return 1;
    }

  handle = pcap_open_live(device, BUFSIZ, 1, 1000, error_buffer);
if (handle == NULL)
{
fprintf(stderr, "Couldn't open device %s: %s\n", device, error_buffer);
return(2);
}

     /*Attempt to capture one packet. If there is no network traffic
      and the timeout is reached, return "No pack found." */
     
    packet = pcap_next(handle, &packet_header);
     if (packet == NULL)
{
        printf("No pack found!\n");
        return 2;
    }

    /*print the len of the packet if found*/
	
    printf("Packet captured with a lenght of [%d]\n", packet_header.len);

    return 0;
}
void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header) {
    printf("Packet capture length: %d\n", packet_header.caplen);
    printf("Packet total length %d\n", packet_header.len);
}pcap