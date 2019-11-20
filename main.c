#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

uint8_t *hostname;
uint8_t *HTTP_METHOD[] = {"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS"};

struct pseudo_header
{
    uint8_t saddr[4];
    uint8_t daddr[4];
    uint8_t zero;
    uint8_t protocol;
    uint16_t tcp_header_length;
};

unsigned short checksum(unsigned short *buf, int size) {
    unsigned long sum = 0;
 
    while(size--)
        sum += *buf++;
 
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
 
    return (unsigned short)(~sum);
}

void forward_rst(unsigned char *buf, pcap_t *handle, int packetsize) 
{
    uint8_t* np = (uint8_t *)malloc(packetsize);
    memcpy(np, buf, packetsize);
    
    uint8_t *ptr;
    uint8_t *etn_ptr = ptr = np;
	uint8_t *ip_ptr =  ptr = etn_ptr + 14;
	int ip_header_len = (*(ip_ptr) & 0b00001111) * 4;
    int ip_total_len = *(ip_ptr+2) * 256 + *(ip_ptr+3);

    uint8_t *tcp_ptr = ptr = ip_ptr + ip_header_len;
    int tcp_header_len = (*(ptr + 12) >> 4) * 4;

    int tcp_seg_size = ip_total_len - ip_header_len - tcp_header_len;

 
    // rst check
    *(tcp_ptr + 13) |= 0b00000100;
    // reset checksum
    *(tcp_ptr + 16) = *(tcp_ptr + 17) = 0;

    // tcp checksum
    // build pseudo header
    struct pseudo_header *phdr = (struct pseudo_header *)malloc(sizeof(struct pseudo_header));
    for (int i = 0; i < 4; i++) 
    {
        phdr->saddr[i] = *(ip_ptr + 12 + i);
        phdr->daddr[i] = *(ip_ptr + 16 + i);
    }
    phdr->zero = 0;
    phdr->protocol = 6;
    phdr->tcp_header_length = htons(tcp_header_len);

    uint8_t *t;
    uint32_t tsize;

    tsize = sizeof(struct pseudo_header) + tcp_header_len + tcp_seg_size;
    t = (uint8_t *)malloc(tsize);
    memcpy(t, phdr, sizeof(struct pseudo_header));
    memcpy(t + sizeof(struct pseudo_header), tcp_ptr, (tcp_header_len+tcp_seg_size));


    uint16_t cs = checksum(t, tsize);
    *(tcp_ptr + 16) = *(uint8_t *)&cs;
    *(tcp_ptr + 17) = *(((uint8_t *)&cs) + 1);
 
    if (pcap_sendpacket(handle, np, packetsize) != 0) {
		printf("Error sending packet\n");
		return -1;
	}

    free(np);
    free(t);
}

void backward_fin(unsigned char *buf, pcap_t *handle, int packetsize) 
{
    uint8_t* np = (uint8_t *)malloc(packetsize);
    memcpy(np, buf, packetsize);
    
    uint8_t *ptr;
    uint8_t *etn_ptr = ptr = np;

    // swap mac
    for (int i = 0; i < 6; i++) {
        *(ptr+i) ^= *(ptr+6+i);
        *(ptr+6+i) ^= *(ptr+i);
        *(ptr+i) ^= *(ptr+6+i);
    }

	uint8_t *ip_ptr =  ptr = etn_ptr + 14;
	int ip_header_len = (*(ip_ptr) & 0b00001111) * 4;
    int ip_total_len = *(ip_ptr+2) * 256 + *(ip_ptr+3);

    // swap ip
    ptr += 12;
    for (int i = 0; i < 4; i++) {
        *(ptr+i) ^= *(ptr+4+i);
        *(ptr+4+i) ^= *(ptr+i);
        *(ptr+i) ^= *(ptr+4+i);
    }

    uint8_t *tcp_ptr = ptr = ip_ptr + ip_header_len;
    int tcp_header_len = (*(ptr + 12) >> 4) * 4;

    int tcp_seg_size = ip_total_len - ip_header_len - tcp_header_len;

    // port swap
    for (int i = 0; i < 2; i++) {
        *(ptr+i) ^= *(ptr+2+i);
        *(ptr+2+i) ^= *(ptr+i);
        *(ptr+i) ^= *(ptr+2+i);
    }

    // seq ack swap
    ptr += 4;
    // ack add tcp seg len -> no seg + 0
    *(int *)ptr = htonl(ntohl(*(int *)ptr) + 0);
    for (int i = 0; i < 4; i++) {
        *(ptr+i) ^= *(ptr+4+i);
        *(ptr+4+i) ^= *(ptr+i);
        *(ptr+i) ^= *(ptr+4+i);
    }

 
    // fin check
    *(tcp_ptr + 13) |= 0b00000001;
    // reset checksum
    *(tcp_ptr + 16) = *(tcp_ptr + 17) = 0;

    // tcp checksum
    // build pseudo header
    struct pseudo_header *phdr = (struct pseudo_header *)malloc(sizeof(struct pseudo_header));
    for (int i = 0; i < 4; i++) 
    {
        phdr->saddr[i] = *(ip_ptr + 12 + i);
        phdr->daddr[i] = *(ip_ptr + 16 + i);
    }
    phdr->zero = 0;
    phdr->protocol = 6;

    phdr->tcp_header_length = htons(tcp_header_len);

    uint8_t *t;
    uint32_t tsize;

    tsize = sizeof(struct pseudo_header) + tcp_header_len; //  + tcp_seg_size no payload
    t = (uint8_t *)malloc(tsize);
    memcpy(t, phdr, sizeof(struct pseudo_header));
    memcpy(t + sizeof(struct pseudo_header), tcp_ptr, (tcp_header_len));

    uint16_t cs = checksum(t, tsize);

    *(tcp_ptr + 16) = *(uint8_t *)&cs;
    *(tcp_ptr + 17) = *(((uint8_t *)&cs) + 1);
 
    if (pcap_sendpacket(handle, np, packetsize - tcp_seg_size) != 0) {
		printf("Error sending packet\n");
		return -1;
	}

    free(np);
    free(t);
}

uint32_t filter_host(unsigned char* buf, int size) {

	uint8_t *ptr;

    // Ethernet Header: dst mac / src mac / IP Check (IPv4 (0x0800))
	uint8_t *etn_ptr = ptr = buf;
	// dst mac
	printf("Destination MAC: ");
	for (int i = 0; i < 6; i++) printf("%02x:", *(ptr++)); printf("\n");
	// src mac
	printf("Source MAC: ");
	for (int i = 0; i < 6; i++) printf("%02x:", *(ptr++)); printf("\n");
	// IP Check (IPv4 (0x08 00))
	if (*(ptr++) == 0x08 && *(ptr++) == 0x00) printf("Type: IPv4\n");
    else return 0;

	// IP Header: TCP Check / src ip / dst ip (TCP (6))
	uint8_t *ip_ptr = ptr = etn_ptr + 14;
	int ip_header_len = (*(ip_ptr) & 0b00001111) * 4;
	int ip_total_len = *(ip_ptr+2) * 256 + *(ip_ptr+3);
	// TCP Check (TCP (6))
	if (*(ptr+=9) == 0x06) {
		printf("\nProtocol: TCP\n");
		// src ip
		ptr += 3;
		printf("Source IP: ");
		for (int i = 0; i < 4; i++) printf("%d.", *(ptr++)); printf("\n");
		// dst ip
		printf("Destination IP: ");
		for (int i = 0; i < 4; i++) printf("%d.", *(ptr++)); printf("\n");
	}
	else return 0;

	// TCP Header: src port / dst port / Payload check (TCP Segment Len)
	uint8_t *tcp_ptr = ptr = ip_ptr + ip_header_len;
	int tcp_header_len = (*(ptr + 12) >> 4) * 4;
	// src port
	printf("Source Port: %d\n", *(ptr++) * 256 + *(ptr++));
	// dst port
	printf("Destination Port: %d\n", *(ptr++) * 256 + *(ptr++));
	// Payload check (TCP Segment Len)
	// TCP Payload Segment Size = IP total length - IP header length - TCP header len
 	int tcp_seg_size = ip_total_len - ip_header_len - tcp_header_len;
	printf("TCP Payload Segment Size: %d\n", tcp_seg_size);

	// Payload hexa decimal value (32 bytes)
	uint8_t *payload_ptr = tcp_ptr + tcp_header_len;
	if (tcp_seg_size) {
		ptr = strtok(payload_ptr, "\r\n");
		if (ptr != NULL) {
			int i = 0;
			int http_request_flag = 0;
			for (; i < 6; i++) {
				if(!strncmp(ptr, HTTP_METHOD[i], strlen(HTTP_METHOD[i]))) {
					http_request_flag = 1;
					break;
				}
			}
			if (http_request_flag) printf("HTTP Method: %s\n", HTTP_METHOD[i]);
			else return 0;

			ptr = strtok(NULL, "\r\n");
			if (ptr != NULL) {
				ptr = strtok(ptr, ": ");
				uint8_t *http_host = strtok(NULL, ": ");
				printf("HTTP Host: %s\n", http_host);

				// filtering packet by hostname
				if(!strncmp(http_host, hostname, strlen(hostname))) {
					return 1;
				}
			}
		}
	}
	return 0;
}


int main(int argc, char* argv[]) 
{
    if (argc != 3) {
        printf("syntax : tcp_block <interface> <host>\n");
        printf("sample : tcp_block wlan0 test.gilgil.net\n");
        return 0;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    hostname = argv[2];

    while (1) {
        struct pcap_pkthdr* header;
        unsigned char *packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        // filter_host(packet, header->len);

        if(filter_host(packet, header->len)) 
        {   
            forward_rst(packet, handle, header->len);
            backward_fin(packet, handle, header->len);
        } 
    } 
	
    pcap_close(handle);
    return 0;
}