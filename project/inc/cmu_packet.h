#ifndef _CMU_PACKET_H_
#define _CMU_PACKET_H_

#include <netinet/in.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "global.h"
#include "grading.h"


typedef struct {
	uint32_t identifier;   		//4 bytes
	uint16_t source_port;		//2 bytes
	uint16_t destination_port;	//2 bytes
	uint32_t seq_num; 			//4 bytes
	uint32_t ack_num; 			//4 bytes
	uint16_t hlen;				//2 bytes //header length
	uint16_t plen;				//2 bytes //packet length
	uint8_t flags;				//1 byte
	uint16_t advertised_window; //2 bytes
	uint16_t extension_length;  //2 bytes
	char* extension_data;	    //X bytes
} cmu_header_t;

typedef struct {
	cmu_header_t header;
	struct timeval sent_time;
	char* data;
} cmu_packet_t;

	

#define SYN_FLAG_MASK 0x8
#define ACK_FLAG_MASK 0x4
#define FIN_FLAG_MASK 0x2
#define IDENTIFIER 15441
#define DEFAULT_HEADER_LEN 25


char* set_headers(uint16_t src, uint16_t dst, uint32_t seq, uint32_t ack,
    uint16_t hlen, uint16_t plen, uint8_t flags, uint16_t adv_window, 
    uint16_t ext, char* ext_data);

cmu_packet_t* create_packet(uint16_t src, uint16_t dst, uint32_t seq, 
    uint32_t ack, uint16_t hlen, uint16_t plen, uint8_t flags, 
    uint16_t adv_window, uint16_t ext, char* ext_data, char* data, int len);

char* create_packet_buf(uint16_t src, uint16_t dst, uint32_t seq, uint32_t ack,
    uint16_t hlen, uint16_t plen, uint8_t flags, uint16_t adv_window, 
    uint16_t ext, char* ext_data, char* data, int len);

char* packet_to_buf(cmu_packet_t* packet);
void free_packet(cmu_packet_t* packet);


uint16_t get_src(char* msg);
uint16_t get_dst(char* msg);
uint32_t get_seq(char* msg);
uint32_t get_ack(char* msg);
uint16_t get_hlen(char* msg);
uint16_t get_plen(char* msg);
uint8_t get_flags(char* msg);
uint16_t get_advertised_window(char* msg);
uint16_t get_extension_length(char* msg);

void set_seq(char *pkt, uint32_t val);
void set_ack(char *pkt, uint32_t val);


#endif
