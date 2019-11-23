#include "cmu_packet.h"

/*
 * Param: src - Source port
 * Param: dst - Destination port
 * Param: seq - Sequence Number
 * Param: ack - Acknowledgement Number
 * Param: hlen - Header Length
 * Param: plen - Packet Length
 * Param: flags - Packet Flags
 * Param: Adv_window - Advertised Window
 * Param: ext - Header Extension Length
 * Param: ext_data - Header Extension Data
 *
 * Purpose: To handle setting all of the packet header information in
 *  the current endianness for network transport.
 *
 * Return: A pointer to the buffer containing the headers with length plen.
 *
 * Comment: Review TCP headers for more information.
 *  http://telescript.denayer.wenk.be/~hcr/cn/idoceo/tcp_header.html
 *
 */
char* set_headers(uint16_t src, uint16_t dst, uint32_t seq, uint32_t ack,
    uint16_t hlen, uint16_t plen, uint8_t flags, uint16_t adv_window, 
    uint16_t ext, char* ext_data){

	char* msg;
	uint16_t temp16;
    uint32_t temp32;
    int index = 0;
    msg = (char*) calloc(plen, sizeof(char));
    
    temp32 = htonl(IDENTIFIER);
    memcpy(msg, &temp32, SIZE32);
    index += SIZE32;
    temp16 = htons(src);
    memcpy(msg+index, &temp16, SIZE16);
    index += SIZE16;
    temp16 = htons(dst);
    memcpy(msg+index, &temp16, SIZE16);
    index += SIZE16;
    temp32 = htonl(seq);
    memcpy(msg+index, &temp32, SIZE32);
    index += SIZE32;
    temp32 = htonl(ack);
    memcpy(msg+index, &temp32, SIZE32);
    index += SIZE32;
    temp16 = htons(hlen);
    memcpy(msg+index, &temp16, SIZE16);
    index += SIZE16;
    temp16 = htons(plen);
    memcpy(msg+index, &temp16, SIZE16);
    index += SIZE16;
    memcpy(msg+index, &flags, SIZE8);
    index += SIZE8;
    temp16 = htons(adv_window);
    memcpy(msg+index, &temp16, SIZE16);
    index += SIZE16;


    temp16 = htons(ext);
    memcpy(msg+index, &temp16, SIZE16);
    index += SIZE16;


    if(ext > 0)
        memcpy(msg+index, ext_data, ext);
    

	return msg;
}

/*
 * Param: p - A packet for network communications
 *
 * Purpose: To construct the buffer representation of the given packet.
 *
 * Return: Returns a buffer of length p->plen, that contains the information
 *  of the packet.
 *
 */
char* packet_to_buf(cmu_packet_t* p){
    char* msg = set_headers(p->header.source_port, p->header.destination_port, 
        p->header.seq_num, p->header.ack_num, p->header.hlen, p->header.plen, 
        p->header.flags, p->header.advertised_window, 
        p->header.extension_length, p->header.extension_data);
    
    if(p->header.extension_length > 0)
        memcpy(msg+(DEFAULT_HEADER_LEN), p->header.extension_data, 
            p->header.extension_length);
    
    if(p->header.plen > p->header.hlen)
        memcpy(msg+(p->header.hlen), p->data, (p->header.plen - (p->header.hlen)));


    return msg;
}

/*
 * Param: src - Source port
 * Param: dst - Destination port
 * Param: seq - Sequence Number
 * Param: ack - Acknowledgement Number
 * Param: hlen - Header Length
 * Param: plen - Packet Length
 * Param: flags - Packet Flags
 * Param: Adv_window - Advertised Window
 * Param: ext - Header Extension Length
 * Param: ext_data - Header Extension Data
 * Param: data - Data attribute of packet
 * Param: len - Length of the data attribute
 *
 * Purpose: To create a packet representation of the provided parameters.
 *
 * Return: Returns the packet structure containing the provided information.
 *
 */
cmu_packet_t* create_packet(uint16_t src, uint16_t dst, uint32_t seq, 
    uint32_t ack, uint16_t hlen, uint16_t plen, uint8_t flags, 
    uint16_t adv_window, uint16_t ext, char* ext_data, char* data, int len){

    cmu_packet_t* new = malloc(sizeof(cmu_packet_t));

    new->header.identifier = IDENTIFIER;
    new->header.source_port = src;
    new->header.destination_port = dst;
    new->header.seq_num = seq;
    new->header.ack_num = ack;
    new->header.hlen = hlen;
    new->header.plen = plen;
    new->header.flags = flags;
    new->header.advertised_window = adv_window;
    new->header.extension_length = ext;
    if(ext > 0){
        new->header.extension_data = malloc(ext);
        memcpy(new->header.extension_data, ext_data, ext);
    }
    else
        new->header.extension_data = NULL;
    if(len > 0){
        new->data = malloc(len);
        new->data = memcpy(new->data, data, len);
    }
    else
        new->data = NULL;
    return new;
}

/*
 * Param: src - Source port
 * Param: dst - Destination port
 * Param: seq - Sequence Number
 * Param: ack - Acknowledgement Number
 * Param: hlen - Header Length
 * Param: plen - Packet Length
 * Param: flags - Packet Flags
 * Param: Adv_window - Advertised Window
 * Param: ext - Header Extension Length
 * Param: ext_data - Header Extension Data
 * Param: data - Data attribute of packet
 * Param: len - Length of the data attribute
 *
 * Purpose: To construct the buffer representation of a packet with the given information.
 *
 * Return: Returns a buffer of length plen, that contains the information
 *  of the packet.
 *
 */
char* create_packet_buf(uint16_t src, uint16_t dst, uint32_t seq, uint32_t ack,
    uint16_t hlen, uint16_t plen, uint8_t flags, uint16_t adv_window, 
    uint16_t ext, char* ext_data, char* data, int len){

    cmu_packet_t* temp;
    char* final;  

    temp = create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window, 
        ext, ext_data, data, len);

    final = packet_to_buf(temp);

    free_packet(temp);
    return final;
}

/*
 * Param: packet - the packet to free data from
 *
 * Purpose: To cleanup state preserved in the packet
 *
 */
void free_packet(cmu_packet_t* packet){
    if(packet->data != NULL)
         free(packet->data);
    if(packet->header.extension_data != NULL)
        free(packet->header.extension_data);
    free(packet);
}

/*
 * Param: msg - buffer representation of a packet
 *
 * Purpose: To get the source port sent by the packet.
 *
 * Return: The source port of the packet
 *
 */
uint16_t get_src(char* msg){
    int offset = 4;
    uint16_t var;
    memcpy(&var, msg+offset, SIZE16);
    return ntohs(var);
}

/*
 * Param: msg - buffer representation of a packet
 *
 * Purpose: To get the destination port sent by the packet.
 *
 * Return: The destination port of the packet
 *
 */
uint16_t get_dst(char* msg){
    int offset = 6;
    uint16_t var;
    memcpy(&var, msg+offset, SIZE16);
    return ntohs(var);
}

/*
 * Param: msg - buffer representation of a packet
 *
 * Purpose: To get the sequence number sent by the packet.
 *
 * Return: The sequence number of the packet
 *
 */
uint32_t get_seq(char* msg){
    int offset = 8;
    uint32_t var;
    memcpy(&var, msg+offset, SIZE32);
    return ntohl(var);
}

/*
 * Param: msg - buffer representation of a packet
 *
 * Purpose: To get the acknowledgment number sent by the packet.
 *
 * Return: The acknowledgment number of the packet
 *
 */
uint32_t get_ack(char* msg){
    int offset = 12;
    uint32_t var;
    memcpy(&var, msg+offset, SIZE32);
    return ntohl(var);
}

/*
 * Param: msg - buffer representation of a packet
 *
 * Purpose: To get the header length sent by the packet.
 *
 * Return: The header length of the packet
 *
 */
uint16_t get_hlen(char* msg){
    int offset = 16;
    uint16_t var;
    memcpy(&var, msg+offset, SIZE16);
    return ntohs(var);
}

/*
 * Param: msg - buffer representation of a packet
 *
 * Purpose: To get the packet length sent by the packet.
 *
 * Return: The packet length of the packet
 *
 */
uint16_t get_plen(char* msg){
    int offset = 18;
    uint16_t var;
    memcpy(&var, msg+offset, SIZE16);
    return ntohs(var);
}

/*
 * Param: msg - buffer representation of a packet
 *
 * Purpose: To get the flags sent by the packet.
 *
 * Return: The flags of the packet
 *
 */
uint8_t get_flags(char* msg){
    int offset = 20;
    uint8_t var;
    memcpy(&var, msg+offset, SIZE8);
    return var;
}

/*
 * Param: msg - buffer representation of a packet
 *
 * Purpose: To get the advertised window sent by the packet.
 *
 * Return: The advertised window of the packet
 *
 */
uint16_t get_advertised_window(char* msg){
    int offset = 21;
    uint16_t var;
    memcpy(&var, msg+offset, SIZE16);
    return ntohs(var);
}

/*
 * Param: msg - buffer representation of a packet
 *
 * Purpose: To get the extension length sent by the packet.
 *
 * Return: The extension length of the packet
 *
 */
uint16_t get_extension_length(char* msg){
    int offset = 23;
    uint16_t var;
    memcpy(&var, msg+offset, SIZE16);
    return ntohs(var);
}

