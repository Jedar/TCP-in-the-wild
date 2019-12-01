#ifndef _CMU_BACK_H_
#define _CMU_BACK_H_
#include "cmu_tcp.h"
#include "global.h"
#include "cmu_packet.h"
#include "window.h"

int check_ack(cmu_socket_t * dst, uint32_t seq);
char * check_for_data(cmu_socket_t * dst, int flags);
void * begin_backend(void * in);
int TCP_handshake(cmu_socket_t *sock);
#endif
