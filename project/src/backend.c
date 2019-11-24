#include "backend.h"

/*
 * Param: sock - The socket to check for acknowledgements. 
 * Param: seq - Sequence number to check 
 *
 * Purpose: To tell if a packet (sequence number) has been acknowledged.
 *
 */
int check_ack(cmu_socket_t * sock, uint32_t seq){
	int result;
	while(pthread_mutex_lock(&(sock->window.ack_lock)) != 0);
	if(sock->window.last_ack_received > seq)
		result = TRUE;
	else
		result = FALSE;
	pthread_mutex_unlock(&(sock->window.ack_lock));
	return result;
}

/*
 * Param: sock - The socket used for handling packets received
 * Param: pkt - The packet data received by the socket
 *
 * Purpose: Updates the socket information to represent
 *  the newly received packet.
 *
 * Comment: This will need to be updated for checkpoints 1,2,3
 *
 */
void handle_message(cmu_socket_t * sock, char* pkt){
	char* rsp;
	/* 标志位 */
	uint8_t flags = get_flags(pkt);
	uint32_t data_len, seq;
	socklen_t conn_len = sizeof(sock->conn);
	switch(flags){
		case ACK_FLAG_MASK: /* 包含ACK */
			if(get_ack(pkt) > sock->window.last_ack_received) /* 如果ack的值大于上次收到的值 */
				sock->window.last_ack_received = get_ack(pkt); /* 设置为新值 */
			break;
		default:
			seq = get_seq(pkt); /* 检查对方收到的序列 */
			/* 发送只有头部的包（ACK） */
			rsp = create_packet_buf(sock->my_port, ntohs(sock->conn.sin_port), seq, seq+1, 
				DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, ACK_FLAG_MASK, 1, 0, NULL, NULL, 0);
			/* 发送UDP包 */
			sendto(sock->socket, rsp, DEFAULT_HEADER_LEN, 0, (struct sockaddr*) 
				&(sock->conn), conn_len);
			free(rsp);

			if(seq > sock->window.last_seq_received || (seq == 0 && 
				sock->window.last_seq_received == 0)){
				
				sock->window.last_seq_received = seq;
				data_len = get_plen(pkt) - DEFAULT_HEADER_LEN;
				/* 创建接收数据的空间 */
				if(sock->received_buf == NULL){
					sock->received_buf = malloc(data_len);
				}
				else{
					sock->received_buf = realloc(sock->received_buf, sock->received_len + data_len);
				}
				/* 将packet的数据拷贝到socket的结构中去 */
				memcpy(sock->received_buf + sock->received_len, pkt + DEFAULT_HEADER_LEN, data_len);
				sock->received_len += data_len;
			}

			break;
	}
}

/*
 * Param: sock - The socket used for receiving data on the connection.
 * Param: flags - Signify different checks for checking on received data.
 *  These checks involve no-wait, wait, and timeout.
 *
 * Purpose: To check for data received by the socket. 
 *
 */
void check_for_data(cmu_socket_t * sock, int flags){
	/* 储存包头部信息 */
	char hdr[DEFAULT_HEADER_LEN];
	char* pkt;
	socklen_t conn_len = sizeof(sock->conn);
	ssize_t len = 0;
	uint32_t plen = 0, buf_size = 0, n = 0;
	/* fd_set for select and pselect */
	fd_set ackFD;
	/* 3秒的超时时间 */
	struct timeval time_out;
	time_out.tv_sec = 3;
	time_out.tv_usec = 0;


	while(pthread_mutex_lock(&(sock->recv_lock)) != 0);
	switch(flags){
		case NO_FLAG:  /* 与不等待类似 */
			len = recvfrom(sock->socket, hdr, DEFAULT_HEADER_LEN, MSG_PEEK,
								(struct sockaddr *) &(sock->conn), &conn_len);
			break;
		case TIMEOUT: /* 注意没有break */
			/* 设置非堵塞等待 */
			FD_ZERO(&ackFD);
			FD_SET(sock->socket, &ackFD);
			/* 等待设定时间直到socket收到信息，如果时间内没有返回则break */
			if(select(sock->socket+1, &ackFD, NULL, NULL, &time_out) <= 0){
				break;
			}
		case NO_WAIT:
			len = recvfrom(sock->socket, hdr, DEFAULT_HEADER_LEN, MSG_DONTWAIT | MSG_PEEK,
							 (struct sockaddr *) &(sock->conn), &conn_len);
			break;
		default:
			perror("ERROR unknown flag");
	}
	if(len >= DEFAULT_HEADER_LEN){
		plen = get_plen(hdr);
		pkt = malloc(plen);
		/* 直到包的信息全部收到 */
		while(buf_size < plen ){
				n = recvfrom(sock->socket, pkt + buf_size, plen - buf_size, 
					NO_FLAG, (struct sockaddr *) &(sock->conn), &conn_len);
			buf_size = buf_size + n;
		}
		/* 将收到的数据（pkt）储存在socket中 */
		handle_message(sock, pkt);
		free(pkt);
	}
	pthread_mutex_unlock(&(sock->recv_lock));
}

/*
 * Param: sock - The socket to use for sending data
 * Param: data - The data to be sent
 * Param: buf_len - the length of the data being sent
 *
 * Purpose: Breaks up the data into packets and sends a single 
 *  packet at a time.
 *
 * Comment: This will need to be updated for checkpoints 1,2,3
 *
 */
void single_send(cmu_socket_t * sock, char* data, int buf_len){
		char* msg;
		char* data_offset = data;
		int sockfd, plen;
		size_t conn_len = sizeof(sock->conn);
		uint32_t seq;

		sockfd = sock->socket; 
		if(buf_len > 0){
			/* 循环直到所有的包发送完毕 */
			while(buf_len != 0){
				seq = sock->window.last_ack_received;
				if(buf_len <= MAX_DLEN){/* 包长 */
					plen = DEFAULT_HEADER_LEN + buf_len;
					msg = create_packet_buf(sock->my_port, sock->their_port, seq, seq, 
						DEFAULT_HEADER_LEN, plen, NO_FLAG, 1, 0, NULL, data_offset, buf_len);
					buf_len = 0;
				}
				else{  /* 如果包太长 */
					plen = DEFAULT_HEADER_LEN + MAX_DLEN;
					msg = create_packet_buf(sock->my_port, sock->their_port, seq, seq, 
						DEFAULT_HEADER_LEN, plen, NO_FLAG, 1, 0, NULL, data_offset, MAX_DLEN);
					/* 分多次发送 */
					buf_len -= MAX_DLEN;
				}
				while(TRUE){
					/* 把UDP的包发过去 */
					sendto(sockfd, msg, plen, 0, (struct sockaddr*) &(sock->conn), conn_len);
					/* 超时重发，收到3次ACK马上重发需要修改的位置 */
					check_for_data(sock, TIMEOUT);
					/* 确认包是否收到 */
					if(check_ack(sock, seq))
						break;
				}
				data_offset = data_offset + plen - DEFAULT_HEADER_LEN;
			}
		}
}

/*
 * Param: in - the socket that is used for backend processing
 *
 * Purpose: To poll in the background for sending and receiving data to
 *  the other side. 
 *
 */
void* begin_backend(void * in){
	cmu_socket_t * dst = (cmu_socket_t *) in;
	int death, buf_len, send_signal;
	char* data;

	/* TODO: TCP hand shake here */

	while(TRUE){
		while(pthread_mutex_lock(&(dst->death_lock)) !=  0);
		death = dst->dying;
		pthread_mutex_unlock(&(dst->death_lock));
		
		while(pthread_mutex_lock(&(dst->send_lock)) != 0);
		buf_len = dst->sending_len;

		if(death && buf_len == 0)
			break;

		if(buf_len > 0){
			data = malloc(buf_len);
			memcpy(data, dst->sending_buf, buf_len);
			dst->sending_len = 0;
			free(dst->sending_buf);
			dst->sending_buf = NULL;
			pthread_mutex_unlock(&(dst->send_lock));
			single_send(dst, data, buf_len);
			free(data);
		}
		else
			pthread_mutex_unlock(&(dst->send_lock));

		/* 检查recv数据 */
		check_for_data(dst, NO_WAIT);
		
		while(pthread_mutex_lock(&(dst->recv_lock)) != 0);
		
		if(dst->received_len > 0)
			send_signal = TRUE;
		else
			send_signal = FALSE;
		pthread_mutex_unlock(&(dst->recv_lock));
		
		if(send_signal){
			/* 这里没懂 */
			pthread_cond_signal(&(dst->wait_cond));  
		}
	}
	pthread_exit(NULL); 
	return NULL; 
}

/* 暂定成功返回0，失败返回1，注意对发送者和接收者应该有不同的处理 */
int TCP_handshake(cmu_socket_t *socket){
	/* 注意当第三次握手失败时的处理操作: */
	/* 可以看出当失败时服务器并不会重传ack报文 */ 
	/* 而是直接发送RTS报文段，进入CLOSED状态。*/
	/* 这样做的目的是为了防止SYN洪泛攻击。 */
	/* socket的type确定了发送者和接收者 */
}

/* 滑动窗口发送数据，使用GBN的策略，替代原来的single_send函数 */
void TCP_GBN_send(cmu_socket_t * sock, char* data, int buf_len){

}


