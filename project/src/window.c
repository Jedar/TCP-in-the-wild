#include "window.h"
#include "cmu_packet.h"
#include <time.h>
#include <sys/time.h>
#include <stdio.h>
#include <signal.h>

#define RESEND_TIME 4

static void recv_start(void *ptr);
static void deliver_data(cmu_socket_t *sock, char *pkt, int data_len);
static void slide_window_handle_message(slide_window_t * win, cmu_socket_t *sock, char* pkt);
static void resend(slide_window_t * win);
static void time_out(int sig, void *ptr);

/* 设置计时 */
void set_timer(int sec, int usec, void (*handler)(int)){
    /* 设置时间到达后的处理函数,注意这里占用了SIGALRM信号 */
    // printf("timer set\n");
    signal(SIGALRM,handler);
    struct itimerval itv;
    itv.it_interval.tv_sec=0;//自动装载，之后每10秒响应一次
    itv.it_interval.tv_usec=0;
    itv.it_value.tv_sec=5;//第一次定时的时间
    itv.it_value.tv_usec=0;
    setitimer(ITIMER_REAL,&itv,NULL);
}

/* 关闭计时 */
void unset_timer(){
    /* 设置回默认信号处理方式，也可以屏蔽信号 */
    // printf("unset timer\n");
    signal(SIGALRM,SIG_DFL);
    struct itimerval itv;
    itv.it_interval.tv_sec=0;//设置为0
    itv.it_interval.tv_usec=0;
    itv.it_value.tv_sec=0;
    itv.it_value.tv_usec=0;
    setitimer(ITIMER_REAL,&itv,NULL);
}

/* 初始化一个滑窗 */
int slide_window_init(slide_window_t *win,  
					uint32_t last_seq_received,  
					uint32_t last_ack_received,  
					size_t sdsz,size_t rcsz){
    win->last_ack_received = last_ack_received;
    win->last_seq_received = last_seq_received;
    win->EXP = last_seq_received;
    pthread_mutex_init(&(win->ack_lock), NULL);
    pthread_mutex_init(&(win->timer_lock), NULL);
    win->dup_ack_num = 0;
    win->SWS=sdsz;
    win->RWS=rcsz;
    win->send_buffer = (sendQ_slot *)calloc(sdsz,sizeof(sendQ_slot));  /* 发送缓冲区 */
    win->recv_buffer = (recvQ_slot *)calloc(rcsz,sizeof(recvQ_slot));  /* 发送缓冲区 */
	if(sem_init(&win->sendlock,0,sdsz)!=0){    // 此处初始信号量设为sdsz. 第2个参数为0表示不应用于其他进程。
    	fprintf(stdout,"sem_init is wrong\n");
		return EXIT_FAILURE;
    }	
    /* 创建一个用于接收数据的子线程 */
    // if(pthread_create(&win->recv_thread, NULL, (void *)recv_start, &win) != 0) {
	// 	fprintf(stdout,"thread creation failed\n");
	// 	return EXIT_FAILURE;
	// }
    /* 初始化信号处理函数，以便超时能够访问window */
    time_out(0,win);
    return EXIT_SUCCESS;
}

void slide_window_send(slide_window_t *win, cmu_socket_t *sock, char *data, int len){
    // fprintf(stdout,"slide window send:%s\n",data);
    // fflush(stdout);
	/* 每一次发送的UDP包 */
	char* msg;
    /* 用于堵塞SIGALRM信号，防止信号影响发包 */
    sigset_t mask;
    sigemptyset(&mask); /*将信号集合设置为空*/
    sigaddset(&mask,SIGALRM);/*加入中断SIGALRM信号*/
	int sockfd=sock->socket, plen;
	size_t conn_len = sizeof(sock->conn);
	/* 当前发送的序列号 */
	uint32_t ack;
    win->dup_ack_num = 0;
    win->LAR = 0;
    win->LFS = 0;
    win->timer_flag = 0;
    /* 没有数据或者数据长度出错，直接返回 */
    if(len <= 0){
        return;
    }
    /* 当前数据发送位置 */
    int data_idx = 0;
    /* 当前打包的seq */
    uint32_t mkpkt_seq = win->last_ack_received;
    uint32_t last_seq = win->last_ack_received + len;
    /* 所有数据是否全部发送 */
    uint8_t finish = 0;
    /* 如果还有包没有被收到 */
    while(!finish){
        while(pthread_mutex_lock(&(win->ack_lock)) !=  0);
        /* 判断是否所有的包已经被接收到 */
        finish = (data_idx == len && win->last_ack_received == last_seq);
        
        // printf("send flag[%d,%d,%d,%d]\n",data_idx,len,win->last_ack_received,last_seq);
        ack = win->last_seq_received;
        pthread_mutex_unlock(&(win->ack_lock));
        /* 如果已经结束,跳出循环（这是必须的，但是可以优化） */
        if(finish){
            break;
        }
        /* 堵塞超时信号，防止超时信号干扰当前的发送 */
        sigprocmask(0 /* SIG_BLOCK */ ,&mask,NULL);
        /* 如果数据已经全部发送了，等待ACK或者超时 */
        if(data_idx >= len&&win->send_buffer[(win->LFS-1)%win->SWS].used){
            // fprintf(stdout,"sleep(%d,%d)...\n",data_idx,len);
            sleep(1);
        }
        /* 还有数据可以发送,并且信号量大于0 */
        else if(sem_trywait(&win->sendlock) == 0){
            /* 检查窗口,如果满了则等待ACK或者超时 */
            int val;
            sem_getvalue(&win->sendlock,&val);
            // fprintf(stdout,"sem wait%d...\n",val);
            // fflush(stdout);
            /* 如果缓存中有数据 */
            if(win->send_buffer[win->LFS%win->SWS].used){
                msg = win->send_buffer[win->LFS%win->SWS].msg;
                /* ack num可能已经修改过 */
                set_ack(msg,ack);
            }
            /* 如果缓存中没有数据，需要构造包 */
            else{
                // printf("construct msg...\n");
                // fflush(stdout);
                int buf_len = len - data_idx;
                if(buf_len <= MAX_DLEN){
                    plen = DEFAULT_HEADER_LEN + buf_len;
                    msg = create_packet_buf(sock->my_port, sock->their_port, 
                        mkpkt_seq, ack, 
                        DEFAULT_HEADER_LEN, plen, NO_FLAG, 1, 0, NULL, data+data_idx, buf_len);
                    data_idx += buf_len;
                    mkpkt_seq += buf_len;
                }
                else{  /* 如果包太长,分多次发送,每次只发送最大包长 */
                    plen = DEFAULT_HEADER_LEN + MAX_DLEN;
                    msg = create_packet_buf(sock->my_port, sock->their_port,
                        mkpkt_seq, ack, 
                        DEFAULT_HEADER_LEN, plen, NO_FLAG, 1, 0, NULL, data+data_idx, MAX_DLEN);
                    data_idx += MAX_DLEN;
                    mkpkt_seq += MAX_DLEN;
                }
                win->send_buffer[win->LFS%win->SWS].msg = msg;
                win->send_buffer[win->LFS%win->SWS].used = 1;
            }
            /* 发送指针后移 */
            win->LFS++;

            sigprocmask(1 /* SIG_UNBLOCK */ ,&mask,NULL);
            /* 发送UDP的包 */
            sendto(sock->socket, msg, plen, 0, (struct sockaddr*) &(sock->conn), conn_len);
            // printf("send flag[idx %d,len %d,%d,%d]\n",data_idx,len,win->last_ack_received,last_seq);
            // printf("send over [seq: %d, ack: %d, length: %d]\n",get_seq(msg),get_ack(msg),get_plen(msg));
            // fflush(stdout);
            /* 设置时钟 */
            if(!win->timer_flag){
                // fprintf(stdout,"send set timer\n");
                // fflush(stdout);
                set_timer(RESEND_TIME,0,(void (*)(int))time_out);
                win->timer_flag = 1;
            }
        }
        slide_window_check_for_data(win,sock,NO_WAIT);
    }
    // printf("finish...\n");
    // fflush(stdout);
}

static void recv_start(void *ptr){
    cmu_socket_t *sock = (cmu_socket_t*)ptr;
    slide_window_t *win = &(sock->window);
    win->EXP = 0;
    /* 一直监听是否有数据收到 */

    while(1){
        /* 处理收到的数据 */
        slide_window_check_for_data(win,sock,TIMEOUT);
        sleep(0);
    }
    pthread_exit(NULL); 
	return; 
}

/* 调用前需要确保上锁 */
static void deliver_data(cmu_socket_t *sock, char *pkt, int data_len){
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

/* 处理数据 */
static void slide_window_handle_message(slide_window_t * win, cmu_socket_t *sock, char* pkt){
    // fprintf(stdout,"handle: %s,[%d(lack),%d(lseq)]\n",pkt+DEFAULT_HEADER_LEN,win->last_ack_received,win->last_seq_received);
    fflush(stdout);
    char* rsp;
	/* 标志位 */
	uint8_t flags = get_flags(pkt);
	uint32_t data_len, seq, ack, buffer_offset, msg_exp_ack;
	socklen_t conn_len = sizeof(sock->conn);
    ack = get_ack(pkt);
    seq = get_seq(pkt);
	switch(flags){
		case ACK_FLAG_MASK: /* 处理发送者接收到ACK */
            while(pthread_mutex_lock(&(win->ack_lock)) !=  0){};
            /* 一个发送的包期待收到的seq值（即包发送的seq+包长） */
            msg_exp_ack = get_seq(win->send_buffer[win->LAR%win->SWS].msg) + \
                        get_plen(win->send_buffer[win->LAR%win->SWS].msg) - \
                        DEFAULT_HEADER_LEN;
			if(win->send_buffer[win->LAR%win->SWS].used && ack >= msg_exp_ack){ /* 如果ack的值为期待的 */
                // printf("handle ACK[%d(seq),%d(ack)]\n",seq,ack);
                // fflush(stdout);
				win->last_ack_received = ack; /* 设置为新值 */
                win->last_seq_received = seq;
                win->seq_expect = seq;
                /* 由于累计确认机制，滑窗后移到累计接收的位置 */
                while((ack >= msg_exp_ack) && (win->LAR<=win->LFS-1)){
                    /* 滑窗后移一格 */
                    win->send_buffer[win->LAR%win->SWS].used = 0;
                    /* 信号量加一 */
                    sem_post(&(win->sendlock));
                    msg_exp_ack = get_seq(win->send_buffer[win->LAR%win->SWS].msg)\
                             + get_plen(win->send_buffer[win->LAR%win->SWS].msg)\
                             - DEFAULT_HEADER_LEN;
                    /* 释放已经接收到的数据 */
                    free(win->send_buffer[win->LAR%win->SWS].msg);
                    /* 滑窗后移 */
                    win->LAR++;
                }
                /* 重置计时器 */
                unset_timer();
                /* 缓存中还有包没接收 */
                if((win->LAR%win->SWS) != (win->LFS%win->SWS)){
                    // fprintf(stdout,"handle msg set timer: %d(LAR) %d(LFS)\n",win->LAR,win->LFS);
                    // fflush(stdout);
                    set_timer(RESEND_TIME,0,(void (*)(int))time_out);
                    win->timer_flag = 1;
                }
            }
            else{  /* 收到错序的ACK */
                // printf("handle msg: out of order\n");
                // fflush(stdout);
                win->dup_ack_num++;
                if(win->dup_ack_num == 3){
                    resend(win);
                }
            }
            pthread_mutex_unlock(&(win->ack_lock));
            break;
        case FIN_FLAG_MASK: /* 包含FIN */
            fprintf(stdout,"recv FIN\n");
            break;
		default:
            /* 如果收到的是期待的包 */
			if(seq == win->seq_expect){
                // printf("handle: accept msg\n");
                // fflush(stdout);
                /* seq可能小于上一个包的值 */
                if(win->last_seq_received < seq){
                    win->last_seq_received = seq;
                }
                if(win->last_ack_received < ack){
                    win->last_ack_received = ack; /* 设置为新值 */
                }
                /* 将期待的包设为收到状态 */
                win->recv_buffer[win->EXP%win->RWS].recv_or_not = 1;
                /* 将包复制到缓冲区 */
                win->recv_buffer[win->EXP%win->RWS].msg = pkt;
                /* 由于缓冲区可能已经储存了错序的pkt，所以直接复用那些pkt */
                while(win->recv_buffer[win->EXP%win->RWS].recv_or_not){
                    data_len = get_plen(pkt) - DEFAULT_HEADER_LEN;
                    ack = get_seq(win->recv_buffer[win->EXP%win->RWS].msg);
                    /* 把正确顺序的包发给上层 */
                    deliver_data(sock,win->recv_buffer[win->EXP%win->RWS].msg,data_len);
                    win->recv_buffer[win->EXP%win->RWS].recv_or_not = 0;
                    win->seq_expect += data_len;
                    win->EXP++;
                }
                /* 发送只有头部的包（ACK） */
                // fprintf(stdout,"handle send ACK[%d(seq),%d(ack)]\n",win->last_ack_received,win->seq_expect);
                // fflush(stdout);
                rsp = create_packet_buf(sock->my_port, ntohs(sock->conn.sin_port),
                    win->last_ack_received, win->seq_expect, 
                    DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, ACK_FLAG_MASK, 1, 0, NULL, NULL, 0);
                /* 发送ACK确认包 */
                sendto(sock->socket, rsp, DEFAULT_HEADER_LEN, 0, (struct sockaddr*) 
                    &(sock->conn), conn_len);
                free(rsp);
                /* 通知上层可以读取数据 */
                pthread_cond_signal(&(sock->wait_cond));  
            }
            /* 如果是错序的包 */
            else{
                printf("handle: not accept msg(%d(seq),%d(exp))\n",seq,win->seq_expect);
                fflush(stdout);
                seq = get_seq(pkt);
                /* 计算需要包应该处在的位置 */
                buffer_offset = (seq - win->seq_expect)/MAX_LEN;
                win->recv_buffer[(win->EXP+buffer_offset)%win->RWS].msg = pkt;
                win->recv_buffer[(win->EXP+buffer_offset)%win->RWS].recv_or_not = 1;
            }
			break;
	}
}

static void resend(slide_window_t * win){
    win->timer_flag = 0;
    win->LFS = win->LFS;
    printf("resending.......done\n");
}

/* 与backend的check类似，但是只判断是否有数据到达并不读取数据 */
/* 返回值为收到数据的长度 */
void slide_window_check_for_data(slide_window_t * win, cmu_socket_t *sock, int flags){
    char hdr[DEFAULT_HEADER_LEN];
	socklen_t conn_len = sizeof(sock->conn);
	ssize_t len = 0;
	uint32_t plen = 0, buf_size = 0, n = 0;
    char *pkt;
	/* fd_set for select and pselect */
	fd_set ackFD;
	/* 3秒的超时时间 */
	struct timeval time_out;
	time_out.tv_sec = 1;
	time_out.tv_usec = 0;
	while(pthread_mutex_lock(&(sock->recv_lock)) != 0);
	switch(flags){
		case NO_FLAG:  /* 会堵塞直到数据收到，待确认 */
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
    if(len < DEFAULT_HEADER_LEN){
        /* 暂时没有收到有效数据 */
        // printf("###recv data error %d...\n",(int)len);
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
        slide_window_handle_message(win,sock,pkt);
    }
    pthread_mutex_unlock(&(sock->recv_lock));
}

/* 处理SIGALRM信号，即超时信号 */
static void time_out(int sig, void *ptr){
    static slide_window_t *win;
    /* 首次调用初始化win参数 */
    if(win == NULL){
        win = (slide_window_t *)ptr;
        return;
    }
    /* 正常的信号处理 */
    else{
        while(pthread_mutex_lock(&(win->timer_lock)) !=  0);
        win->LFS = win->LAR;
        win->timer_flag = 0;
        int val;
        sem_getvalue(&win->sendlock,&val);
        while(val < win->SWS){
            sem_post(&win->sendlock);
            val++;
        }
        fprintf(stdout,"-------time out------------\n");
        fflush(stdout);
        unset_timer();
        pthread_mutex_unlock(&(win->timer_lock));
    }
}

/* 关闭滑窗 */
void slide_window_close(slide_window_t *win){
    // pthread_kill(win->recv_thread, SIGINT);
    /* 等待接收线程结束 */
    // pthread_join(win->recv_thread,NULL);
    /* 将信号处理函数转为默认值 */
    signal(SIGALRM,SIG_DFL);
    if(win->send_buffer != NULL){
        free(win->send_buffer);
        win->send_buffer = NULL;
    }
    if(win->recv_buffer != NULL){
        free(win->recv_buffer);
        win->recv_buffer = NULL;
    }
    sem_destroy(&win->sendlock); 
}

