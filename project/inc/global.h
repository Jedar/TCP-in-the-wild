#include <pthread.h> /* pthread struct */
#include <stdint.h> 
#include <semaphore.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdio.h>
/* above add by YuJitao */
#include "grading.h"

#ifndef _GLOBAL_H_
#define _GLOBAL_H_

#define EXIT_SUCCESS 0
#define EXIT_ERROR -1
#define EXIT_FAILURE 1

#define SIZE32 4
#define SIZE16 2
#define SIZE8  1

#define NO_FLAG 0
#define NO_WAIT 1
#define TIMEOUT 2

#define TRUE 1
#define FALSE 0

#define MAX_BUFFER_SIZE (1<<15)

#define MAX_SEQ_NUM (1<<31)

#define MAX_RECV_SIZE 10000

typedef enum {
	TCP_CLOSED = 1,
	TCP_LISTEN = 2,
	TCP_SYN_RCVD = 3,
	TCP_SYN_SEND = 4,
	TCP_ESTABLISHED = 5,
	TCP_FIN_WAIT1 = 6,
	TCP_FIN_WAIT2 = 7, 
	TCP_CLOSING = 8,
	TCP_TIME_WAIT = 9,
	TCP_CLOSE_WAIT = 10,
	TCP_LAST_ACK = 11
} TCP_State;

/* 发送者的状态 */
typedef enum {
	SS_DEFAULT = 1,   /* 默认状态 */
	SS_TIME_OUT = 2,   /* 超时事件 */
	SS_RESEND = 3,   /* 重发事件 */
	SS_SEND_OVER = 4,  /* 当前数据发送完毕 */
	SS_WAIT_ACK = 6  /* 窗口满了，需要等待ACK */
} send_state;

/* 滑窗的下标 */
typedef uint32_t SWPSeq;  /* slide window protocol序列号 */

/* 滑窗接收窗口单位 */
typedef struct RecvQ_slot {
	uint8_t recv_or_not;
	char *msg;
	struct RecvQ_slot *next; /* 组织成链表的形式 */
} recvQ_slot;

/* 定义滑窗协议的窗口结构 */
typedef struct {
	uint32_t last_seq_received; /* 上一个seq序列 */
	uint32_t last_ack_received; /* 上一个ack序列 */
	uint32_t adv_window; /* 上次收到包的建议数据大小 */
	uint32_t my_adv_window; /* 本方的建议数据大小（每次checkdata时更新） */
    size_t SWS; /* send_window_size窗口大小 */
	size_t RWS; /* recv_window_size窗口大小 */
	send_state stat;  /* 发送方所处的状态 */
	SWPSeq LAR; /* last ack recv */ /* |----------LAR+++++++++LFS--------| */
	SWPSeq LFS; /* last byte send */
	SWPSeq DAT; /* 数据的最大下标 */
	char send_buffer[MAX_BUFFER_SIZE];  /* 发送者缓冲 */
	uint32_t seq_expect;  /* 接收下一个包的seq序列 */
	recvQ_slot recv_buffer_header;  /* 缓存已收到的数据 */
    uint32_t dup_ack_num; /* 当前收到ack的数量 */
	uint8_t timer_flag;  /* 滑窗的计时器是否设置 */
	FILE *log;
	/* 一下数据结构用于计算超时重传间隔 */
	struct timeval time_send;  /* 发送包的时间 */
	long TimeoutInterval;  /* 超时时间 */
	long EstimatedRTT;  /* （加权）平均RTT时间 */
	long DevRTT;  /* RTT偏差时间 */
} slide_window_t;

/* 这个结构对于滑窗协议并不够用 */
typedef struct {
	uint32_t last_seq_received; /* 上一个seq序列 */
	uint32_t last_ack_received; /* 上一个ack序列 */
	pthread_mutex_t ack_lock; /* ack的锁（因为ack会增加） */
} window_t;

typedef struct {
	int socket; /* socket端口号 */
	pthread_t thread_id; /* 后端运行的线程号 */
	uint16_t my_port; /* 本机端口 */
	uint16_t their_port; /* 通讯端口 */
	struct sockaddr_in conn;  /* 通讯目标socket地址 */
	char* received_buf; /* 接收数据缓冲，初始化为NULL */
	int received_len; /* 接收数据大小，初始化为0 */
	pthread_mutex_t recv_lock; /* 缓冲区的锁 */
	pthread_cond_t wait_cond;
	char* sending_buf; /* 发送区域的缓冲，初始化为NULL */
	int sending_len; /* 发送区长度 */
	int type; /* 发送者或者接收者 */
	pthread_mutex_t send_lock; /* 发送缓冲的锁 */
	int dying; /* 连接是否关闭，默认为false */
	pthread_mutex_t death_lock;
	slide_window_t window;  /* 滑窗 */
	TCP_State state;
	// window_t window; 
} cmu_socket_t;

#endif
