#include <pthread.h> /* pthread struct */
#include <stdint.h> 
#include <semaphore.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
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

typedef uint32_t SWPSeq;  /* slide window protocol序列号 */

typedef struct {
	uint8_t used;  /* slot是否还在使用，0标识没有使用，1标识正在使用 */
	uint8_t time_flag;  /* 定时器 */
	char *msg;  /* 已经打包好的packet */
} sendQ_slot;

typedef struct {
	uint8_t recv_or_not;
	char *msg;
} recvQ_slot;

/* 定义滑窗协议的窗口结构 */
typedef struct {
	uint32_t last_seq_received; /* 上一个seq序列 */
	uint32_t last_ack_received; /* 上一个ack序列 */
	pthread_mutex_t ack_lock; /* ack的锁 */
    size_t SWS; /* send_window_size窗口大小 */
	size_t RWS; /* recv_window_size窗口大小 */
	sem_t sendlock;  /* 用信号量控制窗口大小，如果窗口满了会堵塞 */
	SWPSeq LAR; /* last ack recv */ /* |----------LAR+++++++++LFS--------| */
	SWPSeq LFS; /* last frame send */
	sendQ_slot *send_buffer;
	uint32_t seq_expect;  /* 接收下一个包的seq序列 */
	SWPSeq EXP;  /* expect packet, 接收缓冲区的起点 */  /* ------------EXP+-+-+-++-------- */
	recvQ_slot *recv_buffer;
    uint32_t dup_ack_num; /* 当前收到ack的数量 */
	pthread_t recv_thread;  /* 接收数据的线程 */
	uint8_t timer_flag;  /* 滑窗的计时器是否设置 */
	pthread_mutex_t timer_lock; /* 计时器的锁 */
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
	// window_t window; 
} cmu_socket_t;

#endif
