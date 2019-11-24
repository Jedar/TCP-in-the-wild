#include <pthread.h> /* pthread struct */ 
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


typedef struct {
	uint32_t last_seq_received; /* 上一个seq序列 */
	uint32_t last_ack_received; /* 上一个ack序列 */
	pthread_mutex_t ack_lock; /* ack的锁（因为ack会加一） */
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
	window_t window; /* 滑窗 */
} cmu_socket_t;

#endif
