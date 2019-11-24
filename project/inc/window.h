#ifndef _WINDOW_H_
#define _WINDOW_H_
#include "cmu_tcp.h"
#include "global.h"
#include "cmu_packet.h"

/* 这个模块用于定义滑窗协议的窗口结构 */
typedef struct {
	uint32_t last_seq_received; /* 上一个seq序列 */
	uint32_t last_ack_received; /* 上一个ack序列 */
	pthread_mutex_t ack_lock; /* ack的锁（因为ack会增加） */
    size_t window_size; /* 窗口大小 */
    uint32_t cur_send_seq; /* 当前发送包的序列号 */
    

} slide_window_t;

#endif //_WINDOW_H_
