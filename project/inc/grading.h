#ifndef _GRADING_H_
#define _GRADING_H_


/*
 * DO NOT CHANGE THIS FILE
 * This contains the variables for your tcp implementation
 * and we will replace this file during the autolab testing with new variables.
 */

//window variables
#define WINDOW_INITIAL_WINDOW_SIZE 1  /* 初始窗口大小 */
#define WINDOW_INITIAL_SSTHRESH 64     /* 拥塞控制要用的属性 */
#define WINDOW_INITIAL_RTT 3000	// ms  /* 初始RTT时间 */
#define WINDOW_INITIAL_ADVERTISED 1 //max packet sizes


//packet lengths
#define MAX_DLEN 1375  /* 最大数据段长度 */
#define MAX_LEN 1400  /* 最大包长 */

//socket types
#define TCP_INITATOR 0  /* 客户端 */
#define TCP_LISTENER 1  /* 服务器 */

//Max TCP Buffer 这个字段用于流量控制
#define MAX_NETWORK_BUFFER 65536 // 2^16 bytes

#endif
