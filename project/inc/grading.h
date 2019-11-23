#ifndef _GRADING_H_
#define _GRADING_H_


/*
 * DO NOT CHANGE THIS FILE
 * This contains the variables for your tcp implementation
 * and we will replace this file during the autolab testing with new variables.
 */

//window variables
#define WINDOW_INITIAL_WINDOW_SIZE 1
#define WINDOW_INITIAL_SSTHRESH 64
#define WINDOW_INITIAL_RTT 3000	// ms
#define WINDOW_INITIAL_ADVERTISED 1 //max packet sizes


//packet lengths
#define MAX_DLEN 1375
#define MAX_LEN 1400

//socket types
#define TCP_INITATOR 0
#define TCP_LISTENER 1

//Max TCP Buffer
#define MAX_NETWORK_BUFFER 65536 // 2^16 bytes


#endif