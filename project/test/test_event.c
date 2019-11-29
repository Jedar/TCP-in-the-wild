#include <netinet/in.h>   
#include <sys/socket.h>   
#include <sys/types.h>   
#include <event.h>
#include <stdio.h>   
#include <time.h>   
#include <unistd.h>

#define MAX_LEN 1400
#define DEFAULT_HEADER_LEN 25
#define MAX_DLEN 1375

typedef union {
	char msg[MAX_LEN];
	char hdr[DEFAULT_HEADER_LEN];
	char data[MAX_DLEN];
} packet;


void cb(evutil_socket_t fd, short what, void *arg){
    fprintf(stdout,"time out \n");
}

int main(){
    printf("size:%d\n",sizeof(packet));
    struct timeval two_sec = {2, 0};
    struct event_base *base = event_base_new();
    struct event *timeout = event_new(base, -1, EV_PERSIST|EV_TIMEOUT, cb, NULL);
    event_add(timeout, &two_sec);
    // event_base_dispatch(base);
    // event_base_loop(base, EVLOOP_NONBLOCK); 
    printf("exit\n");
    // while(1){
    //     printf("sleep...\n");
    //     sleep(0);
    // }
}
