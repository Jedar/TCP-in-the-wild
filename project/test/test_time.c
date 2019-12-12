#include <time.h>
#include <stdio.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>

/* 返回timeval数据结构对应的微秒值 */
long get_timeval(struct timeval *time){
    return 1l*(time->tv_sec*1000000)+time->tv_usec;
}

int main(){
    struct timeval tim;
    gettimeofday(&tim,NULL);
    long start = get_timeval(&tim);

    sleep(2);

    gettimeofday(&tim,NULL);
    long end = get_timeval(&tim);
    printf("time: %ld\n", (end - start)/1000);
}
