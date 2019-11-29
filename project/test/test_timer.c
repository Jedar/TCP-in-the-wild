/* 这个文件只是用来测试C的timer的调用，对项目没有作用 */

#include<stdio.h>
#include<signal.h>
#include<sys/time.h>//itimerval结构体的定义
#include <unistd.h>

/* 设置计时 */
void set_timer(int sec, int usec, void (*handler)(int)){
    /* 设置时间到达后的处理函数,注意这里占用了SIGALRM信号 */
    signal(SIGALRM,handler);
    struct itimerval itv;
    itv.it_interval.tv_sec=10;//自动装载，之后每10秒响应一次
    itv.it_interval.tv_usec=0;
    itv.it_value.tv_sec=5;//第一次定时的时间
    itv.it_value.tv_usec=0;
    setitimer(ITIMER_REAL,&itv,NULL);
}

/* 关闭计时 */
void unset_timer(){
    /* 设置回默认信号处理方式，也可以屏蔽信号 */
    signal(SIGALRM,SIG_DFL);
    struct itimerval itv;
    itv.it_interval.tv_sec=0;//设置为0
    itv.it_interval.tv_usec=0;
    itv.it_value.tv_sec=0;
    itv.it_value.tv_usec=0;
    setitimer(ITIMER_REAL,&itv,NULL);
}

int handle_count=0;
void set_time(void)
{
    printf("set time....\n");
    fflush(stdout);
    struct itimerval itv;
    itv.it_interval.tv_sec=10;//自动装载，之后每10秒响应一次
    itv.it_interval.tv_usec=0;
    itv.it_value.tv_sec=5;//第一次定时的时间
    itv.it_value.tv_usec=0;
    setitimer(ITIMER_REAL,&itv,NULL);
}

void alarm_handle(int sig)
{
    /* 下面展示如何关闭定时器 */
    if(handle_count == 0){
        struct itimerval itv;
        itv.it_interval.tv_sec=0;//全部设置为0
        itv.it_interval.tv_usec=0;
        itv.it_value.tv_sec=0;
        itv.it_value.tv_usec=0;
        setitimer(ITIMER_REAL,&itv,NULL);
    }
    handle_count++;
    printf("have handle count is %d\n",handle_count);
    fflush(stdout);
}

void main(void)
{
    // struct timeval itv = {1,0};
    struct itimerval itv;
    set_timer(3,0,alarm_handle);

    sleep(1);

    unset_timer();
   
    while(1){
        getitimer(ITIMER_REAL,&itv);
        printf("pass second is %d\n",(int)itv.it_value.tv_sec);
        fflush(stdout);
        sleep(1);
    }
   
    return;
}
