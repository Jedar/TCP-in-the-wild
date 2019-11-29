/* 这个文件只是用来测试semphore的使用，对项目没有任何影响，可忽略 */

#include <stdio.h>
#include <pthread.h>
#include <semaphore.h>

/* C语言semphore的使用 */
/* 首先需要用sem_init(); 初始化sem_t型变量，并设置初始信号量。比如设置为1  */
/* 每次调用sem_wait(sem_t *); 信号量减一，当调用sem_post(sem_t *); 信号量加一。 */
/* 当信号量为0时，sem_wait(); 函数阻塞，等待信号量 >0 时，才进行。 */
/* sem_getvalue得到当前信号量的值  */


typedef struct{	
    sem_t *lock;	
    int num;
}STRUCT;

void test(void * obj){	
    STRUCT *point = (STRUCT *)obj;	
    sem_t *semlock = point->lock;	
    sem_wait(semlock);	
    FILE *f = fopen("test.txt","a");	
    if(f==NULL){
        printf("fopen is wrong\n");	
    }
    printf("sem_wait %d\n",point->num);	
    int j=0;
    for(j=0;j<30;j++){
        fprintf(f,"%c111111111111\n",'a'+point->num);
    }
    fclose(f);
    sem_post(semlock); 	
    return;
}  

int main(){	
    pthread_t pid[20];  
    pthread_t pid;	
    int ret,i=0;	
    STRUCT obj[13];	
    sem_t semlock;	
    if(sem_init(&semlock,0,1)!=0){    // 此处初始信号量设为1. 第二个参数为0表示不应用于其他进程。
    	printf("sem_init is wrong\n");
    }	
    for(i=0;i<10;i++)	{		
        obj[i].num = i;		
        obj[i].lock = &semlock;		
        ret = pthread_create(&pid[i],NULL,(void *)test,&obj[i]);
        if(ret!=0){			
            printf("create thread wrong %d!!\n",i);			
            return 0;		
        }			
    }	
    for(i=0;i<10;i++){
        pthread_join(pid[i],NULL);// 等待其他线程结束，如果没有这里，主线程先结束，会释放pid[]及obj[]，则出现BUG。 	
    }
    return 0;
        
}
