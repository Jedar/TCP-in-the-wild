#include <stdio.h>
#include <string.h>

#define MAX_BUFFER_SIZE 10

static void copy_string_to_buffer(char *buf,int *idx, char *data, int len){
    int start = *idx % MAX_BUFFER_SIZE;
    if(start + len > MAX_BUFFER_SIZE){
        int temp = MAX_BUFFER_SIZE - start;
        memcpy(buf+start,data,temp);
        memcpy(buf, data + temp,len - temp);
    }
    else{
        memcpy(buf+start,data,len);
    }
    *idx += len;
}

static int copy_string_from_buffer(char *buf,int *idx, int from, char *data, int max_len){
    from = from % MAX_BUFFER_SIZE;
    int len = (*idx-from<max_len)?*idx-from:max_len;
    int start = from % MAX_BUFFER_SIZE;
    if(start + len > MAX_BUFFER_SIZE){
        int temp = MAX_BUFFER_SIZE-start;
        memcpy(data,buf+start, temp);
        memcpy(data+temp,buf,len-temp);
    }
    else{
        memcpy(data,buf+start, len);
    }
}

int main(){
    char buf[MAX_BUFFER_SIZE+1] = "0000000000";
    int sz = MAX_BUFFER_SIZE;
    char data[MAX_BUFFER_SIZE+1] = "000000000";
    int idx = 5;
    copy_string_to_buffer(buf,&idx,"12345678",8);
    fprintf(stdout,"Msg: %s\n",buf);
    copy_string_from_buffer(buf,&idx,4,data,sz);
    fprintf(stdout,"recv Msg: %s\n",data);
}
