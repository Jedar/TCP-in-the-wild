#include "cmu_tcp.h"

/*
 * Param: sock - used for reading and writing to a connection
 *
 * Purpose: To provide some simple test cases and demonstrate how 
 *  the sockets will be used.
 *
 */
void functionality(cmu_socket_t  * sock){
    char buf[9898];
    FILE *fp;
    int n;
    char *msg;

    // n = cmu_read(sock, buf, 200, NO_FLAG);
    // printf("R: %s\n", buf);
    // printf("N: %d\n", n);
    // msg = "server: hi there 1";
    // cmu_write(sock, msg, strlen(msg));

    // sleep(1);
    // cmu_read(sock, buf, 200, NO_FLAG);
    // msg = "server: hi there 2";
    // cmu_write(sock, msg, strlen(msg));

    // sleep(5);
    fp = fopen("./test/file.c", "w+");
    while(n = cmu_read(sock, buf, 9898, NO_FLAG)){
        printf("N: %d\n", n);
        fwrite(buf, 1, n, fp);
        fflush(fp);
    }
    fclose(fp);
}


/*
 * Param: argc - count of command line arguments provided
 * Param: argv - values of command line arguments provided
 *
 * Purpose: To provide a sample listener for the TCP connection.
 *
 */
int main(int argc, char **argv) {
	int portno;
    char *serverip;
    char *serverport;
    cmu_socket_t socket;
    
    /* 默认服务器网址 */
    serverip = getenv("server15441"); /* getenv：从linux环境变量中读取变量值 */
    if (serverip) ;
    else {
        /* 为什么是10.0.0.1？ */
        serverip = "10.0.0.1";
    }

    /* 默认服务器监听端口 */
    serverport = getenv("serverport15441");
    if (serverport) ;
    else {
        serverport = "15441";
    }
    /* 字符串转为整数  */
    portno = (unsigned short)atoi(serverport);


    /* 判断端口是否被占用 */
    if(cmu_socket(&socket, TCP_LISTENER, portno, serverip) < 0)
        exit(EXIT_FAILURE);

    functionality(&socket);

    if(cmu_close(&socket) < 0)
        exit(EXIT_FAILURE);
    return EXIT_SUCCESS;
}
