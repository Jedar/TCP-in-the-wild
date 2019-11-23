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
    int read;
    FILE *fp;

    cmu_write(sock, "hi there", 9);
    cmu_write(sock, "hi there2", 10);
    cmu_write(sock, "hi there3", 10);
    cmu_write(sock, "hi there4", 10);
    cmu_write(sock, "hi there5", 10);
    cmu_write(sock, "hi there6", 10);
    cmu_read(sock, buf, 200, NO_FLAG);

    cmu_write(sock, "hi there", 9);
    cmu_read(sock, buf, 200, NO_FLAG);
    printf("R: %s\n", buf);

    read = cmu_read(sock, buf, 200, NO_WAIT);
    printf("Read: %d\n", read);

    fp = fopen("./src/cmu_tcp.c", "rb");
    read = 1;
    while(read > 0 ){
        read = fread(buf, 1, 2000, fp);
        if(read > 0)
            cmu_write(sock, buf, read);
    }
    
}

/*
 * Param: argc - count of command line arguments provided
 * Param: argv - values of command line arguments provided
 *
 * Purpose: To provide a sample initator for the TCP connection to a
 *  listener.
 *
 */
int main(int argc, char **argv) {
	int portno;
    char *serverip;
    char *serverport;
    cmu_socket_t socket;
    
    serverip = getenv("server15441");
    if (serverip) ;
    else {
        serverip = "10.0.0.1";
    }

    serverport = getenv("serverport15441");
    if (serverport) ;
    else {
        serverport = "15441";
    }
    portno = (unsigned short)atoi(serverport);


    if(cmu_socket(&socket, TCP_INITATOR, portno, serverip) < 0)
        exit(EXIT_FAILURE);
    
    functionality(&socket);

    if(cmu_close(&socket) < 0)
        exit(EXIT_FAILURE);
    return EXIT_SUCCESS;
}
