
#include "cmu_tcp.h"

/*
 * Param: sock - used for reading and writing to a connection
 *
 *
 */
void functionality(cmu_socket_t  * sock){
    char buf[9898];
    FILE *fp;
    int n;
    int read;

    // Wait to hear from an initiator
    n = 0;
    while (n == 0) {
        n = cmu_read(sock, buf, 9898, NO_FLAG);
    }

    // Send over a random file
    fp = fopen("./test/random.input", "rb");
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
 * Purpose: To provide a sample listener for the TCP connection.
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
    printf("Listening at %s\n", serverip);

    serverport = getenv("serverport15441");
    if (serverport) ;
    else {
        serverport = "15441";
    }
    portno = (unsigned short)atoi(serverport);


    if(cmu_socket(&socket, TCP_LISTENER, portno, serverip) < 0)
        exit(EXIT_FAILURE);

    functionality(&socket);

    if(cmu_close(&socket) < 0)
        exit(EXIT_FAILURE);
    return EXIT_SUCCESS;
}