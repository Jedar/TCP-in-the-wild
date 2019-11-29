#include "cmu_tcp.h"

/*
 * Param: dst - The structure where socket information will be stored
 * Param: flag - A flag indicating the type of socket(Listener / Initiator)
 * Param: port - The port to either connect to, or bind to. (Based on flag)
 * Param: ServerIP - The server IP to connect to if the socket is an initiator.
 *
 * Purpose: To construct a socket that will be used in various connections.
 *  The initiator socket can be used to connect to a listener socket.
 *
 * Return: The newly created socket will be stored in the dst parameter,
 *  and the value returned will provide error information. 
 *
 */
int cmu_socket(cmu_socket_t * dst, int flag, int port, char * serverIP){
  int sockfd, optval;
  socklen_t len;
  /* socket地址结构  */
  struct sockaddr_in conn, my_addr;
  len = sizeof(my_addr);

  /* UDP socket */
  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0){
    perror("ERROR opening socket");
    return EXIT_ERROR;
  }
  /* 初始化socket参数 */
  dst->their_port = port;
  dst->socket = sockfd;
  dst->received_buf = NULL;
  dst->received_len = 0;
  pthread_mutex_init(&(dst->recv_lock), NULL);
  dst->sending_buf = NULL;
  dst->sending_len = 0;
  pthread_mutex_init(&(dst->send_lock), NULL);
  dst->type = flag;
  dst->dying = FALSE;
  pthread_mutex_init(&(dst->death_lock), NULL);
  dst->window.last_ack_received = 0;
  dst->window.last_seq_received = 0;
  pthread_mutex_init(&(dst->window.ack_lock), NULL);

  /* 创建条件变量 */
  if(pthread_cond_init(&dst->wait_cond, NULL) != 0){
    perror("ERROR condition variable not set\n");
    return EXIT_ERROR;
  }
  /* 根据服务器或者客户端创建不同的socket */
  switch(flag){
    case(TCP_INITATOR):  /* server' socket */
      if(serverIP == NULL){
        perror("ERROR serverIP NULL");
        return EXIT_ERROR;
      }
      /* socket地址初始化 */
      memset(&conn, 0, sizeof(conn));          
      conn.sin_family = AF_INET; 
      conn.sin_addr.s_addr = inet_addr(serverIP);  
      conn.sin_port = htons(port); 
      dst->conn = conn;

      my_addr.sin_family = AF_INET;
      my_addr.sin_addr.s_addr = htonl(INADDR_ANY);
      my_addr.sin_port = 0;
      /* 将套接字地址和套接字描述符 */ 
      if (bind(sockfd, (struct sockaddr *) &my_addr, 
        sizeof(my_addr)) < 0){
        perror("ERROR on binding");
        return EXIT_ERROR;
      }

      break;
    
    case(TCP_LISTENER):  /* client's socket */
      bzero((char *) &conn, sizeof(conn));
      conn.sin_family = AF_INET;
      /* 主机数转换成无符号长整型的网络字节 */
      conn.sin_addr.s_addr = htonl(INADDR_ANY);
      /* 端口数转换成无符号长整型的网络字节 */
      conn.sin_port = htons((unsigned short)port);

      optval = 1;
      /* setsockopt(套接字,所在的协议层(SOL_SOCKET为套接字层),访问的选项名,包含新选项值的缓冲,现选项的长度) */
      setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, 
           (const void *)&optval , sizeof(int));
      /* 将套接字地址与套接字描述符绑定 */
      if (bind(sockfd, (struct sockaddr *) &conn, 
        sizeof(conn)) < 0){
          perror("ERROR on binding");
          return EXIT_ERROR;
      }
      dst->conn = conn;
      break;

    default:
      perror("Unknown Flag");
      return EXIT_ERROR;
  }
  /* 返回本地地址（因为服务器的case没有初始化my_addr） */
  getsockname(sockfd, (struct sockaddr *) &my_addr, &len);
  /* ntohs：网络字节顺序转换为主机字节顺序 */
  dst->my_port = ntohs(my_addr.sin_port);

  /* 调用backend.c开始处理后端数据 */
  pthread_create(&(dst->thread_id), NULL, begin_backend, (void *)dst);  
  return EXIT_SUCCESS;
}

/*
 * Param: sock - The socket to close.
 *
 * Purpose: To remove any state tracking on the socket.
 *
 * Return: Returns error code information on the close operation.
 *
 */
int cmu_close(cmu_socket_t * sock){
  /* 连接关闭 */
  while(pthread_mutex_lock(&(sock->death_lock)) != 0);
  sock->dying = TRUE;
  pthread_mutex_unlock(&(sock->death_lock));
  /* 回收线程 */
  pthread_join(sock->thread_id, NULL); 
  /* 释放缓冲区 */
  if(sock != NULL){
    if(sock->received_buf != NULL)
      free(sock->received_buf);
    if(sock->sending_buf != NULL)
      free(sock->sending_buf);
  }
  else{
    perror("ERORR Null scoket\n");
    return EXIT_ERROR;
  }
  /* 关闭UDP socket */
  return close(sock->socket);
}

/*
 * Param: sock - The socket to read data from the received buffer.
 * Param: dst - The buffer to place read data into.
 * Param: length - The length of data the buffer is willing to accept.
 * Param: flags - Flags to signify if the read operation should wait for
 *  available data or not.
 *
 * Purpose: To retrive data from the socket buffer for the user application.
 *
 * Return: If there is data available in the socket buffer, it is placed
 *  in the dst buffer, and error information is returned. 
 *
 */
int cmu_read(cmu_socket_t * sock, char* dst, int length, int flags){
  char* new_buf;
  int read_len = 0;

  if(length < 0){
    perror("ERROR negative length");
    return EXIT_ERROR;
  }
  /* 等待接收缓冲区到可用状态 */
  while(pthread_mutex_lock(&(sock->recv_lock)) != 0);
  /* 根据读操作是否需要等待执行不同读操作 */
  switch(flags){
    case NO_FLAG:  /* 需要等待，注意没有break */
      while(sock->received_len == 0){
        /* 如果没有收到数据，释放锁，等待socket收到数据后继续加锁，这里会堵塞 */
        pthread_cond_wait(&(sock->wait_cond), &(sock->recv_lock)); 
      }
    case NO_WAIT:   /* 不需要等待 */
      if(sock->received_len > 0){  /* 如果缓冲区里有数据 */
        if(sock->received_len > length) /* 如果缓冲区足够大 */
          read_len = length;  /* 那么读取的就是需要的长度 */
        else
          read_len = sock->received_len;  /* 如果缓冲区不够大，则只返回缓冲区大小的数据 */
        /* copy数据 */
        memcpy(dst, sock->received_buf, read_len);
        if(read_len < sock->received_len){  /* 如果没有把所有的数据读取出来 */
           new_buf = malloc(sock->received_len - read_len);
           /* 把剩余数据储存下来，替换之前的数据 */
           memcpy(new_buf, sock->received_buf + read_len, 
                sock->received_len - read_len);
           free(sock->received_buf);
           sock->received_len -= read_len;
           sock->received_buf = new_buf;
        }
        else{  /* 如果全部数据读出来了，则释放缓冲区 */
          free(sock->received_buf); 
          sock->received_buf = NULL; 
          sock->received_len = 0; 
        }
      }
      break;
    default:
      perror("ERROR Unknown flag.\n");
      read_len = EXIT_ERROR;
  }
  pthread_mutex_unlock(&(sock->recv_lock));
  /* 返回读取长度 */
  return read_len;
}

/*
 * Param: sock - The socket which will facilitate data transfer.
 * Param: src - The data source where data will be taken from for sending.
 * Param: length - The length of the data to be sent.
 *
 * Purpose: To send data to the other side of the connection.
 *
 * Return: Writes the data from src into the sockets buffer and
 *  error information is returned. 
 *
 */
int cmu_write(cmu_socket_t * sock, char* src, int length){
  while(pthread_mutex_lock(&(sock->send_lock)) != 0);
  /* 如果发送缓冲区不存在或者太小，将缓冲区变得足够大 */
  if(sock->sending_buf == NULL)
    sock->sending_buf = malloc(length);
  else
    sock->sending_buf = realloc(sock->sending_buf, length + sock->sending_len);
  /* 将需要发送的数据储存进缓冲区 */
  memcpy(sock->sending_buf + sock->sending_len, src, length);
  sock->sending_len += length;

  pthread_mutex_unlock(&(sock->send_lock));
  return EXIT_SUCCESS;
}

