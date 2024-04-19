#include "Server.h"


// Accept SSL connection
link_info accept_ssl(SSL_CTX* ctx, int server_fd) {
    int client_fd;
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    SSL *ssl;

    // Accept client connection
    client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
    if (client_fd < 0) {
        perror("Unable to accept client connection");
        exit(EXIT_FAILURE);
    }

    // Create SSL structure
    ssl = SSL_new(ctx);
    if (!ssl) {
        perror("Unable to create SSL structure");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Attach SSL to socket
    SSL_set_fd(ssl, client_fd);

    // Perform SSL handshake
    if (SSL_accept(ssl) <= 0) {
        perror("SSL handshake failed");
        exit(EXIT_FAILURE);
    }

    //设置为非阻塞
    int flags = fcntl(client_fd, F_GETFL, 0);
    if (flags == -1) {
        perror("fcntl F_GETFL");
        exit(EXIT_FAILURE);
    }
    if (fcntl(client_fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        perror("fcntl F_SETFL O_NONBLOCK");
        exit(EXIT_FAILURE);
    }

    //输出登录信息
    char ip[16] = {0};
    inet_ntop(AF_INET,&client_addr.sin_addr.s_addr,ip,sizeof(ip));

    time_t now = time(0);
    // 将时间转换为字符串格式
    char* dt = ctime(&now);

    log_info("[%s]%s:%d:connect\n",dt,ip,client_addr.sin_port);

    link_info info = {client_fd,ssl,client_addr};
    return info;
}


int Server_ssl(char* SERVER_ADDRESS,int SERVER_PORT)
{
    SSL_CTX *ctx;
    int server_fd;
    struct sockaddr_in server_addr;

    // Initialize OpenSSL
    init_openssl();

    // Create SSL context
    ctx = create_context(SERVER);

    // Create server socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("Unable to create server socket");
        exit(EXIT_FAILURE);
    }

    //设置端口复用
    int opt = 1;
	setsockopt(server_fd,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt));

    // Initialize server address structure
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    inet_pton(AF_INET,SERVER_ADDRESS,&server_addr.sin_addr.s_addr);// Bind to localhost
    server_addr.sin_port = htons(SERVER_PORT);

    // Bind server socket
    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Unable to bind server socket");
        exit(EXIT_FAILURE);
    }

    // Listen for incoming connections
    if (listen(server_fd, 1) < 0) {
        perror("Unable to listen for connections");
        exit(EXIT_FAILURE);
    }

    // Accept incoming connections
    int epollfd = epoll_create(1);

    epoll_event ev;
    ev.data.fd = server_fd;
    ev.events = EPOLLIN;

    int ret = epoll_ctl(epollfd,EPOLL_CTL_ADD,server_fd,&ev);

    while(1)
    {
        epoll_event evs[1024];
        int nready = epoll_wait(epollfd,evs,1024,-1);
        if(nready < 0)
        {
            if(errno == EINTR)//判断是不是信号打断
            {
                continue;
            }
            break;
        }

        for(int i = 0;i < nready;i++)
        {
            if(evs[i].data.fd == server_fd && evs[i].events == EPOLLIN)
            {
                // printf("connect\n");
                link_info info = accept_ssl(ctx, server_fd);
                ev.data.ptr = &info;
                ev.events = EPOLLIN;

                int ret = epoll_ctl(epollfd,EPOLL_CTL_ADD,info.fd,&ev);
            }

            else if(evs[i].events == EPOLLIN)
            {
                // printf("recv\n");
                char buf[1024];
                while(1)
                {
                    bzero(buf,sizeof(buf));
                    int n = SSL_read(((link_info*)evs[i].data.ptr)->ssl,buf,sizeof(buf));

                    //输出退出信息
                    char ip[16] = {0};
                    inet_ntop(AF_INET,&((link_info*)evs[i].data.ptr)->client_addr.sin_addr.s_addr,ip,sizeof(ip));

                    time_t now = time(0);
                    // 将时间转换为字符串格式
                    char* dt = ctime(&now);

                    // printf("n= %d\n",n);
                    if(n <= 0)
                    {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) 
                        {
                            // No more data available
                            break;
                        }
                        close(evs[i].data.fd);
                        SSL_shutdown(((link_info*)evs[i].data.ptr)->ssl);
                        SSL_free(((link_info*)evs[i].data.ptr)->ssl);
                        epoll_ctl(epollfd,EPOLL_CTL_DEL,evs[i].data.fd,&evs[i]);

                        //输出退出信息
                        log_info("[%s]%s:%d:disconnect\n",dt,ip,((link_info*)evs[i].data.ptr)->client_addr.sin_port);
                        break;
                    }
                    
                    //输出用户发送信息
                    log_info("[%s]%s:%d:%s",dt,ip,((link_info*)evs[i].data.ptr)->client_addr.sin_port,buf);
                }
                // printf("over\n");
            }
        }
    }

    // Clean up OpenSSL
    SSL_CTX_free(ctx);
    cleanup_openssl();

    // Close socket
    close(server_fd);

    return 0;
}


