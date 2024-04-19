#include "Client.h"


// Establish SSL connection,返回文件描述符
link_info connect_ssl(SSL_CTX* ctx, const char* server_address, int port) {
    int sockfd;
    struct sockaddr_in server_addr;
    SSL *ssl;

    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    // Initialize server address structure
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(server_address);
    server_addr.sin_port = htons(port);

    // Connect to server
    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Unable to connect to server");
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
    SSL_set_fd(ssl, sockfd);

    // Perform SSL handshake
    if (SSL_connect(ssl) <= 0) {
        perror("SSL handshake failed");
        exit(EXIT_FAILURE);
    }

    link_info info = {sockfd,ssl};
    return info;
}



int Client_ssl(char* SERVER_ADDRESS,int SERVER_PORT)
{
    //创建信号回收子进程,防止僵尸进程
    signal(SIGCHLD,[](int signo){
        while(1)
        {
            pid_t pid  = waitpid(-1,NULL,WNOHANG);
            if(pid == 0 || pid == -1)
            {
                break;
            }
        }
    });


    SSL_CTX *ctx;

    // Initialize OpenSSL
    init_openssl();

    // Create SSL context
    ctx = create_context(CLIENT);

    // Establish SSL connection
    link_info client = connect_ssl(ctx, SERVER_ADDRESS, SERVER_PORT);

    int pid = fork();
    if(pid > 0)//child proc
    {
        char buf[1024];
        
        while(1)
        {
            bzero(buf,sizeof(buf));
            int n = SSL_read(client.ssl, buf, sizeof(buf));

            if(n <= 0)
            {
                kill(getppid(),SIGKILL);
                break;
            }
        }    
    }
    else if(pid == 0)//parent proc
    {
        char buf[1024];

        while(1)
        {
            bzero(buf,sizeof(buf));
            int n = read(STDIN_FILENO, buf, sizeof(buf));

            if(n <= 0)
            {
                break;
            }

            SSL_write(client.ssl,buf,n);
        }
        

    }


    // Clean up OpenSSL

    SSL_shutdown(client.ssl);
    SSL_free(client.ssl);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    close(client.fd);
    return 0;
}
