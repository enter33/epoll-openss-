#ifndef __SSL_H__
#define __SSL_H__

#include <iostream>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/types.h>   
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/epoll.h>
#include "log.h"
#include <fcntl.h>


#define CLIENT 0
#define SERVER 1

struct link_info
{
    int fd;
    SSL* ssl;
    sockaddr_in client_addr;
};


// Initialize OpenSSL
void init_openssl();

// Clean up OpenSSL
void cleanup_openssl();

// Create SSL context
SSL_CTX* create_context(int type);

// Establish SSL connection
link_info connect_ssl(SSL_CTX* ctx, const char* server_address, int port);

// Accept SSL connection
link_info accept_ssl(SSL_CTX* ctx, int server_fd);

int Client_ssl(char* SERVER_ADDRESS,int SERVER_PORT);

int Server_ssl(char* SERVER_ADDRESS,int SERVER_PORT);

#endif /*SSL_H__*/
