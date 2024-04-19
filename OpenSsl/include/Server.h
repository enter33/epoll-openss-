#ifndef __SERVER_H__
#define __SERVER_H__
#include "Ssl.h"

// Accept SSL connection
link_info accept_ssl(SSL_CTX* ctx, int server_fd);

int Server_ssl(char* SERVER_ADDRESS,int SERVER_PORT);

#endif /*__SERVER_H__*/