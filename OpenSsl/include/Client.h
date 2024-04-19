#ifndef __CLIENT_H__
#define __CLIENT_H__
#include "Ssl.h"

link_info connect_ssl(SSL_CTX* ctx, const char* server_address, int port);

int Client_ssl(char* SERVER_ADDRESS,int SERVER_PORT);


#endif /*__CLIENT_H__*/