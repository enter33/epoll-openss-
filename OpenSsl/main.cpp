#include "./include/main.h"

#define SERVER_PORT 8888
#define SERVER_ADDRESS "192.168.50.135"

int main(int argc,char*argv[]) 
{
    if(argc != 2)
    {
        log_err("argc error\n");
        return 0;
    }

    if(strcmp("client",argv[1]) == 0)
    {
        Client_ssl(SERVER_ADDRESS,SERVER_PORT);
    }
    else if(strcmp("server",argv[1]) == 0)
    {
        Server_ssl(SERVER_ADDRESS,SERVER_PORT);
    }
    else
    {
        log_err("argv error\n");
        return 0;
    }

    return 0;
}
