#include "detec_ssh.h"
#include <string.h>

//ssh协议通常以"SSH-"开头
int detec_ssh(prt_info_t* p)
{
    if(p->tcph == NULL)
    {
        return 0;
    }
    p->data = (u_int8_t*)((char*)p->tcph + p->tcph->doff*4);
    //如果数据的前四个字节是SSH-,则可认为是ssh协议
    if(strncmp((char*)(p->data),"SSH-",4) == 0)
    {
        return 1;
    }

    return 0;
}