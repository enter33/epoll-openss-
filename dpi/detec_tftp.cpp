#include "detec_tftp.h"
#include <string.h>

int detec_tftp(prt_info_t* p)
{
    if(p->udph == NULL)
    {
        return 0;
    }

    //tftp协议
    //最小的包为ack包,长度为4字节
    if(ntohs(p->udph->len) - sizeof(*(p->udph)) < 4)
    {
        return 0;
    }

    if(ntohs(*(short*)p->data) == TFTP_RRQ || ntohs(*(short*)p->data) == TFTP_WRQ)
    {
        //rrq和wrq的格式
            //2bytes + string + 1byte + string + 1byte
            //|Opcode|Filename|0|Mode|0|
        //跳过文件名
        char* temp = (char*)p->data +strlen((char*)p->data+2) +1;
        
        //mode支持两种:netascii和octet
        if(strcmp(temp,"netascii") == 0 \
        || strcmp(temp,"NETASCII") == 0 \
        || strcmp(temp,"octet") == 0 \
        || strcmp(temp,"OCTET") == 0 )
        {
            return 1;
        }
    }

    p->data = (u_int8_t*)((char*)p->udph + sizeof(*(p->udph)));
    
    return 0;
}