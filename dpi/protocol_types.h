//定义表示应用层协议类型的宏
#ifndef __PROTOCOL_H__
#define __PROTOCOL_H__

#define PRT_UNKNOW 0
#define PRT_SSH 1
#define PRT_TFTP 2

#define PRT_LAST PRT_TFTP

#define PRT_TYPES_MAX (PRT_LAST+1)

#define PRT_NAMES \
    {"unknow"},\
    {"ssh"},\
    {"tftp"}


#endif