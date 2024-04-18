#ifndef __DETEC_TFTP_H
#define __DETEC_TFTP_H

#include "protocol_types.h"
#include "protocol_info.h"


//没有找到其他包含宏定义的头文件
#define TFTP_RRQ 1
#define TFTP_WRQ 2


#ifndef DETEC_TFTP
#define DETEC_TFTP
int detec_tftp(prt_info_t* p);
#endif

#endif /*__DETEC_TFTP_H*/