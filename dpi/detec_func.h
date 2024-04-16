#ifndef __DETEC_FUNC_H
#define __DETEC_FUNC_H

#include "protocol_types.h"
#include "protocol_info.h"



#ifndef DETEC_SSH
#define DETEC_SSH
int detec_ssh(prt_info_t* p);
#endif

#ifndef DETEC_TFTP
#define DETEC_TFTP
int detec_tftp(prt_info_t* p);
#endif

#endif