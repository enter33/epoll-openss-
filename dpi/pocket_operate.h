//处理pcap文件的函数

#ifndef __POCKET_OPERATE_H__
#define __POCKET_OPERATE_H__

#include "log.h"
#include "protocol_info.h"
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <strings.h>
#include <sys/mman.h>
#include <pcap.h>



int get_pkt_count( char *argv[]);//不调用pcap_loop
int get_pkt_count_loop( char *argv[],prt_info_t *p);//调用pcap_loop


//回调函数,统计pocket数量
void handler(u_char *user, const struct pcap_pkthdr *h,const u_char *bytes);


#endif