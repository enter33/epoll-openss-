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
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

int get_pkt_count( char *argv[]);//不调用pcap_loop
int get_pkt_count_loop( char *argv[],prt_info_t *p);//调用pcap_loop


//回调函数,统计pocket数量
void handler(u_char *user, const struct pcap_pkthdr *h,const u_char *bytes);

//分析ip协议
void analysis_ip(prt_info_t*);

//分析ipv4
void analysis_ipv4(prt_info_t*);

//分析ipv6
void analysis_ipv6(prt_info_t*);

//分析tcp
void analysis_tcp(prt_info_t*);

//分析udp
void analysis_udp(prt_info_t*);

//探测应用层协议类型
int detect_protocol_type(prt_info_t*);

//usr/include/linux/if_ether.h
//以太网帧头部结构体
// struct ethhdr {
// 	unsigned char	h_dest[ETH_ALEN];	/* destination eth addr	*/
// 	unsigned char	h_source[ETH_ALEN];	/* source ether addr	*/
// 	__be16		h_proto;		/* packet type ID field	*/
// } __attribute__((packed));



//usr/include/netinet/ip.h
//ip数据报头部结构体
// struct iphdr
//   {
// #if __BYTE_ORDER == __LITTLE_ENDIAN
//     unsigned int ihl:4;
//     unsigned int version:4;
// #elif __BYTE_ORDER == __BIG_ENDIAN
//     unsigned int version:4;
//     unsigned int ihl:4;
// #else
// # error	"Please fix <bits/endian.h>"
// #endif
//     u_int8_t tos;
//     u_int16_t tot_len;
//     u_int16_t id;
//     u_int16_t frag_off;
//     u_int8_t ttl;
//     u_int8_t protocol;
//     u_int16_t check;
//     u_int32_t saddr;
//     u_int32_t daddr;
//     /*The options start here. */
//   };



#endif