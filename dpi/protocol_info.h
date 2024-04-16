//定义协议栈信息结构体及操作函数

#ifndef __PROTOCOL_INFO__
#define __PROTOCOL_INFO__
#include <stdio.h>
#include <iostream>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>


//协议栈信息结构体
struct prt_info_t
{
    int count;
    //其他信息
    int tcp_count;
    int udp_count;

    ethhdr* ethh;//帧头
    iphdr* iph;//ip头
    tcphdr* tcph;//tcp头
    udphdr* udph;//udp头

};

//初始化协议栈信息结构体函数
prt_info_t *init_prt_info(void);


//释放协议栈信息结构体指针
int free_prt_info(prt_info_t *p);

//输出协议信息
int output_prt_info(prt_info_t *p);

#endif