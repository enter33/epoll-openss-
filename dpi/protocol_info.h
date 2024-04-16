//定义协议栈信息结构体及操作函数

#ifndef __PROTOCOL_INFO__
#define __PROTOCOL_INFO__
#pragma once
#include <stdio.h>
#include <iostream>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "log.h"
#include "protocol_types.h"

struct prt_info_t;
struct func_type;
typedef int (*DetectFunction)(prt_info_t*);

//区分探测函数的传输层协议类型
struct func_type
{
    int flag;
    DetectFunction func;
};

//协议栈信息结构体
struct prt_info_t
{
    int count;
    //其他信息
    int tcp_count;
    int udp_count;

    //应用层协议数组
    int app_prt_types[PRT_TYPES_MAX];
    char* app_prt_names[PRT_TYPES_MAX] = {PRT_NAMES};
    func_type func_detec[PRT_TYPES_MAX];


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

#include "detec_func.h"
#endif