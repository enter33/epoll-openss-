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
struct four_tupel;
typedef int (*DetectFunction)(prt_info_t*);

//区分探测函数的传输层协议类型
struct func_type
{
    int flag;
    DetectFunction func;
};

//四元组存储源ip和port以及目的ip和port
struct four_tupel
{
    u_int32_t sip;//源ip
    u_int16_t sport;//源port
    u_int32_t dip;//目的ip
    u_int16_t dport;//目的port
};

//协议栈信息结构体
struct prt_info_t
{
    int count;
    //其他信息
    int tcp_count;
    int udp_count;

    //应用层协议数组
    int app_prt_types[PRT_TYPES_MAX];//应用协议数组
    char* app_prt_names[PRT_TYPES_MAX] = {PRT_NAMES};//应用协议名称
    func_type func_detec[PRT_TYPES_MAX];//探测函数指针数组
    four_tupel tulels_prt[PRT_TYPES_MAX];//应用协议对应的四元组数组



    ethhdr* ethh;//帧头
    iphdr* iph;//ip头
    tcphdr* tcph;//tcp头
    udphdr* udph;//udp头
    u_int8_t* data;
};

//初始化协议栈信息结构体函数
prt_info_t *init_prt_info(void);


//释放协议栈信息结构体指针
int free_prt_info(prt_info_t *p);

//输出协议信息
int output_prt_info(prt_info_t *p);

//保存四元组
int save_four_tupel(prt_info_t *p,int type);

//比较四元组
int cmp_four_tupel(prt_info_t *p,int type); 

#endif