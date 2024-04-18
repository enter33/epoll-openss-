//protocol_info.h实现代码

#include "protocol_info.h"
#include "detec_ssh.h"
#include "detec_tftp.h"
// #include "detec_func.h"//为什么放在cpp里就不重复定义,放在.h里面就重定义


//对协议栈信息结构体初始化.成功,返回指针;失败,返回NULL
prt_info_t *init_prt_info(void)
{
    try
    {
        //使用智能指针防止内存泄漏
        prt_info_t *p = new prt_info_t();
        p->count = 0;
        p->arp_count = 0;
        p->ip_count = 0;
        p->other_count = 0;
        p->tcp_count = 0;
        p->udp_count = 0;
        p->iph = NULL;
        p->ethh = NULL;
        p->tcph = NULL;
        p->udph = NULL;

        for(int i = 0;i < PRT_TYPES_MAX;i++)
        {
            p->app_prt_types[i] = 0;
            p->tulels_prt[i] = {0};
        }
//按需求增加函数指针
#ifdef DETEC_SSH
        p->func_detec[PRT_SSH] = func_type{IPPROTO_TCP,detec_ssh};
#endif

#ifdef DETEC_TFTP
        p->func_detec[PRT_TFTP] = func_type{IPPROTO_UDP,detec_tftp};
#endif
    
        return p;

    }
    catch(const std::bad_alloc& e)
    {
        log_err("error for new prt_info_t\n");
        return NULL;
    }
}


//释放协议栈信息结构体
int free_prt_info(prt_info_t *p)
{
    delete p;
    return 0;
}



//输出协议栈信息
int output_prt_info(prt_info_t *p)
{
    log_info("tt_pkt count = %d\n",p->count);
    log_info("\tip_pkt count = %d\n",p->ip_count);
    log_info("\t\ttcp_pkt count = %d\n",p->tcp_count);
    log_info("\t\tudp_pkt count = %d\n",p->udp_count);
    log_info("\tarp_pkt count = %d\n",p->arp_count);
    log_info("\tother_pkt count = %d\n",p->other_count);


    log_info("app protocol:\n");
    for(int i = 0; i<PRT_TYPES_MAX;i++)
    {
        if(p->app_prt_types[i] != 0)
        {
            log_info("\t%s : %d\n",p->app_prt_names[i],p->app_prt_types[i]);
        }
    }
    return 0;
}

//保存四元组
int save_four_tupel(prt_info_t *p,int type)
{
    if(p->iph->protocol == IPPROTO_TCP)
    {
        p->tulels_prt[type] = {p->iph->saddr,p->tcph->source,p->iph->daddr,p->tcph->dest};
    }
    else if(p->iph->protocol == IPPROTO_UDP)
    {
        p->tulels_prt[type] = {p->iph->saddr,p->udph->source,p->iph->daddr,p->udph->dest};
    }

    return 0;
}

//判断当前的源ip和port\目标ip和port能否与已有的ip和port对应,如果能,能说明该应用数据包的协议与已有的ip和port对应的应用协议一致
int cmp_four_tupel(prt_info_t *p,int type)
{
    if(p->iph->protocol == IPPROTO_TCP)
    {
        if(p->tulels_prt[type].sip == p->iph->saddr \
        && p->tulels_prt[type].sport == p->tcph->source)
        {
            if(p->tulels_prt[type].dip == p->iph->daddr \
            && p->tulels_prt[type].dport == p->tcph->dest)
            {
                return 1;
            }
        }
        else if(p->tulels_prt[type].sip == p->iph->daddr \
        && p->tulels_prt[type].sport == p->tcph->dest)
        {
            if(p->tulels_prt[type].dip == p->iph->saddr \
            && p->tulels_prt[type].dport == p->tcph->source)
            {
                return 1;
            }
        }
    }
    else if(p->iph->protocol == IPPROTO_UDP)
    {
        if(p->tulels_prt[type].sip == p->iph->saddr \
        && p->tulels_prt[type].sport == p->udph->source)
        {
            if(p->tulels_prt[type].dip == p->iph->daddr \
            && p->tulels_prt[type].dport == p->udph->dest)
            {
                return 1;
            }
        }
        else if(p->tulels_prt[type].sip == p->iph->daddr \
        && p->tulels_prt[type].sport == p->udph->dest)
        {
            if(p->tulels_prt[type].dip == p->iph->saddr \
            && p->tulels_prt[type].dport == p->udph->source)
            {
                return 1;
            }
        }
    }


    
    return 0;
}

