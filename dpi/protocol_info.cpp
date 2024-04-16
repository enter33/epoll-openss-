//protocol_info.h实现代码

#include "protocol_info.h"
// #include "detec_func.h"//为什么放在cpp里就不重复定义,放在.h里面就重定义


//对协议栈信息结构体初始化.成功,返回指针;失败,返回NULL
prt_info_t *init_prt_info(void)
{
    try
    {
        //使用智能指针防止内存泄漏
        prt_info_t *p = new prt_info_t();
        p->count = 0;
        p->tcp_count = 0;
        p->udp_count = 0;
        p->iph = NULL;
        p->ethh = NULL;
        p->tcph = NULL;
        p->udph = NULL;

        for(int i = 0;i < PRT_TYPES_MAX;i++)
        {
            p->app_prt_types[i] = 0;
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
    log_info("pkt count = %d\n",p->count);
    log_info("tcp_pkt count = %d\n",p->tcp_count);
    log_info("udp_pkt count = %d\n",p->udp_count);

    for(int i = 0; i<PRT_TYPES_MAX;i++)
    {
        if(p->app_prt_types[i] != 0)
        {
            log_info("%s : %d\n",p->app_prt_names[i],p->app_prt_types[i]);
        }
    }
    return 0;
}

