//protocol_info.h实现代码

#include "protocol_info.h"


//对协议栈信息结构体初始化.成功,返回指针;失败,返回NULL
prt_info_t *init_prt_info(void)
{
    try
    {
        //使用智能指针防止内存泄漏
        prt_info_t *p = new prt_info_t();
        p->count = 0;
        return p;
    }
    catch(const std::bad_alloc& e)
    {
        printf("error for new prt_info_t\n");
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
    printf("pkt count = %d\n",p->count);
    return 0;
}

