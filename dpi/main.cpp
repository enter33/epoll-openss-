#include "main.h"

int main(int argc,char *argv[])
{
    int pkt_count;//包的数量
    int pkt_len;//总读取长度
    //从命令行读入pcap文件
    if(argc < 2)
    {
        log_err("please input correct pcap_filename\n");//printf和fprintf的区别
        return 1;
    }

    //初始化协议栈信息结构体
    prt_info_t *p = init_prt_info();
    if(p == NULL)
    {
        log_err("error for init prt_info_t\n");
        return 2;
    }

    int ret;
    if((ret = get_pkt_count_loop(argv,p)) < 0)
    {
        log_err("get_pkt_count error\n");
        return 3;
    }

    output_prt_info(p);
    free_prt_info(p);

    return 0;
}
