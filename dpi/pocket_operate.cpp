#include "pocket_operate.h"



int get_pkt_count( char *argv[])
{
    int pkt_count;//包的数量
    int pkt_len;//总读取长度

    //打开pcap文件
    int fd;
    if((fd = open(argv[1],O_RDONLY)) < 0)
    {
        log_err("error for open pcapfile %s\n",argv[1]);
        return -1;
    }

    //获取文件长度
    int len = lseek(fd,0,SEEK_END);
    // printf("len = %d\n",len);

    //文件映射,mmap相比于read减少了系统调用和文件IO,加快了读取速度,但是增大了对虚拟内存的消耗
    char *p = (char*)mmap(NULL,len,PROT_READ,MAP_PRIVATE,fd,0);
    if(p == MAP_FAILED)
    {
        log_err("error for mmap\n");
        close(fd);
        return -1;
    }

    //解析pcap文件
    pcap_file_header *pfh;//pcap global header
    pcap_pkthdr *pkh;//pcap pocket header

    pfh = (pcap_file_header*)p;
    pkt_len = sizeof(*pfh);


    pkh = (pcap_pkthdr*)(p+sizeof(*pfh));//第一个包
    pkt_len += sizeof(*pkh);
    // printf("size = %d\n",sizeof(*pkh));

    pkt_count = 0;//pkt数量

    while(len > pkt_len)
    {
        pkt_count ++;
        //printf("pkt_count = %d\n",pkt_count);

        pkt_len += sizeof(*pkh) + pkh->len;//当前包的数据长度加上下一个包头长度
        if(len <= pkt_len)
        {
            break;
        }
        pkh = (pcap_pkthdr*)((char*)pkh + sizeof(*pkh) + pkh->len);
    }

    //解除映射
    munmap(p,len);

    return pkt_count;


}


void handler(u_char *user, const struct pcap_pkthdr *h,const u_char *bytes)
{
    ((prt_info_t*)user)->count++;
    //对pcap_pkthdr和bytes进行处理

    return;
}



int get_pkt_count_loop(char *argv[],prt_info_t *prt)
{
    //打开pcap文件
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *p = pcap_open_offline(argv[1], errbuf);
    if(p == NULL)
    {
        log_err("error for pcap_open file %s\n",argv[1]);
        return -1;
    }

    //调用pcap_loop
    if(pcap_loop(p,-1,handler,(u_char*)prt) < 0)
    {
        log_err("error for pcap_loop\n");
        pcap_close(p);
        return -1;
    }

    //关闭pcap文件
    pcap_close(p);
    return prt->count;
}