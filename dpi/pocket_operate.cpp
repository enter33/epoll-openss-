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
    ((prt_info_t*)user)->iph = NULL;
    ((prt_info_t*)user)->ethh = NULL;
    ((prt_info_t*)user)->tcph = NULL;
    ((prt_info_t*)user)->udph = NULL;

    //对pcap_pkthdr和bytes进行处理

    //包不完整,丢弃
    if(h->caplen != h->len)
    {
        return;
    }

    //以太网帧头部,14字节
    // ethhdr eth = *(ethhdr*)bytes;
    ((prt_info_t*)user)->ethh = (ethhdr*)bytes;

    //不是ip数据报,丢弃
    //网络字节序转换主机字节序
    if(ntohs(((prt_info_t*)user)->ethh->h_proto) != ETH_P_IP)
    {
        return;
    }

    ((prt_info_t*)user)->count++;
    // ((prt_info_t*)user)->iph = (iphdr*)(bytes + sizeof(ethhdr));

    // printf("bytes addr = %p\n",bytes);
    // printf("size = %d\n",sizeof(ethhdr));
    // printf("iph addr = %p\n",((prt_info_t*)user)->iph);


    analysis_ip(((prt_info_t*)user));
    
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
    return 0;
}

//处理ip协议
void analysis_ip(prt_info_t* p)
{
    p->iph = (iphdr*)((char*)p->ethh + sizeof(ethhdr));
    // printf("ethh addr = %p\n",p->ethh);
    // printf("size = %d\n",sizeof(ethhdr));
    // printf("iph addr = %p\n",p->iph);

    //对于ip分片,只处理第一个片
    //偏移量为0的情况下,一种是未分片,一种是第一个片
    //不为0,则为第n个片
    if(ntohs(p->iph->frag_off) & 0x1FFF != 0)//0x1FFF = 0001 1111 1111 1111
    {
        return;
    }

    if(p->iph->version == 4)//ipv4
    {
        analysis_ipv4(p);
    }
    else if(p->iph->version == 6)//ipv6
    {
        analysis_ipv6(p);
    }

    return;
}

//分析ipv4
void analysis_ipv4(prt_info_t* p)
{
    if(p->iph->protocol == IPPROTO_TCP)//TCp包
    {
        p->tcp_count++;

        //tcp header
        p->tcph = (tcphdr*)((char*)p->iph  + p->iph->ihl*4);

        analysis_tcp(p);
    }

    else if(p->iph->protocol == IPPROTO_UDP)//UDP包
    {
        p->udp_count++;
        //udp header
        p->udph = (udphdr*)((char*)p->iph  + p->iph->ihl*4);

        analysis_udp(p);
    }

    int prt_type = detect_protocol_type(p);
    p->app_prt_types[prt_type] ++;

    return;
}

//分析ipv6
void analysis_ipv6(prt_info_t* p)
{
    return;
}


//分析tcp
void analysis_tcp(prt_info_t* p)
{
    //判断是否具有数据,无则丢弃
    if(ntohs(p->iph->tot_len) - p->tcph->th_off*4 - p->iph->ihl*4 <= 0)
    {
        // printf("no data\n");
        return;
    }
    

    return;
}

//分析udp
void analysis_udp(prt_info_t* p)
{
    if(ntohs(p->udph->len) <= 8)
    {
        printf("no data\n");
        return;
    }

    

    return;
}


int detect_protocol_type(prt_info_t* p)
{
    int type = PRT_UNKNOW;

    for(int i = 0;i < PRT_TYPES_MAX;i++)
    {
        if(p->func_detec[i].func == NULL && p->func_detec[i].flag != p->iph->protocol)
        {
            continue;
        }
        if(p->func_detec[i].func(p) == 1)
        {
            type = i;
            return type;
        }
    }


    return type;
}