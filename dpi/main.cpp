#include "main.h"

int get_pkt_count( char *argv[]);//不调用pcap_loop
int get_pkt_count_loop( char *argv[]);//调用pcap_loop

int main(int argc,char *argv[])
{
    int pkt_count;//包的数量
    int pkt_len;//总读取长度
    //从命令行读入pcap文件
    if(argc < 2)
    {
        fprintf(stderr,"please input correct pcap_filename\n");//printf和fprintf的区别
        return 1;
    }

    int ret;
    if((ret = get_pkt_count_loop(argv)) < 0)
    {
        printf("get_pkt_count error\n");
        return 0;
    }

    printf("pkt = %d\n",ret);
    

    return 0;
}

int get_pkt_count( char *argv[])
{
    int pkt_count;//包的数量
    int pkt_len;//总读取长度

    //打开pcap文件
    int fd;
    if((fd = open(argv[1],O_RDONLY)) < 0)
    {
        fprintf(stdout,"error for open pcapfile %s\n",argv[1]);
        return -1;
    }

    //获取文件长度
    int len = lseek(fd,0,SEEK_END);
    // printf("len = %d\n",len);

    //文件映射,mmap相比于read减少了系统调用和文件IO,加快了读取速度,但是增大了对虚拟内存的消耗
    char *p = (char*)mmap(NULL,len,PROT_READ,MAP_PRIVATE,fd,0);
    if(p == MAP_FAILED)
    {
        fprintf(stderr,"error for mmap\n");
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
    (*(int*)user)++;
    //对pcap_pkthdr和bytes进行处理

    

    return;
}



int get_pkt_count_loop( char *argv[])
{
    //打开pcap文件
    pcap_t *p = pcap_open_offline(argv[1], NULL);
    if(p == NULL)
    {
        printf("error for pcap_open file %s\n",argv[1]);
        return -1;
    }

    int count = 0;
    if(pcap_loop(p,-1,handler,(u_char*)&count) < 0)
    {
        printf("error for pcap_loop\n");
        pcap_close(p);
        return -1;
    }

    //关闭pcap文件
    pcap_close(p);
    return count;
}