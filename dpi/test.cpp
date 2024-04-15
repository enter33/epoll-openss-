#include <iostream>
#include <pcap.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <pcap_file>" << std::endl;
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(argv[1], errbuf);
    if (handle == NULL) {
        std::cerr << "Error opening pcap file: " << errbuf << std::endl;
        return 1;
    }

    int packet_count = 0;
    struct pcap_pkthdr *header;
    const u_char *packet_data;
    int ret;

    // 循环读取每个数据包
    while ((ret = pcap_next_ex(handle, &header, &packet_data)) >= 0) {
        if (ret == 0) continue;  // 超时或无数据包可读
        packet_count++;
    }

    if (ret == -1) {
        std::cerr << "Error reading packets: " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        return 1;
    }

    std::cout << "Packet count: " << packet_count << std::endl;

    pcap_close(handle);
    return 0;
}
