#include <stdio.h>
#include <stdlib.h>
#include "dpi.h"
#include <arpa/inet.h>
#include <netinet/in.h>

void usage(const char *argv0)
{
    fprintf(stderr,"usage : %s <pcap file>\n",argv0);
}

void displayResult(dpi_result *res)
{
    printf("==============================================\n");
    printf("以太网报文数量:%lu\n",res->ether_packet_count);
    printf("IP文数量:%lu\n",res->ip_packet_count);
    printf("TCP报文数量:%lu\n",res->tcp_packet_count);
    printf("UDP报文数量:%lu\n",res->udp_packet_count);
    printf("SSH报文数量:%lu\n",res->tcp_payload_packet_count[SSH]);
    printf("==============================================\n");
    //遍历连接的链表，输出当前的连接以及协议
    printf("TCP连接的数量：%u\n",res->tcp_connection_list->size);
    dpi_list_node *node = res->tcp_connection_list->sentinel.next;
    while(node!=&res->tcp_connection_list->sentinel)
    {
        dpi_connection *con = node->data;
        struct in_addr sip;
        struct in_addr dip;
        sip.s_addr = con->sip;
        dip.s_addr = con->dip;
        printf("connection : %s:%u", inet_ntoa(sip),ntohs(con->sport));
        printf("->%s:%u---%d\n", inet_ntoa(dip),ntohs(con->dport),con->protocol);
        node = node->next;
    }
    printf("==============================================\n");

}

int main(int argc ,char **argv)
{
    //1 先判断参数
    if(argc!=2)
    {
        usage(argv[0]);
        exit(-1);
    }

    //2 初始化
    dpi_result *res = dpi_init(argv[1]);
    if(res==NULL)
    {
        fprintf(stderr,"Error in dpi_init\n");
        exit(-1);
    }
    //3 业务处理
    dpi_analyze(res);
    //打印最终分析结果
    displayResult(res);
    //4 垃圾回收
    dpi_free(res);
    return 0;
}
