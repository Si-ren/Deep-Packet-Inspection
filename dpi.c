#include "dpi.h"
#include <string.h>

void dpi_pcap_callback(u_char *user, const struct pcap_pkthdr *h,const u_char *bytes);
void dpi_analyze_pkt_ip(dpi_result *res,dpi_pkt *pkt);


//用来分析ssh协议的函数声明
int dpi_analyze_tcp_ssh(dpi_pkt *pkt);

//dpi项目支持的TCP协议的函数指针数组
dpi_pkt_protocol_analyze_func_t dpi_tcp_analyze_func_collection[DPI_PROTOCOL_TCP_COUNT];
dpi_result *dpi_init(const char *pcapFileName)
{
    static int hasInitArray=0;
    if(hasInitArray==0)
    {
        hasInitArray=1;
        //初始化函数指针数组
        dpi_tcp_analyze_func_collection[SSH] = dpi_analyze_tcp_ssh;
    }

    //打开pcap文件，有错报错
    char errbuf[PCAP_ERRBUF_SIZE]={0};
    pcap_t *pcap = pcap_open_offline(pcapFileName,errbuf);
    if(pcap==NULL)
    {
        //出错处理
        DPI_LOG_ERROR("Error in pcap_open_offline : %s\n",errbuf);
        return NULL;
    }
    dpi_result *res = (dpi_result*)calloc(1,sizeof(dpi_result));
    //TODO:res判空
    res->pcap = pcap;

    //对链表进行初始化
    res->tcp_connection_list = dpi_list_create();

    return res;
}
void dpi_analyze(dpi_result *res)
{
    //主要分析报文的模块
    //最后一个参数是用户自定义的透传参数
    pcap_loop(res->pcap,0,dpi_pcap_callback,(u_char*)res);
}
void dpi_free(dpi_result *res)
{
    if(!res)
    {
        return;
    }
    //释放pcap的句柄
    pcap_close(res->pcap);
    //释放TCP连接的链表
    dpi_list_destroy(res->tcp_connection_list,free);
    //释放dpi_result 句柄
    free(res);
}

//回调函数
void dpi_pcap_callback(u_char *user, const struct pcap_pkthdr *h,const u_char *bytes)
{
    //之后的业务都在这里进行处理
    dpi_result *res = (dpi_result*)user;        //先将用户自定义的参数转换回来
    //让以太网报文数量++
    res->ether_packet_count++;

    //保护,如果当前报文的packet header 中 
    //caplen != len ，表示抓包的过程中出现截断，该报文不要继续分析，就直接跳过
    if(h->caplen != h->len)
    {
        //报错
        DPI_LOG_ERROR("packet %u : Caplen != len\n",res->ether_packet_count);
        return;
    }
    //如果caplen和len是相等，说明报文没什么问题，创建一个pkt 记录当前报文的信息
    dpi_pkt pkt;
    memset(&pkt,0,sizeof(pkt));

    //记录每个报文的以太网起始位置以及长度
    pkt.ether_packet = (struct ether_header*)bytes; 
    pkt.ether_packet_len = h->caplen;



    //以太网报文的起始地址+12字节，获取以太网类型
    //uint16_t *type = (uint16_t*)(pkt.ether_packet + 12);
    //printf("type:%04x\n",ntohs(*type));
    

    if(ntohs(pkt.ether_packet->ether_type)!=ETHERTYPE_IP)
    {
        //以太网报文的分析，只需要分析出装载的数据是IP报文，其他不用管
        return;
    }

    //IP报文的情况，计算IP报文的起始位置以及IP报文的长度
    pkt.ip_packet = (struct iphdr*)((u_char*)pkt.ether_packet + 14);
    pkt.ip_packet_len = pkt.ether_packet_len - 14;

    //进入IP报文的解析阶段
    dpi_analyze_pkt_ip(res,&pkt);

}
