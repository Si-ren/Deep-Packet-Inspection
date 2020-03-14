#include "dpi.h"


void dpi_analyze_pkt_tcp(dpi_result *res,dpi_pkt *pkt);
void dpi_analyze_pkt_udp(dpi_result *res,dpi_pkt *pkt);
void dpi_analyze_pkt_ip(dpi_result *res,dpi_pkt *pkt)
{
    //IP报文数量++
    res->ip_packet_count++;

    //IP报文的解析
    //只解析版本号是4的
    if(pkt->ip_packet->version!=4)
    {
        DPI_LOG_ERROR("Error ip packet version not 4\n");
        return ;
    }

    //记住IP报文的头部长度
    unsigned short ipHeaderLen = pkt->ip_packet->ihl<<2; //单位是4字节，要乘以4
    unsigned short ipPacketLen = ntohs(pkt->ip_packet->tot_len);
    
    //计算片偏移13位都为0
    if(ntohs(pkt->ip_packet->frag_off)&0x1fff!=0)
    {
        //如果不等于0，不是第一个分片，不要处理 
        DPI_LOG_ERROR("Error ip packet frag_off not 0\n");
        return ;
    }

    //8位的协议，目前只考虑TCP和UDP，其他协议的报文不用管
    if(pkt->ip_packet->protocol==IPPROTO_TCP)
    {
        //TCP
        //计算报文的起始位置以及长度
        pkt->tcp_packet = (struct tcphdr*)((u_char*)pkt->ip_packet + ipHeaderLen);
        pkt->tcp_packet_len = ipPacketLen - ipHeaderLen;
        //调用分析TCP的函数
        dpi_analyze_pkt_tcp(res,pkt);
    }
    if(pkt->ip_packet->protocol==IPPROTO_UDP)
    {
        //UDP
        pkt->udp_packet = (struct udphdr*)((u_char*)pkt->ip_packet + ipHeaderLen);
        pkt->udp_packet_len = ipPacketLen - ipHeaderLen;
        //调用分析UDP的函数
        dpi_analyze_pkt_udp(res,pkt);
    }

}

//TCP报文的分析函数
void dpi_analyze_pkt_tcp(dpi_result *res,dpi_pkt *pkt)
{
    //TCP报文数量++
    res->tcp_packet_count++;

    //提取TCP报文中的首部长度 ，来计算应用层数据报文的起始位置以及长度
    unsigned int tcpHeaderLen = pkt->tcp_packet->doff<<2;  //单位是4字节，要乘以4
    //DPI_LOG_DEBUG("tcp header length : %u\n",tcpHeaderLen);

    //数据区域的起始位置= tcp报文的起始位置+tcp头部长度
    pkt->payload = (u_char*)pkt->tcp_packet + tcpHeaderLen;
    //数据区域长度=tcp报文的总长度 - tcp报头的长度
    pkt->payload_len = pkt->tcp_packet_len - tcpHeaderLen;


    //如果TCP中没有带数据，不要再继续往下解析
    if(pkt->payload_len==0)
    {
        return;
    }

    //先遍历已经被标识协议的连接的容器
    dpi_list_node *node = res->tcp_connection_list->sentinel.next;
    while(node!=&res->tcp_connection_list->sentinel)
    {
        dpi_connection *con = node->data;
        //如果当前连接是已经被标识的协议，就直接报文数量++
        //否则就继续遍历函数指针数组

        int flag=0;
        if(pkt->ip_packet->saddr == con->sip && pkt->ip_packet->daddr == con->dip)
        {
            if(pkt->tcp_packet->source == con->sport && pkt->tcp_packet->dest == con->dport)
            {
                //同一个方向的报文
                flag=1;
            }
        }
        if(pkt->ip_packet->saddr == con->dip && pkt->ip_packet->daddr == con->sip)
        {
            if(pkt->tcp_packet->source == con->dport && pkt->tcp_packet->dest == con->sport)
            {
                //反方向的报文
                flag=1;
            }
        }
        if(flag)
        {
            res->tcp_payload_packet_count[con->protocol]++;
            //直接返回不需要继续往下走
            return;
        }
        node = node->next;
    }

    //以遍历数组的形式，来遍历每一个协议分析函数
    int i;
    for(i=0;i<DPI_PROTOCOL_TCP_COUNT;++i)
    {
        if(dpi_tcp_analyze_func_collection[i](pkt))
        {
            //确定该报文就是该协议的
            //对应报文数量++
            res->tcp_payload_packet_count[i]++;

            //对已经识别的报文，标识它为一个连接，存储到链表中
            dpi_connection *con = malloc(sizeof(dpi_connection));
            //记录当前连接的两对IP和端口号
            con->sip = pkt->ip_packet->saddr;
            con->dip = pkt->ip_packet->daddr;
            con->sport = pkt->tcp_packet->source;
            con->dport = pkt->tcp_packet->dest;
            con->protocol = i;

            //将连接的结构体追加到链表中
            dpi_list_append(res->tcp_connection_list,con);
        }
    }
}


//UDP报文的分析函数
void dpi_analyze_pkt_udp(dpi_result *res,dpi_pkt *pkt)
{
    res->udp_packet_count++;
}
