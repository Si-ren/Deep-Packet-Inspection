#pragma once
#include <pcap/pcap.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "dpi_list.h"

//定义一些用于打印日志的LOG 宏，留坑以后填
#define DPI_LOG_DEBUG(...) do{fprintf(stderr,__VA_ARGS__);}while(0)
#define DPI_LOG_INFO(...)  do{fprintf(stderr,__VA_ARGS__);}while(0)
#define DPI_LOG_WARN(...)  do{fprintf(stderr,__VA_ARGS__);}while(0)
#define DPI_LOG_ERROR(...) do{fprintf(stderr,__VA_ARGS__);}while(0)
#define DPI_LOG_FATAL(...) do{fprintf(stderr,__VA_ARGS__);}while(0)

//当前DPI项目支持的TCP的一些协议枚举，最后一个值用来表示当前支持的TCP的协议数量
typedef enum dpi_protocol_tcp
{
    SSH,
    DPI_PROTOCOL_TCP_COUNT
}dpi_protocol_tcp;

//定义DPI 的连接的类型
typedef struct dpi_connection
{
    //通过两对IP + 端口标识
    uint32_t sip;
    uint16_t sport;

    uint32_t dip;
    uint16_t dport;

    dpi_protocol_tcp protocol;  //标识该连接是什么协议
}dpi_connection;

//自定义的句柄，以结果集为导向
typedef struct dpi_result
{
    pcap_t *pcap;
    dpi_list *tcp_connection_list;          //保存了当前的一些tcp连接的链表
    unsigned int ether_packet_count;        //以太网报文数量
    unsigned int ip_packet_count;           //IP报文数量
    unsigned int tcp_packet_count;          //TCP报文数量
    unsigned int udp_packet_count;          //UDP报文数量
    unsigned int tcp_payload_packet_count[DPI_PROTOCOL_TCP_COUNT]; //TCP协议对应的应用层报文的数量
}dpi_result;


//数据报文分析的结构
typedef struct dpi_pkt
{
    const struct ether_header *ether_packet;               //以太网报文的起始位置
    unsigned int ether_packet_len;      //以太网报文的长度

    const struct iphdr *ip_packet;                  //IP报文的起始位置
    unsigned int ip_packet_len;         //IP报文的长度
    union
    {
        struct
        {
            const struct tcphdr *tcp_packet;                 //TCP报文的起始位置
            unsigned int tcp_packet_len;        //TCP报文的长度
        };
        struct
        {
            const struct udphdr *udp_packet;                 //UDP报文的起始位置
            unsigned int udp_packet_len;        //UDP报文的长度
        };
    };
    const u_char *payload;                    //应用层报文的起始位置
    unsigned int payload_len;           //应用层报文的长度

}dpi_pkt;

//初始化的函数
//pcapFileName : pcap文件
//返回值就是我们自定义的句柄的指针，失败返回NULL
dpi_result *dpi_init(const char *pcapFileName);


//业务处理
//分析pcap文件中的每一种报文的数量
//res 就是 dpi_init获取的句柄
void dpi_analyze(dpi_result *res);


//垃圾回收
void dpi_free(dpi_result *res);

//用来进行协议分析的函数指针
typedef int (*dpi_pkt_protocol_analyze_func_t)(dpi_pkt *pkt);

//函数指针数组
extern dpi_pkt_protocol_analyze_func_t dpi_tcp_analyze_func_collection[DPI_PROTOCOL_TCP_COUNT];
